package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.framework.options.Options;

import com.lauriewired.Util;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_READ_BYTES = 4096;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Util.sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            Util.sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            Util.sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            Util.sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = Util.parseLimitOrDefault(qparams.get("limit"),  100);
            Util.sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            Util.sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            Util.sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            Util.sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            Util.sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Util.sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            Util.sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            Util.sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            Util.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            Util.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            Util.sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                Util.sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                Util.sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            Util.sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            Util.sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            Util.sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            Util.sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            Util.sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // ---- Labels ----

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, createLabel(params.get("address"), params.get("name")));
        });

        server.createContext("/remove_label", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, removeLabel(params.get("address"), params.get("name")));
        });

        server.createContext("/list_labels", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            Util.sendResponse(exchange, listLabels(offset, limit, filter));
        });

        // ---- Bookmarks ----

        server.createContext("/set_bookmark", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, setBookmark(
                params.get("address"), params.get("category"), params.get("comment")));
        });

        server.createContext("/remove_bookmark", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, removeBookmark(params.get("address"), params.get("category")));
        });

        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            String category = qparams.get("category");
            Util.sendResponse(exchange, listBookmarks(offset, limit, category));
        });

        // ---- Raw memory ----

        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = Util.parseIntOrDefault(qparams.get("length"), 16);
            String format = qparams.get("format");
            Util.sendResponse(exchange, readBytes(address, length, format));
        });

        // ---- Decompiler output with address mapping + P-code ----

        server.createContext("/decompile_with_map", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            Util.sendResponse(exchange, decompileWithAddressMap(qparams.get("address"), qparams.get("name")));
        });

        server.createContext("/get_high_pcode", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            Util.sendResponse(exchange, getHighPcode(qparams.get("address")));
        });

        server.createContext("/get_pcode", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = Util.parseIntOrDefault(qparams.get("length"), 0);
            Util.sendResponse(exchange, getLowPcode(address, length));
        });

        // ---- Data types (structs, enums, typedefs) ----

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            int offset = Util.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = Util.parseLimitOrDefault(qparams.get("limit"), 100);
            Util.sendResponse(exchange, listDataTypes(offset, limit,
                qparams.get("category"), qparams.get("filter")));
        });

        server.createContext("/get_data_type", exchange -> {
            Map<String, String> qparams = Util.parseQueryParams(exchange);
            Util.sendResponse(exchange, getDataTypeDefinition(qparams.get("name")));
        });

        server.createContext("/create_struct", exchange -> {
            String body = Util.readBody(exchange);
            Util.sendResponse(exchange, createStructFromJson(body));
        });

        server.createContext("/create_enum", exchange -> {
            String body = Util.readBody(exchange);
            Util.sendResponse(exchange, createEnumFromJson(body));
        });

        server.createContext("/create_typedef", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, createTypedef(
                params.get("name"), params.get("targetType"), params.get("category")));
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            boolean clear = "true".equalsIgnoreCase(params.get("clear_existing"));
            Util.sendResponse(exchange, applyDataType(
                params.get("address"), params.get("type_name"), clear));
        });

        server.createContext("/delete_data_type", exchange -> {
            Map<String, String> params = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, deleteDataType(params.get("name")));
        });

        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "GhidraMCP-HTTP-Worker");
            t.setDaemon(true);
            return t;
        }));
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return Util.paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return Util.paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return Util.paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return Util.paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return Util.paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return Util.paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        Util.escapeNonAscii(label),
                        Util.escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return Util.paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return Util.paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    DecompileResults result =
                        decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                    if (result != null && result.decompileCompleted()) {
                        return result.getDecompiledFunction().getC();
                    } else {
                        return "Decompilation failed";
                    }
                }
            }
            return "Function not found";
        } finally {
            decomp.dispose();
        }
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);

            Function func = null;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }

            if (func == null) {
                return "Function not found";
            }

            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) {
                return "Decompilation failed";
            }

            HighFunction highFunction = result.getHighFunction();
            if (highFunction == null) {
                return "Decompilation failed (no high function)";
            }

            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            if (localSymbolMap == null) {
                return "Decompilation failed (no local symbol map)";
            }

            HighSymbol highSymbol = null;
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();

                if (symbolName.equals(oldVarName)) {
                    highSymbol = symbol;
                }
                if (symbolName.equals(newVarName)) {
                    return "Error: A variable with name '" + newVarName + "' already exists in this function";
                }
            }

            if (highSymbol == null) {
                return "Variable not found";
            }

            boolean commitRequired = checkFullCommit(highSymbol, highFunction);

            final HighSymbol finalHighSymbol = highSymbol;
            final Function finalFunction = func;
            AtomicBoolean successFlag = new AtomicBoolean(false);

            try {
                SwingUtilities.invokeAndWait(() -> {
                    int tx = program.startTransaction("Rename variable");
                    try {
                        if (commitRequired) {
                            HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                        }
                        HighFunctionDBUtil.updateDBVariable(
                            finalHighSymbol,
                            newVarName,
                            null,
                            SourceType.USER_DEFINED
                        );
                        successFlag.set(true);
                    }
                    catch (Exception e) {
                        Msg.error(this, "Failed to rename variable", e);
                    }
                    finally {
                        successFlag.set(program.endTransaction(tx, true));
                    }
                });
            } catch (InterruptedException | InvocationTargetException e) {
                String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
                Msg.error(this, errorMsg, e);
                return errorMsg;
            }
            return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
        } finally {
            decomp.dispose();
        }
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

                return (result != null && result.decompileCompleted())
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CommentType.EOL, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE or EOL)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, CommentType commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.PRE, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.EOL, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(),
                CommentType.PLATE,
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results.
     * DecompInterface is disposed before returning; the returned DecompileResults
     * (and its HighFunction) are already materialized and remain valid for the caller.
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            decomp.setSimplificationStyle("decompile");
            DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
            if (!results.decompileCompleted()) {
                Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
                return null;
            }
            return results;
        } finally {
            decomp.dispose();
        }
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return Util.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return Util.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return Util.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return Util.paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Labels, bookmarks, raw memory
    // ----------------------------------------------------------------------------------

    /**
     * Create a USER_DEFINED label at the given address.
     */
    private String createLabel(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create label");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        err.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Create label error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Label created" : ("Failed to create label: " + err);
    }

    /**
     * Remove a label at the given address. If name is provided, only a matching symbol is deleted;
     * otherwise the primary label at that address is removed.
     */
    private String removeLabel(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove label");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        err.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol target = null;
                    if (name != null && !name.isEmpty()) {
                        for (Symbol s : symTable.getSymbols(addr)) {
                            if (name.equals(s.getName())) {
                                target = s;
                                break;
                            }
                        }
                        if (target == null) {
                            err.append("No symbol '").append(name).append("' at ").append(addressStr);
                            return;
                        }
                    } else {
                        target = symTable.getPrimarySymbol(addr);
                        if (target == null) {
                            err.append("No symbol at ").append(addressStr);
                            return;
                        }
                    }
                    if (target.getSource() == SourceType.DEFAULT) {
                        err.append("Cannot remove default (auto-generated) symbol");
                        return;
                    }
                    success.set(target.delete());
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Remove label error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Label removed" : ("Failed to remove label: " + err);
    }

    /**
     * List user-meaningful labels (functions, labels, code symbols). Filter is case-insensitive substring.
     */
    private String listLabels(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        SymbolIterator it = program.getSymbolTable().getSymbolIterator(true);
        String filterLc = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();
        while (it.hasNext()) {
            Symbol s = it.next();
            SymbolType t = s.getSymbolType();
            if (t != SymbolType.LABEL && t != SymbolType.FUNCTION) continue;
            if (s.isDynamic()) continue;
            String name = s.getName();
            if (filterLc != null && !name.toLowerCase().contains(filterLc)) continue;
            lines.add(String.format("%s @ %s [%s]", name, s.getAddress(), t.toString()));
        }
        return Util.paginateList(lines, offset, limit);
    }

    /**
     * Set (or overwrite) a "Note"-type bookmark at an address under the given category.
     */
    private String setBookmark(String addressStr, String category, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (category == null) category = "";
        final String finalCategory = category;
        final String finalComment = comment == null ? "" : comment;

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        err.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    program.getBookmarkManager().setBookmark(
                        addr, BookmarkType.NOTE, finalCategory, finalComment);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Set bookmark error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Bookmark set" : ("Failed to set bookmark: " + err);
    }

    /**
     * Remove a Note bookmark matching the given category at the address.
     */
    private String removeBookmark(String addressStr, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        final String finalCategory = category == null ? "" : category;

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        err.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    BookmarkManager bm = program.getBookmarkManager();
                    Bookmark bookmark = bm.getBookmark(addr, BookmarkType.NOTE, finalCategory);
                    if (bookmark == null) {
                        err.append("No bookmark at ").append(addressStr)
                           .append(" with category '").append(finalCategory).append("'");
                        return;
                    }
                    bm.removeBookmark(bookmark);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Remove bookmark error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Bookmark removed" : ("Failed to remove bookmark: " + err);
    }

    /**
     * List Note bookmarks. When category is provided, only matching entries are returned.
     */
    private String listBookmarks(int offset, int limit, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        BookmarkManager bm = program.getBookmarkManager();
        Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.NOTE);
        while (it.hasNext()) {
            Bookmark b = it.next();
            if (category != null && !category.isEmpty() && !category.equals(b.getCategory())) continue;
            lines.add(String.format("%s [%s] %s",
                b.getAddress(),
                b.getCategory() == null ? "" : b.getCategory(),
                Util.escapeNonAscii(b.getComment() == null ? "" : b.getComment())));
        }
        return Util.paginateList(lines, offset, limit);
    }

    /**
     * Read raw bytes from memory. Length is capped at MAX_READ_BYTES to protect MCP context.
     * format: "hex" (default) or "base64".
     */
    private String readBytes(String addressStr, int length, String format) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (length <= 0) return "Length must be positive";
        if (length > MAX_READ_BYTES) {
            return "Length exceeds max of " + MAX_READ_BYTES + "; issue multiple calls with different addresses";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;

            byte[] buf = new byte[length];
            Memory mem = program.getMemory();
            int n = mem.getBytes(addr, buf);
            String effectiveFmt = (format == null || format.isEmpty()) ? "hex" : format.toLowerCase();

            if ("base64".equals(effectiveFmt)) {
                byte[] slice = (n == length) ? buf : Arrays.copyOf(buf, n);
                return Base64.getEncoder().encodeToString(slice);
            }
            // default hex
            StringBuilder sb = new StringBuilder(n * 2);
            for (int i = 0; i < n; i++) {
                sb.append(String.format("%02x", buf[i] & 0xFF));
            }
            return sb.toString();
        } catch (MemoryAccessException e) {
            return "Memory access error: " + e.getMessage();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Decompiler output with address mapping + P-code
    // ----------------------------------------------------------------------------------

    /**
     * Resolve a function from either an address string or a function name. Caller passes
     * at least one; address takes precedence when both are provided.
     */
    private Function resolveFunction(Program program, String addressStr, String name) {
        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return null;
            return getFunctionForAddress(program, addr);
        }
        if (name != null && !name.isEmpty()) {
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) return f;
            }
        }
        return null;
    }

    /**
     * Decompile a function and emit each source line prefixed with the minimum address
     * of its tokens. Enables the client to comment/rename at the correct location without
     * a second disassembly round-trip.
     */
    private String decompileWithAddressMap(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = resolveFunction(program, addressStr, name);
        if (func == null) return "Function not found";

        DecompileResults results = decompileFunction(func, program);
        if (results == null) return "Decompilation failed";

        ClangTokenGroup root = results.getCCodeMarkup();
        if (root == null) return "No C code markup available";

        List<ClangLine> lines = DecompilerUtils.toLines(root);
        StringBuilder out = new StringBuilder();
        for (ClangLine line : lines) {
            Address minAddr = null;
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < line.getIndent(); i++) text.append(' ');
            int numTokens = line.getNumTokens();
            for (int i = 0; i < numTokens; i++) {
                ClangToken tok = line.getToken(i);
                Address a = tok.getMinAddress();
                if (a != null && (minAddr == null || a.compareTo(minAddr) < 0)) {
                    minAddr = a;
                }
                String s = tok.getText();
                if (s != null) text.append(s);
            }
            out.append(minAddr != null ? minAddr.toString() : "        ")
               .append(" | ")
               .append(text)
               .append('\n');
        }
        return out.toString();
    }

    /**
     * Dump the high P-code operations (post-decompilation IR) for a function.
     * Produces one op per line, prefixed with the op's sequence address.
     */
    private String getHighPcode(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Function func = resolveFunction(program, addressStr, null);
        if (func == null) return "No function found at or containing address " + addressStr;

        DecompileResults results = decompileFunction(func, program);
        if (results == null) return "Decompilation failed";

        HighFunction high = results.getHighFunction();
        if (high == null) return "No high function available";

        StringBuilder out = new StringBuilder();
        Iterator<PcodeOpAST> ops = high.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            Address opAddr = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;
            out.append(opAddr != null ? opAddr.toString() : "        ")
               .append(": ")
               .append(op.toString())
               .append('\n');
        }
        return out.length() == 0 ? "No P-code ops emitted" : out.toString();
    }

    /**
     * Dump raw (low-level) P-code for instructions. If length > 0, iterate N instructions
     * starting at address; otherwise walk the function body containing that address.
     */
    private String getLowPcode(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;

            Listing listing = program.getListing();
            StringBuilder out = new StringBuilder();
            int count = 0;

            if (length > 0) {
                InstructionIterator it = listing.getInstructions(addr, true);
                while (it.hasNext() && count < length) {
                    appendPcodeForInstruction(out, it.next());
                    count++;
                }
            } else {
                Function func = getFunctionForAddress(program, addr);
                if (func == null) return "No function at or containing address " + addressStr
                    + " (pass length=N to walk N instructions instead)";
                Address end = func.getBody().getMaxAddress();
                InstructionIterator it = listing.getInstructions(func.getEntryPoint(), true);
                while (it.hasNext()) {
                    Instruction instr = it.next();
                    if (instr.getAddress().compareTo(end) > 0) break;
                    appendPcodeForInstruction(out, instr);
                }
            }
            return out.length() == 0 ? "No P-code emitted" : out.toString();
        } catch (Exception e) {
            return "Error getting P-code: " + e.getMessage();
        }
    }

    private void appendPcodeForInstruction(StringBuilder out, Instruction instr) {
        PcodeOp[] ops = instr.getPcode();
        if (ops == null || ops.length == 0) {
            out.append(instr.getAddress()).append(": (no pcode)\n");
            return;
        }
        for (PcodeOp op : ops) {
            out.append(instr.getAddress()).append(": ").append(op.toString()).append('\n');
        }
    }

    // ----------------------------------------------------------------------------------
    // Data types: list, define, create (struct/enum/typedef), apply, delete
    // ----------------------------------------------------------------------------------

    private CategoryPath toCategoryPath(String category) {
        if (category == null || category.isEmpty()) return CategoryPath.ROOT;
        return new CategoryPath(category.startsWith("/") ? category : ("/" + category));
    }

    private String listDataTypes(int offset, int limit, String category, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        String catLc = (category == null || category.isEmpty()) ? null : category.toLowerCase();
        String filtLc = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();

        List<String> lines = new ArrayList<>();
        Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            String path = dt.getPathName();
            String name = dt.getName();
            if (catLc != null && !path.toLowerCase().contains(catLc)) continue;
            if (filtLc != null && !name.toLowerCase().contains(filtLc)) continue;
            int len = -1;
            try { len = dt.getLength(); } catch (Exception ignored) {}
            lines.add(String.format("%s (size=%s)", path, len >= 0 ? Integer.toString(len) : "?"));
        }
        Collections.sort(lines);
        return Util.paginateList(lines, offset, limit);
    }

    private String getDataTypeDefinition(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt == null) return "Data type not found: " + name;

        StringBuilder sb = new StringBuilder();
        sb.append("path: ").append(dt.getPathName()).append('\n');
        sb.append("size: ").append(safeLen(dt)).append('\n');

        if (dt instanceof ghidra.program.model.data.Structure) {
            ghidra.program.model.data.Structure st = (ghidra.program.model.data.Structure) dt;
            sb.append("struct ").append(st.getName()).append(" {\n");
            for (ghidra.program.model.data.DataTypeComponent c : st.getDefinedComponents()) {
                sb.append(String.format("  %d: %s %s",
                    c.getOffset(),
                    c.getDataType().getName(),
                    c.getFieldName() != null ? c.getFieldName() : ("field_" + c.getOrdinal())));
                if (c.getComment() != null && !c.getComment().isEmpty()) {
                    sb.append("  // ").append(c.getComment());
                }
                sb.append('\n');
            }
            sb.append("}\n");
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
            sb.append("enum ").append(en.getName()).append(" (size=").append(en.getLength()).append(") {\n");
            for (String vn : en.getNames()) {
                sb.append(String.format("  %s = %d%n", vn, en.getValue(vn)));
            }
            sb.append("}\n");
        } else if (dt instanceof ghidra.program.model.data.TypeDef) {
            ghidra.program.model.data.TypeDef td = (ghidra.program.model.data.TypeDef) dt;
            sb.append("typedef ").append(td.getDataType().getName())
              .append(" ").append(td.getName()).append('\n');
        } else {
            sb.append(dt.toString()).append('\n');
        }
        return sb.toString();
    }

    private int safeLen(DataType dt) {
        try { return dt.getLength(); } catch (Exception e) { return -1; }
    }

    @SuppressWarnings("unchecked")
    private String createStructFromJson(String body) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Object parsed;
        try { parsed = Util.MiniJson.parse(body); }
        catch (Exception e) { return "Invalid JSON: " + e.getMessage(); }
        if (!(parsed instanceof Map)) return "Expected JSON object at root";

        Map<String, Object> root = (Map<String, Object>) parsed;
        Object nameObj = root.get("name");
        Object fieldsObj = root.get("fields");
        if (!(nameObj instanceof String) || ((String) nameObj).isEmpty()) return "Missing 'name'";
        if (!(fieldsObj instanceof List)) return "Missing 'fields' array";
        final String structName = (String) nameObj;
        final List<Object> fields = (List<Object>) fieldsObj;
        final String category = root.get("category") instanceof String ? (String) root.get("category") : null;
        final boolean packed = Boolean.TRUE.equals(root.get("packed"));

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create struct " + structName);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    StructureDataType st = new StructureDataType(toCategoryPath(category), structName, 0, dtm);
                    if (packed) st.setToDefaultPacking();

                    int idx = 0;
                    for (Object f : fields) {
                        if (!(f instanceof Map)) {
                            err.append("Field ").append(idx).append(" is not an object");
                            return;
                        }
                        Map<String, Object> field = (Map<String, Object>) f;
                        Object fname = field.get("name");
                        Object ftype = field.get("type");
                        if (!(fname instanceof String) || !(ftype instanceof String)) {
                            err.append("Field ").append(idx).append(" missing name or type");
                            return;
                        }
                        DataType fdt = resolveDataType(dtm, (String) ftype);
                        if (fdt == null) {
                            err.append("Field ").append(idx).append(": unknown type ").append(ftype);
                            return;
                        }
                        Object offObj = field.get("offset");
                        if (offObj instanceof Number) {
                            int desired = ((Number) offObj).intValue();
                            int cur = st.getLength();
                            if (desired < cur) {
                                err.append("Field ").append(idx).append(": offset ")
                                   .append(desired).append(" < current size ").append(cur);
                                return;
                            }
                            if (desired > cur) st.growStructure(desired - cur);
                        }
                        st.add(fdt, fdt.getLength(), (String) fname, null);
                        idx++;
                    }
                    dtm.addDataType(st, DataTypeConflictHandler.DEFAULT_HANDLER);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Create struct error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? ("Struct created: " + structName) : ("Failed to create struct: " + err);
    }

    @SuppressWarnings("unchecked")
    private String createEnumFromJson(String body) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Object parsed;
        try { parsed = Util.MiniJson.parse(body); }
        catch (Exception e) { return "Invalid JSON: " + e.getMessage(); }
        if (!(parsed instanceof Map)) return "Expected JSON object at root";

        Map<String, Object> root = (Map<String, Object>) parsed;
        Object nameObj = root.get("name");
        Object sizeObj = root.get("size");
        Object valuesObj = root.get("values");
        if (!(nameObj instanceof String) || ((String) nameObj).isEmpty()) return "Missing 'name'";
        if (!(sizeObj instanceof Number)) return "Missing 'size' (1, 2, 4 or 8)";
        if (!(valuesObj instanceof List)) return "Missing 'values' array";
        final String enumName = (String) nameObj;
        final int size = ((Number) sizeObj).intValue();
        final List<Object> values = (List<Object>) valuesObj;
        final String category = root.get("category") instanceof String ? (String) root.get("category") : null;

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum " + enumName);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    EnumDataType en = new EnumDataType(toCategoryPath(category), enumName, size, dtm);
                    int idx = 0;
                    for (Object v : values) {
                        if (!(v instanceof Map)) {
                            err.append("Value ").append(idx).append(" is not an object");
                            return;
                        }
                        Map<String, Object> val = (Map<String, Object>) v;
                        Object vname = val.get("name");
                        Object vvalue = val.get("value");
                        if (!(vname instanceof String) || !(vvalue instanceof Number)) {
                            err.append("Value ").append(idx).append(" missing name or numeric value");
                            return;
                        }
                        en.add((String) vname, ((Number) vvalue).longValue());
                        idx++;
                    }
                    dtm.addDataType(en, DataTypeConflictHandler.DEFAULT_HANDLER);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Create enum error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? ("Enum created: " + enumName) : ("Failed to create enum: " + err);
    }

    private String createTypedef(String name, String targetType, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Name is required";
        if (targetType == null || targetType.isEmpty()) return "Target type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef " + name);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType target = resolveDataType(dtm, targetType);
                    if (target == null) {
                        err.append("Unknown target type: ").append(targetType);
                        return;
                    }
                    TypedefDataType td = new TypedefDataType(toCategoryPath(category), name, target, dtm);
                    dtm.addDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Create typedef error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? ("Typedef created: " + name) : ("Failed to create typedef: " + err);
    }

    private String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (typeName == null || typeName.isEmpty()) return "type_name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply data type " + typeName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        err.append("Invalid address: ").append(addressStr);
                        return;
                    }
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = resolveDataType(dtm, typeName);
                    if (dt == null) {
                        err.append("Unknown type: ").append(typeName);
                        return;
                    }
                    int len = dt.getLength();
                    Listing listing = program.getListing();
                    if (clearExisting && len > 0) {
                        listing.clearCodeUnits(addr, addr.add(len - 1), false);
                    }
                    listing.createData(addr, dt);
                    success.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Apply data type error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get()
            ? ("Applied " + typeName + " at " + addressStr)
            : ("Failed to apply data type: " + err + " (pass clear_existing=true to overwrite)");
    }

    private String deleteDataType(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete data type " + name);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, name);
                    if (dt == null) {
                        err.append("Not found: ").append(name);
                        return;
                    }
                    success.set(dtm.remove(dt));
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "Delete data type error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute on Swing thread: " + e.getMessage();
        }
        return success.get() ? ("Deleted: " + name) : ("Failed to delete: " + err);
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
