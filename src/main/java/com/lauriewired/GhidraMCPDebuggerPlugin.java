package com.lauriewired;

import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchConfigurator;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.PromptMode;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.RelPrompt;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Companion plugin that runs in the Ghidra Debugger tool (the sibling of the
 * CodeBrowser tool). Exposes runtime debugger control — execution state,
 * step/resume, memory/register read+write, breakpoints — over HTTP so the
 * Python MCP bridge can reach it the same way it reaches the static plugin.
 *
 * Listens on a separate port (default 18081) to avoid colliding with the
 * CodeBrowser plugin on 8080 when both tools are open at once.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = DebuggerPluginPackage.NAME,
    category = PluginCategoryNames.DEBUGGER,
    shortDescription = "GhidraMCP Debugger HTTP server",
    description = "Exposes FlatDebuggerAPI runtime control over HTTP for the MCP bridge. "
        + "Port configurable via Tool Options."
)
public class GhidraMCPDebuggerPlugin extends Plugin {

    private static final String OPTION_CATEGORY_NAME = "GhidraMCP Debugger HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 18081;
    private static final int MAX_READ_BYTES = 4096;

    private HttpServer server;
    private final FlatDebuggerAPI api;

    public GhidraMCPDebuggerPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPDebuggerPlugin loading...");

        this.api = new FlatDebuggerAPI() {
            @Override
            public GhidraState getState() {
                ProgramManager pm = tool.getService(ProgramManager.class);
                Program prog = pm != null ? pm.getCurrentProgram() : null;
                return new GhidraState(tool, tool.getProject(), prog, null, null, null);
            }
        };

        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT, null,
            "Port for the embedded HTTP server that exposes debugger control. "
          + "Requires tool restart to apply.");

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start Debugger HTTP server", e);
        }
        Msg.info(this, "GhidraMCPDebuggerPlugin loaded.");
    }

    private void startServer() throws IOException {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        if (server != null) {
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/dbg/ping", exchange -> {
            Util.sendResponse(exchange, "ok — GhidraMCPDebuggerPlugin active in tool=" + tool.getName());
        });

        // ---- Execution control ----
        // Steps return a diff JSON (before_pc/after_pc/instruction/changed_registers);
        // resume/interrupt/kill stay text/plain ok|failed — their "diff" is
        // basically the whole trace state, not a single instruction delta.
        server.createContext("/dbg/resume",    exchange -> Util.sendResponse(exchange, runBool("resume", api::resume)));
        server.createContext("/dbg/step_into", exchange -> Util.sendJson(exchange, stepDetailed("step_into", api::stepInto)));
        server.createContext("/dbg/step_over", exchange -> Util.sendJson(exchange, stepDetailed("step_over", api::stepOver)));
        server.createContext("/dbg/step_out",  exchange -> Util.sendJson(exchange, stepDetailed("step_out", api::stepOut)));
        server.createContext("/dbg/interrupt", exchange -> Util.sendResponse(exchange, runBool("interrupt", api::interrupt)));
        server.createContext("/dbg/kill",      exchange -> Util.sendResponse(exchange, runBool("kill", api::kill)));

        // ---- State inspection ----
        server.createContext("/dbg/state",           exchange -> Util.sendResponse(exchange, getStateString()));
        server.createContext("/dbg/list_threads",    exchange -> Util.sendResponse(exchange, listThreadsString()));
        server.createContext("/dbg/list_frames",     exchange -> Util.sendResponse(exchange, listFramesString()));
        server.createContext("/dbg/read_registers", exchange -> {
            var q = Util.parseQueryParams(exchange);
            Util.sendResponse(exchange, readRegistersString(q.get("filter")));
        });

        // ---- Memory + register write ----
        server.createContext("/dbg/read_memory", exchange -> {
            var q = Util.parseQueryParams(exchange);
            int length = Util.parseIntOrDefault(q.get("length"), 16);
            Util.sendResponse(exchange, readMemoryString(q.get("address"), length, q.get("format")));
        });
        server.createContext("/dbg/write_memory", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, writeMemoryString(p.get("address"), p.get("bytes_hex")));
        });
        server.createContext("/dbg/write_register", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, writeRegisterString(p.get("name"), p.get("value")));
        });

        // ---- Breakpoints ----
        server.createContext("/dbg/set_breakpoint", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, setBreakpointString(p.get("address")));
        });
        server.createContext("/dbg/remove_breakpoint", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, removeBreakpointString(p.get("address")));
        });
        server.createContext("/dbg/list_breakpoints", exchange -> Util.sendResponse(exchange, listBreakpointsString()));

        // ---- Launcher autonomy (Milestone 3) ----
        server.createContext("/dbg/list_launchers", exchange -> Util.sendResponse(exchange, listLaunchersString()));
        server.createContext("/dbg/launch", exchange -> {
            String body = Util.readBody(exchange);
            Util.sendResponse(exchange, launchFromJson(body));
        });
        server.createContext("/dbg/launch_gdb", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, launchWrapper("gdb", p.get("binary_path"), p.get("args")));
        });
        server.createContext("/dbg/launch_dbgeng", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, launchWrapper("dbgeng", p.get("binary_path"), p.get("args")));
        });
        server.createContext("/dbg/execute", exchange -> {
            var p = Util.parsePostParams(exchange);
            Util.sendResponse(exchange, executeCommand(p.get("command")));
        });
        server.createContext("/dbg/disconnect", exchange -> Util.sendResponse(exchange, disconnectSession()));

        // Thread pool so a long-running handler (launchProgram can stall 30s+ while
        // Python boots pybag+dbgmodel) doesn't block /dbg/state or /dbg/ping on the
        // same server.
        server.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "GhidraMCP-Debugger-HTTP-Worker");
            t.setDaemon(true);
            return t;
        }));
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP Debugger HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start Debugger HTTP server on port " + port, e);
                server = null;
            }
        }, "GhidraMCP-Debugger-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Handlers
    // ----------------------------------------------------------------------------------

    @FunctionalInterface
    private interface BoolAction { boolean run(); }

    /**
     * Snapshot general-purpose registers (RIP, RFLAGS, RAX, ...) as
     * name → "0xhex". Used for the step diff.
     */
    private Map<String, String> snapshotGeneralRegs() {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            TracePlatform plat = api.getCurrentPlatform();
            if (plat == null) return out;
            List<String> names = plat.getLanguage().getRegisters().stream()
                .map(Register::getName)
                .filter(n -> regCategory(n).equals("general"))
                .collect(Collectors.toList());
            List<RegisterValue> vals = api.readRegistersNamed(names);
            for (RegisterValue rv : vals) {
                if (rv == null) continue;
                BigInteger v = rv.getUnsignedValue();
                out.put(rv.getRegister().getName(), v != null ? ("0x" + v.toString(16)) : "?");
            }
        } catch (Exception ignore) { /* best-effort */ }
        return out;
    }

    /**
     * Run a step action and emit a structured JSON diff: before/after PC,
     * which instruction was executed (looked up on the pre-step PC), and
     * which general-purpose registers changed value. Agents no longer need
     * a second /dbg/state round-trip after every step.
     */
    private String stepDetailed(String label, BoolAction action) {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "{\"error\":\"No active debug session\"}";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("action", label);
        try {
            Address beforePc = api.getProgramCounter();
            Map<String, String> before = snapshotGeneralRegs();
            String instrStr = null;
            try {
                if (beforePc != null && api.getCurrentView() != null) {
                    Instruction instr = api.getCurrentView().getListing().getInstructionAt(beforePc);
                    if (instr != null) instrStr = instr.toString();
                }
            } catch (Exception ignore) {}

            boolean ok = action.run();
            // flushAsyncPipelines + waitForBreak together: the flush forces
            // queued updates to land, waitForBreak pauses until the trace
            // reports STOPPED again. Without the wait, a fast read can race
            // the coordinate update and see the pre-step snap (reproduced
            // deterministically on alternating steps against a dbgeng target).
            try { api.flushAsyncPipelines(trace); } catch (Exception ignore) {}
            try {
                api.waitForBreak(trace, 2, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignore) { /* timeout or already stopped — proceed */ }
            try { api.flushAsyncPipelines(trace); } catch (Exception ignore) {}

            Address afterPc = null;
            try {
                // Prefer reading RIP directly — the Trace coordinates snapshot
                // can lag even after waitForBreak, but a direct register read
                // hits the current trace snap unambiguously.
                RegisterValue rip = api.readRegister("RIP");
                if (rip != null && rip.getUnsignedValue() != null) {
                    afterPc = trace.getBaseAddressFactory().getDefaultAddressSpace()
                        .getAddress(rip.getUnsignedValue().longValue());
                }
            } catch (Exception ignore) {}
            if (afterPc == null) {
                try {
                    var coords = api.getCurrentDebuggerCoordinates();
                    afterPc = coords != null ? api.getProgramCounter(coords) : api.getProgramCounter();
                } catch (Exception ignore) {}
            }
            Map<String, String> after = snapshotGeneralRegs();

            out.put("success", ok);
            out.put("before_pc", beforePc != null ? beforePc.toString() : null);
            out.put("after_pc", afterPc != null ? afterPc.toString() : null);
            out.put("instruction", instrStr);
            Map<String, String> diff = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : after.entrySet()) {
                String bv = before.get(e.getKey());
                String av = e.getValue();
                boolean differs = (bv == null) ? (av != null) : !bv.equals(av);
                if (differs) diff.put(e.getKey(), (bv == null ? "?" : bv) + " -> " + av);
            }
            out.put("changed_registers", diff);
            return Util.toJson(out);
        } catch (Exception e) {
            out.put("success", false);
            out.put("error", e.getClass().getSimpleName() + ": "
                + (e.getMessage() == null ? "" : e.getMessage()));
            return Util.toJson(out);
        }
    }

    private String runBool(String label, BoolAction action) {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "No active debug session";
        try {
            boolean ok = action.run();
            // Force the Trace view to catch up with backend state before this
            // response returns. Without it, a /state call issued immediately
            // after stepInto still reports the pre-step PC because the async
            // update hadn't landed yet.
            try { api.flushAsyncPipelines(trace); } catch (Exception ignore) {}
            return ok ? (label + ": ok") : (label + ": failed");
        } catch (Exception e) {
            return label + " error: " + e.getMessage();
        }
    }

    private String getStateString() {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "No active debug session";
        try {
            // Reading PC through the current DebuggerCoordinates forces the
            // value to come from the active thread+snap, not a cached initial
            // frame. Without this a /state issued right after /step_into kept
            // reporting the pre-step PC.
            var coords = api.getCurrentDebuggerCoordinates();
            TraceExecutionState state = api.getExecutionState(trace);
            TraceThread thread = api.getCurrentThread();
            long snap = api.getCurrentSnap();
            Address pc = coords != null ? api.getProgramCounter(coords) : api.getProgramCounter();
            StringBuilder sb = new StringBuilder();
            sb.append("execution_state: ").append(state).append('\n');
            sb.append("trace: ").append(trace.getName()).append('\n');
            sb.append("thread: ").append(thread != null ? thread.getName(snap) : "(none)").append('\n');
            sb.append("thread_id: ").append(thread != null ? thread.getKey() : -1).append('\n');
            sb.append("pc: ").append(pc != null ? pc.toString() : "(unknown)").append('\n');
            sb.append("frame: ").append(api.getCurrentFrame()).append('\n');
            sb.append("snap: ").append(snap).append('\n');
            sb.append("target_alive: ").append(api.isTargetAlive());
            return sb.toString();
        } catch (Exception e) {
            // After /dbg/disconnect the Trace reference survives briefly but
            // any backend-touching call raises TraceRmiError: "Socket closed".
            // Report that as a clean "no session" instead of a stack-ish error.
            String msg = e.getMessage() == null ? "" : e.getMessage();
            if (msg.contains("Socket closed") || msg.contains("TraceRmiError")
                    || e.getClass().getSimpleName().contains("TraceRmiError")) {
                return "No active debug session (trace terminated)";
            }
            return "Error: " + e.getMessage();
        }
    }

    private String listThreadsString() {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "No active debug session";
        try {
            StringBuilder sb = new StringBuilder();
            long snap = api.getCurrentSnap();
            for (TraceThread t : trace.getThreadManager().getAllThreads()) {
                sb.append(t.getKey()).append(" | ")
                  .append(t.getName(snap)).append(" | alive=")
                  .append(api.isThreadAlive(t)).append('\n');
            }
            return sb.length() == 0 ? "No threads" : sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String listFramesString() {
        if (api.getCurrentTrace() == null) return "No active debug session";
        Address pc = api.getProgramCounter();
        return String.format("#%d pc=%s (v1 exposes only the current frame)",
            api.getCurrentFrame(),
            pc != null ? pc.toString() : "(unknown)");
    }

    // x86/x64 general-purpose set the agent actually reads when inspecting
    // call state. Explicit whitelist beats a broad else-branch: dbgeng exposes
    // DR*, CR*, BND*, bit-flags (CF/ZF/PF/...), decoder internals
    // (rexWprefix, longMode, evex*) and FPU state as top-level names too.
    // We bucket those out instead of pretending they're "general".
    private static final java.util.Set<String> GENERAL_REGS = java.util.Set.of(
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
        "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
        "RIP", "EIP",
        "RFLAGS", "EFLAGS", "FLAGS", "rflags", "eflags", "flags",
        "CS", "DS", "ES", "FS", "GS", "SS", "FS_OFFSET", "GS_OFFSET"
    );

    /**
     * Classify a register by name into general / float / vector.
     *  - general: explicit whitelist of the x86/x64 GP registers + RIP +
     *    RFLAGS + segment regs (no sub-registers like AX/AL, no bit flags,
     *    no debug/control registers, no decoder internals).
     *  - vector: XMM/YMM/ZMM, K0-K7 mask registers, MXCSR.
     *  - float: x87 ST*, MMX MM*, FPR*, FPU* control words.
     *  - everything else ends up in "other" and is visible only with filter=all.
     */
    private static String regCategory(String name) {
        if (GENERAL_REGS.contains(name)) return "general";
        String u = name.toUpperCase();
        if (u.startsWith("XMM") || u.startsWith("YMM") || u.startsWith("ZMM")
                || (u.length() == 2 && u.charAt(0) == 'K' && Character.isDigit(u.charAt(1)))
                || u.equals("MXCSR")) {
            return "vector";
        }
        if (u.startsWith("ST") || u.startsWith("MM") || u.startsWith("FPR")
                || u.startsWith("FPU") || u.equals("FPCW") || u.equals("FPSW") || u.equals("FPTW")) {
            return "float";
        }
        return "other";
    }

    private String readRegistersString(String filter) {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "No active debug session";
        try {
            TracePlatform plat = api.getCurrentPlatform();
            if (plat == null) return "No current platform";
            String f = (filter == null || filter.isEmpty()) ? "general" : filter.toLowerCase();
            List<String> names = plat.getLanguage().getRegisters().stream()
                .map(Register::getName)
                .filter(n -> f.equals("all") || f.equals(regCategory(n)))
                .collect(Collectors.toList());
            if (names.isEmpty()) return "No registers match filter=" + f
                + " (try filter=general|float|vector|all)";
            List<RegisterValue> vals = api.readRegistersNamed(names);
            StringBuilder sb = new StringBuilder();
            for (RegisterValue rv : vals) {
                if (rv == null) continue;
                BigInteger v = rv.getUnsignedValue();
                sb.append(rv.getRegister().getName())
                  .append(": 0x").append(v != null ? v.toString(16) : "?")
                  .append('\n');
            }
            return sb.length() == 0 ? "No registers read" : sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String readMemoryString(String addrStr, int length, String format) {
        if (addrStr == null || addrStr.isEmpty()) return "address is required";
        if (length <= 0) return "length must be positive";
        if (length > MAX_READ_BYTES) {
            return "length exceeds max " + MAX_READ_BYTES + "; issue multiple calls";
        }
        if (api.getCurrentTrace() == null) return "No active debug session";
        try {
            ProgramLocation loc = api.dynamicLocation(addrStr);
            if (loc == null) return "Invalid address: " + addrStr;
            byte[] buf = api.readMemory(loc.getAddress(), length, TaskMonitor.DUMMY);
            if (buf == null) return "Read failed";
            String fmt = (format == null || format.isEmpty()) ? "hex" : format.toLowerCase();
            if ("base64".equals(fmt)) {
                return Base64.getEncoder().encodeToString(buf);
            }
            StringBuilder sb = new StringBuilder(buf.length * 2);
            for (byte b : buf) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String writeMemoryString(String addrStr, String bytesHex) {
        if (addrStr == null || addrStr.isEmpty()) return "address is required";
        if (bytesHex == null || bytesHex.isEmpty()) return "bytes_hex is required";
        if (api.getCurrentTrace() == null) return "No active debug session";
        String clean = bytesHex.replace(" ", "").replace("0x", "");
        if (clean.length() % 2 != 0) return "bytes_hex must have even length";
        byte[] buf = new byte[clean.length() / 2];
        try {
            for (int i = 0; i < buf.length; i++) {
                buf[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return "Invalid hex: " + e.getMessage();
        }
        try {
            ProgramLocation loc = api.dynamicLocation(addrStr);
            if (loc == null) return "Invalid address: " + addrStr;
            boolean ok = api.writeMemory(loc.getAddress(), buf);
            return ok ? ("Wrote " + buf.length + " bytes at " + addrStr)
                      : "Write failed (is control mode set to allow target writes?)";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String writeRegisterString(String name, String valueStr) {
        if (name == null || name.isEmpty()) return "name is required";
        if (valueStr == null || valueStr.isEmpty()) return "value is required";
        if (api.getCurrentTrace() == null) return "No active debug session";
        BigInteger value;
        try {
            String s = valueStr.trim();
            value = s.startsWith("0x") || s.startsWith("0X")
                ? new BigInteger(s.substring(2), 16)
                : new BigInteger(s);
        } catch (NumberFormatException e) {
            return "Invalid value (use 0x... or decimal): " + valueStr;
        }
        try {
            boolean ok = api.writeRegister(name, value);
            return ok ? ("Wrote " + name + " = 0x" + value.toString(16))
                      : "Write failed (register unknown or control mode forbids writes)";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String setBreakpointString(String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return "address is required";
        if (api.getCurrentTrace() == null) return "No active debug session";
        try {
            ProgramLocation loc = api.dynamicLocation(addrStr);
            if (loc == null) return "Invalid address: " + addrStr;
            Set<LogicalBreakpoint> bps = api.breakpointSetSoftwareExecute(loc, "");
            return bps == null || bps.isEmpty()
                ? "Breakpoint not created"
                : ("Breakpoint(s) set: " + bps.size() + " at " + addrStr);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String removeBreakpointString(String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return "address is required";
        if (api.getCurrentTrace() == null) return "No active debug session";
        try {
            ProgramLocation loc = api.dynamicLocation(addrStr);
            if (loc == null) return "Invalid address: " + addrStr;
            boolean ok = api.breakpointsClear(loc);
            return ok ? ("Breakpoint(s) cleared at " + addrStr) : "No breakpoint to clear";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String listBreakpointsString() {
        if (api.getCurrentTrace() == null) return "No active debug session";
        try {
            Set<LogicalBreakpoint> bps = api.getAllBreakpoints();
            if (bps == null || bps.isEmpty()) return "No breakpoints";
            List<String> lines = new ArrayList<>();
            for (LogicalBreakpoint bp : bps) {
                lines.add(bp.toString());
            }
            return String.join("\n", lines);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Launcher autonomy (Milestone 3)
    // ----------------------------------------------------------------------------------

    /**
     * Resolve the Program to launch against: prefer the one loaded in this tool,
     * fall back to the FlatDebuggerAPI helper (may pull from a companion tool).
     */
    private Program getLaunchProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null && pm.getCurrentProgram() != null) return pm.getCurrentProgram();
        try { return api.getCurrentProgram(); } catch (Exception e) { return null; }
    }

    private TraceRmiLauncherService getLauncherService() {
        return tool.getService(TraceRmiLauncherService.class);
    }

    private String listLaunchersString() {
        TraceRmiLauncherService svc = getLauncherService();
        if (svc == null) return "TraceRmiLauncherService not available (open the Debugger tool fully)";
        Program prog = getLaunchProgram();
        if (prog == null) return "No program loaded. Open a binary in the CodeBrowser or via the Debugger tool, then retry.";
        try {
            Collection<TraceRmiLaunchOffer> offers = svc.getOffers(prog);
            if (offers == null || offers.isEmpty()) return "No launchers available for this program";
            StringBuilder sb = new StringBuilder();
            for (TraceRmiLaunchOffer off : offers) {
                sb.append(off.getConfigName()).append(" | ").append(off.getTitle());
                String desc = off.getDescription();
                if (desc != null && !desc.isEmpty()) sb.append(" | ").append(desc.replace('\n', ' '));
                Map<String, LaunchParameter<?>> params = off.getParameters();
                if (params != null && !params.isEmpty()) {
                    sb.append("\n    params: ");
                    boolean first = true;
                    for (LaunchParameter<?> p : params.values()) {
                        if (!first) sb.append(", ");
                        sb.append(p.name()).append(":").append(p.type().getSimpleName());
                        if (p.required()) sb.append("*");
                        first = false;
                    }
                }
                sb.append('\n');
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error listing launchers: " + e.getMessage();
        }
    }

    /**
     * Build a LaunchConfigurator that injects the given raw (string-valued)
     * args into the offer's parameter map, leaving untouched params at their
     * defaults. Uses PromptMode.NEVER so nothing pops a modal in headless/MCP.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private LaunchConfigurator buildConfigurator(Map<String, String> rawArgs) {
        return new LaunchConfigurator() {
            @Override public PromptMode getPromptMode() { return PromptMode.NEVER; }
            @Override
            public Map<String, ValStr<?>> configureLauncher(
                    TraceRmiLaunchOffer offer,
                    Map<String, ValStr<?>> defaults,
                    RelPrompt relPrompt) {
                Map<String, ValStr<?>> out = new LinkedHashMap<>(defaults);
                Map<String, LaunchParameter<?>> params = offer.getParameters();
                for (Map.Entry<String, String> e : rawArgs.entrySet()) {
                    LaunchParameter<?> p = params.get(e.getKey());
                    if (p == null) continue; // silently ignore unknown keys
                    try {
                        ValStr<?> decoded = ((LaunchParameter) p).decode(e.getValue());
                        out.put(e.getKey(), decoded);
                    } catch (Exception ex) {
                        Msg.warn(this, "Bad value for " + e.getKey() + ": " + ex.getMessage());
                    }
                }
                return out;
            }
        };
    }

    private String describeLaunchResult(String launcherId, LaunchResult res) {
        if (res == null) return "Launch returned null";
        StringBuilder sb = new StringBuilder();
        sb.append("launcher: ").append(launcherId).append('\n');
        // LaunchResult is a record where `trace` and `exception` can both be
        // non-null (dbgeng in particular reports soft errors alongside a usable
        // trace). Treat the existence of a trace as the authoritative signal
        // of success; surface the exception as a warning instead of failing.
        boolean hasTrace = res.trace() != null;
        Throwable ex = res.exception();
        if (hasTrace) {
            sb.append("status: ok\n");
            sb.append("trace: ").append(res.trace().getName()).append('\n');
            if (res.connection() != null) {
                sb.append("connection: ").append(res.connection().getDescription()).append('\n');
            }
            if (res.sessions() != null && !res.sessions().isEmpty()) {
                sb.append("sessions: ").append(res.sessions().keySet()).append('\n');
            }
            if (ex != null) {
                sb.append("warning: ").append(ex.getClass().getSimpleName())
                  .append(": ").append(ex.getMessage());
            }
            return sb.toString();
        }
        sb.append("status: failed\n");
        if (ex != null) {
            sb.append("error: ").append(ex.getClass().getSimpleName())
              .append(": ").append(ex.getMessage());
        } else {
            sb.append("error: unknown (no trace created, no exception reported)");
        }
        return sb.toString();
    }

    private String launchFromJson(String body) {
        if (body == null || body.isBlank()) return "Empty body; expected JSON {launcher_id, args}";
        Object parsed;
        try { parsed = Util.MiniJson.parse(body); }
        catch (Exception e) { return "Invalid JSON: " + e.getMessage(); }
        if (!(parsed instanceof Map)) return "Expected JSON object at root";
        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) parsed;
        Object idObj = root.get("launcher_id");
        if (!(idObj instanceof String)) return "Missing 'launcher_id'";
        String launcherId = (String) idObj;

        Map<String, String> rawArgs = new HashMap<>();
        Object argsObj = root.get("args");
        if (argsObj instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) argsObj).entrySet()) {
                if (e.getValue() != null) rawArgs.put(e.getKey().toString(), e.getValue().toString());
            }
        }
        return launchById(launcherId, rawArgs, false);
    }

    private String launchWrapper(String hint, String binaryPath, String argsLine) {
        Map<String, String> rawArgs = new HashMap<>();
        if (binaryPath != null && !binaryPath.isEmpty()) {
            // Common parameter name across offers; if the specific offer uses
            // a different name, the image parameter is set via imageParameter below.
            rawArgs.put("image", binaryPath);
        }
        if (argsLine != null && !argsLine.isEmpty()) rawArgs.put("args", argsLine);
        return launchById(hint, rawArgs, true);
    }

    /**
     * Look up an offer by exact configName, or (if fuzzy=true) the first offer
     * whose configName contains `idOrHint`. Then inject rawArgs and launch.
     */
    private String launchById(String idOrHint, Map<String, String> rawArgs, boolean fuzzy) {
        TraceRmiLauncherService svc = getLauncherService();
        if (svc == null) return "TraceRmiLauncherService not available";
        Program prog = getLaunchProgram();
        if (prog == null) return "No program loaded; load a binary before launching";
        Collection<TraceRmiLaunchOffer> offers;
        try {
            offers = svc.getOffers(prog);
        } catch (Exception e) {
            return "Error listing offers: " + e.getMessage();
        }
        if (offers == null || offers.isEmpty()) return "No launchers available for this program";

        TraceRmiLaunchOffer match = null;
        for (TraceRmiLaunchOffer off : offers) {
            if (idOrHint.equals(off.getConfigName())) { match = off; break; }
        }
        if (match == null && fuzzy) {
            String lc = idOrHint.toLowerCase();
            for (TraceRmiLaunchOffer off : offers) {
                if (off.getConfigName().toLowerCase().contains(lc)) { match = off; break; }
            }
        }
        if (match == null) {
            return "Launcher not found: " + idOrHint
                + "\n(available: "
                + offers.stream().map(TraceRmiLaunchOffer::getConfigName).collect(Collectors.joining(", "))
                + ")";
        }

        // Translate "image" alias to the offer's actual image parameter name if present.
        LaunchParameter<?> imgParam = match.imageParameter();
        if (imgParam != null && rawArgs.containsKey("image") && !rawArgs.containsKey(imgParam.name())) {
            rawArgs.put(imgParam.name(), rawArgs.remove("image"));
        }

        LaunchConfigurator cfg = buildConfigurator(rawArgs);
        try {
            LaunchResult res = match.launchProgram(new ConsoleTaskMonitor(), cfg);
            return describeLaunchResult(match.getConfigName(), res);
        } catch (Exception e) {
            return "Launch threw: " + e.getMessage();
        }
    }

    private String executeCommand(String command) {
        if (command == null || command.isEmpty()) return "command is required";
        if (api.getCurrentTrace() == null) return "No active debug session";
        try {
            String out = api.executeCapture(command);
            return out == null ? "" : out;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String disconnectSession() {
        Trace trace = api.getCurrentTrace();
        if (trace == null) return "No active debug session";
        StringBuilder warn = new StringBuilder();
        // Kill is a best-effort — some backends raise if the target already
        // exited. Keep going and still close the trace either way.
        try {
            api.kill();
        } catch (Exception e) {
            warn.append("kill raised: ").append(e.getMessage()).append("; ");
        }
        // closeTrace(Trace) on FlatDebuggerAPI shows a modal dialog if the
        // trace has unsaved changes; closeTraceNoConfirm skips it and actually
        // detaches the trace from the tool so the next /state returns "No
        // active debug session".
        DebuggerTraceManagerService traceMgr = tool.getService(DebuggerTraceManagerService.class);
        try {
            if (traceMgr != null) {
                traceMgr.closeTraceNoConfirm(trace);
            } else {
                api.closeTrace(trace);
            }
        } catch (Exception e) {
            return "Session killed but trace close failed: " + e.getMessage();
        }
        String suffix = warn.length() > 0 ? (" (warn: " + warn + ")") : "";
        return "Session terminated" + suffix;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP Debugger HTTP server...");
            server.stop(1);
            server = null;
            Msg.info(this, "GhidraMCP Debugger HTTP server stopped.");
        }
        super.dispose();
    }
}
