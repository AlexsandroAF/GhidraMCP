# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, payload: dict) -> str:
    """POST with application/json body. Used for structured payloads
    (create_struct/create_enum) where form-encoding would be awkward."""
    try:
        url = urljoin(ghidra_server_url, endpoint)
        response = requests.post(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a user-defined label at the given address.
    """
    return safe_post("create_label", {"address": address, "name": name})

@mcp.tool()
def remove_label(address: str, name: str = "") -> str:
    """
    Remove a label at the given address. If name is empty, removes the primary
    non-default symbol at that address.
    """
    return safe_post("remove_label", {"address": address, "name": name})

@mcp.tool()
def list_labels(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List user-meaningful labels (functions + standalone labels). Filter is a
    case-insensitive substring match on the symbol name.
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_labels", params)

@mcp.tool()
def set_bookmark(address: str, category: str = "", comment: str = "") -> str:
    """
    Set a Note-type bookmark at the given address. Overwrites any existing
    bookmark with the same category at that address.
    """
    return safe_post("set_bookmark", {
        "address": address, "category": category, "comment": comment,
    })

@mcp.tool()
def remove_bookmark(address: str, category: str = "") -> str:
    """
    Remove the Note-type bookmark at the address matching the given category.
    """
    return safe_post("remove_bookmark", {"address": address, "category": category})

@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List Note-type bookmarks with pagination. If category is provided, only
    bookmarks with that exact category are returned.
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_bookmarks", params)

@mcp.tool()
def read_bytes(address: str, length: int = 16, format: str = "hex") -> str:
    """
    Read raw bytes from memory starting at address. Length is capped at 4096
    bytes on the server side. format: "hex" (default) or "base64".
    """
    return "\n".join(safe_get("read_bytes", {
        "address": address, "length": length, "format": format,
    }))

@mcp.tool()
def decompile_with_map(address: str = "", name: str = "") -> list:
    """
    Decompile a function and return each source line prefixed with the minimum
    address among its tokens. Pass either address or name (address wins if both).
    Lines look like: "0x401000 | void main(int argc, char **argv) {".
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return safe_get("decompile_with_map", params)

@mcp.tool()
def get_high_pcode(address: str) -> list:
    """
    Get the high-level (post-decompilation) P-code ops for the function at
    or containing the given address. One op per line, prefixed with its
    sequence address.
    """
    return safe_get("get_high_pcode", {"address": address})

@mcp.tool()
def get_pcode(address: str, length: int = 0) -> list:
    """
    Get raw P-code per instruction. If length > 0, walks N instructions from
    the given address. If length is 0, walks the whole function body at that
    address. Each line is "<instr_addr>: <pcode_op>".
    """
    return safe_get("get_pcode", {"address": address, "length": length})

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100,
                    category: str = None, filter: str = None) -> list:
    """
    List data types in the Data Type Manager. Optionally filter by category path
    substring and/or name substring.
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if filter:
        params["filter"] = filter
    return safe_get("list_data_types", params)

@mcp.tool()
def get_data_type(name: str) -> str:
    """
    Dump a readable definition of a data type (struct layout, enum values,
    typedef target, or default toString).
    """
    return "\n".join(safe_get("get_data_type", {"name": name}))

@mcp.tool()
def create_struct(name: str, fields: list,
                  category: str = None, packed: bool = False) -> str:
    """
    Create a struct in the Data Type Manager.

    Args:
        name: struct name (required).
        fields: list of {"name": str, "type": str, "offset"?: int}. Types use
            the same syntax as set_local_variable_type (e.g. "int", "char*",
            "P void", or any type already in the DTM). If "offset" is given,
            padding is inserted; offset must be >= current struct size.
        category: optional "/Cat/SubCat" category path (default: root).
        packed: if true, applies default packing.
    """
    payload = {"name": name, "fields": fields}
    if category:
        payload["category"] = category
    if packed:
        payload["packed"] = True
    return safe_post_json("create_struct", payload)

@mcp.tool()
def create_enum(name: str, size: int, values: list, category: str = None) -> str:
    """
    Create an enum in the Data Type Manager.

    Args:
        name: enum name.
        size: width in bytes (1, 2, 4 or 8).
        values: list of {"name": str, "value": int}.
        category: optional category path.
    """
    payload = {"name": name, "size": size, "values": values}
    if category:
        payload["category"] = category
    return safe_post_json("create_enum", payload)

@mcp.tool()
def create_typedef(name: str, target_type: str, category: str = None) -> str:
    """
    Create a typedef aliasing target_type to name.
    """
    data = {"name": name, "targetType": target_type}
    if category:
        data["category"] = category
    return safe_post("create_typedef", data)

@mcp.tool()
def apply_data_type(address: str, type_name: str, clear_existing: bool = False) -> str:
    """
    Apply an existing data type to an address. Pass clear_existing=True to
    overwrite conflicting existing data/code units.
    """
    return safe_post("apply_data_type", {
        "address": address,
        "type_name": type_name,
        "clear_existing": "true" if clear_existing else "false",
    })

@mcp.tool()
def delete_data_type(name: str) -> str:
    """
    Remove a data type from the Data Type Manager.
    """
    return safe_post("delete_data_type", {"name": name})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

