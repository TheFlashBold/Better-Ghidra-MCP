# better-ghidra-mcp

A Ghidra plugin that exposes the Ghidra API as an MCP (Model Context Protocol) server. This allows AI assistants like Claude to directly interact with Ghidra for reverse engineering tasks — no bridge or proxy needed.

## Why "Better"?

This is a drop-in replacement for [ghidra-mcp](https://github.com/bethington/ghidra-mcp) that fixes its core architectural problems:

| | ghidra-mcp | better-ghidra-mcp |
|---|---|---|
| **Architecture** | Ghidra plugin (REST) + Python bridge (MCP) — two processes, two failure points | Single Ghidra plugin speaks MCP natively |
| **Connection** | `stdio` → Python → HTTP → Ghidra | `http` → Ghidra (direct) |
| **Dependencies** | Python, pip, requests, mcp SDK | None (just the JAR) |
| **Setup** | Install plugin, install Python package, configure bridge script | Install plugin, add URL to `.mcp.json` |
| **Tools** | ~30 | 160+ |
| **Inline scripting** | No | Yes — run arbitrary Java code as GhidraScript |
| **Multi-program** | No | Yes — switch between open programs |
| **Data types** | Basic listing | Full CRUD for structs, enums, unions, typedefs, pointers, arrays |
| **Batch operations** | No | Yes — batch rename, batch comments, batch decompile |
| **Protocol** | MCP over stdio (requires bridge process) | MCP Streamable HTTP (direct connection) |

### The bridge problem

ghidra-mcp requires a Python process that translates between MCP (stdio) and REST (HTTP). This means:
- Two processes to manage and debug
- Extra latency on every call
- Python + pip as runtime dependencies
- The bridge can crash independently of Ghidra
- Version mismatches between bridge and plugin

better-ghidra-mcp eliminates all of this. The Ghidra plugin *is* the MCP server. Claude connects directly.

## Features

- Native MCP protocol (JSON-RPC 2.0 over HTTP) — connects directly, no Python bridge
- 160+ tools covering functions, data types, symbols, memory, scripts, and analysis
- Decompile and disassemble functions
- Rename functions, variables, and labels
- Create and modify structs, enums, unions, typedefs
- Cross-reference analysis
- Run Ghidra scripts (from file or inline Java)
- Multi-program support

## Requirements

- Ghidra 11.0+ (tested with 12.0.2)
- JDK 17+

## Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./build.sh
```

## Install

Copy the JAR to your Ghidra extensions:

```bash
mkdir -p ~/.ghidra/.ghidra_$(basename $GHIDRA_INSTALL_DIR)/Extensions/GhidraMCP/lib
cp extension.properties ~/.ghidra/.ghidra_$(basename $GHIDRA_INSTALL_DIR)/Extensions/GhidraMCP/
cp build/GhidraMCP.jar ~/.ghidra/.ghidra_$(basename $GHIDRA_INSTALL_DIR)/Extensions/GhidraMCP/lib/
```

Or use the install script:

```bash
./install.sh
```

Then restart Ghidra. The plugin starts an HTTP server on port **8089**.

## Configure Claude Code

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:8089/mcp"
    }
  }
}
```

## Architecture

```
src/main/java/ghidramcp/
├── GhidraMCPPlugin.java      # Plugin entry point, starts HTTP server
├── mcp/
│   └── McpServer.java        # MCP protocol handler (JSON-RPC 2.0)
└── tools/
    ├── ToolHelper.java        # Shared utilities (address parsing, etc.)
    ├── FunctionTools.java     # Decompile, rename, call graphs, comments
    ├── DataTypeTools.java     # Structs, enums, unions, type management
    ├── SymbolTools.java       # Labels, xrefs, imports, exports, strings
    ├── MemoryTools.java       # Memory reads, hex dumps
    ├── ProgramTools.java      # Program info, open/switch/save programs
    ├── AnalysisTools.java     # Auto-analysis, malware detection
    └── ScriptTools.java       # Run Ghidra scripts (file or inline)
```

The plugin speaks MCP Streamable HTTP transport on a single `/mcp` endpoint. No external dependencies beyond what Ghidra bundles (Gson).

## License

MIT
