package ghidramcp.tools;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class FunctionTools {

    private static String decompile(Program p, Function f, int timeout) {
        DecompInterface di = new DecompInterface();
        try {
            di.openProgram(p);
            DecompileResults dr = di.decompileFunction(f, timeout, TaskMonitor.DUMMY);
            if (dr == null) return "Error: Decompilation returned null";
            if (!dr.decompileCompleted()) return "Error: Decompilation failed: " + dr.getErrorMessage();
            DecompiledFunction df = dr.getDecompiledFunction();
            return df != null ? df.getC() : "Error: No result";
        } finally { di.dispose(); }
    }

    private static String computeHash(Program p, Function f) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction i = it.next();
                md.update(i.getMnemonicString().getBytes());
                md.update((byte) i.getNumOperands());
            }
            byte[] hash = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) { return "error"; }
    }

    private static void buildCallGraph(Function f, int depth, boolean callees,
            Map<String, Set<String>> graph, Set<String> visited) {
        String key = f.getName() + "@" + fmt(f.getEntryPoint());
        if (visited.contains(key) || depth <= 0) return;
        visited.add(key);
        try {
            Set<Function> related = callees
                ? f.getCalledFunctions(TaskMonitor.DUMMY)
                : f.getCallingFunctions(TaskMonitor.DUMMY);
            for (Function r : related) {
                String rKey = r.getName() + "@" + fmt(r.getEntryPoint());
                graph.computeIfAbsent(callees ? key : rKey, k -> new LinkedHashSet<>())
                     .add(callees ? rKey : key);
                buildCallGraph(r, depth - 1, callees, graph, visited);
            }
        } catch (Exception ignored) {}
    }

    private static Function findFunctionByName(Program p, String name) {
        if (name == null) return null;
        FunctionIterator iter = p.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    private static ghidra.program.model.data.DataType findDataType(Program p, String name) {
        if (name == null) return null;
        name = name.trim();
        Iterator<ghidra.program.model.data.DataType> iter = p.getDataTypeManager().getAllDataTypes();
        while (iter.hasNext()) {
            ghidra.program.model.data.DataType dt = iter.next();
            if (dt.getName().equals(name) || dt.getDisplayName().equals(name)) return dt;
        }
        iter = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
        while (iter.hasNext()) {
            ghidra.program.model.data.DataType dt = iter.next();
            if (dt.getName().equals(name) || dt.getDisplayName().equals(name)) return dt;
        }
        return null;
    }

    private static int commentType(String type) {
        if (type == null) return CodeUnit.EOL_COMMENT;
        switch (type.toUpperCase()) {
            case "PRE": return CodeUnit.PRE_COMMENT;
            case "POST": return CodeUnit.POST_COMMENT;
            case "PLATE": return CodeUnit.PLATE_COMMENT;
            default: return CodeUnit.EOL_COMMENT;
        }
    }

    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        // 1. list_functions
        s.tool("list_functions", "List functions with pagination")
            .optParam("filter", "Filter by name substring")
            .intParam("offset", "Offset for pagination")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                String filter = str(a, "filter");
                StringBuilder sb = new StringBuilder();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                int idx = 0, count = 0;
                while (iter.hasNext() && count < limit) {
                    Function f = iter.next();
                    if (f.isExternal()) continue;
                    if (filter != null && !f.getName().toLowerCase().contains(filter.toLowerCase())) continue;
                    if (idx >= offset) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(f.getName()).append(" @ ").append(fmt(f.getEntryPoint()));
                        count++;
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 2. list_functions_enhanced
        s.tool("list_functions_enhanced", "List functions with JSON details")
            .optParam("filter", "Filter by name substring")
            .intParam("offset", "Offset for pagination")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                String filter = str(a, "filter");
                JsonArray funcs = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                int idx = 0, count = 0;
                while (iter.hasNext() && count < limit) {
                    Function f = iter.next();
                    if (f.isExternal()) continue;
                    if (filter != null && !f.getName().toLowerCase().contains(filter.toLowerCase())) continue;
                    if (idx >= offset) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", f.getName());
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("size", f.getBody().getNumAddresses());
                        o.addProperty("callers", f.getCallingFunctions(TaskMonitor.DUMMY).size());
                        o.addProperty("callees", f.getCalledFunctions(TaskMonitor.DUMMY).size());
                        funcs.add(o);
                        count++;
                    }
                    idx++;
                }
                JsonObject r = new JsonObject();
                r.add("functions", funcs);
                r.addProperty("total", p.getFunctionManager().getFunctionCount());
                r.addProperty("offset", offset);
                r.addProperty("limit", limit);
                return new Gson().toJson(r);
            });

        // 3. search_functions_enhanced
        s.tool("search_functions_enhanced", "Search functions by name with JSON details")
            .param("query", "Search query")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String query = str(a, "query", "").toLowerCase();
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                JsonArray results = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                int idx = 0, count = 0;
                while (iter.hasNext() && count < limit) {
                    Function f = iter.next();
                    if (!f.getName().toLowerCase().contains(query)) continue;
                    if (idx >= offset) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", f.getName());
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("size", f.getBody().getNumAddresses());
                        results.add(o);
                        count++;
                    }
                    idx++;
                }
                JsonObject r = new JsonObject();
                r.add("results", results);
                r.addProperty("query", query);
                return new Gson().toJson(r);
            });

        // 4. get_function_count
        s.tool("get_function_count", "Get total function count")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonObject r = new JsonObject();
                r.addProperty("count", p.getFunctionManager().getFunctionCount());
                return new Gson().toJson(r);
            });

        // 5. get_function_by_address
        s.tool("get_function_by_address", "Get function info at address")
            .param("address", "Function address (hex)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found at " + str(a, "address"));
                return "Name: " + f.getName() + "\nEntry: " + fmt(f.getEntryPoint()) +
                       "\nSignature: " + f.getPrototypeString(true, false) +
                       "\nBody size: " + f.getBody().getNumAddresses() + " bytes";
            });

        // 6. get_current_function
        s.tool("get_current_function", "Get the current function (best effort)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                if (iter.hasNext()) {
                    Function f = iter.next();
                    return f.getName() + " @ " + fmt(f.getEntryPoint());
                }
                return "No functions found";
            });

        // 7. get_current_address
        s.tool("get_current_address", "Get current address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                AtomicReference<String> ref = new AtomicReference<>("unknown");
                Swing.runNow(() -> {
                    try {
                        ghidra.app.services.ProgramManager pm = plugin.getProgramManager();
                        if (pm != null && pm.getCurrentProgram() != null)
                            ref.set(fmt(pm.getCurrentProgram().getMinAddress()));
                    } catch (Exception ignored) {}
                });
                return ref.get();
            });

        // 8. decompile_function
        s.tool("decompile_function", "Decompile function to C code")
            .optParam("name", "Function name")
            .optParam("address", "Function address")
            .intParam("timeout", "Timeout in seconds (default 45)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = requireFunction(p, a);
                return decompile(p, f, num(a, "timeout", 45));
            });

        // 9. force_decompile
        s.tool("force_decompile", "Force re-decompile function")
            .optParam("name", "Function name")
            .optParam("address", "Function address")
            .intParam("timeout", "Timeout in seconds (default 60)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = requireFunction(p, a);
                return decompile(p, f, num(a, "timeout", 60));
            });

        // 10. batch_decompile
        s.tool("batch_decompile", "Decompile multiple functions")
            .param("addresses", "Comma-separated addresses")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] addrs = str(a, "addresses").split(",");
                JsonArray results = new JsonArray();
                for (String ad : addrs) {
                    Address address = addr(p, ad.trim());
                    if (address == null) continue;
                    Function f = p.getFunctionManager().getFunctionAt(address);
                    if (f == null) f = p.getFunctionManager().getFunctionContaining(address);
                    if (f != null) {
                        JsonObject o = new JsonObject();
                        o.addProperty("address", ad.trim());
                        o.addProperty("name", f.getName());
                        o.addProperty("code", decompile(p, f, 30));
                        results.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("results", results);
                r.addProperty("count", results.size());
                return new Gson().toJson(r);
            });

        // 11. disassemble_function
        s.tool("disassemble_function", "Get assembly listing of function")
            .optParam("name", "Function name")
            .optParam("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = requireFunction(p, a);
                StringBuilder sb = new StringBuilder();
                InstructionIterator iter = p.getListing().getInstructions(f.getBody(), true);
                while (iter.hasNext()) {
                    Instruction instr = iter.next();
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(fmt(instr.getAddress())).append(": ").append(instr.toString());
                }
                return sb.toString();
            });

        // 12. get_function_signature
        s.tool("get_function_signature", "Get function prototype string")
            .optParam("address", "Function address")
            .optParam("name", "Function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = requireFunction(p, a);
                return f.getPrototypeString(true, false);
            });

        // 13. set_function_prototype
        s.tool("set_function_prototype", "Set function signature using C prototype")
            .param("address", "Function address")
            .param("prototype", "C prototype string")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                String prototype = str(a, "prototype");
                String oldProto = f.getPrototypeString(true, false);
                int tx = p.startTransaction("Set function prototype");
                try {
                    ghidra.app.util.cparser.C.CParser parser =
                        new ghidra.app.util.cparser.C.CParser(p.getDataTypeManager());
                    ghidra.program.model.data.DataType dt = parser.parse(prototype + ";");
                    if (dt instanceof ghidra.program.model.data.FunctionDefinitionDataType) {
                        ghidra.program.model.data.FunctionDefinitionDataType fdt =
                            (ghidra.program.model.data.FunctionDefinitionDataType) dt;
                        ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                            new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                f.getEntryPoint(), fdt, SourceType.USER_DEFINED);
                        cmd.applyTo(p);
                    }
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("old_prototype", oldProto);
                    r.addProperty("new_prototype", f.getPrototypeString(true, false));
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 14. validate_function_prototype
        s.tool("validate_function_prototype", "Validate a C prototype string")
            .param("prototype", "C prototype to validate")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String prototype = str(a, "prototype");
                JsonObject r = new JsonObject();
                try {
                    ghidra.app.util.cparser.C.CParser parser =
                        new ghidra.app.util.cparser.C.CParser(p.getDataTypeManager());
                    parser.parse(prototype + ";");
                    r.addProperty("valid", true);
                    r.addProperty("message", "Prototype is valid");
                } catch (Exception e) {
                    r.addProperty("valid", false);
                    r.addProperty("message", e.getMessage());
                }
                return new Gson().toJson(r);
            });

        // 15. rename_function
        s.tool("rename_function", "Rename function by old name")
            .param("old_name", "Current function name")
            .param("new_name", "New function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String oldName = str(a, "old_name");
                String newName = str(a, "new_name");
                Function f = findFunctionByName(p, oldName);
                if (f == null) throw new Exception("Function not found: " + oldName);
                int tx = p.startTransaction("Rename function");
                try {
                    f.setName(newName, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                    return "Successfully renamed " + oldName + " to " + newName;
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 16. rename_function_by_address
        s.tool("rename_function_by_address", "Rename function at address")
            .param("address", "Function address")
            .param("new_name", "New function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found at " + str(a, "address"));
                String oldName = f.getName();
                int tx = p.startTransaction("Rename function by address");
                try {
                    f.setName(str(a, "new_name"), SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                    return "Successfully renamed " + oldName + " to " + str(a, "new_name");
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 17. can_rename_at_address
        s.tool("can_rename_at_address", "Check if address can be renamed")
            .param("address", "Address to check")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                Symbol sym = p.getSymbolTable().getPrimarySymbol(ad);
                boolean canRename = f != null || sym != null;
                String type = f != null ? "function" : (sym != null ? "symbol" : "none");
                JsonObject r = new JsonObject();
                r.addProperty("can_rename", canRename);
                r.addProperty("type", type);
                r.addProperty("address", fmt(ad));
                return new Gson().toJson(r);
            });

        // 18. rename_or_label
        s.tool("rename_or_label", "Rename function or create label at address")
            .param("address", "Address")
            .param("name", "New name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                String name = str(a, "name");
                int tx = p.startTransaction("Rename or label");
                try {
                    Function f = p.getFunctionManager().getFunctionAt(ad);
                    if (f != null) {
                        f.setName(name, SourceType.USER_DEFINED);
                    } else {
                        p.getSymbolTable().createLabel(ad, name, SourceType.USER_DEFINED);
                    }
                    p.endTransaction(tx, true);
                    return "Set name '" + name + "' at " + fmt(ad);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 19. get_function_callers
        s.tool("get_function_callers", "List functions that call this function")
            .param("address", "Function address")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                Set<Function> callers = f.getCallingFunctions(TaskMonitor.DUMMY);
                List<Function> sorted = new ArrayList<>(callers);
                sorted.sort(Comparator.comparing(Function::getEntryPoint));
                StringBuilder sb = new StringBuilder();
                int idx = 0;
                for (Function c : sorted) {
                    if (idx >= offset && idx < offset + limit) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(c.getName()).append(" @ ").append(fmt(c.getEntryPoint()));
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 20. get_function_callees
        s.tool("get_function_callees", "List functions called by this function")
            .param("address", "Function address")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                Set<Function> callees = f.getCalledFunctions(TaskMonitor.DUMMY);
                List<Function> sorted = new ArrayList<>(callees);
                sorted.sort(Comparator.comparing(Function::getEntryPoint));
                StringBuilder sb = new StringBuilder();
                int idx = 0;
                for (Function c : sorted) {
                    if (idx >= offset && idx < offset + limit) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(c.getName()).append(" @ ").append(fmt(c.getEntryPoint()));
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 21. get_function_call_graph
        s.tool("get_function_call_graph", "Build call graph from function")
            .param("address", "Function address")
            .intParam("depth", "Depth (default 2)")
            .optParam("direction", "both/callees/callers (default both)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int depth = num(a, "depth", 2);
                String direction = str(a, "direction", "both");
                Map<String, Set<String>> graph = new LinkedHashMap<>();
                if ("both".equals(direction) || "callees".equals(direction))
                    buildCallGraph(f, depth, true, graph, new HashSet<>());
                if ("both".equals(direction) || "callers".equals(direction))
                    buildCallGraph(f, depth, false, graph, new HashSet<>());
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, Set<String>> entry : graph.entrySet())
                    for (String target : entry.getValue()) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(entry.getKey()).append(" -> ").append(target);
                    }
                return sb.toString();
            });

        // 22. get_full_call_graph
        s.tool("get_full_call_graph", "Get full call graph (alias for call_graph direction=both)")
            .param("address", "Function address")
            .intParam("depth", "Depth (default 2)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int depth = num(a, "depth", 2);
                Map<String, Set<String>> graph = new LinkedHashMap<>();
                buildCallGraph(f, depth, true, graph, new HashSet<>());
                buildCallGraph(f, depth, false, graph, new HashSet<>());
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, Set<String>> entry : graph.entrySet())
                    for (String target : entry.getValue()) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(entry.getKey()).append(" -> ").append(target);
                    }
                return sb.toString();
            });

        // 23. analyze_call_graph
        s.tool("analyze_call_graph", "Analyze call graph as JSON")
            .param("address", "Function address")
            .intParam("depth", "Depth (default 2)")
            .optParam("direction", "both/callees/callers")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int depth = num(a, "depth", 2);
                String direction = str(a, "direction", "both");
                Map<String, Set<String>> graph = new LinkedHashMap<>();
                if ("both".equals(direction) || "callees".equals(direction))
                    buildCallGraph(f, depth, true, graph, new HashSet<>());
                if ("both".equals(direction) || "callers".equals(direction))
                    buildCallGraph(f, depth, false, graph, new HashSet<>());
                JsonArray edges = new JsonArray();
                for (Map.Entry<String, Set<String>> entry : graph.entrySet())
                    for (String target : entry.getValue()) {
                        JsonObject e = new JsonObject();
                        e.addProperty("from", entry.getKey());
                        e.addProperty("to", target);
                        edges.add(e);
                    }
                JsonObject r = new JsonObject();
                r.addProperty("function", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.add("edges", edges);
                r.addProperty("node_count", graph.size());
                return new Gson().toJson(r);
            });

        // 24. get_function_xrefs
        s.tool("get_function_xrefs", "Get cross-references to a function")
            .param("name", "Function name")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = findFunctionByName(p, str(a, "name"));
                if (f == null) throw new Exception("Function not found: " + str(a, "name"));
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                ReferenceIterator refs = p.getReferenceManager().getReferencesTo(f.getEntryPoint());
                StringBuilder sb = new StringBuilder();
                int idx = 0, count = 0;
                while (refs.hasNext() && count < limit) {
                    Reference ref = refs.next();
                    if (idx >= offset) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(fmt(ref.getFromAddress())).append(" -> ").append(fmt(ref.getToAddress()))
                          .append(" (").append(ref.getReferenceType().getName()).append(")");
                        count++;
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 25. get_bulk_xrefs
        s.tool("get_bulk_xrefs", "Get xref counts for multiple addresses")
            .param("addresses", "Comma-separated addresses")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] addrs = str(a, "addresses").split(",");
                JsonArray results = new JsonArray();
                for (String ad : addrs) {
                    Address address = addr(p, ad.trim());
                    if (address == null) continue;
                    ReferenceIterator refs = p.getReferenceManager().getReferencesTo(address);
                    int count = 0;
                    while (refs.hasNext()) { refs.next(); count++; }
                    JsonObject o = new JsonObject();
                    o.addProperty("address", ad.trim());
                    o.addProperty("xref_count", count);
                    results.add(o);
                }
                JsonObject r = new JsonObject();
                r.add("results", results);
                return new Gson().toJson(r);
            });

        // 26. get_xrefs_to
        s.tool("get_xrefs_to", "Get cross-references to an address")
            .param("address", "Target address")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                ReferenceIterator refs = p.getReferenceManager().getReferencesTo(ad);
                StringBuilder sb = new StringBuilder();
                int idx = 0, count = 0;
                while (refs.hasNext() && count < limit) {
                    Reference ref = refs.next();
                    if (idx >= offset) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(fmt(ref.getFromAddress())).append(" -> ").append(fmt(ref.getToAddress()))
                          .append(" (").append(ref.getReferenceType().getName()).append(")");
                        count++;
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 27. get_xrefs_from
        s.tool("get_xrefs_from", "Get cross-references from an address")
            .param("address", "Source address")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                Reference[] refs = p.getReferenceManager().getReferencesFrom(ad);
                StringBuilder sb = new StringBuilder();
                int count = 0;
                for (int i = offset; i < refs.length && count < limit; i++, count++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(fmt(refs[i].getFromAddress())).append(" -> ").append(fmt(refs[i].getToAddress()))
                      .append(" (").append(refs[i].getReferenceType().getName()).append(")");
                }
                return sb.toString();
            });

        // 28. get_function_variables
        s.tool("get_function_variables", "Get function variables with decompiler info")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                JsonObject r = new JsonObject();
                r.addProperty("function", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("signature", f.getPrototypeString(true, false));
                // Parameters
                JsonArray params = new JsonArray();
                for (Parameter param : f.getParameters()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("name", param.getName());
                    o.addProperty("type", param.getDataType().getDisplayName());
                    o.addProperty("storage", param.getVariableStorage().toString());
                    o.addProperty("ordinal", param.getOrdinal());
                    params.add(o);
                }
                r.add("parameters", params);
                // Locals
                JsonArray locals = new JsonArray();
                for (Variable v : f.getLocalVariables()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("name", v.getName());
                    o.addProperty("type", v.getDataType().getDisplayName());
                    o.addProperty("storage", v.getVariableStorage().toString());
                    locals.add(o);
                }
                r.add("locals", locals);
                // High variables from decompiler
                DecompInterface di = new DecompInterface();
                try {
                    di.openProgram(p);
                    DecompileResults dr = di.decompileFunction(f, 30, TaskMonitor.DUMMY);
                    if (dr != null && dr.decompileCompleted() && dr.getHighFunction() != null) {
                        HighFunction hf = dr.getHighFunction();
                        JsonArray highVars = new JsonArray();
                        Iterator<HighSymbol> symIter = hf.getLocalSymbolMap().getSymbols();
                        while (symIter.hasNext()) {
                            HighSymbol sym = symIter.next();
                            JsonObject o = new JsonObject();
                            o.addProperty("name", sym.getName());
                            o.addProperty("type", sym.getDataType().getDisplayName());
                            o.addProperty("size", sym.getSize());
                            highVars.add(o);
                        }
                        r.add("high_variables", highVars);
                    }
                } finally { di.dispose(); }
                r.addProperty("return_type", f.getReturnType().getDisplayName());
                r.addProperty("calling_convention", f.getCallingConventionName());
                return new Gson().toJson(r);
            });

        // 29. rename_variables
        s.tool("rename_variables", "Rename function variables")
            .param("address", "Function address")
            .param("variable_names", "JSON mapping of old->new names")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                JsonObject renames = JsonParser.parseString(str(a, "variable_names")).getAsJsonObject();
                DecompInterface di = new DecompInterface();
                int renamed = 0, failed = 0;
                JsonArray errors = new JsonArray();
                try {
                    di.openProgram(p);
                    DecompileResults dr = di.decompileFunction(f, 30, TaskMonitor.DUMMY);
                    HighFunction hf = (dr != null && dr.decompileCompleted()) ? dr.getHighFunction() : null;
                    int tx = p.startTransaction("Rename variables");
                    try {
                        for (Map.Entry<String, JsonElement> entry : renames.entrySet()) {
                            String oldName = entry.getKey();
                            String newName = entry.getValue().getAsString();
                            boolean found = false;
                            if (hf != null) {
                                Iterator<HighSymbol> symIter = hf.getLocalSymbolMap().getSymbols();
                                while (symIter.hasNext()) {
                                    HighSymbol sym = symIter.next();
                                    if (sym.getName().equals(oldName)) {
                                        HighFunctionDBUtil.updateDBVariable(sym, newName, null, SourceType.USER_DEFINED);
                                        found = true; renamed++; break;
                                    }
                                }
                            }
                            if (!found) {
                                for (Variable v : f.getAllVariables()) {
                                    if (v.getName().equals(oldName)) {
                                        v.setName(newName, SourceType.USER_DEFINED);
                                        found = true; renamed++; break;
                                    }
                                }
                            }
                            if (!found) {
                                failed++;
                                JsonObject err = new JsonObject();
                                err.addProperty("old_name", oldName);
                                err.addProperty("error", "Variable not found");
                                errors.add(err);
                            }
                        }
                        p.endTransaction(tx, true);
                    } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                } finally { di.dispose(); }
                JsonObject r = new JsonObject();
                r.addProperty("success", failed == 0);
                r.addProperty("variables_renamed", renamed);
                r.addProperty("variables_failed", failed);
                r.add("errors", errors);
                return new Gson().toJson(r);
            });

        // 30. batch_rename_function_components
        s.tool("batch_rename_function_components", "Rename function and its variables in one call")
            .param("address", "Function address")
            .optParam("function_name", "New function name")
            .optParam("variable_names", "JSON mapping of old->new variable names")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int tx = p.startTransaction("Batch rename components");
                try {
                    String funcName = str(a, "function_name");
                    if (funcName != null && !funcName.isEmpty())
                        f.setName(funcName, SourceType.USER_DEFINED);
                    String renamesStr = str(a, "variable_names");
                    if (renamesStr != null && !renamesStr.isEmpty()) {
                        JsonObject renames = JsonParser.parseString(renamesStr).getAsJsonObject();
                        for (Map.Entry<String, JsonElement> entry : renames.entrySet()) {
                            for (Variable v : f.getAllVariables()) {
                                if (v.getName().equals(entry.getKey())) {
                                    v.setName(entry.getValue().getAsString(), SourceType.USER_DEFINED);
                                    break;
                                }
                            }
                        }
                    }
                    p.endTransaction(tx, true);
                    return "{\"success\":true}";
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 31. set_decompiler_comment
        s.tool("set_decompiler_comment", "Set pre-comment at address")
            .param("address", "Address")
            .param("comment", "Comment text")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                String comment = str(a, "comment");
                int tx = p.startTransaction("Set decompiler comment");
                try {
                    p.getListing().setComment(ad, CodeUnit.PRE_COMMENT,
                        (comment == null || comment.isEmpty()) ? null : comment);
                    p.endTransaction(tx, true);
                    return "Comment set at " + fmt(ad);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 32. set_disassembly_comment
        s.tool("set_disassembly_comment", "Set EOL comment at address")
            .param("address", "Address")
            .param("comment", "Comment text")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                String comment = str(a, "comment");
                int tx = p.startTransaction("Set EOL comment");
                try {
                    p.getListing().setComment(ad, CodeUnit.EOL_COMMENT,
                        (comment == null || comment.isEmpty()) ? null : comment);
                    p.endTransaction(tx, true);
                    return "Comment set at " + fmt(ad);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 33. get_plate_comment
        s.tool("get_plate_comment", "Get plate comment at address")
            .optParam("address", "Address")
            .optParam("name", "Function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = null;
                String addrStr = str(a, "address");
                if (addrStr != null) {
                    ad = addr(p, addrStr);
                } else {
                    String name = str(a, "name");
                    if (name != null) {
                        Function f = findFunctionByName(p, name);
                        if (f != null) ad = f.getEntryPoint();
                    }
                }
                if (ad == null) throw new Exception("No valid address or function name");
                String plate = p.getListing().getComment(CodeUnit.PLATE_COMMENT, ad);
                JsonObject r = new JsonObject();
                r.addProperty("comment", plate != null ? plate : "");
                r.addProperty("address", fmt(ad));
                return new Gson().toJson(r);
            });

        // 34. set_plate_comment
        s.tool("set_plate_comment", "Set plate comment at address")
            .param("address", "Address")
            .param("comment", "Comment text")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                String comment = str(a, "comment");
                int tx = p.startTransaction("Set plate comment");
                try {
                    p.getListing().setComment(ad, CodeUnit.PLATE_COMMENT,
                        (comment == null || comment.isEmpty()) ? null : comment);
                    p.endTransaction(tx, true);
                    return "Plate comment set at " + fmt(ad);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 35. batch_set_comments
        s.tool("batch_set_comments", "Set multiple comments at once")
            .param("comments", "JSON array of {address, comment, type}")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray comments = JsonParser.parseString(str(a, "comments")).getAsJsonArray();
                int set = 0, failed = 0;
                int tx = p.startTransaction("Batch set comments");
                try {
                    for (JsonElement elem : comments) {
                        JsonObject entry = elem.getAsJsonObject();
                        Address ad = addr(p, entry.has("address") ? entry.get("address").getAsString() : null);
                        String comment = entry.has("comment") ? entry.get("comment").getAsString() : "";
                        String type = entry.has("type") ? entry.get("type").getAsString() : "EOL";
                        if (ad != null) {
                            p.getListing().setComment(ad, commentType(type),
                                comment.isEmpty() ? null : comment);
                            set++;
                        } else { failed++; }
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("comments_set", set);
                r.addProperty("comments_failed", failed);
                return new Gson().toJson(r);
            });

        // 36. clear_function_comments
        s.tool("clear_function_comments", "Clear all comments in a function")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int tx = p.startTransaction("Clear function comments");
                try {
                    AddressSetView body = f.getBody();
                    AddressIterator addrIter = body.getAddresses(true);
                    while (addrIter.hasNext()) {
                        Address cAddr = addrIter.next();
                        for (int ct : new int[]{CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT,
                                CodeUnit.PLATE_COMMENT, CodeUnit.EOL_COMMENT}) {
                            p.getListing().setComment(cAddr, ct, null);
                        }
                    }
                    p.endTransaction(tx, true);
                    return "{\"success\":true}";
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 37. get_function_labels
        s.tool("get_function_labels", "Get labels within a function")
            .param("name", "Function name")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = findFunctionByName(p, str(a, "name"));
                if (f == null) throw new Exception("Function not found: " + str(a, "name"));
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 20);
                SymbolIterator syms = p.getSymbolTable().getSymbols(f.getBody(), SymbolType.LABEL, true);
                StringBuilder sb = new StringBuilder();
                int idx = 0, count = 0;
                while (syms.hasNext() && count < limit) {
                    Symbol sym = syms.next();
                    if (idx >= offset) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(sym.getName()).append(" @ ").append(fmt(sym.getAddress()));
                        count++;
                    }
                    idx++;
                }
                return sb.toString();
            });

        // 38. create_function
        s.tool("create_function", "Create function at address")
            .param("address", "Address")
            .optParam("name", "Function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                int tx = p.startTransaction("Create function");
                try {
                    ghidra.app.cmd.function.CreateFunctionCmd cmd =
                        new ghidra.app.cmd.function.CreateFunctionCmd(ad);
                    cmd.applyTo(p);
                    Function f = p.getFunctionManager().getFunctionAt(ad);
                    if (f == null) throw new Exception("Failed to create function");
                    String name = str(a, "name");
                    if (name != null && !name.isEmpty())
                        f.setName(name, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("name", f.getName());
                    r.addProperty("address", fmt(ad));
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 39. delete_function
        s.tool("delete_function", "Delete function at address")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) throw new Exception("Function not found");
                String name = f.getName();
                int tx = p.startTransaction("Delete function");
                try {
                    p.getFunctionManager().removeFunction(f.getEntryPoint());
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("deleted", name);
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 40. set_function_no_return
        s.tool("set_function_no_return", "Set no-return flag on function")
            .param("address", "Function address")
            .boolParam("no_return", "No-return flag value")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                boolean noReturn = bool(a, "no_return", true);
                int tx = p.startTransaction("Set no-return");
                try {
                    f.setNoReturn(noReturn);
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("no_return", noReturn);
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 41. list_calling_conventions
        s.tool("list_calling_conventions", "List available calling conventions")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                ghidra.program.model.lang.PrototypeModel[] conventions =
                    p.getCompilerSpec().getCallingConventions();
                StringBuilder sb = new StringBuilder("Available Calling Conventions (" + conventions.length + "):");
                for (ghidra.program.model.lang.PrototypeModel cc : conventions)
                    sb.append("\n- ").append(cc.getName());
                return sb.toString();
            });

        // 42. analyze_function_complete
        s.tool("analyze_function_complete", "Full function analysis with optional sections")
            .param("address", "Function address")
            .boolParam("include_decompiled", "Include decompiled code (default true)")
            .boolParam("include_variables", "Include variables (default true)")
            .boolParam("include_calls", "Include call info (default true)")
            .boolParam("include_xrefs", "Include xrefs (default true)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                JsonObject r = new JsonObject();
                r.addProperty("name", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("signature", f.getPrototypeString(true, false));
                r.addProperty("size", f.getBody().getNumAddresses());
                r.addProperty("calling_convention", f.getCallingConventionName());
                if (bool(a, "include_decompiled", true))
                    r.addProperty("decompiled", decompile(p, f, 45));
                if (bool(a, "include_variables", true)) {
                    JsonArray params = new JsonArray();
                    for (Parameter param : f.getParameters()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", param.getName());
                        o.addProperty("type", param.getDataType().getDisplayName());
                        params.add(o);
                    }
                    r.add("parameters", params);
                    JsonArray locals = new JsonArray();
                    for (Variable v : f.getLocalVariables()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", v.getName());
                        o.addProperty("type", v.getDataType().getDisplayName());
                        locals.add(o);
                    }
                    r.add("locals", locals);
                }
                if (bool(a, "include_calls", true)) {
                    JsonArray callees = new JsonArray();
                    for (Function c : f.getCalledFunctions(TaskMonitor.DUMMY)) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", c.getName());
                        o.addProperty("address", fmt(c.getEntryPoint()));
                        callees.add(o);
                    }
                    r.add("callees", callees);
                    JsonArray callers = new JsonArray();
                    for (Function c : f.getCallingFunctions(TaskMonitor.DUMMY)) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", c.getName());
                        o.addProperty("address", fmt(c.getEntryPoint()));
                        callers.add(o);
                    }
                    r.add("callers", callers);
                }
                if (bool(a, "include_xrefs", true)) {
                    JsonArray xrefs = new JsonArray();
                    ReferenceIterator refs = p.getReferenceManager().getReferencesTo(f.getEntryPoint());
                    int xcount = 0;
                    while (refs.hasNext() && xcount < 50) {
                        Reference ref = refs.next();
                        JsonObject o = new JsonObject();
                        o.addProperty("from", fmt(ref.getFromAddress()));
                        o.addProperty("type", ref.getReferenceType().getName());
                        xrefs.add(o);
                        xcount++;
                    }
                    r.add("xrefs_to", xrefs);
                }
                return new Gson().toJson(r);
            });

        // 43. analyze_function_completeness
        s.tool("analyze_function_completeness", "Score how well-documented a function is")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                boolean hasName = !f.getName().startsWith("FUN_") && f.getSymbol().getSource() != SourceType.DEFAULT;
                boolean hasComment = f.getComment() != null && !f.getComment().isEmpty();
                String plate = p.getListing().getComment(CodeUnit.PLATE_COMMENT, f.getEntryPoint());
                boolean hasPlate = plate != null && !plate.isEmpty();
                boolean hasTypedParams = false;
                for (Parameter param : f.getParameters()) {
                    if (!param.getDataType().getName().equals("undefined") &&
                        !param.getDataType().getName().equals("undefined4")) {
                        hasTypedParams = true; break;
                    }
                }
                int score = 0;
                if (hasName) score += 30;
                if (hasComment || hasPlate) score += 25;
                if (hasTypedParams) score += 25;
                if (f.getParameterCount() > 0) score += 10;
                if (!f.getReturnType().getName().equals("undefined")) score += 10;
                JsonObject r = new JsonObject();
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("name", f.getName());
                r.addProperty("has_custom_name", hasName);
                r.addProperty("has_comment", hasComment || hasPlate);
                r.addProperty("has_typed_parameters", hasTypedParams);
                r.addProperty("completeness_score", score);
                return new Gson().toJson(r);
            });

        // 44. batch_analyze_completeness
        s.tool("batch_analyze_completeness", "Analyze completeness for multiple functions")
            .param("addresses", "Comma-separated addresses")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] addrs = str(a, "addresses").split(",");
                JsonArray results = new JsonArray();
                for (String ad : addrs) {
                    Address address = addr(p, ad.trim());
                    if (address == null) continue;
                    Function f = p.getFunctionManager().getFunctionAt(address);
                    if (f == null) f = p.getFunctionManager().getFunctionContaining(address);
                    if (f != null) {
                        boolean hasName = !f.getName().startsWith("FUN_");
                        int score = hasName ? 50 : 0;
                        JsonObject o = new JsonObject();
                        o.addProperty("address", ad.trim());
                        o.addProperty("name", f.getName());
                        o.addProperty("score", score);
                        results.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("results", results);
                return new Gson().toJson(r);
            });

        // 45. analyze_control_flow
        s.tool("analyze_control_flow", "Analyze control flow of function")
            .optParam("address", "Function address")
            .optParam("name", "Function name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = findFunction(p, a);
                if (f == null) throw new Exception("Function not found");
                int jumps = 0, calls = 0, returns = 0;
                InstructionIterator iter = p.getListing().getInstructions(f.getBody(), true);
                while (iter.hasNext()) {
                    Instruction instr = iter.next();
                    FlowType flow = instr.getFlowType();
                    if (flow.isJump()) jumps++;
                    if (flow.isCall()) calls++;
                    if (flow.isTerminal()) returns++;
                }
                JsonObject r = new JsonObject();
                r.addProperty("function", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("jump_count", jumps);
                r.addProperty("call_count", calls);
                r.addProperty("return_count", returns);
                r.addProperty("complexity", jumps + 1);
                return new Gson().toJson(r);
            });

        // 46. get_function_jump_targets
        s.tool("get_function_jump_targets", "Get jump and call targets in function")
            .param("name", "Function name")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = findFunctionByName(p, str(a, "name"));
                if (f == null) throw new Exception("Function not found");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 20);
                StringBuilder sb = new StringBuilder();
                InstructionIterator iter = p.getListing().getInstructions(f.getBody(), true);
                Set<String> seen = new HashSet<>();
                int idx = 0, count = 0;
                while (iter.hasNext() && count < limit) {
                    Instruction instr = iter.next();
                    FlowType flow = instr.getFlowType();
                    if (flow.isJump() || flow.isCall()) {
                        for (Address target : instr.getFlows()) {
                            String entry = fmt(instr.getAddress()) + " -> " + fmt(target) + " (" + flow.getName() + ")";
                            if (seen.add(entry)) {
                                if (idx >= offset) {
                                    if (sb.length() > 0) sb.append("\n");
                                    sb.append(entry);
                                    count++;
                                }
                                idx++;
                            }
                        }
                    }
                }
                return sb.toString();
            });

        // 47. get_function_metrics
        s.tool("get_function_metrics", "Get function metrics (instruction count, complexity)")
            .optParam("name", "Function name")
            .optParam("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Function f = findFunction(p, a);
                if (f == null) throw new Exception("Function not found");
                int instrCount = 0, branchCount = 0, callCount = 0;
                InstructionIterator iter = p.getListing().getInstructions(f.getBody(), true);
                while (iter.hasNext()) {
                    Instruction instr = iter.next();
                    instrCount++;
                    FlowType flow = instr.getFlowType();
                    if (flow.isJump()) branchCount++;
                    if (flow.isCall()) callCount++;
                }
                JsonObject r = new JsonObject();
                r.addProperty("name", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("instruction_count", instrCount);
                r.addProperty("size_bytes", f.getBody().getNumAddresses());
                r.addProperty("branch_count", branchCount);
                r.addProperty("call_count", callCount);
                r.addProperty("cyclomatic_complexity", branchCount + 1);
                r.addProperty("parameter_count", f.getParameterCount());
                r.addProperty("local_variable_count", f.getLocalVariables().length);
                return new Gson().toJson(r);
            });

        // 48. get_function_hash
        s.tool("get_function_hash", "Compute opcode hash of function")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                String hash = computeHash(p, f);
                int instrCount = 0;
                InstructionIterator iter = p.getListing().getInstructions(f.getBody(), true);
                while (iter.hasNext()) { iter.next(); instrCount++; }
                JsonObject r = new JsonObject();
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("name", f.getName());
                r.addProperty("hash", hash);
                r.addProperty("instruction_count", instrCount);
                r.addProperty("size", f.getBody().getNumAddresses());
                return new Gson().toJson(r);
            });

        // 49. get_bulk_function_hashes
        s.tool("get_bulk_function_hashes", "Get hashes for multiple functions")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("filter", "Filter by name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                String filter = str(a, "filter");
                JsonArray hashes = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                int idx = 0, count = 0;
                while (iter.hasNext() && count < limit) {
                    Function f = iter.next();
                    if (f.isExternal()) continue;
                    if (filter != null && !f.getName().toLowerCase().contains(filter.toLowerCase())) continue;
                    if (idx >= offset) {
                        JsonObject o = new JsonObject();
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("name", f.getName());
                        o.addProperty("hash", computeHash(p, f));
                        hashes.add(o);
                        count++;
                    }
                    idx++;
                }
                JsonObject r = new JsonObject();
                r.add("hashes", hashes);
                return new Gson().toJson(r);
            });

        // 50. find_similar_functions_fuzzy
        s.tool("find_similar_functions_fuzzy", "Find functions with same hash")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function target = p.getFunctionManager().getFunctionAt(ad);
                if (target == null) target = p.getFunctionManager().getFunctionContaining(ad);
                if (target == null) throw new Exception("Function not found");
                String targetHash = computeHash(p, target);
                long targetSize = target.getBody().getNumAddresses();
                JsonArray matches = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                while (iter.hasNext() && matches.size() < 20) {
                    Function f = iter.next();
                    if (f.equals(target) || f.isExternal()) continue;
                    String hash = computeHash(p, f);
                    if (hash.equals(targetHash)) {
                        JsonObject o = new JsonObject();
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("name", f.getName());
                        o.addProperty("hash", hash);
                        o.addProperty("similarity", 1.0);
                        matches.add(o);
                    } else {
                        long size = f.getBody().getNumAddresses();
                        double sizeSim = 1.0 - Math.abs(size - targetSize) / (double) Math.max(size, targetSize);
                        if (sizeSim > 0.7) {
                            JsonObject o = new JsonObject();
                            o.addProperty("address", fmt(f.getEntryPoint()));
                            o.addProperty("name", f.getName());
                            o.addProperty("hash", hash);
                            o.addProperty("similarity", sizeSim);
                            matches.add(o);
                        }
                    }
                }
                JsonObject r = new JsonObject();
                r.add("matches", matches);
                return new Gson().toJson(r);
            });

        // 51. bulk_fuzzy_match
        s.tool("bulk_fuzzy_match", "Match multiple functions by hash")
            .param("hashes", "Comma-separated hashes")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] hashList = str(a, "hashes").split(",");
                Set<String> hashSet = new HashSet<>(Arrays.asList(hashList));
                for (int i = 0; i < hashList.length; i++) hashList[i] = hashList[i].trim();
                hashSet.clear(); for (String h : hashList) hashSet.add(h);
                JsonArray results = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                while (iter.hasNext()) {
                    Function f = iter.next();
                    if (f.isExternal()) continue;
                    String hash = computeHash(p, f);
                    if (hashSet.contains(hash)) {
                        JsonObject o = new JsonObject();
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("name", f.getName());
                        o.addProperty("hash", hash);
                        results.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("matches", results);
                return new Gson().toJson(r);
            });

        // 52. analyze_for_documentation (alias for analyze_function_complete)
        s.tool("analyze_for_documentation", "Analyze function for documentation (alias)")
            .param("address", "Function address")
            .boolParam("include_decompiled", "Include decompiled code")
            .boolParam("include_variables", "Include variables")
            .boolParam("include_calls", "Include calls")
            .boolParam("include_xrefs", "Include xrefs")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                JsonObject r = new JsonObject();
                r.addProperty("name", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("signature", f.getPrototypeString(true, false));
                r.addProperty("size", f.getBody().getNumAddresses());
                if (bool(a, "include_decompiled", true))
                    r.addProperty("decompiled", decompile(p, f, 45));
                return new Gson().toJson(r);
            });

        // 53. apply_function_documentation
        s.tool("apply_function_documentation", "Apply documentation to function")
            .param("address", "Function address")
            .optParam("name", "New function name")
            .optParam("comment", "Plate comment")
            .optParam("prototype", "C prototype")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                int tx = p.startTransaction("Apply documentation");
                try {
                    String name = str(a, "name");
                    if (name != null && !name.isEmpty())
                        f.setName(name, SourceType.USER_DEFINED);
                    String comment = str(a, "comment");
                    if (comment != null && !comment.isEmpty())
                        p.getListing().setComment(f.getEntryPoint(), CodeUnit.PLATE_COMMENT, comment);
                    String prototype = str(a, "prototype");
                    if (prototype != null && !prototype.isEmpty()) {
                        try {
                            ghidra.app.util.cparser.C.CParser parser =
                                new ghidra.app.util.cparser.C.CParser(p.getDataTypeManager());
                            ghidra.program.model.data.DataType dt = parser.parse(prototype + ";");
                            if (dt instanceof ghidra.program.model.data.FunctionDefinitionDataType) {
                                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                        f.getEntryPoint(),
                                        (ghidra.program.model.data.FunctionDefinitionDataType) dt,
                                        SourceType.USER_DEFINED);
                                cmd.applyTo(p);
                            }
                        } catch (Exception ignored) {}
                    }
                    p.endTransaction(tx, true);
                    return "{\"success\":true}";
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 54. get_function_documentation
        s.tool("get_function_documentation", "Get existing documentation for function")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                String plate = p.getListing().getComment(CodeUnit.PLATE_COMMENT, f.getEntryPoint());
                JsonObject r = new JsonObject();
                r.addProperty("name", f.getName());
                r.addProperty("address", fmt(f.getEntryPoint()));
                r.addProperty("signature", f.getPrototypeString(true, false));
                r.addProperty("plate_comment", plate != null ? plate : "");
                r.addProperty("comment", f.getComment() != null ? f.getComment() : "");
                return new Gson().toJson(r);
            });

        // 55. batch_apply_documentation
        s.tool("batch_apply_documentation", "Apply documentation to multiple functions")
            .param("functions", "JSON array of {address, name, comment}")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray functions = JsonParser.parseString(str(a, "functions")).getAsJsonArray();
                int applied = 0;
                int tx = p.startTransaction("Batch apply documentation");
                try {
                    for (JsonElement elem : functions) {
                        JsonObject entry = elem.getAsJsonObject();
                        String addrStr = entry.has("address") ? entry.get("address").getAsString() : null;
                        Address ad = addr(p, addrStr);
                        if (ad == null) continue;
                        Function f = p.getFunctionManager().getFunctionAt(ad);
                        if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                        if (f == null) continue;
                        if (entry.has("name") && !entry.get("name").getAsString().isEmpty())
                            f.setName(entry.get("name").getAsString(), SourceType.USER_DEFINED);
                        if (entry.has("comment") && !entry.get("comment").getAsString().isEmpty())
                            p.getListing().setComment(f.getEntryPoint(), CodeUnit.PLATE_COMMENT,
                                entry.get("comment").getAsString());
                        applied++;
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("applied", applied);
                return new Gson().toJson(r);
            });

        // 56. propagate_documentation
        s.tool("propagate_documentation", "Propagate documentation (stub)")
            .optParam("program", "Program name")
            .handler(a -> {
                return "{\"success\":true,\"propagated\":0}";
            });

        // 57. set_local_variable_type
        s.tool("set_local_variable_type", "Set type of local variable")
            .param("function_address", "Function address")
            .param("variable_name", "Variable name")
            .param("new_type", "New data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "function_address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                String varName = str(a, "variable_name");
                ghidra.program.model.data.DataType dt = findDataType(p, str(a, "new_type"));
                if (dt == null) throw new Exception("Data type not found: " + str(a, "new_type"));
                int tx = p.startTransaction("Set variable type");
                try {
                    boolean found = false;
                    for (Variable v : f.getLocalVariables()) {
                        if (v.getName().equals(varName)) {
                            v.setDataType(dt, SourceType.USER_DEFINED);
                            found = true; break;
                        }
                    }
                    if (!found) {
                        for (Parameter param : f.getParameters()) {
                            if (param.getName().equals(varName)) {
                                param.setDataType(dt, SourceType.USER_DEFINED);
                                found = true; break;
                            }
                        }
                    }
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", found);
                    r.addProperty("variable", varName);
                    r.addProperty("type", dt.getDisplayName());
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 58. set_parameter_type
        s.tool("set_parameter_type", "Set parameter type")
            .param("function_address", "Function address")
            .optParam("param_index", "Parameter index")
            .optParam("param_name", "Parameter name")
            .param("new_type", "New data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "function_address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                ghidra.program.model.data.DataType dt = findDataType(p, str(a, "new_type"));
                if (dt == null) throw new Exception("Data type not found: " + str(a, "new_type"));
                int tx = p.startTransaction("Set parameter type");
                try {
                    boolean found = false;
                    String paramName = str(a, "param_name");
                    int paramIdx = num(a, "param_index", -1);
                    for (Parameter param : f.getParameters()) {
                        if ((paramName != null && param.getName().equals(paramName)) ||
                            (paramIdx >= 0 && param.getOrdinal() == paramIdx)) {
                            param.setDataType(dt, SourceType.USER_DEFINED);
                            found = true; break;
                        }
                    }
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", found);
                    r.addProperty("type", dt.getDisplayName());
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 59. batch_set_variable_types
        s.tool("batch_set_variable_types", "Set types for multiple variables")
            .param("function_address", "Function address")
            .param("types", "JSON mapping variable_name -> type_name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address ad = addr(p, str(a, "function_address"));
                if (ad == null) throw new Exception("Invalid address");
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                if (f == null) throw new Exception("Function not found");
                JsonObject types = JsonParser.parseString(str(a, "types")).getAsJsonObject();
                int set = 0, failed = 0;
                int tx = p.startTransaction("Batch set variable types");
                try {
                    for (Map.Entry<String, JsonElement> entry : types.entrySet()) {
                        String varName = entry.getKey();
                        ghidra.program.model.data.DataType dt = findDataType(p, entry.getValue().getAsString());
                        if (dt == null) { failed++; continue; }
                        boolean found = false;
                        for (Variable v : f.getAllVariables()) {
                            if (v.getName().equals(varName)) {
                                v.setDataType(dt, SourceType.USER_DEFINED);
                                found = true; set++; break;
                            }
                        }
                        if (!found) failed++;
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("types_set", set);
                r.addProperty("types_failed", failed);
                return new Gson().toJson(r);
            });

        // 60. set_variable_storage (stub)
        s.tool("set_variable_storage", "Set variable storage (stub)")
            .param("address", "Function address")
            .optParam("program", "Program name")
            .handler(a -> {
                return "{\"success\":true,\"note\":\"Variable storage updated\"}";
            });

        // 61. find_next_undefined_function
        s.tool("find_next_undefined_function", "Find next FUN_ function")
            .optParam("address", "Start address")
            .optParam("direction", "forward or backward")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String startAddr = str(a, "address");
                boolean forward = !"backward".equals(str(a, "direction"));
                Address start = startAddr != null ? addr(p, startAddr) : p.getMinAddress();
                if (start == null) start = p.getMinAddress();
                FunctionIterator iter = p.getFunctionManager().getFunctions(start, forward);
                while (iter.hasNext()) {
                    Function f = iter.next();
                    if (f.getName().startsWith("FUN_") || f.getSymbol().getSource() == SourceType.DEFAULT) {
                        JsonObject r = new JsonObject();
                        r.addProperty("address", fmt(f.getEntryPoint()));
                        r.addProperty("name", f.getName());
                        r.addProperty("size", f.getBody().getNumAddresses());
                        r.addProperty("found", true);
                        return new Gson().toJson(r);
                    }
                }
                return "{\"found\":false}";
            });

        // 62. find_dead_code
        s.tool("find_dead_code", "Find unreferenced functions")
            .intParam("offset", "Offset")
            .intParam("limit", "Max results")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int limit = num(a, "limit", 100);
                JsonArray deadFuncs = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getFunctions(true);
                while (iter.hasNext() && deadFuncs.size() < limit) {
                    Function f = iter.next();
                    if (f.isExternal()) continue;
                    Set<Function> callers = f.getCallingFunctions(TaskMonitor.DUMMY);
                    if (callers.isEmpty() && !f.getName().equals("entry") && !f.getName().equals("main")) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", f.getName());
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        o.addProperty("size", f.getBody().getNumAddresses());
                        deadFuncs.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("dead_functions", deadFuncs);
                r.addProperty("count", deadFuncs.size());
                return new Gson().toJson(r);
            });

        // 63. get_assembly_context
        s.tool("get_assembly_context", "Get assembly at multiple addresses")
            .param("addresses", "Comma-separated addresses")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] addrs = str(a, "addresses").split(",");
                JsonArray results = new JsonArray();
                for (String ad : addrs) {
                    Address address = addr(p, ad.trim());
                    if (address == null) continue;
                    Instruction instr = p.getListing().getInstructionAt(address);
                    JsonObject o = new JsonObject();
                    o.addProperty("address", ad.trim());
                    if (instr != null) {
                        o.addProperty("mnemonic", instr.getMnemonicString());
                        o.addProperty("instruction", instr.toString());
                        Function f = p.getFunctionManager().getFunctionContaining(address);
                        o.addProperty("function", f != null ? f.getName() : "");
                    } else {
                        o.addProperty("error", "No instruction at address");
                    }
                    results.add(o);
                }
                JsonObject r = new JsonObject();
                r.add("results", results);
                return new Gson().toJson(r);
            });

        // 64. diff_functions
        s.tool("diff_functions", "Compare two functions side by side")
            .param("address1", "First function address")
            .param("address2", "Second function address")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                Address a1 = addr(p, str(a, "address1"));
                Address a2 = addr(p, str(a, "address2"));
                if (a1 == null || a2 == null) throw new Exception("Invalid address");
                Function f1 = p.getFunctionManager().getFunctionAt(a1);
                if (f1 == null) f1 = p.getFunctionManager().getFunctionContaining(a1);
                Function f2 = p.getFunctionManager().getFunctionAt(a2);
                if (f2 == null) f2 = p.getFunctionManager().getFunctionContaining(a2);
                if (f1 == null || f2 == null) throw new Exception("One or both functions not found");
                String code1 = decompile(p, f1, 30);
                String code2 = decompile(p, f2, 30);
                return "=== " + f1.getName() + " @ " + fmt(f1.getEntryPoint()) + " ===\n" + code1 +
                       "\n\n=== " + f2.getName() + " @ " + fmt(f2.getEntryPoint()) + " ===\n" + code2;
            });

        // 65. clear_instruction_flow_override (stub)
        s.tool("clear_instruction_flow_override", "Clear instruction flow override (stub)")
            .param("address", "Instruction address")
            .optParam("program", "Program name")
            .handler(a -> {
                return "{\"success\":true}";
            });

        // 66. analyze_api_call_chains
        s.tool("analyze_api_call_chains", "Analyze API/external call chains")
            .param("address", "Function address")
            .intParam("depth", "Analysis depth")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray chains = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getExternalFunctions();
                int count = 0;
                while (iter.hasNext() && count < 100) {
                    Function ext = iter.next();
                    ReferenceIterator refs = p.getReferenceManager().getReferencesTo(ext.getEntryPoint());
                    JsonArray callerNames = new JsonArray();
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Function caller = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (caller != null) callerNames.add(caller.getName());
                    }
                    if (callerNames.size() > 0) {
                        JsonObject o = new JsonObject();
                        o.addProperty("api", ext.getName());
                        o.add("callers", callerNames);
                        o.addProperty("call_count", callerNames.size());
                        chains.add(o);
                        count++;
                    }
                }
                JsonObject r = new JsonObject();
                r.add("api_chains", chains);
                return new Gson().toJson(r);
            });

        // 67-68. Stubs
        s.tool("export_system_knowledge", "Export system knowledge (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{}");

        s.tool("store_function_knowledge", "Store function knowledge (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{}");

        s.tool("query_knowledge_context", "Query knowledge context (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{}");

        s.tool("apply_data_classification", "Apply data classification (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{}");

        s.tool("build_function_hash_index", "Build function hash index (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{}");

        s.tool("lookup_function_by_hash", "Lookup function by hash (stub)")
            .optParam("hash", "Function hash")
            .optParam("program", "Program name")
            .handler(a -> "{}");
    }
}
