package ghidramcp.tools;

import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.util.*;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class SymbolTools {

    private static byte[] parseHexBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        // 1. list_classes
        s.tool("list_classes", "List namespaces/classes in the program")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                Set<String> namespaces = new LinkedHashSet<>();
                SymbolIterator iter = st.getAllSymbols(true);
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        namespaces.add(ns.getName(true));
                    }
                }
                List<String> sorted = new ArrayList<>(namespaces);
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, sorted.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(sorted.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(sorted.size()).append(" namespaces]");
                return sb.toString();
            });

        // 2. list_namespaces (alias)
        s.tool("list_namespaces", "List namespaces in the program (alias for list_classes)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                Set<String> namespaces = new LinkedHashSet<>();
                SymbolIterator iter = st.getAllSymbols(true);
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        namespaces.add(ns.getName(true));
                    }
                }
                List<String> sorted = new ArrayList<>(namespaces);
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, sorted.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(sorted.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(sorted.size()).append(" namespaces]");
                return sb.toString();
            });

        // 3. list_segments
        s.tool("list_segments", "List memory blocks/segments")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                MemoryBlock[] blocks = p.getMemory().getBlocks();
                StringBuilder sb = new StringBuilder();
                for (MemoryBlock b : blocks) {
                    if (sb.length() > 0) sb.append("\n");
                    String perms = (b.isRead() ? "R" : "-") + (b.isWrite() ? "W" : "-") + (b.isExecute() ? "X" : "-");
                    sb.append(b.getName())
                      .append(" 0x").append(b.getStart().toString())
                      .append("-0x").append(b.getEnd().toString())
                      .append(" (").append(b.getSize()).append(" bytes) ")
                      .append(perms);
                }
                return sb.toString();
            });

        // 4. list_imports
        s.tool("list_imports", "List imported/external symbols")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                List<String> imports = new ArrayList<>();
                SymbolIterator iter = st.getExternalSymbols();
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    imports.add(sym.getName() + " @ " + fmt(sym.getAddress()) + " [" + sym.getParentNamespace().getName() + "]");
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, imports.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(imports.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(imports.size()).append(" imports]");
                return sb.toString();
            });

        // 5. list_exports
        s.tool("list_exports", "List exported symbols")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                List<String> exports = new ArrayList<>();
                SymbolIterator iter = st.getAllSymbols(true);
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    if (sym.isExternalEntryPoint()) {
                        exports.add(sym.getName() + " @ " + fmt(sym.getAddress()));
                    }
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, exports.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(exports.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(exports.size()).append(" exports]");
                return sb.toString();
            });

        // 6. list_data_items
        s.tool("list_data_items", "List defined data items")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                DataIterator diter = p.getListing().getDefinedData(true);
                List<String> items = new ArrayList<>();
                while (diter.hasNext()) {
                    Data d = diter.next();
                    items.add(fmt(d.getAddress()) + " " + d.getDataType().getName() +
                        " (" + d.getLength() + " bytes)" +
                        (d.hasStringValue() ? " = " + d.getDefaultValueRepresentation() : ""));
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, items.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(items.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(items.size()).append(" data items]");
                return sb.toString();
            });

        // 7. list_data_items_by_xrefs
        s.tool("list_data_items_by_xrefs", "List data items sorted by cross-reference count")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 50)")
            .intParam("min_xrefs", "Minimum xref count (default 1)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 50);
                int minXrefs = num(a, "min_xrefs", 1);
                ReferenceManager rm = p.getReferenceManager();
                DataIterator diter = p.getListing().getDefinedData(true);
                List<JsonObject> items = new ArrayList<>();
                while (diter.hasNext()) {
                    Data d = diter.next();
                    int count = rm.getReferenceCountTo(d.getAddress());
                    if (count >= minXrefs) {
                        JsonObject o = new JsonObject();
                        o.addProperty("address", fmt(d.getAddress()));
                        o.addProperty("type", d.getDataType().getName());
                        o.addProperty("xref_count", count);
                        o.addProperty("value", d.getDefaultValueRepresentation());
                        items.add(o);
                    }
                }
                items.sort((x, y) -> y.get("xref_count").getAsInt() - x.get("xref_count").getAsInt());
                JsonArray arr = new JsonArray();
                int end = Math.min(offset + limit, items.size());
                for (int i = offset; i < end; i++) arr.add(items.get(i));
                JsonObject r = new JsonObject();
                r.add("items", arr);
                r.addProperty("count", arr.size());
                r.addProperty("total", items.size());
                return new Gson().toJson(r);
            });

        // 8. list_globals
        s.tool("list_globals", "List global labels/symbols")
            .optParam("filter", "Filter by name substring")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String filter = str(a, "filter");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                List<String> globals = new ArrayList<>();
                SymbolIterator iter = st.getAllSymbols(true);
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    if (sym.getParentNamespace().isGlobal() && sym.getSymbolType() == SymbolType.LABEL) {
                        if (filter == null || sym.getName().toLowerCase().contains(filter.toLowerCase())) {
                            globals.add(sym.getName() + " @ " + fmt(sym.getAddress()));
                        }
                    }
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, globals.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(globals.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(globals.size()).append(" globals]");
                return sb.toString();
            });

        // 9. list_strings
        s.tool("list_strings", "List defined string data")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .intParam("min_length", "Minimum string length (default 4)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                int minLen = num(a, "min_length", 4);
                DataIterator diter = p.getListing().getDefinedData(true);
                List<String> strings = new ArrayList<>();
                while (diter.hasNext()) {
                    Data d = diter.next();
                    if (d.hasStringValue()) {
                        String val = d.getDefaultValueRepresentation();
                        if (val != null && val.length() >= minLen) {
                            strings.add(fmt(d.getAddress()) + " " + val);
                        }
                    }
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, strings.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(strings.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(strings.size()).append(" strings]");
                return sb.toString();
            });

        // 10. get_entry_points
        s.tool("get_entry_points", "List program entry points")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                SymbolTable st = p.getSymbolTable();
                StringBuilder sb = new StringBuilder();
                SymbolIterator iter = st.getAllSymbols(true);
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    if (sym.isExternalEntryPoint()) {
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(sym.getName() + " @ " + fmt(sym.getAddress()));
                    }
                }
                if (sb.length() == 0) sb.append("No entry points found");
                return sb.toString();
            });

        // 11. get_xrefs_to
        s.tool("get_xrefs_to", "Get cross-references to an address")
            .param("address", "Target address (hex)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                ReferenceManager rm = p.getReferenceManager();
                List<Reference> refs = new ArrayList<>();
                ReferenceIterator it = rm.getReferencesTo(address);
                while (it.hasNext()) refs.add(it.next());
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, refs.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    Reference ref = refs.get(i);
                    Function f = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    sb.append(fmt(ref.getFromAddress()))
                      .append(" -> ").append(fmt(ref.getToAddress()))
                      .append(" [").append(ref.getReferenceType().getName()).append("]");
                    if (f != null) sb.append(" in ").append(f.getName());
                }
                sb.append("\n[").append(end - offset).append(" of ").append(refs.size()).append(" xrefs]");
                return sb.toString();
            });

        // 12. get_xrefs_from
        s.tool("get_xrefs_from", "Get cross-references from an address")
            .param("address", "Source address (hex)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                ReferenceManager rm = p.getReferenceManager();
                Reference[] refs = rm.getReferencesFrom(address);
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, refs.length);
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    Reference ref = refs[i];
                    sb.append(fmt(ref.getFromAddress()))
                      .append(" -> ").append(fmt(ref.getToAddress()))
                      .append(" [").append(ref.getReferenceType().getName()).append("]");
                }
                sb.append("\n[").append(end - offset).append(" of ").append(refs.length).append(" xrefs]");
                return sb.toString();
            });

        // 13. list_external_locations (alias for list_imports)
        s.tool("list_external_locations", "List external locations (alias for list_imports)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                List<String> imports = new ArrayList<>();
                SymbolIterator iter = st.getExternalSymbols();
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    imports.add(sym.getName() + " @ " + fmt(sym.getAddress()) + " [" + sym.getParentNamespace().getName() + "]");
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, imports.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(imports.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(imports.size()).append(" external locations]");
                return sb.toString();
            });

        // 14. get_external_location (alias for list_imports)
        s.tool("get_external_location", "Get external location details (alias)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                SymbolTable st = p.getSymbolTable();
                List<String> imports = new ArrayList<>();
                SymbolIterator iter = st.getExternalSymbols();
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    imports.add(sym.getName() + " @ " + fmt(sym.getAddress()) + " [" + sym.getParentNamespace().getName() + "]");
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, imports.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(imports.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(imports.size()).append(" external locations]");
                return sb.toString();
            });

        // 15. list_bookmarks
        s.tool("list_bookmarks", "List bookmarks in the program")
            .optParam("category", "Filter by category")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String category = str(a, "category");
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                BookmarkManager bm = p.getBookmarkManager();
                List<String> bookmarks = new ArrayList<>();
                Iterator<Bookmark> iter = bm.getBookmarksIterator();
                while (iter.hasNext()) {
                    Bookmark b = iter.next();
                    if (category != null && !b.getCategory().equals(category)) continue;
                    bookmarks.add(fmt(b.getAddress()) + " [" + b.getCategory() + "] " + b.getComment());
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, bookmarks.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(bookmarks.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(bookmarks.size()).append(" bookmarks]");
                return sb.toString();
            });

        // 16. set_bookmark
        s.tool("set_bookmark", "Set a bookmark at an address")
            .param("address", "Address (hex)")
            .optParam("category", "Bookmark category (default MCP)")
            .optParam("comment", "Bookmark comment")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String category = str(a, "category", "MCP");
                String comment = str(a, "comment", "");
                int tx = p.startTransaction("Set bookmark");
                try {
                    p.getBookmarkManager().setBookmark(address, "Note", category, comment);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                return new Gson().toJson(r);
            });

        // 17. delete_bookmark
        s.tool("delete_bookmark", "Delete bookmarks at an address")
            .param("address", "Address (hex)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                BookmarkManager bm = p.getBookmarkManager();
                int tx = p.startTransaction("Delete bookmark");
                try {
                    Bookmark[] marks = bm.getBookmarks(address);
                    for (Bookmark b : marks) bm.removeBookmark(b);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                return new Gson().toJson(r);
            });

        // 18. create_label
        s.tool("create_label", "Create a label at an address")
            .param("address", "Address (hex)")
            .param("name", "Label name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String name = str(a, "name");
                int tx = p.startTransaction("Create label");
                try {
                    p.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                r.addProperty("name", name);
                return new Gson().toJson(r);
            });

        // 19. rename_label
        s.tool("rename_label", "Rename a label at an address")
            .param("address", "Address (hex)")
            .param("oldName", "Current label name")
            .param("newName", "New label name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String oldName = str(a, "oldName");
                String newName = str(a, "newName");
                SymbolTable st = p.getSymbolTable();
                Symbol sym = null;
                for (Symbol s2 : st.getSymbols(address)) {
                    if (s2.getName().equals(oldName)) { sym = s2; break; }
                }
                if (sym == null) throw new Exception("Label not found: " + oldName + " at " + fmt(address));
                int tx = p.startTransaction("Rename label");
                try {
                    sym.setName(newName, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                r.addProperty("old_name", oldName);
                r.addProperty("new_name", newName);
                return new Gson().toJson(r);
            });

        // 20. rename_or_label
        s.tool("rename_or_label", "Rename function or create label at address")
            .param("address", "Address (hex)")
            .param("name", "New name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String name = str(a, "name");
                int tx = p.startTransaction("Rename or label");
                try {
                    // Try function rename first
                    Function f = p.getFunctionManager().getFunctionAt(address);
                    if (f == null) f = p.getFunctionManager().getFunctionContaining(address);
                    if (f != null) {
                        f.setName(name, SourceType.USER_DEFINED);
                        p.endTransaction(tx, true);
                        JsonObject r = new JsonObject();
                        r.addProperty("success", true);
                        r.addProperty("type", "function_rename");
                        r.addProperty("address", fmt(address));
                        r.addProperty("name", name);
                        return new Gson().toJson(r);
                    }
                    // Try existing symbol rename
                    Symbol[] syms = p.getSymbolTable().getSymbols(address);
                    if (syms.length > 0) {
                        syms[0].setName(name, SourceType.USER_DEFINED);
                        p.endTransaction(tx, true);
                        JsonObject r = new JsonObject();
                        r.addProperty("success", true);
                        r.addProperty("type", "symbol_rename");
                        r.addProperty("address", fmt(address));
                        r.addProperty("name", name);
                        return new Gson().toJson(r);
                    }
                    // Create new label
                    p.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("type", "label_created");
                    r.addProperty("address", fmt(address));
                    r.addProperty("name", name);
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 21. delete_label
        s.tool("delete_label", "Delete a label at an address")
            .param("address", "Address (hex)")
            .optParam("name", "Label name (deletes first if not specified)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String name = str(a, "name");
                SymbolTable st = p.getSymbolTable();
                Symbol sym = null;
                if (name != null) {
                    for (Symbol s2 : st.getSymbols(address)) {
                        if (s2.getName().equals(name)) { sym = s2; break; }
                    }
                } else {
                    Symbol[] syms = st.getSymbols(address);
                    if (syms.length > 0) sym = syms[0];
                }
                if (sym == null) throw new Exception("No label found at " + fmt(address));
                int tx = p.startTransaction("Delete label");
                try {
                    sym.delete();
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                return new Gson().toJson(r);
            });

        // 22. batch_create_labels
        s.tool("batch_create_labels", "Create multiple labels at once")
            .param("labels", "JSON array of {address, name}")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String labelsStr = str(a, "labels");
                JsonArray arr = JsonParser.parseString(labelsStr).getAsJsonArray();
                int tx = p.startTransaction("Batch create labels");
                try {
                    int created = 0;
                    for (JsonElement el : arr) {
                        JsonObject lo = el.getAsJsonObject();
                        String addrStr = lo.get("address").getAsString();
                        String name = lo.get("name").getAsString();
                        var address = addr(p, addrStr);
                        if (address != null) {
                            p.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                            created++;
                        }
                    }
                    p.endTransaction(tx, true);
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("created", created);
                    r.addProperty("total", arr.size());
                    return new Gson().toJson(r);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
            });

        // 23. batch_delete_labels (stub)
        s.tool("batch_delete_labels", "Delete multiple labels (stub)")
            .param("labels", "JSON array of {address, name}")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":true,\"deleted\":0}");

        // 24. rename_data
        s.tool("rename_data", "Rename data at an address")
            .param("address", "Address (hex)")
            .param("newName", "New name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String newName = str(a, "newName");
                SymbolTable st = p.getSymbolTable();
                int tx = p.startTransaction("Rename data");
                try {
                    Symbol[] syms = st.getSymbols(address);
                    if (syms.length > 0) {
                        syms[0].setName(newName, SourceType.USER_DEFINED);
                    } else {
                        st.createLabel(address, newName, SourceType.USER_DEFINED);
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                r.addProperty("name", newName);
                return new Gson().toJson(r);
            });

        // 25. rename_external_location (alias for rename_data)
        s.tool("rename_external_location", "Rename an external location (alias)")
            .param("address", "Address (hex)")
            .param("newName", "New name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                String newName = str(a, "newName");
                SymbolTable st = p.getSymbolTable();
                int tx = p.startTransaction("Rename external location");
                try {
                    Symbol[] syms = st.getSymbols(address);
                    if (syms.length > 0) {
                        syms[0].setName(newName, SourceType.USER_DEFINED);
                    } else {
                        st.createLabel(address, newName, SourceType.USER_DEFINED);
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                r.addProperty("name", newName);
                return new Gson().toJson(r);
            });

        // 26. rename_global_variable
        s.tool("rename_global_variable", "Rename a global variable by its current name")
            .param("oldName", "Current variable name")
            .param("newName", "New variable name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String oldName = str(a, "oldName");
                String newName = str(a, "newName");
                SymbolTable st = p.getSymbolTable();
                SymbolIterator iter = st.getAllSymbols(true);
                Symbol found = null;
                while (iter.hasNext()) {
                    Symbol sym = iter.next();
                    if (sym.getName().equals(oldName)) { found = sym; break; }
                }
                if (found == null) throw new Exception("Symbol not found: " + oldName);
                int tx = p.startTransaction("Rename global variable");
                try {
                    found.setName(newName, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("old_name", oldName);
                r.addProperty("new_name", newName);
                r.addProperty("address", fmt(found.getAddress()));
                return new Gson().toJson(r);
            });

        // 27. search_byte_patterns
        s.tool("search_byte_patterns", "Search for byte patterns in memory")
            .param("pattern", "Hex byte string (e.g. '4889e5')")
            .optParam("mask", "Hex mask bytes (ff = must match, 00 = wildcard)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                byte[] pattern = parseHexBytes(str(a, "pattern"));
                String maskStr = str(a, "mask");
                byte[] mask = maskStr != null ? parseHexBytes(maskStr) : null;
                Memory mem = p.getMemory();
                StringBuilder sb = new StringBuilder();
                int count = 0;
                Address start = p.getMinAddress();
                while (start != null && count < 100) {
                    Address found;
                    if (mask != null) {
                        found = mem.findBytes(start, pattern, mask, true, TaskMonitor.DUMMY);
                    } else {
                        found = mem.findBytes(start, pattern, null, true, TaskMonitor.DUMMY);
                    }
                    if (found == null) break;
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(fmt(found));
                    Function f = p.getFunctionManager().getFunctionContaining(found);
                    if (f != null) sb.append(" in ").append(f.getName());
                    count++;
                    try { start = found.add(1); } catch (Exception e) { break; }
                }
                if (count == 0) return "No matches found";
                sb.append("\n[").append(count).append(" matches]");
                return sb.toString();
            });

        // 28. search_memory_strings
        s.tool("search_memory_strings", "Search defined strings containing a query")
            .param("query", "Search text")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String query = str(a, "query").toLowerCase();
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                DataIterator diter = p.getListing().getDefinedData(true);
                List<String> matches = new ArrayList<>();
                while (diter.hasNext()) {
                    Data d = diter.next();
                    if (d.hasStringValue()) {
                        String val = d.getDefaultValueRepresentation();
                        if (val != null && val.toLowerCase().contains(query)) {
                            matches.add(fmt(d.getAddress()) + " " + val);
                        }
                    }
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, matches.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(matches.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(matches.size()).append(" matches]");
                return sb.toString();
            });

        // 29. disassemble_bytes
        s.tool("disassemble_bytes", "Disassemble bytes at an address")
            .param("address", "Address (hex)")
            .intParam("length", "Number of bytes to disassemble (default 64)")
            .boolParam("clear_existing", "Clear existing code/data first (default false)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                int length = num(a, "length", 64);
                boolean clear = bool(a, "clear_existing", false);
                AddressSet addrSet = new AddressSet(address, address.add(length - 1));
                int tx = p.startTransaction("Disassemble");
                try {
                    if (clear) {
                        p.getListing().clearCodeUnits(address, address.add(length - 1), false);
                    }
                    DisassembleCommand cmd = new DisassembleCommand(address, addrSet, true);
                    cmd.applyTo(p, TaskMonitor.DUMMY);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                // Read back disassembled instructions
                StringBuilder sb = new StringBuilder();
                InstructionIterator iter = p.getListing().getInstructions(addrSet, true);
                while (iter.hasNext()) {
                    Instruction inst = iter.next();
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(fmt(inst.getAddress())).append("  ").append(inst.toString());
                }
                if (sb.length() == 0) sb.append("No instructions disassembled");
                return sb.toString();
            });

        // 30. analyze_data_region
        s.tool("analyze_data_region", "Analyze data at an address")
            .param("address", "Address (hex)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                Data data = p.getListing().getDefinedDataAt(address);
                JsonObject r = new JsonObject();
                r.addProperty("address", fmt(address));
                if (data != null) {
                    r.addProperty("defined", true);
                    r.addProperty("type", data.getDataType().getName());
                    r.addProperty("size", data.getLength());
                    r.addProperty("value", data.getDefaultValueRepresentation());
                    // Xrefs
                    ReferenceManager rm = p.getReferenceManager();
                    r.addProperty("xref_to_count", rm.getReferenceCountTo(address));
                    Reference[] from = rm.getReferencesFrom(address);
                    r.addProperty("xref_from_count", from.length);
                    // Containing function
                    Function f = p.getFunctionManager().getFunctionContaining(address);
                    if (f != null) r.addProperty("function", f.getName());
                    // Memory block
                    MemoryBlock block = p.getMemory().getBlock(address);
                    if (block != null) r.addProperty("block", block.getName());
                } else {
                    r.addProperty("defined", false);
                    MemoryBlock block = p.getMemory().getBlock(address);
                    if (block != null) {
                        r.addProperty("block", block.getName());
                        r.addProperty("block_permissions",
                            (block.isRead() ? "R" : "") + (block.isWrite() ? "W" : "") + (block.isExecute() ? "X" : ""));
                    }
                }
                return new Gson().toJson(r);
            });

        // 31. detect_array_bounds (stub)
        s.tool("detect_array_bounds", "Detect array boundaries at an address (stub)")
            .param("address", "Address (hex)")
            .optParam("program", "Program name")
            .handler(a -> {
                JsonObject r = new JsonObject();
                r.addProperty("detected", false);
                return new Gson().toJson(r);
            });

        // 32. inspect_memory_content
        s.tool("inspect_memory_content", "Hex dump memory at an address")
            .param("address", "Address (hex)")
            .intParam("length", "Number of bytes (default 256)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                int length = num(a, "length", 256);
                byte[] data = new byte[length];
                int read = p.getMemory().getBytes(address, data);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < read; i += 16) {
                    sb.append(fmt(address.add(i))).append("  ");
                    // Hex part
                    for (int j = 0; j < 16 && i + j < read; j++) {
                        if (j == 8) sb.append(" ");
                        sb.append(String.format("%02x ", data[i + j] & 0xff));
                    }
                    // Pad if last line is short
                    int remaining = Math.min(16, read - i);
                    for (int j = remaining; j < 16; j++) {
                        if (j == 8) sb.append(" ");
                        sb.append("   ");
                    }
                    // ASCII part
                    sb.append(" |");
                    for (int j = 0; j < 16 && i + j < read; j++) {
                        int b = data[i + j] & 0xff;
                        sb.append(b >= 0x20 && b <= 0x7e ? (char) b : '.');
                    }
                    sb.append("|\n");
                }
                return sb.toString();
            });

        // 33. create_memory_block (stub)
        s.tool("create_memory_block", "Create a memory block (stub)")
            .param("name", "Block name")
            .param("address", "Start address")
            .intParam("size", "Block size")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":false,\"note\":\"Not implemented via MCP\"}");

        // 34. get_ordinal_mapping / store_ordinal_mapping (stubs)
        s.tool("get_ordinal_mapping", "Get ordinal mapping (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{\"mappings\":{}}");

        s.tool("store_ordinal_mapping", "Store ordinal mapping (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":true}");

        // 35. get_assembly_context
        s.tool("get_assembly_context", "Get assembly context at addresses")
            .param("addresses", "Comma-separated addresses (hex)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String[] addrs = str(a, "addresses").split(",");
                JsonArray results = new JsonArray();
                for (String addrStr : addrs) {
                    var address = addr(p, addrStr.trim());
                    if (address == null) continue;
                    JsonObject item = new JsonObject();
                    item.addProperty("address", fmt(address));
                    // Instruction info
                    Instruction inst = p.getListing().getInstructionAt(address);
                    if (inst != null) {
                        item.addProperty("mnemonic", inst.getMnemonicString());
                        item.addProperty("instruction", inst.toString());
                        item.addProperty("length", inst.getLength());
                        // Bytes
                        byte[] bytes = inst.getBytes();
                        StringBuilder hex = new StringBuilder();
                        for (byte b : bytes) hex.append(String.format("%02x", b & 0xff));
                        item.addProperty("bytes", hex.toString());
                    }
                    // Function context
                    Function f = p.getFunctionManager().getFunctionContaining(address);
                    if (f != null) {
                        item.addProperty("function", f.getName());
                        item.addProperty("function_address", fmt(f.getEntryPoint()));
                    }
                    // Data info
                    Data data = p.getListing().getDefinedDataAt(address);
                    if (data != null) {
                        item.addProperty("data_type", data.getDataType().getName());
                        item.addProperty("data_value", data.getDefaultValueRepresentation());
                    }
                    // Memory block
                    MemoryBlock block = p.getMemory().getBlock(address);
                    if (block != null) item.addProperty("block", block.getName());
                    results.add(item);
                }
                JsonObject r = new JsonObject();
                r.add("contexts", results);
                return new Gson().toJson(r);
            });
    }
}
