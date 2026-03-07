package ghidramcp.tools;

import com.google.gson.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.util.*;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class DataTypeTools {

    private static DataType findType(Program p, String name) {
        if (name == null || name.isEmpty()) return null;
        DataTypeManager dtm = p.getDataTypeManager();
        // Search program DTM
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) { DataType dt = it.next(); if (dt.getName().equals(name) || dt.getPathName().equals(name)) return dt; }
        // Search built-in types
        DataTypeManager builtin = BuiltInDataTypeManager.getDataTypeManager();
        Iterator<DataType> bit = builtin.getAllDataTypes();
        while (bit.hasNext()) { DataType dt = bit.next(); if (dt.getName().equals(name) || dt.getPathName().equals(name)) return dt; }
        // Try parsing pointer/array syntax
        if (name.endsWith("*")) {
            DataType base = findType(p, name.substring(0, name.length() - 1).trim());
            if (base != null) return new PointerDataType(base);
        }
        return null;
    }

    private static List<String> splitJsonArray(String inner) {
        List<String> items = new ArrayList<>();
        if (inner == null || inner.isEmpty()) return items;
        int depth = 0;
        int start = 0;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            else if (c == ',' && depth == 0) {
                items.add(inner.substring(start, i).trim());
                start = i + 1;
            }
        }
        String last = inner.substring(start).trim();
        if (!last.isEmpty()) items.add(last);
        return items;
    }

    private static void collectCategories(Category cat, List<String> list, String prefix) {
        String path = prefix.isEmpty() ? cat.getName() : prefix + "/" + cat.getName();
        list.add(path);
        for (Category sub : cat.getCategories()) {
            collectCategories(sub, list, path);
        }
    }

    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        // 1. list_data_types
        s.tool("list_data_types", "List data types with pagination")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("category", "Filter by category path")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                String category = str(a, "category");
                DataTypeManager dtm = p.getDataTypeManager();
                List<String> lines = new ArrayList<>();
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (category != null && !dt.getCategoryPath().getPath().contains(category)) continue;
                    String catPath = dt.getCategoryPath().getPath();
                    lines.add(dt.getName() + " (" + dt.getLength() + " bytes) [" + catPath + "]");
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, lines.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(lines.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(lines.size()).append(" total]");
                return sb.toString();
            });

        // 2. search_data_types
        s.tool("search_data_types", "Search data types by name pattern")
            .param("pattern", "Search pattern (substring match)")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String pattern = str(a, "pattern").toLowerCase();
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                DataTypeManager dtm = p.getDataTypeManager();
                List<String> lines = new ArrayList<>();
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (dt.getName().toLowerCase().contains(pattern)) {
                        String catPath = dt.getCategoryPath().getPath();
                        lines.add(dt.getName() + " (" + dt.getLength() + " bytes) [" + catPath + "]");
                    }
                }
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, lines.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(lines.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(lines.size()).append(" matches]");
                return sb.toString();
            });

        // 3. get_data_type_size
        s.tool("get_data_type_size", "Get the size of a data type")
            .param("type_name", "Data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "type_name"));
                if (dt == null) throw new Exception("Data type not found: " + str(a, "type_name"));
                JsonObject r = new JsonObject();
                r.addProperty("type", dt.getName());
                r.addProperty("size", dt.getLength());
                return new Gson().toJson(r);
            });

        // 4. get_struct_layout
        s.tool("get_struct_layout", "Get structure layout with field details")
            .param("struct_name", "Structure name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "struct_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "struct_name"));
                if (!(dt instanceof Structure)) throw new Exception("Not a structure: " + dt.getName());
                Structure st = (Structure) dt;
                JsonObject r = new JsonObject();
                r.addProperty("name", st.getName());
                r.addProperty("size", st.getLength());
                r.addProperty("alignment", st.getAlignment());
                JsonArray fields = new JsonArray();
                for (DataTypeComponent comp : st.getComponents()) {
                    JsonObject f = new JsonObject();
                    f.addProperty("name", comp.getFieldName() != null ? comp.getFieldName() : "field_" + comp.getOrdinal());
                    f.addProperty("type", comp.getDataType().getName());
                    f.addProperty("offset", comp.getOffset());
                    f.addProperty("size", comp.getLength());
                    f.addProperty("comment", comp.getComment() != null ? comp.getComment() : "");
                    fields.add(f);
                }
                r.add("fields", fields);
                return new Gson().toJson(r);
            });

        // 5. get_enum_values
        s.tool("get_enum_values", "Get enum type entries")
            .param("enum_name", "Enum type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "enum_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "enum_name"));
                if (!(dt instanceof ghidra.program.model.data.Enum))
                    throw new Exception("Not an enum: " + dt.getName());
                ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
                StringBuilder sb = new StringBuilder();
                for (String name : en.getNames()) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(name).append(" = ").append(en.getValue(name));
                }
                return sb.toString();
            });

        // 6. list_data_type_categories
        s.tool("list_data_type_categories", "List all data type categories")
            .intParam("offset", "Start offset (default 0)")
            .intParam("limit", "Max results (default 100)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                int offset = num(a, "offset", 0);
                int limit = num(a, "limit", 100);
                DataTypeManager dtm = p.getDataTypeManager();
                List<String> cats = new ArrayList<>();
                Category root = dtm.getRootCategory();
                collectCategories(root, cats, "");
                StringBuilder sb = new StringBuilder();
                int end = Math.min(offset + limit, cats.size());
                for (int i = offset; i < end; i++) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(cats.get(i));
                }
                sb.append("\n[").append(end - offset).append(" of ").append(cats.size()).append(" categories]");
                return sb.toString();
            });

        // 7. get_valid_data_types
        s.tool("get_valid_data_types", "List all data type names")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataTypeManager dtm = p.getDataTypeManager();
                StringBuilder sb = new StringBuilder();
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(dt.getPathName());
                }
                return sb.toString();
            });

        // 8. validate_data_type_exists
        s.tool("validate_data_type_exists", "Check if a data type exists")
            .param("type_name", "Data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "type_name");
                DataType dt = findType(p, name);
                JsonObject r = new JsonObject();
                r.addProperty("exists", dt != null);
                r.addProperty("type_name", name);
                r.addProperty("resolved_name", dt != null ? dt.getPathName() : "");
                return new Gson().toJson(r);
            });

        // 9. validate_data_type (alias)
        s.tool("validate_data_type", "Check if a data type exists (alias)")
            .param("type_name", "Data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "type_name");
                DataType dt = findType(p, name);
                JsonObject r = new JsonObject();
                r.addProperty("exists", dt != null);
                r.addProperty("type_name", name);
                r.addProperty("resolved_name", dt != null ? dt.getPathName() : "");
                return new Gson().toJson(r);
            });

        // 10. suggest_field_names
        s.tool("suggest_field_names", "Suggest field names for a structure (stub)")
            .param("struct_name", "Structure name")
            .optParam("program", "Program name")
            .handler(a -> {
                JsonObject r = new JsonObject();
                r.add("suggestions", new JsonArray());
                return new Gson().toJson(r);
            });

        // 11. create_struct
        s.tool("create_struct", "Create a new structure data type")
            .param("name", "Structure name")
            .optParam("fields", "JSON array of {name, type, comment}")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "name");
                DataTypeManager dtm = p.getDataTypeManager();
                StructureDataType st = new StructureDataType(name, 0);
                String fieldsStr = str(a, "fields");
                if (fieldsStr != null && !fieldsStr.isEmpty()) {
                    JsonArray arr = JsonParser.parseString(fieldsStr).getAsJsonArray();
                    for (JsonElement el : arr) {
                        JsonObject fo = el.getAsJsonObject();
                        String fn = fo.has("name") ? fo.get("name").getAsString() : null;
                        String ft = fo.has("type") ? fo.get("type").getAsString() : "byte";
                        String fc = fo.has("comment") ? fo.get("comment").getAsString() : null;
                        DataType fdt = findType(p, ft);
                        if (fdt == null) fdt = findType(p, "byte");
                        st.add(fdt, fdt.getLength(), fn, fc);
                    }
                }
                int tx = p.startTransaction("Create struct " + name);
                try {
                    dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("name", name);
                r.addProperty("size", st.getLength());
                return new Gson().toJson(r);
            });

        // 12. create_enum
        s.tool("create_enum", "Create a new enum data type")
            .param("name", "Enum name")
            .intParam("size", "Enum size in bytes (default 4)")
            .optParam("values", "JSON object of name:value pairs")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "name");
                int size = num(a, "size", 4);
                DataTypeManager dtm = p.getDataTypeManager();
                EnumDataType en = new EnumDataType(name, size);
                String valuesStr = str(a, "values");
                if (valuesStr != null && !valuesStr.isEmpty()) {
                    JsonObject vals = JsonParser.parseString(valuesStr).getAsJsonObject();
                    for (Map.Entry<String, JsonElement> e : vals.entrySet()) {
                        en.add(e.getKey(), e.getValue().getAsLong());
                    }
                }
                int tx = p.startTransaction("Create enum " + name);
                try {
                    dtm.addDataType(en, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("name", name);
                return new Gson().toJson(r);
            });

        // 13. create_union
        s.tool("create_union", "Create a new union data type")
            .param("name", "Union name")
            .optParam("fields", "JSON array of {name, type, comment}")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "name");
                DataTypeManager dtm = p.getDataTypeManager();
                UnionDataType un = new UnionDataType(name);
                String fieldsStr = str(a, "fields");
                if (fieldsStr != null && !fieldsStr.isEmpty()) {
                    JsonArray arr = JsonParser.parseString(fieldsStr).getAsJsonArray();
                    for (JsonElement el : arr) {
                        JsonObject fo = el.getAsJsonObject();
                        String fn = fo.has("name") ? fo.get("name").getAsString() : null;
                        String ft = fo.has("type") ? fo.get("type").getAsString() : "byte";
                        String fc = fo.has("comment") ? fo.get("comment").getAsString() : null;
                        DataType fdt = findType(p, ft);
                        if (fdt == null) fdt = findType(p, "byte");
                        un.add(fdt, fdt.getLength(), fn, fc);
                    }
                }
                int tx = p.startTransaction("Create union " + name);
                try {
                    dtm.addDataType(un, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("name", name);
                return new Gson().toJson(r);
            });

        // 14. create_typedef
        s.tool("create_typedef", "Create a typedef data type")
            .param("name", "Typedef name")
            .param("base_type", "Base type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String name = str(a, "name");
                DataType base = findType(p, str(a, "base_type"));
                if (base == null) throw new Exception("Base type not found: " + str(a, "base_type"));
                DataTypeManager dtm = p.getDataTypeManager();
                TypedefDataType td = new TypedefDataType(name, base);
                int tx = p.startTransaction("Create typedef " + name);
                try {
                    dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("name", name);
                r.addProperty("base_type", base.getName());
                return new Gson().toJson(r);
            });

        // 15. create_array_type
        s.tool("create_array_type", "Create an array data type")
            .param("base_type", "Element type name")
            .intParam("length", "Number of elements")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType base = findType(p, str(a, "base_type"));
                if (base == null) throw new Exception("Base type not found: " + str(a, "base_type"));
                int length = num(a, "length", 1);
                DataTypeManager dtm = p.getDataTypeManager();
                ArrayDataType arr = new ArrayDataType(base, length, base.getLength());
                int tx = p.startTransaction("Create array type");
                try {
                    dtm.addDataType(arr, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("type", arr.getName());
                r.addProperty("element_type", base.getName());
                r.addProperty("length", length);
                return new Gson().toJson(r);
            });

        // 16. create_pointer_type
        s.tool("create_pointer_type", "Create a pointer data type")
            .param("base_type", "Pointed-to type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType base = findType(p, str(a, "base_type"));
                if (base == null) throw new Exception("Base type not found: " + str(a, "base_type"));
                DataTypeManager dtm = p.getDataTypeManager();
                PointerDataType ptr = new PointerDataType(base);
                int tx = p.startTransaction("Create pointer type");
                try {
                    dtm.addDataType(ptr, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("type", ptr.getName());
                return new Gson().toJson(r);
            });

        // 17. create_data_type_category
        s.tool("create_data_type_category", "Create a data type category")
            .param("category_path", "Category path (e.g. /MyCategory/SubCat)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String path = str(a, "category_path");
                DataTypeManager dtm = p.getDataTypeManager();
                int tx = p.startTransaction("Create category " + path);
                try {
                    dtm.createCategory(new CategoryPath(path));
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("category_path", path);
                return new Gson().toJson(r);
            });

        // 18. move_data_type_to_category
        s.tool("move_data_type_to_category", "Move a data type to a different category")
            .param("type_name", "Data type name")
            .param("category_path", "Target category path")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "type_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "type_name"));
                String path = str(a, "category_path");
                DataTypeManager dtm = p.getDataTypeManager();
                int tx = p.startTransaction("Move type to " + path);
                try {
                    Category cat = dtm.createCategory(new CategoryPath(path));
                    cat.moveDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("type", dt.getName());
                r.addProperty("category", path);
                return new Gson().toJson(r);
            });

        // 19. clone_data_type
        s.tool("clone_data_type", "Clone a data type with a new name")
            .param("source_type", "Source data type name")
            .param("new_name", "New name for the clone")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType src = findType(p, str(a, "source_type"));
                if (src == null) throw new Exception("Source type not found: " + str(a, "source_type"));
                String newName = str(a, "new_name");
                DataType clone = src.clone(p.getDataTypeManager());
                try { clone.setName(newName); } catch (Exception ignored) {}
                DataTypeManager dtm = p.getDataTypeManager();
                int tx = p.startTransaction("Clone type " + src.getName());
                try {
                    dtm.addDataType(clone, DataTypeConflictHandler.REPLACE_HANDLER);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("source", src.getName());
                r.addProperty("new_name", newName);
                return new Gson().toJson(r);
            });

        // 20. apply_data_type
        s.tool("apply_data_type", "Apply a data type at an address")
            .param("address", "Address (hex)")
            .param("type_name", "Data type name")
            .boolParam("clear_existing", "Clear existing data (default true)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                DataType dt = findType(p, str(a, "type_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "type_name"));
                boolean clear = bool(a, "clear_existing", true);
                int tx = p.startTransaction("Apply data type");
                try {
                    ghidra.program.model.data.DataUtilities.ClearDataMode mode = clear
                        ? ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
                        : ghidra.program.model.data.DataUtilities.ClearDataMode.CHECK_FOR_SPACE;
                    ghidra.program.model.data.DataUtilities.createData(p, address, dt, dt.getLength(), mode);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("address", fmt(address));
                r.addProperty("type", dt.getName());
                return new Gson().toJson(r);
            });

        // 21. delete_data_type
        s.tool("delete_data_type", "Delete a data type")
            .param("type_name", "Data type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "type_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "type_name"));
                DataTypeManager dtm = p.getDataTypeManager();
                int tx = p.startTransaction("Delete type " + dt.getName());
                try {
                    dtm.remove(dt, TaskMonitor.DUMMY);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("deleted", dt.getName());
                return new Gson().toJson(r);
            });

        // 22. modify_struct_field
        s.tool("modify_struct_field", "Modify a field in a structure")
            .param("struct_name", "Structure name")
            .param("field_name", "Field to modify")
            .optParam("new_name", "New field name")
            .optParam("new_type", "New field type")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "struct_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "struct_name"));
                if (!(dt instanceof Structure)) throw new Exception("Not a structure: " + dt.getName());
                Structure st = (Structure) dt;
                String fieldName = str(a, "field_name");
                int ordinal = -1;
                for (DataTypeComponent comp : st.getComponents()) {
                    if (fieldName.equals(comp.getFieldName())) { ordinal = comp.getOrdinal(); break; }
                }
                if (ordinal < 0) throw new Exception("Field not found: " + fieldName);
                String newName = str(a, "new_name");
                String newType = str(a, "new_type");
                int tx = p.startTransaction("Modify struct field");
                try {
                    if (newType != null) {
                        DataType ndt = findType(p, newType);
                        if (ndt == null) throw new Exception("Type not found: " + newType);
                        String name = newName != null ? newName : fieldName;
                        st.replace(ordinal, ndt, ndt.getLength(), name, null);
                    } else if (newName != null) {
                        DataTypeComponent comp = st.getComponent(ordinal);
                        st.replace(ordinal, comp.getDataType(), comp.getLength(), newName, null);
                    }
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("struct", st.getName());
                return new Gson().toJson(r);
            });

        // 23. add_struct_field
        s.tool("add_struct_field", "Add a field to a structure")
            .param("struct_name", "Structure name")
            .param("field_name", "New field name")
            .param("field_type", "Field type name")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "struct_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "struct_name"));
                if (!(dt instanceof Structure)) throw new Exception("Not a structure: " + dt.getName());
                Structure st = (Structure) dt;
                DataType fdt = findType(p, str(a, "field_type"));
                if (fdt == null) throw new Exception("Field type not found: " + str(a, "field_type"));
                int tx = p.startTransaction("Add struct field");
                try {
                    st.add(fdt, fdt.getLength(), str(a, "field_name"), null);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("struct", st.getName());
                r.addProperty("field", str(a, "field_name"));
                return new Gson().toJson(r);
            });

        // 24. remove_struct_field
        s.tool("remove_struct_field", "Remove a field from a structure")
            .param("struct_name", "Structure name")
            .param("field_name", "Field name to remove")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                DataType dt = findType(p, str(a, "struct_name"));
                if (dt == null) throw new Exception("Type not found: " + str(a, "struct_name"));
                if (!(dt instanceof Structure)) throw new Exception("Not a structure: " + dt.getName());
                Structure st = (Structure) dt;
                String fieldName = str(a, "field_name");
                int ordinal = -1;
                for (DataTypeComponent comp : st.getComponents()) {
                    if (fieldName.equals(comp.getFieldName())) { ordinal = comp.getOrdinal(); break; }
                }
                if (ordinal < 0) throw new Exception("Field not found: " + fieldName);
                int tx = p.startTransaction("Remove struct field");
                try {
                    st.delete(ordinal);
                    p.endTransaction(tx, true);
                } catch (Exception e) { p.endTransaction(tx, false); throw e; }
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("struct", st.getName());
                r.addProperty("removed", fieldName);
                return new Gson().toJson(r);
            });

        // 25. import_data_types (stub)
        s.tool("import_data_types", "Import data types from file (not supported)")
            .optParam("source", "Source file path")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":false,\"note\":\"Import not supported via MCP\"}");

        // 26. consolidate_duplicate_types (stub)
        s.tool("consolidate_duplicate_types", "Consolidate duplicate data types (stub)")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":true,\"consolidated\":0}");

        // 27. analyze_struct_field_usage (stub)
        s.tool("analyze_struct_field_usage", "Analyze structure field usage (stub)")
            .param("struct_name", "Structure name")
            .optParam("program", "Program name")
            .handler(a -> {
                JsonObject r = new JsonObject();
                r.add("usage", new JsonArray());
                return new Gson().toJson(r);
            });

        // 28. get_field_access_context (stub)
        s.tool("get_field_access_context", "Get field access context (stub)")
            .param("struct_name", "Structure name")
            .param("field_name", "Field name")
            .optParam("program", "Program name")
            .handler(a -> {
                JsonObject r = new JsonObject();
                r.add("accesses", new JsonArray());
                return new Gson().toJson(r);
            });
    }
}
