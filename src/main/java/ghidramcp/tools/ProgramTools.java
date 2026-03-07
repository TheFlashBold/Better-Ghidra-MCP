package ghidramcp.tools;

import com.google.gson.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class ProgramTools {
    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        s.tool("check_connection", "Check if Ghidra MCP server is running")
            .handler(a -> "OK");

        s.tool("get_version", "Get GhidraMCP version")
            .handler(a -> "GhidraMCP 2.0.0 (native MCP)");

        s.tool("list_open_programs", "List all open programs in Ghidra")
            .optParam("program", "Program name")
            .handler(a -> {
                AtomicReference<String> ref = new AtomicReference<>();
                Swing.runNow(() -> {
                    ProgramManager pm = plugin.getProgramManager();
                    if (pm == null) { ref.set("{\"error\":\"No program manager\"}"); return; }
                    Program[] programs = pm.getAllOpenPrograms();
                    Program current = pm.getCurrentProgram();
                    JsonArray list = new JsonArray();
                    for (Program p : programs) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", p.getName());
                        o.addProperty("path", p.getDomainFile().getPathname());
                        o.addProperty("is_current", p == current);
                        o.addProperty("language", p.getLanguageID().toString());
                        o.addProperty("image_base", fmt(p.getImageBase()));
                        o.addProperty("function_count", p.getFunctionManager().getFunctionCount());
                        list.add(o);
                    }
                    JsonObject r = new JsonObject();
                    r.add("programs", list);
                    r.addProperty("count", programs.length);
                    r.addProperty("current_program", current != null ? current.getName() : "");
                    ref.set(new Gson().toJson(r));
                });
                return ref.get();
            });

        s.tool("get_current_program_info", "Get detailed info about the current program")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonObject r = new JsonObject();
                r.addProperty("name", p.getName());
                r.addProperty("path", p.getDomainFile().getPathname());
                r.addProperty("executable_format", p.getExecutableFormat());
                r.addProperty("language", p.getLanguageID().toString());
                r.addProperty("compiler", p.getCompilerSpec().getCompilerSpecID().toString());
                r.addProperty("address_size", p.getDefaultPointerSize());
                r.addProperty("image_base", fmt(p.getImageBase()));
                r.addProperty("min_address", fmt(p.getMinAddress()));
                r.addProperty("max_address", fmt(p.getMaxAddress()));
                r.addProperty("memory_block_count", p.getMemory().getBlocks().length);
                r.addProperty("function_count", p.getFunctionManager().getFunctionCount());
                r.addProperty("symbol_count", p.getSymbolTable().getNumSymbols());
                return new Gson().toJson(r);
            });

        s.tool("get_metadata", "Get program metadata")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonObject r = new JsonObject();
                r.addProperty("name", p.getName());
                r.addProperty("language", p.getLanguageID().toString());
                r.addProperty("compiler", p.getCompilerSpec().getCompilerSpecID().toString());
                r.addProperty("image_base", fmt(p.getImageBase()));
                r.addProperty("function_count", p.getFunctionManager().getFunctionCount());
                return new Gson().toJson(r);
            });

        s.tool("switch_program", "Switch to a different open program")
            .param("name", "Program name to switch to")
            .handler(a -> {
                Program p = plugin.getProgram(str(a, "name"));
                if (p == null) throw new Exception("Program not found: " + str(a, "name"));
                plugin.setDefaultProgram(p.getName());
                Swing.runNow(() -> {
                    ProgramManager pm = plugin.getProgramManager();
                    if (pm != null) pm.setCurrentProgram(p);
                });
                return "{\"success\":true,\"program\":\"" + p.getName() + "\"}";
            });

        s.tool("list_project_files", "List files in the Ghidra project")
            .optParam("folder", "Folder path (default /)")
            .handler(a -> {
                AtomicReference<String> ref = new AtomicReference<>();
                Swing.runNow(() -> {
                    Project project = plugin.getPluginTool().getProject();
                    if (project == null) { ref.set("{\"error\":\"No project open\"}"); return; }
                    ProjectData pd = project.getProjectData();
                    DomainFolder root = pd.getRootFolder();
                    String folder = str(a, "folder");
                    DomainFolder target = root;
                    if (folder != null && !folder.equals("/")) {
                        target = root.getFolder(folder.startsWith("/") ? folder.substring(1) : folder);
                        if (target == null) target = root;
                    }
                    JsonArray files = new JsonArray();
                    for (DomainFile df : target.getFiles()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("name", df.getName());
                        o.addProperty("path", df.getPathname());
                        o.addProperty("content_type", df.getContentType());
                        files.add(o);
                    }
                    JsonObject r = new JsonObject();
                    r.addProperty("project", pd.getProjectLocator().getName());
                    r.add("files", files);
                    ref.set(new Gson().toJson(r));
                });
                return ref.get();
            });

        s.tool("open_program", "Open a program from the project")
            .param("path", "Path within the project")
            .handler(a -> {
                AtomicReference<String> ref = new AtomicReference<>();
                Swing.runNow(() -> {
                    try {
                        Project project = plugin.getPluginTool().getProject();
                        if (project == null) { ref.set("{\"error\":\"No project open\"}"); return; }
                        DomainFile df = project.getProjectData().getFile(str(a, "path"));
                        if (df == null) { ref.set("{\"error\":\"File not found\"}"); return; }
                        ProgramManager pm = plugin.getProgramManager();
                        if (pm != null) {
                            Program p = (Program) df.getDomainObject(plugin, false, false, ghidra.util.task.TaskMonitor.DUMMY);
                            pm.openProgram(p);
                            plugin.setDefaultProgram(p.getName());
                            ref.set("{\"success\":true,\"name\":\"" + p.getName() + "\"}");
                        }
                    } catch (Exception e) { ref.set("{\"error\":\"" + e.getMessage() + "\"}"); }
                });
                return ref.get();
            });

        s.tool("save_program", "Save the current program")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                p.getDomainFile().save(ghidra.util.task.TaskMonitor.DUMMY);
                return "{\"success\":true,\"program\":\"" + p.getName() + "\"}";
            });

        s.tool("get_current_selection", "Get current selection in Ghidra UI")
            .handler(a -> "{\"has_selection\":false}");

        s.tool("exit_ghidra", "Exit Ghidra")
            .handler(a -> {
                new Thread(() -> { try { Thread.sleep(1000); System.exit(0); } catch (Exception ignored) {} }).start();
                return "{\"success\":true,\"note\":\"Exit requested\"}";
            });
    }
}
