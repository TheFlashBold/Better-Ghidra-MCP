package ghidramcp.tools;

import com.google.gson.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.io.File;
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

        s.tool("import_binary", "Import a binary file from disk into the project and open it (like File > Import File). " +
                "Use open_program for files already in the project.")
            .param("file_path", "Absolute path to the binary on disk")
            .optParam("folder", "Project folder to import into (default /, created if missing)")
            .optParam("name", "Program name in the project (default: file name)")
            .boolParam("auto_analyze", "Run auto-analysis after import (default true). Without it Ghidra will not prompt to analyze later; use run_analysis")
            .boolParam("open", "Open the program in the CodeBrowser and make it current (default true)")
            .boolParam("raw_binary", "Import as raw binary image instead of format detection (default false, requires language_id)")
            .optParam("language_id", "Language override, e.g. x86:LE:32:default or ARM:LE:32:v7")
            .optParam("compiler_spec_id", "Compiler spec, e.g. windows or gcc (only with language_id)")
            .handler(a -> {
                String path = str(a, "file_path");
                if (path == null || path.isBlank()) throw new Exception("file_path is required");
                File file = new File(path.trim());
                if (!file.isFile()) throw new Exception("File not found: " + file.getAbsolutePath());

                Project project = plugin.getPluginTool().getProject();
                if (project == null) throw new Exception("No project open");
                ProjectData pd = project.getProjectData();

                String folder = str(a, "folder", "/").trim().replace('\\', '/');
                if (!folder.startsWith("/")) folder = "/" + folder;
                while (folder.length() > 1 && folder.endsWith("/")) folder = folder.substring(0, folder.length() - 1);
                String name = str(a, "name", file.getName()).trim();
                String target = (folder.equals("/") ? "" : folder) + "/" + name;
                if (pd.getFile(target) != null)
                    throw new Exception("Project already contains " + target + " - use open_program or pass a different name");

                boolean analyze = bool(a, "auto_analyze", true);
                boolean open = bool(a, "open", true);
                boolean raw = bool(a, "raw_binary", false);

                Language lang = null;
                CompilerSpec cspec = null;
                String langId = str(a, "language_id");
                if (langId != null && !langId.isBlank()) {
                    lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(langId.trim()));
                    String cs = str(a, "compiler_spec_id");
                    cspec = cs != null && !cs.isBlank()
                        ? lang.getCompilerSpecByID(new CompilerSpecID(cs.trim()))
                        : lang.getDefaultCompilerSpec();
                } else if (raw) {
                    throw new Exception("raw_binary requires language_id (e.g. x86:LE:32:default)");
                }

                DomainFolder dest = pd.getRootFolder();
                for (String part : folder.split("/")) {
                    if (part.isEmpty()) continue;
                    DomainFolder next = dest.getFolder(part);
                    dest = next != null ? next : dest.createFolder(part);
                }

                // Import runs on the HTTP worker thread -- never on Swing, it can take a while
                TaskMonitor monitor = TaskMonitor.DUMMY;
                MessageLog log = new MessageLog();
                long start = System.currentTimeMillis();
                LoadResults<Program> results;
                try {
                    if (raw) {
                        results = new LoadResults<>(AutoImporter.importAsBinary(file, project, folder, lang, cspec, plugin, log, monitor));
                    } else if (lang != null) {
                        results = AutoImporter.importByLookingForLcs(file, project, folder, lang, cspec, plugin, log, monitor);
                    } else {
                        results = AutoImporter.importByUsingBestGuess(file, project, folder, plugin, log, monitor);
                    }
                } catch (LoadException e) {
                    throw new Exception("No loader could handle " + file.getName() +
                        " - pass language_id with raw_binary=true to import it as a raw image. " + log);
                }

                DomainFile imported;
                try (results) {
                    results.save(monitor);
                    imported = results.getPrimary().getSavedDomainFile();
                    if (!imported.getName().equals(name)) imported = imported.setName(name);
                }
                long importMs = System.currentTimeMillis() - start;

                // Analyze (or suppress the analysis prompt) before the CodeBrowser sees the program,
                // otherwise Ghidra shows a modal "Analyze now?" dialog and this call blocks on it
                Program p = (Program) imported.getDomainObject(plugin, false, false, monitor);
                try {
                    JsonObject r = new JsonObject();
                    int before = p.getFunctionManager().getFunctionCount();
                    long analysisStart = System.currentTimeMillis();
                    int tx = p.startTransaction(analyze ? "Auto Analysis (import)" : "Import");
                    boolean ok = false;
                    try {
                        if (analyze) {
                            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
                            mgr.initializeOptions();
                            mgr.reAnalyzeAll(p.getMemory().getLoadedAndInitializedAddressSet());
                            mgr.startAnalysis(monitor);
                            GhidraProgramUtilities.markProgramAnalyzed(p);
                        } else {
                            GhidraProgramUtilities.markProgramNotToAskToAnalyze(p);
                        }
                        ok = true;
                    } finally {
                        p.endTransaction(tx, ok);
                    }
                    imported.save(monitor);

                    if (open) {
                        Swing.runNow(() -> {
                            ProgramManager pm = plugin.getProgramManager();
                            if (pm != null) { pm.openProgram(p); pm.setCurrentProgram(p); }
                        });
                        plugin.setDefaultProgram(p.getName());
                    }

                    r.addProperty("success", true);
                    r.addProperty("name", p.getName());
                    r.addProperty("path", imported.getPathname());
                    r.addProperty("source_file", file.getAbsolutePath());
                    r.addProperty("language", p.getLanguageID().toString());
                    r.addProperty("compiler", p.getCompilerSpec().getCompilerSpecID().toString());
                    r.addProperty("image_base", fmt(p.getImageBase()));
                    r.addProperty("function_count", p.getFunctionManager().getFunctionCount());
                    r.addProperty("auto_analyzed", analyze);
                    if (analyze) {
                        r.addProperty("new_functions", p.getFunctionManager().getFunctionCount() - before);
                        r.addProperty("analysis_ms", System.currentTimeMillis() - analysisStart);
                    }
                    r.addProperty("import_ms", importMs);
                    r.addProperty("opened", open);
                    if (log.hasMessages()) r.addProperty("importer_log", log.toString());
                    return new Gson().toJson(r);
                } finally {
                    // The ProgramManager holds its own reference once opened
                    p.release(plugin);
                }
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
