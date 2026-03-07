package ghidramcp.tools;

import com.google.gson.*;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class ScriptTools {
    private static Path scriptDir() { return Paths.get(System.getProperty("user.home"), "ghidra_scripts"); }

    private static GhidraState makeState(GhidraMCPPlugin plugin, Program p) {
        return new GhidraState(plugin.getPluginTool(), plugin.getPluginTool().getProject(), p, null, null, null);
    }

    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        s.tool("list_scripts", "List available Ghidra scripts")
            .optParam("filter", "Filter by name substring")
            .handler(a -> {
                String filter = str(a, "filter", "");
                Path dir = scriptDir();
                JsonArray scripts = new JsonArray();
                if (Files.exists(dir)) {
                    try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                        for (Path p : stream) {
                            String name = p.getFileName().toString();
                            if ((name.endsWith(".java") || name.endsWith(".py")) &&
                                (filter.isEmpty() || name.toLowerCase().contains(filter.toLowerCase()))) {
                                JsonObject o = new JsonObject();
                                o.addProperty("name", name);
                                o.addProperty("path", p.toString());
                                o.addProperty("size", Files.size(p));
                                scripts.add(o);
                            }
                        }
                    }
                }
                JsonObject r = new JsonObject();
                r.add("scripts", scripts);
                r.addProperty("count", scripts.size());
                return new Gson().toJson(r);
            });

        s.tool("list_ghidra_scripts", "List available Ghidra scripts (alias)")
            .optParam("filter", "Filter by name substring")
            .handler(a -> {
                // delegate to list_scripts
                String filter = str(a, "filter", "");
                Path dir = scriptDir();
                JsonArray scripts = new JsonArray();
                if (Files.exists(dir)) {
                    try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                        for (Path p : stream) {
                            String name = p.getFileName().toString();
                            if ((name.endsWith(".java") || name.endsWith(".py")) &&
                                (filter.isEmpty() || name.toLowerCase().contains(filter.toLowerCase()))) {
                                JsonObject o = new JsonObject();
                                o.addProperty("name", name);
                                o.addProperty("path", p.toString());
                                scripts.add(o);
                            }
                        }
                    }
                }
                JsonObject r = new JsonObject();
                r.add("scripts", scripts);
                r.addProperty("count", scripts.size());
                return new Gson().toJson(r);
            });

        s.tool("run_script", "Run a Ghidra script by path")
            .param("script_path", "Path to the script file")
            .optParam("args", "Script arguments (space-separated)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                File scriptFile = new File(str(a, "script_path"));
                if (!scriptFile.exists()) scriptFile = scriptDir().resolve(str(a, "script_path")).toFile();
                if (!scriptFile.exists()) throw new Exception("Script not found: " + str(a, "script_path"));
                JavaScriptProvider provider = new JavaScriptProvider();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintWriter pw = new PrintWriter(baos);
                GhidraScript script = provider.getScriptInstance(new ResourceFile(scriptFile), pw);
                String args = str(a, "args", "");
                if (!args.isEmpty()) script.setScriptArgs(args.split("\\s+"));
                script.execute(makeState(plugin, p), TaskMonitor.DUMMY, pw);
                pw.flush();
                return "Script output:\n" + baos.toString();
            });

        s.tool("run_ghidra_script", "Run a Ghidra script by name from ~/ghidra_scripts")
            .param("script_name", "Script filename")
            .optParam("args", "Script arguments (space-separated)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String scriptName = str(a, "script_name");
                Path scriptPath = scriptDir().resolve(scriptName);
                if (!Files.exists(scriptPath)) scriptPath = scriptDir().resolve(scriptName + ".java");
                if (!Files.exists(scriptPath)) throw new Exception("Script not found: " + scriptName);
                JavaScriptProvider provider = new JavaScriptProvider();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintWriter pw = new PrintWriter(baos);
                GhidraScript script = provider.getScriptInstance(new ResourceFile(scriptPath.toFile()), pw);
                String args = str(a, "args", "");
                if (!args.isEmpty()) script.setScriptArgs(args.split("\\s+"));
                script.execute(makeState(plugin, p), TaskMonitor.DUMMY, pw);
                pw.flush();
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("script", scriptName);
                r.addProperty("output", baos.toString());
                return new Gson().toJson(r);
            });

        s.tool("run_script_inline", "Run inline Java code as a GhidraScript")
            .param("code", "Java code to execute")
            .optParam("args", "Script arguments")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                String code = str(a, "code");
                Path tempScript = Files.createTempFile("mcp_inline_", ".java");
                try {
                    if (!code.contains("extends GhidraScript")) {
                        String className = tempScript.getFileName().toString().replace(".java", "").replaceAll("[^a-zA-Z0-9_]", "_");
                        code = "import ghidra.app.script.GhidraScript;\n" +
                               "import ghidra.program.model.listing.*;\n" +
                               "import ghidra.program.model.symbol.*;\n" +
                               "import ghidra.program.model.address.*;\n" +
                               "public class " + className + " extends GhidraScript {\n" +
                               "    public void run() throws Exception {\n" + code + "\n    }\n}\n";
                    }
                    Files.writeString(tempScript, code);
                    JavaScriptProvider provider = new JavaScriptProvider();
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    PrintWriter pw = new PrintWriter(baos);
                    GhidraScript script = provider.getScriptInstance(new ResourceFile(tempScript.toFile()), pw);
                    String args = str(a, "args", "");
                    if (!args.isEmpty()) script.setScriptArgs(args.split("\\s+"));
                    script.execute(makeState(plugin, p), TaskMonitor.DUMMY, pw);
                    pw.flush();
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("output", baos.toString());
                    return new Gson().toJson(r);
                } finally { Files.deleteIfExists(tempScript); }
            });

        s.tool("save_ghidra_script", "Save a script to ~/ghidra_scripts")
            .param("name", "Script filename")
            .param("content", "Script source code")
            .boolParam("overwrite", "Overwrite existing (default false)")
            .handler(a -> {
                Path dir = scriptDir();
                Files.createDirectories(dir);
                Path path = dir.resolve(str(a, "name"));
                if (Files.exists(path) && !bool(a, "overwrite", false))
                    throw new Exception("Script already exists. Set overwrite=true to replace.");
                Files.writeString(path, str(a, "content"));
                JsonObject r = new JsonObject();
                r.addProperty("success", true);
                r.addProperty("name", str(a, "name"));
                r.addProperty("path", path.toString());
                return new Gson().toJson(r);
            });

        s.tool("get_ghidra_script", "Get the content of a script")
            .param("name", "Script filename")
            .handler(a -> {
                Path path = scriptDir().resolve(str(a, "name"));
                if (!Files.exists(path)) throw new Exception("Script not found: " + str(a, "name"));
                return Files.readString(path);
            });

        s.tool("update_ghidra_script", "Update an existing script")
            .param("name", "Script filename")
            .param("content", "New script content")
            .handler(a -> {
                Path path = scriptDir().resolve(str(a, "name"));
                if (!Files.exists(path)) throw new Exception("Script not found");
                Files.writeString(path, str(a, "content"));
                return "{\"success\":true,\"name\":\"" + str(a, "name") + "\"}";
            });

        s.tool("delete_ghidra_script", "Delete a script")
            .param("name", "Script filename")
            .handler(a -> {
                Path path = scriptDir().resolve(str(a, "name"));
                if (!Files.exists(path)) throw new Exception("Script not found");
                Files.delete(path);
                return "{\"success\":true,\"deleted\":\"" + str(a, "name") + "\"}";
            });
    }
}
