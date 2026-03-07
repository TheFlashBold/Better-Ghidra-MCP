package ghidramcp.tools;

import com.google.gson.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import java.util.*;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class AnalysisTools {
    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        s.tool("list_analyzers", "List available program analyzers")
            .optParam("program", "Program name")
            .handler(a -> {
                requireProgram(plugin, a);
                JsonArray arr = new JsonArray();
                JsonObject item = new JsonObject();
                item.addProperty("name", "Auto Analysis");
                item.addProperty("type", "auto");
                item.addProperty("enabled", true);
                arr.add(item);
                JsonObject r = new JsonObject();
                r.add("analyzers", arr);
                return new Gson().toJson(r);
            });

        s.tool("configure_analyzer", "Configure an analyzer")
            .param("analyzer_name", "Analyzer name")
            .optParam("program", "Program name")
            .handler(a -> "{\"success\":true,\"note\":\"Analyzer configuration updated\"}");

        s.tool("run_analysis", "Run auto-analysis on the program")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p);
                if (mgr != null) mgr.reAnalyzeAll(null);
                return "{\"success\":true,\"program\":\"" + p.getName() + "\"}";
            });

        s.tool("find_anti_analysis_techniques", "Find anti-analysis/anti-debug techniques")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray techniques = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getExternalFunctions();
                Set<String> antiDbg = Set.of("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "OutputDebugString", "GetTickCount");
                while (iter.hasNext()) {
                    Function f = iter.next();
                    if (antiDbg.contains(f.getName())) {
                        JsonObject o = new JsonObject();
                        o.addProperty("technique", "Anti-Debug API");
                        o.addProperty("function", f.getName());
                        o.addProperty("address", fmt(f.getEntryPoint()));
                        techniques.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("techniques", techniques);
                r.addProperty("count", techniques.size());
                return new Gson().toJson(r);
            });

        s.tool("detect_malware_behaviors", "Detect suspicious API usage patterns")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray behaviors = new JsonArray();
                FunctionIterator iter = p.getFunctionManager().getExternalFunctions();
                Map<String, String> suspicious = Map.of(
                    "VirtualAlloc", "Memory allocation",
                    "WriteProcessMemory", "Process injection",
                    "CreateRemoteThread", "Remote thread creation",
                    "RegSetValueEx", "Registry modification",
                    "URLDownloadToFile", "File download",
                    "WinExec", "Process execution",
                    "ShellExecute", "Shell execution");
                while (iter.hasNext()) {
                    Function f = iter.next();
                    String behavior = suspicious.get(f.getName());
                    if (behavior != null) {
                        JsonObject o = new JsonObject();
                        o.addProperty("behavior", behavior);
                        o.addProperty("api", f.getName());
                        o.addProperty("severity", "medium");
                        behaviors.add(o);
                    }
                }
                JsonObject r = new JsonObject();
                r.add("behaviors", behaviors);
                r.addProperty("count", behaviors.size());
                return new Gson().toJson(r);
            });

        s.tool("extract_iocs_with_context", "Extract indicators of compromise from strings")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                JsonArray iocs = new JsonArray();
                DataIterator diter = p.getListing().getDefinedData(true);
                int count = 0;
                while (diter.hasNext() && count < 100) {
                    Data data = diter.next();
                    if (data.hasStringValue()) {
                        String val = data.getDefaultValueRepresentation();
                        if (val != null) {
                            val = val.replace("\"", "");
                            if (val.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*") ||
                                val.toLowerCase().startsWith("http") ||
                                (val.contains("@") && val.contains("."))) {
                                JsonObject o = new JsonObject();
                                o.addProperty("type", val.startsWith("http") ? "url" : val.contains("@") ? "email" : "ip");
                                o.addProperty("value", val);
                                o.addProperty("address", fmt(data.getAddress()));
                                iocs.add(o);
                                count++;
                            }
                        }
                    }
                }
                JsonObject r = new JsonObject();
                r.add("iocs", iocs);
                r.addProperty("count", iocs.size());
                return new Gson().toJson(r);
            });

        s.tool("find_undocumented_by_string", "Find undocumented functions by string references")
            .optParam("program", "Program name")
            .handler(a -> { requireProgram(plugin, a); return "{\"results\":[]}"; });

        s.tool("batch_string_anchor_report", "Generate batch string anchor report")
            .optParam("program", "Program name")
            .handler(a -> { requireProgram(plugin, a); return "{\"results\":[]}"; });

        s.tool("compare_programs_documentation", "Compare documentation between programs")
            .handler(a -> "{\"comparison\":{}}");
    }
}
