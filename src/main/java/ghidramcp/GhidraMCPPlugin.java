package ghidramcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.MiscellaneousPluginPackage;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;

import ghidramcp.mcp.McpServer;
import ghidramcp.tools.*;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "MCP Server for Ghidra",
    description = "Native MCP server exposing Ghidra functionality via JSON-RPC over HTTP"
)
public class GhidraMCPPlugin extends Plugin {
    private HttpServer server;
    private static final int PORT = 8089;
    private String defaultProgramName = null;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        try { startServer(); }
        catch (IOException e) { Msg.error(this, "Failed to start MCP server on port " + PORT, e); }
    }

    private void startServer() throws IOException {
        McpServer mcp = new McpServer();

        FunctionTools.register(mcp, this);
        DataTypeTools.register(mcp, this);
        SymbolTools.register(mcp, this);
        MemoryTools.register(mcp, this);
        ProgramTools.register(mcp, this);
        AnalysisTools.register(mcp, this);
        ScriptTools.register(mcp, this);

        server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/mcp", mcp::handle);
        server.start();
        Msg.info(this, "GhidraMCP server started on port " + PORT + " (MCP streamable HTTP)");
    }

    public Program getCurrentProgram() {
        AtomicReference<Program> ref = new AtomicReference<>();
        Swing.runNow(() -> {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) { ref.set(null); return; }
            if (defaultProgramName != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p.getName().equals(defaultProgramName) || p.getName().contains(defaultProgramName)) {
                        ref.set(p); return;
                    }
                }
            }
            ref.set(pm.getCurrentProgram());
        });
        return ref.get();
    }

    public Program getProgram(String name) {
        if (name == null || name.isEmpty()) return getCurrentProgram();
        AtomicReference<Program> ref = new AtomicReference<>();
        Swing.runNow(() -> {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) { ref.set(null); return; }
            for (Program p : pm.getAllOpenPrograms()) {
                if (p.getName().equals(name)) { ref.set(p); return; }
            }
            for (Program p : pm.getAllOpenPrograms()) {
                if (p.getName().contains(name)) { ref.set(p); return; }
            }
        });
        return ref.get();
    }

    public ProgramManager getProgramManager() { return tool.getService(ProgramManager.class); }
    public PluginTool getPluginTool() { return tool; }
    public void setDefaultProgram(String name) { this.defaultProgramName = name; }
    public String getDefaultProgramName() { return defaultProgramName; }

    @Override
    protected void dispose() {
        if (server != null) { server.stop(0); Msg.info(this, "GhidraMCP server stopped"); }
        super.dispose();
    }
}
