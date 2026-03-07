package ghidramcp.mcp;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class McpServer {

    @FunctionalInterface
    public interface Handler {
        String call(JsonObject args) throws Exception;
    }

    static final class Tool {
        final String name, description;
        final JsonObject inputSchema;
        final Handler handler;
        Tool(String n, String d, JsonObject s, Handler h) { name=n; description=d; inputSchema=s; handler=h; }
    }

    private final Map<String, Tool> tools = new LinkedHashMap<>();
    private String sessionId;
    private static final Gson GSON = new Gson();

    // --- Arg helpers ---

    public static String str(JsonObject a, String k) {
        if (a == null || !a.has(k) || a.get(k).isJsonNull()) return null;
        try { return a.get(k).getAsString(); } catch (Exception e) { return a.get(k).toString(); }
    }

    public static String str(JsonObject a, String k, String d) {
        String v = str(a, k); return v != null && !v.isEmpty() ? v : d;
    }

    public static int num(JsonObject a, String k, int d) {
        if (a == null || !a.has(k) || a.get(k).isJsonNull()) return d;
        try { return a.get(k).getAsInt(); } catch (Exception e) { return d; }
    }

    public static boolean bool(JsonObject a, String k, boolean d) {
        if (a == null || !a.has(k) || a.get(k).isJsonNull()) return d;
        try { return a.get(k).getAsBoolean(); } catch (Exception e) { return d; }
    }

    // --- Tool builder ---

    public ToolBuilder tool(String name, String description) {
        return new ToolBuilder(name, description);
    }

    public class ToolBuilder {
        private final String name, description;
        private final JsonObject properties = new JsonObject();
        private final JsonArray required = new JsonArray();

        ToolBuilder(String name, String description) {
            this.name = name; this.description = description;
        }

        public ToolBuilder param(String name, String desc) {
            addProp(name, "string", desc); required.add(name); return this;
        }

        public ToolBuilder optParam(String name, String desc) {
            addProp(name, "string", desc); return this;
        }

        public ToolBuilder intParam(String name, String desc) {
            addProp(name, "integer", desc); return this;
        }

        public ToolBuilder boolParam(String name, String desc) {
            addProp(name, "boolean", desc); return this;
        }

        private void addProp(String name, String type, String desc) {
            JsonObject p = new JsonObject();
            p.addProperty("type", type);
            p.addProperty("description", desc);
            properties.add(name, p);
        }

        public void handler(Handler h) {
            JsonObject schema = new JsonObject();
            schema.addProperty("type", "object");
            schema.add("properties", properties);
            if (required.size() > 0) schema.add("required", required);
            tools.put(name, new Tool(name, description, schema, h));
        }
    }

    // --- HTTP handler ---

    public void handle(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id");

        switch (ex.getRequestMethod()) {
            case "OPTIONS": ex.sendResponseHeaders(204, -1); ex.close(); return;
            case "DELETE":  ex.sendResponseHeaders(200, -1); ex.close(); return;
            case "GET":     handleGet(ex); return;
            case "POST":    break;
            default:        sendPlain(ex, 405, "Method not allowed"); return;
        }

        String body;
        try (InputStream is = ex.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        try {
            JsonElement parsed = JsonParser.parseString(body);
            if (parsed.isJsonArray()) {
                JsonArray responses = new JsonArray();
                for (JsonElement elem : parsed.getAsJsonArray()) {
                    JsonObject r = processRequest(elem.getAsJsonObject());
                    if (r != null) responses.add(r);
                }
                sendJson(ex, GSON.toJson(responses));
            } else {
                JsonObject resp = processRequest(parsed.getAsJsonObject());
                if (resp == null) { ex.sendResponseHeaders(202, -1); ex.close(); }
                else {
                    if (sessionId != null) ex.getResponseHeaders().set("Mcp-Session-Id", sessionId);
                    sendJson(ex, GSON.toJson(resp));
                }
            }
        } catch (Exception e) {
            sendJsonRpcError(ex, null, -32700, "Parse error: " + e.getMessage());
        }
    }

    private JsonObject processRequest(JsonObject req) {
        JsonElement id = req.get("id");
        String method = req.has("method") ? req.get("method").getAsString() : null;
        JsonObject params = req.has("params") && req.get("params").isJsonObject()
            ? req.getAsJsonObject("params") : new JsonObject();

        if (id == null) return null; // notification

        JsonObject result;
        try {
            switch (method != null ? method : "") {
                case "initialize":  result = doInitialize(params); break;
                case "ping":        result = new JsonObject(); break;
                case "tools/list":  result = doToolsList(); break;
                case "tools/call":  result = doToolsCall(params); break;
                default:            return rpcError(id, -32601, "Unknown method: " + method);
            }
        } catch (Exception e) {
            return rpcError(id, -32603, e.getMessage());
        }

        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", "2.0");
        resp.add("id", id);
        resp.add("result", result);
        return resp;
    }

    // --- MCP methods ---

    private JsonObject doInitialize(JsonObject params) {
        sessionId = UUID.randomUUID().toString();
        JsonObject r = new JsonObject();
        r.addProperty("protocolVersion", "2024-11-05");
        JsonObject caps = new JsonObject();
        caps.add("tools", new JsonObject());
        r.add("capabilities", caps);
        JsonObject info = new JsonObject();
        info.addProperty("name", "ghidra-mcp");
        info.addProperty("version", "1.0.0");
        r.add("serverInfo", info);
        return r;
    }

    private JsonObject doToolsList() {
        JsonArray arr = new JsonArray();
        for (Tool t : tools.values()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", t.name);
            o.addProperty("description", t.description);
            o.add("inputSchema", t.inputSchema);
            arr.add(o);
        }
        JsonObject r = new JsonObject();
        r.add("tools", arr);
        return r;
    }

    private JsonObject doToolsCall(JsonObject params) {
        String name = str(params, "name");
        JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
            ? params.getAsJsonObject("arguments") : new JsonObject();
        Tool tool = name != null ? tools.get(name) : null;
        if (tool == null) return errorContent("Tool not found: " + name);
        try {
            String text = tool.handler.call(args);
            return textContent(text);
        } catch (Exception e) {
            return errorContent(e.getMessage());
        }
    }

    // --- Response helpers ---

    private JsonObject textContent(String text) {
        JsonObject r = new JsonObject();
        JsonArray c = new JsonArray();
        JsonObject item = new JsonObject();
        item.addProperty("type", "text");
        item.addProperty("text", text != null ? text : "");
        c.add(item);
        r.add("content", c);
        return r;
    }

    private JsonObject errorContent(String msg) {
        JsonObject r = textContent(msg);
        r.addProperty("isError", true);
        return r;
    }

    private JsonObject rpcError(JsonElement id, int code, String msg) {
        JsonObject r = new JsonObject();
        r.addProperty("jsonrpc", "2.0");
        r.add("id", id);
        JsonObject e = new JsonObject();
        e.addProperty("code", code);
        e.addProperty("message", msg);
        r.add("error", e);
        return r;
    }

    private void handleGet(HttpExchange ex) throws IOException {
        JsonObject info = new JsonObject();
        info.addProperty("name", "ghidra-mcp");
        info.addProperty("version", "1.0.0");
        info.addProperty("transport", "streamable-http");
        info.addProperty("tools", tools.size());
        sendJson(ex, GSON.toJson(info));
    }

    private void sendJson(HttpExchange ex, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(200, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private void sendJsonRpcError(HttpExchange ex, JsonElement id, int code, String msg) throws IOException {
        sendJson(ex, GSON.toJson(rpcError(id, code, msg)));
    }

    private void sendPlain(HttpExchange ex, int code, String msg) throws IOException {
        byte[] b = msg.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
