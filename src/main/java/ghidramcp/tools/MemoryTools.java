package ghidramcp.tools;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidramcp.GhidraMCPPlugin;
import ghidramcp.mcp.McpServer;

import static ghidramcp.mcp.McpServer.*;
import static ghidramcp.tools.ToolHelper.*;

public class MemoryTools {
    public static void register(McpServer s, GhidraMCPPlugin plugin) {

        s.tool("read_memory", "Read memory bytes at an address as hex dump")
            .param("address", "Memory address (hex)")
            .intParam("length", "Number of bytes to read (default 256)")
            .optParam("program", "Program name")
            .handler(a -> {
                Program p = requireProgram(plugin, a);
                var address = addr(p, str(a, "address"));
                if (address == null) throw new Exception("Invalid address");
                int length = num(a, "length", 256);
                byte[] data = new byte[length];
                int read = p.getMemory().getBytes(address, data);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < read; i++) {
                    if (i > 0 && i % 16 == 0) sb.append("\n");
                    else if (i > 0) sb.append(" ");
                    sb.append(String.format("%02x", data[i] & 0xff));
                }
                return sb.toString();
            });
    }
}
