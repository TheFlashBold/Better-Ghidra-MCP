package ghidramcp.tools;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidramcp.GhidraMCPPlugin;

import static ghidramcp.mcp.McpServer.str;

public class ToolHelper {

    public static Program program(GhidraMCPPlugin plugin, JsonObject a) {
        return plugin.getProgram(str(a, "program"));
    }

    public static Program requireProgram(GhidraMCPPlugin plugin, JsonObject a) throws Exception {
        Program p = program(plugin, a);
        if (p == null) throw new Exception("No program open");
        return p;
    }

    public static Address addr(Program p, String s) {
        if (s == null || s.isEmpty()) return null;
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        try { return p.getAddressFactory().getDefaultAddressSpace().getAddress(s); }
        catch (Exception e) { return null; }
    }

    public static String fmt(Address a) {
        return "0x" + a.toString();
    }

    public static Function findFunction(Program p, JsonObject a) {
        String name = str(a, "name");
        String address = str(a, "address");
        if (address != null) {
            Address ad = addr(p, address);
            if (ad != null) {
                Function f = p.getFunctionManager().getFunctionAt(ad);
                if (f == null) f = p.getFunctionManager().getFunctionContaining(ad);
                return f;
            }
        }
        if (name != null) {
            FunctionIterator iter = p.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getName().equals(name)) return f;
            }
        }
        return null;
    }

    public static Function requireFunction(Program p, JsonObject a) throws Exception {
        Function f = findFunction(p, a);
        if (f == null) throw new Exception("Function not found");
        return f;
    }
}
