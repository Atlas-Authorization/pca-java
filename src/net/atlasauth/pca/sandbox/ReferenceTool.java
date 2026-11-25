package net.atlasauth.pca.sandbox;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Hand-assembled core-WebAssembly modules for tests, demos and guides: no toolchain needed to see the sandbox work. Byte-identical to
 * the reference's builders (including its habit of writing a name's UTF-16 length as the length prefix).
 */
public final class ReferenceTool {
    private ReferenceTool() {}

    private static void u(ByteArrayOutputStream o, double n) {
        do {
            int b = (int) (long) n & 0x7f;
            n = Math.floor(n / 128);
            if (n > 0) b |= 0x80;
            o.write(b);
        } while (n > 0);
    }

    private static byte[] u(double n) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u(o, n);
        return o.toByteArray();
    }

    private static void sleb(ByteArrayOutputStream o, double d) {
        int n = (int) (long) d;
        for (;;) {
            int b = n & 0x7f;
            n >>= 7;
            if ((n == 0 && (b & 0x40) == 0) || (n == -1 && (b & 0x40) != 0)) { o.write(b); return; }
            o.write(b | 0x80);
        }
    }

    private static void i32c(ByteArrayOutputStream o, double n) {
        o.write(0x41);
        sleb(o, n);
    }

    private static void str(ByteArrayOutputStream o, String x) {
        u(o, x.length());
        byte[] b = Json.utf8(x);
        o.write(b, 0, b.length);
    }

    private static void bytes(ByteArrayOutputStream o, byte[] b) { o.write(b, 0, b.length); }

    private static byte[] vec(List<byte[]> items) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u(o, items.size());
        for (byte[] i : items) bytes(o, i);
        return o.toByteArray();
    }

    private static byte[] section(int id, byte[] body) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(id);
        u(o, body.length);
        bytes(o, body);
        return o.toByteArray();
    }

    private static byte[] b(int... xs) {
        byte[] r = new byte[xs.length];
        for (int i = 0; i < xs.length; i++) r[i] = (byte) xs[i];
        return r;
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) bytes(o, p);
        return o.toByteArray();
    }

    private static byte[] name(String x) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        str(o, x);
        return o.toByteArray();
    }

    private static double numOf(Object o) {
        Double d = JsVal.num(o);
        if (d == null) throw new JsVal.TypeError("not a number");
        return d;
    }

    private static final byte[] HEADER = b(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0);

    /**
     * A module that calls {@code pca:act.invoke(handle, ptr, cap)} for each call of {@code spec.calls} and returns either the last
     * call's return code or the first byte of linear memory. {@code spec}: calls [{handle, ptr, cap}], returns ("last" | "byte0"),
     * extraImports [{module, name}], memory {min, max (null: none declared)}, spin.
     */
    @SuppressWarnings("unchecked")
    public static byte[] buildTool(Map<String, Object> spec) {
        List<Object> extra = spec.get("extraImports") == null ? List.of() : (List<Object>) spec.get("extraImports");
        List<Object> calls = (List<Object>) spec.get("calls");
        byte[] types = vec(List.of(b(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), b(0x60, 0, 1, 0x7f), b(0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f)));
        List<byte[]> imp = new java.util.ArrayList<>();
        imp.add(cat(name("pca:act"), name("invoke"), b(0, 0)));
        for (Object e : extra) {
            Map<String, Object> m = (Map<String, Object>) e;
            imp.add(cat(name(JsVal.str(m.get("module"))), name(JsVal.str(m.get("name"))), b(0, 2)));
        }
        Object memV = spec.get("memory");
        double min = 1, max = 1;
        boolean noMax = false;
        if (memV instanceof Map) {
            Map<String, Object> mm = (Map<String, Object>) memV;
            min = numOf(mm.get("min"));
            if (mm.get("max") == null) noMax = true;
            else max = numOf(mm.get("max"));
        }
        byte[] memItem = noMax ? cat(b(0), u(min)) : cat(b(1), u(min), u(max));
        byte[] memory = vec(List.of(memItem));
        int runIndex = 1 + extra.size();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0);
        boolean last = !"byte0".equals(spec.get("returns")); // `returns ?? 'last'` is 'last' for anything but byte0 in the supported shapes
        for (int i = 0; i < calls.size(); i++) {
            Map<String, Object> c = (Map<String, Object>) calls.get(i);
            i32c(body, numOf(c.get("handle")));
            i32c(body, numOf(c.get("ptr")));
            i32c(body, numOf(c.get("cap")));
            body.write(0x10);
            body.write(0);
            if (!(i == calls.size() - 1 && last)) body.write(0x1a);
        }
        if (JsVal.truthy(spec.get("spin"))) bytes(body, b(0x03, 0x40, 0x0c, 0x00, 0x0b));
        if ("byte0".equals(spec.get("returns"))) {
            i32c(body, 0);
            bytes(body, b(0x2d, 0, 0));
        }
        if (calls.isEmpty()) i32c(body, 0);
        body.write(0x0b);
        byte[] bodyB = body.toByteArray();
        byte[] code = vec(List.of(cat(u(bodyB.length), bodyB)));
        byte[] exports = vec(List.of(cat(name("memory"), b(2, 0)), cat(name("run"), b(0), u(runIndex))));
        return cat(HEADER, section(1, types), section(2, vec(imp)), section(3, vec(List.of(b(1)))), section(5, memory), section(7, exports), section(10, code));
    }

    /** A tool that asks the table what it holds: returns {@code handle_count() * 256 + first byte of handle 1's verb} (the verb window is {@code cap} bytes). */
    public static byte[] buildProbeTool(Object capArg) {
        double cap = capArg == null ? 64 : numOf(capArg);
        byte[] types = vec(List.of(b(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), b(0x60, 0, 1, 0x7f)));
        byte[] imports = vec(List.of(
            cat(name("pca:act"), name("invoke"), b(0, 0)),
            cat(name("pca:act"), name("handle_count"), b(0, 1)),
            cat(name("pca:act"), name("handle_verb"), b(0, 0))));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0);
        i32c(body, 1);
        i32c(body, 0);
        i32c(body, cap);
        bytes(body, b(0x10, 2, 0x1a, 0x10, 1));
        i32c(body, 256);
        body.write(0x6c);
        i32c(body, 0);
        bytes(body, b(0x2d, 0, 0, 0x6a, 0x0b));
        byte[] bodyB = body.toByteArray();
        byte[] code = vec(List.of(cat(u(bodyB.length), bodyB)));
        byte[] exports = vec(List.of(cat(name("memory"), b(2, 0)), cat(name("run"), b(0, 3))));
        return cat(HEADER, section(1, types), section(2, imports), section(3, vec(List.of(b(1)))), section(5, vec(List.of(b(1, 1, 1)))), section(7, exports), section(10, code));
    }
}
