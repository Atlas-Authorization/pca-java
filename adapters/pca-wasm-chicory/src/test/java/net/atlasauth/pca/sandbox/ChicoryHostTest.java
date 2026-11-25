package net.atlasauth.pca.sandbox;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;
import org.junit.jupiter.api.Test;

/** The Chicory core host: handle use, fuel, wall-clock, memory cap, import allow-list, egress through the policy. */
class ChicoryHostTest {
    private static Authorize.AuthorizeResult allow(String verb, String resource, Map<String, Object> params) {
        var op = new Authorize.AuthorizedOperation(verb, resource, Pca.hashCanonical(params), "op");
        return new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<String, String>(), new ArrayList<String>(), null, op, null, null, new ArrayList<String>());
    }

    private static void mint(Handles.HandleTable t, String verb, String resource) {
        Map<String, Object> params = new LinkedHashMap<>();
        t.mint(allow(verb, resource, params), new Authorize.Operation(verb, resource, params), new Handles.MintOptions());
    }

    /** handles: 1 fs.read, 2 net.ok (admitted), 3 net.evil (no admission). */
    private static Handles.HandleTable table() {
        Egress.EgressPolicy policy = new Egress.EgressPolicy(null);
        Map<String, Object> params = new LinkedHashMap<>();
        Map<String, Object> tmpl = new LinkedHashMap<>(Map.of("method", "GET", "scheme", "https", "host", "api.example.com", "path", "/v1"));
        policy.admit(allow("net.ok", "api.example.com", params), new Authorize.Operation("net.ok", "api.example.com", params), op -> tmpl, null, null);
        Map<String, Handles.Executor> ex = new LinkedHashMap<>();
        ex.put("fs.read", (v, r, p) -> new byte[] {7, 8, 9});
        ex.put("net.ok", (v, r, p) -> fetch(policy, "https://api.example.com/v1"));
        ex.put("net.evil", (v, r, p) -> fetch(policy, "https://evil.example/x"));
        var t = new Handles.HandleTable("wasi_no_ambient", new Receipts.ReceiptLog(), ex, null);
        mint(t, "fs.read", "/x");
        mint(t, "net.ok", "api.example.com");
        mint(t, "net.evil", "evil.example");
        return t;
    }

    private static byte[] fetch(Egress.EgressPolicy policy, String url) {
        if (!Boolean.TRUE.equals(policy.claim("GET", url, null).get("allow"))) throw new IllegalStateException("egress denied");
        return new byte[] {1};
    }

    private static Map<String, Object> call(int h, int ptr, int cap) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("handle", h);
        c.put("ptr", ptr);
        c.put("cap", cap);
        return c;
    }

    private static byte[] tool(Object... kv) {
        Map<String, Object> spec = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) spec.put((String) kv[i], kv[i + 1]);
        return ReferenceTool.buildTool(spec);
    }

    private static ChicoryHost.Options opts() { return new ChicoryHost.Options(10_000_000L); }

    @Test void handleResultLandsInMemory() {
        var t = table();
        var r = ChicoryHost.run(t, tool("calls", List.of(call(1, 0, 16)), "returns", "byte0"), "run", opts());
        assertTrue(r.ok, r.toString());
        assertEquals(7, r.value);
    }

    @Test void infiniteLoopHitsFuel() {
        var r = ChicoryHost.run(table(), tool("calls", List.of(), "spin", true), "run", new ChicoryHost.Options(10_000));
        assertEquals("fuel_exhausted", r.reason);
    }

    @Test void infiniteLoopHitsWallClock() {
        var o = new ChicoryHost.Options(Long.MAX_VALUE / 2);
        o.timeoutMs = 300;
        assertEquals("timeout", ChicoryHost.run(table(), tool("calls", List.of(), "spin", true), "run", o).reason);
    }

    @Test void fuelIsRequired() {
        assertEquals("bad_fuel", ChicoryHost.run(table(), tool("calls", List.of()), "run", new ChicoryHost.Options(0)).reason);
    }

    @Test void memoryOverCapOrUndeclaredIsRefused() {
        for (Map<String, Object> m : List.of(mem(1, 257), mem(1, null), mem(257, 257))) {
            assertEquals("memory_limits", ChicoryHost.run(table(), tool("calls", List.of(), "memory", m), "run", opts()).reason);
        }
        var o = opts();
        o.maxMemoryPages = 2;
        assertEquals("memory_limits", ChicoryHost.run(table(), tool("calls", List.of(), "memory", mem(1, 4)), "run", o).reason);
        assertTrue(ChicoryHost.run(table(), tool("calls", List.of(), "memory", mem(1, 4)), "run", opts()).ok);
    }

    private static Map<String, Object> mem(Integer min, Integer max) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("min", min);
        m.put("max", max);
        return m;
    }

    @Test void forbiddenImportsAreRefused() {
        for (String[] e : new String[][] {{"wasi_snapshot_preview1", "fd_write"}, {"env", "x"}, {"pca:act", "other"}}) {
            Map<String, Object> imp = new LinkedHashMap<>(Map.of("module", e[0], "name", e[1]));
            var r = ChicoryHost.run(table(), tool("calls", List.of(), "extraImports", List.of(imp)), "run", opts());
            assertEquals("ambient_import:" + e[0] + "." + e[1], r.reason);
        }
    }

    @Test void malformedSizeAndEntry() {
        assertEquals("module_size", ChicoryHost.run(table(), new byte[0], "run", opts()).reason);
        assertEquals("malformed_module", ChicoryHost.run(table(), new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}, "run", opts()).reason);
        assertEquals("no_entry", ChicoryHost.run(table(), tool("calls", List.of()), "nope", opts()).reason);
    }

    @Test void badOutputWindowSpendsNoUse() {
        var t = table();
        assertEquals(-4, ChicoryHost.run(t, tool("calls", List.of(call(1, 70000, 16))), "run", opts()).value);
        assertEquals(3, ChicoryHost.run(t, tool("calls", List.of(call(1, 0, 16))), "run", opts()).value);
    }

    @Test void egressInsidePolicyPassesOutsideIsRefused() {
        var t = table();
        assertEquals(1, ChicoryHost.run(t, tool("calls", List.of(call(2, 0, 16))), "run", opts()).value);
        assertEquals(-5, ChicoryHost.run(t, tool("calls", List.of(call(3, 0, 16))), "run", opts()).value);
    }
}
