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

/** createSandbox: the table, the receipt log, the proven runtime class and a run over a minted handle. */
class SandboxTest {
    private static Authorize.AuthorizeResult allow(String verb, String resource, Map<String, Object> params) {
        var op = new Authorize.AuthorizedOperation(verb, resource, Pca.hashCanonical(params), "op");
        return new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<String, String>(), new ArrayList<String>(), null, op, null, null, new ArrayList<String>());
    }

    private static Sandbox sandbox() {
        Map<String, Handles.Executor> ex = new LinkedHashMap<>();
        ex.put("fs.read", (v, r, p) -> new byte[] {7, 8, 9});
        Sandbox s = Sandbox.createSandbox(new Sandbox.Options(ex, 1_000_000));
        Map<String, Object> params = new LinkedHashMap<>();
        s.table.mint(allow("fs.read", "/x", params), new Authorize.Operation("fs.read", "/x", params), new Handles.MintOptions());
        return s;
    }

    private static byte[] tool(Object... kv) {
        Map<String, Object> spec = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) spec.put((String) kv[i], kv[i + 1]);
        return ReferenceTool.buildTool(spec);
    }

    @Test void aToolUsesTheMintedHandleAndTheUseIsReceipted() {
        Sandbox s = sandbox();
        Map<String, Object> call = new LinkedHashMap<>();
        call.put("handle", 1);
        call.put("ptr", 0);
        call.put("cap", 16);
        var r = s.run(tool("calls", List.of(call), "returns", "byte0"));
        assertTrue(r.ok, r.toString());
        assertEquals(7, r.value);
        assertTrue(s.log.entries().size() >= 1);
    }

    @Test void withoutAClaimTheClassIsNoneAndABadModuleIsRefusedWithAReason() {
        Sandbox s = sandbox();
        assertEquals("none", s.table.runtimeClass());
        assertEquals("module_size", s.run(new byte[0]).reason);
        assertEquals("malformed_module", s.run(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}).reason);
    }

    @Test void aBudgetIsRequired() {
        Sandbox s = Sandbox.createSandbox(new Sandbox.Options(new LinkedHashMap<>(), 0));
        assertEquals("bad_fuel", s.run(tool("calls", List.of())).reason);
    }
}
