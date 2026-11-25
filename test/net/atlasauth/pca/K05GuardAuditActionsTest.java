package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Guard-deletion audit (Actions group): the restored explicit refusals keep the references' verdicts for non-object, null and missing inputs. */
public class K05GuardAuditActionsTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> j(String s) { return (Map<String, Object>) Json.parse(s); }

    @Test
    void reapprovalOfAnythingButAnObjectWithAnObjectSigIsRefused() {
        assertFalse(ActionRegistry.reapprovalValid("x", "g", "i", "v", "d"));
        assertFalse(ActionRegistry.reapprovalValid(null, "g", "i", "v", "d"));
        assertFalse(ActionRegistry.reapprovalValid(j("{\"v\":1,\"kind\":\"k\",\"grant\":\"g\",\"verb\":\"v\",\"diff\":\"d\",\"sig\":\"s\"}"), "g", "i", "v", "d"));
    }

    @Test
    void rule22DeniesAnUnknownVerb() {
        assertEquals("deny", ActionRegistry.rule22Decide(j("{\"verbs\":[]}"), "nope", j("{\"max_esc\":3,\"preauth_esc\":3,\"caveats\":[]}"), new ArrayList<>()));
    }

    @Test
    void undoTokenAndReceiptShapes() {
        Map<String, Object> rec = new LinkedHashMap<>();
        assertEquals(Undo.MALFORMED, Undo.tokenCheck("x", "s", rec, 0L));
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(null, "s", rec, 0L));
        // ten members, one unknown (so a known one is absent)
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(j("{\"v\":1,\"kind\":\"k\",\"record\":\"r\",\"aud\":\"a\",\"principal\":\"p\",\"compensation_digest\":\"c\",\"render_digest\":\"d\",\"exp\":1,\"signer\":\"s\",\"zzz\":\"q\"}"), "s", rec, 0L));
        assertNull(Undo.decodeToken(null));
        assertNull(Undo.decodeToken(""));
        assertNull(Undo.decodeToken("!!"));
        assertNull(Undo.decodeToken(Pca.b64("[1]".getBytes(StandardCharsets.UTF_8))));
        assertNull(Undo.decodeToken(Pca.b64("null".getBytes(StandardCharsets.UTF_8))));
        assertFalse(Undo.verifyReceipt("x", "s"));
        assertFalse(Undo.verifyReceipt(j("{}"), null));
    }

    @Test
    void requestBundleWithoutAUsableBody() {
        assertNull(ArgProvenance.requestBundle(null, null));
        assertNull(ArgProvenance.requestBundle(null, new byte[0]));
        assertNull(ArgProvenance.requestBundle(null, "[1]".getBytes(StandardCharsets.UTF_8)));
        assertNull(ArgProvenance.requestBundle(null, "\"s\"".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void provenanceGateAndInclusionRefuseMalformedInput() {
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate("x").code);
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate(null).code);
        byte[] h = new byte[32];
        List<byte[]> withNull = new ArrayList<>();
        withNull.add(null);
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(h, 0, 2, null, h));
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(h, 0, 2, withNull, h));
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(h, 0, 2, List.of(new byte[31]), h));
    }
}
