package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Round-6 threshold seams under the unit suite (so mutation testing sees them): the shared threshold_set / signer_set_hash /
 * malformed / depth primitives with their exact verdicts, plus the package-private helpers (exactT, validatedRegistry,
 * signerSetHashB64u) whose individual guards are otherwise masked by the later checks of verifyShare.
 */
public class ThresholdR6UnitTest {
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }
    static Json.Num n(String s) { return new Json.Num(s); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> prim() throws Exception { return (Map<String, Object>) ReasonSnapshot.loadJson("vectors.json").get("primitives"); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> tsEntry(String name) throws Exception {
        for (Object x : (List<Object>) prim().get("threshold_set")) if (name.equals(((Map<String, Object>) x).get("name"))) return (Map<String, Object>) x;
        throw new IllegalStateException(name);
    }

    static final java.util.Set<String> IMPL = java.util.Set.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65");

    @SuppressWarnings("unchecked")
    @Test void thresholdSetVectorsExact() throws Exception {
        int ran = 0;
        for (Object x : (List<Object>) prim().get("threshold_set")) {
            Map<String, Object> e = (Map<String, Object>) x;
            if (e.get("requires") instanceof String && !IMPL.contains(e.get("requires"))) continue;
            assertEquals(Boolean.TRUE.equals(e.get("valid")), Threshold.verifyShareEntry(e), String.valueOf(e.get("name")));
            // the same verdict through the typed entry point
            byte[] tm = Pca.decodeB64uStrict(e.get("threshold_message"), -1);
            Integer t = Threshold.exactT(e.get("t"));
            if (tm != null && t != null && e.get("role") instanceof String && e.get("signer_set") instanceof List && e.get("share") instanceof Map)
                assertEquals(Boolean.TRUE.equals(e.get("valid")), Threshold.verifyShare((String) e.get("role"), tm, (List<Object>) e.get("signer_set"), t, (Map<String, Object>) e.get("share")), String.valueOf(e.get("name")));
            ran++;
        }
        assertTrue(ran >= 55, "ran " + ran);
    }

    @SuppressWarnings("unchecked")
    @Test void signerSetHashVectorsExact() throws Exception {
        for (Object x : (List<Object>) prim().get("signer_set_hash")) {
            Map<String, Object> e = (Map<String, Object>) x;
            assertEquals(e.get("hash"), Threshold.signerSetHashB64u(e.get("signer_set")), String.valueOf(e.get("name")));
        }
        Map<String, Object> m = map("role", "agent", "publicKey", "k");
        assertNotNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(m))));
        assertNull(Threshold.signerSetHashB64u(null));
        assertNull(Threshold.signerSetHashB64u(map("role", "agent")));
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of("x"))));
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(map("role", 1, "publicKey", "k")))));
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(map("role", "agent", "publicKey", 1)))));
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(map("publicKey", "k")))));
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(map("role", "agent")))));
        // a lone surrogate cannot be strict-canonicalised: null, never an exception
        assertNull(Threshold.signerSetHashB64u(new ArrayList<>(List.of(map("role", "\uD800", "publicKey", "k")))));
    }

    @SuppressWarnings("unchecked")
    @Test void malformedAndDepthVectorsDeny() throws Exception {
        for (Object x : (List<Object>) prim().get("malformed")) {
            Map<String, Object> m = (Map<String, Object>) x;
            if (!"threshold_share".equals(m.get("api"))) continue;
            assertFalse(Threshold.verifyShareEntry(m.get("input")), String.valueOf(m.get("name")));
        }
        for (Object x : (List<Object>) prim().get("depth")) {
            Map<String, Object> d = (Map<String, Object>) x;
            if (d.get("expand") != null || !"threshold_share".equals(d.get("api"))) continue;
            assertEquals(Boolean.TRUE.equals(d.get("valid")), Threshold.verifyShareEntry(d.get("input")), String.valueOf(d.get("name")));
        }
    }

    @Test void exactT() {
        assertNull(Threshold.exactT(null));
        assertNull(Threshold.exactT(Boolean.TRUE));
        assertNull(Threshold.exactT(Boolean.FALSE));
        assertNull(Threshold.exactT("1"));
        assertNull(Threshold.exactT(new ArrayList<>(List.of(1))));
        assertNull(Threshold.exactT(n("0")));
        assertNull(Threshold.exactT(n("4")));
        assertNull(Threshold.exactT(n("-1")));
        assertNull(Threshold.exactT(n("1.5")));
        assertNull(Threshold.exactT(n("x")));
        assertNull(Threshold.exactT(0));
        assertNull(Threshold.exactT(4L));
        assertEquals(1, Threshold.exactT(n("1")));
        assertEquals(2, Threshold.exactT(n("2.0")));
        assertEquals(3, Threshold.exactT(n("3")));
        assertEquals(1, Threshold.exactT(1));
        assertEquals(2, Threshold.exactT(2L));
        assertEquals(3, Threshold.exactT(3.0d));
    }

    static String b64(int len, int fill) { byte[] b = new byte[len]; java.util.Arrays.fill(b, (byte) fill); return Pca.b64(b); }

    @Test void validatedRegistry() {
        String a = b64(32, 1), g = b64(32, 2), p = b64(32, 3), pq = b64(1952, 7);
        Map<String, String[]> reg = Threshold.validatedRegistry(new ArrayList<>(List.of(
            map("role", "agent", "publicKey", a, "pq_pk", pq), map("role", "guardian", "publicKey", g),
            map("role", "principal", "publicKey", p), map("role", "agent", "publicKey", a, "pq_pk", pq))));
        assertNotNull(reg);
        assertEquals(3, reg.size());
        assertArrayEquals(new String[] {a, pq}, reg.get("agent"));
        assertArrayEquals(new String[] {g, null}, reg.get("guardian"));
        // every malformed set is null (not an empty registry)
        List<List<Object>> bad = List.of(
            List.of("x"),
            List.of(map("role", "Agent", "publicKey", a)),
            List.of(map("role", 1, "publicKey", a)),
            List.of(map("role", "agent", "publicKey", 5)),
            List.of(map("role", "agent", "publicKey", b64(31, 1))),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", null)),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", 5)),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", "")),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", b64(100, 1))),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", "!!")),
            List.of(map("role", "agent", "publicKey", a), map("role", "agent", "publicKey", g)),
            List.of(map("role", "agent", "publicKey", a, "pq_pk", pq), map("role", "agent", "publicKey", a)),
            List.of(map("role", "agent", "publicKey", a), map("role", "guardian", "publicKey", a)));
        for (List<Object> s : bad) assertNull(Threshold.validatedRegistry(new ArrayList<>(s)), s.toString());
        // every registered PQ key length is accepted
        for (int len : new int[] {1952, 2592, 32, 64, 897, 1793, 97484})
            assertNotNull(Threshold.validatedRegistry(new ArrayList<>(List.of(map("role", "agent", "publicKey", a, "pq_pk", b64(len, 9))))), "len " + len);
    }

    @SuppressWarnings("unchecked")
    @Test void verifyShareGuards() throws Exception {
        Map<String, Object> e = tsEntry("r6-pos-ed25519");
        String role = (String) e.get("role");
        byte[] tm = Pca.decodeB64uStrict(e.get("threshold_message"), -1);
        List<Object> set = (List<Object>) e.get("signer_set");
        Map<String, Object> share = (Map<String, Object>) e.get("share");
        assertTrue(Threshold.verifyShare(role, tm, set, 1, share));
        for (int t : new int[] {0, 2, 3, 4, -1, 256}) assertFalse(Threshold.verifyShare(role, tm, set, t, share), "t=" + t);
        Map<String, Object> noRole = new LinkedHashMap<>(share); noRole.remove("role");
        assertFalse(Threshold.verifyShare(role, tm, set, 1, noRole));
        Map<String, Object> otherRole = new LinkedHashMap<>(share); otherRole.put("role", "guardian");
        assertFalse(Threshold.verifyShare(role, tm, set, 1, otherRole));
        assertFalse(Threshold.verifyShare("guardian", tm, set, 1, otherRole));
        assertFalse(Threshold.verifyShare(role, tm, new ArrayList<>(List.of("x")), 1, share));
        assertFalse(Threshold.verifyShare(role, tm, null, 1, share));
        // the entry form: each field's type is checked
        assertTrue(Threshold.verifyShareEntry(e));
        for (String k : new String[] {"role", "t", "signer_set", "threshold_message", "share"}) {
            Map<String, Object> m = new LinkedHashMap<>(e); m.put(k, 7);
            assertFalse(Threshold.verifyShareEntry(m), k);
            Map<String, Object> r = new LinkedHashMap<>(e); r.remove(k);
            assertFalse(Threshold.verifyShareEntry(r), k);
        }
        assertFalse(Threshold.verifyShareEntry(new ArrayList<>(List.of(e))));
        assertFalse(Threshold.verifyShareEntry(null));
    }
}
