package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The reference per-hop type check (capability.ts wellTyped) with EXACT reasons: an ill-typed hop is "hop N: malformed
 * capability" (never an exception routed through the total catch), checked before any signature work, so a validly signed root
 * that only gains an ill-typed unsigned field is refused. Plus the lenient canonical cap on nested OBJECTS and the empty
 * signer-set hash.
 */
public class WellTypedKillTest {
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }

    static Map<String, Object> root() throws Exception { return new LinkedHashMap<>(PcaUnitTest.m(PcaUnitTest.twoHop().get(0))); }

    static String chain1(Map<String, Object> r) { return Pca.verifyChain(new ArrayList<>(List.of(r)), (String) r.get("issuer"), true, null); }

    @Test void validRootBaseline() throws Exception {
        assertEquals("", chain1(root()));
        assertTrue(Pca.wellTyped(root()));
    }

    @Test void emptyAndNullChain() {
        assertEquals("empty chain", Pca.verifyChain(null, "x", true, null));
        assertEquals("empty chain", Pca.verifyChain(new ArrayList<>(), "x", true, null));
    }

    @Test void illTypedOptionalFieldsOnASignedRoot() throws Exception {
        // the unsigned / suite fields: present-but-not-a-string is ill-typed, even though the signature would verify
        for (String k : new String[] {"alg", "pq_pk", "pq_sig", "holder_pq", "parent"}) {
            for (Object bad : new Object[] {5, null, new ArrayList<>(), map("a", 1), Boolean.TRUE}) {
                Map<String, Object> r = root();
                r.put(k, bad);
                assertFalse(Pca.wellTyped(r), k + "=" + bad);
                assertEquals("hop 0: malformed capability", chain1(r), k + "=" + bad);
            }
        }
        for (String k : new String[] {"id", "issuer", "holder", "body_digest", "sig"}) {
            Map<String, Object> r = root();
            r.put(k, 5);
            assertFalse(Pca.wellTyped(r), k);
            r.remove(k);
            assertFalse(Pca.wellTyped(r), k);
        }
    }

    @Test void illTypedCaveats() throws Exception {
        for (Object bad : new Object[] {5, null, "x", map("type", "a")}) {
            Map<String, Object> r = root();
            r.put("caveats", bad);
            assertFalse(Pca.wellTyped(r), String.valueOf(bad));
            assertEquals("hop 0: malformed capability", chain1(r), String.valueOf(bad));
        }
        Map<String, Object> r = root();
        r.remove("caveats");
        assertEquals("hop 0: malformed capability", chain1(r));
        for (Object badCv : new Object[] {5, null, "x", new ArrayList<>(List.of("type", "a")), map("note", 1), map("type", 5), map("type", null)}) {
            Map<String, Object> c = root();
            List<Object> cv = new ArrayList<>(PcaUnitTest.l(c.get("caveats")));
            cv.add(badCv);
            c.put("caveats", cv);
            assertFalse(Pca.wellTyped(c), String.valueOf(badCv));
            assertEquals("hop 0: malformed capability", chain1(c), String.valueOf(badCv));
        }
        assertFalse(Pca.wellTyped(null));
        assertFalse(Pca.wellTyped("x"));
        assertFalse(Pca.wellTyped(new ArrayList<>()));
        // an empty caveat list is well-typed
        Map<String, Object> e = root();
        e.put("caveats", new ArrayList<>());
        assertTrue(Pca.wellTyped(e));
    }

    /** k nested single-key objects around 1: depth k. */
    static Object nestedMap(int k) {
        Object a = 1;
        for (int i = 0; i < k; i++) a = map("k", a);
        return a;
    }

    @Test void lenientCapOnNestedObjects() throws Throwable {
        DepthTotalityTest.onSmallStack(() -> {
            assertNotNull(Json.canonicalize(nestedMap(Json.MAX_LENIENT_DEPTH)));
            assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(nestedMap(Json.MAX_LENIENT_DEPTH + 1))).getMessage());
            assertNotNull(Json.canonicalizeStrict(nestedMap(Json.MAX_DEPTH)));
            assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(nestedMap(Json.MAX_DEPTH + 1))).getMessage());
        });
    }

    @Test void emptySignerSet() {
        assertNotNull(Threshold.signerSetHashB64u(new ArrayList<>()));
        assertNotNull(Threshold.validatedRegistry(new ArrayList<>()));
        assertTrue(Threshold.validatedRegistry(new ArrayList<>()).isEmpty());
    }
}
