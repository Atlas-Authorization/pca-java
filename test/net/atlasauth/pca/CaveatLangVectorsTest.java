package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The shared caveat language v2 vectors (caveat-lang-vectors.json): all six primitives, plus exact-outcome unit tests. */
public class CaveatLangVectorsTest {
    static final String FILE = "conformance/caveat-lang-vectors.json";

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> table(String name) throws Exception {
        Map<String, Object> d = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE)));
        return (List<Map<String, Object>>) (List<?>) ((Map<String, Object>) d.get("primitives")).get(name);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static String name(Map<String, Object> v) { return String.valueOf(v.get("name")); }

    static Json.Num num(long v) { return IntentJs.ofLong(v); }

    static Map<String, Object> clock(long now) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("now", num(now));
        return b;
    }

    @Test void tableSizes() throws Exception {
        assertEquals(60, table("discharge_verify").size());
        assertEquals(110, table("k1_eval").size());
        assertEquals(52, table("caveat_shape").size());
        assertEquals(5, table("uses_key").size());
        assertEquals(12, table("uses_reserve").size());
        assertEquals(9, table("k1_unconfigured").size());
        assertEquals(9, table("consume_once_ttl").size());
        assertEquals(15, table("k1_headers").size());
        assertEquals(24, table("spiffe_id").size());
    }

    @Test void dischargeVerifyVectors() throws Exception {
        int ran = 0, unsupported = 0;
        for (Map<String, Object> v : table("discharge_verify")) {
            Map<String, Object> in = m(v.get("input"));
            Map<String, Object> e = m(v.get("expect"));
            CaveatLang.DischargeVerdict r = CaveatLang.verifyDischarge(in.get("discharge"), in.get("caveat"), m(in.get("binding")));
            Object need = v.get("requires_suite");
            if (need != null && !Pq.supportedSuites().contains(need)) {
                // a suite this SDK does not implement is never accepted: the discharge is refused as unsupported_suite
                assertFalse(r.ok, name(v) + " must not verify under an unimplemented suite");
                assertTrue(r.reason.contains("unsupported_suite"), name(v) + ": " + r.reason);
                unsupported++;
                continue;
            }
            assertEquals(e.get("ok"), r.ok, name(v) + ": " + r.reason);
            if (r.ok) {
                assertEquals(e.get("digest"), r.digest, name(v));
                assertEquals(IntentJs.canon(e.get("claims")), IntentJs.canon(r.claims), name(v));
            } else {
                assertTrue(r.reason.contains((String) e.get("reason_contains")), name(v) + ": " + r.reason);
            }
            ran++;
        }
        assertTrue(ran >= 40, "ran " + ran);
        assertTrue(unsupported <= 10, "unsupported " + unsupported);
    }

    @Test void k1EvalVectors() throws Exception {
        int ran = 0;
        for (Map<String, Object> v : table("k1_eval")) {
            Map<String, Object> in = m(v.get("input"));
            Map<String, Object> e = m(v.get("expect"));
            Caveats.Result r = CaveatLang.evaluateCaveatsK1(in.get("grant"), in.get("chain"), m(in.get("k1")), m(in.get("context")));
            assertEquals(e.get("allow"), r.ok, name(v) + ": " + r.failed);
            assertEquals(e.get("failed"), r.failed, name(v));
            ran++;
        }
        assertEquals(110, ran);
    }

    @Test void caveatShapeVectors() throws Exception {
        int ran = 0;
        for (Map<String, Object> v : table("caveat_shape")) {
            Object c = m(v.get("input")).get("caveat");
            String type = String.valueOf(m(c).get("type"));
            String err;
            switch (type) {
                case "needs_discharge": err = CaveatLang.needsDischargeError(c); break;
                case "max_uses": err = CaveatLang.maxUsesError(c); break;
                case "derive": err = CaveatLang.deriveError(c); break;
                case "spiffe_bound": err = CaveatLang.spiffeBoundError(c); break;
                default: throw new AssertionError("unexpected caveat type " + type);
            }
            assertEquals(m(v.get("expect")).get("valid"), err == null, name(v) + ": " + err);
            ran++;
        }
        assertEquals(52, ran);
    }

    @Test void usesKeyVectors() throws Exception {
        for (Map<String, Object> v : table("uses_key")) {
            Map<String, Object> in = m(v.get("input"));
            assertEquals(m(v.get("expect")).get("key"),
                CaveatLang.maxUsesSlotKey((String) in.get("cap_hash"), (String) in.get("id"), (int) IntentJs.lng(in.get("i"))), name(v));
        }
    }

    @Test void usesReserveVectors() throws Exception {
        int calls = 0;
        for (Map<String, Object> v : table("uses_reserve")) {
            Map<String, Object> in = m(v.get("input"));
            List<CaveatLang.BoundCaveat> bound = new ArrayList<>();
            for (Object b : (List<?>) in.get("bound")) bound.add(new CaveatLang.BoundCaveat(m(b).get("caveat"), 0, (String) m(b).get("cap_hash")));
            MemoryStateStore store = new MemoryStateStore();
            List<?> want = (List<?>) m(v.get("expect")).get("results");
            List<?> cs = (List<?>) in.get("calls");
            assertEquals(want.size(), cs.size(), name(v));
            for (int i = 0; i < cs.size(); i++) {
                CaveatLang.UsesVerdict r = CaveatLang.reserveMaxUses(store, bound, m(cs.get(i)).get("now"));
                Map<String, Object> w = m(want.get(i));
                assertEquals(w.get("ok"), r.ok, name(v) + " call " + i + ": " + r.reason);
                if (r.ok) assertEquals((int) IntentJs.lng(w.get("spent")), r.spent, name(v) + " call " + i);
                else assertTrue(r.reason.contains((String) w.get("reason_contains")), name(v) + " call " + i + ": " + r.reason);
                calls++;
            }
        }
        assertTrue(calls >= 250, "calls " + calls);
    }

    @Test void spiffeIdVectors() throws Exception {
        for (Map<String, Object> v : table("spiffe_id")) {
            String err = CaveatLang.spiffeIdError(m(v.get("input")).get("id"));
            assertEquals(m(v.get("expect")).get("valid"), err == null, name(v) + ": " + err);
        }
    }

    // ---- exact outcomes the vectors cannot show -------------------------------------------------------------------

    @Test void hostileInputsDoNotThrow() {
        Map<String, Object> bind = clock(1);
        bind.put("pins", new ArrayList<>());
        assertEquals("malformed needs_discharge caveat: caveat must be an object", CaveatLang.verifyDischarge("x", "y", bind).reason);
        assertTrue(CaveatLang.verifyDischarge(null, null, null).reason.startsWith("discharge error (fail closed)"));
        assertEquals("malformed narrow block: not an object", CaveatLang.verifyNarrow(5, null, null, bind).reason);
        assertTrue(CaveatLang.verifyNarrow(null, null, null, null).reason.startsWith("narrow error (fail closed)"));
        assertEquals("the verifier clock is not a safe integer (fail closed)", CaveatLang.verifyNarrow(null, null, null, new LinkedHashMap<>()).reason);
        assertNull(CaveatLang.boundCaveats(5, "x"));
        assertNull(CaveatLang.boundCaveats(null, null));
        assertEquals("caveat must be an object", CaveatLang.deriveError(null));
        assertEquals("caveat must be an object", CaveatLang.maxUsesError("x"));
        assertEquals("caveat must be an object", CaveatLang.spiffeBoundError(List.of()));
        assertEquals("caveat must be an object", CaveatLang.needsDischargeError(7));
        assertEquals("not an object", CaveatLang.dischargeShapeError("x"));
        assertEquals("not an object", CaveatLang.narrowShapeError(null));
        assertFalse(CaveatLang.isK1Caveat("sealed"));
        assertFalse(CaveatLang.isK1Caveat(null));
        CaveatLang.K1Result k = CaveatLang.evaluateK1(null, null, null, null);
        assertFalse(k.ok);
        assertEquals(List.of("<malformed>"), k.failed);
        assertEquals(List.of("malformed capability chain"), k.reasons);
        assertTrue(k.bound.isEmpty());
        CaveatLang.K1Result k2 = CaveatLang.evaluateK1(m(Json.parseLenient("{\"caveats\":[]}")), null, null, clock(1));
        assertTrue(k2.ok, String.valueOf(k2.reasons));
        assertEquals(0, k2.bound.size());
        Caveats.Result r = CaveatLang.evaluateCaveatsK1(null, null, null, null);
        assertFalse(r.ok);
    }

    @Test void reserveWithoutCaveatsSpendsNothing() {
        CaveatLang.UsesVerdict r = CaveatLang.reserveMaxUses(new MemoryStateStore(), new ArrayList<>(), 5L);
        assertTrue(r.ok);
        assertEquals(0, r.spent);
        CaveatLang.UsesVerdict bad = CaveatLang.reserveMaxUses(new MemoryStateStore(), new ArrayList<>(), new Json.Num("5.5"));
        assertFalse(bad.ok);
        assertTrue(bad.reason.contains("not a safe integer"));
    }

    @Test void failingStoreRefuses() {
        Map<String, Object> cv = m(Json.parseLenient("{\"type\":\"max_uses\",\"id\":\"u\",\"n\":2,\"until\":1800000010000}"));
        List<CaveatLang.BoundCaveat> bound = List.of(new CaveatLang.BoundCaveat(cv, 0, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"));
        CaveatLang.UsesVerdict thrown = CaveatLang.reserveMaxUses((k, c) -> { throw new IllegalStateException("down"); }, bound, 1800000000000L);
        assertFalse(thrown.ok);
        assertTrue(thrown.reason.startsWith("max_uses error (fail closed)"), thrown.reason);
        CaveatLang.UsesVerdict nul = CaveatLang.reserveMaxUses((k, c) -> null, bound, 1800000000000L);
        assertFalse(nul.ok);
        assertTrue(nul.reason.startsWith("max_uses error (fail closed)"), nul.reason);
    }

    @Test void identifiersAreFullMatch() {
        // an id with a trailing newline is malformed (a "$"-style anchor would tolerate it)
        Map<String, Object> mu = m(Json.parseLenient("{\"type\":\"max_uses\",\"id\":\"u\\n\",\"n\":1,\"until\":5}"));
        assertEquals("id is malformed", CaveatLang.maxUsesError(mu));
        Map<String, Object> ok = m(Json.parseLenient("{\"type\":\"max_uses\",\"id\":\"u\",\"n\":1,\"until\":5}"));
        assertNull(CaveatLang.maxUsesError(ok));
        assertNotNull(CaveatLang.spiffeIdError("spiffe://acme.test/a\n"));
    }

    // ---- round 2: unconfigured k1, TTL'd consume-once, discharge headers -------------------------------------------

    @Test void k1UnconfiguredVectors() throws Exception {
        int ran = 0;
        for (Map<String, Object> v : table("k1_unconfigured")) {
            Map<String, Object> in = m(v.get("input"));
            Map<String, Object> e = m(v.get("expect"));
            Caveats.Result r = CaveatLang.evaluateCaveatsK1(in.get("grant"), in.get("chain"), null, m(in.get("context")));
            assertEquals(e.get("allow"), r.ok, name(v) + ": " + r.failed);
            assertEquals(e.get("failed"), r.failed, name(v));
            ran++;
        }
        assertTrue(ran >= 9, "ran " + ran);
    }

    @Test void unconfiguredK1ReasonAndEmptyObjectIsConfigured() {
        Map<String, Object> g = m(Json.parseLenient("{\"caveats\":[{\"type\":\"sealed\"}]}"));
        Map<String, Object> ctx = clock(1);
        CaveatLang.K1Result none = CaveatLang.evaluateK1(g, null, null, ctx);
        assertFalse(none.ok);
        assertEquals(List.of("the caveat language is not configured (no k1 input)"), none.reasons);
        assertTrue(CaveatLang.evaluateK1(g, null, new LinkedHashMap<>(), ctx).ok);
    }

    private static String ttl(StateStore s, Map<String, Object> st) {
        try {
            return String.valueOf(s.consumeOnce((String) st.get("key"), IntentJs.lng(st.get("retain_until")), IntentJs.lng(st.get("now"))));
        } catch (IllegalArgumentException e) {
            return "error";
        }
    }

    private static int replayTtl(java.util.function.Supplier<StateStore> fresh) throws Exception {
        int steps = 0;
        for (Map<String, Object> v : table("consume_once_ttl")) {
            StateStore s = fresh.get();
            List<?> want = (List<?>) m(v.get("expect")).get("results");
            List<?> in = (List<?>) m(v.get("input")).get("steps");
            assertEquals(want.size(), in.size(), name(v));
            for (int i = 0; i < in.size(); i++) {
                assertEquals(want.get(i), ttl(s, m(in.get(i))), name(v) + " step " + i);
                steps++;
            }
        }
        return steps;
    }

    @Test void consumeOnceTtlMemory() throws Exception {
        assertTrue(replayTtl(MemoryStateStore::new) >= 15);
    }

    @Test void consumeOnceTtlJdbc() throws Exception {
        Path dir = Files.createTempDirectory("pca-ttl");
        int[] n = {0};
        try {
            assertTrue(replayTtl(() -> {
                try { return AuthorizeFixtures.sqlite(dir.resolve("s" + (n[0]++) + ".db")); } catch (Exception e) { throw new IllegalStateException(e); }
            }) >= 15);
        } finally {
            try (var fs = Files.list(dir)) { fs.forEach(f -> f.toFile().delete()); }
            dir.toFile().delete();
        }
    }

    @Test void maxUsesSlotExpiresWithUntil() {
        MemoryStateStore store = new MemoryStateStore();
        Map<String, Object> cv = m(Json.parseLenient("{\"type\":\"max_uses\",\"id\":\"u\",\"n\":1,\"until\":100}"));
        List<CaveatLang.BoundCaveat> b = List.of(new CaveatLang.BoundCaveat(cv, 0, "h"));
        assertTrue(CaveatLang.reserveMaxUses(store, b, 10L).ok);
        assertFalse(CaveatLang.reserveMaxUses(store, b, 11L).ok);
        assertTrue(store.consumeOnce("k", 100, 100)); // the slot's record is gone once pruned past its horizon
        assertFalse(store.consumeOnce("k", 100, 100));
        assertTrue(store.consumeOnce("k", 300, 101));
    }

    @Test void k1HeadersVectors() throws Exception {
        int ran = 0;
        for (Map<String, Object> v : table("k1_headers")) {
            Map<String, String> h = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(m(v.get("input")).get("headers")).entrySet()) h.put(e.getKey(), (String) e.getValue());
            net.atlasauth.pca.servlet.PcaCore.PresentedK1 r = net.atlasauth.pca.servlet.PcaCore.presentedK1(h);
            Map<String, Object> e = m(v.get("expect"));
            assertEquals(e.get("ok"), r.ok, name(v) + ": " + r.error);
            if (r.ok) assertEquals(IntentJs.canon(e.get("value")), IntentJs.canon(r.value), name(v));
            ran++;
        }
        assertTrue(ran >= 15, "ran " + ran);
    }
}
