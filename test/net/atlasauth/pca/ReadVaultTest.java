package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** K5 tokenisation vault and aggregate reads (C-315..C-319): the shared vault-aggregate-vectors.json. A missing file FAILS. */
public class ReadVaultTest {
    static final Map<String, Object> VA = Track3Vectors.load("vault-aggregate-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static Object norm(Object o) { return K5VectorsTest.norm(o); }

    @Test void samplerStreams() {
        Map<String, Object> sampler = m(VA.get("sampler"));
        assertTrue(l(sampler.get("uniform")).size() >= 2 && l(sampler.get("laplace")).size() >= 2);
        for (Object x : l(sampler.get("uniform"))) {
            Map<String, Object> u = m(x);
            ReadVault.Draws d = ReadVault.seededDraws((String) u.get("seed"));
            List<Object> got = new ArrayList<>();
            for (Object b : l(u.get("bounds"))) got.add(d.uniform(Json.asLong(b)));
            assertEquals(norm(u.get("draws")), got, "uniform " + u.get("seed"));
        }
        for (Object x : l(sampler.get("laplace"))) {
            Map<String, Object> s = m(x);
            ReadVault.Draws d = ReadVault.seededDraws((String) s.get("seed"));
            List<Object> got = new ArrayList<>();
            for (int i = 0; i < l(s.get("values")).size(); i++) got.add(ReadVault.discreteLaplace(d, Json.asLong(s.get("s")), Json.asLong(s.get("t"))));
            assertEquals(norm(s.get("values")), got, "laplace " + s.get("seed"));
        }
    }

    @Test void vault() {
        assertTrue(l(VA.get("vault")).size() >= 10);
        Map<String, Object> grants = m(m(VA.get("grants")).get("vault"));
        for (Object x : l(VA.get("vault"))) {
            Map<String, Object> c = m(x), in = m(c.get("redact")), dt = m(c.get("detok"));
            ReadVault.VaultStore store = ReadVault.memoryVault();
            ReadSide.Read red = ReadVault.redactReadWithVault(grants.get(c.get("redact_grant")), in.get("principal"), in.get("now"), in.get("verb"), in.get("resource"), in.get("purpose"),
                in.get("schema"), in.get("record"), in.get("tighten"), in.get("salt"), in.get("counts"), store);
            Object token = c.get("token") != null ? c.get("token") : red.view.get((String) c.get("field"));
            ReadVault.Detok got = ReadVault.detokenize(grants.get(c.get("detok_grant")), dt.get("principal"), dt.get("now"), dt.get("sink"), token, store);
            assertEquals(norm(c.get("expect")), got.toMap(), "vault: " + c.get("name"));
        }
    }

    static Map<String, Object> aggregateStep(Map<String, Object> input, Object state) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("principal", m(VA.get("keys")).get("principal"));
        a.put("now", 1800000000000L);
        a.put("verb", "orders.stats");
        a.put("resource", "orders/eu");
        a.put("purpose", "analytics");
        a.put("fn", "sum");
        a.put("values", new ArrayList<Object>(List.of(10L, 20L, 500L, -900L)));
        a.put("salt", "a-per-read-secret-salt");
        a.put("noise", "seeded");
        for (Map.Entry<String, Object> e : input.entrySet()) a.put(e.getKey(), e.getValue());
        Object grant = m(m(VA.get("grants")).get("aggregate")).get(input.get("grant"));
        return ReadVault.aggregateRead(grant, a.get("principal"), a.get("now"), a.get("verb"), a.get("resource"), a.get("purpose"), a.get("fn"), a.get("values"), a.get("salt"), a.get("noise"), state).toMap();
    }

    @Test void aggregate() {
        assertTrue(l(VA.get("aggregate")).size() >= 10);
        for (Object x : l(VA.get("aggregate"))) {
            Map<String, Object> c = m(x);
            Object state = c.get("initial_state");
            for (Object so : l(c.get("steps"))) {
                Map<String, Object> s = m(so);
                Map<String, Object> got = aggregateStep(m(s.get("input")), state);
                assertEquals(norm(s.get("expect")), got, "aggregate: " + c.get("name"));
                state = got.get("state");
            }
        }
    }

    @Test void malformedStateIsRefusedWithTheEmptyState() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("grant", "main");
        Map<String, Object> bad = new LinkedHashMap<>();
        bad.put("spent_micro", 1.5);
        bad.put("queries", 0L);
        bad.put("answered", new LinkedHashMap<String, Object>());
        Map<String, Object> got = aggregateStep(input, bad);
        assertEquals("bad_request", got.get("code"));
        assertEquals(ReadVault.State.empty().toMap(), got.get("state"));
        assertEquals("bad_request", aggregateStep(input, null).get("code"));
    }

    @Test void uniformRejectsBadBounds() {
        ReadVault.Draws d = ReadVault.seededDraws("seed-a");
        for (long bad : new long[] {0, -1, (1L << 47) + 1}) {
            try { d.uniform(bad); throw new AssertionError("uniform accepted " + bad); } catch (IllegalArgumentException expected) { /* a bad bound */ }
        }
    }

    @Test void secureNoiseDiffersBetweenCalls() {
        // 'secure' draws a fresh CSPRNG seed per call: two streams must differ (values are not pinned)
        boolean differ = false;
        long first = ReadVault.discreteLaplace(ReadVault.secureDraws(), 1, 1);
        for (int i = 0; i < 64 && !differ; i++) differ = ReadVault.discreteLaplace(ReadVault.secureDraws(), 1, 1) != first;
        assertTrue(differ, "64 secure draws all equal: the stream is not random");
        ReadVault.Draws a = ReadVault.secureDraws(), b = ReadVault.secureDraws();
        long sa = 0, sb = 0;
        for (int i = 0; i < 8; i++) { sa = sa * 31 + a.uniform(1L << 47); sb = sb * 31 + b.uniform(1L << 47); }
        assertNotEquals(sa, sb);
    }
}
