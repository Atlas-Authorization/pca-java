package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Agent}: defaults, setters, every signed slot, counters, delegation and the HTTP helpers, asserted exactly. */
public class AgentRestKillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "ins_agent_kill";

    static byte[] fill(int b) { byte[] x = new byte[32]; java.util.Arrays.fill(x, (byte) b); return x; }

    static final Keys.SuiteKey PRINCIPAL = Keys.ed25519(Keys.edFromSeed(fill(1)));
    static final Keys.SuiteKey ME = Keys.ed25519(Keys.edFromSeed(fill(2)));
    static final Keys.SuiteKey SUB = Keys.ed25519(Keys.edFromSeed(fill(3)));

    static Map<String, Object> grant() { return Issue.mintGrant(PRINCIPAL, ME.id(), null, ProducerTest.envelope(), "g", Pca.b64(new byte[16])).grant; }

    static long num(Object o) { return ((Number) o).longValue(); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void defaultsUseTheSystemClockAndTheDefaultTtl() {
        Agent a = Agent.create(ME, AUD, grant(), null);
        long before = System.currentTimeMillis();
        Map<String, Object> p = a.act("read", "x", null);
        long after = System.currentTimeMillis();
        long iat = num(p.get("iat"));
        assertTrue(iat >= before && iat <= after, "iat " + iat);
        assertEquals(1_200_000L, num(p.get("exp")) - iat);
        assertEquals(Issue.DEFAULT_TTL_MS, num(p.get("exp")) - iat);
        assertEquals(22, ((String) p.get("nonce")).length());
        assertEquals(16, Pca.decodeB64uStrict(p.get("nonce"), -1).length);
        assertEquals(1L, num(p.get("counter")));
        assertEquals(1L, a.counter());
        assertEquals("n1", m(p.get("plan")).get("node_id"));
        assertEquals(AUD, p.get("aud"));
    }

    @Test void settersReturnThisAndApply() {
        Agent a = Agent.create(ME, AUD, grant(), null);
        assertSame(a, a.ttlMs(5_000L));
        assertSame(a, a.clock(() -> NOW));
        assertSame(a, a.nonces(false));
        assertSame(a, a.counter(5L));
        assertEquals(5L, a.counter());
        Map<String, Object> p = a.act("read", "x", null);
        assertEquals(NOW, num(p.get("iat")));
        assertEquals(NOW + 5_000L, num(p.get("exp")));
        assertFalse(p.containsKey("nonce"));
        assertEquals(6L, num(p.get("counter")));
        assertEquals(6L, a.counter());
        assertEquals("n6", m(p.get("plan")).get("node_id"));
        Map<String, Object> q = a.act("read", "y", null);
        assertEquals("n7", m(q.get("plan")).get("node_id"));
        assertEquals(7L, num(q.get("counter")));
        a.nonces(true);
        assertEquals(22, ((String) a.act("read", "z", null).get("nonce")).length());
    }

    static final String[] MAP_SLOTS = {"progress_step", "intent", "intent_session", "fresh_at", "provenance", "attestation", "freshness", "risk_claim"};

    @Test void everySlotIsSignedAsGiven() {
        Agent a = Agent.create(ME, AUD, grant(), null).clock(() -> NOW);
        Map<String, Object> slots = new LinkedHashMap<>();
        slots.put("nonce", "c2xvdC1ub25jZS0xMjM0NTY");
        slots.put("caution", new Json.Num("0.5"));
        slots.put("rationale_commitment", "rc");
        slots.put("tool_binding", "tb");
        slots.put("prohibition_evidence", new ArrayList<Object>(List.of("pe")));
        for (String k : MAP_SLOTS) slots.put(k, Issue.obj("slot", k));
        Map<String, Object> p = a.act("read", "x", null, slots);
        for (Map.Entry<String, Object> e : slots.entrySet()) assertSame(e.getValue(), p.get(e.getKey()), e.getKey());
        // a map slot holding a non-object is absent, not empty
        Map<String, Object> wrong = new LinkedHashMap<>();
        for (String k : MAP_SLOTS) wrong.put(k, "not-an-object");
        Map<String, Object> w = a.act("read", "x", null, wrong);
        for (String k : MAP_SLOTS) {
            if (k.equals("attestation") || k.equals("provenance") || k.equals("freshness") || k.equals("risk_claim")) {
                assertNotEquals("not-an-object", w.get(k), k); // replaced by the unattested default
                assertFalse(m(w.get(k)).containsKey("slot"), k);
            } else assertFalse(w.containsKey(k), k);
        }
        assertEquals(Json.canonicalize(Issue.obj("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested")),
            Json.canonicalize(w.get("attestation")));
        assertEquals(22, ((String) w.get("nonce")).length()); // slots without a nonce keep the generated one
        assertFalse(w.containsKey("caution"));
        assertFalse(w.containsKey("rationale_commitment"));
        assertFalse(w.containsKey("tool_binding"));
        assertFalse(w.containsKey("prohibition_evidence"));
        Map<String, Object> onlyNonce = new LinkedHashMap<>();
        onlyNonce.put("nonce", "Zml4ZWQtbm9uY2UtMDAwMDA");
        assertEquals("Zml4ZWQtbm9uY2UtMDAwMDA", a.nonces(false).act("read", "x", null, onlyNonce).get("nonce"));
    }

    @Test void actNodeNeedsAPlan() {
        Agent a = Agent.create(ME, AUD, grant(), null).clock(() -> NOW);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> a.actNode("s0", null));
        assertEquals("commitPlan() first", e.getMessage());
        assertEquals(0L, a.counter());
        List<Map<String, Object>> nodes = new ArrayList<>();
        nodes.add(Issue.obj("id", "s0", "verb", "read", "resource", "r"));
        a.commitPlan(nodes);
        assertEquals("s0", m(a.actNode("s0", null).get("plan")).get("node_id"));
    }

    @Test void createChecksAudAndCopiesTheChain() {
        Map<String, Object> g = grant();
        IllegalArgumentException e1 = assertThrows(IllegalArgumentException.class, () -> Agent.create(ME, null, g, null));
        assertEquals("Agent: aud (the resource server / instance id) is required", e1.getMessage());
        IllegalArgumentException e2 = assertThrows(IllegalArgumentException.class, () -> Agent.create(ME, "", g, null));
        assertEquals("Agent: aud (the resource server / instance id) is required", e2.getMessage());
        Agent d = Agent.create(ME, AUD, g, null);
        assertEquals(1, d.chain.size());
        assertSame(g, d.chain.get(0));
        List<Object> chain = new ArrayList<>(List.of(g, "hop"));
        Agent c = Agent.create(ME, AUD, g, chain);
        assertEquals(chain, c.chain);
        assertNotSame(chain, c.chain);
        assertSame(g, c.grant);
        assertSame(ME, c.signer);
        assertEquals(AUD, c.aud);
    }

    @Test void delegateInheritsSettingsAndBindsThePqKey() {
        Keys.SuiteKey pure = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(4)));
        Agent a = Agent.create(ME, AUD, grant(), null).clock(() -> NOW).ttlMs(7_000L).nonces(false).counter(9L);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> a.delegate(pure, null));
        assertEquals("a delegate holder needs an Ed25519 identity", e.getMessage());
        Agent child = a.delegate(SUB, null);
        assertEquals(0L, child.counter());
        assertEquals(9L, a.counter());
        Map<String, Object> p = child.act("read", "x", null);
        assertEquals(1L, num(p.get("counter")));
        assertEquals("n1", m(p.get("plan")).get("node_id"));
        assertEquals(NOW, num(p.get("iat")));
        assertEquals(NOW + 7_000L, num(p.get("exp")));
        assertFalse(p.containsKey("nonce"));
        assertEquals(2, child.chain.size());
        assertFalse(m(child.chain.get(1)).containsKey("holder_pq"));

        Keys.SuiteKey hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(5)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(6)));
        Agent h = a.delegate(hybrid, null);
        assertEquals(Pca.holderPqCommitment(hybrid.pqPk()), m(h.chain.get(1)).get("holder_pq"));
        assertEquals(hybrid.id(), m(h.chain.get(1)).get("holder"));
        assertSame(hybrid, h.signer);
    }

    @Test void attachSetsTheHeaderOnTheSameBuilder() {
        Map<String, Object> p = Agent.create(ME, AUD, grant(), null).clock(() -> NOW).act("read", "x", null);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1/"));
        assertSame(b, Agent.attach(b, p));
        assertEquals(Agent.header(p), b.build().headers().firstValue(Agent.HEADER).orElse(null));
        assertEquals(Issue.header(p), Agent.header(p));
    }

    @Test void sendCarriesTheHeader() throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        srv.createContext("/", ex -> {
            byte[] out = String.valueOf(ex.getRequestHeaders().getFirst(Agent.HEADER)).getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        srv.start();
        try {
            Map<String, Object> p = Agent.create(ME, AUD, grant(), null).clock(() -> NOW).act("read", "x", null);
            HttpResponse<String> r = Agent.send(HttpClient.newHttpClient(),
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.getAddress().getPort() + "/a")), p);
            assertNotNull(r);
            assertEquals(200, r.statusCode());
            assertEquals(Agent.header(p), r.body());
        } finally {
            srv.stop(0);
        }
    }
}
