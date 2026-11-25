package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.ciba.Ciba;
import net.atlasauth.pca.ciba.CibaApproval;
import net.atlasauth.pca.ciba.CibaClient;
import net.atlasauth.pca.ciba.CibaKv;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference oracle of the CIBA on-ramp (auth request, gating, brokers, KV store, client) and covers the file stores directly. */
class CibaDiffTest {
    private static final String MOD = "ref-ciba";
    private static final long T0 = 1_800_000_000_000L;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Map<String, Object> opt(List<?> a, int i) { return a.size() > i ? (a.get(i) instanceof Map ? m(a.get(i)) : new java.util.LinkedHashMap<>()) : null; } // a non-object options value has no members

    // ---- pure functions ----

    @Test void cibaActionFromStepUp() throws Exception { OracleCases.each(MOD, "cibaActionFromStepUp", a -> Ciba.cibaActionFromStepUp(m(a.get(0)))); }

    @Test void toCibaAuthRequest() throws Exception {
        OracleCases.each(MOD, "toCibaAuthRequest", a -> {
            if (a.size() > 1 && a.get(1) == null) throw new IllegalArgumentException("opts is null"); // the reference reads a member of null
            return Ciba.toCibaAuthRequest(m(a.get(0)), opt(a, 1));
        });
    }

    @Test void asciiForm() throws Exception { OracleCases.each(MOD, "asciiForm", a -> Ciba.asciiForm((String) a.get(0))); }

    @Test void requiresCiba() throws Exception { OracleCases.each(MOD, "requiresCiba", a -> Ciba.requiresCiba(a.get(0))); }

    @Test void cibaDecisionToCosign() throws Exception {
        OracleCases.each(MOD, "cibaDecisionToCosign", a -> Ciba.cibaDecisionToCosign(a.get(0), m(a.get(1)), m(a.get(2)), a.get(3), opt(a, 4)));
    }

    @Test void verifyPingCallback() throws Exception {
        OracleCases.each(MOD, "verifyPingCallback", a -> {
            Map<String, Object> in = m(a.get(0));
            Object auth = in.get("authorization");
            return CibaClient.verifyPingCallback(auth == null ? null : (String) auth, in.get("body"), m(a.get(1)));
        });
    }

    @Test void createCibaClientConfig() throws Exception {
        OracleCases.each(MOD, "createCibaClientConfig", a -> {
            Map<String, Object> c = m(a.get(0));
            CibaClient.Config cfg = new CibaClient.Config();
            cfg.backchannelAuthenticationEndpoint = (String) c.get("backchannelAuthenticationEndpoint");
            cfg.tokenEndpoint = (String) c.get("tokenEndpoint");
            cfg.clientId = (String) c.get("clientId");
            cfg.clientSecret = (String) c.get("clientSecret");
            cfg.allowInsecureHttp = Boolean.TRUE.equals(c.get("allowInsecureHttp"));
            if (c.containsKey("timeoutMs")) cfg.timeoutMs = IntentJs.num(c.get("timeoutMs"));
            cfg.transport = (url, headers, body, timeoutMs) -> new CibaClient.Response(200, "{}");
            CibaClient.createCibaClient(cfg);
            return Boolean.TRUE;
        });
    }

    @Test void durableBrokerConfig() throws Exception {
        OracleCases.each(MOD, "durableBrokerConfig", a -> {
            Map<String, Object> c = m(a.get(0));
            CibaApproval.DurableBrokerOptions o = new CibaApproval.DurableBrokerOptions();
            if (!Boolean.TRUE.equals(c.get("noStore"))) o.store = CibaApproval.createMemoryApprovalStore();
            if (c.containsKey("decisionTtlSec")) o.decisionTtlSec = IntentJs.num(c.get("decisionTtlSec"));
            try { CibaApproval.createDurableCibaBroker(o); return "ok"; } catch (RuntimeException e) { return "throws"; }
        });
    }

    // ---- brokers as scripted scenarios ----

    private static Object redactIds(Object v, List<String> ids) {
        if (v instanceof String) {
            String s = (String) v;
            for (int i = 0; i < ids.size(); i++) s = s.replace(ids.get(i), "<ID" + (i + 1) + ">");
            return s;
        }
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(redactIds(x, ids)); return out; }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(v).entrySet()) out.put(e.getKey(), redactIds(e.getValue(), ids));
            return out;
        }
        return v;
    }

    private static Object brokerScenario(Map<String, Object> s) {
        long[] clock = {T0};
        String kind = (String) s.get("kind");
        Map<String, Object> opts = s.containsKey("opts") ? m(s.get("opts")) : new LinkedHashMap<>();
        String oc = (String) opts.get("onComplete");
        List<Object> completes = new ArrayList<>();
        Consumer<Map<String, Object>> onComplete = oc == null ? null : sess -> {
            completes.add(sess);
            if (oc.equals("throws")) throw new IllegalStateException("notifier down");
        };
        CibaKv.DurableKv kv = null;
        CibaApproval.ApprovalStore store = null;
        CibaApproval.ApprovalBroker broker;
        if (kind.equals("memory")) {
            CibaApproval.BrokerOptions bo = new CibaApproval.BrokerOptions();
            bo.now = () -> clock[0];
            bo.onComplete = onComplete;
            broker = CibaApproval.createCibaBroker(bo);
        } else {
            if (kind.equals("durable-kv")) { kv = CibaKv.createMemoryKv(); store = CibaKv.createKvApprovalStore(kv); } else store = CibaApproval.createMemoryApprovalStore();
            CibaApproval.DurableBrokerOptions o = new CibaApproval.DurableBrokerOptions();
            o.store = store;
            o.now = () -> clock[0];
            if (opts.containsKey("decisionTtlSec")) o.decisionTtlSec = IntentJs.num(opts.get("decisionTtlSec"));
            o.onComplete = onComplete;
            broker = CibaApproval.createDurableCibaBroker(o);
        }
        List<String> ids = new ArrayList<>();
        List<Object> trace = new ArrayList<>();
        for (Object so : l(s.get("steps"))) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("op", op);
            try {
                Object value = null;
                String id = null;
                Object idO = st.get("id");
                if (idO instanceof String) {
                    String x = (String) idO;
                    id = x.equals("$id") ? ids.get(ids.size() - 1) : x.startsWith("$id") ? ids.get(Integer.parseInt(x.substring(3)) - 1) : x;
                }
                switch (op) {
                    case "start": {
                        Map<String, Object> req = broker.start(m(st.get("stepUp")), st.containsKey("opts") ? m(st.get("opts")) : null);
                        if (!ids.contains((String) req.get("auth_req_id"))) ids.add((String) req.get("auth_req_id"));
                        value = req;
                        break;
                    }
                    case "poll": value = broker.poll(id); break;
                    case "token": value = broker.token(id); break;
                    case "resolve": {
                        Object d = st.get("decision"), by = st.get("by");
                        value = broker.resolve(id, d instanceof String ? (String) d : "\u0000invalid", by instanceof String ? (String) by : null);
                        break;
                    }
                    case "get": value = broker.get(id); break;
                    case "advance": clock[0] += (long) (double) IntentJs.num(st.get("ms")); value = clock[0]; break;
                    case "storeSet": {
                        String key = ((String) st.get("key")).replace("$id", ids.isEmpty() ? "" : ids.get(ids.size() - 1));
                        CibaApproval.Versioned cur = store.get(key);
                        value = store.cas(key, cur == null ? 0 : cur.version, st.get("value"));
                        break;
                    }
                    case "kvRaw": {
                        String key = ((String) st.get("key")).replace("$id", ids.isEmpty() ? "" : ids.get(ids.size() - 1));
                        value = kv.putIfEquals(key, kv.get(key), (String) st.get("raw"));
                        break;
                    }
                    default: throw new IllegalStateException("unknown step " + op);
                }
                entry.put("ok", true);
                entry.put("value", value);
            } catch (CibaKv.ApprovalStoreError e) {
                entry.put("ok", false);
                entry.put("msg", e.getMessage());
                entry.put("code", e.code());
            } catch (RuntimeException e) {
                entry.put("ok", false);
                entry.put("msg", e.getMessage());
            }
            if (!completes.isEmpty()) { entry.put("complete", new ArrayList<>(completes)); completes.clear(); }
            trace.add(entry);
        }
        return redactIds(OracleCases.toJson(trace), ids);
    }

    @Test void brokerScenario() throws Exception { OracleCases.each(MOD, "brokerScenario", a -> brokerScenario(m(a.get(0)))); }

    // ---- the KV approval store ----

    private static Object kvScenario(Map<String, Object> s) {
        CibaKv.DurableKv kv = CibaKv.createMemoryKv();
        CibaApproval.ApprovalStore store = CibaKv.createKvApprovalStore(kv);
        List<Object> trace = new ArrayList<>();
        for (Object so : l(s.get("steps"))) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("op", op);
            try {
                Object value;
                switch (op) {
                    case "get": {
                        CibaApproval.Versioned v = store.get((String) st.get("key"));
                        Map<String, Object> o = null;
                        if (v != null) { o = new LinkedHashMap<>(); o.put("version", v.version); o.put("value", v.value); }
                        value = o;
                        break;
                    }
                    case "cas": value = store.cas((String) st.get("key"), (long) (double) IntentJs.num(st.get("expected")), st.get("value")); break;
                    case "kvSet": value = kv.putIfEquals((String) st.get("key"), kv.get((String) st.get("key")), (String) st.get("raw")); break;
                    case "kvGet": value = kv.get((String) st.get("key")); break;
                    default: throw new IllegalStateException("unknown step " + op);
                }
                entry.put("ok", true);
                entry.put("value", value);
            } catch (CibaKv.ApprovalStoreError e) {
                entry.put("ok", false);
                entry.put("code", e.code());
            } catch (RuntimeException e) {
                entry.put("ok", false);
                entry.put("code", "other");
            }
            trace.add(entry);
        }
        return trace;
    }

    @Test void kvScenario() throws Exception { OracleCases.each(MOD, "kvScenario", a -> kvScenario(m(a.get(0)))); }

    // ---- the client ----

    private static Object redactToken(Object v, String nt) {
        if (nt.isEmpty()) return v;
        if (v instanceof String) return ((String) v).replace(nt, "<NTOKEN>");
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(redactToken(x, nt)); return out; }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(v).entrySet()) out.put(e.getKey(), redactToken(e.getValue(), nt));
            return out;
        }
        return v;
    }

    private static Object clientScenario(Map<String, Object> s) {
        long[] clock = {T0};
        List<Object> reqs = new ArrayList<>();
        List<Object> sleeps = new ArrayList<>();
        List<Object> queue = new ArrayList<>(l(s.get("responses")));
        Map<String, Object> c = m(s.get("cfg"));
        CibaClient.Config cfg = new CibaClient.Config();
        cfg.backchannelAuthenticationEndpoint = (String) c.get("backchannelAuthenticationEndpoint");
        cfg.tokenEndpoint = (String) c.get("tokenEndpoint");
        cfg.clientId = (String) c.get("clientId");
        cfg.clientSecret = (String) c.get("clientSecret");
        cfg.allowInsecureHttp = Boolean.TRUE.equals(c.get("allowInsecureHttp"));
        cfg.now = () -> clock[0];
        cfg.sleep = ms -> { sleeps.add(ms); clock[0] += ms; };
        cfg.transport = (url, headers, body, timeoutMs) -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("url", url);
            r.put("method", "POST");
            r.put("headers", new LinkedHashMap<String, Object>(headers));
            r.put("body", body);
            reqs.add(r);
            if (queue.isEmpty()) throw new IOException("no scripted response");
            Map<String, Object> resp = m(queue.remove(0));
            if (Boolean.TRUE.equals(resp.get("fail"))) throw new IOException("connection reset");
            Object b = resp.get("body");
            return new CibaClient.Response((int) (double) IntentJs.num(resp.get("status")), b instanceof String ? (String) b : Json.canonicalize(b));
        };
        CibaClient.Client client = CibaClient.createCibaClient(cfg);
        CibaClient.Poller poller = null;
        List<Object> trace = new ArrayList<>();
        String nt = "";
        for (Object so : l(s.get("steps"))) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("op", op);
            try {
                Object value = null;
                switch (op) {
                    case "initiate": {
                        Map<String, Object> flow = client.initiate(m(st.get("stepUp")), st.containsKey("opts") ? m(st.get("opts")) : null);
                        poller = client.poller(flow);
                        value = flow;
                        boolean given = st.containsKey("opts") && m(st.get("opts")).containsKey("clientNotificationToken");
                        if (flow.get("clientNotificationToken") != null && !given) nt = (String) flow.get("clientNotificationToken");
                        break;
                    }
                    case "poll": value = poller.poll(); break;
                    case "wait": value = poller.await(null); break;
                    case "notify": poller.notifyPing(); break;
                    case "advance": clock[0] += (long) (double) IntentJs.num(st.get("ms")); value = clock[0]; break;
                    case "interval": value = poller.intervalSec(); break;
                    default: throw new IllegalStateException("unknown step " + op);
                }
                entry.put("ok", true);
                entry.put("value", value);
            } catch (CibaClient.CibaProviderError e) {
                entry.put("ok", false);
                entry.put("error", e.error);
                entry.put("status", e.status);
                entry.put("retryable", e.retryable);
                entry.put("errorDescription", e.errorDescription);
            } catch (RuntimeException e) {
                entry.put("ok", false);
                entry.put("other", true);
            }
            entry.put("requests", new ArrayList<>(reqs));
            reqs.clear();
            entry.put("sleeps", new ArrayList<>(sleeps));
            sleeps.clear();
            trace.add(redactToken(OracleCases.toJson(entry), nt));
        }
        return trace;
    }

    @Test void clientScenario() throws Exception { OracleCases.each(MOD, "clientScenario", a -> clientScenario(m(a.get(0)))); }

    // ---- what the oracle cannot cover: random values, files, the real transport seam ----

    @Test void newClientNotificationTokenShape() {
        String t = CibaClient.newClientNotificationToken();
        assertTrue(t.matches("[A-Za-z0-9_-]{43}"));
        assertFalse(t.equals(CibaClient.newClientNotificationToken()));
    }

    @Test void fileApprovalStoreRoundTrip(@org.junit.jupiter.api.io.TempDir Path dir) throws IOException {
        Path f = dir.resolve("approvals.json");
        CibaApproval.ApprovalStore s = CibaApproval.createFileApprovalStore(f);
        assertEquals(null, s.get("k"));
        assertTrue(s.cas("k", 0, Map.of("a", 1L)));
        assertFalse(s.cas("k", 0, "again"));
        CibaApproval.Versioned v = s.get("k");
        assertEquals(1L, v.version);
        assertTrue(s.cas("k", 1, "two"));
        assertEquals("two", CibaApproval.createFileApprovalStore(f).get("k").value); // a second store object over the same file (a restart)
        Files.writeString(f, "[1,2]");
        assertThrows(IllegalStateException.class, () -> s.get("k")); // a corrupt file fails closed
    }

    @Test void directoryKvSwap(@org.junit.jupiter.api.io.TempDir Path dir) {
        CibaKv.DurableKv kv = CibaKv.createDirectoryKv(dir, 200);
        assertEquals(null, kv.get("k"));
        assertTrue(kv.putIfEquals("k", null, "one"));
        assertFalse(kv.putIfEquals("k", null, "two"));
        assertEquals("one", kv.get("k"));
        assertTrue(kv.putIfEquals("k", "one", "three"));
        assertEquals("three", kv.get("k"));
        assertThrows(CibaKv.ApprovalStoreError.class, () -> kv.get(""));
    }

    @Test void durableBrokerOverDirectoryKv(@org.junit.jupiter.api.io.TempDir Path dir) {
        CibaApproval.ApprovalStore store = CibaKv.createKvApprovalStore(CibaKv.createDirectoryKv(dir));
        long[] clock = {T0};
        CibaApproval.DurableBrokerOptions o = new CibaApproval.DurableBrokerOptions();
        o.store = store;
        o.now = () -> clock[0];
        CibaApproval.ApprovalBroker b = CibaApproval.createDurableCibaBroker(o);
        Map<String, Object> su = new LinkedHashMap<>();
        su.put("id", "su-1");
        su.put("verb", "stripe.payout");
        su.put("resource", "acct-1");
        su.put("tier", 3L);
        su.put("goalCommit", "abcdefghijklmnopqrstuvwxyz");
        Map<String, Object> req = b.start(su, null);
        String id = (String) req.get("auth_req_id");
        assertEquals("pending", b.poll(id).get("status"));
        b.resolve(id, "approve", "alice");
        // a restarted broker over the same directory still sees the decision and redeems it once
        CibaApproval.DurableBrokerOptions o2 = new CibaApproval.DurableBrokerOptions();
        o2.store = CibaKv.createKvApprovalStore(CibaKv.createDirectoryKv(dir));
        o2.now = () -> clock[0] + 10_000;
        CibaApproval.ApprovalBroker b2 = CibaApproval.createDurableCibaBroker(o2);
        assertEquals(Boolean.TRUE, b2.token(id).get("ok"));
        assertEquals("invalid_grant", b2.token(id).get("error"));
    }
}
