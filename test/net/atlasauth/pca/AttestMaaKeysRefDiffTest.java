package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Azure MAA token-signing key trust against the reference corpus (ref-attest-maa, 261 cases): the guarded certs fetch, JWKS evaluation (real
 * Microsoft-chained and self-signed instance certificates plus forged ones), the rotation-safe trust store with signed re-pin, the durable store
 * adapter, multi-vantage corroboration, and the release-signed built-in pins. A rejection whose reference reason is library text is compared by
 * presence only.
 */
class AttestMaaKeysRefDiffTest {
    static final String MODULE = "ref-attest-maa";
    static final int TOTAL = 261;

    private static Map<String, Object> m(Object o) { return AttestRootsKit.m(o); }

    private static Object arg(List<?> a, int i) { return AttestRootsKit.arg(a, i); }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    /** The scripted transport: steps[min(i, last)] is the answer of the i-th request; every request URL is logged as the reference does. */
    private static AttestMaaKeys.Fetch scripted(List<?> steps, List<Object> log) {
        int[] i = {0};
        return url -> {
            log.add(url + " [redirect:error]");
            Map<String, Object> s = m(steps.get(Math.min(i[0]++, steps.size() - 1)));
            if (s != null && s.containsKey("keys") && !s.containsKey("body")) s = Issue.obj("body", s);
            if (s.containsKey("$throws")) throw new RuntimeException((String) s.get("$throws"));
            byte[] body;
            if (s.get("bodyBytes") != null) body = AttestRootsKit.unb((String) m(s.get("bodyBytes")).get("$bytes"));
            else if (m(s.get("body")) != null && m(s.get("body")).get("$text") instanceof String) body = ((String) m(s.get("body")).get("$text")).getBytes(StandardCharsets.UTF_8);
            else body = Json.canonicalize(s.get("body")).getBytes(StandardCharsets.UTF_8);
            return new AttestMaaKeys.Response(s.get("status") == null ? 200 : (int) dbl(s.get("status")), (String) s.get("url"),
                s.get("contentLength") == null ? null : dbl(s.get("contentLength")), body);
        };
    }

    private static Object fetchCerts(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        List<Object> log = new ArrayList<>();
        Map<String, Object> opts = m(sc.get("opts"));
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Map<String, Object> jwks = AttestMaaKeys.fetchMaaCerts((String) sc.get("issuer"), scripted(java.util.Collections.singletonList(sc.get("response")), log),
                opts == null || opts.get("timeoutMs") == null ? null : dbl(opts.get("timeoutMs")), opts == null || opts.get("maxBytes") == null ? null : dbl(opts.get("maxBytes")));
            out.put("ok", true);
            out.put("jwks", jwks);
        } catch (RuntimeException e) {
            out.put("ok", false);
            out.put("error", e.getMessage());
        }
        out.put("requests", log);
        return out;
    }

    private static Object trust(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        AttestMaaKeys.MemoryStateStore store = AttestMaaKeys.createMemoryMaaKeyStateStore();
        if (m(sc.get("initial")) != null) for (Map.Entry<String, Object> e : m(sc.get("initial")).entrySet()) store.set(e.getKey(), e.getValue());
        List<Object> log = new ArrayList<>(), results = new ArrayList<>();
        try {
            AttestMaaKeys.Trust t = AttestMaaKeys.createMaaKeyTrust(m(sc.get("policy")), store, scripted((List<?>) sc.get("fetches"), log));
            for (Object co : (List<?>) sc.get("calls")) {
                Map<String, Object> c = m(co);
                results.add(t.getTrustAnchors((String) c.get("issuer"), c.get("nowMs"), m(c.get("repin"))));
            }
        } catch (RuntimeException e) {
            return Issue.obj("$throws", String.valueOf(e.getMessage()));
        }
        return Issue.obj("results", results, "store", store.snapshot(), "fetches", log);
    }

    private static Object kvStore(List<?> x) {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        AttestMaaKeys.StateStore st = AttestMaaKeys.durableMaaKeyStateStore(kv);
        List<Object> out = new ArrayList<>();
        for (Object so : (List<?>) m(arg(x, 0)).get("steps")) {
            Map<String, Object> s = m(so);
            if (s.containsKey("set")) {
                List<?> a = (List<?>) s.get("set");
                st.set((String) a.get(0), a.get(1));
                out.add(null);
            } else out.add(st.get((String) s.get("get")));
        }
        Map<String, Object> snap = new LinkedHashMap<>();
        for (String k : kv.keys()) snap.put(k, kv.get(k));
        return Issue.obj("results", out, "kv", snap);
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("BUILTIN_CHAIN_LEAF_CN", new ArrayList<Object>(AttestMaaPins.BUILTIN_CHAIN_LEAF_CN),
            "BUILTIN_MAA_PINS_ISSUER_ID", AttestMaaPins.BUILTIN_MAA_PINS_ISSUER_ID, "BUILTIN_MAA_PINS_ISSUER_KEYS", AttestMaaPins.builtinIssuerKeys()));
        f.put("evaluateMaaJwks", x -> AttestMaaKeys.evaluateMaaJwks(arg(x, 0), (String) arg(x, 1), m(arg(x, 2)), dbl(arg(x, 3))));
        f.put("loadBuiltinMaaPins", x -> AttestMaaPins.loadBuiltinMaaPins(m(arg(x, 0))));
        f.put("corroborate", x -> AttestMaaKeys.corroborateMaaKeySets(arg(x, 0), arg(x, 1), m(arg(x, 2))));
        f.put("fetchCerts", AttestMaaKeysRefDiffTest::fetchCerts);
        f.put("trust", AttestMaaKeysRefDiffTest::trust);
        f.put("kvStore", AttestMaaKeysRefDiffTest::kvStore);
        f.put("buildTrust", x -> {
            Map<String, Object> c = m(arg(x, 0));
            AttestMaaKeys.createMaaKeyTrust(m(c.get("policy")), AttestMaaKeys.createMemoryMaaKeyStateStore(), Boolean.TRUE.equals(c.get("noFetch")) ? null : url -> new AttestMaaKeys.Response(200, null, null, new byte[] {'{', '}'}));
            return Issue.obj("built", true);
        });
        AttestRootsKit.replay(MODULE, TOTAL, f, null);
    }
}
