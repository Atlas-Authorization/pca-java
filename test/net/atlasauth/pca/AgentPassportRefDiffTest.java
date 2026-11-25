package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * The agent passport against the reference corpus (ref-passport, 516 cases): fingerprint and issue, the binding match, the registry, the trust
 * score, the evidence binding, signing under three suites, verification (time, revocation, hardware evidence) and the assurance label. A
 * corpus argument cannot carry a signed zero, so the case named svn-negzero gets -0. The 1 verification the reference accepts only through
 * its legacy unbound-PQ option is asserted REFUSED. The text after a malformed refusal is the reference's own exception text and is not compared.
 */
class AgentPassportRefDiffTest {
    static final String MODULE = "ref-passport";
    static final int TOTAL = 516;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static Attestation.HardwareVerifier hw(Object h) {
        Map<String, Object> spec = m(h);
        if (spec == null) return null;
        if (spec.containsKey("throws")) return in -> { throw new RuntimeException((String) spec.get("throws")); };
        return in -> spec.get("result");
    }

    private static Function<Map<String, Object>, Object> revocation(Object r) {
        if (r == null || "none".equals(r)) return null;
        if ("throws".equals(r)) return p -> { throw new RuntimeException("rev"); };
        Map<String, Object> spec = m(r);
        if (spec.get("revokedIds") instanceof List) return p -> ((List<?>) spec.get("revokedIds")).contains(p.get("id"));
        return p -> spec.get("revoked");
    }

    private static Object registry(List<?> x) {
        AgentPassport.Registry r = AgentPassport.buildRegistry((List<?>) arg(x, 0));
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) arg(x, 1)) {
            List<?> op = (List<?>) o;
            switch ((String) op.get(0)) {
                case "get": out.add(r.get(op.get(1))); break;
                case "has": out.add(r.has(op.get(1))); break;
                default: out.add(r.all()); break;
            }
        }
        return out;
    }

    private static Object verify(List<?> x) {
        Map<String, Object> raw = m(arg(x, 1));
        Map<String, Object> o = new LinkedHashMap<>(m(nums(raw)));
        o.remove("revocation");
        o.remove("hardware");
        return AgentPassport.verifyPassport(nums(arg(x, 0)), o, revocation(raw.get("revocation")), hw(raw.get("hardware")));
    }

    private static Object assurance(List<?> x) {
        Object label = arg(x, 1);
        Object verifier = "no-verifier".equals(label) ? null : new Object();
        if (verifier != null && m(label) != null) {
            Map<String, Object> l = m(label);
            Assurance.setLabel(verifier, new Assurance.Label((String) l.get("level"), (String) l.get("vendor"), false, null));
        }
        return AgentPassport.passportAssurance(m(arg(x, 0)), verifier);
    }

    /** A malformed refusal keeps no detail unless it is the fixed text "times". */
    private static Object trim(Object v) {
        Map<String, Object> map = m(v);
        if (map == null || !"malformed".equals(map.get("reason")) || "times".equals(map.get("detail"))) return v;
        Map<String, Object> out = new LinkedHashMap<>(map);
        out.remove("detail");
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("PASSPORT_SIG_DOMAIN", AgentPassport.PASSPORT_SIG_DOMAIN, "PASSPORT_VERSION", AgentPassport.PASSPORT_VERSION,
            "DEFAULT_PASSPORT_EVIDENCE_AGE_MS", AgentPassport.DEFAULT_PASSPORT_EVIDENCE_AGE_MS));
        f.put("passportFingerprint", x -> AgentPassport.passportFingerprint(m(nums(arg(x, 0)))));
        f.put("issuePassport", x -> AgentPassport.issuePassport(m(nums(arg(x, 0)))));
        f.put("matchesBinding", x -> AgentPassport.matchesBinding(m(nums(arg(x, 0))), m(nums(arg(x, 1)))));
        f.put("registry", AgentPassportRefDiffTest::registry);
        f.put("trustScore", x -> AgentPassport.trustScore(m(nums(arg(x, 0))), m(nums(arg(x, 1)))));
        f.put("passportEvidenceBinding", x -> AgentPassport.passportEvidenceBinding(arg(x, 0), arg(x, 1), arg(x, 2)));
        f.put("signPassport", x -> {
            Map<String, Object> o = new LinkedHashMap<>(m(nums(arg(x, 1))));
            o.put("issuerSecret", bytes(m(arg(x, 1)).get("issuerSecret")));
            o.put("suite", suite(m(arg(x, 1)).get("suite")));
            return AgentPassport.signPassport(m(nums(arg(x, 0))), o);
        });
        f.put("verifyPassport", AgentPassportRefDiffTest::verify);
        f.put("passportAssurance", AgentPassportRefDiffTest::assurance);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        int refused = 0;
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                Object want = c.get("out");
                OracleCases.Fn fn = e.getValue();
                if (e.getKey().equals("verifyPassport")) {
                    Map<String, Object> o = m(arg((List<?>) c.get("args"), 1));
                    if (o != null && Boolean.TRUE.equals(o.get("allowUnboundPq")) && Boolean.TRUE.equals(m(want).get("ok"))) {
                        refused++; // accepted by the reference only because the passport vouches for its own PQ key
                        want = Issue.obj("ok", false, "reason", "bad_signature");
                    }
                    Object w = trim(want);
                    OracleCases.Fn run = fn;
                    fn = a -> trim(run.apply(a));
                    want = w;
                }
                if (e.getKey().equals("matchesBinding") && ((String) c.get("name")).contains("svn-negzero")) {
                    fn = a -> {
                        Map<String, Object> b = new LinkedHashMap<>(m(nums(arg(a, 1))));
                        b.put("min_measurement", Issue.obj("svn", -0.0));
                        return AgentPassport.matchesBinding(m(nums(arg(a, 0))), b);
                    };
                }
                String d = OracleCases.diff(c, want, fn);
                if (d != null) bad.add(d);
            }
        }
        assertEquals(1, refused);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
