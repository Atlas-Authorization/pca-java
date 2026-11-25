package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The safety certificate against the reference corpus (ref-safety-certificate, 262 cases): every function, every case. The two cases
 * in which the reference accepts a post-quantum certificate under its OWN key (the legacy unbound option) must be refused here, with
 * the reason a failed signature gives: this SDK verifies a PQ signature only under a key the verifier pins.
 */
class SafetyCertificateRefDiffTest {
    static final String MODULE = "ref-safety-certificate";
    static final int TOTAL = 262;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** The corpus spelling of a non-finite number, {"$num": text}, as that double (throughout a value). */
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

    private static Object n(double d) {
        if (Double.isNaN(d)) return Issue.obj("$num", "NaN");
        if (Double.isInfinite(d)) return Issue.obj("$num", d > 0 ? "Infinity" : "-Infinity");
        return d;
    }

    /** {"$bytes": base64url} (the loader has already replaced a seed label by its base64url seed). */
    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static final OracleCases.Fn VERIFY = x -> SafetyCertificate.verifySafetyCertificate(nums(arg(x, 0)), m(nums(arg(x, 1))));

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("MAX_SAFETY_CHECKS", SafetyCertificate.MAX_SAFETY_CHECKS, "SAFETY_CERT_DOMAIN", SafetyCertificate.SAFETY_CERT_DOMAIN,
            "SAFETY_CERT_SCOPE", SafetyCertificate.SAFETY_CERT_SCOPE, "SAFETY_CERT_VERSION", SafetyCertificate.SAFETY_CERT_VERSION));
        f.put("safetyCertificateBound", x -> {
            Map<String, Object> p = m(nums(arg(x, 0)));
            return n(SafetyCertificate.safetyCertificateBound(OracleCases.num(p.get("bMax")), OracleCases.num(p.get("kappa"))));
        });
        f.put("safetyCertificateStatement", x -> SafetyCertificate.safetyCertificateStatement(OracleCases.num(nums(arg(x, 0)))));
        f.put("validateSafetyChecks", x -> SafetyCertificate.validateSafetyChecks(nums(arg(x, 0))));
        f.put("safetyCertificateMessage", x -> SafetyCertificate.safetyCertificateMessage(m(nums(arg(x, 0)))));
        f.put("issueSafetyCertificate", x -> {
            Map<String, Object> a = m(nums(arg(x, 0))), opts = new LinkedHashMap<>();
            for (String k : new String[] {"grantRef", "instance", "checks", "issuedAt"}) if (a.containsKey(k)) opts.put(k, a.get(k));
            return SafetyCertificate.issueSafetyCertificate(a.get("policy"), bytes(a.get("guardianSecret")), opts, suite(a.get("suite")));
        });
        f.put("encodeSafetyCertificate", x -> SafetyCertificate.encodeSafetyCertificate(m(nums(arg(x, 0)))));
        f.put("decodeSafetyCertificate", x -> SafetyCertificate.decodeSafetyCertificate(arg(x, 0)));
        f.put("safetyCertificateForCompliance", x -> SafetyCertificate.safetyCertificateForCompliance(nums(arg(x, 0)), m(nums(arg(x, 1)))));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>(), handled = new TreeSet<>(f.keySet());
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        handled.add("verifySafetyCertificate"); // replayed below
        assertEquals(handled, fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    @Test void verifyEveryCase() throws Exception {
        List<String> bad = new ArrayList<>();
        int unbound = 0;
        for (Map<String, Object> c : OracleCases.of(MODULE, "verifySafetyCertificate")) {
            Map<String, Object> opts = m(arg((List<?>) c.get("args"), 1)), want = m(c.get("out"));
            Object expect = want;
            if (opts != null && Boolean.TRUE.equals(opts.get("allowUnboundPq")) && Boolean.TRUE.equals(want.get("ok"))) {
                unbound++; // accepted by the reference only because the certificate vouches for its own PQ key
                expect = Issue.obj("ok", false, "reason", "guardian signature does not verify", "recomputedBound", want.get("recomputedBound"));
            }
            String d = OracleCases.diff(c, expect, VERIFY);
            if (d != null) bad.add(d);
        }
        assertEquals(2, unbound);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }
}
