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
 * The full verdict of the resource-server verifier against the reference corpus (ref-verify-verdict, 1022 cases, one function): allow, the risk
 * score, the required threshold, every check with its status, the reasons (exact text, exact order), the budget and the assurance report.
 *
 * <p>Counted deviations (asserted, never skipped): the reference's strict-JSON parser words its refusal of an undecodable wire string its own way
 * (3 cases: the prefix up to the parser's text is compared); the reference's legacy {@code allowUnboundPq} option is never read here (2 cases, Ed25519
 * artifacts, which the option does not touch: the verdicts are compared in full and must be identical).
 */
class ServerVerifyRefDiffTest {
    static final String MODULE = "ref-verify-verdict";
    static final int TOTAL = 1022;
    static final String STRICT_PREFIX = "undecodable PCActn: strict JSON:";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** A constant hook of the corpus: {enforced: false} | {enforced: true, ok, reason?, t?} | {throws} | {raw}. */
    private static PcaCore.Hook hook(Object h) {
        Map<String, Object> hm = m(h);
        if (hm != null && hm.containsKey("throws")) {
            String msg = String.valueOf(hm.get("throws"));
            return ctx -> { throw new RuntimeException(msg); };
        }
        Object r = hm != null && hm.containsKey("raw") ? hm.get("raw") : h;
        if (hm != null && hm.containsKey("raw") && r == null) {
            return ctx -> { throw new RuntimeException("Cannot read properties of null (reading 'enforced')"); };
        }
        Map<String, Object> rm = m(r);
        PcaCore.HookResult res;
        if (rm == null || !Zk.truthy(rm.get("enforced"))) res = PcaCore.HookResult.notEnforced();
        else res = PcaCore.HookResult.enforced(Zk.truthy(rm.get("ok")), rm.get("reason") instanceof String ? (String) rm.get("reason") : null, IntentJs.num(rm.get("t")));
        final PcaCore.HookResult fixed = res;
        return ctx -> fixed;
    }

    private static PcaCore.Hooks hooks(Object o) {
        Map<String, Object> hm = m(o);
        if (hm == null) return null;
        PcaCore.Hooks h = new PcaCore.Hooks();
        if (hm.containsKey("attestation")) h.attestation = hook(hm.get("attestation"));
        if (hm.containsKey("threshold")) h.threshold = hook(hm.get("threshold"));
        if (hm.containsKey("revocation")) h.revocation = hook(hm.get("revocation"));
        if (hm.containsKey("zk")) h.zk = hook(hm.get("zk"));
        return h; // a `replay` entry is not a hook of the reference verifier: ignored
    }

    private static PcaCore.Enforce enforce(Object o) {
        Map<String, Object> em = m(o);
        if (em == null) return null;
        PcaCore.Enforce e = new PcaCore.Enforce();
        Map<String, Object> f = m(em.get("freshness"));
        if (f != null) {
            PcaCore.Freshness fr = new PcaCore.Freshness(IntentJs.num(f.get("maxAgeMs")));
            if (f.get("epochMs") != null) fr.epochMs = IntentJs.num(f.get("epochMs"));
            if (f.get("clockSkewMs") != null) fr.clockSkewMs = IntentJs.num(f.get("clockSkewMs"));
            if (f.get("now") != null) fr.now = (long) (double) IntentJs.num(f.get("now"));
            e.freshness = fr;
        }
        Map<String, Object> a = m(em.get("attestation"));
        if (a != null) {
            PcaCore.AttestationGate g = new PcaCore.AttestationGate(hook(a.get("verifier")));
            if (a.containsKey("required")) g.required = Zk.truthy(a.get("required"));
            e.attestation = g;
        }
        return e;
    }

    private static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }

    private static double num(Object o) {
        Double d = IntentJs.num(o);
        return d == null ? ((Number) o).doubleValue() : d;
    }

    /** null when the verdicts agree, else the first difference. */
    @SuppressWarnings("unchecked")
    private static String diff(Map<String, Object> exp, Map<String, Object> act, int[] prefixOnly) {
        if (!exp.get("allow").equals(act.get("allow"))) return "allow " + exp.get("allow") + " vs " + act.get("allow");
        double er = num(exp.get("r")), ar = num(act.get("r"));
        if (Math.abs(er - ar) > 1e-12 * Math.max(1, Math.abs(er))) return "r " + er + " vs " + ar;
        Map<String, Object> et = m(exp.get("requiredThreshold")), at = m(act.get("requiredThreshold"));
        if (num(et.get("t")) != num(at.get("t")) || !et.get("proof").equals(at.get("proof")) || !et.get("optimisticAllowed").equals(at.get("optimisticAllowed")))
            return "requiredThreshold " + canon(et) + " vs " + canon(at);
        Map<String, Object> ec = m(exp.get("checks")), ac = m(act.get("checks"));
        if (!new TreeSet<>(ec.keySet()).equals(new TreeSet<>(ac.keySet()))) return "check names " + new TreeSet<>(ec.keySet()) + " vs " + new TreeSet<>(ac.keySet());
        for (Map.Entry<String, Object> e : ec.entrySet()) if (!e.getValue().equals(ac.get(e.getKey()))) return "check " + e.getKey() + " " + e.getValue() + " vs " + ac.get(e.getKey());
        List<Object> er2 = (List<Object>) exp.get("reasons"), ar2 = (List<Object>) act.get("reasons");
        boolean prefix = er2.size() == 1 && ((String) er2.get(0)).startsWith(STRICT_PREFIX);
        if (prefix) {
            prefixOnly[0]++;
            if (!(ar2.size() == 1 && ((String) ar2.get(0)).startsWith(STRICT_PREFIX))) return "reasons " + er2 + " vs " + ar2;
        } else if (!er2.equals(ar2)) return "reasons " + er2 + " vs " + ar2;
        if (exp.containsKey("budget") != act.containsKey("budget")) return "budget presence " + exp.containsKey("budget") + " vs " + act.containsKey("budget");
        if (exp.containsKey("budget")) {
            Map<String, Object> eb = m(exp.get("budget")), ab = m(act.get("budget"));
            for (String k : new String[] {"B", "tau", "asOf"}) {
                boolean ep = eb.containsKey(k), ap = ab.containsKey(k);
                if (ep != ap || (ep && num(eb.get(k)) != num(ab.get(k)))) return "budget." + k + " " + canon(eb) + " vs " + canon(ab);
            }
        }
        if (exp.containsKey("assurance") != act.containsKey("assurance")) return "assurance presence";
        if (exp.containsKey("assurance") && !canon(exp.get("assurance")).equals(canon(act.get("assurance"))))
            return "assurance " + canon(exp.get("assurance")) + " vs " + canon(act.get("assurance"));
        if (exp.containsKey("k1Bound") != act.containsKey("k1Bound")) return "k1Bound presence";
        return null;
    }

    @Test
    @SuppressWarnings("unchecked")
    void verdictReplaysTheReference() throws Exception {
        List<Map<String, Object>> all = BaseOracle.all(MODULE);
        assertEquals(TOTAL, all.size());
        Set<Object> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add(c.get("fn"));
        assertEquals(Set.of("verifyVerdict"), fns);
        List<String> bad = new ArrayList<>();
        int[] prefixOnly = {0};
        int unbound = 0, allowed = 0;
        for (Map<String, Object> c : all) {
            List<Object> args = (List<Object>) c.get("args");
            Map<String, Object> opts = new LinkedHashMap<>(m(args.get(1)));
            Object hk = opts.remove("hooks");
            Object en = opts.remove("enforce");
            if (opts.containsKey("allowUnboundPq")) unbound++;
            Map<String, Object> exp = m(c.get("out"));
            if (Boolean.TRUE.equals(exp.get("allow"))) allowed++;
            String d;
            try {
                d = diff(exp, ServerVerify.verify(args.get(0), opts, hooks(hk), enforce(en)), prefixOnly);
            } catch (RuntimeException ex) {
                d = "threw " + ex;
            }
            if (d != null) bad.add(c.get("name") + ": " + d);
        }
        assertEquals(3, prefixOnly[0], "strict-JSON wording cases");
        assertEquals(2, unbound, "allowUnboundPq cases (option not offered)");
        assertTrue(allowed > 100, "the corpus allows a good share of its cases: " + allowed);
        assertTrue(bad.isEmpty(), bad.size() + " of " + TOTAL + " differ; first: " + bad.subList(0, Math.min(25, bad.size())));
    }

    @Test
    void defaultDenyNamesTheRequiredCheckThatIsNotPass() {
        Map<String, Object> v = new LinkedHashMap<>();
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("counter_format", "pass");
        checks.put("bond", "unsupported");
        v.put("allow", true);
        v.put("checks", checks);
        v.put("reasons", new ArrayList<String>());
        ServerVerify.enforceRequired(v, List.of("counter", "bond", "revocation", "revocation"));
        assertEquals(Boolean.FALSE, v.get("allow"));
        assertEquals("fail", checks.get("bond"));
        assertEquals("fail", checks.get("revocation"));
        assertEquals(List.of("bond: required check is unsupported (default-deny: not enforced by this resource server)",
            "revocation: required check is absent (default-deny: not enforced by this resource server)"), v.get("reasons"));
    }
}
