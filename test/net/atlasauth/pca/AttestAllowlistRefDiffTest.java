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
 * Allowlist manifests and their transparency anchor against the reference corpus (ref-attest-allowlist, 959 cases): verification under every
 * signature suite, the durable rollback floor, create / sign / revoke, projection and policy fields, and the anchor's operator and verifier
 * sides (including the committed anchor conformance vectors). A refusal is compared by its code; the reason text is not. A durable case whose
 * persisted state is a stored JSON null keeps it distinct from an absent key ({@link AtomicKv#JSON_NULL}).
 */
class AttestAllowlistRefDiffTest {
    static final String MODULE = "ref-attest-allowlist";
    static final int TOTAL = 959;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) o); }

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

    /** A refusal keeps its code only; an array or {results} value strips each element the same way; a per-op throw keeps no text. */
    @SuppressWarnings("unchecked")
    private static Object strip(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(strip(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (e.getKey().equals("reason") && map.containsKey("code")) continue;
            out.put(e.getKey(), e.getKey().equals("$throws") ? "" : e.getKey().equals("results") ? strip(e.getValue()) : e.getValue());
        }
        return out;
    }

    private static Pq.SuiteSecretKeys secrets(Map<String, Object> spec) {
        Pq.SuiteSecretKeys k = new Pq.SuiteSecretKeys();
        if (spec.get("edSecret") instanceof String) k.edSecret = bytes(spec.get("edSecret"));
        if (spec.get("seed") instanceof String) {
            Pq.Suite s = Pq.resolveSigAlg(spec.get("alg"), true);
            byte[] seed = bytes(spec.get("seed"));
            if (s != null && s.pq == Pq.Prim.ML_DSA_65) k.mlDsa = Pq.mlDsa65Keygen(seed);
            else if (s != null && s.pq == Pq.Prim.ML_DSA_87) k.mlDsa87 = Pq.mlDsa87Keygen(seed);
        }
        return k;
    }

    private static Object durable(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        MemoryAtomicKv kv = new MemoryAtomicKv();
        if (sc.get("initial") != null) for (Map.Entry<String, Object> e : m(sc.get("initial")).entrySet()) kv.set(e.getKey(), e.getValue() == null ? AtomicKv.JSON_NULL : e.getValue());
        List<Object> results = new ArrayList<>();
        for (Object s : (List<?>) sc.get("steps")) results.add(AttestAllowlist.verifyAllowlistDurable(nums(s), m(nums(sc.get("opts"))), kv));
        Map<String, Object> state = new LinkedHashMap<>();
        for (String k : kv.keys()) state.put(k, kv.get(k) == AtomicKv.JSON_NULL ? null : kv.get(k));
        return Issue.obj("results", results, "kv", state);
    }

    private static Object policyFields(List<?> x) {
        Map<String, Object> p = m(arg(x, 1));
        switch ((String) arg(x, 0)) {
            case "azureMaaPolicyFields": return AttestAllowlist.azureMaaPolicyFields(p);
            case "intelDcapPolicyFields": return AttestAllowlist.intelDcapPolicyFields(p);
            case "sevSnpPolicyFields": return AttestAllowlist.sevSnpPolicyFields(p);
            case "gcpCsPolicyFields": return AttestAllowlist.gcpCsPolicyFields(p);
            default: return AttestAllowlist.nvidiaCcPolicyFields(p);
        }
    }

    private static Object anchorOps(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        AttestAllowlistAnchor.Log log = AttestAllowlistAnchor.createAllowlistAnchorLog((String) sc.get("instanceId"), (String) sc.get("principal"));
        byte[] guardian = bytes(sc.get("secret"));
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) sc.get("ops")) {
            Map<String, Object> op = m(nums(o));
            try {
                AttestAllowlistAnchor.SignOptions so = new AttestAllowlistAnchor.SignOptions();
                so.guardianSecret = guardian;
                if (op.containsKey("anchor")) { so.nowMs = dbl(op.get("nowMs")); out.add(AttestAllowlistAnchor.anchorAllowlistHead(log, op.get("anchor"), so)); }
                else if (op.containsKey("refresh")) { so.nowMs = dbl(op.get("refresh")); out.add(AttestAllowlistAnchor.refreshAnchorHead(log, so)); }
                else if (op.containsKey("evidenceFor")) {
                    Map<String, Object> cached = m(op.get("cached"));
                    out.add(AttestAllowlistAnchor.evidenceFor(log, (long) dbl(op.get("evidenceFor")), cached == null ? null : (long) dbl(cached.get("size"))));
                } else if (op.containsKey("latest")) out.add(log.latest());
                else out.add(log.entries());
            } catch (RuntimeException e) {
                out.add(Issue.obj("$throws", ""));
            }
        }
        return out;
    }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("ALLOWLIST_KINDS", new ArrayList<Object>(AttestAllowlist.ALLOWLIST_KINDS), "DOMAIN", AttestAllowlist.DOMAIN));
        f.put("verifyAllowlistManifest", x -> AttestAllowlist.verifyAllowlistManifest(nums(arg(x, 0)), m(nums(arg(x, 1)))));
        f.put("createAllowlistManifest", x -> AttestAllowlist.createAllowlistManifest(nums(arg(x, 0))));
        f.put("signAllowlistManifest", x -> {
            Map<String, Object> o = m(arg(x, 1));
            Object alg = o.get("alg");
            return AttestAllowlist.signAllowlistManifest(nums(arg(x, 0)), (String) o.get("issuer"), (String) alg, secrets(m(o.get("keySpec"))));
        });
        f.put("revokeAllowlistEntry", x -> AttestAllowlist.revokeAllowlistEntry(m(nums(arg(x, 0))), m(nums(arg(x, 1))), m(nums(arg(x, 2)))));
        f.put("driverVersionSlotHex", x -> AttestAllowlist.driverVersionSlotHex((String) arg(x, 0)));
        f.put("projectAllowlist", x -> AttestAllowlist.projectAllowlist(m(arg(x, 0)), m(arg(x, 1))));
        f.put("policyFields", AttestAllowlistRefDiffTest::policyFields);
        f.put("anchorCommit", x -> AttestAllowlistAnchor.allowlistAnchorCommit(arg(x, 0)));
        f.put("anchorEntryOf", x -> AttestAllowlistAnchor.anchorEntryOf(m(arg(x, 0))));
        f.put("anchorOps", AttestAllowlistRefDiffTest::anchorOps);
        f.put("verifyAnchored", x -> {
            Map<String, Object> sc = m(arg(x, 0));
            return AttestAllowlistAnchor.verifyAllowlistAnchored(m(sc.get("verified")), sc.get("evidence"), m(nums(sc.get("opts"))));
        });
        f.put("verifyAllowlistDurable", AttestAllowlistRefDiffTest::durable);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                OracleCases.Fn fn = e.getValue();
                String d = OracleCases.diff(c, strip(c.get("out")), a -> strip(fn.apply(a)));
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
