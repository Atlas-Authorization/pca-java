package net.atlasauth.pca.analyzer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs;
import net.atlasauth.pca.analyzer.Enumerate.Probes;

/**
 * POLICY-AS-CODE TEST RUNNER. A policy test document lists actions with the decision the author expects (and optionally the clause expected
 * to decide). It names the policy it was written for by digest and may be signed, so a recompile that drifts must still reproduce every
 * confirmed example or the run fails. {@link #generateBoundaryTests} writes the examples a reviewer would otherwise have to think of: one
 * minimal allow per permit clause, one trigger per prohibition, and for every numeric threshold the points just below, at and just above it.
 * Expectations in a generated document are the policy's CURRENT behaviour, to be read and confirmed by a person.
 */
public final class TestRunner {
    private TestRunner() {}

    public static final String POLICY_TESTS_KIND = "pca-policy-tests";
    public static final String POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\0";

    /** {v: 1, kind, policy_digest, cases}: the document for {@code policy} over {@code cases} ({name, action, expect, decidedBy?}). */
    public static Map<String, Object> policyTestsDoc(Object policy, List<Object> cases) {
        return Js.obj("v", Js.n(1), "kind", POLICY_TESTS_KIND, "policy_digest", Residual.policyDigestOf(Enumerate.toModel(policy)), "cases", cases);
    }

    /** Run a document against a policy: {total, passed, failures, digestMatch, ok}. With {@code requireDigest} a changed policy fails even if every case passes. */
    public static Map<String, Object> runPolicyTests(Object policy, Map<String, Object> doc, boolean requireDigest) {
        PolicyModel model = Enumerate.toModel(policy);
        List<Object> cases = Js.list(Js.get(Js.req(doc), "cases"));
        List<Object> failures = new ArrayList<>();
        for (Object c : cases) {
            Map<String, Object> w = Coverage.witnessOf(model, Js.map(Js.get(c, "action")));
            Object decidedBy = Js.get(Js.get(w, "winner"), "id");
            if (!Js.strictEq(w.get("decision"), Js.get(c, "expect")) || (Js.has(c, "decidedBy") && !Js.strictEq(Js.get(c, "decidedBy"), decidedBy))) {
                Map<String, Object> f = Js.obj();
                Js.putIf(f, "name", c, "name");
                Js.putIf(f, "expected", c, "expect");
                f.put("got", w.get("decision"));
                f.put("decidedBy", decidedBy);
                if (Js.has(c, "decidedBy")) f.put("expectedDecidedBy", Js.get(c, "decidedBy"));
                failures.add(f);
            }
        }
        boolean digestMatch = Residual.policyDigestOf(model).equals(Js.get(doc, "policy_digest"));
        return Js.obj("total", Js.n(cases.size()), "passed", Js.n(cases.size() - failures.size()), "failures", failures, "digestMatch", digestMatch,
            "ok", failures.isEmpty() && (!requireDigest || digestMatch));
    }

    private static byte[] message(Object doc) {
        byte[] pre = POLICY_TESTS_SIG_DOMAIN.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(Pca.hashCanonical(doc).getBytes(StandardCharsets.UTF_8));
            byte[] m = new byte[pre.length + d.length];
            System.arraycopy(pre, 0, m, 0, pre.length);
            System.arraycopy(d, 0, m, pre.length, d.length);
            return m;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The principal signs the confirmed examples: {doc, signer, sig}. */
    public static Map<String, Object> signPolicyTests(Map<String, Object> doc, Keys.EdKey secret, String signerPublic) {
        return Js.obj("doc", doc, "signer", signerPublic, "sig", Keys.b64u(secret.sign(message(doc))));
    }

    /** Is the signed document signed by {@code expectedSigner}? Never throws. */
    public static boolean verifyPolicyTests(Object s, String expectedSigner) {
        try {
            Object doc = Js.get(s, "doc");
            if (!expectedSigner.equals(Js.get(s, "signer")) || !POLICY_TESTS_KIND.equals(Js.get(doc, "kind"))) return false;
            Object sig = Js.get(s, "sig");
            if (!(sig instanceof String)) return false;
            byte[] pk = Pca.decodeB64uStrict(Js.get(s, "signer"), 32), sg = Pca.decodeB64uStrict(sig, 64);
            return pk != null && sg != null && EdStrict.verify(pk, message(doc), sg);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static List<String> paramPaths(Object p) {
        Set<String> out = new LinkedHashSet<>();
        Object w = Js.get(p, "where");
        if (w instanceof List) for (Object c : (List<?>) w) walk(c, out);
        return new ArrayList<>(out);
    }

    private static void walk(Object c, Set<String> out) {
        if (!(c instanceof Map || c instanceof List)) return;
        Object f = Js.get(c, "field");
        if (f instanceof String && ((String) f).startsWith("action.params.")) out.add((String) f);
        for (String k : new String[] {"all_of", "any_of"}) if (Js.get(c, k) instanceof List) for (Object x : (List<?>) Js.get(c, k)) walk(x, out);
        if (Js.truthy(Js.get(c, "not"))) walk(Js.get(c, "not"), out);
    }

    /** Boundary examples for every clause and numeric threshold of the policy; expectations are the current behaviour. Options: epsilon (default 1). */
    public static Map<String, Object> generateBoundaryTests(Object policy, Map<String, Object> o) {
        double eps = Js.get(o, "epsilon") == null ? 1 : Js.toNum(Js.get(o, "epsilon"));
        PolicyModel model = Enumerate.toModel(policy);
        List<Object> cases = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        java.util.function.BiConsumer<String, Map<String, Object>> add = (name, action) -> {
            String key = Js.stringify(action);
            if (!seen.add(key)) return;
            Map<String, Object> w = Coverage.witnessOf(model, action);
            Map<String, Object> c = Js.obj("name", name, "action", action, "expect", w.get("decision"));
            Object id = Js.get(w.get("winner"), "id");
            if (id != null) c.put("decidedBy", id);
            cases.add(c);
        };
        for (int i = 0; i < model.predicates.size(); i++) {
            Object p = model.predicates.get(i);
            Map<String, Object> r = Analyzer.alwaysDenies(Js.obj("predicates", Js.arr(p), "caveats", model.caveats, "vetoes", model.vetoes, "tighten", model.tighten));
            Object base0 = r.get("witness");
            if (base0 == null) base0 = Analyzer.alwaysDenies(Js.obj("predicates", Js.arr(p), "caveats", model.caveats)).get("witness");
            if (base0 == null) continue;
            Map<String, Object> base = Js.map(base0);
            String pid = Coverage.permitId(i);
            add.accept(pid + ": minimal admitted action", base);
            for (String path : paramPaths(p)) {
                String name = path.substring("action.params.".length());
                for (double t : Exposure.thresholds(Enumerate.toModel(Js.obj("predicates", Js.arr(p))), path)) {
                    String[] tags = {"below", "at", "above"};
                    double[] vs = {t - eps, t, t + eps};
                    for (int k = 0; k < 3; k++) {
                        Map<String, Object> params = Js.copy(base.get("params"));
                        params.put(name, Js.n(vs[k]));
                        Map<String, Object> a = Js.copy(base);
                        a.put("params", params);
                        add.accept(pid + ": " + name + " " + tags[k] + " " + Js.fmt(t), a);
                    }
                }
            }
            Map<String, Object> other = Js.copy(base);
            other.put("resource", base.get("resource") + "/__other__");
            add.accept(pid + ": unmentioned resource", other);
        }
        // a trigger per prohibition: an action some permit would allow and this prohibition stops (so the prohibition is what is tested)
        PolicyModel permitOnly = model.copy();
        permitOnly.vetoes = new ArrayList<>();
        permitOnly.tighten = new ArrayList<>();
        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes pr = Enumerate.collectProbes(in);
        for (Object v : model.vetoes) {
            Enumerate.Collected hit = Enumerate.collect(pr, rep -> !Enumerate.decide(permitOnly, rep).equals("deny") && Enumerate.vetoApplies(v, Enumerate.contextOfAction(Enumerate.repToAction(rep))), Enumerate.DEFAULT_MAX_COMBINATIONS, 1);
            if (!hit.hits.isEmpty()) add.accept(CaveatAnalysis.jsString(Js.get(v, "id"), Js.has(v, "id")) + ": trigger", Enumerate.repToAction(hit.hits.get(0)));
        }
        return policyTestsDoc(policy, cases);
    }

    /** The decision of every case under {@code policy} (for a table in a PR comment). */
    public static List<Object> decideAll(Object policy, Map<String, Object> doc) {
        PolicyModel model = Enumerate.toModel(policy);
        List<Object> out = new ArrayList<>();
        for (Object c : Js.list(Js.get(Js.req(doc), "cases"))) out.add(Enumerate.decideAction(model, Js.get(c, "action")));
        return out;
    }
}
