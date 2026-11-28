package net.atlasauth.pca.policyci;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.analyzer.Exposure;

/**
 * Authoring gates built on the analyzer, for CI: {@code diff} (does a change widen authority or raise the most that can leave?),
 * {@code test} (a policy test document against a policy, pinned by digest) and {@code coverage} (which clauses and thresholds the
 * tests or traffic never exercise, and which mutations they cannot tell apart). Each returns {@code {ok, exitCode, lines}}: the lines
 * to print and an exit code (0 ok, 1 a gate failed, 2 unusable input). None of them signs or changes anything.
 */
public final class Authoring {
    private Authoring() {}

    /** The analyzer's policy-test runner and coverage engine, which {@code test} and {@code coverage} drive. */
    public interface Backend {
        /** {@code runPolicyTests(policy, doc, {requireDigest?})}: {@code {ok, total, passed, digestMatch, failures[]}}. */
        Map<String, Object> runPolicyTests(Map<String, Object> policy, Map<String, Object> doc, Map<String, Object> options);
        /** {@code coverage(policy, actions)}: {@code {score, mutants, untested}}. */
        Map<String, Object> coverage(Map<String, Object> policy, List<Object> actions);
        /** {@code coverageGate(report, thresholds)}: {@code {ok, reasons[]}}. */
        Map<String, Object> coverageGate(Map<String, Object> report, Map<String, Object> thresholds);
    }

    /** The analyzer's test runner and coverage engine as the backend of {@code test} and {@code coverage}. */
    public static final Backend ANALYZER_BACKEND = new Backend() {
        @Override public Map<String, Object> runPolicyTests(Map<String, Object> policy, Map<String, Object> doc, Map<String, Object> options) {
            return net.atlasauth.pca.analyzer.TestRunner.runPolicyTests(policy, doc, options != null && Boolean.TRUE.equals(options.get("requireDigest")));
        }
        @Override public Map<String, Object> coverage(Map<String, Object> policy, List<Object> actions) {
            return net.atlasauth.pca.analyzer.Coverage.coverage(policy, actions, new LinkedHashMap<String, Object>());
        }
        @Override public Map<String, Object> coverageGate(Map<String, Object> report, Map<String, Object> thresholds) {
            return net.atlasauth.pca.analyzer.Coverage.coverageGate(report, thresholds);
        }
    };

    private static Map<String, Object> result(boolean ok, int exitCode, List<Object> lines) {
        return Js.obj("ok", ok, "exitCode", Js.n(exitCode), "lines", lines);
    }

    private static Map<String, Object> bad(String line) {
        List<Object> lines = new ArrayList<>();
        lines.add(line);
        return result(false, 2, lines);
    }

    /** A policy document as the analyzer reads it: any shape lint accepts, plus optional {@code vetoes} and {@code tighten} members. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toAnalyzerPolicy(Object doc) {
        Map<String, Object> n = Normalize.normalizePolicyInput(doc);
        if (!Boolean.TRUE.equals(n.get("ok"))) return n;
        Map<String, Object> np = (Map<String, Object>) n.get("policy");
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("predicates", np.get("predicates"));
        policy.put("caveats", np.get("caveats"));
        if (Js.isRecord(doc)) {
            if (Js.get(doc, "vetoes") instanceof List) policy.put("vetoes", Js.get(doc, "vetoes"));
            if (Js.get(doc, "tighten") instanceof List) policy.put("tighten", Js.get(doc, "tighten"));
        }
        return Js.obj("ok", true, "policy", policy);
    }

    private static boolean truthy(Object v) {
        if (v == null || Boolean.FALSE.equals(v)) return false;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = Js.num(v);
        return d == null || !(d == 0 || d.isNaN());
    }

    /**
     * {@code diff}: options {@code allowWiden}, {@code verb}, {@code amountField}, {@code integer}, {@code windowSecs},
     * {@code maxExposureIncrease}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> diffCommand(Object oldDoc, Object newDoc, Map<String, Object> o) {
        Map<String, Object> a = toAnalyzerPolicy(oldDoc), b = toAnalyzerPolicy(newDoc);
        if (!Boolean.TRUE.equals(a.get("ok"))) return bad("old policy: " + a.get("reason"));
        if (!Boolean.TRUE.equals(b.get("ok"))) return bad("new policy: " + b.get("reason"));
        Map<String, Object> dopts = new LinkedHashMap<>();
        if (o.get("verb") != null) {
            Map<String, Object> ex = new LinkedHashMap<>();
            ex.put("verb", o.get("verb"));
            if (truthy(o.get("amountField"))) ex.put("amountField", o.get("amountField"));
            if (truthy(o.get("integer"))) ex.put("integer", Boolean.TRUE);
            if (o.get("windowSecs") != null) ex.put("windowSecs", o.get("windowSecs"));
            dopts.put("exposure", ex);
        }
        Map<String, Object> d = Exposure.diffPolicies(a.get("policy"), b.get("policy"), dopts);
        Map<String, Object> allow = new LinkedHashMap<>();
        allow.put("widen", Boolean.TRUE.equals(o.get("allowWiden")));
        if (o.get("maxExposureIncrease") != null) allow.put("maxExposureIncrease", o.get("maxExposureIncrease"));
        Map<String, Object> gate = Exposure.diffGate(d, allow);
        boolean gateOk = Boolean.TRUE.equals(gate.get("ok"));
        List<Object> lines = new ArrayList<>();
        List<Object> summary = (List<Object>) d.get("summary");
        if (Boolean.TRUE.equals(d.get("equivalent"))) lines.add("no change in what is admitted");
        else if (!summary.isEmpty()) lines.addAll(summary);
        else lines.add("no witness found");
        if (!gateOk) for (Object r : (List<Object>) gate.get("reasons")) lines.add("FAIL: " + Js.str(r));
        lines.add(gateOk ? "PASS" : "FAIL");
        return result(gateOk, gateOk ? 0 : 1, lines);
    }

    /** {@code test}: a policy test document run against a policy; option {@code requireDigest}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> testCommand(Object policyDoc, Object testsDoc, Map<String, Object> o, Backend backend) {
        Map<String, Object> p = toAnalyzerPolicy(policyDoc);
        if (!Boolean.TRUE.equals(p.get("ok"))) return bad("policy: " + p.get("reason"));
        if (!Js.isRecord(testsDoc) || !"pca-policy-tests".equals(Js.get(testsDoc, "kind")) || !(Js.get(testsDoc, "cases") instanceof List)) return bad("tests: not a pca-policy-tests document");
        if (backend == null) return bad("tests: the analyzer's policy test runner is not available");
        Map<String, Object> opts = new LinkedHashMap<>();
        if (o.get("requireDigest") != null) opts.put("requireDigest", o.get("requireDigest"));
        Map<String, Object> r = backend.runPolicyTests((Map<String, Object>) p.get("policy"), (Map<String, Object>) testsDoc, opts);
        List<Object> lines = new ArrayList<>();
        for (Object fo : (List<Object>) r.get("failures")) {
            Map<String, Object> f = (Map<String, Object>) fo;
            Object by = f.get("expectedDecidedBy");
            Object got = f.get("decidedBy");
            lines.add("FAIL " + Js.str(f.get("name"), f.containsKey("name")) + ": expected " + Js.str(f.get("expected"), f.containsKey("expected")) + (truthy(by) ? " by " + Js.str(by) : "")
                + ", got " + Js.str(f.get("got"), f.containsKey("got")) + " by " + (got != null ? Js.str(got) : "no clause"));
        }
        if (!Boolean.TRUE.equals(r.get("digestMatch"))) lines.add((truthy(o.get("requireDigest")) ? "FAIL" : "note") + ": the policy differs from the one the examples were confirmed against");
        boolean ok = Boolean.TRUE.equals(r.get("ok"));
        lines.add(Js.str(r.get("passed")) + "/" + Js.str(r.get("total")) + " examples " + (ok ? "PASS" : "FAIL"));
        return result(ok, ok ? 0 : 1, lines);
    }

    /** {@code coverage}: options {@code minClauses}, {@code minBoundaries}, {@code minMutation}, {@code maxSurvivors}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> coverageCommand(Object policyDoc, Object trafficDoc, Map<String, Object> o, Backend backend) {
        Map<String, Object> p = toAnalyzerPolicy(policyDoc);
        if (!Boolean.TRUE.equals(p.get("ok"))) return bad("policy: " + p.get("reason"));
        // traffic: an array of actions, or a pca-policy-tests document (its cases are the traffic)
        List<Object> actions = null;
        if (trafficDoc instanceof List) actions = (List<Object>) trafficDoc;
        else if (Js.isRecord(trafficDoc) && Js.get(trafficDoc, "cases") instanceof List) {
            actions = new ArrayList<>();
            for (Object c : (List<Object>) Js.get(trafficDoc, "cases")) actions.add(Js.isRecord(c) ? Js.get(c, "action") : c);
        }
        boolean badTraffic = actions == null;
        if (!badTraffic) for (Object a : actions) if (!Js.isRecord(a) || !(Js.get(a, "verb") instanceof String) || !(Js.get(a, "resource") instanceof String)) { badTraffic = true; break; }
        if (badTraffic) return bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document");
        if (backend == null) return bad("traffic: the analyzer's coverage engine is not available");
        Map<String, Object> r = backend.coverage((Map<String, Object>) p.get("policy"), actions);
        Map<String, Object> th = new LinkedHashMap<>();
        if (o.get("minClauses") != null) th.put("clauses", o.get("minClauses"));
        if (o.get("minBoundaries") != null) th.put("boundaries", o.get("minBoundaries"));
        if (o.get("minMutation") != null) th.put("mutation", o.get("minMutation"));
        if (o.get("maxSurvivors") != null) th.put("maxSurvivors", o.get("maxSurvivors"));
        Map<String, Object> gate = backend.coverageGate(r, th);
        Map<String, Object> score = (Map<String, Object>) r.get("score"), mutants = (Map<String, Object>) r.get("mutants");
        List<Object> lines = new ArrayList<>();
        double total = Js.num(mutants.get("total")), equivalent = Js.num(mutants.get("equivalent"));
        lines.add("clauses decisive " + pct(score.get("clauses")) + "%, boundaries covered " + pct(score.get("boundaries")) + "%, mutants killed " + pct(score.get("mutation")) + "% ("
            + Js.str(mutants.get("killed")) + "/" + Js.numStr(total - equivalent) + ")");
        for (Object id : (List<Object>) r.get("untested")) lines.add("untested: " + Js.str(id));
        for (Object mo : (List<Object>) mutants.get("survivors")) {
            Map<String, Object> m = (Map<String, Object>) mo;
            Object killer = m.get("killer");
            lines.add("survives: " + Js.str(m.get("description"), m.containsKey("description")) + (truthy(killer) ? " (kill with " + Js.stringify(killer) + ")" : ""));
        }
        for (Object x : (List<Object>) gate.get("reasons")) lines.add("FAIL: " + Js.str(x));
        boolean ok = Boolean.TRUE.equals(gate.get("ok"));
        lines.add(ok ? "PASS" : "FAIL");
        return result(ok, ok ? 0 : 1, lines);
    }

    /** {@code (x * 100).toFixed(0)}: the exact binary value rounded half up. */
    private static String pct(Object x) {
        double v = Js.num(x) * 100;
        if (Double.isNaN(v) || Double.isInfinite(v)) return Js.numStr(v);
        return new BigDecimal(v).setScale(0, RoundingMode.HALF_UP).toPlainString();
    }
}
