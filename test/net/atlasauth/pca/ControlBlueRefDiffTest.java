package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.controlevals.ControlEvals;
import net.atlasauth.pca.controlevals.ControlEvalsExample;
import net.atlasauth.pca.revoke.JsVal;
import org.junit.jupiter.api.Test;

/**
 * The blue control protocol against the reference corpus (ref-control-blue, 362 cases): the example agent and its review battery, the example blue protocol, the decision procedure
 * behind every episode (replay, predicates and caveats through reviewAction, data-flow governance, the immune-adapted metered budget), and the example evaluation. Numbers compare to a
 * relative 1e-12 (the leak decays exponentially).
 *
 * Counted deviation (asserted, never skipped): the reference refuses an integer past 2^53 in an action's params when the review has to hash them (5 episodes throw out of
 * canonicalize). The native refuses the same input in its canonicalization too, with its own wording; the case must throw a "canonicalize:" error.
 */
class ControlBlueRefDiffTest {
    private static final String M = "ref-control-blue";
    private static final int TOTAL = 362;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    /** The reference's three agents: example, risk (no limits) and cap50 (refund $50/day). */
    private static Facade.Handle agentOf(String name) {
        if (name.equals("example")) return ControlEvalsExample.buildExampleAgent();
        Map<String, Object> permissions = new LinkedHashMap<>();
        permissions.put("stripe", new ArrayList<Object>(List.of("refund")));
        permissions.put("gmail", new ArrayList<Object>(List.of("send", "draft")));
        permissions.put("files", new ArrayList<Object>(List.of("read", "write")));
        permissions.put("github", new ArrayList<Object>(List.of("read")));
        Facade.AgentOptions o = new Facade.AgentOptions(Keys.ed25519(Keys.edGenerate()), "handle refunds and customer email for October", permissions).aud("ins_example").now(0);
        if (name.equals("cap50")) {
            Map<String, Object> limits = new LinkedHashMap<>();
            limits.put("refund", "$50/day");
            o.limits(limits);
        }
        return Facade.agent(o);
    }

    private static ControlEvalsExample.ExampleBlue blueOf(Map<String, Object> b) {
        ControlEvalsExample.ExampleBlue blue = ControlEvalsExample.exampleBlue(agentOf((String) b.get("agent")));
        if (Boolean.FALSE.equals(b.get("dlp"))) blue.dlp = null;
        if ("agent".equals(b.get("theta"))) blue.basePolicy = null;
        if (JsVal.num(b.get("stepMs")) != null) blue.stepMs = (long) (double) JsVal.num(b.get("stepMs"));
        if (JsVal.num(b.get("startMs")) != null) blue.startMs = (long) (double) JsVal.num(b.get("startMs"));
        if (m(b.get("immune")) != null) blue.immuneConfig = m(b.get("immune"));
        if (m(b.get("adapt")) != null) blue.adaptConfig = m(b.get("adapt"));
        return blue;
    }

    private static Object review(Facade.Handle a, Map<String, Object> e) {
        Approvals.ReviewOptions ro = new Approvals.ReviewOptions();
        ro.now = (long) (double) JsVal.num(e.get("now"));
        ro.insecureUnboundApproval = true;
        Map<String, Object> r = Approvals.reviewAction(a, (String) e.get("verb"), (String) e.get("resource"), m(e.get("params")), ro);
        Map<String, Object> rv = new LinkedHashMap<>();
        rv.put("kind", r.get("kind"));
        if (r.get("reason") != null) rv.put("reason", r.get("reason"));
        Map<String, Object> out = new LinkedHashMap<>(e);
        out.put("review", rv);
        return out;
    }

    private static Object buildExampleAgent(List<?> args, Object want) {
        Facade.Handle a = ControlEvalsExample.buildExampleAgent();
        List<Object> acts = new ArrayList<>();
        for (Catalog.Spec s : a.policy.actions) {
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("connector", s.connector);
            x.put("action", s.action);
            x.put("verb", s.verb);
            x.put("reversibility", s.reversibility);
            x.put("blastRadius", s.blastRadius);
            if (s.amountField != null) x.put("amountField", s.amountField);
            if (s.resource != null) x.put("resource", s.resource);
            acts.add(x);
        }
        Map<String, Object> pol = new LinkedHashMap<>();
        pol.put("predicates", a.policy.predicates);
        pol.put("caveats", a.policy.caveats);
        pol.put("riskPolicy", a.policy.riskPolicy);
        pol.put("budgetModel", a.policy.budgetModel);
        pol.put("approximations", new ArrayList<Object>(a.policy.approximations));
        pol.put("inputLimits", a.policy.inputLimits);
        pol.put("actions", acts);
        List<Object> reviews = new ArrayList<>();
        for (Object e : l(m(want).get("reviews"))) reviews.add(review(a, m(e)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("policy", pol);
        out.put("reviews", reviews);
        return out;
    }

    private static Object blueEpisode(List<?> args) {
        Map<String, Object> spec = m(args.get(0));
        ControlEvalsExample.ExampleBlue blue = blueOf(m(spec.get("blue")));
        ControlEvals.RedPolicy red;
        if (args.size() > 1) {
            List<Map<String, Object>> list = new ArrayList<>();
            for (Object o : l(args.get(1))) list.add(m(o));
            red = new ControlEvals.RedPolicy("custom", "custom", ctx -> list);
        } else red = ControlEvalsDiffTest.red((String) spec.get("red"));
        ControlEvals.Env env = "example".equals(spec.get("env")) ? ControlEvals.exampleEnv : ControlEvals.gapAwareEnv();
        return ControlEvals.runEpisode(red, blue, env, ControlEvalsDiffTest.d(spec.get("seed")));
    }

    /** JSON value equality, numbers to a relative 1e-12. */
    @SuppressWarnings("unchecked")
    static boolean eq(Object w, Object g) {
        Double wn = JsVal.num(w);
        if (wn != null) {
            Double gn = JsVal.num(g);
            return gn != null && (wn.doubleValue() == gn.doubleValue() || Math.abs(wn - gn) <= 1e-12 * Math.max(1, Math.abs(wn)));
        }
        if (w instanceof Map) {
            if (!(g instanceof Map) || ((Map<?, ?>) w).size() != ((Map<?, ?>) g).size()) return false;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) w).entrySet()) {
                if (!((Map<String, Object>) g).containsKey(e.getKey()) || !eq(e.getValue(), ((Map<String, Object>) g).get(e.getKey()))) return false;
            }
            return true;
        }
        if (w instanceof List) {
            if (!(g instanceof List) || ((List<?>) w).size() != ((List<?>) g).size()) return false;
            for (int i = 0; i < ((List<?>) w).size(); i++) if (!eq(((List<Object>) w).get(i), ((List<Object>) g).get(i))) return false;
            return true;
        }
        return w == null ? g == null : w.equals(g);
    }

    @Test void everyCase() throws Exception {
        List<Map<String, Object>> all = BaseOracle.of(M, null);
        assertEquals(TOTAL, all.size(), "case total");
        Map<String, Integer> counts = new LinkedHashMap<>();
        List<String> bad = new ArrayList<>();
        int deviations = 0, replayed = 0;
        for (Map<String, Object> c : all) {
            String fn = (String) c.get("fn"), name = String.valueOf(c.get("name"));
            counts.merge(fn, 1, Integer::sum);
            replayed++;
            List<?> args = l(c.get("args"));
            Object want = c.get("out");
            Object got = null;
            Throwable err = null;
            try {
                switch (fn) {
                    case "buildExampleAgent": got = buildExampleAgent(args, want); break;
                    case "exampleBlue": {
                        ControlEvalsExample.ExampleBlue b = ControlEvalsExample.exampleBlue(agentOf((String) args.get(0)));
                        Map<String, Object> o = new LinkedHashMap<>();
                        o.put("name", b.name);
                        o.put("basePolicy", b.basePolicy);
                        o.put("dlp", b.dlp);
                        o.put("startMs", b.startMs);
                        o.put("stepMs", b.stepMs);
                        got = o;
                        break;
                    }
                    case "blueEpisode": got = blueEpisode(args); break;
                    case "exampleEval": {
                        Map<String, Object> spec = m(args.get(0));
                        got = ControlEvalsExample.exampleControlEval(spec.get("episodes"), spec.get("seed"), null);
                        break;
                    }
                    default: throw new IllegalStateException("no native entry point for " + fn);
                }
            } catch (Throwable t) {
                err = t;
            }
            if (m(want).containsKey("$throws")) {
                if (err != null && String.valueOf(err.getMessage()).startsWith("canonicalize:")) deviations++;
                else bad.add(name + "\n  want: " + want + "\n  got:  " + (err != null ? "throw " + err : "no throw"));
                continue;
            }
            if (err != null) { bad.add(name + "\n  want: " + Json.canonicalize(want) + "\n  got:  THROWS " + err); continue; }
            Object norm = IntentJs.normalize(OracleCases.toJson(got));
            if (!eq(want, norm)) {
                String g;
                try { g = Json.canonicalize(norm); } catch (RuntimeException e) { g = String.valueOf(norm); }
                String w = Json.canonicalize(want);
                bad.add(name + "\n  want: " + (w.length() > 1500 ? w.substring(0, 1500) + "..." : w) + "\n  got:  " + (g.length() > 1500 ? g.substring(0, 1500) + "..." : g));
            }
        }
        assertEquals(TOTAL, replayed, "every case was replayed");
        assertEquals(Map.of("buildExampleAgent", 1, "exampleBlue", 3, "blueEpisode", 352, "exampleEval", 6), counts, "every function of the corpus is replayed");
        assertEquals(5, deviations, "the five reference refusals of an integer past 2^53 are replayed as native canonicalization refusals");
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
