package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalReview;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the review flow (card, diff, signed approval, loader) over a stub compiler kernel. */
class GoalReviewDiffTest {
    private static final String M = "ref-goal-review";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return o instanceof List ? (List<Object>) o : null; }

    private static Json.Num num(long n) { return new Json.Num(Long.toString(n)); }

    private static int intOf(Object o) { return Double.valueOf(((Json.Num) o).raw).intValue(); }

    /** The stub kernel of the oracle (see its header). */
    private static GoalReview.ReviewKernel kernel(String mode) {
        return new GoalReview.ReviewKernel() {
            public Map<String, Object> compile(Map<String, Object> goal, Map<String, Object> ont) {
                if (mode.equals("throwcompile")) throw new RuntimeException("boom");
                List<Object> grants = l(goal.get("grants"));
                Map<String, Object> r = new java.util.LinkedHashMap<>();
                if (grants.isEmpty()) { r.put("ok", false); r.put("reasons", new ArrayList<Object>(List.of("empty"))); return r; }
                List<Object> gids = new ArrayList<>();
                for (Object g : grants) gids.add(m(g).get("gid"));
                Map<String, Object> pol = new java.util.LinkedHashMap<>();
                pol.put("gids", gids); pol.put("n", num(grants.size()));
                r.put("ok", true); r.put("policy", pol);
                return r;
            }

            public String policyDigest(Map<String, Object> policy) {
                if (mode.equals("throwdigest")) throw new RuntimeException("boom");
                Map<String, Object> b = new java.util.LinkedHashMap<>();
                b.put("d", "stub-policy"); b.put("p", policy);
                return Pca.hashCanonical(b);
            }

            public List<String> analyze(Map<String, Object> policy) { return intOf(policy.get("n")) >= 5 ? List.of("too many") : List.of(); }

            public boolean canDecide() { return !mode.equals("nodecide"); }

            public String decide(Map<String, Object> goal, Map<String, Object> ont, Map<String, Object> act, Map<String, Object> hist) {
                for (Object g : l(goal.get("grants"))) if (m(g).get("verb").equals(act.get("verb"))) return "allow";
                return "deny";
            }

            public boolean canListNewlyAllowed() { return !mode.equals("nonewly"); }

            public Map<String, Object> newlyAllowed(Map<String, Object> prev, Map<String, Object> next, Map<String, Object> ont, long limit) {
                List<Object> w = new ArrayList<>();
                for (Object x : l(next.get("grants"))) {
                    boolean known = false;
                    for (Object y : l(prev.get("grants"))) if (m(y).get("gid").equals(m(x).get("gid"))) known = true;
                    if (known) continue;
                    Map<String, Object> a = new java.util.LinkedHashMap<>();
                    a.put("verb", m(x).get("verb")); a.put("res", "r"); a.put("params", new java.util.LinkedHashMap<String, Object>()); a.put("t", num(0)); a.put("sess", "s"); a.put("prin", "p");
                    a.put("org", "o"); a.put("agent", "a"); a.put("depth", num(0));
                    w.add(a);
                }
                Map<String, Object> r = new java.util.LinkedHashMap<>();
                r.put("witnesses", w); r.put("complete", true);
                return r;
            }
        };
    }

    private static Long lng(Object o) {
        if (o == null) return null;
        java.math.BigDecimal d = new java.math.BigDecimal(((Json.Num) o).raw);
        try { return d.toBigIntegerExact().longValueExact(); } catch (ArithmeticException e) { return Long.MAX_VALUE; }
    }

    @Test void effectiveLimits() throws Exception { OracleCases.each(M, "effectiveLimits", a -> GoalReview.effectiveLimits(m(a.get(0)))); }

    @Test void renderPolicyCard() throws Exception {
        OracleCases.each(M, "renderPolicyCard", a -> {
            Map<String, Object> opts = m(a.get(2));
            return GoalReview.renderPolicyCard(m(a.get(0)), l(a.get(1)), m(opts.get("limits")), Boolean.TRUE.equals(opts.get("allowHoles")));
        });
    }

    @Test void cardDigest() throws Exception { OracleCases.each(M, "cardDigest", a -> GoalReview.cardDigest(m(a.get(0)))); }
    @Test void cardToText() throws Exception { OracleCases.each(M, "cardToText", a -> GoalReview.cardToText(m(a.get(0)))); }

    @Test void diffGoals() throws Exception {
        OracleCases.each(M, "diffGoals", a -> {
            Map<String, Object> op = m(a.get(2));
            String km = (String) op.get("kmode");
            return GoalReview.diffGoals(m(a.get(0)), m(a.get(1)), km.equals("none") ? null : kernel(km), m(op.get("limits")), m(op.get("ontology")));
        });
    }

    @Test void diffToText() throws Exception { OracleCases.each(M, "diffToText", a -> GoalReview.diffToText(m(a.get(0)))); }

    @Test void approveGoalSeed() throws Exception {
        OracleCases.each(M, "approveGoalSeed", a -> {
            Map<String, Object> op = m(a.get(2));
            GoalReview.ApproveOptions o = new GoalReview.ApproveOptions();
            o.kernel = kernel((String) op.get("kmode"));
            o.now = lng(op.get("now"));
            o.ttlMs = lng(op.get("ttlMs"));
            o.limits = m(op.get("limits"));
            o.base = m(op.get("base"));
            return GoalReview.approveGoal(m(a.get(0)), Keys.unb64u((String) a.get(1)), o);
        });
    }

    @Test void loadApprovedGoal() throws Exception {
        OracleCases.each(M, "loadApprovedGoal", a -> {
            Map<String, Object> op = m(a.get(2));
            GoalReview.LoadOptions o = new GoalReview.LoadOptions();
            o.kernel = kernel((String) op.get("kmode"));
            o.reviewers = l(op.get("reviewers"));
            o.ontologyDigest = (String) op.get("ontology_digest");
            o.now = lng(op.get("now"));
            o.limits = m(op.get("limits"));
            return GoalReview.loadApprovedGoal(m(a.get(0)), m(a.get(1)), o);
        });
    }
}
