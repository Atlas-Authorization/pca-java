package net.atlasauth.pca.invariants;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.ForbidWins;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.InvariantsBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.W3Bridge;

/**
 * The PCA core safety invariants as seeded property checks, with no property-testing library: each {@code *Property} runs ONE
 * generated case from a {@link Rng} and returns {@code true} when the invariant holds (any violation is {@code false}); {@link #run}
 * repeats it {@code numRuns} times from a fixed seed and fails with the failing run index. Every property feeds the REAL core
 * (nothing is re-implemented): chain verification, predicate and caveat evaluation, the risk functional and admission, forbid-wins.
 */
public final class InvariantProperties {
    private InvariantProperties() {}

    private static final double EPS = 1e-9;

    @SuppressWarnings("unchecked") private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked") private static List<Object> list(Object o) { return (List<Object>) o; }

    private static double d(Object o) { return ((Number) o).doubleValue(); }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static boolean chainOk(List<Object> caps, String rootIssuer) { return Pca.verifyChain(caps, rootIssuer, true, null).isEmpty(); }

    private static double riskOf(Map<String, Object> in, Map<String, Object> weights) {
        return W3Bridge.riskScore(new double[] {d(in.get("semanticDistance")), d(in.get("reversibility")), d(in.get("blastRadius")),
            d(in.get("taint")), d(in.get("confidence")), d(in.get("age"))}, weights);
    }

    // ============================ 1. ATTENUATION MONOTONICITY ===============================

    /** Effective authority of a hop for a probe point: envelope predicates AND every caveat satisfied. */
    private static boolean authAllowed(Object caveats, Object predicates, Map<String, Object> pt) {
        if (!Predicates.evaluatePredicates(predicates, map(pt.get("action")))) return false;
        return Caveats.evaluateCaveats(caveats, pt.get("cavCtx")).ok;
    }

    private static boolean prefixExtension(Map<String, Object> parent, Map<String, Object> child) {
        List<Object> pc = list(parent.get("caveats")), cc = list(child.get("caveats"));
        if (cc.size() < pc.size()) return false;
        for (int j = 0; j < pc.size(); j++) if (!Pca.hashCanonical(cc.get(j)).equals(Pca.hashCanonical(pc.get(j)))) return false;
        return true;
    }

    /**
     * For any legal chain: (a) it verifies; (b) each hop's caveats are an append-only extension of its parent's; (c) budget_alloc limits
     * are monotone non-increasing; (d) at every probe point the per-hop allowed verdict is monotone non-increasing root to leaf.
     */
    public static boolean attenuationMonotonicityProperty(Rng r) {
        Map<String, Object> chain = Arbitraries.chain(r);
        List<Object> points = new ArrayList<>();
        for (long i = r.integer(1, 5); i > 0; i--) points.add(Arbitraries.evalPoint(r));
        List<Object> caps = list(chain.get("caps"));
        if (!chainOk(caps, (String) chain.get("rootIssuer"))) return false;
        for (int i = 1; i < caps.size(); i++) if (!prefixExtension(map(caps.get(i - 1)), map(caps.get(i)))) return false;
        Map<String, Object> leaf = map(caps.get(caps.size() - 1));
        if (InvariantsBridge.allocationsError(list(leaf.get("caveats"))) != null) return false;
        double prev = Double.NaN;
        for (Object cv : list(leaf.get("caveats"))) {
            Map<String, Object> c = map(cv);
            if (!"budget_alloc".equals(c.get("type")) || !(c.get("limit") instanceof Number || c.get("limit") instanceof Json.Num)) continue;
            double cur = c.get("limit") instanceof Json.Num ? Double.parseDouble(((Json.Num) c.get("limit")).raw) : d(c.get("limit"));
            if (!Double.isNaN(prev) && cur > prev) return false;
            prev = cur;
        }
        for (Object pt : points) {
            boolean ancestorAllowed = true;
            for (Object cap : caps) {
                boolean allowed = authAllowed(map(cap).get("caveats"), chain.get("predicates"), map(pt));
                if (allowed && !ancestorAllowed) return false; // a true after a false would be a widening
                ancestorAllowed = allowed;
            }
        }
        return true;
    }

    // ================================ 2. BUDGET SOUNDNESS ===================================

    /** r is clamped to [0, 1] and monotone: a pointwise-worse input never yields a lower r. */
    public static boolean riskMonotoneProperty(Rng r) {
        Map<String, Object> policy = Arbitraries.riskPolicy(r), inputs = Arbitraries.riskInputs(r), deltas = Arbitraries.riskDeltas(r);
        double risk = riskOf(inputs, map(policy.get("weights")));
        if (!(risk >= 0 && risk <= 1)) return false;
        double worse = riskOf(Invariants.worsen(inputs, deltas), map(policy.get("weights")));
        if (!(worse >= 0 && worse <= 1)) return false;
        return worse + EPS >= risk;
    }

    /** Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget; safetyBound is bMax/kappa. */
    public static boolean admissionSoundnessProperty(Rng r) {
        Map<String, Object> policy = Arbitraries.riskPolicy(r), inputs = Arbitraries.riskInputs(r), budget = Arbitraries.trustBudget(r);
        if (InvariantsBridge.validateRiskPolicy(policy) != null) return false;
        double risk = riskOf(inputs, map(policy.get("weights")));
        double c = W3Bridge.cost(risk, d(policy.get("kappa")));
        Map<String, Object> adm = InvariantsBridge.admit(risk, d(budget.get("B")), d(policy.get("theta1")), d(policy.get("theta2")), d(policy.get("kappa")));
        boolean admit = (Boolean) adm.get("admit"), metered = (Boolean) adm.get("metered");
        long t = (Long) adm.get("t");
        if (metered) {
            if (t >= 3) return false;
            if (!(d(budget.get("B")) + EPS >= c)) return false;
        }
        if (admit) {
            if (t != 1 || !metered) return false;
            if (!(d(budget.get("B")) + EPS >= c)) return false;
        }
        return true;
    }

    private static double safetyBound(Map<String, Object> policy) {
        double kappa = d(policy.get("kappa"));
        return kappa > 0 ? Math.max(0, d(policy.get("bMax"))) / kappa : 0;
    }

    /** Starting from a full budget, machine-only actions debit kappa*r each: B never goes negative and Sum(r) <= bMax/kappa. */
    public static boolean cumulativeBudgetBoundProperty(Rng r) {
        Map<String, Object> policy = Arbitraries.riskPolicy(r);
        List<Map<String, Object>> seq = new ArrayList<>();
        for (long i = r.integer(1, 40); i > 0; i--) seq.add(Arbitraries.riskInputs(r));
        double bound = safetyBound(policy), kappa = d(policy.get("kappa")), bMax = d(policy.get("bMax"));
        double budget = Math.max(0, bMax), sumR = 0;
        for (Map<String, Object> inputs : seq) {
            double risk = riskOf(inputs, map(policy.get("weights")));
            Map<String, Object> adm = InvariantsBridge.admit(risk, budget, d(policy.get("theta1")), d(policy.get("theta2")), kappa);
            if ((Boolean) adm.get("metered") && (Long) adm.get("t") < 3) {
                double c = W3Bridge.cost(risk, kappa);
                if (!(budget + EPS >= c)) return false;
                budget = Math.max(0, budget - c);
                sumR += risk;
                if (budget < -EPS) return false;
                if (!(kappa * sumR <= bMax + 1e-6)) return false;
                if (!(sumR <= bound + 1e-6)) return false;
            }
        }
        return true;
    }

    // ================================== 3. FAIL-CLOSED ======================================

    private static final Set<String> KNOWN_CAVEAT_TYPES = Set.of(
        "expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth", "budget_alloc", "max_spend", "intent_session");

    /** Every structurally undecidable (but well-typed) leaf evaluates to unknown, never true, so a predicate carrying it never grants. */
    public static boolean undecidableLeafFailsClosedProperty(Rng r) {
        int pick = (int) r.integer(0, 4);
        String verb = r.pick("read", "write", "delete");
        String f = "subject.role";
        Map<String, Object> leaf;
        switch (pick) {
            case 0: leaf = obj("field", f + ".definitely_absent", "op", "eq", "value", "x"); break; // missing field
            case 1: leaf = obj("field", f, "op", "lt", "value", 5L); break; // string field vs number: incomparable
            case 2: leaf = obj("field", f, "op", "in", "value", "not-an-array"); break; // non-array operand
            case 3: leaf = obj("field", f, "op", "eq"); break; // no value and no ref
            default: leaf = obj("field", f, "op", "member_of", "value", "g", "collection", "env.no_such_collection"); // missing collection
        }
        Map<String, Object> ctx = obj("action", obj("verb", verb, "resource", "/x"), "subject", obj("role", "admin"));
        if (Predicates.evaluateConditionTri(leaf, ctx) == Predicates.Tri.TRUE) return false;
        if (Predicates.evaluateCondition(leaf, ctx)) return false;
        List<Object> preds = new ArrayList<>();
        preds.add(obj("verb", verb, "resource", "/x", "where", new ArrayList<>(List.of(leaf))));
        return !Predicates.evaluatePredicates(preds, ctx);
    }

    /** A not / all_of / any_of built over undecidable or empty children fails closed (never true). */
    public static boolean undecidableGroupsFailClosedProperty(Rng r) {
        Map<String, Object> ctx = obj("action", obj("verb", "read", "resource", "/x"), "subject", obj("role", "admin"));
        Map<String, Object> child = obj("field", "subject.role", "op", "lt", "value", 5L);
        List<Object> none = new ArrayList<>();
        List<Object> one = new ArrayList<>(List.of(child));
        for (Map<String, Object> g : List.of(obj("not", child), obj("all_of", none), obj("any_of", none), obj("all_of", one), obj("any_of", one)))
            if (Predicates.evaluateConditionTri(g, ctx) == Predicates.Tri.TRUE) return false;
        return true;
    }

    /** member_of over a cyclic adjacency terminates with the correct verdict: reachable targets true, an unreachable one false. */
    public static boolean memberOfCycleSafeProperty(Rng r) {
        String target = r.pick("a", "b", "c", "z");
        Map<String, Object> rel = obj("a", new ArrayList<>(List.of("b")), "b", new ArrayList<>(List.of("a", "c")));
        Map<String, Object> ctx = obj("action", obj("verb", "read", "resource", "/x"), "subject", obj("g", "a"), "env", obj("rel", rel));
        Predicates.Tri tri = Predicates.evaluateConditionTri(obj("field", "subject.g", "op", "member_of", "value", target, "collection", "env.rel"), ctx);
        Predicates.Tri expected = Set.of("a", "b", "c").contains(target) ? Predicates.Tri.TRUE : Predicates.Tri.FALSE;
        return tri == expected;
    }

    /** An unknown caveat TYPE is never satisfied, so a caveat set containing it is never ok. */
    public static boolean unknownCaveatTypeDeniesProperty(Rng r) {
        String type;
        do { type = r.string(1, 12); } while (KNOWN_CAVEAT_TYPES.contains(type));
        long now = r.integer(0, 10_000_000);
        Map<String, Object> cav = obj("type", type), ctx = obj("now", now);
        if (Caveats.satisfied(cav, ctx)) return false;
        return !Caveats.evaluateCaveats(new ArrayList<>(List.of(cav)), ctx).ok;
    }

    private static final List<String> ALL_MUTATIONS = List.of(
        "tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch", "break-id", "append-forged-hop");

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    private static List<Object> cloneCaps(List<Object> caps) { return list(deepCopy(caps)); }

    /** Every forged chain (nine distinct attacks on a legal one) fails verification. */
    public static boolean forgedChainRejectedProperty(Rng r) {
        Map<String, Object> chain = Arbitraries.chain(r);
        String mutation = r.pick(ALL_MUTATIONS);
        long pick = r.integer(0, 1_000_000);
        Invariants.GenKeyPair aux = Arbitraries.keyPair(r);
        List<Object> caps = list(chain.get("caps"));
        String root = (String) chain.get("rootIssuer");
        if (!chainOk(caps, root)) return false;
        int n = caps.size(), idx = (int) (pick % n);
        switch (mutation) {
            case "tamper-caveat": {
                List<Object> m = cloneCaps(caps);
                Map<String, Object> hop = map(m.get(idx));
                List<Object> cv = new ArrayList<>(list(hop.get("caveats")));
                cv.add(obj("type", "expires", "at", 999L));
                hop.put("caveats", cv);
                return !chainOk(m, root);
            }
            case "drop-leaf-caveat": {
                List<Object> m = cloneCaps(caps);
                Map<String, Object> hop = map(m.get(n - 1));
                List<Object> cv = list(hop.get("caveats"));
                if (cv.isEmpty()) return true; // inapplicable: trivially pass
                hop.put("caveats", new ArrayList<>(cv.subList(0, cv.size() - 1)));
                return !chainOk(m, root);
            }
            case "swap-holder": {
                List<Object> m = cloneCaps(caps);
                map(m.get(idx)).put("holder", aux.pub); // changes the signed body: digest mismatch
                return !chainOk(m, root);
            }
            case "break-parent": {
                if (n < 2) return true; // no non-root hop to detach
                List<Object> m = cloneCaps(caps);
                map(m.get(Math.max(1, idx))).put("parent", Pca.hashCanonical(obj("bogus", 32L, "tag", "not-a-real-parent")));
                return !chainOk(m, root);
            }
            case "bad-sig": {
                List<Object> m = cloneCaps(caps);
                // a well-formed but wrong signature: over different bytes, by a different key
                map(m.get(idx)).put("sig", Keys.b64u(aux.key().sign(new byte[] {1, 2, 3, 4})));
                return !chainOk(m, root);
            }
            case "wrong-root-issuer": {
                if (aux.pub.equals(root)) return true; // negligibly rare key collision: skip
                return !chainOk(caps, aux.pub);
            }
            case "suite-mismatch": {
                List<Object> m = cloneCaps(caps);
                map(m.get(idx)).put("alg", "ml-dsa-65"); // the suite fields are bound into body_digest
                return !chainOk(m, root);
            }
            case "break-id": {
                List<Object> m = cloneCaps(caps);
                map(m.get(idx)).put("id", Pca.hashCanonical(obj("not", "the-body-digest", "n", (long) idx)));
                return !chainOk(m, root);
            }
            default: { // append-forged-hop: issued as if from the leaf, but signed by a key that is NOT the leaf's holder
                Map<String, Object> forged = Issue.delegate(map(caps.get(n - 1)), aux.pub, new ArrayList<>(), Keys.ed25519(aux.key()), null);
                List<Object> m = new ArrayList<>(caps);
                m.add(forged);
                return !chainOk(m, root);
            }
        }
    }

    /** Well-typed but never-signed "capabilities" (random fields) never verify; neither does the empty chain. */
    public static boolean garbageChainRejectedProperty(Rng r) {
        List<Object> garbage = new ArrayList<>();
        for (long i = r.integer(0, 4); i > 0; i--) {
            List<Object> cv = new ArrayList<>();
            for (long j = r.integer(0, 3); j > 0; j--) cv.add(obj("type", r.string(0, 10)));
            garbage.add(obj("id", r.string(0, 10), "issuer", r.string(0, 10), "holder", r.string(0, 10), "caveats", cv,
                "body_digest", r.string(0, 10), "sig", r.string(0, 10)));
        }
        return !Pca.verifyChain(garbage, null, false, null).isEmpty();
    }

    // =================================== 4. DETERMINISM =====================================

    /** verifyChain, evaluatePredicates, evaluateCaveats, riskScore, the threshold band and admit are all deterministic. */
    public static boolean determinismProperty(Rng r) {
        Map<String, Object> chain = Arbitraries.chain(r), pt = Arbitraries.evalPoint(r), policy, inputs, budget;
        List<Object> preds = Arbitraries.predicateList(r);
        policy = Arbitraries.riskPolicy(r);
        inputs = Arbitraries.riskInputs(r);
        budget = Arbitraries.trustBudget(r);
        List<Object> caps = list(chain.get("caps"));
        String root = (String) chain.get("rootIssuer");
        if (!Pca.verifyChain(caps, root, true, null).equals(Pca.verifyChain(caps, root, true, null))) return false;
        if (Predicates.evaluatePredicates(preds, map(pt.get("action"))) != Predicates.evaluatePredicates(preds, map(pt.get("action")))) return false;
        Map<String, Object> leaf = map(caps.get(caps.size() - 1));
        Caveats.Result c1 = Caveats.evaluateCaveats(leaf.get("caveats"), pt.get("cavCtx")), c2 = Caveats.evaluateCaveats(leaf.get("caveats"), pt.get("cavCtx"));
        if (c1.ok != c2.ok || !String.join("|", c1.failed).equals(String.join("|", c2.failed))) return false;
        double r1 = riskOf(inputs, map(policy.get("weights"))), r2 = riskOf(inputs, map(policy.get("weights")));
        if (Double.doubleToLongBits(r1) != Double.doubleToLongBits(r2)) return false;
        double th1 = d(policy.get("theta1")), th2 = d(policy.get("theta2")), kappa = d(policy.get("kappa"));
        if (W3Bridge.requiredThreshold(r1, th1, th2, false) != W3Bridge.requiredThreshold(r1, th1, th2, false)) return false;
        return InvariantsBridge.admit(r1, d(budget.get("B")), th1, th2, kappa).equals(InvariantsBridge.admit(r1, d(budget.get("B")), th1, th2, kappa));
    }

    /**
     * Forbid-wins is monotone and order-independent: adding a forbid clause only moves a decision down, a matching forbid always denies
     * whatever the permits say, and the decision does not depend on the order of the clauses.
     */
    public static boolean forbidMonotoneProperty(Rng r) {
        List<Object> permits = Arbitraries.predicateList(r), forbids = Arbitraries.predicateList(r), extra = Arbitraries.predicateList(r);
        Map<String, Object> pt = Arbitraries.evalPoint(r);
        long rot = r.integer(0, 5);
        Map<String, Object> ctx = map(pt.get("action"));
        List<Object> base = new ArrayList<>();
        base.addAll(clauses("permit", permits, "p"));
        base.addAll(clauses("escalate", extra, "e"));
        List<Object> withForbid = new ArrayList<>(base);
        withForbid.addAll(clauses("forbid", forbids, "f"));
        int before = rank(ForbidWins.decide(base, ctx, null, null).decision);
        String afterDecision = ForbidWins.decide(withForbid, ctx, null, null).decision;
        if (rank(afterDecision) > before) return false; // adding a forbid must never grow the admit set
        boolean anyForbid = false;
        for (Object when : forbids) anyForbid |= ForbidWins.whenMatches(when, ctx);
        if (anyForbid && !"deny".equals(afterDecision)) return false; // a matching forbid beats every permit
        int k = (int) (rot % withForbid.size());
        List<Object> rotated = new ArrayList<>(withForbid.subList(k, withForbid.size()));
        rotated.addAll(withForbid.subList(0, k));
        return ForbidWins.decide(rotated, ctx, null, null).decision.equals(afterDecision); // order-independent
    }

    private static List<Object> clauses(String kind, List<Object> ps, String tag) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < ps.size(); i++) out.add(obj("id", tag + i, "kind", kind, "when", ps.get(i)));
        return out;
    }

    private static int rank(String decision) { return "deny".equals(decision) ? 0 : "escalate".equals(decision) ? 1 : 2; }

    // =================================== runner / registry ==================================

    /** The twelve invariants by name, in registry order (the same names as {@link Invariants#INVARIANT_NAMES}). */
    public static final Map<String, Predicate<Rng>> INVARIANTS = new LinkedHashMap<>();
    static {
        INVARIANTS.put("attenuation-monotonicity", InvariantProperties::attenuationMonotonicityProperty);
        INVARIANTS.put("risk-wellformed-and-monotone", InvariantProperties::riskMonotoneProperty);
        INVARIANTS.put("admission-soundness", InvariantProperties::admissionSoundnessProperty);
        INVARIANTS.put("cumulative-budget-bound", InvariantProperties::cumulativeBudgetBoundProperty);
        INVARIANTS.put("fail-closed:undecidable-leaf", InvariantProperties::undecidableLeafFailsClosedProperty);
        INVARIANTS.put("fail-closed:undecidable-groups", InvariantProperties::undecidableGroupsFailClosedProperty);
        INVARIANTS.put("fail-closed:member-of-cycle-safe", InvariantProperties::memberOfCycleSafeProperty);
        INVARIANTS.put("fail-closed:unknown-caveat-type", InvariantProperties::unknownCaveatTypeDeniesProperty);
        INVARIANTS.put("fail-closed:forged-chain-rejected", InvariantProperties::forgedChainRejectedProperty);
        INVARIANTS.put("fail-closed:garbage-chain-rejected", InvariantProperties::garbageChainRejectedProperty);
        INVARIANTS.put("forbid-monotone", InvariantProperties::forbidMonotoneProperty);
        INVARIANTS.put("determinism", InvariantProperties::determinismProperty);
    }

    /**
     * Run one property {@code numRuns} times from {@code seed}; throws an {@link AssertionError} naming the failing run (a property that
     * throws fails too). The same (seed, numRuns) always generates the same cases.
     */
    public static void run(Predicate<Rng> property, long numRuns, long seed) {
        Rng rng = new Rng(seed);
        for (long i = 0; i < numRuns; i++) {
            boolean ok;
            try {
                ok = property.test(rng);
            } catch (RuntimeException e) {
                throw new AssertionError("Property failed after " + (i + 1) + " test(s) (seed " + seed + "): threw " + e, e);
            }
            if (!ok) throw new AssertionError("Property failed after " + (i + 1) + " test(s) (seed " + seed + ")");
        }
    }

    /**
     * Machine-check every invariant: one result per invariant {@code {name, ok, numRuns, seed[, error]}}. {@code ok: false} with an
     * {@code error} is a surfaced counterexample (a candidate core bug). A check that runs zero cases passes vacuously, so it is refused.
     */
    public static List<Map<String, Object>> checkInvariants(Long numRunsOpt, Long seedOpt, boolean bail) {
        long numRuns = numRunsOpt == null ? Invariants.DEFAULT_NUM_RUNS : numRunsOpt;
        long seed = seedOpt == null ? Invariants.DEFAULT_SEED : seedOpt;
        if (numRuns < 1 || numRuns > 9007199254740991L) throw new IllegalArgumentException("checkInvariants: numRuns must be a positive integer");
        if (Math.abs(seed) > 9007199254740991L) throw new IllegalArgumentException("checkInvariants: seed must be an integer");
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map.Entry<String, Predicate<Rng>> inv : INVARIANTS.entrySet()) {
            try {
                run(inv.getValue(), numRuns, seed);
                results.add(obj("name", inv.getKey(), "ok", true, "numRuns", numRuns, "seed", seed));
            } catch (AssertionError | RuntimeException e) {
                results.add(obj("name", inv.getKey(), "ok", false, "numRuns", numRuns, "seed", seed, "error", String.valueOf(e.getMessage())));
                if (bail) break;
            }
        }
        return results;
    }
}
