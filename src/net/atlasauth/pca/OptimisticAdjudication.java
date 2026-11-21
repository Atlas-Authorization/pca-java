package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The server-side judgments of the optimistic fast path: {@link #verifyClaim}, {@link #verifyFraudProof} (re-runs the Policy VM on the
 * frozen open-time snapshot under the grant the verifier trusts) and {@link #adjudicateDispute} (substitutes an objective oracle's value for
 * the one disputed input and re-adjudicates). The settlement layer never takes a slash on a challenger's word: it recomputes these itself.
 * Claims, proofs, grants and snapshots are JSON objects; verdicts are JSON objects too.
 */
public final class OptimisticAdjudication {
    private OptimisticAdjudication() {}

    static final String IRREVERSIBLE = "irreversible";
    static final double DEFAULT_R_MARGIN = 1e-9;
    /** The realistic floor of a derived challenge window (30 s). */
    public static final double DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000;

    /** Resolves the truthful value of a disputed input from server-authoritative facts. Total: report {@code valid:false} rather than throw. */
    public interface ObjectiveOracle {
        /** Returns {@code {input, value?, class?, valid, reason?}}. */
        Map<String, Object> resolve(String input, Map<String, Object> snapshot);
    }

    private static Map<String, Object> obj(Object v) {
        if (v instanceof Map) return StoreJs.map(v);
        if (v instanceof List) return new LinkedHashMap<>(); // typeof [] === 'object'
        return null;
    }

    private static Map<String, Object> shallow(Object v) {
        Map<String, Object> m = obj(v);
        return m == null ? new LinkedHashMap<>() : new LinkedHashMap<>(m);
    }

    private static boolean memberEq(Map<String, Object> a, Map<String, Object> b, String k) {
        boolean ha = a.containsKey(k), hb = b.containsKey(k);
        if (ha != hb) return false;
        return !ha || Ledger.jsEq(a.get(k), b.get(k));
    }

    private static double dnum(Object o) { Double d = StoreJs.dbl(o); return d == null ? Double.NaN : d; }

    private static boolean finite(Object o) { return StoreJs.isFinite(o); }

    private static String fixed3(double x) {
        return new BigDecimal(x).setScale(3, RoundingMode.HALF_UP).toPlainString(); // JavaScript toFixed(3): exact value, ties up
    }

    private static String js(double x) { return AttestCommon.jsNumString(x); }

    private static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = StoreJs.dbl(o);
        if (d != null) return d != 0 && !d.isNaN();
        return true;
    }

    /** {@code {ok, reason?}}: the claim covers this action, is not irreversible, and its signature and window verify against {@code serverNow}. Never throws. */
    public static Map<String, Object> verifyClaim(Object claim, Map<String, Object> pcactn, String signerPublic, double serverNow, Optimistic.ChallengeWindowPolicy policyOrNull) {
        Optimistic.ChallengeWindowPolicy policy = policyOrNull != null ? policyOrNull : Optimistic.DEFAULT_POLICY;
        Map<String, Object> out = new LinkedHashMap<>();
        String reason;
        try {
            String check = Optimistic.claimCheck(claim, Pca.hashCanonical(pcactn), signerPublic, serverNow, policy);
            switch (check) {
                case "ok": out.put("ok", true); return out;
                case "irreversible": reason = "irreversible action is ineligible for the optimistic path"; break;
                case "digest": reason = "claim does not cover this PCActn"; break;
                case "claimed_r": reason = "claimed_r is not finite"; break;
                case "window": {
                    Map<String, Object> c = obj(claim);
                    String bad = Optimistic.validateWindow(dnum(c.get("issued_at")), dnum(c.get("challenge_window_ms")), serverNow, policy);
                    reason = bad != null ? bad : "malformed challenge window";
                    break;
                }
                case "signature": reason = "claim signature does not verify"; break;
                default: reason = "malformed claim";
            }
        } catch (RuntimeException e) {
            reason = "claim verification error: " + (e.getMessage() == null ? "unknown" : e.getMessage());
        }
        out.put("ok", false);
        out.put("reason", reason);
        return out;
    }

    private static Map<String, Object> verdict(boolean fraudulent, String bondRef, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fraudulent", fraudulent);
        if (bondRef != null) m.put("slashBondRef", bondRef);
        m.put("reason", reason);
        return m;
    }

    private static Map<String, Object> summary(boolean release, Object r, boolean optimisticAllowed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("releaseGuardianShare", release);
        m.put("r", r);
        m.put("optimisticAllowed", optimisticAllowed);
        return m;
    }

    private static Map<String, Object> summarizeDecision(Map<String, Object> d) {
        Map<String, Object> thr = StoreJs.map(d.get("requiredThreshold"));
        return summary(Boolean.TRUE.equals(d.get("releaseGuardianShare")), numOf(d.get("r")), thr != null && Boolean.TRUE.equals(thr.get("optimisticAllowed")));
    }

    private static Object numOf(Object o) { Double d = StoreJs.dbl(o); return d == null ? null : StoreJs.num(d); }

    /**
     * Independently verify a fraud proof: re-run the Policy VM on the frozen open-time snapshot under the trusted grant, confirm the proof's
     * decision matches, and confirm the recomputed decision refutes the claim. Returns {@code {fraudulent, slashBondRef?, reason}}. Never throws.
     */
    public static Map<String, Object> verifyFraudProof(Map<String, Object> claim, Object proofO, Map<String, Object> grant, Object snapO) {
        try {
            Map<String, Object> proof = obj(proofO);
            if (proof == null) return verdict(false, null, "malformed fraud proof");
            if (!memberEq(proof, claim, "pcactn_digest")) return verdict(false, null, "fraud proof targets a different PCActn than the claim");
            if (!memberEq(proof, claim, "bond_ref")) return verdict(false, null, "fraud proof names a different bond than the claim");
            Map<String, Object> snap = obj(snapO);
            if (snap == null) return verdict(false, null, "no frozen open-time snapshot supplied; cannot judge the claim");
            Map<String, Object> input = shallow(snap);
            input.put("grant", grant);
            Map<String, Object> recomputed = Decide.decide(input);
            Map<String, Object> s = summarizeDecision(recomputed);
            double r = dnum(s.get("r"));
            Map<String, Object> pd = obj(proof.get("decision"));
            if (pd == null) {
                // a primitive decision has no members (they read as undefined); an absent or null one is a TypeError in the reference
                if (proof.get("decision") == null) return verdict(false, null, "fraud-proof verification error: Cannot read properties of " + (proof.containsKey("decision") ? "null" : "undefined") + " (reading 'releaseGuardianShare')");
                pd = new LinkedHashMap<>();
            }
            if (!java.util.Objects.equals(s.get("releaseGuardianShare"), pd.get("releaseGuardianShare"))
                || !java.util.Objects.equals(s.get("optimisticAllowed"), pd.get("optimisticAllowed"))
                || Math.abs(r - dnum(pd.get("r"))) > 1e-9) {
                return verdict(false, null, "proof decision does not match an independent recomputation");
            }
            double margin = finite(proof.get("r_margin")) ? Math.max(0, dnum(proof.get("r_margin"))) : DEFAULT_R_MARGIN;
            Map<String, Object> inner = obj(obj(snap.get("action")) == null ? null : obj(snap.get("action")).get("action"));
            boolean irreversible = IRREVERSIBLE.equals(claim.get("reversibility_class")) || (inner != null && IRREVERSIBLE.equals(inner.get("reversibility_class")));
            String bond = (String) claim.get("bond_ref");
            if (irreversible) return verdict(true, bond, "irreversible action is ineligible for the optimistic path");
            if (!Boolean.TRUE.equals(s.get("releaseGuardianShare"))) {
                StringBuilder sb = new StringBuilder();
                Object rs = recomputed.get("reasons");
                if (rs instanceof List) for (Object x : (List<?>) rs) sb.append(sb.length() == 0 ? "" : "; ").append(x);
                return verdict(true, bond, "Policy VM denies the action: " + (sb.length() == 0 ? "not compliant" : sb));
            }
            if (!Boolean.TRUE.equals(s.get("optimisticAllowed"))) return verdict(true, bond, "optimistic path not allowed at real r=" + fixed3(r));
            double claimed = dnum(claim.get("claimed_r"));
            if (r > claimed + margin) return verdict(true, bond, "risk understated: claimed " + js(claimed) + ", real " + fixed3(r));
            return verdict(false, null, "claim is compliant under independent recomputation; bond stands");
        } catch (RuntimeException e) {
            return verdict(false, null, "fraud-proof verification error: " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }

    /**
     * Files a fraud proof against a bonded claim, or returns {@code null} when the action is compliant (nothing to prove). The decision is
     * RE-DERIVED by replaying the Policy VM on {@code openSnapshot} under {@code grant}, never taken from the caller; a pcactn the claim does
     * not cover returns {@code null}. {@code rMargin} (null = default) is clamped at zero.
     */
    public static Map<String, Object> fileFraudProof(Map<String, Object> claim, Map<String, Object> pcactn, Map<String, Object> grant,
                                                     Map<String, Object> openSnapshot, Double rMargin) {
        if (openSnapshot == null) return null;
        Map<String, Object> input = shallow(openSnapshot);
        input.put("grant", grant);
        Map<String, Object> actual = Decide.decide(input);
        if (!java.util.Objects.equals(claim.get("pcactn_digest"), Pca.hashCanonical(pcactn))) return null;
        double margin = rMargin != null && finite(rMargin) ? Math.max(0, rMargin) : DEFAULT_R_MARGIN;
        Map<String, Object> thr = StoreJs.map(actual.get("requiredThreshold"));
        Map<String, Object> decision = summarizeDecision(actual);
        Map<String, Object> evidence = shallow(openSnapshot);
        evidence.remove("grant");
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("pcactn_digest", claim.get("pcactn_digest"));
        proof.put("bond_ref", claim.get("bond_ref"));
        proof.put("claimed_r", claim.get("claimed_r"));
        proof.put("decision", decision);
        proof.put("evidence", evidence);
        proof.put("r_margin", StoreJs.num(margin));
        Map<String, Object> act = obj(pcactn == null ? null : pcactn.get("action"));
        double r = dnum(decision.get("r"));
        String kind = null, reason = "";
        if (IRREVERSIBLE.equals(claim.get("reversibility_class")) || (act != null && IRREVERSIBLE.equals(act.get("reversibility_class")))) {
            kind = "irreversible";
            reason = "irreversible action took the optimistic path";
        } else if (!Boolean.TRUE.equals(decision.get("releaseGuardianShare"))) {
            kind = "policy-denied";
            StringBuilder sb = new StringBuilder();
            Object rs = actual.get("reasons");
            if (rs instanceof List) for (Object x : (List<?>) rs) sb.append(sb.length() == 0 ? "" : "; ").append(x);
            reason = "Policy VM denied the action: " + (sb.length() == 0 ? "not compliant" : sb);
        } else if (!Boolean.TRUE.equals(decision.get("optimisticAllowed"))) {
            kind = "optimistic-not-allowed";
            reason = "optimistic path not allowed at real r=" + fixed3(r) + " (t=" + (thr == null ? "undefined" : js(dnum(thr.get("t")))) + ")";
        } else if (r > dnum(claim.get("claimed_r")) + margin) {
            kind = "risk-understated";
            reason = "claimed r=" + js(dnum(claim.get("claimed_r"))) + " but real r=" + fixed3(r);
        }
        if (kind == null) return null;
        proof.put("kind", kind);
        proof.put("reason", reason);
        return proof;
    }

    /** Deep-copies a Policy VM input captured at claim open and makes every map and list in the copy unmodifiable. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> freezeOpenSnapshot(Map<String, Object> input) {
        return (Map<String, Object>) freezeDeep(Json.parse(Json.canonicalize(input)));
    }

    private static Object freezeDeep(Object o) {
        if (o instanceof Map) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) m.put((String) e.getKey(), freezeDeep(e.getValue()));
            return java.util.Collections.unmodifiableMap(m);
        }
        if (o instanceof List) {
            List<Object> l = new java.util.ArrayList<>();
            for (Object x : (List<?>) o) l.add(freezeDeep(x));
            return java.util.Collections.unmodifiableList(l);
        }
        return o;
    }

    // ---- dispute adjudication ----

    private static boolean disputable(Object i) {
        return "reversibility_class".equals(i) || "reversibility".equals(i) || "blastRadius".equals(i) || "semanticDistance".equals(i);
    }

    private static Map<String, Object> indeterminate(String input, String reason, Map<String, Object> baseline, Object agentValue) {
        Map<String, Object> worst = summary(false, StoreJs.num(1L), false);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("outcome", "indeterminate");
        m.put("fraudulent", false);
        m.put("slashCounterBond", false);
        m.put("input", input);
        if (agentValue != null) m.put("agentValue", agentValue);
        m.put("baseline", baseline != null ? baseline : worst);
        m.put("adjudicated", worst);
        m.put("reason", reason);
        return m;
    }

    private static Object snapshotValueOf(Map<String, Object> snap, String input) {
        if ("reversibility_class".equals(input)) {
            Map<String, Object> cc = obj(snap.get("caveatContext"));
            Object v = cc == null ? null : cc.get("reversibilityClass");
            if (v != null) return v;
            Map<String, Object> a = obj(snap.get("action"));
            Map<String, Object> inner = a == null ? null : obj(a.get("action"));
            return inner == null ? null : inner.get("reversibility_class");
        }
        Map<String, Object> risk = obj(snap.get("risk"));
        return risk == null ? null : risk.get(input);
    }

    private static Map<String, Object> substitute(Map<String, Object> snap, Map<String, Object> res) {
        String input = (String) res.get("input");
        Map<String, Object> next = new LinkedHashMap<>(snap);
        Map<String, Object> cc = obj(snap.get("caveatContext"));
        if ("reversibility_class".equals(input)) {
            Object cls = res.get("class");
            if (!(cls instanceof String) || ((String) cls).isEmpty()) throw new IllegalStateException("oracle reversibility_class resolution carries no class");
            Map<String, Object> a = shallow(snap.get("action"));
            Map<String, Object> inner = shallow(a.get("action"));
            inner.put("reversibility_class", cls);
            a.put("action", inner);
            next.put("action", a);
            if (cc != null && cc.containsKey("reversibilityClass")) {
                Map<String, Object> c2 = new LinkedHashMap<>(cc);
                c2.put("reversibilityClass", cls);
                next.put("caveatContext", c2);
            }
            return next;
        }
        if (!finite(res.get("value"))) throw new IllegalStateException("oracle " + input + " resolution carries no finite value");
        Map<String, Object> risk = shallow(snap.get("risk"));
        risk.put(input, res.get("value"));
        next.put("risk", risk);
        if ("blastRadius".equals(input) && cc != null && cc.containsKey("blastRadius")) {
            Map<String, Object> c2 = new LinkedHashMap<>(cc);
            c2.put("blastRadius", res.get("value"));
            next.put("caveatContext", c2);
        }
        return next;
    }

    private static boolean fastPathAdmits(Map<String, Object> s, double claimedR, double margin) {
        return Boolean.TRUE.equals(s.get("releaseGuardianShare")) && Boolean.TRUE.equals(s.get("optimisticAllowed")) && dnum(s.get("r")) <= claimedR + margin;
    }

    private static String jsonStr(Object v) { return v == null ? "undefined" : Json.canonicalize(v); }

    /**
     * Adjudicate a contestable dispute. Re-runs the Policy VM on the frozen snapshot with the oracle's value substituted for the single disputed
     * input, under the trusted grant. Fails closed to {@code indeterminate} (slashing no one) on a mismatched target, a missing snapshot or an
     * oracle that cannot resolve. {@code rMargin} may be null. Never throws.
     */
    public static Map<String, Object> adjudicateDispute(Map<String, Object> claim, Object disputeO, Map<String, Object> grant, Object snapO,
                                                        ObjectiveOracle oracle, Double rMargin) {
        double margin = rMargin != null && !rMargin.isNaN() && !rMargin.isInfinite() ? Math.max(0, rMargin) : DEFAULT_R_MARGIN;
        Map<String, Object> dispute = obj(disputeO);
        String fallbackInput = dispute != null && dispute.get("input") instanceof String ? (String) dispute.get("input") : "reversibility_class";
        try {
            if (dispute == null) return indeterminate("reversibility_class", "malformed dispute", null, null);
            Object in = dispute.get("input");
            if (!disputable(in)) return indeterminate("reversibility_class", "unknown disputed input: " + (in instanceof String ? in : in == null ? "undefined" : Json.canonicalize(in)), null, null);
            String input = (String) in;
            if (!memberEq(dispute, claim, "pcactn_digest")) return indeterminate(input, "dispute targets a different PCActn than the claim", null, null);
            if (!memberEq(dispute, claim, "bond_ref")) return indeterminate(input, "dispute names a different bond than the claim", null, null);
            Map<String, Object> open = obj(snapO);
            if (open == null) return indeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate", null, null);
            if (oracle == null) return indeterminate(input, "no objective oracle supplied", null, null);

            Map<String, Object> snap = shallow(open);
            snap.put("grant", grant);
            Map<String, Object> baseline = summarizeDecision(Decide.decide(snap));
            Object agentValue = snapshotValueOf(snap, input);

            Map<String, Object> res = oracle.resolve(input, snap);
            if (res == null || !input.equals(res.get("input")) || !truthy(res.get("valid"))) {
                Object why = res == null ? null : res.get("reason");
                return indeterminate(input, "objective oracle could not authoritatively resolve " + input + (truthy(why) ? ": " + why : ""), baseline, agentValue);
            }
            Object oracleValue = res.get("class") != null ? res.get("class") : res.get("value");
            Map<String, Object> substituted = substitute(snap, res);
            Map<String, Object> adjudicated = summarizeDecision(Decide.decide(substituted));
            double claimedR = dnum(claim.get("claimed_r"));

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("input", input);
            if (agentValue != null) m.put("agentValue", agentValue);
            if (oracleValue != null) m.put("oracleValue", oracleValue);
            m.put("baseline", baseline);
            m.put("adjudicated", adjudicated);
            if (!fastPathAdmits(adjudicated, claimedR, margin)) {
                String why = !Boolean.TRUE.equals(adjudicated.get("releaseGuardianShare")) ? "the Policy VM denies the action"
                    : !Boolean.TRUE.equals(adjudicated.get("optimisticAllowed")) ? "the optimistic path is not allowed (higher threshold) at r=" + fixed3(dnum(adjudicated.get("r")))
                    : "the real r=" + fixed3(dnum(adjudicated.get("r"))) + " exceeds the claimed r=" + js(claimedR);
                m.put("outcome", "agent-fraud");
                m.put("fraudulent", true);
                m.put("slashBondRef", claim.get("bond_ref"));
                m.put("slashCounterBond", false);
                m.put("reason", "understated " + input + ": agent relied on " + jsonStr(agentValue) + ", oracle says " + jsonStr(oracleValue) + " — " + why);
                return m;
            }
            m.put("outcome", "claim-upheld");
            m.put("fraudulent", false);
            m.put("slashCounterBond", true);
            m.put("reason", "the objective oracle upholds the agent's " + input + " (" + jsonStr(oracleValue) + "); fast-path admission survives — the dispute is frivolous");
            return m;
        } catch (RuntimeException e) {
            return indeterminate(fallbackInput, "dispute adjudication error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), null, null);
        }
    }

    // ---- the interactive dispute game (refereed bisection) ----

    /** Exact equality of two step assertions (NaN equals NaN, +0 differs from -0): the bisection divergence predicate. */
    private static boolean assertionEquals(Map<String, Object> a, Map<String, Object> b) {
        boolean ha = a.containsKey("value"), hb = b.containsKey("value");
        Double av = StoreJs.dbl(a.get("value")), bv = StoreJs.dbl(b.get("value"));
        boolean valueEq = (!ha && !hb) || (ha && hb && av != null && bv != null && Double.compare(av, bv) == 0);
        return valueEq && memberEq(a, b, "class");
    }

    private static Map<String, Object> applyAssertion(Map<String, Object> snap, String input, Map<String, Object> a) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("input", input);
        res.put("valid", true);
        if (a.containsKey("value")) res.put("value", a.get("value"));
        if (a.containsKey("class")) res.put("class", a.get("class"));
        return substitute(snap, res);
    }

    /** A party's move at step {@code i}: null when it has none; a non-object move has no members. */
    private static Map<String, Object> move(List<?> list, int i) {
        Object x = list.get(i);
        if (x == null) return null;
        Map<String, Object> m = obj(x);
        return m == null ? new LinkedHashMap<>() : m;
    }

    private static Map<String, Object> stateAfter(Map<String, Object> snap, List<?> steps, List<?> assertions, int j) {
        Map<String, Object> s = snap;
        for (int i = 0; i < j; i++) {
            Object input = steps.get(i);
            Map<String, Object> a = move(assertions, i);
            if (!(input instanceof String) || a == null) throw new IllegalStateException("dispute game trace is shorter than its step list");
            s = applyAssertion(s, (String) input, a);
        }
        return summarizeDecision(Decide.decide(s));
    }

    private static boolean prefixAgrees(List<?> defender, List<?> challenger, int m) {
        for (int i = 0; i < m; i++) {
            Map<String, Object> di = move(defender, i), ci = move(challenger, i);
            if (di == null || ci == null || !assertionEquals(di, ci)) return false;
        }
        return true;
    }

    private static Map<String, Object> gameFail(Map<String, Object> game, String reason, String input) {
        Object steps = game == null ? null : game.get("steps");
        Object first = steps instanceof List && !((List<?>) steps).isEmpty() ? ((List<?>) steps).get(0) : null;
        Map<String, Object> v = indeterminate(input != null ? input : disputable(first) ? (String) first : "reversibility_class", reason, null, null);
        v.put("adjudicated", new LinkedHashMap<>(StoreJs.map(v.get("baseline"))));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verdict", v);
        out.put("converged", false);
        out.put("contestedStep", StoreJs.num(-1L));
        out.put("transcript", new java.util.ArrayList<Object>());
        out.put("rounds", StoreJs.num(0L));
        return out;
    }

    /**
     * Adjudicate an INTERACTIVE multi-round dispute game by refereed bisection: narrow the parties' committed traces ({@code game.defender},
     * {@code game.challenger}, parallel to {@code game.steps}) to the ONE step on which they first diverge, then resolve THAT step with the
     * objective oracle through {@link #adjudicateDispute} against the mutually agreed pre-state. Returns {@code {verdict, converged,
     * contestedStep, contestedInput?, transcript, rounds}}. Never throws; fails closed to {@code indeterminate} (slashing no one) on any
     * malformed input, binding mismatch, missing snapshot or oracle, absence of a genuine admission dispute, non-convergence or error.
     * {@code rMargin} may be null.
     */
    public static Map<String, Object> adjudicateDisputeGame(Map<String, Object> claim, Object gameO, Map<String, Object> grant, Object openSnapshot,
                                                            ObjectiveOracle oracle, Double rMargin) {
        double margin = rMargin != null && !rMargin.isNaN() && !rMargin.isInfinite() ? Math.max(0, rMargin) : DEFAULT_R_MARGIN;
        Map<String, Object> game = obj(gameO);
        try {
            if (game == null) return gameFail(game, "malformed dispute game", null);
            if (!memberEq(game, claim, "pcactn_digest")) return gameFail(game, "dispute game targets a different PCActn than the claim", null);
            if (!memberEq(game, claim, "bond_ref")) return gameFail(game, "dispute game names a different bond than the claim", null);
            List<?> steps = game.get("steps") instanceof List ? (List<?>) game.get("steps") : null;
            List<?> defender = game.get("defender") instanceof List ? (List<?>) game.get("defender") : null;
            List<?> challenger = game.get("challenger") instanceof List ? (List<?>) game.get("challenger") : null;
            if (steps == null || steps.isEmpty()) return gameFail(game, "dispute game has no steps", null);
            for (Object s : steps) if (!disputable(s)) return gameFail(game, "unknown disputed input: " + (s instanceof String ? (String) s : IntentRevocation.jsText(s, true)), null);
            if (defender == null || challenger == null || defender.size() != steps.size() || challenger.size() != steps.size())
                return gameFail(game, "party assertions do not cover every step", null);
            Map<String, Object> open = obj(openSnapshot);
            if (open == null) return gameFail(game, "no frozen open-time snapshot supplied; cannot adjudicate", null);
            if (oracle == null) return gameFail(game, "no objective oracle supplied", null);

            int n = steps.size();
            Map<String, Object> snap = shallow(open);
            snap.put("grant", grant);
            double claimedR = dnum(claim.get("claimed_r"));

            // genuine-dispute gate: the defender's full trace must still admit the fast path and the challenger's must not
            Map<String, Object> defenderFinal = stateAfter(snap, steps, defender, n);
            Map<String, Object> challengerFinal = stateAfter(snap, steps, challenger, n);
            if (!fastPathAdmits(defenderFinal, claimedR, margin)) return gameFail(game, "defender does not defend the fast-path admission; nothing to adjudicate", null);
            if (fastPathAdmits(challengerFinal, claimedR, margin)) return gameFail(game, "the parties do not disagree on admission; no genuine dispute to bisect", null);
            if (prefixAgrees(defender, challenger, n)) return gameFail(game, "the parties committed identical traces; no contested step to bisect", null);

            int lo = 0, hi = n;
            List<Object> transcript = new java.util.ArrayList<>();
            while (hi - lo > 1) {
                int mid = (lo + hi) / 2;
                boolean agreedAtMid = prefixAgrees(defender, challenger, mid);
                Map<String, Object> round = new LinkedHashMap<>();
                round.put("lo", StoreJs.num((long) lo));
                round.put("hi", StoreJs.num((long) hi));
                round.put("mid", StoreJs.num((long) mid));
                round.put("agreedAtMid", agreedAtMid);
                transcript.add(round);
                if (agreedAtMid) lo = mid; else hi = mid;
            }
            int contestedStep = lo;
            String contestedInput = (String) steps.get(contestedStep); // every step passed disputable(), so it is a string

            // the agreed pre-state: every earlier correction folded in, re-verifying that the prefix really is agreed
            Map<String, Object> preState = snap;
            for (int i = 0; i < contestedStep; i++) {
                Map<String, Object> di = move(defender, i), ci = move(challenger, i);
                if (di == null || ci == null || !assertionEquals(di, ci)) return gameFail(game, "agreed prefix is not actually agreed; cannot reconstruct the pre-state", contestedInput);
                preState = applyAssertion(preState, (String) steps.get(i), di);
            }

            Map<String, Object> chalMove = move(challenger, contestedStep);
            if (chalMove == null) return gameFail(game, "challenger has no assertion for the contested step", contestedInput);
            Map<String, Object> dispute = new LinkedHashMap<>();
            dispute.put("pcactn_digest", claim.get("pcactn_digest"));
            dispute.put("bond_ref", claim.get("bond_ref"));
            dispute.put("input", contestedInput);
            if (chalMove.containsKey("value")) dispute.put("asserted_value", chalMove.get("value"));
            if (chalMove.containsKey("class")) dispute.put("asserted_class", chalMove.get("class"));
            Map<String, Object> verdict = adjudicateDispute(claim, dispute, grant, preState, oracle, margin);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("verdict", verdict);
            out.put("converged", true);
            out.put("contestedStep", StoreJs.num((long) contestedStep));
            out.put("contestedInput", contestedInput);
            out.put("transcript", transcript);
            out.put("rounds", StoreJs.num((long) transcript.size()));
            return out;
        } catch (RuntimeException e) {
            return gameFail(game, "dispute game adjudication error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), null);
        }
    }
}
