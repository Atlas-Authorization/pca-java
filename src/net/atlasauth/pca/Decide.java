package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Policy VM decision (the reference's {@code decide}): whether the guardian share may be released for an action, the
 * threshold and proof it then needs, the risk, the budget admission and the budget afterwards. Pure and total: any fault is a
 * denial carrying a reason (fail closed).
 *
 * <p>The input and the result are the reference's objects as {@link Json} trees. Input members: {@code grant}, {@code pqPins?},
 * {@code trustedRoot?}, {@code chain?}, {@code action} ({@code {action: {verb, resource, params, reversibility_class}, subject?, env?, toolBinding?}}),
 * {@code plan?}, {@code risk} (any of {@code semanticDistance, reversibility, blastRadius, taint, confidence, age}), {@code budget}
 * ({@code {B, tau, asOf?}}), {@code now}, {@code nodeId?}, {@code goalNodeId?}, {@code caveatContext?} ({@code recentActionTimes,
 * reversibilityClass, blastRadius, delegationDepth}), {@code ageHorizonMs?}, {@code rFloor?}, {@code chainVerified?}, {@code k1?}.
 * Result members: {@code releaseGuardianShare, requiredThreshold {t, proof, optimisticAllowed}, r, admit, needStepUp, reasons, budget, k1Bound?}.
 */
public final class Decide {
    private Decide() {}

    /** Classes recognised as non-irreversible (so the optimistic fast path may be offered); anything else is treated as irreversible. */
    private static final List<String> FAST_PATH_CLASSES = Arrays.asList("reversible", "rate_limited", "costly");

    private static Map<String, Object> map(Object o) { return o instanceof Map ? IntentJs.obj(o) : new LinkedHashMap<>(); }

    private static Map<String, Object> denied(String reason, Object budget) {
        Map<String, Object> thr = new LinkedHashMap<>();
        thr.put("t", 3);
        thr.put("proof", "strong");
        thr.put("optimisticAllowed", false);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("releaseGuardianShare", false);
        out.put("requiredThreshold", thr);
        out.put("r", 1);
        out.put("admit", false);
        out.put("needStepUp", true);
        out.put("reasons", new ArrayList<Object>(List.of(reason)));
        out.put("budget", budget);
        return out;
    }

    /** Decides {@code input}; never throws. */
    public static Map<String, Object> decide(Map<String, Object> input) {
        Object fallback = input != null && input.get("budget") != null ? input.get("budget") : budgetMap(new Risk.Budget(0, 0, 0));
        try {
            return SafeRegex.withBudget(() -> decideInner(input, fallback));
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return denied("policy evaluation error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), fallback);
        }
    }

    private static Map<String, Object> budgetMap(Risk.Budget b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", b.b);
        if (!b.tauAbsent) m.put("tau", b.tau); // an absent tau stays absent; an explicit NaN is kept
        m.put("asOf", b.asOf);
        return m;
    }

    private static List<Object> withoutK1(Object cs) {
        List<Object> out = new ArrayList<>();
        if (cs instanceof List) for (Object c : (List<?>) cs) if (!CaveatLang.isK1Caveat(c)) out.add(c);
        return out;
    }

    private static Double pnum(Map<String, Object> m, String k) { return Caveats.fin(m.get(k)); }

    private static Object ctxPut(Map<String, Object> cctx, String camel, String snake, Map<String, Object> over) {
        return over.containsKey(camel) ? cctx.put(snake, over.get(camel)) : null;
    }

    /** The reference's {@code horizonMs = 3_600_000} default applies to undefined only; anything else is coerced like {@code horizonMs > 0} (NaN, "x" and null are not positive). */
    static double horizonOf(Map<String, Object> in) {
        return in.containsKey("ageHorizonMs") ? net.atlasauth.pca.doctor.Js.toNumber(in.get("ageHorizonMs")) : 3_600_000;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decideInner(Map<String, Object> in, Object fallbackBudget) {
        Object budgetIn = in.get("budget");
        Object grantO = in.get("grant");
        Map<String, Object> env = Authorize.readEnvelope(grantO);
        if (env == null) return denied("grant carries no valid envelope", budgetIn);
        Map<String, Object> grant = map(grantO);
        Double nowD = Caveats.fin(in.get("now"));
        if (nowD == null) return denied("invalid decision time", budgetIn);
        double now = nowD;
        boolean hasChain = in.containsKey("chain");
        Object chainO = in.get("chain");

        // an unverified capability chain is DENIED here: unless the caller vouches it was verified, decide re-verifies it
        if (!Boolean.TRUE.equals(in.get("chainVerified"))) {
            List<Object> toVerify = chainO instanceof List && !((List<?>) chainO).isEmpty() ? (List<Object>) chainO : new ArrayList<>(List.of(grant));
            Object issuer = grant.get("issuer");
            String why = Pca.verifyChain(toVerify, issuer instanceof String ? (String) issuer : null, issuer instanceof String, null,
                in.get("pqPins") instanceof Map ? map(in.get("pqPins")) : null, in.get("trustedRoot") instanceof Map ? map(in.get("trustedRoot")) : null);
            if (!why.isEmpty()) return denied("capability chain unverified: " + why, budgetIn);
        }

        Map<String, Object> pol = map(env.get("risk_policy"));
        List<String> reasons = new ArrayList<>();
        Map<String, Object> actionCtx = map(in.get("action"));
        Map<String, Object> inner = map(actionCtx.get("action"));

        // 1. semantic predicates (default deny)
        String denial = Predicates.denialReason(env.get("predicates"), actionCtx);
        boolean prOk = denial == null;
        if (!prOk) reasons.add(denial);

        Object nodeId = in.get("nodeId");
        List<Object> plan = in.get("plan") instanceof List ? (List<Object>) in.get("plan") : null;
        Map<String, Object> risk = map(in.get("risk"));

        // the class the action is bound to: its own, else the plan node it names, else unknown (fail closed)
        Object revClass = inner.get("reversibility_class");
        if (revClass == null && nodeId instanceof String && plan != null) {
            for (Object n : plan) {
                if (n instanceof Map && nodeId.equals(((Map<?, ?>) n).get("id"))) { revClass = ((Map<?, ?>) n).get("reversibility_class"); break; }
            }
        }

        // 2. envelope caveats
        Map<String, Object> cctx = new LinkedHashMap<>();
        cctx.put("now", now);
        cctx.put("action", inner);
        cctx.put("blast_radius", risk.get("blastRadius"));
        cctx.put("reversibility_class", revClass);
        Map<String, Object> over = map(in.get("caveatContext"));
        ctxPut(cctx, "blastRadius", "blast_radius", over);
        ctxPut(cctx, "reversibilityClass", "reversibility_class", over);
        ctxPut(cctx, "delegationDepth", "delegation_depth", over);
        ctxPut(cctx, "recentActionTimes", "recent_action_times", over);
        Map<String, Object> toolCall = new LinkedHashMap<>();
        toolCall.put("tool", inner.get("verb") instanceof String ? inner.get("verb") : "");
        Object params = inner.get("params");
        toolCall.put("args", params instanceof Map ? params : new LinkedHashMap<String, Object>());
        if (actionCtx.get("toolBinding") instanceof String) toolCall.put("toolSignatureDigest", actionCtx.get("toolBinding"));

        boolean chainOk = true;
        Object extra = new ArrayList<Object>();
        List<Object> gcs = grant.get("caveats") instanceof List ? (List<Object>) grant.get("caveats") : new ArrayList<>();
        List<Object> chain = chainO instanceof List ? (List<Object>) chainO : null;
        if (hasChain) {
            if (chain == null || chain.isEmpty()) {
                chainOk = false;
                reasons.add("delegation chain is empty or malformed");
            } else {
                cctx.put("delegation_depth", chain.size() - 1);
                Object lcs = map(chain.get(chain.size() - 1)).get("caveats");
                extra = lcs instanceof List ? new ArrayList<>(((List<Object>) lcs).subList(Math.min(gcs.size(), ((List<?>) lcs).size()), ((List<?>) lcs).size())) : new ArrayList<>();
            }
        }
        Caveats.Result ecv = Authorize.evaluateAgentCaveats(env.get("caveats"), cctx, actionCtx, toolCall);
        if (!ecv.ok) reasons.add("caveat(s) not satisfied: " + String.join(", ", ecv.failed));

        // root caveats outside the envelope are signed authority too; the caveat-language (K1) types are evaluated over the whole chain
        Object leafCaveats = (chain != null && !chain.isEmpty() ? map(chain.get(chain.size() - 1)) : grant).get("caveats");
        boolean useK1 = in.get("k1") instanceof Map && map(in.get("k1")).containsKey("narrow");
        if (leafCaveats instanceof List) for (Object c : (List<?>) leafCaveats) if (CaveatLang.isK1Caveat(c)) useK1 = true;
        CaveatLang.K1Result k1 = null;
        if (useK1) {
            Map<String, Object> k1Ctx = new LinkedHashMap<>();
            k1Ctx.put("now", IntentJs.ofLong((long) now));
            k1Ctx.put("action", inner);
            k1 = CaveatLang.evaluateK1(grant, chainO, in.get("k1") instanceof Map ? map(in.get("k1")) : null, k1Ctx);
        }
        Caveats.Result rcv = Authorize.evaluateAgentCaveats(withoutK1(Caveats.rootCaveats(grant)), cctx, actionCtx, toolCall);
        if (!rcv.ok) reasons.add("root caveat(s) not satisfied: " + String.join(", ", rcv.failed));
        boolean cvOk = ecv.ok && rcv.ok;
        List<Object> dl = withoutK1(extra);
        if (k1 != null) dl.addAll(k1.plain);
        Caveats.Result dcv = Authorize.evaluateAgentCaveats(dl, cctx, actionCtx, toolCall);
        boolean dcvOk = dcv.ok;
        if (!dcv.ok) reasons.add("delegated caveat(s) not satisfied: " + String.join(", ", dcv.failed));
        if (k1 != null && !k1.ok) {
            dcvOk = false;
            for (int i = 0; i < k1.reasons.size(); i++) reasons.add("caveat language: " + k1.failed.get(i) + ": " + k1.reasons.get(i));
        }

        // 3. risk
        Risk.Budget budget = Risk.Budget.of(budgetIn);
        if (budget == null) budget = Risk.Budget.ofLenient(budgetIn);
        if (budget == null) budget = Risk.Budget.ofJs(budgetIn); // any other non-null value: B coerced like arithmetic, a non-object has none
        if (budget == null) throw new IllegalArgumentException("budget is not a trust budget");
        double th1 = pnum(pol, "theta1"), th2 = pnum(pol, "theta2"), kappa = pnum(pol, "kappa"), lambda = pnum(pol, "lambda");
        Map<String, Object> weights = pol.get("weights") instanceof Map ? map(pol.get("weights")) : new LinkedHashMap<>();
        Risk.Budget leaked = Risk.leak(budget, now, lambda);
        double[] inputs = Risk.WORST.clone();
        List<String> missing = new ArrayList<>();
        for (int i = 0; i < Risk.KEYS.length; i++) {
            Double v = Caveats.fin(risk.get(Risk.KEYS[i]));
            if (v != null) inputs[i] = v;
            else if (i != 5) missing.add(Risk.KEYS[i]);
        }
        if (plan != null && risk.get("semanticDistance") == null) {
            Object goal = in.get("goalNodeId") != null ? in.get("goalNodeId")
                : plan.isEmpty() ? null : map(plan.get(plan.size() - 1)).get("id");
            inputs[0] = nodeId instanceof String && goal instanceof String ? Risk.planGeodesic(plan, (String) nodeId, (String) goal) : 1;
            missing.remove("semanticDistance");
        }
        if (risk.get("age") == null) {
            inputs[5] = Risk.ageSinceTouch(leaked, now, horizonOf(in));
        }
        if (!missing.isEmpty()) reasons.add("risk input(s) missing, assumed worst case: " + String.join(", ", missing));
        Double rf = Caveats.fin(in.get("rFloor"));
        double rFloor = rf == null ? 0 : Math.min(1, Math.max(0, rf));
        double r = Math.max(Risk.riskScore(inputs, weights), rFloor);

        Object rc = cctx.get("reversibility_class");
        boolean irreversible = !(rc instanceof String && FAST_PATH_CLASSES.contains(rc));
        Risk.Required rt = Risk.requiredThreshold(r, th1, th2, irreversible);

        // 4. budget admission
        Risk.Admission adm = Risk.admit(Risk.requiredThreshold(r, th1, th2, false).t, Double.isFinite(leaked.b) && leaked.b >= Risk.cost(r, kappa));
        if (adm.needStepUp) {
            reasons.add(rt.t < 3 && adm.t == 3 ? "trust budget depleted: human recharge required"
                : "risk " + String.format(java.util.Locale.ROOT, "%.3f", r) + " exceeds auto threshold: step-up to t=" + adm.t);
        }

        // 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
        boolean release = prOk && cvOk && dcvOk && chainOk;
        Risk.Required thr = Risk.escalate(rt, adm.t);
        Risk.Budget out = release && adm.metered ? Risk.debit(leaked, Risk.cost(r, kappa)) : leaked;
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("t", thr.t);
        t.put("proof", thr.proof);
        t.put("optimisticAllowed", thr.optimisticAllowed);
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("releaseGuardianShare", release);
        res.put("requiredThreshold", t);
        res.put("r", r);
        res.put("admit", release && adm.admit);
        res.put("needStepUp", release ? adm.needStepUp : true);
        res.put("reasons", new ArrayList<Object>(reasons));
        res.put("budget", budgetMap(out));
        if (k1 != null) {
            List<Object> bound = new ArrayList<>();
            for (CaveatLang.BoundCaveat b : k1.bound) {
                Map<String, Object> bm = new LinkedHashMap<>();
                bm.put("caveat", b.caveat);
                bm.put("hop", b.hop);
                bm.put("capHash", b.capHash);
                bound.add(bm);
            }
            res.put("k1Bound", bound);
        }
        return res;
    }

    /**
     * Assembles a {@link #decide} input from a PCActn plus the resource server's context, so caller and verifier derive the action, node id and
     * chain identically. {@code ctx}: {@code grant} (REQUIRED: the verifier's OWN stored grant, never the artifact's chain root; it is also the chain's
     * trusted root), {@code plan?}, {@code params?} (checked by the caller against the action's params_digest), {@code risk}, {@code budget},
     * {@code chain?}, {@code now}, {@code pqPins?}, {@code goalNodeId?}, {@code subject?}, {@code env?}, {@code caveatContext?}, {@code ageHorizonMs?}.
     * Throws {@link IllegalArgumentException} when there is no grant.
     */
    public static Map<String, Object> deriveDecideInput(Object p, Map<String, Object> ctx) {
        if (ctx == null) throw new IllegalArgumentException("deriveDecideInput: no context");
        Object grant = ctx.get("grant");
        if (!(grant instanceof Map) && !(grant instanceof List)) throw new DecideInputGrantRequired();
        if (p == null) throw new IllegalArgumentException("deriveDecideInput: no PCActn");
        // a member the reference reads as undefined is absent here; a present null stays null
        Map<String, Object> pm = p instanceof Map ? map(p) : new LinkedHashMap<>();
        Map<String, Object> act = pm.get("action") instanceof Map ? map(pm.get("action")) : new LinkedHashMap<>();
        Map<String, Object> inner = new LinkedHashMap<>();
        if (act.containsKey("verb")) inner.put("verb", act.get("verb"));
        if (act.containsKey("resource")) inner.put("resource", act.get("resource"));
        inner.put("params", ctx.get("params") != null ? ctx.get("params") : new LinkedHashMap<String, Object>());
        if (act.containsKey("reversibility_class")) inner.put("reversibility_class", act.get("reversibility_class"));
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("action", inner);
        if (Zk.truthy(ctx.get("subject"))) action.put("subject", ctx.get("subject"));
        if (Zk.truthy(ctx.get("env"))) action.put("env", ctx.get("env"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("grant", grant);
        out.put("trustedRoot", grant);
        if (ctx.containsKey("pqPins")) out.put("pqPins", ctx.get("pqPins"));
        if (ctx.get("chain") != null) out.put("chain", ctx.get("chain"));
        else if (pm.containsKey("cap_chain")) out.put("chain", pm.get("cap_chain"));
        out.put("action", action);
        if (ctx.containsKey("plan")) out.put("plan", ctx.get("plan"));
        Object plan = pm.get("plan");
        if (plan instanceof Map && map(plan).containsKey("node_id")) out.put("nodeId", map(plan).get("node_id"));
        for (String k : new String[] {"goalNodeId", "risk", "budget", "now", "caveatContext", "ageHorizonMs"}) if (ctx.containsKey(k)) out.put(k, ctx.get(k));
        return out;
    }
}
