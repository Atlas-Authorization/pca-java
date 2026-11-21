package net.atlasauth.pca.payments;

import static net.atlasauth.pca.payments.PayJs.clamp01;
import static net.atlasauth.pca.payments.PayJs.copy;
import static net.atlasauth.pca.payments.PayJs.get;
import static net.atlasauth.pca.payments.PayJs.has;
import static net.atlasauth.pca.payments.PayJs.isFiniteNum;
import static net.atlasauth.pca.payments.PayJs.isSafeInteger;
import static net.atlasauth.pca.payments.PayJs.jn;
import static net.atlasauth.pca.payments.PayJs.map;
import static net.atlasauth.pca.payments.PayJs.nz;
import static net.atlasauth.pca.payments.PayJs.str;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Payment mandates over PCA Root Intent Grants, the charge decision and the durable cumulative budget (the reference's
 * mandate, authorize and charge-action modules). A mandate, a charge and every decision are JSON-shaped maps, exactly the
 * reference's objects: numbers are {@link net.atlasauth.pca.Json.Num} (or any Java number), bytes are {@code byte[]} or
 * {@code {"$bytes": b64url}}.
 *
 * <p>The policy decision (the reference's {@code decide}) defaults to {@link net.atlasauth.pca.Decide#decide}; a caller may supply its own {@link Decider}: this port
 * assembles its exact input ({@link #chargeDecideInput}) and applies everything after it (refusals, outcome, exact money
 * arithmetic, budget threading, the atomic budget store).
 */
public final class Payments {
    private Payments() {}

    /** Reversibility class every charge is minted in. */
    public static final String CHARGE_REVERSIBILITY_CLASS = "reversible";
    /** The action verb a charge denotes. */
    public static final String CHARGE_VERB = "charge";
    /** Reason on a charge whose amount is not a non-negative safe integer (minor units). */
    public static final String AMOUNT_NOT_MINOR_UNITS = "amount_not_integer_minor_units";
    /** Reason on a charge whose merchant is not a plain non-empty id. */
    public static final String MERCHANT_INVALID = "merchant_invalid";

    private static final int MAX_CAS_ATTEMPTS = 8;

    /** The policy decision: takes the decide input map, returns the policy decision map (releaseGuardianShare, requiredThreshold, r, admit, needStepUp, reasons, budget). */
    @FunctionalInterface
    public interface Decider {
        Map<String, Object> decide(Map<String, Object> input);
    }

    // ---- mandate ---------------------------------------------------------------------------------------------------------

    /** A merchant id that cannot act as a resource pattern: a non-empty string with no {@code *} and no control characters. */
    public static boolean isPlainId(Object x) {
        if (!(x instanceof String) || ((String) x).isEmpty()) return false;
        String s = (String) x;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '*' || c <= 0x1f || c == 0x7f) return false;
        }
        return true;
    }

    /** String(m[k]) where an absent member reads as undefined. */
    private static String strOf(Map<String, Object> m, String k) { return m != null && m.containsKey(k) ? str(m.get(k)) : "undefined"; }

    private static Double fin(Object o) { return isFiniteNum(o) ? PayJs.num(o) : null; }

    private static void bad(String msg) { throw new IllegalArgumentException("buildPaymentMandate: " + msg); }

    private static void validate(Map<String, Object> p) {
        if (!Boolean.FALSE.equals(p.get("strictMinorUnits"))) {
            Object rep = p.get("replenishPerCosign");
            Object[][] kv = {{"perTransactionCap", p.get("perTransactionCap")}, {"autoApproveThreshold", p.get("autoApproveThreshold")},
                {"cumulativeCap", p.get("cumulativeCap")}, {"replenishPerCosign", rep == null ? Long.valueOf(0) : rep}};
            for (Object[] e : kv)
                if (!isSafeInteger(e[1])) bad(e[0] + " must be a safe integer in minor units (strictMinorUnits)");
        }
        Object ms = p.get("merchants");
        if (!(ms instanceof List) || ((List<?>) ms).isEmpty()) bad("at least one allowlisted merchant is required");
        for (Object m : (List<?>) ms) if (!(m instanceof String) || ((String) m).isEmpty()) bad("merchant ids must be non-empty strings");
        for (Object m : (List<?>) ms) if (!isPlainId(m)) bad("merchant ids must not contain `*` or control characters");
        Object cur = p.get("currency");
        if (!(cur instanceof String) || ((String) cur).isEmpty()) bad("currency is required");
        Double x = fin(p.get("perTransactionCap"));
        if (x == null || x <= 0) bad("perTransactionCap (X) must be a finite number > 0");
        Double y = fin(p.get("autoApproveThreshold"));
        if (y == null || y < 0 || y > x) bad("autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X");
        Double cap = fin(p.get("cumulativeCap"));
        if (cap == null || cap < x) bad("cumulativeCap must be a finite number ≥ perTransactionCap (X)");
        if (p.containsKey("periodMs")) {
            Double d = fin(p.get("periodMs"));
            if (d == null || d <= 0) bad("periodMs must be a finite number > 0 when given");
        }
        if (p.containsKey("maxTransactionsPerPeriod")) {
            Object o = p.get("maxTransactionsPerPeriod");
            Double d = fin(o);
            if (d == null || d != Math.rint(d) || d <= 0) bad("maxTransactionsPerPeriod must be a positive integer when given");
        }
        if (p.containsKey("replenishPerCosign")) {
            Double d = fin(p.get("replenishPerCosign"));
            if (d == null || d < 0) bad("replenishPerCosign must be a finite number ≥ 0 when given");
        }
    }

    @SuppressWarnings("unchecked")
    /** {@code params.categories ? [...params.categories] : []}: a falsy value is none, a string spreads by code point, a non-iterable throws. */
    private static List<Object> spreadCategories(Object cats) {
        if (!PayJs.truthy(cats)) return new ArrayList<>();
        if (cats instanceof String) {
            List<Object> out = new ArrayList<>();
            ((String) cats).codePoints().forEach(cp -> out.add(new String(Character.toChars(cp))));
            return out;
        }
        return new ArrayList<>(listOf(cats, "categories"));
    }

    private static List<Object> listOf(Object o, String what) {
        if (!(o instanceof List)) throw new IllegalArgumentException(what + " must be a list");
        return (List<Object>) o;
    }

    /** The allowlist predicates: one per merchant, each carrying the currency, category and hard-ceiling guards. */
    public static List<Object> mandatePredicates(Map<String, Object> terms) {
        List<Object> merchants = listOf(terms.get("merchants"), "terms.merchants");
        List<Object> out = new ArrayList<>();
        for (Object m : merchants) {
            Map<String, Object> c1 = map("field", "action.params.amount", "op", "lte");
            PayJs.putTerm(c1, "value", terms, "perTransactionCap");
            Map<String, Object> c2 = map("field", "action.params.currency", "op", "eq");
            PayJs.putTerm(c2, "value", terms, "currency");
            List<Object> conds = PayJs.list(c1, c2, map("field", "action.params.amount", "op", "gte", "value", new net.atlasauth.pca.Json.Num("0")));
            Object cats = terms.get("categories");
            if (cats == null) throw new IllegalArgumentException("terms.categories must not be null");
            if (PayJs.jsLength(cats) > 0) conds.add(map("field", "action.params.category", "op", "in", "value", cats));
            out.add(map("verb", "charge", "resource", "merchant:" + str(m), "where", conds));
        }
        return out;
    }

    /** The envelope caveats: period window, velocity cap, and the reversibility floor. */
    public static List<Object> mandateCaveats(Map<String, Object> terms) {
        List<Object> cs = new ArrayList<>();
        if (PayJs.numOf(terms, "periodStart") > 0) cs.add(map("type", "not_before", "at", terms.get("periodStart")));
        boolean hasEnd = terms.containsKey("periodEnd");
        if (hasEnd) cs.add(map("type", "expires", "at", terms.get("periodEnd")));
        if (terms.containsKey("maxTransactionsPerPeriod") && hasEnd) {
            double a = PayJs.numOf(terms, "periodEnd") - PayJs.numOf(terms, "periodStart");
            double secs = Math.max(1, jsRound(a / 1000));
            if (Double.isNaN(a)) secs = Double.NaN;
            cs.add(map("type", "rate", "max", terms.get("maxTransactionsPerPeriod"), "per_secs", jn(secs)));
        }
        cs.add(map("type", "reversibility_max", "class", "reversible"));
        return cs;
    }

    private static double nzNaN(Double d) { return d == null ? Double.NaN : d; }

    /** Math.round of JavaScript: floor(x + 0.5), NaN and the infinities unchanged. */
    private static double jsRound(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x)) return x;
        double f = Math.floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    /** The risk policy that makes "spend = risk" exact (only gamma is weighted; theta1 = theta2 = Y/X; kappa = X; bMax = cumulative cap). */
    public static Map<String, Object> mandateRiskPolicy(Map<String, Object> terms, Object replenishPerCosign) {
        Object theta = jn(PayJs.numOf(terms, "autoApproveThreshold") / PayJs.numOf(terms, "perTransactionCap"));
        Map<String, Object> out = map("weights", map("alpha", jn(0), "beta", jn(0), "gamma", jn(1), "delta", jn(0), "epsilon", jn(0), "zeta", jn(0)), "theta1", theta, "theta2", theta);
        PayJs.putTerm(out, "kappa", terms, "perTransactionCap");
        out.put("lambda", jn(0));
        out.put("rho", replenishPerCosign);
        PayJs.putTerm(out, "bMax", terms, "cumulativeCap");
        return out;
    }

    /** The most an agent can spend autonomously between two human co-signs: safetyBound(policy) * kappa. */
    public static double autoSpendBound(Map<String, Object> mandate) {
        Map<String, Object> pol = PayJs.copy(get(mandate, "policy"));
        double kappa = nzNaN(PayJs.num(pol.get("kappa")));
        double bMax = nzNaN(PayJs.num(pol.get("bMax")));
        double bound = kappa > 0 ? Math.max(0, bMax) / kappa : 0;
        return bound * kappa;
    }

    /** Build a payment mandate: the params as a Root Intent Grant envelope plus the initial trust budget. */
    public static Map<String, Object> buildPaymentMandate(Map<String, Object> params) {
        validate(params);
        double now = isFiniteNum(params.get("now")) ? PayJs.num(params.get("now")) : (double) System.currentTimeMillis();
        double periodStart = isFiniteNum(params.get("periodStart")) ? PayJs.num(params.get("periodStart")) : now;
        Object cats = params.get("categories");
        Map<String, Object> terms = new java.util.LinkedHashMap<>();
        terms.put("merchants", new ArrayList<>((List<?>) params.get("merchants")));
        terms.put("categories", spreadCategories(cats));
        terms.put("currency", params.get("currency"));
        terms.put("perTransactionCap", params.get("perTransactionCap"));
        terms.put("autoApproveThreshold", params.get("autoApproveThreshold"));
        terms.put("cumulativeCap", params.get("cumulativeCap"));
        terms.put("periodStart", jn(periodStart));
        if (params.containsKey("periodMs")) terms.put("periodEnd", jn(periodStart + PayJs.num(params.get("periodMs"))));
        if (params.containsKey("maxTransactionsPerPeriod")) terms.put("maxTransactionsPerPeriod", params.get("maxTransactionsPerPeriod"));
        Object rep = params.get("replenishPerCosign");
        Map<String, Object> policy = mandateRiskPolicy(terms, rep == null ? params.get("cumulativeCap") : rep);

        Object g = params.get("goal");
        Object goalO = g != null ? g : "spend ≤ " + str(terms.get("autoApproveThreshold")) + " " + str(terms.get("currency")) + " autonomously / ≤ "
            + str(terms.get("perTransactionCap")) + " with co-sign, ≤ " + str(terms.get("cumulativeCap")) + " cumulative, at ["
            + joinStr((List<?>) terms.get("merchants")) + "]";
        if (!(goalO instanceof String) || ((String) goalO).isEmpty()) throw new IllegalArgumentException("mintGrant: goal required");

        byte[] seed = PayJs.bytes(params.get("principalSecret"));
        if (seed == null) throw new IllegalArgumentException("buildPaymentMandate: principalSecret is required");
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(seed));
        if (!principal.id().equals(params.get("principalPublic"))) throw new IllegalArgumentException("buildPaymentMandate: principalPublic does not match principalSecret");
        Object salt = params.get("goalSalt");
        Map<String, Object> envelope = map("predicates", mandatePredicates(terms), "caveats", mandateCaveats(terms), "agent_binding", map(), "risk_policy", policy);
        Issue.Grant grant = Issue.mintGrant(principal, (String) params.get("agentPublic"), null, envelope, (String) goalO, salt instanceof String ? (String) salt : null);

        return map("grant", grant.grant, "policy", policy, "budget", map("B", terms.get("cumulativeCap"), "tau", jn(now), "asOf", jn(now)),
            "terms", terms, "goalCommit", grant.goalCommit, "goalSalt", grant.goalSalt);
    }

    private static String joinStr(List<?> l) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(", ");
            if (l.get(i) != null) sb.append(str(l.get(i)));
        }
        return sb.toString();
    }

    // ---- charge action ---------------------------------------------------------------------------------------------------

    /** True for a non-negative safe integer that is not -0 (amounts are integer minor units). */
    public static boolean isMinorUnits(Object x) {
        return isSafeInteger(x) && PayJs.num(x) >= 0 && !PayJs.isNegZero(x);
    }

    private static Object currencyOf(Map<String, Object> mandate, Map<String, Object> charge) {
        return has(charge, "currency") ? charge.get("currency") : get(get(mandate, "terms"), "currency");
    }

    /** The action context a charge denotes (the verb, resource and params the predicates and risk read). */
    public static Map<String, Object> chargeActionContext(Map<String, Object> mandate, Map<String, Object> charge) {
        Map<String, Object> params = new java.util.LinkedHashMap<>();
        if (has(charge, "amount")) params.put("amount", charge.get("amount"));
        params.put("currency", currencyOf(mandate, charge));
        if (has(charge, "category")) params.put("category", charge.get("category"));
        return map("action", map("verb", CHARGE_VERB, "resource", "merchant:" + strOf(charge, "merchant"), "params", params, "reversibility_class", CHARGE_REVERSIBILITY_CLASS));
    }

    /** The charge params committed in both the plan node and the PCActn action. */
    public static Map<String, Object> chargeParams(Map<String, Object> mandate, Map<String, Object> charge) {
        Map<String, Object> params = new java.util.LinkedHashMap<>();
        if (has(charge, "amount")) params.put("amount", charge.get("amount"));
        params.put("currency", currencyOf(mandate, charge));
        if (has(charge, "category")) params.put("category", charge.get("category"));
        return params;
    }

    /** The committed plan node for a charge; its params_digest is pinned to the charge params. */
    public static Map<String, Object> chargePlanNode(Map<String, Object> mandate, Map<String, Object> charge, String id) {
        return map("id", id, "verb", CHARGE_VERB, "resource", "merchant:" + strOf(charge, "merchant"), "reversibility_class", CHARGE_REVERSIBILITY_CLASS,
            "params_digest", Pca.paramsDigest(chargeParams(mandate, charge)));
    }

    /**
     * A signed PCActn for a charge: returns {@code {pcactn, node}}. {@code opts}: signerSecret (32-byte Ed25519 seed), aud, counter,
     * and optionally chain, nodeId, now.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> chargeToPCActn(Map<String, Object> mandate, Map<String, Object> charge, Map<String, Object> opts) {
        if (!isMinorUnits(charge.get("amount"))) throw new IllegalArgumentException("chargeToPCActn: amount must be a non-negative integer in minor units");
        Object nid = opts.get("nodeId");
        String nodeId = nid != null ? (String) nid : "charge:" + strOf(charge, "merchant") + ":" + str(opts.get("counter"));
        Map<String, Object> node = chargePlanNode(mandate, charge, nodeId);
        Double X = PayJs.num(get(get(mandate, "terms"), "perTransactionCap"));
        double x = X == null ? Double.NaN : X;
        Double a = PayJs.num(charge.get("amount"));
        double amount = a != null && isFiniteNum(a) ? a : x;
        double r = clamp01(x > 0 ? amount / x : 1);
        Map<String, Object> params = chargeParams(mandate, charge);
        Object ch = opts.get("chain");
        List<Object> chain = ch != null ? (List<Object>) ch : PayJs.list(get(mandate, "grant"));
        Issue.ActSpec s = new Issue.ActSpec();
        s.grant = (Map<String, Object>) chain.get(0);
        s.chain = chain;
        List<Map<String, Object>> nodes = new ArrayList<>();
        nodes.add(node);
        s.plan = Issue.commitPlan(nodes);
        s.nodeId = nodeId;
        s.params = params;
        s.counter = (long) (double) PayJs.num(opts.get("counter"));
        byte[] seed = PayJs.bytes(opts.get("signerSecret"));
        if (seed == null) throw new IllegalArgumentException("chargeToPCActn: signerSecret is required");
        s.signer = Keys.ed25519(Keys.edFromSeed(seed));
        s.aud = (String) opts.get("aud");
        if (opts.get("now") != null) s.iat = (long) (double) PayJs.num(opts.get("now"));
        Map<String, Object> inputs = new java.util.LinkedHashMap<>(params);
        inputs.put("blastRadius", jn(r));
        s.riskClaim = map("r", jn(r), "inputs", inputs);
        return map("pcactn", Issue.buildPCActn(s), "node", node);
    }

    // ---- authorize -------------------------------------------------------------------------------------------------------

    private static double numOr(Object x, double fallback) { return isFiniteNum(x) ? PayJs.num(x) : fallback; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bindToVerifiedGrant(Map<String, Object> mandate, Object verifiedGrant) {
        if (!PayJs.isObj(verifiedGrant)) throw new MandateGrantError("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority");
        if (mandate == null || !Pca.hashCanonical(mandate.get("grant")).equals(Pca.hashCanonical(verifiedGrant)))
            throw new MandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant");
        Map<String, Object> env = Authorize.readEnvelope(verifiedGrant);
        boolean ok = env != null && PayJs.truthy(mandate.get("terms")) && PayJs.truthy(mandate.get("policy"));
        if (ok) {
            Map<String, Object> terms = (Map<String, Object>) mandate.get("terms");
            ok = same(env.get("predicates"), mandatePredicates(terms)) && same(env.get("caveats"), mandateCaveats(terms)) && same(env.get("risk_policy"), mandate.get("policy"));
        }
        if (!ok) throw new MandateGrantError("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant");
        Object bMaxO = get(env.get("risk_policy"), "bMax");
        double bMax = nzNaN(PayJs.num(bMaxO));
        Object b0 = get(mandate.get("budget"), "B");
        double B = isFiniteNum(b0) ? Math.max(0, Math.min(PayJs.num(b0), bMax)) : 0;
        Map<String, Object> budget = copy(mandate.get("budget"));
        budget.put("B", jn(B));
        Map<String, Object> out = copy(mandate);
        out.put("grant", verifiedGrant);
        out.put("budget", budget);
        return out;
    }

    private static boolean same(Object a, Object b) { return Pca.hashCanonical(a).equals(Pca.hashCanonical(b)); }

    /** The decide input for a charge: risk is collapsed to the normalized amount (spend = risk). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> chargeDecideInput(Map<String, Object> mandate0, Map<String, Object> charge, double now, Object verifiedGrant) {
        Map<String, Object> mandate = bindToVerifiedGrant(mandate0, verifiedGrant);
        Double X = PayJs.num(get(mandate.get("terms"), "perTransactionCap"));
        double amount = numOr(charge.get("amount"), Double.POSITIVE_INFINITY);
        double blast = X != null && X > 0 ? amount / X : 1;
        Map<String, Object> cav = map("reversibilityClass", CHARGE_REVERSIBILITY_CLASS);
        if (has(charge, "recentChargeTimes")) cav.put("recentActionTimes", charge.get("recentChargeTimes"));
        return map("grant", verifiedGrant, "action", chargeActionContext(mandate, charge),
            "risk", map("semanticDistance", jn(0), "reversibility", jn(1), "blastRadius", jn(blast), "taint", jn(0), "confidence", jn(1), "age", jn(0)),
            "budget", mandate.get("budget"), "now", jn(now), "caveatContext", cav);
    }

    private static double budgetCost(double r, double kappa) {
        return nz(kappa) * clamp01(Double.isNaN(r) || Double.isInfinite(r) ? 1 : r);
    }

    /**
     * Run a charge through the PCA decision against the grant the caller VERIFIED (or loaded from its own store). Pure: reads the
     * mandate budget (clamped to the signed bMax) and returns the next budget in {@code budgetAfter}. Throws {@link MandateGrantError}
     * when there is no verified grant or the mandate's grant, terms or policy are not that grant's; never throws on a charge.
     */
    public static Map<String, Object> authorizeCharge(Map<String, Object> mandate0, Map<String, Object> charge, Object verifiedGrant) {
        return authorizeCharge(mandate0, charge, verifiedGrant, null);
    }

    /** {@link #authorizeCharge(Map, Map, Object)} with the decision supplied by the caller (null = the core {@link net.atlasauth.pca.Decide#decide}). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> authorizeCharge(Map<String, Object> mandate0, Map<String, Object> charge, Object verifiedGrant, Decider decider) {
        Map<String, Object> mandate = bindToVerifiedGrant(mandate0, verifiedGrant);
        double now = numOr(charge.get("now"), (double) System.currentTimeMillis());
        Map<String, Object> raw = (decider != null ? decider : (Decider) net.atlasauth.pca.Decide::decide).decide(chargeDecideInput(mandate, charge, now, verifiedGrant));
        String refusal = !isMinorUnits(charge.get("amount")) ? AMOUNT_NOT_MINOR_UNITS : !isPlainId(charge.get("merchant")) ? MERCHANT_INVALID : null;
        Map<String, Object> decision;
        if (refusal == null) {
            decision = raw;
        } else {
            decision = copy(raw);
            decision.put("admit", false);
            decision.put("releaseGuardianShare", false);
            List<Object> reasons = new ArrayList<>();
            reasons.add(refusal);
            Object rr = raw.get("reasons");
            if (rr instanceof List) reasons.addAll((List<Object>) rr);
            decision.put("reasons", reasons);
            decision.put("budget", mandate.get("budget"));
        }
        String outcome;
        if (!PayJs.truthy(decision.get("releaseGuardianShare"))) outcome = "deny";
        else if (PayJs.truthy(decision.get("admit"))) outcome = "auto";
        else outcome = "step_up";

        Object kappa = get(mandate.get("policy"), "kappa");
        Object cap = get(mandate.get("terms"), "perTransactionCap");
        Object budget = mandate.get("budget");
        boolean exact = outcome.equals("auto") && isMinorUnits(charge.get("amount")) && isFiniteNum(kappa) && isFiniteNum(cap)
            && PayJs.num(kappa).doubleValue() == PayJs.num(cap).doubleValue() && isSafeInteger(get(budget, "B"));
        Object cost = outcome.equals("auto") ? (exact ? charge.get("amount") : jn(budgetCost(nzNaN(PayJs.num(decision.get("r"))), nzNaN(PayJs.num(kappa))))) : jn(0);
        Object budgetAfter;
        if (exact) {
            Map<String, Object> b = copy(decision.get("budget"));
            b.put("B", jn(PayJs.num(get(budget, "B")) - PayJs.num(charge.get("amount"))));
            budgetAfter = b;
        } else {
            budgetAfter = decision.get("budget");
        }
        Object rt = decision.get("requiredThreshold");
        return map("outcome", outcome, "t", get(rt, "t"), "r", decision.get("r"), "requiredThreshold", rt, "cost", cost, "budgetBefore", budget,
            "budgetAfter", budgetAfter, "reasons", decision.get("reasons"), "decision", decision);
    }

    /** Advance the mandate's budget after a decision (functional): the decision's budgetAfter becomes the mandate budget. */
    public static Map<String, Object> settleCharge(Map<String, Object> mandate, Map<String, Object> decision) {
        Map<String, Object> out = copy(mandate);
        out.put("budget", decision.get("budgetAfter"));
        return out;
    }

    /** Apply a human co-sign: restore autonomous budget by rho (partial) or fully re-confirm to bMax. The ONLY way the budget goes up. */
    public static Map<String, Object> applyHumanCosign(Map<String, Object> mandate, double now, boolean full) {
        Object pol = mandate.get("policy");
        double bMax = nzNaN(PayJs.num(get(pol, "bMax")));
        Object budget;
        if (full) {
            budget = map("B", jn(nz(bMax)), "tau", jn(now), "asOf", jn(now));
        } else {
            double rho = nz(nzNaN(PayJs.num(get(pol, "rho"))));
            Object bo = mandate.get("budget");
            if (bo == null) throw new IllegalArgumentException("applyHumanCosign: the mandate has no budget");
            Object bv = get(bo, "B");
            boolean absent = !PayJs.has(bo, "B");
            double sum;
            // JavaScript '+': a string, array or object operand concatenates, anything else adds
            if (bv instanceof String || bv instanceof List || bv instanceof Map) sum = PayJs.toNumber(str(bv) + str(jn(rho)));
            else sum = absent ? Double.NaN : PayJs.toNumber(bv) + rho;
            budget = map("B", jn(Math.min(nz(bMax), sum)), "tau", jn(now), "asOf", jn(now));
        }
        Map<String, Object> out = copy(mandate);
        out.put("budget", budget);
        return out;
    }

    private static boolean validRecord(ChargeBudgetStore.Record r) {
        if (r == null || !PayJs.isSafeInteger(r.version) || PayJs.isNegZero(r.version)) return false;
        Object b = r.budget;
        return b instanceof Map && isFiniteNum(get(b, "B")) && isFiniteNum(get(b, "tau")) && isFiniteNum(get(b, "asOf"));
    }

    /**
     * {@link #authorizeCharge} against the DURABLE cumulative budget in {@code store}: the debit of an auto charge is committed with an
     * atomic compare-and-set before it is returned, so two concurrent charges cannot both spend the same budget; losing the race
     * re-reads and re-decides. A malformed store throws {@link ChargeStoreError}; persistent contention returns a deny. {@code key} null = the grant hash.
     */
    public static Map<String, Object> authorizeChargeAtomic(Map<String, Object> mandate, Map<String, Object> charge, Object verifiedGrant, ChargeBudgetStore store, String key) {
        return authorizeChargeAtomic(mandate, charge, verifiedGrant, store, key, null);
    }

    /** {@link #authorizeChargeAtomic(Map, Map, Object, ChargeBudgetStore, String)} with the decision supplied by the caller (null = the core decision). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> authorizeChargeAtomic(Map<String, Object> mandate, Map<String, Object> charge, Object verifiedGrant, ChargeBudgetStore store, String key, Decider decider) {
        if (store == null) throw new ChargeStoreError("a ChargeBudgetStore with get and compareAndSet is required");
        String k = key != null ? key : Pca.hashCanonical(verifiedGrant);
        for (int i = 0; i < MAX_CAS_ATTEMPTS; i++) {
            ChargeBudgetStore.Record rec = store.get(k);
            if (rec != null && !validRecord(rec)) throw new ChargeStoreError("the store returned a malformed budget record");
            Map<String, Object> m = rec != null ? withBudget(mandate, rec.budget) : mandate;
            Map<String, Object> d = authorizeCharge(m, charge, verifiedGrant, decider);
            if (!"auto".equals(d.get("outcome"))) return d;
            if (store.compareAndSet(k, rec == null ? null : rec.version, (Map<String, Object>) d.get("budgetAfter"))) return d;
        }
        Map<String, Object> d = authorizeCharge(mandate, charge, verifiedGrant, decider);
        Map<String, Object> out = copy(d);
        out.put("outcome", "deny");
        out.put("t", new net.atlasauth.pca.Json.Num("3"));
        out.put("cost", jn(0));
        out.put("budgetAfter", d.get("budgetBefore"));
        List<Object> reasons = new ArrayList<>();
        reasons.add("budget_store_conflict");
        if (d.get("reasons") instanceof List) reasons.addAll((List<Object>) d.get("reasons"));
        out.put("reasons", reasons);
        return out;
    }

    private static Map<String, Object> withBudget(Map<String, Object> mandate, Object budget) {
        Map<String, Object> m = copy(mandate);
        m.put("budget", budget);
        return m;
    }

    /**
     * {@link #applyHumanCosign} against the DURABLE budget in {@code store}, committed with a compare-and-set. Call it only after you have
     * verified the human co-sign. Persistent contention throws (a co-sign is never silently dropped). {@code key} null = the grant hash.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> applyHumanCosignAtomic(Map<String, Object> mandate, Object verifiedGrant, ChargeBudgetStore store, double now, boolean full, String key) {
        if (store == null) throw new ChargeStoreError("a ChargeBudgetStore with get and compareAndSet is required");
        String k = key != null ? key : Pca.hashCanonical(verifiedGrant);
        for (int i = 0; i < MAX_CAS_ATTEMPTS; i++) {
            ChargeBudgetStore.Record rec = store.get(k);
            if (rec != null && !validRecord(rec)) throw new ChargeStoreError("the store returned a malformed budget record");
            Map<String, Object> bound = bindToVerifiedGrant(rec != null ? withBudget(mandate, rec.budget) : mandate, verifiedGrant);
            Map<String, Object> next = (Map<String, Object>) applyHumanCosign(bound, now, full).get("budget");
            if (store.compareAndSet(k, rec == null ? null : rec.version, next)) return next;
        }
        throw new ChargeStoreError("could not commit the co-sign: the budget record kept changing");
    }

    /**
     * Opens a challenge-windowed bonded claim for a charge's PCActn: if the charge is later disputed, a fraud proof slashes the bond and
     * the charge is rolled back. Thin wrapper over {@link net.atlasauth.pca.Optimistic#openOptimistic}; REFUSES (throws) an irreversible charge.
     */
    public static Map<String, Object> openChargeBond(Map<String, Object> pcactn, net.atlasauth.pca.Optimistic.OpenOptions opts, net.atlasauth.pca.Keys.EdKey signer) {
        return net.atlasauth.pca.Optimistic.openOptimistic(pcactn, opts, signer);
    }
}
