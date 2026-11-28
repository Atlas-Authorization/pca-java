package net.atlasauth.pca.ap2;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.PcaCore;
import net.atlasauth.pca.Risk;
import net.atlasauth.pca.payments.Payments;
import net.atlasauth.pca.ap2.Chain.MandateIssuer;

/**
 * AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant.
 *
 * <p>PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other
 * parties verify. Settlement rails (x402, Stripe Shared Payment Tokens) move the value, fed by PCA's decision. The package is
 * split as {@link Sdjwt} (SD-JWT and ES256), {@link Mandates} (shapes, validators, minor units), {@link Constraints},
 * {@link Chain} (issue, present, verify), {@link Settlement} and {@link Ledger}; this class holds the PCA binding helpers that
 * need no PCA verifier. A PCA mandate is the JSON object {@code {grant, terms, ...}}; PCA terms are integer minor units of the
 * mandate currency.
 */
public final class Ap2 {
    private Ap2() {}

    /** The AP2 repository commit whose schemas and documentation this package is checked against. */
    public static final String AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";

    public static final int PCA_BINDING_VERSION = 1;

    /** A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused. */
    static double minorTerm(Object v, String name) {
        if (!Js.isSafeInteger(v) || Js.num(v) < 0 || Js.isNegZero(Js.num(v))) {
            throw new Ap2Error("PCA term " + name + " must be a non-negative integer in minor units, got " + Js.str(v));
        }
        return Js.num(v);
    }

    /** {@code JSON.parse(JSON.stringify(v))}: a deep copy through the JSON text. */
    static Object toJson(Object v) {
        String s = Js.stringify(v);
        if (s == null) throw new IllegalArgumentException("\"undefined\" is not valid JSON");
        return Js.jsOrder(Json.parseLenient(s));
    }

    // ---------------------------------------------------------------------------------------------
    // PCA terms -> AP2 open mandates
    // ---------------------------------------------------------------------------------------------

    /** The {@code x_pca} claim of an open mandate: the principal-signed grant and the terms it was minted from. */
    public static Map<String, Object> pcaOpenClaim(Map<String, Object> mandate) {
        return Js.m("v", Js.n(PCA_BINDING_VERSION), "grant", toJson(Js.getU(mandate, "grant")), "terms", toJson(Js.getU(mandate, "terms")));
    }

    /** Options for issuing an open mandate from PCA terms. */
    public static class FromTermsOptions {
        public MandateIssuer issuer;
        public Map<String, Object> agentJwk;
        /** Descriptors for every merchant id in the PCA terms (AP2 needs a name; PCA only holds the id). */
        public List<Object> merchants;
        /** Issued-at, epoch seconds. */
        public double iat = Double.NaN;
        /** Expiry, epoch seconds; must not exceed the PCA period end. Required when the terms have no period end. */
        public Double exp;
        public Supplier<String> salt;
    }

    /** {@link FromTermsOptions} for the open payment mandate. */
    public static final class PaymentFromTermsOptions extends FromTermsOptions {
        public String checkoutReference;
    }

    /** {@link FromTermsOptions} for the open checkout mandate: the acceptable line items. */
    public static final class CheckoutFromTermsOptions extends FromTermsOptions {
        public List<Object> lineItems;
    }

    private static double openExpiry(Map<String, Object> terms, FromTermsOptions o) {
        Double periodEnd = terms.containsKey("periodEnd") ? (Double) Math.floor(Js.num(terms.get("periodEnd")) / 1000) : null;
        Double exp = o.exp != null ? o.exp : periodEnd;
        if (exp == null) throw new Ap2Error("exp is required when the PCA terms have no period end");
        if (periodEnd != null && !(exp <= periodEnd)) throw new Ap2Error("exp must not exceed the PCA period end");
        return exp;
    }

    private static List<Object> merchantsFor(Map<String, Object> terms, List<Object> merchants) {
        List<Object> out = new ArrayList<>();
        for (Object id : Js.arr(terms.get("merchants"))) {
            Object found = null;
            for (Object x : merchants) {
                if (Js.sEq(Js.get(x, "id"), id)) {
                    found = x;
                    break;
                }
            }
            if (found == null) throw new Ap2Error("no merchant descriptor supplied for PCA merchant " + Js.str(id));
            out.add(found);
        }
        return out;
    }

    private static double trunc(double x) { return x < 0 ? Math.ceil(x) : Math.floor(x); }

    /**
     * The value of AP2 {@code payment.budget.max} for a PCA cap in integer minor units. The official AP2 SDK reads it as
     * {@code int(max * 100)} whatever the currency, while the schema calls it an amount, so two readers exist: the SDK
     * (hundredths) and a major-unit reader ({@code max * 10^exponent}). The value emitted never lets EITHER read more than the cap:
     * exponent 0 or 1 (JPY) and 2 (USD): {@code cap / 100}; exponent 3 or more (KWD): {@code cap / 10^exponent}. The double is
     * nudged up by at most a few ulps when {@code cap / divisor} falls just under the exact decimal, so that the SDK's
     * {@code int(max * 100)} is exact (0.29 * 100 is 28.999999999999996 in floating point).
     */
    public static double ap2BudgetMax(Object capMinor, Object currency) {
        double cap = minorTerm(capMinor, "cumulativeCap");
        int e = Mandates.currencyExponent(currency);
        double sdkTarget = e <= 2 ? cap : Math.floor(cap / Math.pow(10, e - 2));
        double d = cap / Math.pow(10, Math.max(e, 2));
        for (int i = 0; i < 8 && d > 0 && trunc(d * 100) < sdkTarget; i++) d = Math.nextUp(d);
        if (trunc(d * 100) != sdkTarget || Js.round(d * Math.pow(10, e)) > cap) {
            throw new Ap2Error("cumulativeCap " + Js.str(Js.n(cap)) + " " + currency + " has no exact AP2 budget.max representation");
        }
        return d;
    }

    /** What the two readers of an AP2 {@code budget.max} read, in minor units of {@code currency}: {@code {sdk, major}}. */
    public static Map<String, Object> ap2BudgetReads(Object max, Object currency) {
        int e = Mandates.currencyExponent(currency);
        if (!Js.isFinite(max) || Js.num(max) < 0) throw new Ap2Error("budget.max must be a finite non-negative number, got " + Js.str(max));
        double m = Js.num(max);
        return Js.m("sdk", Js.n(trunc(m * 100)), "major", Js.n(Js.round(m * Math.pow(10, e))));
    }

    /**
     * The AP2 open payment constraints a set of PCA terms denotes. PCA terms are INTEGER MINOR UNITS of the mandate currency (ISO
     * 4217 exponent per currency: USD 2, JPY 0, KWD 3); {@code amount_range} is in the same minor units. {@code budget.max} is
     * derived exactly by {@link #ap2BudgetMax}; no currency is refused for its exponent.
     */
    public static List<Object> paymentConstraintsFromTerms(Map<String, Object> terms, List<Object> merchants, String checkoutReference) {
        Object cur = Js.getU(terms, "currency");
        double perTx = minorTerm(terms.get("perTransactionCap"), "perTransactionCap");
        double budgetMax = ap2BudgetMax(terms.get("cumulativeCap"), cur);
        List<Object> out = new ArrayList<>();
        out.add(Js.m("type", "payment.amount_range", "currency", cur, "min", Js.n(0), "max", Js.n(perTx)));
        out.add(Js.m("type", "payment.allowed_payees", "allowed", merchantsFor(terms, merchants)));
        out.add(Js.m("type", "payment.reference", "conditional_transaction_id", checkoutReference));
        out.add(Js.m("type", "payment.budget", "currency", cur, "max", Js.n(budgetMax)));
        Map<String, Object> rec = Js.m("type", "payment.agent_recurrence", "frequency", "ON_DEMAND");
        if (terms.containsKey("maxTransactionsPerPeriod")) rec.put("max_occurrences", terms.get("maxTransactionsPerPeriod"));
        out.add(rec);
        return out;
    }

    private static void fill(Chain.OpenMandateCommon c, FromTermsOptions o, double exp, Map<String, Object> pca) {
        c.issuer = o.issuer;
        c.agentJwk = o.agentJwk;
        c.iat = o.iat;
        c.exp = exp;
        c.pca = pca;
        c.salt = o.salt;
    }

    /** Issue the open payment mandate for a PCA mandate (grant + terms), chained to {@code checkoutReference}. */
    public static String openPaymentMandateFromPca(Map<String, Object> mandate, PaymentFromTermsOptions o) {
        Map<String, Object> terms = Js.obj(mandate.get("terms"));
        Chain.OpenPaymentMandateInput in = new Chain.OpenPaymentMandateInput();
        double exp = openExpiry(terms, o);
        Map<String, Object> pca = pcaOpenClaim(mandate);
        in.constraints = paymentConstraintsFromTerms(terms, o.merchants, o.checkoutReference);
        fill(in, o, exp, pca);
        return Chain.issueOpenPaymentMandate(in);
    }

    /** Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items. */
    public static String openCheckoutMandateFromPca(Map<String, Object> mandate, CheckoutFromTermsOptions o) {
        Map<String, Object> terms = Js.obj(mandate.get("terms"));
        Chain.OpenCheckoutMandateInput in = new Chain.OpenCheckoutMandateInput();
        double exp = openExpiry(terms, o);
        Map<String, Object> pca = pcaOpenClaim(mandate);
        List<Object> constraints = new ArrayList<>();
        constraints.add(Js.m("type", "checkout.line_items", "items", o.lineItems));
        constraints.add(Js.m("type", "checkout.allowed_merchants", "allowed", merchantsFor(terms, o.merchants)));
        in.constraints = constraints;
        fill(in, o, exp, pca);
        return Chain.issueOpenCheckoutMandate(in);
    }

    // ---------------------------------------------------------------------------------------------
    // the closed payment: binding facts
    // ---------------------------------------------------------------------------------------------

    /**
     * The value the PCActn's signed {@code nonce} must equal for these AP2 facts: {@code ap2:<hashCanonical({v, ...facts})>}.
     * {@code facts} is {@code {transactionId, payeeId, amount, currency, instrumentId, openHash, agentJkt}}
     * ({@code openHash}: the {@code sd_hash} of the open payment mandate token; {@code agentJkt}: RFC 7638 thumbprint of the
     * agent's AP2 key).
     */
    public static String pcaBindingNonce(Map<String, Object> facts) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", Js.n(PCA_BINDING_VERSION));
        body.putAll(facts);
        return "ap2:" + Pca.hashCanonical(body);
    }

    /**
     * amount / cap, clamped to [0, 1] and rounded UP to 12 decimals. PCA's canonical encoding refuses numbers with more than 15
     * significant digits (so 100/300 cannot be signed as-is); rounding up can only raise the risk the threshold policy sees,
     * never lower it.
     */
    public static double riskRatio(double amount, double cap) {
        double r = cap > 0 ? amount / cap : 1;
        return Math.min(1, Math.max(0, Math.ceil(r * 1e12 - 1e-6) / 1e12));
    }

    // ---------------------------------------------------------------------------------------------
    // the closed payment: PCActn bound to the AP2 mandate
    // ---------------------------------------------------------------------------------------------

    /** Inputs of {@link #buildPcaPaymentBinding}. */
    public static final class PcaPaymentBindingInput {
        /** The PCA mandate (grant + terms + budget) the agent holds. */
        public Map<String, Object> mandate;
        /** The open payment mandate token the closed mandate will be chained to. */
        public String open;
        public Map<String, Object> agentJwk;
        /** The agent's Ed25519 seed (the PCA grant's holder); signs the PCActn. */
        public byte[] agentSecret;
        /** PCA audience (the resource server / Atlas instance id this action is for). */
        public String audience;
        public long counter;
        public String transactionId;
        public Map<String, Object> payee;
        /** {@code {amount, currency}}: integer minor units. */
        public Map<String, Object> amount;
        public String instrumentId;
        public String category;
        /** PCActn {@code iat}, epoch ms (default: now). */
        public Long now;
        /** For a charge that needs a human co-sign: returns the threshold shares over the built PCActn. */
        public Function<Map<String, Object>, Map<String, Object>> cosign;
    }

    /** Build the {@code x_pca} claim of a closed payment mandate: a PCActn authorising exactly this charge. */
    public static Map<String, Object> buildPcaPaymentBinding(PcaPaymentBindingInput i) {
        double major = minorTerm(i.amount.get("amount"), "amount");
        if (!i.payee.containsKey("id")) throw new IllegalArgumentException("canonicalize: unsupported type undefined"); // the nonce hashes payeeId: undefined
        Map<String, Object> charge = Js.m("merchant", i.payee.get("id"), "amount", Js.n(major), "currency", i.amount.get("currency"));
        if (i.category != null) charge.put("category", i.category);
        Map<String, Object> facts = Js.m("transactionId", i.transactionId, "payeeId", i.payee.get("id"), "amount", i.amount.get("amount"), "currency", i.amount.get("currency"),
            "instrumentId", i.instrumentId, "openHash", Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(i.open)), "agentJkt", Sdjwt.jwkThumbprint(i.agentJwk));
        Map<String, Object> terms = Js.obj(Js.obj(i.mandate).get("terms"));
        double risk = riskRatio(major, Js.num(terms.get("perTransactionCap")));
        String nodeId = "ap2:" + i.transactionId;
        Map<String, Object> grant = Js.obj(i.mandate.get("grant"));
        Map<String, Object> node = Payments.chargePlanNode(i.mandate, charge, nodeId);
        Map<String, Object> params = Payments.chargeParams(i.mandate, charge);
        Issue.ActSpec s = new Issue.ActSpec();
        s.grant = grant;
        s.chain = Js.l(grant);
        s.plan = Issue.commitPlan(java.util.Collections.singletonList(node));
        s.nodeId = nodeId;
        s.params = params;
        s.counter = i.counter;
        s.signer = Keys.ed25519(Keys.edFromSeed(i.agentSecret));
        s.aud = i.audience;
        s.nonce = pcaBindingNonce(facts);
        Map<String, Object> inputs = new LinkedHashMap<>(params);
        inputs.put("blastRadius", Js.n(risk));
        s.riskClaim = Js.m("r", Js.n(risk), "inputs", inputs);
        if (i.now != null) s.iat = i.now;
        Map<String, Object> built = Issue.buildPCActn(s);
        Map<String, Object> pcactn = built;
        if (i.cosign != null) {
            pcactn = new LinkedHashMap<>(built);
            pcactn.put("threshold", i.cosign.apply(built));
        }
        Map<String, Object> c2 = Js.m("amount", Js.n(major), "currency", i.amount.get("currency"));
        if (i.category != null) c2.put("category", i.category);
        return Js.m("v", Js.n(PCA_BINDING_VERSION), "charge", c2, "pcactn", toJson(pcactn));
    }

    private static Object findConstraint(Object constraints, String type) {
        for (Object c : Js.arr(constraints)) if (type.equals(Js.get(c, "type"))) return c;
        return null;
    }

    /**
     * Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant). Returns the first
     * problem, or null when every constraint is within the terms.
     */
    public static String constraintsWithinTerms(Map<String, Object> open, Map<String, Object> terms) {
        Object cur = Js.getU(terms, "currency");
        double perTx = minorTerm(terms.get("perTransactionCap"), "perTransactionCap");
        Object cs = open.get("constraints");
        Object range = findConstraint(cs, "payment.amount_range");
        if (range == null) return "open mandate has no amount_range to compare with the PCA per-transaction cap";
        if (!Js.sEq(Js.get(range, "currency"), cur)) return "amount_range currency differs from the PCA terms";
        if (!(Js.num(Js.get(range, "max")) <= perTx)) return "amount_range.max " + Js.str(Js.getU(range, "max")) + " exceeds the PCA per-transaction cap " + Js.str(Js.n(perTx));
        Object payees = findConstraint(cs, "payment.allowed_payees");
        if (payees != null) {
            for (Object m : Js.arr(Js.get(payees, "allowed"))) {
                boolean in = false;
                for (Object id : Js.arr(terms.get("merchants"))) if (Js.sEq(id, Js.get(m, "id"))) in = true;
                if (!in) return "allowed_payees names a merchant outside the PCA allowlist";
            }
        }
        if (payees == null) return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side";
        Object budget = findConstraint(cs, "payment.budget");
        if (budget == null) return "open mandate has no budget to compare with the PCA cumulative cap";
        if (!Js.sEq(Js.get(budget, "currency"), cur)) return "budget exceeds the PCA cumulative cap";
        Map<String, Object> reads = ap2BudgetReads(Js.get(budget, "max"), cur);
        double capMinor = minorTerm(terms.get("cumulativeCap"), "cumulativeCap");
        if (!(Js.num(reads.get("sdk")) <= capMinor) || !(Js.num(reads.get("major")) <= capMinor)) return "budget exceeds the PCA cumulative cap";
        Object rec = findConstraint(cs, "payment.agent_recurrence");
        if (terms.containsKey("maxTransactionsPerPeriod")) {
            Object mo = Js.get(rec, "max_occurrences");
            if (rec == null || !Js.def(rec, "max_occurrences") || !(Js.num(mo) <= Js.num(terms.get("maxTransactionsPerPeriod")))) return "max_occurrences is missing or exceeds the PCA transaction limit";
        }
        if (terms.containsKey("periodEnd") && (!open.containsKey("exp") || !(Js.num(open.get("exp")) <= Math.floor(Js.num(terms.get("periodEnd")) / 1000)))) return "open mandate outlives the PCA period";
        return null;
    }

    // ---------------------------------------------------------------------------------------------
    // verification
    // ---------------------------------------------------------------------------------------------

    /** Inputs of {@link #verifyPcaBinding}. */
    public static final class VerifyPcaBindingInput {
        /** The parsed open payment mandate claims (from the verified AP2 chain). */
        public Map<String, Object> open;
        /** The parsed closed payment mandate claims. */
        public Map<String, Object> closed;
        /** {@code sd_hash} of the open payment mandate hop. */
        public String openHash;
        /** The Ed25519 key (b64u) of the principal who must have signed the grant. */
        public String expectedPrincipal;
        /** Verifier-side PQ pins {@code issuer -> pq_pk}. */
        public Map<String, Object> pqPins;
        /** This verifier's PCA audience. */
        public String audience;
        /** Verification time, epoch ms (null = the clock). */
        public Long now;
        /** The PCA mandate state THIS verifier holds (its live budget); required. */
        public Map<String, Object> mandate;
        /** Epoch-ms times of this holder's earlier admitted charges; required when the mandate limits the charge count. */
        public List<Object> recentChargeTimes;
        public PcaCore.Hooks hooks;
        public PcaCore.Enforce enforce;
    }

    private static Map<String, Object> bindFail(String reason) { return Js.m("ok", Boolean.FALSE, "reason", reason); }

    /**
     * Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent
     * with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience,
     * committing to exactly this AP2 charge). Run it after {@code Chain.verifyPaymentChain}. Returns {@code {ok: true, pcactn, grant, terms}}
     * or {@code {ok: false, reason}}; throws {@link PcaBindingError} when the server-held mandate state is missing.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyPcaBinding(VerifyPcaBindingInput i) {
        if (i == null || !(i.mandate instanceof Map))
            throw new PcaBindingError("mandate_required", "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped");
        if (Js.def(Js.get(i.mandate, "terms"), "maxTransactionsPerPeriod")) {
            boolean ok = i.recentChargeTimes != null;
            if (ok) for (Object t : i.recentChargeTimes) if (!Js.isNumber(t) || Double.isNaN(Js.num(t)) || Double.isInfinite(Js.num(t))) ok = false;
            if (!ok) throw new PcaBindingError("charge_history_required", "the mandate limits the charge count: pass recentChargeTimes from your own records");
        }
        try {
            Object oc = Js.get(i.open, "x_pca");
            if (!(oc instanceof Map) || !Js.sEq(Js.get(oc, "v"), Js.n(PCA_BINDING_VERSION)) || !(Js.get(oc, "grant") instanceof Map) || !(Js.get(oc, "terms") instanceof Map))
                return bindFail("open mandate carries no x_pca grant");
            Map<String, Object> grant = Js.obj(Js.get(oc, "grant"));
            Map<String, Object> terms = Js.obj(Js.get(oc, "terms"));
            String chain = Pca.verifyChain(Js.l(grant), i.expectedPrincipal, true, null, i.pqPins, null);
            if (!chain.isEmpty()) return bindFail("PCA grant: " + chain);
            Map<String, Object> env = Authorize.readEnvelope(grant);
            if (env == null) return bindFail("PCA grant has no envelope");
            if (!Pca.hashCanonical(env.get("predicates")).equals(Pca.hashCanonical(Payments.mandatePredicates(terms)))
                || !Pca.hashCanonical(env.get("caveats")).equals(Pca.hashCanonical(Payments.mandateCaveats(terms)))) return bindFail("x_pca terms do not match the grant envelope");
            Map<String, Object> pol = Js.obj(env.get("risk_policy"));
            if (!Js.sEq(pol.get("kappa"), terms.get("perTransactionCap")) || !Js.sEq(pol.get("bMax"), terms.get("cumulativeCap"))) return bindFail("x_pca terms do not match the grant risk policy");
            String within = constraintsWithinTerms(i.open, terms);
            if (within != null) return bindFail(within);

            Object cc = Js.get(i.closed, "x_pca");
            if (!(cc instanceof Map) || !Js.sEq(Js.get(cc, "v"), Js.n(PCA_BINDING_VERSION)) || !(Js.get(cc, "pcactn") instanceof Map) || !(Js.get(cc, "charge") instanceof Map))
                return bindFail("closed mandate carries no x_pca PCActn");
            Map<String, Object> pcactn = Js.obj(Js.get(cc, "pcactn"));
            Map<String, Object> charge = Js.obj(Js.get(cc, "charge"));
            Object amt = Js.get(i.closed, "payment_amount");
            Object payee = Js.get(i.closed, "payee");
            if (!Js.sEq(charge.get("currency"), Js.get(amt, "currency")) || !Js.sEq(charge.get("amount"), Js.get(amt, "amount"))) return bindFail("x_pca charge differs from the mandate payment_amount");
            List<Object> cats = Js.arr(terms.get("categories"));
            if (!cats.isEmpty()) {
                boolean has = false;
                if (charge.get("category") instanceof String) for (Object c : cats) if (Js.sEq(c, charge.get("category"))) has = true;
                if (!has) return bindFail("x_pca charge lacks an allowed category");
            }

            // the `t` the threshold hook REPORTS it enforced (as the core verifier does): a hook built for a smaller t cannot satisfy a charge that needs more
            PcaCore.Options co = new PcaCore.Options(grant);
            co.planRoots = Pca.PlanRoots.SKIP;
            co.audience(i.audience);
            if (i.now != null) co.nowEpoch = i.now;
            co.hooks = i.hooks;
            co.enforce = i.enforce;
            PcaCore.Result core = PcaCore.verify(pcactn, co);
            if (!core.allow) return bindFail("PCActn: " + (core.reason == null ? "rejected" : core.reason));
            Double enforcedT = core.enforcedT;
            Map<String, Object> act = Js.obj(pcactn.get("action"));
            if (!"charge".equals(act.get("verb")) || !Js.sEq(act.get("resource"), "merchant:" + Js.str(Js.get(payee, "id")))) return bindFail("PCActn action is not a charge at this payee");
            Map<String, Object> params = Js.m("amount", charge.get("amount"), "currency", charge.get("currency"));
            if (charge.get("category") instanceof String) params.put("category", charge.get("category"));
            if (!Js.sEq(act.get("params_digest"), Pca.paramsDigest(params))) return bindFail("PCActn params do not commit to the x_pca charge");
            Object cnf = Js.get(i.open, "cnf");
            if (cnf == null) throw new IllegalStateException("Cannot read properties of " + (Js.def(i.open, "cnf") ? "null" : "undefined") + " (reading 'jwk')");
            Object agentJwk = Js.get(cnf, "jwk");
            Map<String, Object> facts = Js.m("transactionId", Js.get(i.closed, "transaction_id"), "payeeId", Js.get(payee, "id"), "amount", Js.get(amt, "amount"), "currency", Js.get(amt, "currency"),
                "instrumentId", Js.get(Js.get(i.closed, "payment_instrument"), "id"), "openHash", i.openHash, "agentJkt", Sdjwt.jwkThumbprint(agentJwk));
            if (!Js.sEq(pcactn.get("nonce"), pcaBindingNonce(facts))) return bindFail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key");
            if (!(Double.isFinite(Js.num(Js.get(amt, "amount"))) && Js.num(Js.get(amt, "amount")) <= minorTerm(terms.get("perTransactionCap"), "perTransactionCap"))) return bindFail("payment exceeds the PCA per-transaction cap");
            // the agent may not understate the risk of its own charge, and a charge whose risk needs a human co-sign (t > 1) is only accepted with a threshold verifier
            double recomputed = riskRatio(Js.num(Js.get(amt, "amount")), Js.num(terms.get("perTransactionCap")));
            Object claimed = Js.get(pcactn.get("risk_claim"), "r");
            if (!(Js.isNumber(claimed) && Js.num(claimed) >= recomputed - 1e-9)) return bindFail("PCActn understates the risk of this charge");
            Risk.Required need = Risk.requiredThreshold(Js.num(claimed), Js.num(pol.get("theta1")), Js.num(pol.get("theta2")), false);
            if (need.t > 1 && (i.hooks == null || i.hooks.threshold == null)) return bindFail("this charge needs a threshold of " + need.t + " (human co-sign); supply hooks.threshold to verify it");
            if (need.t > 1 && !(enforcedT != null && enforcedT >= need.t)) {
                return bindFail("this charge needs a threshold of " + need.t + " but the threshold hook enforced t=" + (enforcedT == null ? "unreported" : AttestCommon.jsNumString(enforcedT))
                    + "; build it with createThresholdVerifier({ t: " + need.t + " })");
            }
            if (!Js.sEq(Js.get(amt, "currency"), terms.get("currency")) || !containsStr(terms.get("merchants"), Js.get(payee, "id"))) return bindFail("payment currency or payee is outside the PCA terms");

            if (!Pca.hashCanonical(i.mandate.get("grant")).equals(Pca.hashCanonical(grant))) return bindFail("the supplied PCA mandate is not the one in the open mandate");
            // `grant` was verified above under the caller-pinned principal; the decision is bound to it
            Map<String, Object> ch = Js.m("merchant", Js.get(payee, "id"), "amount", Js.get(amt, "amount"), "currency", Js.get(amt, "currency"));
            if (charge.get("category") instanceof String) ch.put("category", charge.get("category"));
            ch.put("recentChargeTimes", i.recentChargeTimes != null ? i.recentChargeTimes : new ArrayList<Object>());
            if (i.now != null) ch.put("now", Js.n(i.now));
            Map<String, Object> decision = Payments.authorizeCharge(i.mandate, ch, grant);
            Object outcome = decision.get("outcome");
            if ("deny".equals(outcome)) {
                List<String> rs = new ArrayList<>();
                for (Object r : Js.arr(decision.get("reasons"))) rs.add(Js.str(r));
                return bindFail("PCA denies this charge: " + String.join("; ", rs));
            }
            if ("step_up".equals(outcome) && !(enforcedT != null && enforcedT >= 2)) return bindFail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced");
            return Js.m("ok", Boolean.TRUE, "pcactn", pcactn, "grant", grant, "terms", terms);
        } catch (RuntimeException e) {
            return bindFail(e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    private static boolean containsStr(Object list, Object v) {
        if (!(list instanceof List)) throw new IllegalStateException("terms.merchants is not an array");
        for (Object x : (List<?>) list) if (Js.sEq(x, v)) return true;
        return false;
    }

    /** Thrown when the PCA binding verifier lacks the server-held state the policy decision needs. */
    public static final class PcaBindingError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** {@code mandate_required} or {@code charge_history_required}. */
        public final String code;

        public PcaBindingError(String code, String message) {
            super(message);
            this.code = code;
        }
    }
}
