package net.atlasauth.pca.harness;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;
import net.atlasauth.pca.revoke.JsVal;

/**
 * "Attest the mediator, not the weights". The trusted computing base is this small orchestration harness, not an opaque model: the
 * model is an untrusted oracle that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the trust
 * budget before any candidate becomes a signed PCActn. The oracle holds no signing key.
 */
public final class Harness {
    /** The ordered manifest of checks the harness enforces before signing; folded into {@link #harnessMeasurement()}. */
    public static final List<String> ENFORCED_CHECKS = Collections.unmodifiableList(Arrays.asList(
        "plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign"));

    /** Semantic version of the harness's policy-relevant surface. Bump changes the measurement. */
    public static final String HARNESS_VERSION = "0.1.0";

    /** The model identifier stamped into an emitted PCActn's {@code attestation.model_id} when attestation is enabled. */
    public static final String HARNESS_MODEL_ID = "@atlasauth/pca-harness";

    /**
     * Pure, deterministic self-measurement: a SHA-256 digest (base64url) over the version, the enforced-checks manifest and the
     * risk-policy identity. {@code policy} must carry {@code weights}, {@code theta1}, {@code theta2} and {@code kappa} (a missing
     * one throws, as the reference's canonical form refuses an undefined member).
     */
    public static String computeHarnessMeasurement(Object version, Object enforcedChecks, Object policy) {
        if (policy == null) throw new JsVal.TypeError("policy is null");
        Map<String, Object> rp = new LinkedHashMap<>();
        for (String k : new String[] {"weights", "theta1", "theta2", "kappa"}) {
            if (!JsVal.has(policy, k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            rp.put(k, JsVal.opt(policy, k));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("harness", "@atlasauth/pca-harness");
        m.put("version", version);
        m.put("enforces", enforcedChecks);
        m.put("risk_policy", rp);
        return Pca.hashCanonical(m);
    }

    // ---- allowlisting verifier ------------------------------------------------------------------------------------------

    /**
     * Build the mediator attestation verifier hook: a function from the verify context ({@code {pcactn: {attestation: ...}}}) to a
     * hook result ({@code {enforced, ok?, reason?}}). Fail closed throughout: an empty allowlist accepts nothing; an absent measurement
     * fails unless {@code required} is false; a pinned {@code model_id} must match; a present measurement that is not allowlisted always fails.
     * {@code config}: {@code measurements}, {@code required} (default true), {@code expectedModelId} (true or a string).
     */
    public static Function<Object, Map<String, Object>> createHarnessAttestationVerifier(Object config) {
        Object ms = JsVal.member(config, "measurements");
        Set<Object> allow = new HashSet<>();
        if (ms instanceof List) for (Object x : (List<?>) ms) if (x instanceof String && !((String) x).isEmpty()) allow.add(x);
        boolean required = !Boolean.FALSE.equals(JsVal.opt(config, "required"));
        Object em = JsVal.opt(config, "expectedModelId");
        String expected = Boolean.TRUE.equals(em) ? HARNESS_MODEL_ID : em instanceof String && !((String) em).isEmpty() ? (String) em : null;
        return ctx -> {
            if (allow.isEmpty()) return hook(true, false, "harness attestation configured with an empty measurement allowlist (fail closed)");
            Object att = JsVal.opt(JsVal.opt(ctx, "pcactn"), "attestation");
            Object mv = JsVal.opt(att, "measurement");
            String measurement = mv instanceof String ? (String) mv : "";
            if (measurement.isEmpty()) {
                return required ? hook(true, false, "harness attestation required but the PCActn carries no harness measurement (fail closed)") : hookNotEnforced();
            }
            if (expected != null && !expected.equals(JsVal.opt(att, "model_id"))) {
                return hook(true, false, "attestation.model_id '" + JsVal.strMember(att, "model_id") + "' is not the required harness identity '" + expected + "'");
            }
            if (!allow.contains(measurement)) return hook(true, false, "harness measurement is not in the allowlisted set (unattested or unknown mediator)");
            return hook(true, true, null);
        };
    }

    private static Map<String, Object> hook(boolean enforced, boolean ok, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enforced", enforced);
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    private static Map<String, Object> hookNotEnforced() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enforced", Boolean.FALSE);
        return m;
    }

    // ---- the harness ----------------------------------------------------------------------------------------------------

    /** Construction options. Fields that the reference validates at runtime are {@code Object} so a malformed value is refused the same way. */
    public static final class Options {
        /** The principal-signed root capability (a JSON object); only its {@code id} is read. */
        public Map<String, Object> grant;
        /** The capability chain ending at the leaf the harness signs for; null means {@code [grant]}. */
        public List<Object> chain;
        /** The 32-byte Ed25519 seed of the leaf holder. The oracle never sees it. */
        public byte[] agentSeed;
        /** The principal-authorised, committed plan: a non-empty list of nodes. */
        public Object plan;
        /** The audience the PCActns are for (a non-empty string). */
        public Object audience;
        /** The decaying trust budget {@code {B, tau, asOf}}. */
        public Object budget;
        /** The risk policy; null means the reference default. */
        public Map<String, Object> policy;
        /** Base risk inputs before taint folding; null means the low, reversible default profile. */
        public Map<String, Object> baseRisk;
        /** Clock (epoch ms); null means the system clock. */
        public LongSupplier now;
        /** TTL stamped into each PCActn (ms); null means the default. */
        public Long ttlMs;
        /** Override of the enforced-checks manifest that feeds the measurement. */
        public List<String> measurementManifest;
        /** Nonce source; null means 16 random bytes as hex. */
        public Supplier<String> nonce;
        /** When set ({@code operator}, optional {@code epoch}), the harness stamps its self-measurement into every PCActn's attestation block. */
        public Map<String, Object> attestation;
    }

    private static final String[] RISK_KEYS = {"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"};

    private final Map<String, Object> grant;
    private final List<Object> chain;
    private final Keys.SuiteKey signer;
    private final List<Map<String, Object>> plan;
    private final Map<String, Map<String, Object>> planIndex = new LinkedHashMap<>();
    private final Issue.Plan committed;
    private final String audience;
    private final Map<String, Object> policy;
    private final Map<String, Object> baseRisk;
    private final LongSupplier now;
    private final Long ttlMs;
    private final List<String> manifest;
    private final Supplier<String> nonce;
    private final Map<String, Object> attest;
    private Map<String, Object> budget;
    private long counter;

    @SuppressWarnings("unchecked")
    public Harness(Options opts) {
        if (!(opts.audience instanceof String) || ((String) opts.audience).isEmpty())
            throw new IllegalArgumentException("Harness: `audience` is required (the resource-server / instance id PCActns are for)");
        if (opts.agentSeed == null || opts.agentSeed.length != 32) throw new IllegalArgumentException("Harness: `agentSecret` must be a 32-byte Ed25519 secret key");
        if (!(opts.plan instanceof List) || ((List<?>) opts.plan).isEmpty()) throw new IllegalArgumentException("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)");
        List<?> nodes = (List<?>) opts.plan;
        Set<Object> ids = new HashSet<>();
        for (Object n : nodes) ids.add(JsVal.member(n, "id"));
        if (ids.size() != nodes.size()) throw new IllegalArgumentException("Harness: plan node ids must be unique");
        Object b = opts.budget;
        if (!(b instanceof Map) || !JsVal.isFinite(((Map<?, ?>) b).get("B")) || JsVal.num(((Map<?, ?>) b).get("B")) < 0
            || !JsVal.isFinite(((Map<?, ?>) b).get("tau")) || !JsVal.isFinite(((Map<?, ?>) b).get("asOf")))
            throw new IllegalArgumentException("Harness: `budget` must have finite B >= 0, tau and asOf");
        this.grant = opts.grant;
        this.chain = opts.chain != null ? opts.chain : new ArrayList<Object>(Collections.singletonList(opts.grant));
        this.signer = Keys.ed25519(Keys.edFromSeed(opts.agentSeed));
        List<Map<String, Object>> planNodes = new ArrayList<>();
        for (Object n : nodes) {
            if (!(n instanceof Map)) throw new IllegalArgumentException("Harness: plan nodes must be objects");
            planNodes.add((Map<String, Object>) n);
        }
        this.plan = planNodes;
        for (Map<String, Object> n : planNodes) planIndex.put((String) n.get("id"), n);
        this.committed = Issue.commitPlan(planNodes);
        this.audience = (String) opts.audience;
        this.policy = opts.policy != null ? opts.policy : Issue.defaultRiskPolicy();
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("semanticDistance", new Json.Num("0.1"));
        base.put("reversibility", new Json.Num("1"));
        base.put("blastRadius", new Json.Num("0.1"));
        base.put("taint", new Json.Num("0"));
        base.put("confidence", new Json.Num("1"));
        base.put("age", new Json.Num("0"));
        if (opts.baseRisk != null) base.putAll(opts.baseRisk);
        this.baseRisk = base;
        this.now = opts.now != null ? opts.now : System::currentTimeMillis;
        this.ttlMs = opts.ttlMs;
        this.manifest = opts.measurementManifest != null ? opts.measurementManifest : ENFORCED_CHECKS;
        this.nonce = opts.nonce != null ? opts.nonce : Harness::randomHex;
        this.attest = opts.attestation;
        this.budget = new LinkedHashMap<>((Map<String, Object>) b);
    }

    private static String randomHex() {
        byte[] r = new byte[16];
        new SecureRandom().nextBytes(r);
        StringBuilder sb = new StringBuilder();
        for (byte x : r) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    /** The committed plan root the principal authorised. */
    public String planRoot() { return committed.root; }

    /** The current (leaked-to-last-touch) trust budget {@code {B, tau, asOf}}. */
    public Map<String, Object> budget() { return budget; }

    /** Monotonic action counter: the number of PCActns this harness has emitted. */
    public long counter() { return counter; }

    /** The harness's self-measurement: what a remote attestation of the mediator would cover. */
    public String harnessMeasurement() { return computeHarnessMeasurement(HARNESS_VERSION, manifest, policy); }

    private static Json.Num num(double d) { return (Json.Num) IntentJs.normalize(Double.valueOf(d)); }

    private static double dbl(Object o) {
        Double d = JsVal.num(o);
        return d == null ? Double.NaN : d;
    }

    private static Map<String, Object> budgetMap(double b, double tau, double asOf) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", num(b));
        m.put("tau", num(tau));
        m.put("asOf", num(asOf));
        return m;
    }

    private static Map<String, Object> refuse(String reason, String detail) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", Boolean.FALSE);
        r.put("reason", reason);
        r.put("detail", detail);
        return r;
    }

    /** JavaScript {@code Number.prototype.toFixed} for a finite number. */
    static String toFixed(double x, int digits) {
        return new BigDecimal(x).setScale(digits, RoundingMode.HALF_UP).toPlainString();
    }

    /**
     * Ask the untrusted oracle for a candidate action and, only if it survives the invariant gate, emit a signed PCActn. Order: plan
     * inclusion, taint fold, trust budget, sign. A throwing oracle or a malformed candidate is a refusal ({@code bad_candidate}), never an exception.
     * Returns {@code {ok:true, pcactn, inclusionProof, risk, budget}} or {@code {ok:false, reason, detail, requiredT?, budget?}}.
     */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> step(Callable<Object> proposeAction) {
        Object candidate;
        try {
            candidate = proposeAction.call();
        } catch (Exception e) {
            return refuse("bad_candidate", "oracle failed: " + (e.getMessage() != null ? e.getMessage() : "unknown error"));
        }
        // (0) the oracle is untrusted: validate the shape before use
        if (!(candidate instanceof Map) || !(((Map<?, ?>) candidate).get("nodeId") instanceof String) || !(((Map<?, ?>) candidate).get("verb") instanceof String)
            || !(((Map<?, ?>) candidate).get("resource") instanceof String)) return refuse("bad_candidate", "oracle returned a malformed candidate");
        Map<String, Object> cand = (Map<String, Object>) candidate;
        String nodeId = (String) cand.get("nodeId");
        // (1) plan inclusion: reject out-of-plan BEFORE signing
        Map<String, Object> node = planIndex.get(nodeId);
        if (node == null) return refuse("out_of_plan", "node '" + nodeId + "' is not in the committed plan");
        if (!Objects.equals(node.get("verb"), cand.get("verb")) || !Objects.equals(node.get("resource"), cand.get("resource"))) {
            return refuse("out_of_plan", "action " + cand.get("verb") + " " + cand.get("resource") + " does not match committed node '" + JsVal.str(node.get("id")) + "' ("
                + JsVal.strMember(node, "verb") + " " + JsVal.strMember(node, "resource") + ")");
        }
        Map<String, Object> inclusionProof = committed.proofFor(nodeId);
        // (2) taint fold: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        if (cand.containsKey("inputs") && !(cand.get("inputs") instanceof List)) return refuse("bad_candidate", "candidate.inputs is not an array");
        List<Object> inputs = new ArrayList<>();
        List<Object> trustedRefs = new ArrayList<>();
        boolean tainted = false;
        if (cand.get("inputs") != null) {
            for (Object i : (List<Object>) cand.get("inputs")) {
                boolean trusted = i instanceof Map && "trusted".equals(((Map<?, ?>) i).get("provenance")) && ((Map<?, ?>) i).get("ref") instanceof String;
                Map<String, Object> e = new LinkedHashMap<>();
                Object ref = JsVal.opt(i, "ref");
                e.put("ref", trusted ? ref : ref instanceof String ? ref : "");
                e.put("provenance", trusted ? "trusted" : "untrusted");
                inputs.add(e);
                if (trusted) trustedRefs.add(ref);
                else tainted = true;
            }
        }
        long taint = tainted ? 1 : 0;
        Map<String, Object> riskInputs = new LinkedHashMap<>(baseRisk);
        riskInputs.put("taint", new Json.Num(Long.toString(taint)));
        double[] in = new double[RISK_KEYS.length];
        for (int k = 0; k < in.length; k++) in[k] = dbl(riskInputs.get(RISK_KEYS[k]));
        // rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        double r = JsVal.round(W3Bridge.riskScore(in, (Map<String, Object>) policy.get("weights")) * 1e6) / 1e6;
        int t = W3Bridge.requiredThreshold(r, dbl(policy.get("theta1")), dbl(policy.get("theta2")), "irreversible".equals(node.get("reversibility_class")));
        // (3) trust budget: meter machine-only actions, leaking to now first
        long nowMs = now.getAsLong();
        double[] leaked = W3Bridge.leak(dbl(budget.get("B")), dbl(budget.get("tau")), dbl(budget.get("asOf")), nowMs, dbl(policy.get("lambda")));
        double c = W3Bridge.cost(r, dbl(policy.get("kappa")));
        if (t < 3 && !(leaked[0] >= c)) {
            // the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
            budget = budgetMap(leaked[0], leaked[1], leaked[2]);
            Map<String, Object> out = refuse("over_budget", "budget " + toFixed(leaked[0], 4) + " < cost " + toFixed(c, 4) + "; step up to a human co-sign");
            out.put("requiredT", 3L);
            out.put("budget", budgetMap(leaked[0], leaked[1], leaked[2]));
            return out;
        }
        // (4) sign
        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("causal_hash", Pca.hashCanonical(inputs));
        provenance.put("taint_level", taint);
        provenance.put("trusted_refs", trustedRefs);
        Map<String, Object> attestation = null;
        if (attest != null) {
            attestation = new LinkedHashMap<>();
            attestation.put("quote_digest", "");
            attestation.put("epoch", attest.get("epoch") != null ? attest.get("epoch") : Long.valueOf(0));
            attestation.put("model_id", HARNESS_MODEL_ID);
            attestation.put("measurement", harnessMeasurement());
            attestation.put("operator", attest.get("operator"));
        }
        Map<String, Object> riskClaim = new LinkedHashMap<>();
        riskClaim.put("r", num(r));
        riskClaim.put("inputs", new LinkedHashMap<>(riskInputs));
        Object params = cand.get("params");
        Map<String, Object> pcactn;
        try {
            if (params != null && !(params instanceof Map)) throw new IllegalArgumentException("params must be an object");
            Issue.ActSpec s = new Issue.ActSpec();
            s.grant = grant;
            s.chain = chain;
            s.plan = committed;
            s.nodeId = nodeId;
            s.params = (Map<String, Object>) params;
            s.counter = counter + 1;
            s.signer = signer;
            s.aud = audience;
            s.iat = nowMs;
            s.ttlMs = ttlMs;
            s.nonce = nonce.get();
            s.provenance = provenance;
            s.riskClaim = riskClaim;
            s.attestation = attestation;
            pcactn = Issue.buildPCActn(s);
        } catch (RuntimeException e) {
            // e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
            return refuse("bad_candidate", "could not build PCActn: " + e.getMessage());
        }
        // debit only a metered (machine-only, t < 3) action; commit the counter
        double[] debited = t < 3 ? W3Bridge.debit(leaked[0], leaked[1], leaked[2], c) : leaked;
        budget = budgetMap(debited[0], debited[1], debited[2]);
        counter += 1;
        Map<String, Object> risk = new LinkedHashMap<>();
        risk.put("r", num(r));
        risk.put("inputs", riskInputs);
        risk.put("taint", taint);
        risk.put("t", (long) t);
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", Boolean.TRUE);
        ok.put("pcactn", pcactn);
        ok.put("inclusionProof", inclusionProof);
        ok.put("risk", risk);
        ok.put("budget", budget);
        return ok;
    }
}
