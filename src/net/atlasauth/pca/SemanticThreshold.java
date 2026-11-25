package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import net.atlasauth.pca.intent.IntentSemantic;

/**
 * The k-of-n semantic judge threshold in full: signed judge verdicts bound to one action and goal under an Ed25519, ML-DSA-65 or hybrid
 * suite, the judge attestation gate (a judge's vote counts only when a hardware-attested enclave matches its signed measurement), the
 * threshold with an optional split-conformal cutoff, the verifier hook and the monotone risk contribution. Scores are quantized to integer
 * parts per million BEFORE signing, so a float never reaches a signature. The scoring, the conformal cutoff and the plain threshold are those
 * of {@link IntentSemantic}; this class adds the signing, the message, the attestation gate and the hook.
 *
 * <p>A post-quantum or hybrid verdict counts only under a PQ key the VERIFIER pins for the judge ({@code pqPins}); the reference's legacy
 * option that trusts a verdict's own key is not offered, as everywhere in this SDK.
 */
public final class SemanticThreshold {
    private SemanticThreshold() {}

    public static final String SEMANTIC_JUDGE_DOMAIN = IntentSemantic.SEMANTIC_JUDGE_DOMAIN;
    public static final int SCORE_SCALE = 1_000_000;

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** A score on the integer grid [0, 1e6]; a non-finite score is 0. */
    public static long quantizeScore(double score) { return IntentSemantic.quantizeScore(score); }

    /** The signed statement of a verdict {@code {actionDigest, goalCommitment, faithful, score, judgeMeasurement, alg?, pq_pk?}}: {@code faithful} only when exactly true. */
    public static Map<String, Object> statementOf(Map<String, Object> verdict) { return IntentSemantic.statementOf(verdict); }

    /** {@code SEMANTIC_JUDGE_DOMAIN || strict canonical JSON(statement)}. Throws on a non-integer, negative-zero or non-finite member. */
    public static byte[] semanticJudgeMessage(Map<String, Object> statement) { return IntentJs.message(SEMANTIC_JUDGE_DOMAIN, IntentJs.normalize(statement)); }

    /** The content address of an action: {@code hashCanonical(action)}. */
    public static String actionDigest(Object action) { return Pca.hashCanonical(IntentJs.normalize(action)); }

    /** {@code hashCanonical(verdict)}: a content address for a whole signed verdict. Throws on a value with no canonical form. */
    public static String verdictDigest(Object verdict) { return Pca.hashCanonical(IntentJs.normalize(verdict)); }

    /**
     * Sign a verdict {@code {actionDigest, goalCommitment, faithful, score, judgeMeasurement?}} as the judge whose Ed25519 seed is
     * {@code secretKey}, optionally under a PQ or hybrid {@code suite}. The verdict carries the score as given; the signature covers its
     * quantized statement. Throws on an unknown suite.
     */
    public static Map<String, Object> signJudgeVerdict(byte[] secretKey, Map<String, Object> v, Pq.SignerSuiteOpts suite) {
        Object jmO = v.get("judgeMeasurement");
        String judgeMeasurement = jmO == null ? "" : IntentRevocation.jsText(jmO, true);
        String alg = suite == null ? null : suite.alg;
        Pq.Suite resolved = Pq.resolveSigAlg(alg, alg != null);
        if (resolved == null) throw new IllegalArgumentException("signJudgeVerdict: unknown signature alg '" + alg + "'");
        Pq.SuiteSecretKeys keys = Pq.suiteKeysOf(secretKey, suite);
        String pqPk = Pq.suitePqPublicKey(alg, keys);
        Map<String, Object> st = new LinkedHashMap<>(v);
        st.remove("alg");
        st.remove("pq_pk");
        st.put("judgeMeasurement", judgeMeasurement);
        if (!resolved.alg.equals("ed25519")) st.put("alg", resolved.alg);
        if (pqPk != null) st.put("pq_pk", pqPk);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, keys, semanticJudgeMessage(statementOf(st)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("judge", Keys.edFromSeed(secretKey).id());
        out.put("actionDigest", v.get("actionDigest"));
        out.put("goalCommitment", v.get("goalCommitment"));
        out.put("faithful", Boolean.TRUE.equals(v.get("faithful")));
        out.put("score", v.get("score"));
        out.put("judgeMeasurement", judgeMeasurement);
        out.put("sig", f.sig);
        if (f.alg != null) out.put("alg", f.alg);
        if (f.pqPk != null) out.put("pq_pk", f.pqPk);
        if (f.pqSig != null) out.put("pq_sig", f.pqSig);
        return out;
    }

    /**
     * Verify one verdict against the expected action and goal: well-formed fields, a score in [0, 1], a known suite, and a signature over
     * the quantized statement under the judge key ({@code pqPins} admits a PQ or hybrid verdict). Never throws.
     */
    public static boolean verifyJudgeVerdict(Object verdict, String expectedActionDigest, String expectedGoalCommitment, Map<String, Object> pqPins) {
        return IntentSemantic.verifyJudgeVerdict(verdict, expectedActionDigest, expectedGoalCommitment, pqPins);
    }

    /**
     * The judge attestation gate: a verified, hardware-bound attestation whose measured runtime equals the verdict's signed
     * {@code judgeMeasurement}, and, when {@code approved} (an {@code agent_binding}) is given, whose identity matches it. The attestation is
     * a hardware result {@code {ok, bound, measured, reason?}}. Returns {@code {ok: true, measured}} or {@code {ok: false, reason}}.
     */
    public static Map<String, Object> verifyJudgeAttestation(Object judgeMeasurement, Object attestation, Object approved) {
        boolean absent = attestation == null || Boolean.FALSE.equals(attestation) || "".equals(attestation) || !Zk.truthy(attestation);
        if (absent || !Boolean.TRUE.equals(get(attestation, "ok"))) {
            Object reason = get(attestation, "reason");
            return Issue.obj("ok", false, "reason", reason != null ? reason : "no verified attestation for this judge (fail-closed)");
        }
        if (!Boolean.TRUE.equals(get(attestation, "bound"))) return Issue.obj("ok", false, "reason", "judge attestation not bound to a TEE report (report_data binding unconfirmed)");
        Object measured = get(attestation, "measured");
        if (!(measured instanceof Map) && !(measured instanceof List)) return Issue.obj("ok", false, "reason", "judge attestation carries no measured identity");
        if (!(judgeMeasurement instanceof String) || ((String) judgeMeasurement).isEmpty()) return Issue.obj("ok", false, "reason", "verdict carries no judgeMeasurement to bind to the attested identity");
        if (!judgeMeasurement.equals(get(measured, "runtime_measurement"))) return Issue.obj("ok", false, "reason", "attested enclave measurement does not match the signed judgeMeasurement");
        String appraisal = Attestation.matchAgentBinding(measured, approved);
        if (appraisal != null) return Issue.obj("ok", false, "reason", appraisal);
        return Issue.obj("ok", true, "measured", measured);
    }

    /** The conformal cutoff of {@code calibration = {samples: [{score, faithful}], alpha}} (+Infinity when too few unfaithful samples certify alpha). */
    public static double conformalThreshold(Object calibration) { return IntentSemantic.conformalThreshold(calibration); }

    /** The fraction of the unfaithful samples whose score exceeds {@code cutoff} (0 with none). */
    public static double empiricalFalseAllowRate(Object samples, double cutoff) { return IntentSemantic.empiricalFalseAllowRate(samples, cutoff); }

    /** The attestation requirement of a threshold check. */
    public static final class JudgeAttestation {
        /** Only exactly true enforces the gate. */
        public Object require;
        /** An {@code agent_binding} the attested identity must match (null: any identity). */
        public Object approved;
        /** The hardware result for a verdict's judge (null: none). */
        public Function<Map<String, Object>, Object> resolve;
    }

    /** {@link #verifySemanticThreshold(Object, Map, JudgeAttestation)} without an attestation requirement. */
    public static Map<String, Object> verifySemanticThreshold(Object verdicts, Map<String, Object> opts) { return verifySemanticThreshold(verdicts, opts, null); }

    /**
     * Verify a k-of-n ensemble: {@code opts = {judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?}}. One key is one vote (a judge
     * that signs conflicting verdicts is dropped); with {@code attestation.require} a judge whose attestation is missing, unbound, mismatched
     * or unapproved does not count. The mean score of the agreeing judges must exceed the calibrated cutoff when a calibration is given.
     * Returns {@code {ok, agreeCount, aggregateScore, cutoff?, reason?}}.
     */
    public static Map<String, Object> verifySemanticThreshold(Object verdicts, Map<String, Object> opts, JudgeAttestation att) {
        Predicate<Map<String, Object>> gate = att != null && Boolean.TRUE.equals(att.require)
            ? v -> Boolean.TRUE.equals(verifyJudgeAttestation(v.get("judgeMeasurement"), att.resolve == null ? null : att.resolve.apply(v), att.approved).get("ok"))
            : null;
        return IntentSemantic.verifySemanticThreshold(verdicts, opts, gate);
    }

    /** A semantic verifier's configuration. A resolver answering null means "not available". */
    public static final class VerifierOptions {
        public List<?> judgeKeys;
        public Object k;
        public Object calibration;
        /** The verdicts of an action (null: none supplied). */
        public Function<Object, Object> verdicts;
        /** The goal commitment of an action (null: none). */
        public Function<Object, Object> goalCommitment;
        /** The action digest the verdicts must bind to (null: {@code hashCanonical(ctx.pcactn.action)}). */
        public Function<Object, String> actionDigest;
        /** When true, an action with no ensemble is not enforced instead of denied. */
        public boolean optionalWhenAbsent;
        public Function<Object, JudgeAttestation> attestation;
    }

    /**
     * The semantic verifier hook: {@code apply(ctx)} is {@code {enforced: false}} for an absent ensemble when optional, a denial when not, else
     * the threshold's verdict {@code {enforced: true, ok, reason?}}. The goal commitment must be a string.
     */
    public static Function<Object, Map<String, Object>> createSemanticVerifier(VerifierOptions o) {
        return ctx -> {
            Object goal = o.goalCommitment.apply(ctx), verdicts = o.verdicts.apply(ctx);
            if (!(goal instanceof String) || verdicts == null) {
                return o.optionalWhenAbsent ? Issue.obj("enforced", false)
                    : Issue.obj("enforced", true, "ok", false, "reason", "no semantic ensemble available for this action (fail-closed)");
            }
            JudgeAttestation att = o.attestation == null ? null : o.attestation.apply(ctx);
            Map<String, Object> opts = new LinkedHashMap<>();
            opts.put("judgeKeys", o.judgeKeys);
            opts.put("k", o.k);
            opts.put("goalCommitment", goal);
            opts.put("actionDigest", o.actionDigest != null ? o.actionDigest.apply(ctx) : actionDigest(get(get(ctx, "pcactn"), "action")));
            if (o.calibration != null) opts.put("calibration", o.calibration);
            Map<String, Object> res = verifySemanticThreshold(verdicts, opts, att);
            if (Boolean.TRUE.equals(res.get("ok"))) return Issue.obj("enforced", true, "ok", true);
            return Issue.obj("enforced", true, "ok", false, "reason", res.get("reason") != null ? res.get("reason") : "semantic threshold not met");
        };
    }

    /** The risk a semantic aggregate contributes: {@code 1 - aggregateScore}, clamped to [0, 1]; a non-finite aggregate is 1. Weaker agreement can only RAISE risk. */
    public static double semanticRiskContribution(double aggregateScore) {
        if (Double.isNaN(aggregateScore) || Double.isInfinite(aggregateScore)) return 1;
        double r = 1 - aggregateScore;
        return r < 0 ? 0 : r > 1 ? 1 : r;
    }
}
