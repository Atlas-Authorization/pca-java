package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;

/**
 * The k-of-n semantic judge threshold: signed judge verdicts bound to one action and goal, one key one vote, an optional split-conformal
 * cutoff on the aggregate score. Verdicts are JSON {judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?, pq_pk?, pq_sig?}.
 * The attested-judge gate (a hardware-attested enclave appraisal) is injected as a predicate over a verdict: when given, a verdict it rejects does not vote.
 */
public final class IntentSemantic {
    private IntentSemantic() {}

    public static final String SEMANTIC_JUDGE_DOMAIN = "atlas-pca/semantic-judge/v1\0";
    public static final double SCORE_SCALE = 1_000_000;

    /** A score on the integer grid [0, 1e6]; non-finite is 0. */
    public static long quantizeScore(double score) {
        if (!Double.isFinite(score)) return 0;
        double q = IntentMapKit.jsRound(score * SCORE_SCALE) + 0;
        return (long) (q < 0 ? 0 : q > SCORE_SCALE ? SCORE_SCALE : q);
    }

    /** The signed statement of a verdict (suite fields bound in for a non-ed25519 suite). */
    public static Map<String, Object> statementOf(Map<String, Object> v) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("v", 1L);
        base.put("actionDigest", v.get("actionDigest"));
        base.put("goalCommitment", v.get("goalCommitment"));
        base.put("faithful", Boolean.TRUE.equals(v.get("faithful")));
        Object sc = v.get("score");
        base.put("score_ppm", quantizeScore(IntentBridge.num(sc) == null ? Double.NaN : IntentBridge.num(sc)));
        Object jm = v.get("judgeMeasurement");
        base.put("judgeMeasurement", jm == null ? "" : jm instanceof String ? jm : IntentOmega.isNumber(jm) ? AttestCommon.jsNumString(IntentOmega.dbl(jm)) : String.valueOf(jm));
        return IntentBridge.bindSuiteFields(base, v.get("alg"), v.containsKey("alg"), v.get("pq_pk"), v.containsKey("pq_pk"));
    }

    /** Verify ONE verdict against an expected action / goal binding. Total: never throws. */
    public static boolean verifyJudgeVerdict(Object vo, String expectedAction, String expectedGoal, Map<String, Object> pqPins) {
        try {
            if (!(vo instanceof Map)) return false;
            @SuppressWarnings("unchecked") Map<String, Object> v = (Map<String, Object>) vo;
            if (!(v.get("judge") instanceof String) || Pca.decodeB64uStrict(v.get("judge"), 32) == null) return false;
            if (!(v.get("actionDigest") instanceof String) || !(v.get("goalCommitment") instanceof String)) return false;
            if (!v.get("actionDigest").equals(expectedAction) || !v.get("goalCommitment").equals(expectedGoal)) return false;
            if (!(v.get("faithful") instanceof Boolean)) return false;
            Double score = IntentBridge.num(v.get("score"));
            if (score == null || !Double.isFinite(score) || score < 0 || score > 1) return false;
            if (!(v.get("judgeMeasurement") instanceof String)) return false;
            if (!(v.get("sig") instanceof String)) return false;
            boolean algPresent = v.containsKey("alg");
            if (IntentBridge.suiteName(v.get("alg"), algPresent) == null) return false;
            byte[] msg = IntentBridge.message(SEMANTIC_JUDGE_DOMAIN, statementOf(v));
            return IntentBridge.verifyPinnedSuite(v.get("alg"), algPresent, (String) v.get("judge"), v.get("pq_pk"), msg, v.get("sig"), v.get("pq_sig"), pqPins);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static double clampAlpha(Object alpha) {
        Double a = alpha != null && IntentOmega.isNumber(alpha) ? IntentOmega.dbl(alpha) : null;
        if (a == null || !Double.isFinite(a)) return 1;
        if (a <= 0) return Double.MIN_VALUE;
        return a > 1 ? 1 : a;
    }

    private static List<Double> unfaithful(Object samples) {
        List<Double> out = new ArrayList<>();
        if (!(samples instanceof List)) return out;
        for (Object so : (List<?>) samples) {
            if (so instanceof Map) {
                Map<?, ?> s = (Map<?, ?>) so;
                Object sc = s.get("score");
                if (Boolean.FALSE.equals(s.get("faithful")) && sc != null && IntentOmega.isNumber(sc) && Double.isFinite(IntentOmega.dbl(sc))) out.add(IntentOmega.dbl(sc));
            }
        }
        return out;
    }

    /** The split-conformal upper quantile of the unfaithful scores (+Infinity when too few to certify alpha). */
    public static double conformalThreshold(Object calibration) {
        Map<?, ?> c = calibration instanceof Map ? (Map<?, ?>) calibration : null;
        double alpha = clampAlpha(c == null ? null : c.get("alpha"));
        List<Double> u = unfaithful(c == null ? null : c.get("samples"));
        int m = u.size();
        if (m == 0) return Double.POSITIVE_INFINITY;
        double rank = Math.ceil((m + 1) * (1 - alpha));
        if (rank > m) return Double.POSITIVE_INFINITY;
        java.util.Collections.sort(u);
        return u.get((int) Math.max(rank, 1) - 1);
    }

    /** Fraction of the unfaithful samples whose score exceeds the cutoff (0 with none). */
    public static double empiricalFalseAllowRate(Object samples, double cutoff) {
        int m = 0, allowed = 0;
        if (samples instanceof List) {
            for (Object so : (List<?>) samples) {
                if (so instanceof Map) {
                    Map<?, ?> s = (Map<?, ?>) so;
                    Object sc = s.get("score");
                    if (Boolean.FALSE.equals(s.get("faithful")) && sc != null && IntentOmega.isNumber(sc) && Double.isFinite(IntentOmega.dbl(sc))) {
                        m++;
                        if (IntentOmega.dbl(sc) > cutoff) allowed++;
                    }
                }
            }
        }
        return m == 0 ? 0 : (double) allowed / m;
    }

    private static String jsStr(Object k) {
        if (k == null) return "null";
        if (IntentOmega.isNumber(k)) return AttestCommon.jsNumString(IntentOmega.dbl(k));
        return String.valueOf(k);
    }

    private static Map<String, Object> result(boolean ok, int agree, double score, Double cutoff, String reason) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", ok);
        r.put("agreeCount", (long) agree);
        r.put("aggregateScore", score);
        if (cutoff != null) r.put("cutoff", cutoff);
        if (reason != null) r.put("reason", reason);
        return r;
    }

    /**
     * Verify a k-of-n ensemble. {@code opts}: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?. Returns {ok, agreeCount, aggregateScore,
     * cutoff?, reason?}. {@code attestationGate} (optional) must accept a verdict for it to vote.
     */
    public static Map<String, Object> verifySemanticThreshold(Object verdicts, Map<String, Object> opts, Predicate<Map<String, Object>> attestationGate) {
        Object k = opts.get("k");
        Set<String> allow = new LinkedHashSet<>();
        if (opts.get("judgeKeys") instanceof List) {
            for (Object key : (List<?>) opts.get("judgeKeys")) if (key instanceof String && Pca.decodeB64uStrict(key, 32) != null) allow.add((String) key);
        }
        if (!(opts.get("actionDigest") instanceof String) || !(opts.get("goalCommitment") instanceof String)) return result(false, 0, 0, null, "missing action/goal binding");
        Double kd = k != null && IntentOmega.isNumber(k) ? IntentOmega.dbl(k) : null;
        if (kd == null || !Double.isFinite(kd) || kd != Math.floor(kd) || kd < 1) return result(false, 0, 0, null, "invalid quorum k=" + (opts.containsKey("k") ? jsStr(k) : "undefined"));
        String ad = (String) opts.get("actionDigest"), gc = (String) opts.get("goalCommitment");
        @SuppressWarnings("unchecked") Map<String, Object> pins = opts.get("pqPins") instanceof Map ? (Map<String, Object>) opts.get("pqPins") : null;
        Map<String, Object[]> byJudge = new LinkedHashMap<>(); // judge -> {Set<Boolean>, Set<Long>}
        if (verdicts instanceof List) {
            for (Object vo : (List<?>) verdicts) {
                if (!(vo instanceof Map) || !(((Map<?, ?>) vo).get("judge") instanceof String) || !allow.contains(((Map<?, ?>) vo).get("judge"))) continue;
                @SuppressWarnings("unchecked") Map<String, Object> v = (Map<String, Object>) vo;
                if (!verifyJudgeVerdict(v, ad, gc, pins)) continue;
                if (attestationGate != null && !attestationGate.test(v)) continue;
                Object[] g = byJudge.computeIfAbsent((String) v.get("judge"), j -> new Object[] {new LinkedHashSet<Boolean>(), new LinkedHashSet<Long>()});
                @SuppressWarnings("unchecked") Set<Boolean> fs = (Set<Boolean>) g[0];
                @SuppressWarnings("unchecked") Set<Long> ss = (Set<Long>) g[1];
                fs.add(Boolean.TRUE.equals(v.get("faithful")));
                ss.add(quantizeScore(IntentOmega.dbl(v.get("score"))));
            }
        }
        List<Object[]> agreeing = new ArrayList<>();
        for (Map.Entry<String, Object[]> e : byJudge.entrySet()) {
            @SuppressWarnings("unchecked") Set<Boolean> fs = (Set<Boolean>) e.getValue()[0];
            @SuppressWarnings("unchecked") Set<Long> ss = (Set<Long>) e.getValue()[1];
            if (fs.size() == 1 && fs.contains(true) && ss.size() == 1) agreeing.add(new Object[] {e.getKey(), ss.iterator().next()});
        }
        agreeing.sort((a, b) -> Json.compareUtf8((String) a[0], (String) b[0]));
        int agree = agreeing.size();
        double acc = 0;
        for (Object[] a : agreeing) acc += (double) (Long) a[1] / SCORE_SCALE;
        double aggregate = agree == 0 ? 0 : acc / agree;
        if (agree < kd) return result(false, agree, aggregate, null, "only " + agree + " distinct trusted judge(s) agree, need " + (opts.containsKey("k") ? jsStr(k) : "undefined"));
        if (opts.get("calibration") != null) {
            double cutoff = conformalThreshold(opts.get("calibration"));
            if (!(aggregate > cutoff)) return result(false, agree, aggregate, cutoff, "aggregateScore " + AttestCommon.jsNumString(aggregate) + " does not exceed calibrated cutoff " + AttestCommon.jsNumString(cutoff));
            return result(true, agree, aggregate, cutoff, null);
        }
        return result(true, agree, aggregate, null, null);
    }
}
