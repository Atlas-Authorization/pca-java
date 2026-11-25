package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * The semantic judge threshold against the reference corpus (ref-semantic-threshold, 186 cases): quantization, the signed statement and
 * message, verdict signing under three suites, verdict verification with PQ pins, the judge attestation gate, the k-of-n threshold with
 * attestation and calibration, the verifier hook and the risk contribution. The 2 cases the reference accepts only through its legacy
 * unbound-PQ option (a verdict vouching for its own PQ key) are asserted REFUSED. A non-finite number leaves the native as {"$num": ...}
 * (a signed NaN score too: the regenerated corpus spells it the same way).
 */
class SemanticThresholdRefDiffTest {
    static final String MODULE = "ref-semantic-threshold";
    static final int TOTAL = 186;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    /** A non-finite double in a result as the corpus spells it ({"$num"}), or as JSON text has it (null). */
    @SuppressWarnings("unchecked")
    private static Object outNums(Object v, boolean asNull) {
        if (v instanceof Double && (((Double) v).isNaN() || ((Double) v).isInfinite())) {
            return asNull ? null : Issue.obj("$num", ((Double) v).isNaN() ? "NaN" : ((Double) v) > 0 ? "Infinity" : "-Infinity");
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(outNums(x, asNull));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), outNums(e.getValue(), asNull));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    /** The attestation requirement of a corpus {require, approved?, byJudge} (null: none). */
    private static SemanticThreshold.JudgeAttestation att(Object a) {
        Map<String, Object> s = m(a);
        if (s == null) return null;
        SemanticThreshold.JudgeAttestation out = new SemanticThreshold.JudgeAttestation();
        out.require = s.get("require");
        out.approved = s.get("approved");
        Map<String, Object> byJudge = m(s.get("byJudge"));
        out.resolve = v -> byJudge == null ? null : byJudge.get(v.get("judge"));
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("SEMANTIC_JUDGE_DOMAIN", SemanticThreshold.SEMANTIC_JUDGE_DOMAIN, "SCORE_SCALE", SemanticThreshold.SCORE_SCALE));
        f.put("quantizeScore", x -> SemanticThreshold.quantizeScore(dbl(nums(arg(x, 0)))));
        f.put("statementOf", x -> SemanticThreshold.statementOf(m(nums(arg(x, 0)))));
        f.put("semanticJudgeMessage", x -> SemanticThreshold.semanticJudgeMessage(m(nums(arg(x, 0)))));
        f.put("signJudgeVerdict", x -> outNums(SemanticThreshold.signJudgeVerdict(bytes(arg(x, 0)), m(nums(arg(x, 1))), suite(arg(x, 2))), false));
        f.put("verdictDigest", x -> SemanticThreshold.verdictDigest(nums(arg(x, 0))));
        f.put("verifyJudgeVerdict", x -> {
            Map<String, Object> e = m(arg(x, 1)), pin = m(arg(x, 2));
            return SemanticThreshold.verifyJudgeVerdict(nums(arg(x, 0)), (String) e.get("actionDigest"), (String) e.get("goalCommitment"), pin == null ? null : m(pin.get("pqPins")));
        });
        f.put("verifyJudgeAttestation", x -> SemanticThreshold.verifyJudgeAttestation(nums(arg(x, 0)), nums(arg(x, 1)), arg(x, 2)));
        f.put("verifySemanticThreshold", x -> {
            Map<String, Object> opts = new LinkedHashMap<>(m(nums(arg(x, 1))));
            opts.remove("attestation");
            return outNums(SemanticThreshold.verifySemanticThreshold(nums(arg(x, 0)), opts, att(m(arg(x, 1)).get("attestation"))), false);
        });
        f.put("semanticVerifier", x -> {
            Map<String, Object> op = m(nums(arg(x, 0)));
            SemanticThreshold.VerifierOptions o = new SemanticThreshold.VerifierOptions();
            o.judgeKeys = (List<?>) op.get("judgeKeys");
            o.k = op.get("k");
            o.calibration = op.get("calibration");
            o.optionalWhenAbsent = Boolean.TRUE.equals(op.get("optionalWhenAbsent"));
            o.verdicts = c -> m(c).get("verdicts");
            o.goalCommitment = c -> m(c).get("goal");
            if (op.get("actionDigestMode") instanceof String && ((String) op.get("actionDigestMode")).startsWith("fixed:")) {
                String fixed = ((String) op.get("actionDigestMode")).substring(6);
                o.actionDigest = c -> fixed;
            }
            o.attestation = c -> att(m(c).get("attestation"));
            Function<Object, Map<String, Object>> h = SemanticThreshold.createSemanticVerifier(o);
            List<Object> out = new ArrayList<>();
            for (Object c : (List<?>) arg(x, 1)) out.add(h.apply(c));
            return out;
        });
        f.put("semanticRiskContribution", x -> SemanticThreshold.semanticRiskContribution(dbl(nums(arg(x, 0)))));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        int refused = 0;
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                Object want = c.get("out");
                boolean legacy = (e.getKey().equals("verifyJudgeVerdict") || e.getKey().equals("verifySemanticThreshold")) && usesUnbound(c)
                    && (Boolean.TRUE.equals(want) || (m(want) != null && Boolean.TRUE.equals(m(want).get("ok"))));
                if (legacy) { // accepted by the reference only because the verdict vouches for its own PQ key
                    refused++;
                    want = e.getKey().equals("verifyJudgeVerdict") ? (Object) false : Issue.obj("ok", false, "agreeCount", 0, "aggregateScore", 0, "reason", "only 0 distinct trusted judge(s) agree, need 1");
                }
                String d = OracleCases.diff(c, want, e.getValue());
                if (d != null) bad.add(d);
            }
        }
        assertEquals(2, refused);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    private static boolean usesUnbound(Map<String, Object> c) {
        for (Object a : (List<?>) c.get("args")) {
            Map<String, Object> o = m(a);
            if (o != null && Boolean.TRUE.equals(o.get("allowUnboundPq"))) return true;
        }
        return false;
    }
}
