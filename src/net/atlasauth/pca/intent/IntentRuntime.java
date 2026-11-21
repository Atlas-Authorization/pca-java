package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The pure parts of runtime intent conformance: the judge input and the PCActn action shape for an outcome, the content
 * addresses of the conformance attestation, the calibration set and the just-in-time consent request, the consent prompt, and
 * the monotone risk fold. The route decision and the judge-panel verification need the learner and the semantic-threshold
 * verifier and are not part of this class.
 */
public final class IntentRuntime {
    private IntentRuntime() {}

    public static final String IC_ATT_DOMAIN = "atlas-pca/intent-ic-att/v1";

    /** Deep copy with every Double spelled as the JSON number JavaScript would print (hashed trees carry Json.Num). */
    @SuppressWarnings("unchecked")
    static Object jsonNums(Object v) {
        if (v instanceof Double) return new net.atlasauth.pca.Json.Num(net.atlasauth.pca.AttestCommon.jsNumString((Double) v));
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), jsonNums(e.getValue()));
            return out;
        }
        if (v instanceof java.util.List) {
            java.util.List<Object> out = new java.util.ArrayList<>();
            for (Object x : (java.util.List<Object>) v) out.add(jsonNums(x));
            return out;
        }
        return v;
    }

    /** The PCActn action shape for an outcome (params digest by the canonical rule). */
    public static Map<String, Object> pcactnActionOf(VerbSpace vs, Outcome o) {
        Map<String, Object> a = IntentPolicy.outcomeToAction(vs, o);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verb", a.get("verb"));
        out.put("resource", a.get("resource"));
        out.put("params_digest", Pca.paramsDigest(a.get("params") == null ? new LinkedHashMap<String, Object>() : jsonNums(a.get("params"))));
        out.put("reversibility_class", vs.reversibility);
        return out;
    }

    /** The digest every verdict must bind to. */
    public static String actionDigest(Object action) { return Pca.hashCanonical(action); }

    /** Digest of a verdict (strict canonical over the full verdict). */
    public static String verdictDigest(Object verdict) { return Pca.hashCanonical(verdict); }

    /** What every judge sees; {@code p} is the map's acceptance of the outcome; {@code ctx}: intentRef, mapDigest, statementText, slots, goalCommitment. */
    public static Map<String, Object> judgeInputOf(VerbSpace vs, Outcome o, double p, Map<String, Object> ctx) {
        Map<String, Object> out = new LinkedHashMap<>(ctx);
        out.put("renderedAction", IntentRender.renderAction(vs, o.values()));
        out.put("p", p);
        out.put("reversibility", vs.reversibility);
        out.put("actionDigest", actionDigest(pcactnActionOf(vs, o)));
        return out;
    }

    /** Digest of a calibration set ({alpha, samples: [{score, faithful}]}). */
    public static String calibrationDigest(Map<String, Object> c) {
        java.util.List<Object> samples = new java.util.ArrayList<>();
        for (Object s : IntentOmega.arr(c.get("samples"))) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("score", IntentOmega.obj(s).get("score"));
            m.put("faithful", IntentOmega.obj(s).get("faithful"));
            samples.add(m);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("d", "atlas-pca/intent-calibration/v1");
        body.put("alpha", c.get("alpha"));
        body.put("samples", samples);
        return Pca.hashCanonical(body);
    }

    /** Content address of an IC-Att (the value a PCActn carries as {@code ic_att_digest}). */
    public static String icAttDigest(Object att) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("d", IC_ATT_DOMAIN);
        body.put("a", att);
        return Pca.hashCanonical(body);
    }

    /** The risk contribution of an aggregate judge score: 1 - score clamped to [0, 1] (1 when not finite). */
    public static double semanticRiskContribution(double aggregateScore) {
        if (!Double.isFinite(aggregateScore)) return 1;
        double r = 1 - aggregateScore;
        return r < 0 ? 0 : r > 1 ? 1 : r;
    }

    /** The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r. */
    public static double foldSemanticRisk(double r, Map<String, Object> att) {
        return Math.max(r, semanticRiskContribution(IntentOmega.dbl(att.get("aggregate_score_ppm")) / 1_000_000));
    }

    /** The consent prompt for an action; {@code p} is the map's acceptance of the outcome. */
    public static Map<String, Object> jitConsentRequest(VerbSpace vs, Outcome o, double p, String intentRef, String mapDigest) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", new net.atlasauth.pca.Json.Num("1"));
        out.put("kind", "pca-intent-jit");
        out.put("intent_ref", intentRef);
        out.put("map_digest", mapDigest);
        out.put("verb", o.verb());
        out.put("values", jsonNums(new LinkedHashMap<>(o.values())));
        out.put("reversibility", vs.reversibility);
        out.put("p_ppm", new net.atlasauth.pca.Json.Num(String.valueOf(Math.round(p * 1_000_000))));
        out.put("text", IntentRender.renderAction(vs, o.values()) + " This cannot be undone. Approve?");
        return out;
    }

    public static String jitConsentDigest(Object request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("d", "atlas-pca/intent-jit/v1");
        body.put("r", request);
        return Pca.hashCanonical(body);
    }

}
