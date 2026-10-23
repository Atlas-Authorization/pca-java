package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The W-B checks of an Intent Layer v2 verifier (packages/pca/src/intent-env.ts {@code decideIntentWB}): rules 16
 * ({@code facts}), 17 ({@code provenance}) and 18 ({@code classes}) in that order. Each is REPORTED only when its member is
 * present or its policy is active; the first failing check denies and later checks are not reported. A rule-17
 * {@code question} continues (outcome {@code question}). Never throws.
 */
public final class IntentWB {
    private IntentWB() {}

    /** The W-B result. {@code checks}: insertion order facts, provenance, classes; values pass / question / fail. */
    public static final class Result {
        public String outcome = "admit";
        public final LinkedHashMap<String, String> checks = new LinkedHashMap<>();
        public Map<String, Object> world;
        public Map<String, Object> prov;
        public Map<String, Object> cls;
        public String reason;
        public String friction;
        public List<String> singleSource;
    }

    /**
     * Run rules 16-18 over {@code input} = {@code {now, aud, session, action:{verb,resource,params}, intent_session:{facts?,
     * offer_set?, prov?, classes?, labels?}, artifacts?:{facts?, offer_set?, labels?, verdicts?}, policy:{world?, provenance?,
     * classifiers?}}} (already normalized; an absent key is undefined).
     */
    public static Result decide(Map<String, Object> input) {
        Result out = new Result();
        String ce = contextError(input);
        if (ce != null) return deny(out, "facts", "facts: the W-B context is malformed: " + ce);
        Object s = input.get("intent_session");
        Object a = IntentJs.opt(input, "artifacts", new LinkedHashMap<String, Object>());
        Object policy = IntentJs.opt(input, "policy", new LinkedHashMap<String, Object>());
        Object worldPolicy = IntentJs.opt(policy, "world", new LinkedHashMap<String, Object>());

        Map<String, Object> committed = new LinkedHashMap<>();
        if (IntentJs.own(s, "facts")) committed.put("facts", IntentJs.get(s, "facts"));
        if (IntentJs.own(s, "offer_set")) committed.put("offer_set", IntentJs.get(s, "offer_set"));
        if (OracleFacts.intentWorldActive(committed, worldPolicy)) {
            Map<String, Object> wi = new LinkedHashMap<>();
            wi.put("now", input.get("now"));
            wi.put("aud", input.get("aud"));
            wi.put("session", input.get("session"));
            wi.put("action", input.get("action"));
            wi.put("committed", committed);
            if (IntentJs.own(a, "facts")) wi.put("facts", IntentJs.get(a, "facts"));
            if (IntentJs.own(a, "offer_set")) wi.put("offer_set", IntentJs.get(a, "offer_set"));
            wi.put("policy", worldPolicy);
            OracleFacts.WorldResult w = OracleFacts.decide(wi);
            if (!w.ok) return deny(out, "facts", w.reason);
            out.checks.put("facts", "pass");
            out.world = w.world;
            if (!w.singleSource.isEmpty()) out.singleSource = w.singleSource;
        }
        Object labels = IntentJs.get(s, "labels");
        boolean provActive = provenanceActive(s, policy);
        if (provActive) {
            Map<String, Object> pi = new LinkedHashMap<>();
            // an absent `aud` stays absent (TS passes ctx.aud through: rule 17 prints it as 'undefined', not 'null')
            if (input.containsKey("aud")) pi.put("aud", input.get("aud"));
            pi.put("session", input.get("session"));
            pi.put("action", input.get("action"));
            if (IntentJs.own(s, "prov")) pi.put("prov", IntentJs.get(s, "prov"));
            if (IntentJs.own(s, "labels")) pi.put("committed_labels", labels);
            if (IntentJs.own(a, "labels")) pi.put("labels", IntentJs.get(a, "labels"));
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("params", new LinkedHashMap<String, Object>());
            Object pp = IntentJs.opt(policy, "provenance", empty);
            pi.put("policy", pp);
            ParamProvenance.ProvResult p = ParamProvenance.decide(pi);
            if (p.outcome.equals("deny")) return deny(out, "provenance", p.reason);
            out.checks.put("provenance", p.outcome.equals("question") ? "question" : "pass");
            out.prov = p.env;
            if (p.outcome.equals("question")) {
                out.outcome = "question";
                out.reason = p.reason;
                out.friction = p.friction;
            }
        }
        Map<String, Object> clsPolicy = new LinkedHashMap<>();
        clsPolicy.put("classifiers", IntentJs.opt(policy, "classifiers", new java.util.ArrayList<Object>()));
        Object committedClasses = IntentJs.get(s, "classes");
        if (IntentClassifier.classifierCheckActive(committedClasses, clsPolicy)) {
            Map<String, Object> ci = new LinkedHashMap<>();
            ci.put("session", input.get("session"));
            ci.put("action", input.get("action"));
            if (IntentJs.own(s, "classes")) ci.put("committed", committedClasses);
            if (IntentJs.own(a, "verdicts")) ci.put("verdicts", IntentJs.get(a, "verdicts"));
            ci.put("policy", clsPolicy);
            IntentClassifier.ClassResult c = IntentClassifier.decide(ci);
            if (!c.ok) return deny(out, "classes", c.reason);
            out.checks.put("classes", "pass");
            out.cls = c.classes;
        }
        return out;
    }

    /**
     * The W-B context (absent = empty; present with null or the wrong JSON type = malformed): {@code intent_session} an
     * object; {@code artifacts} an object whose {@code facts}, {@code labels}, {@code verdicts} are arrays and {@code offer_set}
     * an object; {@code policy} an object whose {@code world}, {@code provenance} are objects and {@code classifiers} an array.
     */
    static String contextError(Map<String, Object> input) {
        if (!(input.get("intent_session") instanceof Map)) return "intent_session must be an object";
        if (input.containsKey("artifacts")) {
            Object a = input.get("artifacts");
            if (!(a instanceof Map)) return "artifacts must be an object";
            String am = IntentArtifacts.closedMembers(IntentJs.obj(a), List.of(), List.of("facts", "labels", "verdicts", "offer_set"), "artifacts");
            if (am != null) return am;
            for (String k : new String[] {"facts", "labels", "verdicts"}) if (IntentJs.own(a, k) && !(IntentJs.get(a, k) instanceof List)) return "artifacts." + k + " must be an array";
            if (IntentJs.own(a, "offer_set") && !(IntentJs.get(a, "offer_set") instanceof Map)) return "artifacts.offer_set must be an object";
        }
        if (input.containsKey("policy")) {
            Object p = input.get("policy");
            if (!(p instanceof Map)) return "policy must be an object";
            String pm = IntentArtifacts.closedMembers(IntentJs.obj(p), List.of(), List.of("world", "provenance", "classifiers"), "policy");
            if (pm != null) return pm;
            for (String k : new String[] {"world", "provenance"}) if (IntentJs.own(p, k) && !(IntentJs.get(p, k) instanceof Map)) return "policy." + k + " must be an object";
            if (IntentJs.own(p, "classifiers") && !(IntentJs.get(p, "classifiers") instanceof List)) return "policy.classifiers must be an array";
        }
        return null;
    }

    /** Rule 17 is active iff {@code prov} is present (any value), {@code labels} a non-empty array, or the policy a plain object. */
    public static boolean provenanceActive(Object intentSession, Object policy) {
        return IntentJs.own(intentSession, "prov") || OracleFacts.nonEmpty(IntentJs.get(intentSession, "labels")) || IntentJs.get(policy, "provenance") instanceof Map;
    }

    /** The {@code primitives.intent_wb_active} entry point: which of facts / provenance / classes are reported. */
    public static boolean[] active(Object input) {
        Map<String, Object> in = IntentJs.obj(IntentJs.normalize(input));
        Object s = IntentJs.opt(in, "intent_session", new LinkedHashMap<String, Object>());
        Object p = IntentJs.opt(in, "policy", new LinkedHashMap<String, Object>());
        Map<String, Object> committed = new LinkedHashMap<>();
        if (IntentJs.own(s, "facts")) committed.put("facts", IntentJs.get(s, "facts"));
        if (IntentJs.own(s, "offer_set")) committed.put("offer_set", IntentJs.get(s, "offer_set"));
        Map<String, Object> clsPolicy = new LinkedHashMap<>();
        clsPolicy.put("classifiers", IntentJs.get(p, "classifiers"));
        return new boolean[] {
            OracleFacts.intentWorldActive(committed, IntentJs.opt(p, "world", new LinkedHashMap<String, Object>())),
            provenanceActive(s, p),
            IntentClassifier.classifierCheckActive(IntentJs.get(s, "classes"), clsPolicy)};
    }

    private static Result deny(Result out, String check, String reason) {
        out.outcome = "deny";
        out.checks.put(check, "fail");
        out.reason = reason;
        out.world = null;
        out.prov = null;
        out.cls = null;
        out.friction = null;
        out.singleSource = null;
        return out;
    }
}
