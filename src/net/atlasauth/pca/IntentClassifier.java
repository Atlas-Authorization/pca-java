package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rule 18: classifier verdicts (packages/pca/src/intent-classifier.ts {@code decideClassifierDimensions}). A verdict
 * {@code pca-intent-classification} is signed by its {@code judge} key, which must be on the classifier's allowlist; per
 * classifier exactly one label must reach the k-of-n quorum of distinct judges. First failure wins; never throws.
 */
public final class IntentClassifier {
    private IntentClassifier() {}

    public static final String INTENT_CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\0";
    public static final String INTENT_CLASSIFIER_REF_DOMAIN = "atlas-pca/intent-classifier-ref/v1";
    public static final int MAX_COMMITTED_CLASSES = 8;
    public static final int MAX_CLASSIFIER_LABELS = 32;

    /** The rule-18 verdict: {@code classes} maps each classifier id to its quorum label. */
    public static final class ClassResult {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> classes;
        ClassResult(boolean ok, String reason, Map<String, Object> classes) { this.ok = ok; this.reason = reason; this.classes = classes; }
        static ClassResult fail(String reason) { return new ClassResult(false, "classes: " + reason, null); }
    }

    static String validateVerdictWire(Object vo) {
        if (!(vo instanceof Map)) return "verdict must be an object";
        Map<String, Object> v = IntentJs.obj(vo);
        String m = IntentArtifacts.closedMembers(v, List.of("v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"), IntentArtifacts.SUITE_MEMBERS, "verdict");
        if (m != null) return m;
        if (!OracleFacts.isOne(v.get("v")) || !"pca-intent-classification".equals(v.get("kind"))) return "verdict must be {v: 1, kind: \"pca-intent-classification\"}";
        if (!IntentArtifacts.isName(v.get("classifier"))) return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$";
        if (!IntentArtifacts.isDigest(v.get("session"))) return "'verdict.session' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.isDigest(v.get("content_digest"))) return "'verdict.content_digest' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.isBoundedString(v.get("label"), 64)) return "'verdict.label' must be a non-empty string (<= 64 bytes)";
        if (!IntentArtifacts.isBoundedString(v.get("measurement"), 256)) return "'verdict.measurement' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.isDigest(v.get("judge"))) return "'verdict.judge' must be canonical base64url (32 bytes)";
        if (!(v.get("sig") instanceof String)) return "'verdict.sig' must be a string";
        return null;
    }

    public static String verdictRef(Map<String, Object> v) { return IntentArtifacts.artifactRef(INTENT_CLASSIFIER_REF_DOMAIN, "c", v); }

    static String validatePolicy(Object po) {
        if (!(po instanceof Map) || !(IntentJs.get(po, "classifiers") instanceof List)) return "classifier policy needs a classifiers list";
        String cm = IntentArtifacts.closedMembers(IntentJs.obj(po), List.of("classifiers"), List.of(), "policy");
        if (cm != null) return cm;
        Set<String> ids = new HashSet<>();
        for (Object co : (List<?>) IntentJs.get(po, "classifiers")) {
            if (!(co instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(co), List.of("id", "param", "labels", "keys", "k"), List.of("measurements", "pq_keys"), "classifier") != null)
                return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}";
            if (!IntentArtifacts.isName(IntentJs.get(co, "id")) || ids.contains((String) IntentJs.get(co, "id")))
                return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$";
            Map<String, Object> c = IntentJs.obj(co);
            String id = (String) c.get("id");
            ids.add(id);
            if (!IntentArtifacts.isParamPath(c.get("param"))) return "classifier '" + id + "': param must be an action.params path";
            if (!(c.get("labels") instanceof List) || ((List<?>) c.get("labels")).isEmpty() || ((List<?>) c.get("labels")).size() > MAX_CLASSIFIER_LABELS)
                return "classifier '" + id + "': labels must hold 1.." + MAX_CLASSIFIER_LABELS + " strings";
            List<?> labels = (List<?>) c.get("labels");
            for (Object l : labels) if (!IntentArtifacts.isBoundedString(l, 64)) return "classifier '" + id + "': labels must be distinct non-empty strings";
            if (new HashSet<Object>(labels).size() != labels.size()) return "classifier '" + id + "': labels must be distinct non-empty strings";
            if (!(c.get("keys") instanceof List) || ((List<?>) c.get("keys")).isEmpty()) return "classifier '" + id + "': keys must be distinct 32-byte keys";
            List<?> keys = (List<?>) c.get("keys");
            for (Object k : keys) if (!IntentArtifacts.isDigest(k)) return "classifier '" + id + "': keys must be distinct 32-byte keys";
            if (new HashSet<Object>(keys).size() != keys.size()) return "classifier '" + id + "': keys must be distinct 32-byte keys";
            if (!IntentJs.isInt(c.get("k")) || IntentJs.num(c.get("k")) < 1 || IntentJs.num(c.get("k")) > keys.size())
                return "classifier '" + id + "': k must be an integer in [1, " + keys.size() + "]";
            if (c.containsKey("measurements")) {
                if (!(c.get("measurements") instanceof List)) return "classifier '" + id + "': measurements must be a list of strings";
                for (Object m : (List<?>) c.get("measurements")) if (!(m instanceof String)) return "classifier '" + id + "': measurements must be a list of strings";
            }
            if (c.containsKey("pq_keys")) {
                boolean ok = c.get("pq_keys") instanceof Map;
                if (ok) for (Map.Entry<String, Object> e : IntentJs.obj(c.get("pq_keys")).entrySet())
                    if (!keys.contains(e.getKey()) || !(e.getValue() instanceof String) || ((String) e.getValue()).isEmpty()) ok = false;
                if (!ok) return "classifier '" + id + "': pq_keys must map allowlisted keys to PQ keys";
            }
        }
        return null;
    }

    /** True iff rule 18 is active: the committed verdicts or the classifier policy is a non-empty array. */
    public static boolean classifierCheckActive(Object committed, Object policy) {
        return OracleFacts.nonEmpty(committed) || OracleFacts.nonEmpty(IntentJs.get(policy, "classifiers"));
    }

    /** The {@code primitives.intent_classifier} entry point: normalizes {@code input}, then {@link #decide(Map)}. */
    public static ClassResult decide(Object input) {
        try {
            return decide(IntentJs.obj(IntentJs.normalize(input)));
        } catch (RuntimeException e) {
            return ClassResult.fail("evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /** Rule 18 over an already normalized input {@code {session, action, committed?, verdicts?, policy}}. */
    static ClassResult decide(Map<String, Object> input) {
        try {
            String pe = validatePolicy(input.get("policy"));
            if (pe != null) return ClassResult.fail("policy misconfigured (fail closed): " + pe);
            Object committed = IntentJs.opt(input, "committed", List.of());
            if (!(committed instanceof List) || ((List<?>) committed).size() > MAX_COMMITTED_CLASSES)
                return ClassResult.fail("committed verdicts must be a list of at most " + MAX_COMMITTED_CLASSES + " digests");
            Set<String> seen = new HashSet<>();
            for (Object d : (List<?>) committed) if (!IntentArtifacts.isDigest(d) || !seen.add((String) d)) return ClassResult.fail("committed verdicts must be distinct canonical 32-byte digests");
            Object supplied = IntentJs.opt(input, "verdicts", List.of());
            if (!(supplied instanceof List)) return ClassResult.fail("verdicts must be an array");
            if (!(input.get("action") instanceof Map)) return ClassResult.fail("action must be an object");
            if (!(IntentJs.opt(input.get("action"), "params", Map.of()) instanceof Map)) return ClassResult.fail("action.params must be an object");
            Map<String, Map<String, Object>> byRef = new HashMap<>();
            for (Object v : IntentArtifacts.iterable(supplied)) {
                if (validateVerdictWire(v) != null) continue;
                try { byRef.put(verdictRef(IntentJs.obj(v)), IntentJs.obj(v)); } catch (RuntimeException e) { /* no reference */ }
            }
            Object action = input.get("action");
            Object params = IntentArtifacts.actionParams(action);
            List<?> classifiers = (List<?>) IntentJs.get(input.get("policy"), "classifiers");
            Map<String, Map<String, Integer>> votes = new HashMap<>();
            Set<String> pairs = new HashSet<>();
            for (Object d : (List<?>) committed) {
                Map<String, Object> v = byRef.get(d);
                if (v == null) return ClassResult.fail("a committed verdict was not supplied (or is malformed)");
                String se = IntentArtifacts.artifactSuiteError(v);
                if (se != null) return ClassResult.fail("verdict signature suite: " + se);
                Map<String, Object> c = null;
                for (Object x : classifiers) if (v.get("classifier").equals(IntentJs.get(x, "id"))) { c = IntentJs.obj(x); break; }
                if (c == null) return ClassResult.fail("verdict for undeclared classifier '" + v.get("classifier") + "'");
                String id = (String) c.get("id");
                if (!((List<?>) c.get("keys")).contains(v.get("judge"))) return ClassResult.fail("classifier '" + id + "': judge key is not on the allowlist");
                Object pq = IntentJs.own(c, "pq_keys") ? IntentJs.get(c.get("pq_keys"), (String) v.get("judge")) : null;
                if (!IntentArtifacts.verifyArtifactSig(INTENT_CLASSIFIER_DOMAIN, v, v.get("judge"), pq)) return ClassResult.fail("classifier '" + id + "': bad verdict signature");
                if (!v.get("session").equals(input.get("session"))) return ClassResult.fail("classifier '" + id + "': verdict bound to another session");
                Predicates.Resolved content = IntentArtifacts.resolveParamPath(params, c.get("param"));
                if (!content.found) return ClassResult.fail("classifier '" + id + "': the action carries no '" + c.get("param") + "'");
                if (!IntentJs.hashCanonical(content.value).equals(v.get("content_digest"))) return ClassResult.fail("classifier '" + id + "': verdict is about other content");
                if (!((List<?>) c.get("labels")).contains(v.get("label"))) return ClassResult.fail("classifier '" + id + "': label '" + v.get("label") + "' is not in its label set");
                if (c.containsKey("measurements") && !((List<?>) c.get("measurements")).contains(v.get("measurement")))
                    return ClassResult.fail("classifier '" + id + "': measurement is not pinned");
                if (!pairs.add(id + "\u0000" + v.get("judge"))) return ClassResult.fail("classifier '" + id + "': two verdicts from one judge");
                votes.computeIfAbsent(id, k -> new HashMap<>()).merge((String) v.get("label"), 1, Integer::sum);
            }
            Map<String, Object> classes = new LinkedHashMap<>();
            for (Object co : classifiers) {
                Map<String, Object> c = IntentJs.obj(co);
                String id = (String) c.get("id");
                Map<String, Integer> t = votes.getOrDefault(id, Map.of());
                double k = IntentJs.num(c.get("k"));
                List<String> winners = new ArrayList<>();
                for (Object l : (List<?>) c.get("labels")) if (t.getOrDefault(l, 0) >= k) winners.add((String) l);
                if (winners.isEmpty()) return ClassResult.fail("classifier '" + id + "': no label reaches the quorum " + IntentJs.lng(c.get("k")));
                if (winners.size() > 1) return ClassResult.fail("classifier '" + id + "': ambiguous, " + winners.size() + " labels reach the quorum");
                classes.put(id, winners.get(0));
            }
            return new ClassResult(true, null, classes);
        } catch (RuntimeException e) {
            return ClassResult.fail("evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }
}
