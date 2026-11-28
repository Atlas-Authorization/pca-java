package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.analyzer.Enumerate;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/** Policy plumbing: an outcome as the analyzer's concrete action, and the real evaluator as an admission oracle. */
public final class IntentPolicy {
    private IntentPolicy() {}

    /** Default resource string when the space has no resource dimension for a verb. */
    public static final String ANY_RESOURCE = "resource:any";

    /** {predicates, caveats} of a policy: a non-array member counts as empty. */
    public static Map<String, Object> normalizePolicy(Object p) {
        if (!(p instanceof Map) && !(p instanceof List) && net.atlasauth.pca.oauth.JsVal.truthy(p))
            throw new IllegalStateException("TypeError: Cannot use 'in' operator to search for 'caveats' in " + jsString(p)); // `in` on a truthy primitive
        Object preds = p instanceof Map ? ((Map<?, ?>) p).get("predicates") : null;
        Object cavs = p instanceof Map ? ((Map<?, ?>) p).get("caveats") : null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("predicates", preds instanceof List ? preds : new ArrayList<Object>());
        out.put("caveats", cavs instanceof List ? cavs : new ArrayList<Object>());
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void setPath(Map<String, Object> root, String[] segs, int from, Object value) {
        Map<String, Object> cur = root;
        for (int i = from; i < segs.length - 1; i++) {
            Object next = cur.get(segs[i]);
            if (!(next instanceof Map)) cur.put(segs[i], new LinkedHashMap<String, Object>());
            cur = (Map<String, Object>) cur.get(segs[i]);
        }
        cur.put(segs[segs.length - 1], value);
    }

    static String jsString(Object v) {
        if (v instanceof Double) return AttestCommon.jsNumString((Double) v);
        return String.valueOf(v);
    }

    /** The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the space). */
    public static Map<String, Object> outcomeToAction(VerbSpace vs, Outcome o) {
        Map<String, Object> params = new LinkedHashMap<>();
        Map<String, Object> env = new LinkedHashMap<>();
        Map<String, Object> subject = new LinkedHashMap<>();
        String resource = ANY_RESOURCE;
        for (Map.Entry<String, Object> e : o.values().entrySet()) {
            String path = e.getKey();
            String[] segs = path.split("\\.", -1);
            if (path.equals("action.resource")) resource = jsString(e.getValue());
            else if (segs[0].equals("action") && segs.length > 2 && segs[1].equals("params")) setPath(params, segs, 2, e.getValue());
            else if (segs[0].equals("env") && segs.length > 1) setPath(env, segs, 1, e.getValue());
            else if (segs[0].equals("subject") && segs.length > 1) setPath(subject, segs, 1, e.getValue());
        }
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("verb", o.verb());
        a.put("resource", resource);
        a.put("params", params);
        a.put("reversibilityClass", vs.reversibility);
        if (!env.isEmpty()) a.put("env", env);
        if (!subject.isEmpty()) a.put("subject", subject);
        return a;
    }

    /** A compiled admission oracle for one policy (compile once, query many times). */
    public interface Admitter { boolean admits(VerbSpace vs, Outcome o); }

    public static Admitter admitter(Object policy) {
        Enumerate.PolicyModel model = Enumerate.toModel(policy);
        return (vs, o) -> Enumerate.admitsAction(model, outcomeToAction(vs, o));
    }

    public static VerbSpace vsOf(Omega omega, Outcome o) {
        for (VerbSpace v : omega.verbs) if (v.verb.equals(o.verb())) return v;
        return null;
    }
}
