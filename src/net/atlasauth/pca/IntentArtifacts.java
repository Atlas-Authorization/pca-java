package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Shared conventions of the Intent Layer v2 W-B artifacts (rules 16-18; packages/pca/src/intent-artifacts.ts): closed
 * member sets, Ed25519 signatures under a VERIFIER-pinned key over {@code utf8(domain) || strictCanonical(artifact without
 * sig)}, content-addressed references, and own-member parameter paths.
 */
final class IntentArtifacts {
    private IntentArtifacts() {}

    static final Pattern INTENT_NAME_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    static final Pattern DATA_CLASS_RE = Pattern.compile("[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*");
    static final Pattern PARAM_SEGMENT_RE = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Set<String> FORBIDDEN_SEGMENTS = Set.of("__proto__", "constructor", "prototype");

    static boolean isPathSegment(String s) { return PARAM_SEGMENT_RE.matcher(s).matches() && !FORBIDDEN_SEGMENTS.contains(s); }
    static boolean isName(Object v) { return v instanceof String && INTENT_NAME_RE.matcher((String) v).matches(); }
    static boolean isBoundedString(Object v, int max) {
        return v instanceof String && !((String) v).isEmpty() && IntentJs.u8len((String) v) <= max;
    }
    static boolean isDigest(Object v) { return IntentJs.b32(v); }
    /** A wire scalar: string, boolean or safe integer (not -0). */
    static boolean isScalar(Object v) { return v instanceof String || v instanceof Boolean || IntentJs.isInt(v); }
    /** Same JSON type and value ({@code 2 != "2"}, {@code true != 1}). */
    static boolean scalarEq(Object a, Object b) {
        if (a instanceof String || b instanceof String) return a instanceof String && a.equals(b);
        if (a instanceof Boolean || b instanceof Boolean) return a instanceof Boolean && a.equals(b);
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        if (x != null && y != null) return x.doubleValue() == y.doubleValue();
        return a == null && b == null; // typeof null === 'object' and null === null
    }

    /** Null when every key is listed and every required key is present, else the reason. */
    static String closedMembers(Map<String, Object> o, List<String> required, List<String> optional, String where) {
        for (String k : o.keySet()) if (!required.contains(k) && !optional.contains(k)) return "unknown member '" + where + "." + k + "'";
        for (String k : required) if (!o.containsKey(k)) return "missing member '" + where + "." + k + "'";
        return null;
    }

    /** The optional suite members every W-B artifact may carry ({@code alg} and {@code pq_pk} are signed, {@code pq_sig} is not). */
    static final List<String> SUITE_MEMBERS = List.of("alg", "pq_pk", "pq_sig");

    /** A pin entry's optional {@code pq_pk}: absent, or a non-empty string. */
    static boolean pinPqOk(Object pin) {
        if (!IntentJs.own(pin, "pq_pk")) return true;
        Object v = IntentJs.get(pin, "pq_pk");
        return v instanceof String && !((String) v).isEmpty();
    }

    /**
     * The artifact's suite capability: a non-string {@code alg} is malformed, an {@code alg} this verifier does not implement
     * is {@code unsupported_suite}, {@code pq_pk} / {@code pq_sig} must be strings, and an ed25519 artifact carries neither.
     */
    static String artifactSuiteError(Map<String, Object> a) {
        String e = IntentJs.suiteError(a.get("alg"), a.containsKey("alg"));
        if (e != null) return e;
        for (String k : new String[] {"pq_pk", "pq_sig"}) if (a.containsKey(k) && !(a.get(k) instanceof String)) return k + " must be a string";
        if (IntentJs.suiteOf(a).equals("ed25519") && (a.containsKey("pq_pk") || a.containsKey("pq_sig"))) return "an ed25519 artifact must not carry pq_pk / pq_sig";
        return null;
    }

    /** {@code utf8(domain) || strictCanonical(artifact without sig and pq_sig)}. */
    static byte[] artifactMessage(String domain, Map<String, Object> artifact) {
        Map<String, Object> body = new LinkedHashMap<>(artifact);
        body.remove("sig");
        body.remove("pq_sig");
        return IntentJs.message(domain, body);
    }

    /**
     * The artifact's signature under the PINNED signer ({@code pk}, and for a PQ / hybrid suite the pin's {@code pq_pk}: the
     * artifact's own {@code pq_pk} alone never authorises it); malformed input is a failed signature. Never throws.
     */
    static boolean verifyArtifactSig(String domain, Map<String, Object> artifact, Object pinnedPk, Object pinnedPqPk) {
        try {
            if (!(artifact.get("sig") instanceof String) || !(pinnedPk instanceof String)) return false;
            return IntentJs.verifyPinnedSuite(artifact.get("alg"), artifact.containsKey("alg"), (String) pinnedPk, artifact.get("pq_pk"),
                artifactMessage(domain, artifact), artifact.get("sig"), artifact.get("pq_sig"), IntentJs.pin((String) pinnedPk, pinnedPqPk));
        } catch (RuntimeException e) {
            return false;
        }
    }

    static String artifactRef(String refDomain, String slot, Object artifact) { return IntentJs.ref(refDomain, slot, artifact); }

    /** Resolve {@code action.params.a.b} through OWN members of plain objects (segments [A-Za-z0-9_-]{1,64}, no prototype names). */
    static Predicates.Resolved resolveParamPath(Object params, Object path) {
        if (!(path instanceof String) || !((String) path).startsWith("action.params.")) return new Predicates.Resolved(false, null);
        String[] segs = ((String) path).substring("action.params.".length()).split("\\.", -1);
        Object cur = params;
        for (String s : segs) {
            if (!isPathSegment(s) || !(cur instanceof Map) || !((Map<?, ?>) cur).containsKey(s)) return new Predicates.Resolved(false, null);
            cur = ((Map<?, ?>) cur).get(s);
        }
        return new Predicates.Resolved(true, cur);
    }

    static boolean isParamPath(Object path) {
        if (!(path instanceof String) || !((String) path).startsWith("action.params.")) return false;
        String[] segs = ((String) path).substring("action.params.".length()).split("\\.", -1);
        if (segs.length < 1 || segs.length > 8) return false;
        for (String s : segs) if (!isPathSegment(s)) return false;
        return true;
    }

    /** Set {@code root.<path>} creating plain objects; false when the path collides with an existing member. */
    @SuppressWarnings("unchecked")
    static boolean setNested(Map<String, Object> root, String path, Object value) {
        String[] segs = path.split("\\.", -1);
        Map<String, Object> cur = root;
        for (int i = 0; i < segs.length - 1; i++) {
            String k = segs[i];
            if (!cur.containsKey(k)) cur.put(k, new LinkedHashMap<String, Object>());
            Object next = cur.get(k);
            if (!(next instanceof Map)) return false;
            cur = (Map<String, Object>) next;
        }
        String last = segs[segs.length - 1];
        if (cur.containsKey(last)) return false;
        cur.put(last, value);
        return true;
    }

    /** A list member (read with {@link IntentJs#opt}); anything else, null included, is malformed and fails closed. */
    static List<?> iterable(Object o) {
        if (o instanceof List) return (List<?>) o;
        throw new IllegalArgumentException("not a list");
    }

    /** {@code action.params} (absent = {}); a present non-object is malformed and fails closed. */
    static Object actionParams(Object action) {
        Object p = IntentJs.opt(action, "params", new LinkedHashMap<String, Object>());
        if (!(p instanceof Map)) throw new IllegalArgumentException("action.params is not an object");
        return p;
    }
}
