package net.atlasauth.pca.wallet;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.WalletBridge;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The wallet side of the PCA Intent Layer v2: the wire formats of the trusted question channel (the principal-signed answer,
 * M6), friction tiers scaled by harm, and the helpers the rest of the package shares. Values are the parsed-JSON tree
 * (Map, List, String, Boolean, {@link Json.Num}, null) so a result compares with the TypeScript reference as JSON.
 */
public final class Wallet {
    private Wallet() {}

    public static final String INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\0";
    public static final String INTENT_ANSWER_REF_DOMAIN = "atlas-pca/intent-answer-ref/v1";
    public static final String INTENT_TYPED_DOMAIN = "atlas-pca/intent-typed/v1";
    public static final String INTENT_DEVICE_CHALLENGE_DOMAIN = "atlas-pca/intent-device/v1";
    public static final String INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1";
    public static final long MIN_HOLD_MS = 2000L;

    // ---- friction tiers ------------------------------------------------------------------------------------------------

    public static final List<String> FRICTION_ORDER = List.of("tap", "hold", "typed", "device");

    public static boolean isFrictionTier(Object x) { return x instanceof String && FRICTION_ORDER.contains(x); }

    /** Index in tap &lt; hold &lt; typed &lt; device; -1 for anything else (as {@code Array.indexOf}). */
    public static int frictionRank(Object t) { return t instanceof String ? FRICTION_ORDER.indexOf(t) : -1; }

    public static String maxFriction(List<?> ts) {
        String best = "tap";
        for (Object t : ts) if (frictionRank(t) > frictionRank(best)) best = (String) t;
        return best;
    }

    public static String maxFriction(String... ts) { return maxFriction(Arrays.asList((Object[]) ts)); }

    // ---- shared helpers ------------------------------------------------------------------------------------------------

    /** Is the key present (the reference's "!== undefined" for JSON-sourced input; a JSON null is defined). */
    static boolean defined(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** A plain object in the reference's sense (not null, not an array). */
    public static boolean isObj(Object v) { return v instanceof Map; }

    public static boolean isB64u32(Object v) { return Pca.decodeB64uStrict(v, 32) != null; }

    /** Number.isSafeInteger and not -0. */
    static boolean isInt(Object v) {
        Double d = JsVal.num(v);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0 && !JsVal.isNegZero(v);
    }

    static boolean isSafeInteger(Object v) {
        Double d = JsVal.num(v);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    static boolean isFinite(Object v) {
        Double d = JsVal.num(v);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d);
    }

    /** The number value of a number, else NaN (a comparison with it is false, as in JavaScript). */
    static double nv(Object v) {
        Double d = JsVal.num(v);
        return d == null ? Double.NaN : d;
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static byte[] utf8(String s) { return Json.utf8(s); }

    static byte[] domainMessage(String domain, Object body) { return WalletBridge.message(domain, body); }

    /** Coordinates as the core validates them (shared with intent_required). */
    public static String coordsError(Object c) { return WalletBridge.cellCoordsError(c); }

    /** {@code JSON.parse(JSON.stringify(v))}: a deep copy where -0 becomes 0 and every number is spelled as JavaScript prints it. */
    static Object plain(Object v) {
        if (v instanceof Map) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) m.put((String) e.getKey(), plain(e.getValue()));
            return m;
        }
        if (v instanceof List) {
            List<Object> l = new ArrayList<>();
            for (Object x : (List<?>) v) l.add(plain(x));
            return l;
        }
        if (JsVal.isNumber(v)) return JsVal.isNegZero(v) ? new Json.Num("0") : IntentJs.normalize(v instanceof Json.Num ? v : new Json.Num(String.valueOf(v)));
        return v;
    }

    /** The first member of {@code o} that is not in {@code allowed}, as the reference's message; null when none. */
    static String onlyKeys(Object o, List<String> allowed) {
        for (Object k : ((Map<?, ?>) o).keySet()) if (!allowed.contains(k)) return "unknown member \"" + k + "\"";
        return null;
    }

    // ---- the action and its digest -------------------------------------------------------------------------------------

    /** The V3 action digest of an attempted action (what intent_required.action_digest and a JIT consent bind to). */
    public static String pcaActionDigest(Map<String, Object> a) {
        Object params = a.get("params");
        for (String k : new String[] {"verb", "resource", "reversibility_class"}) if (!a.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        Map<String, Object> action = obj("verb", a.get("verb"), "resource", a.get("resource"), "params_digest", Pca.paramsDigest(params), "reversibility_class", a.get("reversibility_class"));
        return Pca.hashCanonical(obj("d", INTENT_ACTION_DOMAIN, "action", action));
    }

    /**
     * The default projection of an attempted action onto the outcome-space paths: action.resource and every scalar param as
     * action.params.NAME. Returns {verb, values}.
     */
    private static final Object NULL = new Object();

    public static Map<String, Object> actionValuesOf(Map<String, Object> a) {
        Map<String, Object> values = new LinkedHashMap<>();
        if (a.containsKey("resource")) values.put("action.resource", a.get("resource"));
        Object ps = a.get("params");
        if (ps == null) throw new IllegalArgumentException("Cannot convert undefined or null to object");
        List<Map.Entry<String, Object>> entries = new ArrayList<>();
        if (ps instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) ps).entrySet()) entries.add(Map.entry((String) e.getKey(), e.getValue() == null ? NULL : e.getValue()));
        } else if (ps instanceof List) {
            for (int i = 0; i < ((List<?>) ps).size(); i++) entries.add(Map.entry(String.valueOf(i), ((List<?>) ps).get(i) == null ? NULL : ((List<?>) ps).get(i)));
        } else if (ps instanceof String) {
            for (int i = 0; i < ((String) ps).length(); i++) entries.add(Map.entry(String.valueOf(i), String.valueOf(((String) ps).charAt(i))));
        }
        for (Map.Entry<String, Object> e : entries) {
            Object v = e.getValue();
            if (v instanceof String || (JsVal.isNumber(v) && isFinite(v))) values.put("action.params." + e.getKey(), v);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (a.containsKey("verb")) out.put("verb", a.get("verb"));
        out.put("values", values);
        return out;
    }

    // ---- M6: the signed answer -----------------------------------------------------------------------------------------

    private static final Pattern QID_RE = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final List<String> ANS_KEYS = List.of("v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig");
    private static final List<String> UX_KEYS = List.of("tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action");
    private static final List<String> WA_KEYS = List.of("credential_id", "authenticator_data", "client_data_json", "signature");

    private static boolean strEq(Object v, String s) { return s.equals(v); }

    private static boolean numEq(Object v, double d) { return JsVal.isNumber(v) && JsVal.num(v) == d; }

    private static boolean allInts(Object v) {
        if (!(v instanceof List)) return false;
        for (Object x : (List<?>) v) if (!isInt(x)) return false;
        return true;
    }

    private static boolean allNonEmptyStrings(Object v) {
        if (!(v instanceof List)) return false;
        for (Object x : (List<?>) v) if (!(x instanceof String) || ((String) x).isEmpty()) return false;
        return true;
    }

    /** The reference's partialError: null when the "Partly..." spec is structurally valid. */
    public static String partialShapeError(Object p) {
        if (!isObj(p) || !(get(p, "path") instanceof String) || ((String) get(p, "path")).isEmpty()) return "partial.path must be a non-empty string";
        List<String> keys = new ArrayList<>();
        for (Object k : ((Map<?, ?>) p).keySet()) if (!"path".equals(k)) keys.add((String) k);
        if (keys.size() != 1) return "partial must carry exactly one of upTo / from / except / notFor";
        String k = keys.get(0);
        Object v = ((Map<?, ?>) p).get(k);
        if ((k.equals("upTo") || k.equals("from")) && !isInt(v)) return "partial." + k + " must be an integer";
        if (k.equals("except") && !(v instanceof List && !((List<?>) v).isEmpty() && allInts(v))) return "partial.except must be a non-empty integer array";
        if (k.equals("notFor") && !(v instanceof List && !((List<?>) v).isEmpty() && allNonEmptyStrings(v))) return "partial.notFor must be a non-empty string array";
        if (!List.of("upTo", "from", "except", "notFor").contains(k)) return "unknown partial member \"" + k + "\"";
        return null;
    }

    /** The reference's answerShapeError: null when the (unsigned or signed) answer is well formed. */
    public static String answerShapeError(Object a) {
        if (!isObj(a)) return "not an object";
        String extra = onlyKeys(a, ANS_KEYS);
        if (extra != null) return extra;
        if (!numEq(get(a, "v"), 2) || !strEq(get(a, "kind"), "pca-intent-observation")) return "not a pca-intent-observation v2";
        for (String k : new String[] {"map_digest", "session", "signer"}) if (!isB64u32(get(a, k))) return k + " is not canonical base64url (32 bytes)";
        Object qid = get(a, "question_id");
        if (!(qid instanceof String) || !QID_RE.matcher((String) qid).matches()) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (!(get(a, "verb") instanceof String) || ((String) get(a, "verb")).isEmpty()) return "verb must be a non-empty string";
        String ce = coordsError(get(a, "cell"));
        if (ce != null) return "cell: " + ce;
        Object y = get(a, "y");
        if (!numEq(y, 0) && !numEq(y, 1)) return "y must be 0 or 1";
        if (defined(a, "partial")) {
            String pe = partialShapeError(get(a, "partial"));
            if (pe != null) return pe;
            if (!numEq(y, 1)) return "a partial answer carries y = 1 (yes for the part)";
        }
        Object source = get(a, "source");
        if (!strEq(source, "elicitation") && !strEq(source, "clarification")) return "source must be elicitation or clarification";
        Object obs = get(a, "observed_at");
        if (!(isInt(obs) && nv(obs) >= 0)) return "observed_at must be a non-negative safe integer";
        if (!strEq(get(a, "alg"), "ed25519")) return "alg must be ed25519";
        Object ux = get(a, "ux");
        if (!isObj(ux)) return "ux must be an object";
        String ue = onlyKeys(ux, UX_KEYS);
        if (ue != null) return "ux: " + ue;
        if (!isFrictionTier(get(ux, "tier"))) return "ux.tier is not a friction tier";
        if (!isB64u32(get(ux, "rendered_digest"))) return "ux.rendered_digest is not canonical base64url (32 bytes)";
        if (!(get(ux, "canary") instanceof Boolean)) return "ux.canary must be a boolean";
        if (defined(ux, "typed_digest") && !isB64u32(get(ux, "typed_digest"))) return "ux.typed_digest is not canonical base64url (32 bytes)";
        if (defined(ux, "hold_ms") && !(isInt(get(ux, "hold_ms")) && nv(get(ux, "hold_ms")) >= 0)) return "ux.hold_ms must be a non-negative integer";
        if (defined(ux, "action_digest") && !isB64u32(get(ux, "action_digest"))) return "ux.action_digest is not canonical base64url (32 bytes)";
        if (defined(ux, "consent_for_action") && !(get(ux, "consent_for_action") instanceof Boolean)) return "ux.consent_for_action must be a boolean";
        boolean consent = Boolean.TRUE.equals(get(ux, "consent_for_action"));
        if (consent && (!defined(ux, "action_digest") || !numEq(y, 1) || defined(a, "partial"))) return "consent_for_action needs action_digest and a plain yes";
        if (consent && Boolean.TRUE.equals(get(ux, "canary"))) return "a canary never consents to an action";
        if (defined(ux, "webauthn")) {
            Object wa = get(ux, "webauthn");
            boolean bad = !isObj(wa) || onlyKeys(wa, WA_KEYS) != null;
            if (!bad) for (String k : WA_KEYS) if (!(get(wa, k) instanceof String)) bad = true;
            if (bad) return "ux.webauthn is malformed";
        }
        // The tier's own evidence must be present (a "yes" only: a "no" needs no friction).
        if (numEq(y, 1) && !Boolean.TRUE.equals(get(ux, "canary"))) {
            Object tier = get(ux, "tier");
            if ("hold".equals(tier) && !(isInt(get(ux, "hold_ms")) && nv(get(ux, "hold_ms")) >= MIN_HOLD_MS)) return "hold tier needs hold_ms >= " + MIN_HOLD_MS;
            if ("typed".equals(tier) && !defined(ux, "typed_digest")) return "typed tier needs typed_digest";
            if ("device".equals(tier) && !defined(ux, "webauthn")) return "device tier needs a WebAuthn assertion";
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> answerBody(Map<String, Object> a) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg"})
            if (a.containsKey(k)) m.put(k, a.get(k));
        return (Map<String, Object>) plain(m);
    }

    /**
     * Wallet side: sign the principal's answer. {@code a} is the answer without v / kind / signer / alg; {@code principalSeed} is
     * the 32-byte Ed25519 seed of the principal key. Throws when the answer is malformed.
     */
    public static Map<String, Object> signIntentAnswer(Map<String, Object> a, byte[] principalSeed) {
        Keys.EdKey key = Keys.edFromSeed(principalSeed);
        Map<String, Object> in = new LinkedHashMap<>(a);
        in.put("v", JsVal.n(2));
        in.put("kind", "pca-intent-observation");
        in.put("signer", key.id());
        in.put("alg", "ed25519");
        Map<String, Object> body = answerBody(in);
        String bad = answerShapeError(body);
        if (bad != null) throw new IllegalArgumentException("signIntentAnswer: " + bad);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", Keys.b64u(key.sign(domainMessage(INTENT_ANSWER_SIG_DOMAIN, body))));
        return out;
    }

    /** Verify a signed answer; {@code principals} (nullable) restricts the signer. Never throws: {ok:true} or {ok:false, reason}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyIntentAnswer(Object a, List<?> principals) {
        try {
            String bad = answerShapeError(a);
            if (bad != null) return obj("ok", false, "reason", bad);
            Map<String, Object> ans = (Map<String, Object>) a;
            if (principals != null && !principals.contains(ans.get("signer"))) return obj("ok", false, "reason", "signer is not a principal of the session");
            Object sig = ans.get("sig");
            if (!(sig instanceof String) || !WalletBridge.verifyEd((String) ans.get("signer"), domainMessage(INTENT_ANSWER_SIG_DOMAIN, answerBody(ans)), (String) sig)) return obj("ok", false, "reason", "bad signature");
            return obj("ok", true);
        } catch (RuntimeException e) {
            return obj("ok", false, "reason", "malformed answer: " + e.getMessage());
        }
    }

    /** Content address of a signed answer. */
    public static String answerRef(Object a) { return Pca.hashCanonical(obj("d", INTENT_ANSWER_REF_DOMAIN, "a", a)); }

    /** The typed-tier digest. */
    public static String typedDigest(String questionId, String normalizedValue) {
        return Pca.hashCanonical(obj("d", INTENT_TYPED_DOMAIN, "q", questionId, "v", normalizedValue));
    }

    /** The 32-byte WebAuthn challenge of a device-tier answer: {questionId, renderedDigest, y, actionDigest?}. */
    public static String deviceChallenge(String questionId, String renderedDigest, long y, String actionDigest) {
        return Pca.hashCanonical(obj("d", INTENT_DEVICE_CHALLENGE_DOMAIN, "q", questionId, "r", renderedDigest, "y", JsVal.n(y), "a", actionDigest));
    }

    // ---- friction scaled by harm ---------------------------------------------------------------------------------------

    public static final List<String> PROVENANCE_ORDER = List.of("trusted", "first_party", "tool", "web", "agent");

    public static boolean isProvenanceLevel(Object x) { return x instanceof String && PROVENANCE_ORDER.contains(x); }

    /** The highest (least trusted) level of a set; "agent" for an empty or unknown set (fail closed). */
    public static String worstProvenance(Object levels) {
        if (levels instanceof String) return "agent"; // iterating a string yields single characters, none a level
        if (!(levels instanceof List)) throw new IllegalArgumentException("levels is not iterable");
        int best = -1;
        for (Object l : (List<?>) levels) {
            if (!isProvenanceLevel(l)) return "agent";
            best = Math.max(best, PROVENANCE_ORDER.indexOf(l));
        }
        return best < 0 ? "agent" : PROVENANCE_ORDER.get(best);
    }

    /** {hTap: 5, hDevice: 100000}. */
    public static Map<String, Object> defaultFrictionThresholds() { return obj("hTap", JsVal.n(5), "hDevice", JsVal.n(100_000)); }

    /**
     * The tier of a question as {tier, rules}: a pure function of the cell's reversibility, expected harm, provenance and the
     * site minimum. {@code inp} members: reversibility, expectedHarm, provenance?, widensCriticalIdentity?, singleSource?, siteMin?.
     */
    public static Map<String, Object> frictionFor(Map<String, Object> inp, Map<String, Object> th) {
        Object eh = inp.get("expectedHarm");
        if (!(isFinite(eh) && nv(eh) >= 0)) return obj("tier", "device", "rules", new ArrayList<Object>(List.of("harm-unknown")));
        List<Object> rules = new ArrayList<>();
        String[] tier = {"tap"};
        java.util.function.BiConsumer<Object, String> raise = (t, why) -> {
            if (frictionRank(t) >= frictionRank(tier[0])) rules.add(why);
            tier[0] = maxFriction(Arrays.asList((Object) tier[0], t));
        };
        Object rev = inp.get("reversibility");
        double hTap = nv(th.get("hTap")), hDevice = nv(th.get("hDevice"));
        if ("rate_limited".equals(rev)) raise.accept("hold", "rate-limited");
        if (nv(eh) >= hTap) raise.accept("hold", "harm>=h_tap");
        if ("irreversible".equals(rev)) raise.accept("typed", "irreversible");
        boolean taintedCritical = false;
        Object prov = inp.get("provenance");
        if (prov != null) {
            if (!(prov instanceof List)) throw new IllegalArgumentException("provenance is not an array");
            for (Object p : (List<?>) prov) {
                if (p == null) throw new IllegalArgumentException("provenance entry is null");
                if ("critical".equals(get(p, "sensitivity"))) {
                    String w = worstProvenance(get(p, "levels"));
                    if (w.equals("web") || w.equals("agent")) { taintedCritical = true; break; }
                }
            }
        }
        if (taintedCritical) raise.accept("typed", "tainted-critical");
        if (JsVal.truthy(inp.get("widensCriticalIdentity")) && "irreversible".equals(rev)) raise.accept("device", "critical-irreversible");
        if (nv(eh) >= hDevice) raise.accept("device", "harm>=h_device");
        if (JsVal.truthy(inp.get("singleSource"))) raise.accept(FRICTION_ORDER.get(Math.min(FRICTION_ORDER.size() - 1, frictionRank(tier[0]) + 1)), "single-source");
        if (defined(inp, "siteMin")) raise.accept(inp.get("siteMin"), "site-minimum");
        return obj("tier", tier[0], "rules", rules);
    }

    public static Map<String, Object> frictionFor(Map<String, Object> inp) { return frictionFor(inp, defaultFrictionThresholds()); }

    /** Does an answer given at tier {@code given} satisfy a requirement of tier {@code required}? */
    public static boolean satisfiesTier(Object given, Object required) { return frictionRank(given) >= frictionRank(required); }
}
