package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The signed "ask the principal" question of the Intent Layer and its RFC 9457 problem (packages/pca/src/intent-required.ts): when the agent's action
 * falls in a cell the principal's map leaves open, the site answers with a signed question (which action, which cell, how much friction to ask for,
 * where it was delivered, when it expires) and a 403 problem that carries it. Values are JSON-shaped maps.
 */
public final class IntentRequired {
    private IntentRequired() {}

    public static final String PROBLEM_BASE = "https://atlasauth.net/pca/problems/";
    public static final List<String> INTENT_PROBLEM_KINDS = NullSafe.list(List.of("intent-required", "intent-denied", "schema-violation", "ceiling"));
    public static final String INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\0";
    public static final String INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1";
    public static final List<String> FRICTIONS = NullSafe.list(List.of("tap", "hold", "typed", "device"));
    private static final List<String> BODY_KEYS = NullSafe.list(List.of("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason",
        "question_id", "friction", "delivered_to", "expires_at", "sig"));
    private static final Pattern QUESTION_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    private static Object need(Map<String, Object> d, String k) {
        if (!d.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return d.get(k);
    }

    /** The digest every question and verdict binds to: the strict hash of {d, action: {verb, resource, params_digest, reversibility_class}}. */
    public static String intentActionDigest(Object actionO) {
        Map<String, Object> action = IntentJs.obj(actionO);
        Map<String, Object> a = new LinkedHashMap<>();
        for (String k : new String[] {"verb", "resource", "params_digest", "reversibility_class"}) a.put(k, need(action, k));
        return IntentJs.hashCanonical(Issue.obj("d", INTENT_ACTION_DOMAIN, "action", a));
    }

    /** Why the cell coordinates are malformed, or null: 1..64 dimensions, each an index range [lo, hi] (0 &lt;= lo &lt;= hi) or a set of 1..256 distinct strings. */
    public static String cellCoordsError(Object co) {
        if (!(co instanceof Map) || ((Map<?, ?>) co).isEmpty() || ((Map<?, ?>) co).size() > 64) return "coords must be an object of 1..64 dimensions";
        for (Map.Entry<String, Object> e : IntentJs.obj(co).entrySet()) {
            String k = e.getKey();
            Object v = e.getValue();
            if (k.isEmpty() || k.length() > 256) return "a coordinate path must be 1..256 characters";
            if (v instanceof List && ((List<?>) v).size() == 2 && IntentJs.isInt(((List<?>) v).get(0)) && IntentJs.isInt(((List<?>) v).get(1))) {
                double lo = IntentJs.num(((List<?>) v).get(0)), hi = IntentJs.num(((List<?>) v).get(1));
                if (!(lo >= 0 && lo <= hi)) return "coords '" + k + "': need 0 <= lo <= hi";
            } else if (v instanceof List && ((List<?>) v).size() >= 1 && ((List<?>) v).size() <= 256 && allStrings((List<?>) v)) {
                if (new LinkedHashSet<Object>((List<?>) v).size() != ((List<?>) v).size()) return "coords '" + k + "': values must be distinct";
            } else return "coords '" + k + "': an index range [lo, hi] or a value set";
        }
        return null;
    }

    private static boolean allStrings(List<?> l) {
        for (Object x : l) if (!(x instanceof String)) return false;
        return true;
    }

    /** Why a question body is malformed, or null. {@code signed} false: an unsigned body (it must not carry {@code sig}). */
    public static String intentRequiredShapeError(Object bo, boolean signed) {
        if (!(bo instanceof Map)) return "not an object";
        Map<String, Object> b = IntentJs.obj(bo);
        for (String k : b.keySet()) if (!BODY_KEYS.contains(k)) return "unknown member '" + k + "'";
        if (!OracleFacts.isOne(b.get("v")) || !"pca-intent-required".equals(b.get("kind"))) return "not a pca-intent-required v1";
        for (String k : new String[] {"session", "map_digest", "schema", "pcactn_digest", "action_digest"}) if (!IntentJs.b32(b.get(k))) return k + " must be canonical base64url (32 bytes)";
        Object cell = b.get("cell");
        if (!(cell instanceof Map)) return "cell must be {verb, coords}";
        List<String> ck = new ArrayList<>(IntentJs.obj(cell).keySet());
        java.util.Collections.sort(ck);
        if (!String.join(",", ck).equals("coords,verb") || !(IntentJs.obj(cell).get("verb") instanceof String) || ((String) IntentJs.obj(cell).get("verb")).isEmpty()) return "cell must be {verb, coords}";
        String ce = cellCoordsError(IntentJs.obj(cell).get("coords"));
        if (ce != null) return ce;
        if (!"uncertain".equals(b.get("reason"))) return "reason must be 'uncertain'";
        if (!(b.get("question_id") instanceof String) || !QUESTION_ID.matcher((String) b.get("question_id")).matches()) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (!(b.get("friction") instanceof String) || !FRICTIONS.contains(b.get("friction"))) return "unknown friction tier";
        if (!"wallet".equals(b.get("delivered_to")) && !"agent".equals(b.get("delivered_to"))) return "delivered_to must be 'wallet' or 'agent'";
        if (!(IntentJs.isInt(b.get("expires_at")) && IntentJs.num(b.get("expires_at")) >= 0)) return "expires_at must be a non-negative safe integer";
        if (signed) {
            Object so = b.get("sig");
            Map<String, Object> s = so instanceof Map ? IntentJs.obj(so) : null;
            if (s != null) {
                String se = IntentJs.suiteError(s.get("alg"), s.containsKey("alg"));
                if (se != null) return "sig.alg: " + se;
                if (s.containsKey("pq_value") && !(s.get("pq_value") instanceof String)) return "sig.pq_value must be a string";
            }
            boolean bad = s == null;
            if (!bad) for (String k : s.keySet()) if (!Arrays.asList("alg", "kid", "value", "pq_value").contains(k)) bad = true;
            if (!bad) bad = Pq.resolveSigAlg(s.get("alg"), s.containsKey("alg")) == null || !(s.get("kid") instanceof String) || !(s.get("value") instanceof String);
            if (bad) return "sig must be {alg, kid, value, pq_value?}";
        } else if (b.containsKey("sig")) return "an unsigned body must not carry sig";
        return null;
    }

    private static byte[] message(Map<String, Object> b) {
        Map<String, Object> body = new LinkedHashMap<>(b);
        body.remove("sig");
        return IntentJs.message(INTENT_REQUIRED_DOMAIN, body);
    }

    /** Sign a question as the site: {...body, sig: {alg, kid, value, pq_value?}} ({@code suite} null is ed25519). An invalid unsigned body is never signed. */
    public static Map<String, Object> signIntentRequired(Map<String, Object> body, String kid, byte[] siteSecret, Pq.SignerSuiteOpts suite) {
        String e = intentRequiredShapeError(body, false);
        if (e != null) throw new IllegalArgumentException("signIntentRequired: " + e);
        Object alg = suite == null ? null : suite.alg;
        Pq.SuiteArtifactFields parts = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(siteSecret, suite), message(body));
        Map<String, Object> sig = Issue.obj("alg", Pq.resolveSigAlg(alg == null ? "ed25519" : alg, true).alg, "kid", kid, "value", parts.sig);
        if (parts.pqSig != null) sig.put("pq_value", parts.pqSig);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", sig);
        return out;
    }

    private static Map<String, Object> verdict(String reason) { return reason == null ? Issue.obj("ok", true) : Issue.obj("ok", false, "reason", reason); }

    /**
     * Verify a question against the site's discovery keys at {@code now}: the shape, a listed key, the suite pinned by that key, the signature and the
     * expiry. The clock must be a safe integer (else a denial). Returns {ok} or {ok: false, reason}; never throws.
     */
    public static Map<String, Object> verifyIntentRequired(Object b, Object keys, Object now) {
        try {
            if (!IntentJs.isSafeInteger(now)) return verdict("the verifier clock is not a safe integer (fail closed)");
            String e = intentRequiredShapeError(b, true);
            if (e != null) return verdict(e);
            Map<String, Object> s = IntentJs.obj(b);
            Map<String, Object> sig = IntentJs.obj(s.get("sig"));
            if (!(keys instanceof List)) return verdict("the site keys must be an array");
            Map<String, Object> key = null;
            for (Object ko : (List<?>) keys) if (ko instanceof Map && java.util.Objects.equals(IntentJs.obj(ko).get("kid"), sig.get("kid"))) { key = IntentJs.obj(ko); break; }
            if (key == null) return verdict("no site key with kid '" + IntentRevocation.jsText(sig.get("kid"), true) + "'");
            String kse = IntentJs.suiteError(key.get("alg"), key.containsKey("alg"));
            if (kse != null) return verdict("site key: " + kse);
            Pq.Suite ks = Pq.resolveSigAlg(key.get("alg"), key.containsKey("alg")), ss = Pq.resolveSigAlg(sig.get("alg"), sig.containsKey("alg"));
            if (ks == null || ss == null || !ks.alg.equals(ss.alg)) return verdict("sig.alg does not match the pinned key suite");
            Object pkO = key.get("pk");
            boolean ok = pkO instanceof String && IntentJs.verifyPinnedSuite(key.get("alg"), key.containsKey("alg"), (String) pkO, key.get("pq_pk"), message(s), sig.get("value"), sig.get("pq_value"),
                key.containsKey("pq_pk") ? IntentJs.pin((String) pkO, key.get("pq_pk")) : null);
            if (!ok) return verdict("site signature invalid");
            if (!(IntentJs.num(now) <= IntentJs.num(s.get("expires_at")))) return verdict("the question has expired");
            return verdict(null);
        } catch (RuntimeException err) {
            return verdict("malformed intent_required: " + (err.getMessage() == null ? "" : err.getMessage()));
        }
    }

    /** As {@link #verifyIntentRequired}; the clock gate is explicit. */
    public static Map<String, Object> verifyIntentRequiredAt(Object b, Object keys, Object now) {
        if (!IntentJs.isSafeInteger(now)) return verdict("the verifier clock is not a safe integer (fail closed)");
        return verifyIntentRequired(b, keys, now);
    }

    private static String title(String kind) {
        switch (kind) {
            case "intent-required": return "Principal confirmation required for this action";
            case "intent-denied": return "The principal does not intend this action";
            case "schema-violation": return "The action does not conform to the site action schema";
            case "ceiling": return "The action is outside a ceiling the principal cannot widen";
            default: return null;
        }
    }

    /**
     * The RFC 9457 problem of a refused action: {status: 403, headers: {WWW-Authenticate, Content-Type}, body}. {@code intent-required} needs the signed
     * question in {@code opts.body}. A kind outside the four is not refused (its error reads "undefined" and it has no title), as in the reference.
     */
    public static Map<String, Object> intentProblem(Object kind, Map<String, Object> opts) {
        String k = kind instanceof String ? (String) kind : null;
        boolean known = k != null && INTENT_PROBLEM_KINDS.contains(k);
        List<String> ps = new ArrayList<>();
        ps.add("error=\"" + (known ? k.replace('-', '_') : "undefined") + "\"");
        Object body = opts == null ? null : opts.get("body");
        boolean hasBody = IntentRevocation.truthy(body);
        if ("intent-required".equals(k)) {
            if (!hasBody) throw new IllegalArgumentException("intentProblem: intent-required needs the signed body");
            ps.add("session=\"" + IntentRevocation.jsText(IntentJs.get(body, "session"), IntentJs.own(body, "session")) + "\"");
            ps.add("question=\"" + IntentRevocation.jsText(IntentJs.get(body, "question_id"), IntentJs.own(body, "question_id")) + "\"");
        }
        Map<String, Object> pb = Issue.obj("type", PROBLEM_BASE + IntentRevocation.jsText(kind, true));
        if (known) pb.put("title", title(k));
        pb.put("status", IntentJs.ofLong(403));
        if (opts != null && opts.containsKey("detail")) pb.put("detail", opts.get("detail"));
        if (hasBody) pb.put("pca", body);
        return Issue.obj("status", IntentJs.ofLong(403), "headers", Issue.obj("WWW-Authenticate", "PCA " + String.join(", ", ps), "Content-Type", "application/problem+json"), "body", pb);
    }
}
