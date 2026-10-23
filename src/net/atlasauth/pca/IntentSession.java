package net.atlasauth.pca;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Rule 13: the PCActn member {@code intent_session} (wire), the {@code intent_session} grant caveat and the principal-signed
 * session root S ({@code pca-intent-session} v1), mirroring packages/pca/src/intent-session.ts and intent-session-caveat.ts.
 */
public final class IntentSession {
    private IntentSession() {}

    public static final String INTENT_SESSION_KIND = "pca-intent-session";
    public static final String INTENT_SESSION_SIG_DOMAIN = "atlas-pca/intent-session/v1\0";
    public static final String INTENT_SESSION_REF_DOMAIN = "atlas-pca/intent-session-ref/v1";
    public static final String INTENT_SESSION_CAVEAT = "intent_session";
    public static final String INTENT_GOAL_V2_PREFIX = "pca-intent:v2:";
    /** Session grants over a COMMITTED map (rule 19): {@code pca-intent:v2c:<session>:<map_commit>}. */
    public static final String INTENT_GOAL_V2C_PREFIX = "pca-intent:v2c:";
    public static final long MAX_SESSION_SEQ = 2_147_483_647L;
    public static final int MAX_IS_ACC = 16;
    public static final int MAX_IS_FACTS = 16;
    public static final int MAX_IS_PROV_PATHS = 32;
    public static final int MAX_IS_PROV_REFS = 8;
    public static final int MAX_IS_CLASSES = 8;
    public static final int MAX_IS_LABELS = 16;
    public static final int MAX_IS_STRING_BYTES = 256;
    public static final int MAX_SESSION_PRINCIPALS = 16;
    static final List<String> INTENT_SESSION_FIELDS = List.of("session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form");
    static final Pattern ACC_ID_RE = Pattern.compile("[A-Za-z0-9_]{1,64}");
    private static final Pattern PROV_KEY_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}");
    private static final List<String> ROOT_KEYS = List.of("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
        "question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig");

    private static boolean b32(Object o) { return IntentJs.b32(o); }
    private static boolean shortStr(Object v) {
        return v instanceof String && !((String) v).isEmpty() && !Json.hasLoneSurrogate((String) v) && IntentJs.u8len((String) v) <= MAX_IS_STRING_BYTES;
    }

    private static String digestList(Object v, String name, int max) {
        if (!(v instanceof List) || ((List<?>) v).size() > max) return "'intent_session." + name + "' must be an array of at most " + max + " digests";
        for (Object x : (List<?>) v) if (!b32(x)) return "'intent_session." + name + "' entries must be canonical base64url (32 bytes)";
        if (new HashSet<Object>((List<?>) v).size() != ((List<?>) v).size()) return "'intent_session." + name + "' entries must be distinct";
        return null;
    }

    /** Wire validation of {@code intent_session} (part of the terminal {@code wire} check). Null = well-formed. */
    public static String validateWire(Object vO) {
        if (!(vO instanceof Map)) return "'intent_session' must be an object";
        Map<String, Object> v = IntentJs.obj(vO);
        for (String k : v.keySet()) if (!INTENT_SESSION_FIELDS.contains(k)) return "unknown field 'intent_session." + k + "'";
        for (String k : new String[] {"session", "root", "seq", "schema"}) if (!v.containsKey(k)) return "missing field 'intent_session." + k + "'";
        for (String k : new String[] {"session", "root", "schema"}) if (!b32(v.get(k))) return "'intent_session." + k + "' is not canonical base64url (32 bytes)";
        if (!IntentJs.isNonNeg(v.get("seq")) || IntentJs.num(v.get("seq")) > MAX_SESSION_SEQ) return "'intent_session.seq' must be a safe integer in [0, 2147483647]";
        if (v.containsKey("acc")) {
            Object acc = v.get("acc");
            if (!(acc instanceof List) || ((List<?>) acc).size() > MAX_IS_ACC) return "'intent_session.acc' must be an array of at most " + MAX_IS_ACC + " entries";
            Set<String> ids = new HashSet<>();
            List<?> l = (List<?>) acc;
            for (int i = 0; i < l.size(); i++) {
                Object a = l.get(i);
                if (!(a instanceof Map)) return "'intent_session.acc[" + i + "]' must be an object";
                for (Object k : ((Map<?, ?>) a).keySet()) if (!List.of("id", "post", "receipt").contains(k)) return "unknown field 'intent_session.acc[" + i + "]." + k + "'";
                Object id = IntentJs.get(a, "id");
                if (!(id instanceof String) || !ACC_ID_RE.matcher((String) id).matches()) return "'intent_session.acc[" + i + "].id' must match [A-Za-z0-9_]{1,64}";
                if (!ids.add((String) id)) return "'intent_session.acc' ids must be distinct";
                if (!IntentJs.isNonNeg(IntentJs.get(a, "post"))) return "'intent_session.acc[" + i + "].post' must be a non-negative safe integer";
                if (IntentJs.own(a, "receipt") && !b32(IntentJs.get(a, "receipt"))) return "'intent_session.acc[" + i + "].receipt' is not canonical base64url (32 bytes)";
            }
        }
        if (v.containsKey("facts")) { String e = digestList(v.get("facts"), "facts", MAX_IS_FACTS); if (e != null) return e; }
        if (v.containsKey("offer_set") && !b32(v.get("offer_set"))) return "'intent_session.offer_set' is not canonical base64url (32 bytes)";
        if (v.containsKey("prov")) {
            Object prov = v.get("prov");
            if (!(prov instanceof Map) || ((Map<?, ?>) prov).size() > MAX_IS_PROV_PATHS) return "'intent_session.prov' must be an object of at most " + MAX_IS_PROV_PATHS + " entries";
            for (Map.Entry<String, Object> e : IntentJs.obj(prov).entrySet()) {
                if (!PROV_KEY_RE.matcher(e.getKey()).matches()) return "'intent_session.prov' key '" + e.getKey() + "' is not action.params.<name>";
                Object refs = e.getValue();
                boolean ok = refs instanceof List && !((List<?>) refs).isEmpty() && ((List<?>) refs).size() <= MAX_IS_PROV_REFS;
                if (ok) for (Object r : (List<?>) refs) if (!shortStr(r)) { ok = false; break; }
                if (!ok) return "'intent_session.prov." + e.getKey() + "' must be 1.." + MAX_IS_PROV_REFS + " non-empty strings of at most " + MAX_IS_STRING_BYTES + " UTF-8 bytes";
            }
        }
        if (v.containsKey("classes")) { String e = digestList(v.get("classes"), "classes", MAX_IS_CLASSES); if (e != null) return e; }
        if (v.containsKey("labels")) { String e = digestList(v.get("labels"), "labels", MAX_IS_LABELS); if (e != null) return e; }
        if (v.containsKey("map_form") && !IntentMap.MAP_FORM_COMMIT.equals(v.get("map_form"))) return "'intent_session.map_form' must be \"commit\" when present";
        return null;
    }

    /** The goal a session grant commits to: {@code pca-intent:v2:<session>:<map_digest>}. */
    public static String intentGoalV2(String session, String mapDigest) { return INTENT_GOAL_V2_PREFIX + session + ":" + mapDigest; }

    /** The goal a session grant over a COMMITTED map commits to (rule 19): {@code pca-intent:v2c:<session>:<map_commit>}. */
    public static String intentGoalV2c(String session, String mapCommit) { return INTENT_GOAL_V2C_PREFIX + session + ":" + mapCommit; }

    /** The FIRST caveat of {@code grant} whose type is {@code intent_session} (as is), or null. */
    static Map<String, Object> grantSessionCaveat(Object grant) {
        Object cs = IntentJs.get(grant, "caveats");
        if (!(grant instanceof Map) || !(cs instanceof List)) return null;
        for (Object c : (List<?>) cs) if (c instanceof Map && INTENT_SESSION_CAVEAT.equals(((Map<?, ?>) c).get("type"))) return IntentJs.obj(c);
        return null;
    }

    /** Shape of an {@code intent_session} grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq &gt; 0. */
    public static String caveatError(Object cO) {
        if (!(cO instanceof Map) || !INTENT_SESSION_CAVEAT.equals(((Map<?, ?>) cO).get("type"))) return "not an intent_session caveat";
        Map<String, Object> c = IntentJs.obj(cO);
        for (String k : c.keySet()) if (!List.of("type", "session", "seq", "root", "prev").contains(k)) return "intent_session caveat: unknown member '" + k + "'";
        if (!b32(c.get("session")) || !b32(c.get("root"))) return "intent_session caveat: session and root must be canonical base64url (32 bytes)";
        if (!IntentJs.isNonNeg(c.get("seq")) || IntentJs.num(c.get("seq")) > MAX_SESSION_SEQ) return "intent_session caveat: seq must be a safe integer in [0, 2147483647]";
        if ((IntentJs.num(c.get("seq")) == 0) != !c.containsKey("prev")) return "intent_session caveat: prev is present exactly when seq > 0";
        if (c.containsKey("prev") && !b32(c.get("prev"))) return "intent_session caveat: prev must be canonical base64url (32 bytes)";
        return null;
    }

    private static boolean sortedKeysAre(Object o, String... keys) {
        if (!(o instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) o;
        if (m.size() != keys.length) return false;
        for (String k : keys) if (!m.containsKey(k)) return false;
        return true;
    }

    /** Structural validation of a signed session root. Null = well-formed. Never throws. */
    public static String rootShapeError(Object sO) {
        try {
            if (!(sO instanceof Map)) return "session root is not an object";
            Map<String, Object> s = IntentJs.obj(sO);
            for (String k : s.keySet()) if (!ROOT_KEYS.contains(k)) return "session root: unknown member '" + k + "'";
            if (!OracleFacts.isOne(s.get("v")) || !INTENT_SESSION_KIND.equals(s.get("kind"))) return "not a pca-intent-session v1";
            if (!b32(s.get("session")) || !b32(s.get("intent_ref"))) return "session and intent_ref must be canonical base64url (32 bytes)";
            Object ps = s.get("principals");
            if (!(ps instanceof List) || ((List<?>) ps).isEmpty() || ((List<?>) ps).size() > MAX_SESSION_PRINCIPALS) return "principals must be 1.." + MAX_SESSION_PRINCIPALS + " keys";
            Set<String> keys = new HashSet<>();
            for (Object p : (List<?>) ps) {
                boolean ok = p instanceof Map && b32(IntentJs.get(p, "key"));
                if (ok) for (Object k : ((Map<?, ?>) p).keySet()) if (!List.of("key", "alg", "pq_pk").contains(k)) ok = false;
                if (!ok) return "principals entries are {key, alg?, pq_pk?} with a 32-byte key";
                String pse = IntentJs.suiteError(IntentJs.get(p, "alg"), IntentJs.own(p, "alg"));
                if (pse != null) return "principal alg: " + pse;
                if (IntentJs.own(p, "pq_pk") && !IntentJs.b64any(IntentJs.get(p, "pq_pk"))) return "principal pq_pk is not canonical base64url";
                if (!keys.add((String) IntentJs.get(p, "key"))) return "principal keys must be distinct";
            }
            Object sc = s.get("schema");
            if (!sortedKeysAre(sc, "aud", "digest") || !(IntentJs.get(sc, "aud") instanceof String) || ((String) IntentJs.get(sc, "aud")).isEmpty() || !b32(IntentJs.get(sc, "digest")))
                return "schema must be {aud, digest}";
            Object L = s.get("layers");
            if (!(L instanceof Map)) return "layers must be an object";
            for (Object k : ((Map<?, ?>) L).keySet()) if (!List.of("org", "std", "task").contains(k)) return "layers: unknown member '" + k + "'";
            Object task = IntentJs.get(L, "task");
            if (!sortedKeysAre(task, "map_digest") || !b32(IntentJs.get(task, "map_digest"))) return "layers.task must be {map_digest}";
            Object org = IntentJs.get(L, "org");
            if (IntentJs.own(L, "org") && (!(org instanceof Map) || !b32(IntentJs.get(org, "digest")))) return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)";
            Object std = IntentJs.get(L, "std");
            if (IntentJs.own(L, "std")) {
                Object prof = IntentJs.get(std, "profile");
                Object ver = IntentJs.get(std, "version");
                if (!sortedKeysAre(std, "digest", "profile", "version") || !(prof instanceof String) || ((String) prof).isEmpty() || IntentJs.u8len((String) prof) > 128
                    || !(IntentJs.isInt(ver) && IntentJs.num(ver) >= 1) || !b32(IntentJs.get(std, "digest")))
                    return "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)";
            }
            Object accs = s.get("accumulators");
            if (!(accs instanceof List) || ((List<?>) accs).size() > IntentAcc.MAX_SESSION_ACCUMULATORS) return "accumulators must be an array of at most " + IntentAcc.MAX_SESSION_ACCUMULATORS;
            Set<String> ids = new HashSet<>();
            for (Object a : (List<?>) accs) {
                String e = IntentAcc.accumulatorDeclError(a);
                if (e != null) return e;
                if (!ids.add((String) IntentJs.get(a, "id"))) return "accumulator and monitor ids must be distinct";
            }
            Object mons = s.get("monitors");
            if (!(mons instanceof List) || ((List<?>) mons).size() > IntentAcc.MAX_SESSION_MONITORS) return "monitors must be an array of at most " + IntentAcc.MAX_SESSION_MONITORS;
            Set<String> mids = new HashSet<>();
            for (Object m : (List<?>) mons) {
                String e = IntentAcc.monitorDeclError(m);
                if (e != null) return e;
                if (!mids.add((String) IntentJs.get(m, "id"))) return "monitor ids must be distinct";
            }
            Object q = s.get("question_uri");
            if (!(q instanceof String) || ((String) q).isEmpty() || IntentJs.u8len((String) q) > 2048) return "question_uri must be a non-empty string";
            if (s.containsKey("revocation")) {
                Object r = s.get("revocation");
                boolean ok = r instanceof Map;
                if (ok) for (Object k : ((Map<?, ?>) r).keySet()) if (!List.of("epoch_uri", "max_age_s", "key", "pq_pk").contains(k)) ok = false;
                if (!ok) return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}";
                Object eu = IntentJs.get(r, "epoch_uri");
                if (!(eu instanceof String) || ((String) eu).isEmpty()) return "revocation.epoch_uri must be a non-empty string";
                if (!IntentJs.isNonNeg(IntentJs.get(r, "max_age_s"))) return "revocation.max_age_s must be a non-negative safe integer";
                if (!b32(IntentJs.get(r, "key"))) return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)";
                if (keys.contains(IntentJs.get(r, "key"))) return "revocation.key must not be a session principal (a dedicated revocation authority)";
                if (IntentJs.own(r, "pq_pk") && !IntentJs.b64any(IntentJs.get(r, "pq_pk"))) return "revocation.pq_pk must be canonical base64url";
            }
            if (s.containsKey("flows") && !(s.get("flows") instanceof Map)) return "flows must be an object";
            if (!IntentJs.isNonNeg(s.get("expires_at"))) return "expires_at must be a non-negative safe integer (epoch ms)";
            if (!b32(s.get("signer"))) return "signer must be canonical base64url (32 bytes)";
            if (!keys.contains(s.get("signer"))) return "signer is not one of the session principals";
            String ase = IntentJs.suiteError(s.get("alg"), s.containsKey("alg"));
            if (ase != null) return "alg: " + ase;
            String suite = IntentJs.suiteOf(s);
            if (suite.equals("ed25519") && (s.containsKey("pq_pk") || s.containsKey("pq_sig"))) return "an ed25519 session root must not carry pq_pk / pq_sig";
            if (!(s.get("sig") instanceof String)) return "sig must be a string";
            IntentJs.canonBytes(rootBody(s));
            return null;
        } catch (RuntimeException e) {
            return "malformed session root: " + e.getMessage();
        }
    }

    private static Map<String, Object> rootBody(Map<String, Object> s) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri"}) b.put(k, s.get(k));
        if (s.containsKey("revocation")) b.put("revocation", s.get("revocation"));
        if (s.containsKey("flows")) b.put("flows", s.get("flows"));
        b.put("expires_at", s.get("expires_at"));
        return b;
    }

    /** Verify S with no verifier pins: an ed25519 root as before; a pure-PQ / hybrid root fails closed. Null = valid. */
    public static String verifyRoot(Object sO) { return verifyRoot(sO, null); }

    /**
     * Verify S: shape, signer listed, suite signature. Null = valid. R3-01 (fail closed): a non-ed25519 root verifies only
     * under the VERIFIER's pin for its signer ({@code pqPins} = context {@code session.pq_pins}, an object whose member for
     * the signer is a string), never under the root's own {@code principals[].pq_pk}; the signer's own entry, when it
     * declares a {@code pq_pk}, must agree. An ed25519 root never consults the pins.
     */
    public static String verifyRoot(Object sO, Object pqPins) {
        try {
            String bad = rootShapeError(sO);
            if (bad != null) return bad;
            Map<String, Object> s = IntentJs.obj(sO);
            String signer = (String) s.get("signer");
            Map<String, Object> p = null;
            for (Object x : (List<?>) s.get("principals")) if (signer.equals(IntentJs.get(x, "key"))) { p = IntentJs.obj(x); break; }
            Map<String, Object> pin = null;
            Pq.Suite suite = Pq.resolveSigAlg(s.get("alg"), s.containsKey("alg"));
            if (suite != null && suite.needsPqPk) {
                Object pv = pqPins instanceof Map && IntentJs.own(pqPins, signer) ? IntentJs.get(pqPins, signer) : null;
                if (!(pv instanceof String)) return "session root suite '" + suite.alg + "' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it";
                if (!s.containsKey("pq_pk") || !pv.equals(s.get("pq_pk"))) return "session root pq_pk does not match the verifier's pin for the signer";
                if (p.containsKey("pq_pk") && !pv.equals(p.get("pq_pk"))) return "session root pq_pk does not match the signer's principals entry";
                pin = IntentJs.pin(signer, pv);
            }
            Map<String, Object> body = rootBody(s);
            body.put("signer", signer);
            byte[] msg = IntentJs.message(INTENT_SESSION_SIG_DOMAIN, IntentJs.bindSuiteFields(body, s.get("alg"), s.containsKey("alg"), s.get("pq_pk"), s.containsKey("pq_pk")));
            if (!IntentJs.verifyPinnedSuite(s.get("alg"), s.containsKey("alg"), signer, s.get("pq_pk"), msg, s.get("sig"), s.get("pq_sig"), pin)) return "session root signature invalid";
            return null;
        } catch (RuntimeException e) {
            return "malformed session root: " + e.getMessage();
        }
    }

    /** digest(S): the content address of the whole signed session root. */
    public static String rootDigest(Object s) { return IntentJs.ref(INTENT_SESSION_REF_DOMAIN, "s", s); }
}
