package net.atlasauth.pca.intent;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiPredicate;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.IntentRevocation;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Portable, revocable intent profiles ({@code pca-intent-profile} v1): the principal's signed, versioned, append-only record of
 * standing rules (deny wins; permit is explicit, scoped and expiring) and prior answers (negative answers become vetoes, positive
 * ones never feed the learner). Profiles, scopes, rules and uses are JSON trees (Map / List / String / Json.Num / Boolean / null).
 * Signing is Ed25519 (the default suite); verification honours every suite the SDK implements.
 */
public final class IntentProfile {
    private IntentProfile() {}

    public static final String INTENT_PROFILE_KIND = "pca-intent-profile";
    public static final String INTENT_PROFILE_SIG_DOMAIN = "atlas-pca/intent-profile/v1\0";
    public static final String INTENT_PROFILE_REF_DOMAIN = "atlas-pca/intent-profile-ref/v1";
    public static final int MAX_PROFILE_RULES = 256;
    public static final int MAX_PROFILE_OBSERVATIONS = 2000;

    private static final List<String> KEYS = List.of("v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig");
    private static final Pattern ID_RE = Pattern.compile("[A-Za-z0-9_.-]{1,128}");

    private static boolean isObj(Object v) { return v instanceof Map; }

    private static Map<?, ?> m(Object v) { return (Map<?, ?>) v; }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static boolean isInt(Object v) { return IntentBridge.isInt(v); }

    private static double dbl(Object v) {
        Double d = IntentBridge.num(v);
        return d == null ? Double.NaN : d;
    }

    private static boolean b32(Object v) { return Pca.decodeB64uStrict(v, 32) != null; }

    private static boolean strList(Object v) {
        if (!(v instanceof List) || ((List<?>) v).size() > 256) return false;
        for (Object x : (List<?>) v) if (!(x instanceof String) || ((String) x).isEmpty()) return false;
        return true;
    }

    private static boolean predOk(Object p) {
        if (!isObj(p)) return false;
        Object verb = get(p, "verb");
        if (verb instanceof String) return true;
        if (!(verb instanceof List)) return false;
        for (Object x : (List<?>) verb) if (!(x instanceof String)) return false;
        return true;
    }

    private static String sortedKeys(Object o) {
        TreeSet<String> ks = new TreeSet<>();
        for (Object k : m(o).keySet()) ks.add((String) k);
        return String.join(",", ks);
    }

    public static String intentProfileShapeError(Object p) { return intentProfileShapeError(p, true); }

    /** The first reason a profile is malformed, or null. {@code signed = false} skips the suite / signature members. */
    public static String intentProfileShapeError(Object p, boolean signed) {
        try {
            if (!isObj(p)) return "profile is not an object";
            for (Object k : m(p).keySet()) if (!KEYS.contains(k)) return "profile: unknown member '" + k + "'";
            if (!(IntentBridge.num(get(p, "v")) != null && dbl(get(p, "v")) == 1) || !INTENT_PROFILE_KIND.equals(get(p, "kind"))) return "not a pca-intent-profile v1";
            Object pid = get(p, "profile_id");
            if (!(pid instanceof String) || !ID_RE.matcher((String) pid).matches()) return "profile_id must match [A-Za-z0-9_.-]{1,128}";
            if (!(isInt(get(p, "version")) && dbl(get(p, "version")) >= 1)) return "version must be a safe integer >= 1";
            if (Pca.decodeB64uStrict(get(p, "owner"), 32) == null) return "owner must be canonical base64url (32 bytes)";
            Object scope = get(p, "scope");
            if (!isObj(scope)) return "scope must be {sites?, verbs?, semantic_types?}";
            for (Object k : m(scope).keySet()) if (!List.of("sites", "verbs", "semantic_types").contains(k)) return "scope must be {sites?, verbs?, semantic_types?}";
            for (String k : new String[] {"sites", "verbs", "semantic_types"}) if (has(scope, k) && !strList(get(scope, k))) return "scope." + k + " must be a list of strings";
            Object standing = get(p, "standing");
            if (!isObj(standing) || !sortedKeys(standing).equals("deny,permit")) return "standing must be {deny, permit}";
            for (String k : new String[] {"deny", "permit"}) {
                Object r = get(standing, k);
                if (!(r instanceof List) || ((List<?>) r).size() > MAX_PROFILE_RULES) return "standing." + k + " must be at most " + MAX_PROFILE_RULES + " predicates";
                for (Object x : (List<?>) r) if (!predOk(x)) return "standing." + k + " must be at most " + MAX_PROFILE_RULES + " predicates";
            }
            Object prior = get(p, "prior");
            if (!isObj(prior) || !sortedKeys(prior).equals("maps,observations")) return "prior must be {observations, maps}";
            Object obs = get(prior, "observations");
            if (!(obs instanceof List) || ((List<?>) obs).size() > MAX_PROFILE_OBSERVATIONS) return "prior.observations must be at most " + MAX_PROFILE_OBSERVATIONS;
            for (Object o : (List<?>) obs) {
                Object y = get(o, "y");
                boolean yOk = IntentBridge.num(y) != null && (dbl(y) == 0 || dbl(y) == 1);
                if (!isObj(o) || !sortedKeys(o).equals("at,values,verb,y") || !(get(o, "verb") instanceof String) || !isObj(get(o, "values")) || !yOk || !(isInt(get(o, "at")) && dbl(get(o, "at")) >= 0))
                    return "prior.observations entries are {verb, values, y, at}";
            }
            Object maps = get(prior, "maps");
            if (!(maps instanceof List)) return "prior.maps must be 32-byte digests";
            for (Object x : (List<?>) maps) if (!b32(x)) return "prior.maps must be 32-byte digests";
            if (!(isInt(get(p, "expires_at")) && dbl(get(p, "expires_at")) >= 0)) return "expires_at must be a non-negative safe integer";
            Object rev = get(p, "revocation");
            if (!isObj(rev)) return "revocation must be {epoch_uri, key?}";
            for (Object k : m(rev).keySet()) if (!k.equals("epoch_uri") && !k.equals("key")) return "revocation must be {epoch_uri, key?}";
            if (!(get(rev, "epoch_uri") instanceof String) || ((String) get(rev, "epoch_uri")).isEmpty()) return "revocation must be {epoch_uri, key?}";
            if (has(rev, "key") && !b32(get(rev, "key"))) return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)";
            boolean v1 = dbl(get(p, "version")) == 1;
            if (v1 != !has(p, "prev")) return "prev is required exactly when version > 1";
            if (has(p, "prev") && !b32(get(p, "prev"))) return "prev must be canonical base64url (32 bytes)";
            if (signed) {
                if (has(p, "alg") && !(get(p, "alg") instanceof String)) return "alg must be a string";
                String suite = IntentBridge.suiteName(get(p, "alg"), has(p, "alg"));
                if (suite == null) return "alg: unsupported_suite: '" + get(p, "alg") + "'";
                if (suite.equals("ed25519") && (has(p, "pq_pk") || has(p, "pq_sig"))) return "an ed25519 profile must not carry pq_pk / pq_sig";
                if (!(get(p, "sig") instanceof String)) return "sig must be a string";
            }
            Json.canonicalizeStrict(profileBody(m(p)));
            return null;
        } catch (RuntimeException e) {
            return "malformed profile: " + e.getMessage();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> profileBody(Map<?, ?> p) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev"}) {
            if (p.containsKey(k)) b.put(k, p.get(k));
        }
        return b;
    }

    private static byte[] message(Map<String, Object> body) { return IntentBridge.message(INTENT_PROFILE_SIG_DOMAIN, body); }

    /** Sign a profile version as its owner with the owner's Ed25519 seed (the owner identity must be the signer's key). */
    public static Map<String, Object> signIntentProfile(Map<String, Object> body, byte[] ownerSeed) {
        return signIntentProfile(body, Keys.ed25519(Keys.edFromSeed(ownerSeed)));
    }

    /** Sign under any registry suite (ML-DSA, hybrid, ...): {@code alg} and {@code pq_pk} are signed into the profile. */
    public static Map<String, Object> signIntentProfile(Map<String, Object> body, Keys.SuiteKey key) {
        if (key.ed == null) throw new IllegalArgumentException("signIntentProfile: signer needs an Ed25519 identity key");
        String owner = key.ed.id();
        if (body.containsKey("owner") && !owner.equals(body.get("owner"))) throw new IllegalArgumentException("signIntentProfile: owner does not match the signing key");
        Map<String, Object> withOwner = new LinkedHashMap<>(body);
        withOwner.put("owner", owner);
        Map<String, Object> b = profileBody(withOwner);
        String bad = intentProfileShapeError(b, false);
        if (bad != null) throw new IllegalArgumentException("signIntentProfile: " + bad);
        return IntentBridge.signSuite(b, key, bb -> message(bb));
    }

    private static Map<String, Object> result(String reason) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", reason == null);
        if (reason != null) r.put("reason", reason);
        return r;
    }

    public static Map<String, Object> verifyIntentProfile(Object p) { return verifyIntentProfile(p, null); }

    /** {ok: true} or {ok: false, reason}; {@code pin} maps an identity to the PQ key the verifier pins for it. Never throws. */
    public static Map<String, Object> verifyIntentProfile(Object p, Map<String, Object> pin) {
        try {
            String bad = intentProfileShapeError(p);
            if (bad != null) return result(bad);
            Map<?, ?> r = m(p);
            Map<String, Object> body = IntentBridge.bindSuiteFields(profileBody(r), r.get("alg"), r.containsKey("alg"), r.get("pq_pk"), r.containsKey("pq_pk"));
            if (!IntentBridge.verifyPinnedSuite(r.get("alg"), r.containsKey("alg"), (String) r.get("owner"), r.get("pq_pk"), message(body), r.get("sig"), r.get("pq_sig"), pin))
                return result("profile signature invalid");
            return result(null);
        } catch (RuntimeException e) {
            return result("malformed profile: " + e.getMessage());
        }
    }

    /** The content address of a signed profile version. */
    public static String intentProfileDigest(Object p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", INTENT_PROFILE_REF_DOMAIN);
        m.put("p", p);
        return Pca.hashCanonical(m);
    }

    /** Append-only succession: same id and owner, version + 1, {@code prev} = digest(previous). */
    public static Map<String, Object> verifyProfileSuccession(Object prev, Object next) {
        Object[] both = {prev, next};
        String[] names = {"previous", "next"};
        for (int i = 0; i < 2; i++) {
            Map<String, Object> v = verifyIntentProfile(both[i]);
            if (!Boolean.TRUE.equals(v.get("ok"))) return result(names[i] + " version: " + v.get("reason"));
        }
        if (!get(next, "profile_id").equals(get(prev, "profile_id")) || !get(next, "owner").equals(get(prev, "owner"))) return result("a profile version cannot change its id or owner");
        if (!(dbl(get(next, "version")) == dbl(get(prev, "version")) + 1)) return result("versions are append-only: next.version must be previous + 1");
        if (!intentProfileDigest(prev).equals(get(next, "prev"))) return result("next.prev is not the digest of the previous version");
        return result(null);
    }

    private static boolean includes(Object list, Object x) {
        for (Object e : (List<?>) list) if (e != null && e.equals(x)) return true;
        return false;
    }

    /** Is the profile in scope (and unexpired) for this use ({aud, verb, now, semantics?})? */
    public static boolean profileApplies(Map<String, Object> p, Map<String, Object> u) {
        if (!(Double.isFinite(dbl(u.get("now"))) && Double.isFinite(dbl(p.get("expires_at"))) && dbl(u.get("now")) < dbl(p.get("expires_at")))) return false;
        Object scope = p.get("scope");
        if (get(scope, "sites") != null && !includes(get(scope, "sites"), u.get("aud"))) return false;
        if (get(scope, "verbs") != null && !includes(get(scope, "verbs"), u.get("verb"))) return false;
        if (get(scope, "semantic_types") != null) {
            boolean any = false;
            if (u.get("semantics") != null) for (Object s : (List<?>) u.get("semantics")) if (includes(get(scope, "semantic_types"), s)) any = true;
            if (!any) return false;
        }
        return true;
    }

    private static boolean anyRuleMatches(Object rules, Map<String, Object> action) {
        for (Object r : (List<?>) rules) if (Predicates.predicateMatches(r, action)) return true;
        return false;
    }

    /** G^std membership: an in-scope action is OUTSIDE the standing layer iff a deny rule matches it (deny wins). */
    public static boolean standingAdmits(Map<String, Object> p, Map<String, Object> u, Map<String, Object> action) {
        if (!profileApplies(p, u)) return true;
        return !anyRuleMatches(get(p.get("standing"), "deny"), action);
    }

    /** The explicit standing-permission layer: true iff an in-scope permit rule matches. */
    public static boolean standingPermits(Map<String, Object> p, Map<String, Object> u, Map<String, Object> action) {
        return profileApplies(p, u) && anyRuleMatches(get(p.get("standing"), "permit"), action);
    }

    /** The cells that the profile's negative observations veto: [{verb, cell}], de-duplicated in order. */
    public static List<Map<String, Object>> profileVetoCells(Map<String, Object> p, Omega omega) {
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Object o : (List<?>) get(p.get("prior"), "observations")) {
            if (dbl(get(o, "y")) != 0) continue;
            String verb = (String) get(o, "verb");
            VerbSpace vs = IntentOmega.verbSpace(omega, verb);
            Map<String, Object> vals = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m(get(o, "values")).entrySet()) vals.put((String) e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
            int[] cell = vs == null ? null : IntentOmega.cellOf(vs, new Outcome(verb, vals));
            if (vs == null || cell == null) continue;
            StringBuilder k = new StringBuilder(verb).append('|');
            for (int i = 0; i < cell.length; i++) k.append(i == 0 ? "" : ",").append(cell[i]);
            if (seen.add(k.toString())) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("verb", verb);
                List<Object> c = new ArrayList<>();
                for (int x : cell) c.add(x);
                e.put("cell", c);
                out.add(e);
            }
        }
        return out;
    }

    /** A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes. */
    public static BiPredicate<VerbSpace, Outcome> profileCeiling(Map<String, Object> p, Map<String, Object> u) {
        return (vs, o) -> {
            Map<String, Object> a = IntentPolicy.outcomeToAction(vs, o);
            Map<String, Object> ctx = new LinkedHashMap<>();
            Map<String, Object> act = new LinkedHashMap<>();
            act.put("verb", a.get("verb"));
            act.put("resource", a.get("resource"));
            act.put("params", a.get("params"));
            ctx.put("action", act);
            if (a.containsKey("env")) ctx.put("env", a.get("env"));
            if (a.containsKey("subject")) ctx.put("subject", a.get("subject"));
            Map<String, Object> use = new LinkedHashMap<>(u);
            use.put("verb", o.verb());
            return standingAdmits(p, use, ctx);
        };
    }

    /**
     * Is this profile version usable now: signed, unexpired and not revoked per a fresh epoch of its revocation authority?
     * {@code c} members: now, maxAgeMs, revocation?, last?, pin?.
     */
    public static Map<String, Object> profileUsable(Map<String, Object> p, Map<String, Object> c) {
        Map<String, Object> pin = c.get("pin") instanceof Map ? IntentOmega.obj(c.get("pin")) : null;
        Map<String, Object> v = verifyIntentProfile(p, pin);
        if (!Boolean.TRUE.equals(v.get("ok"))) return v;
        if (!(Double.isFinite(dbl(c.get("now"))) && Double.isFinite(dbl(p.get("expires_at"))) && dbl(c.get("now")) < dbl(p.get("expires_at")))) return result("the profile has expired");
        String id = (String) p.get("profile_id");
        Object revKey = get(p.get("revocation"), "key");
        Object authority = revKey != null ? revKey : p.get("owner");
        List<Object> ids = List.of(IntentRevocation.profileRevocationId(id, AttestCommon.jsNumString(dbl(p.get("version")))));
        String r = IntentRevocation.checkSessionRevocation(c.get("revocation"), id, authority, ids, dbl(c.get("now")), dbl(c.get("maxAgeMs")),
            "pca-intent-profile:" + id, pin, c.get("last") != null, c.get("last"));
        return r == null ? result(null) : result("profile revocation: " + r);
    }
}
