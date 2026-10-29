package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Caveat language v2 (port of the TypeScript {@code caveat-lang.ts}; behaviour AND reason strings are normative).
 *
 * <p>Six verifier-side features, every one of them a RESTRICTION (a caveat only removes authority; a verifier that does
 * not know a type refuses the chain): {@code needs_discharge} (a third-party caveat satisfied by a signed discharge from a
 * key the VERIFIER pinned), {@code sealed}, the {@code narrow} artifact (a holder-signed self-attenuation beside the
 * PCActn), {@code max_uses} (n atomic first-use slots in the replay store), {@code derive} (a bounded Kleene three-valued
 * check) and {@code spiffe_bound}.
 *
 * <p>Inputs are JSON trees ({@link Json#parse} / {@link Json#parseLenient}: maps, lists, strings, booleans,
 * {@link Json.Num}). Everything here is total: a malformed caveat, discharge, narrow block or context is a refusal, never
 * an exception and never an allow.
 */
public final class CaveatLang {
    private CaveatLang() {}

    public static final String CAVEAT_NEEDS_DISCHARGE = "needs_discharge";
    public static final String CAVEAT_SEALED = "sealed";
    public static final String CAVEAT_MAX_USES = "max_uses";
    public static final String CAVEAT_DERIVE = "derive";
    public static final String CAVEAT_SPIFFE_BOUND = "spiffe_bound";
    /** Caveat types this module evaluates (the stock evaluators refuse them). */
    public static final List<String> K1_CAVEAT_TYPES = List.of(CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND);

    public static final String DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\0";
    public static final String DISCHARGE_REF_DOMAIN = "atlas-pca/discharge-ref/v1";
    public static final String DISCHARGE_ACTION_DOMAIN = "atlas-pca/discharge-action/v1";
    public static final String NARROW_DOMAIN = "atlas-pca/narrow/v1\0";
    public static final String MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\0";
    /** A discharge or narrow block lives at most 24 hours. */
    public static final long MAX_LIFETIME_MS = 86_400_000L;
    public static final int MAX_USES_LIMIT = 256;
    public static final int NARROW_MAX_CAVEATS = 16;
    public static final int DERIVE_MAX_DEFS = 8;
    public static final int DERIVE_MAX_NODES = 32;
    public static final int DERIVE_MAX_DEPTH = 4;
    public static final long DERIVE_MAX_WINDOW_MS = 30L * 86_400_000L;
    public static final int DERIVE_MAX_HISTORY = 10_000;
    public static final int SPIFFE_MAX_ID_BYTES = 2048;

    // full-match patterns (matcher().matches()): no trailing-newline tolerance, unlike a JavaScript-style "$"
    private static final Pattern NAME_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern ID_RE = Pattern.compile("[a-z0-9][a-z0-9_.-]{0,63}");
    private static final Pattern TRUST_DOMAIN_RE = Pattern.compile("[a-z0-9._-]+");
    private static final Pattern SPIFFE_SEGMENT_RE = Pattern.compile("[A-Za-z0-9._-]+");
    private static final List<String> ISSUER_CLASSES = List.of("human", "org", "workload", "model", "artifact");
    private static final List<String> OPS = List.of("eq", "neq", "gte", "lte", "in");
    private static final List<String> CMP_OPS = List.of("eq", "neq", "lt", "lte", "gt", "gte");
    private static final List<String> NO_MEMBERS = List.of();

    // ---- small helpers -----------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    private static String closed(Object o, List<String> required, List<String> optional, String where) {
        return IntentArtifacts.closedMembers(mp(o), required, optional, where);
    }

    private static boolean idOk(Object v) { return v instanceof String && ID_RE.matcher((String) v).matches(); }
    private static boolean nameOk(Object v) { return v instanceof String && NAME_RE.matcher((String) v).matches(); }
    private static boolean isStr256(Object v) { return IntentArtifacts.isBoundedString(v, 256); }
    private static boolean isScalarClaim(Object v) { return IntentArtifacts.isScalar(v) && (!(v instanceof String) || isStr256(v)); }
    private static boolean isOne(Object v) { return IntentJs.isInt(v) && IntentJs.num(v) == 1.0; }
    private static boolean isK1Type(Object type) { return type instanceof String && K1_CAVEAT_TYPES.contains(type); }

    /** True for an object whose {@code type} is one of the K1 caveat types. */
    public static boolean isK1Caveat(Object c) { return c instanceof Map && isK1Type(((Map<?, ?>) c).get("type")); }

    private static String errMsg(Throwable t) { return t.getMessage() == null ? "unknown" : t.getMessage(); }

    // ================================================================================================================
    // SPIFFE ID syntax
    // ================================================================================================================

    /**
     * Null when {@code s} is a valid SPIFFE ID: {@code spiffe://} + a trust domain of lowercase letters, digits, {@code . - _}
     * + an optional path of non-empty segments over {@code [A-Za-z0-9._-]} that are not {@code .} or {@code ..}, no trailing
     * slash, at most 2048 bytes, no query or fragment.
     */
    public static String spiffeIdError(Object s) {
        if (!(s instanceof String) || ((String) s).isEmpty()) return "SPIFFE ID must be a non-empty string";
        String id = (String) s;
        if (IntentJs.u8len(id) > SPIFFE_MAX_ID_BYTES) return "SPIFFE ID is too long";
        if (!id.startsWith("spiffe://")) return "SPIFFE ID must begin with spiffe://";
        String rest = id.substring(9);
        int slash = rest.indexOf('/');
        String td = slash == -1 ? rest : rest.substring(0, slash);
        String path = slash == -1 ? "" : rest.substring(slash);
        if (td.isEmpty() || td.length() > 255 || !TRUST_DOMAIN_RE.matcher(td).matches()) return "invalid trust domain";
        if (path.isEmpty()) return null;
        if (path.endsWith("/")) return "path must not end with a slash";
        String[] segs = path.split("/", -1);
        for (int i = 1; i < segs.length; i++) {
            String seg = segs[i];
            if (seg.isEmpty() || seg.equals(".") || seg.equals("..") || !SPIFFE_SEGMENT_RE.matcher(seg).matches()) return "invalid path segment";
        }
        return null;
    }

    // ================================================================================================================
    // Hop analysis: which hop introduced a caveat
    // ================================================================================================================

    /** A caveat of the leaf hop with the hop that introduced it. */
    public static final class BoundCaveat {
        public final Object caveat;
        /** Index of the hop that introduced the caveat (0 = the root grant). */
        public final int hop;
        /** The capability content hash ({@link Pca#capHash}) of that hop. */
        public final String capHash;

        public BoundCaveat(Object caveat, int hop, String capHash) {
            this.caveat = caveat;
            this.hop = hop;
            this.capHash = capHash;
        }
    }

    private static List<Object> hopsOf(Object grant, Object chain) {
        List<Object> hops = new ArrayList<>();
        if (chain instanceof List && !((List<?>) chain).isEmpty()) hops.addAll((List<?>) chain);
        else hops.add(grant);
        return hops;
    }

    /**
     * Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only, so the
     * caveat at position {@code p} was introduced by the first hop whose list is longer than {@code p}. Null for a malformed
     * chain.
     */
    public static List<BoundCaveat> boundCaveats(Object grant, Object chain) {
        try {
            List<Object> hops = hopsOf(grant, chain);
            Object lc = IntentJs.get(hops.get(hops.size() - 1), "caveats");
            if (!(lc instanceof List)) return null;
            List<?> cs = (List<?>) lc;
            List<BoundCaveat> out = new ArrayList<>();
            Map<Integer, String> hashes = new HashMap<>();
            for (int p = 0; p < cs.size(); p++) {
                int h = -1;
                for (int i = 0; i < hops.size() && h < 0; i++) {
                    Object hc = IntentJs.get(hops.get(i), "caveats");
                    if (hc instanceof List && ((List<?>) hc).size() > p) h = i;
                }
                if (h < 0) h = hops.size() - 1;
                String ch = hashes.get(h);
                if (ch == null) {
                    ch = Pca.capHash(mp(hops.get(h)));
                    hashes.put(h, ch);
                }
                out.add(new BoundCaveat(cs.get(p), h, ch));
            }
            return out;
        } catch (RuntimeException | StackOverflowError e) {
            return null;
        }
    }

    // ================================================================================================================
    // needs_discharge: the third-party caveat and its discharge
    // ================================================================================================================

    private static String requireError(Object ro) {
        if (!(ro instanceof Map)) return "requirement must be an object";
        Map<String, Object> r = mp(ro);
        String e = closed(r, List.of("claim", "op", "value"), NO_MEMBERS, "require");
        if (e != null) return e;
        if (!nameOk(r.get("claim"))) return "claim name is malformed";
        Object op = r.get("op");
        if (!(op instanceof String) || !OPS.contains(op)) return "op must be eq, neq, gte, lte or in";
        Object value = r.get("value");
        if (op.equals("in")) {
            if (!(value instanceof List) || ((List<?>) value).isEmpty() || ((List<?>) value).size() > 16) return "'in' needs 1..16 scalar values";
            for (Object x : (List<?>) value) if (!isScalarClaim(x)) return "'in' needs 1..16 scalar values";
        } else if (op.equals("gte") || op.equals("lte")) {
            if (!IntentJs.isInt(value)) return "'" + op + "' needs a safe integer";
        } else if (!isScalarClaim(value)) {
            return "value must be a scalar";
        }
        return null;
    }

    /** Null when the caveat is well-formed: closed members, canonical names, bounded sizes. */
    public static String needsDischargeError(Object co) {
        if (!(co instanceof Map)) return "caveat must be an object";
        Map<String, Object> c = mp(co);
        String e = closed(c, List.of("type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"), List.of("issuer_spiffe"), "needs_discharge");
        if (e != null) return e;
        if (!CAVEAT_NEEDS_DISCHARGE.equals(c.get("type"))) return "not a needs_discharge caveat";
        if (!idOk(c.get("id"))) return "id is malformed";
        if (!idOk(c.get("issuer"))) return "issuer label is malformed";
        Object cls = c.get("issuer_class");
        if (!(cls instanceof String) || !ISSUER_CLASSES.contains(cls)) return "issuer_class must be human, org, workload, model or artifact";
        Object bind = c.get("bind");
        if (!"chain_hop".equals(bind) && !"action".equals(bind)) return "bind must be 'chain_hop' or 'action'";
        Object ttl = c.get("ttl_ms");
        if (!(IntentJs.isInt(ttl) && IntentJs.lng(ttl) >= 1 && IntentJs.lng(ttl) <= MAX_LIFETIME_MS)) return "ttl_ms must be 1..86400000";
        Object req = c.get("require");
        if (!(req instanceof List) || ((List<?>) req).size() > 16) return "require must be an array of at most 16 requirements";
        for (Object r : (List<?>) req) {
            String re = requireError(r);
            if (re != null) return re;
        }
        if (c.containsKey("issuer_spiffe")) {
            String se = spiffeIdError(c.get("issuer_spiffe"));
            if (se != null) return "issuer_spiffe: " + se;
        }
        return null;
    }

    /** The digest of the exact PCActn (counter and signature included): a bind-{@code action} discharge authorises that one action. */
    public static String dischargeActionDigest(Map<String, Object> pcactn) { return IntentJs.ref(DISCHARGE_ACTION_DOMAIN, "pcactn", pcactn); }

    /** Content address of a discharge (signature included); what a revocation list names. Throws on an out-of-profile value. */
    public static String dischargeDigest(Object discharge) { return IntentJs.ref(DISCHARGE_REF_DOMAIN, "discharge", IntentJs.normalize(discharge)); }

    private static final List<String> D_REQUIRED = List.of("v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig");
    private static final List<String> D_OPTIONAL = List.of("action_digest", "alg", "pq_pk", "pq_sig");

    /** Null = well-formed. */
    public static String dischargeShapeError(Object ao) {
        if (!(ao instanceof Map)) return "not an object";
        Map<String, Object> a = mp(ao);
        String e = closed(a, D_REQUIRED, D_OPTIONAL, "discharge");
        if (e != null) return e;
        if (!isOne(a.get("v")) || !"pca-discharge".equals(a.get("kind"))) return "not a pca-discharge v1";
        if (!idOk(a.get("caveat_id"))) return "caveat_id is malformed";
        if (!idOk(a.get("issuer"))) return "issuer label is malformed";
        if (!IntentArtifacts.isDigest(a.get("cap_hash"))) return "cap_hash must be canonical base64url (32 bytes)";
        Object bind = a.get("bind");
        if (!"chain_hop".equals(bind) && !"action".equals(bind)) return "bind must be 'chain_hop' or 'action'";
        if ("action".equals(bind) ? !IntentArtifacts.isDigest(a.get("action_digest")) : a.containsKey("action_digest"))
            return "action_digest is required for bind action and forbidden for chain_hop";
        Object claims = a.get("claims");
        if (!(claims instanceof Map) || ((Map<?, ?>) claims).size() > 16) return "claims must be an object of at most 16 members";
        for (Map.Entry<String, Object> en : mp(claims).entrySet())
            if (!nameOk(en.getKey()) || !isScalarClaim(en.getValue())) return "claim '" + en.getKey() + "' is malformed";
        if (!IntentJs.isNonNeg(a.get("iat")) || !IntentJs.isNonNeg(a.get("not_after"))) return "iat and not_after must be non-negative safe integers";
        long iat = IntentJs.lng(a.get("iat")), notAfter = IntentJs.lng(a.get("not_after"));
        if (!(notAfter > iat)) return "not_after must be greater than iat";
        if (notAfter - iat > MAX_LIFETIME_MS) return "a discharge lives at most " + MAX_LIFETIME_MS + " ms";
        byte[] nb = a.get("nonce") instanceof String ? Pca.decodeB64uStrict(a.get("nonce"), -1) : null;
        if (nb == null || nb.length < 16) return "nonce must be canonical base64url of at least 16 bytes";
        if (!(a.get("sig") instanceof String)) return "sig must be a string";
        return IntentArtifacts.artifactSuiteError(a);
    }

    /** {@link #verifyDischarge}'s answer: {@code ok} with the digest and claims, or the refusal reason. */
    public static final class DischargeVerdict {
        public final boolean ok;
        public final String digest;
        public final Map<String, Object> claims;
        public final String reason;

        private DischargeVerdict(boolean ok, String digest, Map<String, Object> claims, String reason) {
            this.ok = ok;
            this.digest = digest;
            this.claims = claims;
            this.reason = reason;
        }

        static DischargeVerdict no(String reason) { return new DischargeVerdict(false, null, null, reason); }

        @Override public String toString() { return ok ? "DischargeVerdict{ok, " + digest + "}" : "DischargeVerdict{" + reason + "}"; }
    }

    private static boolean claimHolds(Map<String, Object> r, Map<String, Object> claims) {
        String claim = (String) r.get("claim");
        if (!claims.containsKey(claim)) return false;
        Object v = claims.get(claim);
        Object value = r.get("value");
        switch ((String) r.get("op")) {
            case "eq": return IntentArtifacts.scalarEq(v, value);
            case "neq": return !IntentArtifacts.scalarEq(v, value);
            case "gte": return IntentJs.isInt(v) && IntentJs.lng(v) >= IntentJs.lng(value);
            case "lte": return IntentJs.isInt(v) && IntentJs.lng(v) <= IntentJs.lng(value);
            case "in":
                for (Object x : (List<?>) value) if (IntentArtifacts.scalarEq(v, x)) return true;
                return false;
            default: return false;
        }
    }

    /**
     * Verify one discharge against one caveat. {@code bind} is {@code {cap_hash, action_digest?, pins, now, revoked?}}:
     * {@code cap_hash} the capability hash of the hop that carries the caveat, {@code action_digest} the
     * {@link #dischargeActionDigest} of the PCActn being decided, {@code pins} the verifier's issuer pins
     * ({@code {label, class, pk, pq_pk?, spiffe_id?}}), {@code revoked} {@link #dischargeDigest} values. The verifier's own
     * pins decide the key. Total.
     */
    public static DischargeVerdict verifyDischarge(Object discharge, Object caveat, Map<String, Object> bind) {
        try {
            if (!IntentJs.isInt(bind.get("now"))) return DischargeVerdict.no("the verifier clock is not a safe integer (fail closed)");
            long now = IntentJs.lng(bind.get("now"));
            Object cav = IntentJs.normalize(caveat);
            String ce = needsDischargeError(cav);
            if (ce != null) return DischargeVerdict.no("malformed needs_discharge caveat: " + ce);
            Map<String, Object> c = mp(cav);
            Object dis = IntentJs.normalize(discharge);
            String de = dischargeShapeError(dis);
            if (de != null) return DischargeVerdict.no("malformed discharge: " + de);
            Map<String, Object> d = mp(dis);
            if (!d.get("caveat_id").equals(c.get("id"))) return DischargeVerdict.no("the discharge is for another caveat");
            if (!d.get("issuer").equals(c.get("issuer"))) return DischargeVerdict.no("the discharge names another issuer");
            if (!(bind.get("pins") instanceof List)) return DischargeVerdict.no("no issuer is pinned");
            List<Map<String, Object>> pins = new ArrayList<>();
            for (Object p : (List<?>) bind.get("pins")) if (p instanceof Map && c.get("issuer").equals(((Map<?, ?>) p).get("label"))) pins.add(mp(p));
            if (pins.isEmpty()) return DischargeVerdict.no("the issuer is not pinned by this verifier");
            if (pins.size() > 1) return DischargeVerdict.no("the issuer label is pinned more than once (ambiguous)");
            Map<String, Object> pin = pins.get(0);
            if (!Objects.equals(pin.get("class"), c.get("issuer_class"))) return DischargeVerdict.no("the pinned issuer is not of the class the caveat requires");
            if (c.containsKey("issuer_spiffe") && !Objects.equals(pin.get("spiffe_id"), c.get("issuer_spiffe")))
                return DischargeVerdict.no("the pinned issuer does not carry the SPIFFE ID the caveat requires");
            if (!IntentArtifacts.verifyArtifactSig(DISCHARGE_DOMAIN, d, pin.get("pk"), pin.get("pq_pk"))) return DischargeVerdict.no("discharge signature invalid");
            if (!Objects.equals(d.get("bind"), c.get("bind"))) return DischargeVerdict.no("the discharge binds differently than the caveat requires");
            if (!Objects.equals(d.get("cap_hash"), bind.get("cap_hash"))) return DischargeVerdict.no("the discharge is bound to another hop");
            if ("action".equals(c.get("bind")) && !Objects.equals(d.get("action_digest"), bind.get("action_digest")))
                return DischargeVerdict.no("the discharge is bound to another action");
            long iat = IntentJs.lng(d.get("iat")), notAfter = IntentJs.lng(d.get("not_after"));
            if (now < iat) return DischargeVerdict.no("the discharge is from the future");
            if (now > notAfter) return DischargeVerdict.no("the discharge has expired");
            if (notAfter - iat > IntentJs.lng(c.get("ttl_ms"))) return DischargeVerdict.no("the discharge lives longer than the caveat allows");
            String digest = dischargeDigest(d);
            if (bind.get("revoked") instanceof List && ((List<?>) bind.get("revoked")).contains(digest)) return DischargeVerdict.no("the discharge is revoked");
            Map<String, Object> claims = mp(d.get("claims"));
            for (Object r : (List<?>) c.get("require"))
                if (!claimHolds(mp(r), claims)) return DischargeVerdict.no("claim '" + mp(r).get("claim") + "' does not satisfy the caveat");
            return new DischargeVerdict(true, digest, claims, null);
        } catch (RuntimeException | StackOverflowError e) {
            return DischargeVerdict.no("discharge error (fail closed): " + errMsg(e));
        }
    }

    // ================================================================================================================
    // narrow: holder-signed per-action self-attenuation (no new hop)
    // ================================================================================================================

    /** Types a narrow block must not carry: structure only a real hop can introduce, and nested narrowing. */
    private static final List<String> NARROW_FORBIDDEN = List.of("envelope", CAVEAT_SEALED, "budget_alloc", "intent_session");
    private static final List<String> N_REQUIRED = List.of("v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig");
    private static final List<String> N_OPTIONAL = List.of("action_digest", "alg", "pq_pk", "pq_sig");

    /** Null = well-formed. */
    public static String narrowShapeError(Object ao) {
        if (!(ao instanceof Map)) return "not an object";
        Map<String, Object> a = mp(ao);
        String e = closed(a, N_REQUIRED, N_OPTIONAL, "narrow");
        if (e != null) return e;
        if (!isOne(a.get("v")) || !"pca-narrow".equals(a.get("kind"))) return "not a pca-narrow v1";
        if (!IntentArtifacts.isDigest(a.get("cap_hash"))) return "cap_hash must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.isBoundedString(a.get("holder"), 64) || Pca.decodeB64uStrict(a.get("holder"), 32) == null)
            return "holder must be canonical base64url (32 bytes)";
        Object cs = a.get("caveats");
        if (!(cs instanceof List) || ((List<?>) cs).size() < 1 || ((List<?>) cs).size() > NARROW_MAX_CAVEATS)
            return "caveats must be 1.." + NARROW_MAX_CAVEATS + " caveats";
        for (Object c : (List<?>) cs) {
            if (!(c instanceof Map) || !(((Map<?, ?>) c).get("type") instanceof String)) return "every caveat must be an object with a string type";
            String type = (String) ((Map<?, ?>) c).get("type");
            if (NARROW_FORBIDDEN.contains(type)) return "a narrow block cannot carry a '" + type + "' caveat";
        }
        if (a.containsKey("action_digest") && !IntentArtifacts.isDigest(a.get("action_digest"))) return "action_digest must be canonical base64url (32 bytes)";
        if (!IntentJs.isNonNeg(a.get("iat")) || !IntentJs.isNonNeg(a.get("not_after"))) return "iat and not_after must be non-negative safe integers";
        long iat = IntentJs.lng(a.get("iat")), notAfter = IntentJs.lng(a.get("not_after"));
        if (!(notAfter > iat)) return "not_after must be greater than iat";
        if (notAfter - iat > MAX_LIFETIME_MS) return "a narrow block lives at most " + MAX_LIFETIME_MS + " ms";
        byte[] nb = a.get("nonce") instanceof String ? Pca.decodeB64uStrict(a.get("nonce"), -1) : null;
        if (nb == null || nb.length < 16) return "nonce must be canonical base64url of at least 16 bytes";
        if (!(a.get("sig") instanceof String)) return "sig must be a string";
        return IntentArtifacts.artifactSuiteError(a);
    }

    /** {@link #verifyNarrow}'s answer: {@code ok} with the block's caveats, or the refusal reason. */
    public static final class NarrowVerdict {
        public final boolean ok;
        public final List<Object> caveats;
        public final String reason;

        private NarrowVerdict(boolean ok, List<Object> caveats, String reason) {
            this.ok = ok;
            this.caveats = caveats;
            this.reason = reason;
        }

        static NarrowVerdict no(String reason) { return new NarrowVerdict(false, null, reason); }

        @Override public String toString() { return ok ? "NarrowVerdict{ok}" : "NarrowVerdict{" + reason + "}"; }
    }

    /**
     * Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key
     * the leaf's {@code holder_pq} commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its
     * window. {@code bind} is {@code {now, action_digest?}}. A narrow block only ADDS restrictions. Total.
     */
    public static NarrowVerdict verifyNarrow(Object narrow, Object grant, Object chain, Map<String, Object> bind) {
        try {
            if (!IntentJs.isInt(bind.get("now"))) return NarrowVerdict.no("the verifier clock is not a safe integer (fail closed)");
            long now = IntentJs.lng(bind.get("now"));
            Object nar = IntentJs.normalize(narrow);
            String e = narrowShapeError(nar);
            if (e != null) return NarrowVerdict.no("malformed narrow block: " + e);
            Map<String, Object> n = mp(nar);
            List<Object> hops = hopsOf(grant, chain);
            Map<String, Object> leaf = mp(hops.get(hops.size() - 1));
            if (!Objects.equals(n.get("holder"), leaf.get("holder"))) return NarrowVerdict.no("the narrow block is not signed by the leaf holder");
            if (!Objects.equals(n.get("cap_hash"), Pca.capHash(leaf))) return NarrowVerdict.no("the narrow block is bound to another hop");
            Object pq = n.get("pq_pk") instanceof String && leaf.get("holder_pq") != null && Pca.holderPqCommitment((String) n.get("pq_pk")).equals(leaf.get("holder_pq"))
                ? n.get("pq_pk") : null;
            if (!IntentArtifacts.verifyArtifactSig(NARROW_DOMAIN, n, n.get("holder"), pq)) return NarrowVerdict.no("narrow signature invalid");
            if (n.containsKey("action_digest") && !Objects.equals(n.get("action_digest"), bind.get("action_digest")))
                return NarrowVerdict.no("the narrow block is bound to another action");
            if (now < IntentJs.lng(n.get("iat"))) return NarrowVerdict.no("the narrow block is from the future");
            if (now > IntentJs.lng(n.get("not_after"))) return NarrowVerdict.no("the narrow block has expired");
            return new NarrowVerdict(true, new ArrayList<>((List<?>) n.get("caveats")), null);
        } catch (RuntimeException | StackOverflowError ex) {
            return NarrowVerdict.no("narrow error (fail closed): " + errMsg(ex));
        }
    }

    // ================================================================================================================
    // max_uses: n atomic first-use slots in the verifier's replay store
    // ================================================================================================================

    /** Null when the caveat is well-formed. */
    public static String maxUsesError(Object co) {
        if (!(co instanceof Map)) return "caveat must be an object";
        Map<String, Object> c = mp(co);
        String e = closed(c, List.of("type", "id", "n", "until"), NO_MEMBERS, "max_uses");
        if (e != null) return e;
        if (!CAVEAT_MAX_USES.equals(c.get("type"))) return "not a max_uses caveat";
        if (!idOk(c.get("id"))) return "id is malformed";
        Object n = c.get("n");
        if (!(IntentJs.isInt(n) && IntentJs.lng(n) >= 1 && IntentJs.lng(n) <= MAX_USES_LIMIT)) return "n must be 1.." + MAX_USES_LIMIT;
        if (!IntentJs.isNonNeg(c.get("until"))) return "until must be a non-negative safe integer";
        return null;
    }

    /** The store key of use slot {@code i} of caveat {@code id} carried by the hop {@code capHashOfHop}: b64u(sha256(domain NUL cap NUL id NUL i)). */
    public static String maxUsesSlotKey(String capHashOfHop, String id, int i) {
        return Pca.b64(Pca.sha((MAX_USES_DOMAIN + capHashOfHop + "\0" + id + "\0" + i).getBytes(StandardCharsets.UTF_8)));
    }

    /** {@link #reserveMaxUses}'s answer: {@code ok} with the number of uses spent, or the refusal reason. */
    public static final class UsesVerdict {
        public final boolean ok;
        public final int spent;
        public final String reason;

        private UsesVerdict(boolean ok, int spent, String reason) {
            this.ok = ok;
            this.spent = spent;
            this.reason = reason;
        }

        static UsesVerdict no(String reason) { return new UsesVerdict(false, 0, reason); }

        @Override public String toString() { return ok ? "UsesVerdict{ok, spent=" + spent + "}" : "UsesVerdict{" + reason + "}"; }
    }

    /** {@link #reserveMaxUses(StateStore, List, Object)} for a clock that is already a {@code long}. */
    public static UsesVerdict reserveMaxUses(StateStore store, List<BoundCaveat> bound, long now) {
        return reserveMaxUses(store, bound, (Object) IntentJs.ofLong(now));
    }

    /**
     * Spend one use of every {@code max_uses} caveat in {@code bound}, in order, after the rest of the decision allows. Each
     * caveat takes the first free slot of its {@code n}: slot {@code i} is one TTL'd first-use ({@code consumeOnce(key, until, now)}) on the
     * replay store, so concurrent actions never share a slot, across processes when the store is durable and shared. The first
     * exhausted, expired or malformed caveat refuses; slots already taken stay spent (fail closed). A store that fails, or
     * answers null, refuses.
     */
    public static UsesVerdict reserveMaxUses(StateStore store, List<BoundCaveat> bound, Object now) {
        try {
            if (!IntentJs.isInt(now)) return UsesVerdict.no("the verifier clock is not a safe integer (fail closed)");
            long t = IntentJs.lng(now);
            int spent = 0;
            Set<String> ids = new HashSet<>();
            for (BoundCaveat b : bound) {
                if (!(b.caveat instanceof Map) || !CAVEAT_MAX_USES.equals(((Map<?, ?>) b.caveat).get("type"))) continue;
                Map<String, Object> caveat = mp(b.caveat);
                String err = maxUsesError(caveat);
                if (err != null) return UsesVerdict.no("malformed max_uses caveat: " + err);
                String id = (String) caveat.get("id");
                if (!ids.add(b.capHash + "\0" + id)) return UsesVerdict.no("duplicate max_uses id '" + id + "'");
                if (t >= IntentJs.lng(caveat.get("until"))) return UsesVerdict.no("max_uses '" + id + "' has expired");
                long n = IntentJs.lng(caveat.get("n"));
                boolean took = false;
                long until = IntentJs.lng(caveat.get("until"));
                for (int i = 0; i < n && !took; i++) took = store.consumeOnce(maxUsesSlotKey(b.capHash, id, i), until, t);
                if (!took) return UsesVerdict.no("max_uses '" + id + "' is exhausted");
                spent += 1;
            }
            return new UsesVerdict(true, spent, null);
        } catch (RuntimeException | StackOverflowError e) {
            return UsesVerdict.no("max_uses error (fail closed): " + errMsg(e));
        }
    }

    // ================================================================================================================
    // derive: bounded derived facts in Kleene three-valued logic
    // ================================================================================================================

    private static String exprError(Object xo, Set<String> names, int depth, int[] count) {
        if (depth > DERIVE_MAX_DEPTH) return "expression nests deeper than " + DERIVE_MAX_DEPTH;
        if (++count[0] > DERIVE_MAX_NODES) return "more than " + DERIVE_MAX_NODES + " expression nodes";
        if (!(xo instanceof Map)) return "expression must be an object";
        Map<String, Object> x = mp(xo);
        if (x.containsKey("ref")) {
            String e = closed(x, List.of("ref"), NO_MEMBERS, "ref");
            if (e != null) return e;
            return x.get("ref") instanceof String && names.contains(x.get("ref")) ? null : "ref names no earlier def";
        }
        if (x.containsKey("const")) {
            String e = closed(x, List.of("const"), NO_MEMBERS, "const");
            if (e != null) return e;
            return isScalarClaim(x.get("const")) ? null : "const must be a scalar";
        }
        Object op = x.get("op");
        if ("and".equals(op) || "or".equals(op)) {
            String e = closed(x, List.of("op", "args"), NO_MEMBERS, (String) op);
            if (e != null) return e;
            Object args = x.get("args");
            if (!(args instanceof List) || ((List<?>) args).size() < 1 || ((List<?>) args).size() > 8) return op + " needs 1..8 arguments";
            for (Object a : (List<?>) args) {
                String r = exprError(a, names, depth + 1, count);
                if (r != null) return r;
            }
            return null;
        }
        if ("not".equals(op)) {
            String e = closed(x, List.of("op", "arg"), NO_MEMBERS, "not");
            return e != null ? e : exprError(x.get("arg"), names, depth + 1, count);
        }
        if (op instanceof String && CMP_OPS.contains(op)) {
            String e = closed(x, List.of("op", "a", "b"), NO_MEMBERS, (String) op);
            if (e != null) return e;
            String r = exprError(x.get("a"), names, depth + 1, count);
            return r != null ? r : exprError(x.get("b"), names, depth + 1, count);
        }
        return "unknown expression";
    }

    private static boolean paramPathOk(Object p) {
        if (!(p instanceof String)) return false;
        String[] segs = ((String) p).split("\\.", -1);
        if (segs.length > 4) return false;
        for (String s : segs) if (!IntentArtifacts.isPathSegment(s)) return false;
        return true;
    }

    /** Null when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it). */
    public static String deriveError(Object co) {
        if (!(co instanceof Map)) return "caveat must be an object";
        Map<String, Object> c = mp(co);
        String e = closed(c, List.of("type", "id", "defs", "check"), NO_MEMBERS, "derive");
        if (e != null) return e;
        if (!CAVEAT_DERIVE.equals(c.get("type"))) return "not a derive caveat";
        if (!idOk(c.get("id"))) return "id is malformed";
        Object defs = c.get("defs");
        if (!(defs instanceof List) || ((List<?>) defs).size() > DERIVE_MAX_DEFS) return "defs must be an array of at most " + DERIVE_MAX_DEFS;
        Set<String> names = new HashSet<>();
        int[] count = {0};
        for (Object d0 : (List<?>) defs) {
            if (!(d0 instanceof Map) || !nameOk(((Map<?, ?>) d0).get("name"))) return "def name is malformed";
            Map<String, Object> d = mp(d0);
            String name = (String) d.get("name");
            if (names.contains(name)) return "def '" + name + "' is defined twice";
            Object kindO = d.get("kind");
            String kind = kindO instanceof String ? (String) kindO : "";
            String de;
            switch (kind) {
                case "count":
                    de = closed(d, List.of("name", "kind", "window_ms"), List.of("verb", "resource_prefix"), "count");
                    if (de == null && !(IntentJs.isInt(d.get("window_ms")) && IntentJs.lng(d.get("window_ms")) >= 1 && IntentJs.lng(d.get("window_ms")) <= DERIVE_MAX_WINDOW_MS))
                        de = "window_ms out of range";
                    if (de == null && d.containsKey("verb") && !isStr256(d.get("verb"))) de = "verb must be a non-empty string";
                    if (de == null && d.containsKey("resource_prefix") && !isStr256(d.get("resource_prefix"))) de = "resource_prefix must be a non-empty string";
                    break;
                case "param":
                    de = closed(d, List.of("name", "kind", "path"), NO_MEMBERS, "param");
                    if (de == null && !paramPathOk(d.get("path"))) de = "param path is malformed";
                    break;
                case "action":
                    de = closed(d, List.of("name", "kind", "field"), NO_MEMBERS, "action");
                    if (de == null && !"verb".equals(d.get("field")) && !"resource".equals(d.get("field"))) de = "field must be 'verb' or 'resource'";
                    break;
                case "claim":
                    de = closed(d, List.of("name", "kind", "caveat_id", "claim"), NO_MEMBERS, "claim");
                    if (de == null && !(idOk(d.get("caveat_id")) && nameOk(d.get("claim")))) de = "claim reference is malformed";
                    break;
                case "expr":
                    de = closed(d, List.of("name", "kind", "expr"), NO_MEMBERS, "expr");
                    if (de == null) de = exprError(d.get("expr"), names, 1, count);
                    break;
                default:
                    de = "unknown def kind";
            }
            if (de != null) return "def '" + name + "': " + de;
            names.add(name);
        }
        return exprError(c.get("check"), names, 1, count);
    }

    /** The value of an expression: a scalar (String, Boolean, Json.Num), or null for unknown. */
    private static Object evalExpr(Object xo, Map<String, Object> env) {
        Map<String, Object> x = mp(xo);
        if (x.containsKey("ref")) return env.get((String) x.get("ref"));
        if (x.containsKey("const")) return x.get("const");
        String op = (String) x.get("op");
        if (op.equals("not")) {
            Object v = evalExpr(x.get("arg"), env);
            return v instanceof Boolean ? Boolean.valueOf(!((Boolean) v)) : null;
        }
        if (op.equals("and") || op.equals("or")) {
            boolean stop = op.equals("or");
            boolean unknown = false;
            for (Object a : (List<?>) x.get("args")) {
                Object v = evalExpr(a, env);
                if (!(v instanceof Boolean)) unknown = true;
                else if (((Boolean) v).booleanValue() == stop) return Boolean.valueOf(stop);
            }
            return unknown ? null : Boolean.valueOf(!stop);
        }
        Object a = evalExpr(x.get("a"), env);
        Object b = evalExpr(x.get("b"), env);
        if (a == null || b == null) return null;
        if (op.equals("eq")) return Boolean.valueOf(IntentArtifacts.scalarEq(a, b));
        if (op.equals("neq")) return Boolean.valueOf(!IntentArtifacts.scalarEq(a, b));
        if (!IntentJs.isInt(a) || !IntentJs.isInt(b)) return null;
        long p = IntentJs.lng(a), q = IntentJs.lng(b);
        switch (op) {
            case "lt": return Boolean.valueOf(p < q);
            case "lte": return Boolean.valueOf(p <= q);
            case "gt": return Boolean.valueOf(p > q);
            default: return Boolean.valueOf(p >= q);
        }
    }

    /**
     * Evaluate a well-formed derive caveat: TRUE only when {@code check} is exactly true (false and unknown both refuse; the
     * result is null for unknown). {@code history} is the verifier's own record ({@code [{t, verb, resource}]}),
     * {@code claims} maps a caveat id to the claims of the discharge that VERIFIED in this evaluation.
     */
    static Boolean evaluateDerive(Map<String, Object> c, long now, Object action, Object history, Map<String, Map<String, Object>> claims) {
        Map<String, Object> env = new HashMap<>();
        for (Object d0 : (List<?>) c.get("defs")) {
            Map<String, Object> d = mp(d0);
            Object v = null;
            switch ((String) d.get("kind")) {
                case "count": {
                    if (!(history instanceof List) || ((List<?>) history).size() > DERIVE_MAX_HISTORY) break;
                    long window = IntentJs.lng(d.get("window_ms"));
                    long n = 0;
                    boolean bad = false;
                    for (Object eo : (List<?>) history) {
                        if (!(eo instanceof Map)) { bad = true; break; }
                        Map<?, ?> ev = (Map<?, ?>) eo;
                        if (!IntentJs.isInt(ev.get("t")) || !(ev.get("verb") instanceof String) || !(ev.get("resource") instanceof String)) { bad = true; break; }
                        long t = IntentJs.lng(ev.get("t"));
                        if (t > now - window && t <= now
                            && (!d.containsKey("verb") || ev.get("verb").equals(d.get("verb")))
                            && (!d.containsKey("resource_prefix") || ((String) ev.get("resource")).startsWith((String) d.get("resource_prefix")))) n += 1;
                    }
                    v = bad ? null : IntentJs.ofLong(n);
                    break;
                }
                case "param": {
                    Predicates.Resolved r = IntentArtifacts.resolveParamPath(IntentJs.get(action, "params"), "action.params." + d.get("path"));
                    v = r.found && isScalarClaim(r.value) ? r.value : null;
                    break;
                }
                case "action": {
                    Object f = IntentJs.get(action, (String) d.get("field"));
                    v = isStr256(f) ? f : null;
                    break;
                }
                case "claim": {
                    Map<String, Object> cl = claims.get((String) d.get("caveat_id"));
                    v = cl == null ? null : cl.get((String) d.get("claim"));
                    break;
                }
                default: // expr
                    v = evalExpr(d.get("expr"), env);
            }
            env.put((String) d.get("name"), v);
        }
        Object r = evalExpr(c.get("check"), env);
        return r instanceof Boolean ? (Boolean) r : null;
    }

    // ================================================================================================================
    // spiffe_bound
    // ================================================================================================================

    /** Null when the caveat is well-formed. */
    public static String spiffeBoundError(Object co) {
        if (!(co instanceof Map)) return "caveat must be an object";
        Map<String, Object> c = mp(co);
        String e = closed(c, List.of("type"), List.of("spiffe_id", "spiffe_prefix"), "spiffe_bound");
        if (e != null) return e;
        if (!CAVEAT_SPIFFE_BOUND.equals(c.get("type"))) return "not a spiffe_bound caveat";
        if (c.containsKey("spiffe_id") == c.containsKey("spiffe_prefix")) return "exactly one of spiffe_id and spiffe_prefix";
        return spiffeIdError(c.containsKey("spiffe_id") ? c.get("spiffe_id") : c.get("spiffe_prefix"));
    }

    /** {@code spiffe_id}: the peer must equal it. {@code spiffe_prefix}: the peer must equal it or lie below it ({@code prefix + "/"}). */
    private static boolean spiffeSatisfied(Map<String, Object> c, Object peer) {
        if (spiffeBoundError(c) != null || spiffeIdError(peer) != null) return false;
        String p = (String) peer;
        if (c.containsKey("spiffe_id")) return p.equals(c.get("spiffe_id"));
        String pre = (String) c.get("spiffe_prefix");
        return p.equals(pre) || p.startsWith(pre + "/");
    }

    // ================================================================================================================
    // The K1 evaluator
    // ================================================================================================================

    /** {@link #evaluateK1}'s answer. */
    public static final class K1Result {
        public final boolean ok;
        /** Types of the unsatisfied caveats, in order ({@code <malformed>} for one without a string type). */
        public final List<String> failed;
        /** One reason per failure (same order). */
        public final List<String> reasons;
        /** Verified narrow-block caveats that are NOT K1 types: the caller evaluates them with its stock evaluator. */
        public final List<Object> plain;
        /** The caveats evaluated, with their hops: hand the {@code max_uses} ones to {@link #reserveMaxUses} once everything allowed. */
        public final List<BoundCaveat> bound;

        K1Result(List<String> failed, List<String> reasons, List<Object> plain, List<BoundCaveat> bound) {
            this.ok = failed.isEmpty();
            this.failed = Collections.unmodifiableList(failed);
            this.reasons = Collections.unmodifiableList(reasons);
            this.plain = Collections.unmodifiableList(plain);
            this.bound = Collections.unmodifiableList(bound);
        }

        @Override public String toString() { return "K1Result{ok=" + ok + ", failed=" + failed + "}"; }
    }

    private static void fail(List<String> failed, List<String> reasons, Object c, String why) {
        Object t = c instanceof Map ? ((Map<?, ?>) c).get("type") : null;
        failed.add(t instanceof String ? (String) t : "<malformed>");
        reasons.add(why);
    }

    /**
     * Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
     * evaluators. {@code k1} is {@code {pins?, discharges?, narrow?, action_digest?, revoked_discharges?, spiffe_id?,
     * history?}}; {@code ctx} is {@code {now, action?}}. {@code needs_discharge} / {@code max_uses} / {@code derive} ids must
     * be unique over the chain and narrow block (a duplicate fails every caveat that shares it). {@code max_uses} is only
     * checked for well-formedness and expiry here; {@link #reserveMaxUses} spends it. Total.
     */
    public static K1Result evaluateK1(Object grant, Object chain, Map<String, Object> k1, Map<String, Object> ctx) {
        List<String> failed = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        try {
            List<BoundCaveat> base = boundCaveats(grant, chain);
            Object nowO = ctx == null ? null : ctx.get("now");
            if (base == null || !IntentJs.isInt(nowO)) {
                fail(failed, reasons, null, base == null ? "malformed capability chain" : "the verifier clock is not a safe integer (fail closed)");
                return new K1Result(failed, reasons, new ArrayList<>(), new ArrayList<>());
            }
            // No k1 input at all (not even {}): every K1 caveat is refused, so an unconfigured verifier never passes sealed or a constant derive.
            if (k1 == null) {
                List<BoundCaveat> mine = new ArrayList<>();
                for (BoundCaveat b : base) if (isK1Caveat(b.caveat)) mine.add(b);
                for (BoundCaveat b : mine) fail(failed, reasons, b.caveat, "the caveat language is not configured (no k1 input)");
                return new K1Result(failed, reasons, new ArrayList<>(), mine);
            }
            Map<String, Object> k = k1;
            long now = IntentJs.lng(nowO);
            Object action = ctx.get("action");
            List<Object> hops = hopsOf(grant, chain);
            int leafIndex = hops.size() - 1;
            List<BoundCaveat> bound = base;
            List<Object> plain = new ArrayList<>();
            if (k.containsKey("narrow")) {
                Map<String, Object> nb = new LinkedHashMap<>();
                nb.put("now", nowO);
                if (k.containsKey("action_digest")) nb.put("action_digest", k.get("action_digest"));
                NarrowVerdict nv = verifyNarrow(k.get("narrow"), grant, chain, nb);
                if (!nv.ok) {
                    Map<String, Object> narrowType = new LinkedHashMap<>();
                    narrowType.put("type", "narrow");
                    fail(failed, reasons, narrowType, nv.reason);
                    List<BoundCaveat> only = new ArrayList<>();
                    for (BoundCaveat b : base) if (isK1Caveat(b.caveat)) only.add(b);
                    return new K1Result(failed, reasons, new ArrayList<>(), only);
                }
                String leafHash = Pca.capHash(mp(hops.get(leafIndex)));
                bound = new ArrayList<>(base);
                for (Object caveat : nv.caveats) {
                    bound.add(new BoundCaveat(caveat, leafIndex, leafHash));
                    if (!isK1Caveat(caveat)) plain.add(caveat);
                }
            }
            List<BoundCaveat> k1Bound = new ArrayList<>();
            for (BoundCaveat b : bound) if (isK1Caveat(b.caveat)) k1Bound.add(b);
            // ids are unique per type across the chain and narrow block
            Map<String, Integer> seen = new HashMap<>();
            for (BoundCaveat b : k1Bound) {
                Map<String, Object> cv = mp(b.caveat);
                if (cv.get("id") instanceof String) seen.merge(cv.get("type") + "\0" + cv.get("id"), 1, Integer::sum);
            }
            Map<String, Map<String, Object>> claims = new HashMap<>();
            // pass 1: discharges (derive reads their claims)
            for (BoundCaveat b : k1Bound) {
                Map<String, Object> cv = mp(b.caveat);
                if (!CAVEAT_NEEDS_DISCHARGE.equals(cv.get("type"))) continue;
                String bad = needsDischargeError(cv);
                if (bad != null) {
                    fail(failed, reasons, cv, bad);
                    continue;
                }
                String id = (String) cv.get("id");
                if (seen.getOrDefault(CAVEAT_NEEDS_DISCHARGE + "\0" + id, 0) > 1) {
                    fail(failed, reasons, cv, "duplicate needs_discharge id '" + id + "'");
                    continue;
                }
                String why = "no discharge presented";
                DischargeVerdict okd = null;
                if (k.get("discharges") instanceof List) {
                    for (Object d : (List<?>) k.get("discharges")) {
                        if (!(d instanceof Map) || !Objects.equals(((Map<?, ?>) d).get("caveat_id"), cv.get("id"))) continue;
                        Map<String, Object> bind = new LinkedHashMap<>();
                        bind.put("cap_hash", b.capHash);
                        if (k.containsKey("action_digest")) bind.put("action_digest", k.get("action_digest"));
                        bind.put("pins", k.get("pins") == null ? new ArrayList<>() : k.get("pins"));
                        bind.put("now", nowO);
                        if (k.containsKey("revoked_discharges")) bind.put("revoked", k.get("revoked_discharges"));
                        DischargeVerdict v = verifyDischarge(d, cv, bind);
                        if (v.ok) {
                            okd = v;
                            break;
                        }
                        why = v.reason;
                    }
                }
                if (okd != null) claims.put(id, okd.claims);
                else fail(failed, reasons, cv, why);
            }
            // pass 2: everything else, in order
            for (BoundCaveat b : k1Bound) {
                Map<String, Object> c = mp(b.caveat);
                String type = (String) c.get("type");
                switch (type) {
                    case CAVEAT_SEALED: {
                        String e = closed(c, List.of("type"), NO_MEMBERS, "sealed");
                        if (e != null) fail(failed, reasons, c, e);
                        else if (b.hop != leafIndex) fail(failed, reasons, c, "a hop was appended below a sealed hop");
                        break;
                    }
                    case CAVEAT_MAX_USES: {
                        String e = maxUsesError(c);
                        if (e != null) fail(failed, reasons, c, e);
                        else if (seen.getOrDefault(CAVEAT_MAX_USES + "\0" + c.get("id"), 0) > 1) fail(failed, reasons, c, "duplicate max_uses id '" + c.get("id") + "'");
                        else if (now >= IntentJs.lng(c.get("until"))) fail(failed, reasons, c, "max_uses '" + c.get("id") + "' has expired");
                        break;
                    }
                    case CAVEAT_DERIVE: {
                        String e = deriveError(c);
                        if (e != null) fail(failed, reasons, c, e);
                        else if (seen.getOrDefault(CAVEAT_DERIVE + "\0" + c.get("id"), 0) > 1) fail(failed, reasons, c, "duplicate derive id '" + c.get("id") + "'");
                        else {
                            Boolean r = evaluateDerive(c, now, action, k.get("history"), claims);
                            if (!Boolean.TRUE.equals(r)) fail(failed, reasons, c, r == null ? "derive check is unknown (a fact is missing)" : "derive check is false");
                        }
                        break;
                    }
                    case CAVEAT_SPIFFE_BOUND:
                        if (!spiffeSatisfied(c, k.get("spiffe_id"))) fail(failed, reasons, c, "the presenting workload does not carry the required SPIFFE ID");
                        break;
                    default: // needs_discharge: decided in pass 1
                }
            }
            return new K1Result(failed, reasons, plain, k1Bound);
        } catch (RuntimeException | StackOverflowError e) {
            fail(failed, reasons, null, "caveat language error (fail closed): " + errMsg(e));
            return new K1Result(failed, reasons, new ArrayList<>(), new ArrayList<>());
        }
    }

    /**
     * Every caveat of {@code policyCaveats(grant, chain)} evaluated: the K1 types by {@link #evaluateK1}, every other one (plus
     * the verified narrow block's plain caveats) by the agent/stock evaluator. {@code context} uses the stock names
     * ({@code now}, {@code delegation_depth}, {@code action {verb, resource, params}}, ...). The result's {@code failed} is
     * the stock failures plus the K1 failures, sorted; {@code ok} iff it is empty.
     */
    public static Caveats.Result evaluateCaveatsK1(Object grant, Object chain, Map<String, Object> k1, Map<String, Object> context) {
        try {
            K1Result k = evaluateK1(grant, chain, k1, context);
            Object pc = Caveats.policyCaveats(grant, chain);
            Object stock = pc;
            if (pc instanceof List) {
                List<Object> l = new ArrayList<>();
                for (Object c : (List<?>) pc) if (!isK1Caveat(c)) l.add(c);
                l.addAll(k.plain);
                stock = l;
            }
            Map<String, Object> actionCtx = new LinkedHashMap<>();
            if (context.containsKey("action")) actionCtx.put("action", context.get("action"));
            Caveats.Result s = Authorize.evaluateAgentCaveats(stock, new LinkedHashMap<>(context), actionCtx, null);
            List<String> failed = new ArrayList<>(s.failed);
            failed.addAll(k.failed);
            Collections.sort(failed);
            return new Caveats.Result(failed.isEmpty(), failed);
        } catch (RuntimeException | StackOverflowError e) {
            return new Caveats.Result(false, new ArrayList<>(List.of("<evaluation error>")));
        }
    }
}
