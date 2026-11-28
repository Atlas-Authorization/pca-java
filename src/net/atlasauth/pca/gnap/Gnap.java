package net.atlasauth.pca.gnap;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.SignersMore;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * A GNAP (RFC 9635) bridge for Proof-Carrying Authority: the Agent-GNAP profile. Mirrors the TypeScript package's main module
 * (access-rights normalization and mapping onto policy predicates, containment and clamping, grant request to capability,
 * action authorization, bound tokens, the {@code jwsd} detached-JWS proof, and continuation / step-up). Every verify path
 * fails closed. Values are JSON trees: {@code Map<String,Object>}, {@code List<Object>}, {@code String}, {@code Boolean},
 * {@link Json.Num} and null; secrets are 32-byte Ed25519 seeds given as {@code byte[]} or base64url text.
 *
 * <p>Deliberate differences from the reference: {@link #grantRequestToCapability} refuses an {@code issuerPublic} that is not
 * the public key of {@code issuerSecret} (the reference would sign a chain that can never verify), and
 * {@link #completeGnapContinuation} verifies its own Ed25519 co-signature shares only.
 */
public final class Gnap {
    private Gnap() {}

    public static final String GNAP_GRANT_CAVEAT = "gnap_grant";
    public static final String GNAP_ACCESS_CAVEAT = "gnap_access";
    /** Upper bound on an accepted detached JWS string (adversarial-size guard). */
    public static final int MAX_DETACHED_JWS_CHARS = 8192;
    private static final String JWSD_TYP = "gnap-binding-jwsd";
    private static final String GNAP_RESOURCE_PREFIX = "gnap";
    /** An argument that is absent (JavaScript undefined): a request body (the proof then covers no content) or a holder override. */
    public static final Object ABSENT = Js.ABSENT;

    /** The replay store of {@link #verifyGnapRequest}: true (or any value but false) means the proof was already seen. */
    public interface SeenProof { Object seen(String proofId, double expiresSec) throws Exception; }

    // ---------------------------------------------------------------------------------------------------------------------
    // small guards
    // ---------------------------------------------------------------------------------------------------------------------

    private static boolean isRecord(Object x) { return x instanceof Map; }

    private static List<Object> strArr(Object u) {
        if (!(u instanceof List)) return null;
        List<Object> out = new ArrayList<>();
        for (Object s : (List<?>) u) if (s instanceof String) out.add(s);
        return out;
    }

    /** A canonical, unpadded base64url Ed25519 public key (exactly 32 bytes), or null. */
    private static String asEd25519(Object x) {
        return x instanceof String && Pca.decodeB64uStrict(x, 32) != null ? (String) x : null;
    }

    private static byte[] secretBytes(Object o) {
        if (o instanceof byte[]) return (byte[]) o;
        if (o instanceof String) return Keys.unb64u((String) o);
        throw new GnapError("a secret key must be 32 bytes (bytes or base64url text)");
    }

    private static Keys.EdKey edKey(Object secret) { return Keys.edFromSeed(secretBytes(secret)); }

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) { return (List<Object>) o; }

    /** The PCA {@code resource} string for a GNAP (type, location) pair: the namespace actions are matched in. */
    public static String gnapActionResource(String type, String location) {
        return GNAP_RESOURCE_PREFIX + ":" + type + ":" + location;
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // access-rights normalization and mapping onto predicates
    // ---------------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> tryNormalizeAccessItem(Object item) {
        if (item instanceof String) return ((String) item).isEmpty() ? null : obj("type", item);
        if (!isRecord(item)) return null;
        Map<String, Object> m = map(item);
        Object type = m.get("type");
        if (!(type instanceof String) || ((String) type).isEmpty()) return null;
        Map<String, Object> out = obj("type", type);
        List<Object> actions = strArr(m.get("actions"));
        if (actions != null && !actions.isEmpty()) out.put("actions", actions);
        List<Object> locations = strArr(m.get("locations"));
        if (locations != null && !locations.isEmpty()) out.put("locations", locations);
        List<Object> datatypes = strArr(m.get("datatypes"));
        if (datatypes != null && !datatypes.isEmpty()) out.put("datatypes", datatypes);
        if (m.get("identifier") instanceof String) out.put("identifier", m.get("identifier"));
        List<Object> privileges = strArr(m.get("privileges"));
        if (privileges != null && !privileges.isEmpty()) out.put("privileges", privileges);
        return out;
    }

    /** Normalize an access array for issuance (throws on any malformed entry). */
    public static List<Object> normalizeAccess(Object items) {
        if (!(items instanceof List)) throw new GnapError("access must be an array");
        List<Object> out = new ArrayList<>();
        for (Object item : (List<?>) items) {
            Map<String, Object> n = tryNormalizeAccessItem(item);
            if (n == null) throw new GnapError("malformed access item (needs a non-empty string `type`)");
            out.add(n);
        }
        return out;
    }

    /** Total, fail-closed read of a stored access array (reading signed caveats). Skips malformed entries. */
    private static List<Object> readAccessArray(Object u) {
        List<Object> out = new ArrayList<>();
        if (!(u instanceof List)) return out;
        for (Object item : (List<?>) u) {
            Map<String, Object> n = tryNormalizeAccessItem(item);
            if (n != null) out.add(n);
        }
        return out;
    }

    private static List<Object> nonEmpty(Object l) { return l instanceof List && !((List<?>) l).isEmpty() ? list(l) : null; }

    /**
     * Map a GNAP access right onto PCA predicates (one per location). {@code type} namespaces the resource, {@code actions}
     * become verbs, {@code locations} become resources, and {@code datatypes}/{@code identifier} become {@code where}
     * conditions on the action's params. An absent {@code actions}/{@code locations} means "any".
     */
    public static List<Object> accessToPredicates(Map<String, Object> access) {
        List<Object> actions = nonEmpty(access.get("actions"));
        Object verb = actions != null ? new ArrayList<>(actions) : "*";
        List<Object> locs = nonEmpty(access.get("locations"));
        List<Object> locations = locs != null ? locs : new ArrayList<>(List.of("*"));
        List<Object> where = new ArrayList<>();
        List<Object> datatypes = nonEmpty(access.get("datatypes"));
        if (datatypes != null) where.add(obj("field", "action.params.datatype", "op", "in", "value", new ArrayList<>(datatypes)));
        if (access.get("identifier") instanceof String) where.add(obj("field", "action.params.identifier", "op", "eq", "value", access.get("identifier")));
        List<Object> out = new ArrayList<>();
        for (Object loc : locations) {
            Map<String, Object> p = obj("verb", verb instanceof List ? new ArrayList<>(list(verb)) : verb, "resource", gnapActionResource((String) access.get("type"), Js.str(loc)));
            if (!where.isEmpty()) {
                List<Object> w = new ArrayList<>();
                for (Object c : where) w.add(new LinkedHashMap<>(map(c)));
                p.put("where", w);
            }
            out.add(p);
        }
        return out;
    }

    private static List<Object> accessArrayToPredicates(List<Object> access) {
        List<Object> out = new ArrayList<>();
        for (Object a : access) out.addAll(accessToPredicates(map(a)));
        return out;
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // containment
    // ---------------------------------------------------------------------------------------------------------------------

    private static boolean coversStrings(List<Object> sup, List<Object> sub) {
        if (sup == null) return true; // issuer allows all
        if (sub == null) return false; // request wants all, issuer has a concrete set
        for (Object s : sub) if (!sup.contains(s)) return false;
        return true;
    }

    private static boolean coversLocations(List<Object> sup, List<Object> sub) {
        if (sup == null) return true;
        if (sub == null) return sup.contains("*");
        for (Object so : sub) {
            String s = (String) so;
            boolean any = false;
            for (Object go : sup) {
                String g = (String) go;
                if (g.equals(s) || g.equals("*") || (g.endsWith("*") && s.startsWith(g.substring(0, g.length() - 1)))) { any = true; break; }
            }
            if (!any) return false;
        }
        return true;
    }

    private static List<Object> strings(Object l) { return l instanceof List ? list(l) : null; }

    /** Does the issuer's granted right {@code g} fully contain the requested right {@code r}? */
    public static boolean accessContains(Map<String, Object> g, Map<String, Object> r) {
        if (!java.util.Objects.equals(g.get("type"), r.get("type"))) return false;
        if (!coversStrings(strings(g.get("actions")), strings(r.get("actions")))) return false;
        if (!coversLocations(strings(g.get("locations")), strings(r.get("locations")))) return false;
        if (!coversStrings(strings(g.get("datatypes")), strings(r.get("datatypes")))) return false;
        if (r.get("identifier") != null && g.get("identifier") != null && !g.get("identifier").equals(r.get("identifier"))) return false;
        return true;
    }

    /** Is {@code r} within the issuer's granted set {@code G} (covered by at least one of its rights)? */
    public static boolean accessWithin(List<Object> G, Map<String, Object> r) {
        for (Object g : G) if (accessContains(map(g), r)) return true;
        return false;
    }

    /** Split a requested access array into the subset within the issuer's authority and the rest: {@code {granted, dropped}}. */
    public static Map<String, Object> clampAccess(List<Object> issuerGranted, List<Object> requested) {
        List<Object> granted = new ArrayList<>(), dropped = new ArrayList<>();
        for (Object r : requested) (accessWithin(issuerGranted, map(r)) ? granted : dropped).add(r);
        return obj("granted", granted, "dropped", dropped);
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // provenance caveats
    // ---------------------------------------------------------------------------------------------------------------------

    /** The root grant's GNAP provenance caveat's granted access, or null when there is none. */
    private static List<Object> readGnapGrantAccess(Object root) {
        Map<String, Object> env = Authorize.readEnvelope(root);
        if (env == null || !(env.get("caveats") instanceof List)) return null;
        Map<String, Object> cv = null;
        for (Object c : list(env.get("caveats"))) {
            if (c instanceof Map && GNAP_GRANT_CAVEAT.equals(map(c).get("type"))) { cv = map(c); break; }
        }
        if (cv == null) return null;
        if (!(cv.get("client_id") instanceof String) || !(cv.get("request_digest") instanceof String)) return null;
        return readAccessArray(cv.get("granted_access"));
    }

    /**
     * The EFFECTIVE granted access of a chain: the most-recent delegated hop's recorded rights, or (for a root-only grant) the
     * root's recorded rights. Every hop is clamped to its issuer at issue time, so the leaf's rights are the narrowest.
     */
    public static List<Object> grantedAccessOf(Object chain) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return new ArrayList<>();
        List<Object> ch = list(chain);
        Object leaf = ch.get(ch.size() - 1);
        if (leaf == null) throw new IllegalArgumentException("chain leaf is null");
        Object caveats = Js.member(leaf, "caveats");
        List<Object> cavs = caveats instanceof List ? list(caveats) : new ArrayList<>();
        for (int i = cavs.size() - 1; i >= 0; i--) {
            Object cv = cavs.get(i);
            if (cv instanceof Map && GNAP_ACCESS_CAVEAT.equals(map(cv).get("type"))) return readAccessArray(map(cv).get("access"));
        }
        List<Object> g = readGnapGrantAccess(ch.get(0));
        return g != null ? g : new ArrayList<>();
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // holder resolution
    // ---------------------------------------------------------------------------------------------------------------------

    /** Resolve the b64u Ed25519 holder key from a request's client key (or an explicit override; {@code ABSENT} for none). */
    public static String resolveHolder(Object req, Object holderOverride) {
        if (req == null) throw new GnapError("grant request is null");
        Object client = Js.member(req, "client");
        Object declared = client instanceof Map ? map(client).get("key") : null;
        if (Js.isObject(declared)) {
            Object proof = Js.member(declared, "proof");
            Object method = proof instanceof String ? proof : isRecord(proof) ? map(proof).get("method") : null;
            if (!"jwsd".equals(method))
                throw new GnapError("unsupported client key proof method: " + (method instanceof String ? method : "none") + " (only jwsd is supported)");
        }
        if (holderOverride != ABSENT) {
            String h = asEd25519(holderOverride);
            if (h == null) throw new GnapError("holder override is not a canonical base64url Ed25519 public key");
            return h;
        }
        Object key = client instanceof Map ? map(client).get("key") : null;
        if (Js.isObject(key)) {
            Object jwk = Js.member(key, "jwk");
            if (jwk instanceof Map && "OKP".equals(map(jwk).get("kty")) && "Ed25519".equals(map(jwk).get("crv"))) {
                String x = asEd25519(map(jwk).get("x"));
                if (x != null) return x;
            }
        }
        throw new GnapError("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override");
    }

    /** The holder key, rendered as a GNAP JWK (for a bound access-token response). */
    public static Map<String, Object> holderJwk(String holder) {
        return obj("kty", "OKP", "crv", "Ed25519", "x", holder, "use", "sig", "alg", "EdDSA");
    }

    private static List<Object> accessOf(Object req) {
        Object at = Js.member(req, "access_token");
        if (isRecord(at) && map(at).get("access") instanceof List) return list(map(at).get("access"));
        throw new GnapError("grant request must carry access_token.access (single-token request)");
    }

    private static String requestDigestOf(String holder, List<Object> granted, Object interact) {
        return Pca.hashCanonical(obj("d", "atlas-pca/gnap/request/v1", "client_id", holder, "access", granted, "interact", interact));
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // grant request -> PCA capability
    // ---------------------------------------------------------------------------------------------------------------------

    /**
     * Convert a GNAP grant request into a PCA capability bound to the client key, ATTENUATED to never exceed the issuer. With no
     * {@code parent} this MINTS a root grant whose policy-envelope predicates ARE the requested access rights; with a
     * {@code parent} it DELEGATES a narrower hop, recording the (clamped) rights as an append-only {@code gnap_access} caveat.
     * {@code opts}: issuerSecret, issuerPublic, parent, issuerChain, clampToIssuer, holder, interacted, now, goal, riskPolicy,
     * agentBinding, salt. Returns {@code {grant, chain, holder, grantedAccess, droppedAccess, provenance}}.
     */
    public static Map<String, Object> grantRequestToCapability(Object req, Map<String, Object> opts) {
        String holder = resolveHolder(req, Js.get(opts, "holder"));
        List<Object> requested = normalizeAccess(accessOf(req));
        Object nowO = opts.get("now");
        long now = nowO == null ? System.currentTimeMillis() : (long) Math.floor(Js.num(nowO));
        boolean interacted = Boolean.TRUE.equals(opts.get("interacted"));
        Object parent = opts.get("parent");
        boolean delegated = Js.truthy(parent);

        List<Object> granted = requested, dropped = new ArrayList<>();
        Object issuerChain = null;
        if (delegated) {
            issuerChain = opts.get("issuerChain") != null ? opts.get("issuerChain") : new ArrayList<>(List.of(parent));
            if (!Boolean.FALSE.equals(opts.get("clampToIssuer"))) {
                Map<String, Object> split = clampAccess(grantedAccessOf(issuerChain), requested);
                granted = list(split.get("granted"));
                dropped = list(split.get("dropped"));
            }
        }
        String requestDigest = requestDigestOf(holder, granted, req == null ? null : Js.member(req, "interact"));
        Keys.EdKey signer = edKey(opts.get("issuerSecret"));

        if (delegated) {
            Map<String, Object> provenance = obj("type", GNAP_ACCESS_CAVEAT, "access", granted, "predicates", accessArrayToPredicates(granted),
                "request_digest", requestDigest, "client_id", holder, "ts", now);
            Map<String, Object> child = Issue.delegate(map(parent), holder, new ArrayList<>(List.of(provenance)), Keys.ed25519(signer), null);
            List<Object> chain = new ArrayList<>(list(issuerChain));
            chain.add(child);
            return obj("grant", child, "chain", chain, "holder", holder, "grantedAccess", granted, "droppedAccess", dropped, "provenance", provenance);
        }

        Map<String, Object> provenance = obj("type", GNAP_GRANT_CAVEAT, "client_id", holder, "granted_access", granted, "request_digest", requestDigest,
            "interacted", interacted, "ts", now);
        if (!(opts.get("issuerPublic") instanceof String) || !opts.get("issuerPublic").equals(signer.id()))
            throw new GnapError("issuerPublic is not the public key of issuerSecret");
        Object goalO = opts.get("goal");
        String goal = goalO != null ? (String) goalO : "gnap:grant:" + holder;
        Object rp = opts.get("riskPolicy");
        Object ab = opts.get("agentBinding");
        Map<String, Object> envelope = obj("predicates", accessArrayToPredicates(granted), "caveats", new ArrayList<>(List.of(provenance)),
            "agent_binding", ab != null ? ab : new LinkedHashMap<String, Object>(), "risk_policy", rp != null ? rp : Issue.defaultRiskPolicy());
        Object salt = opts.get("salt");
        Issue.Grant g = Issue.mintGrant(Keys.ed25519(signer), holder, null, envelope, goal, salt == null ? null : (String) salt);
        return obj("grant", g.grant, "chain", new ArrayList<>(List.of(g.grant)), "holder", holder, "grantedAccess", granted, "droppedAccess", dropped,
            "provenance", provenance);
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // action authorization
    // ---------------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> pqPinsOf(Map<String, Object> opts) {
        return opts != null && opts.get("pqPins") instanceof Map ? map(opts.get("pqPins")) : null;
    }

    private static String chainReason(Object chain, Map<String, Object> opts) {
        boolean haveIssuer = Js.has(opts, "expectedRootIssuer");
        Object issuer = haveIssuer ? opts.get("expectedRootIssuer") : null;
        return Pca.verifyChain(list(chain), issuer instanceof String ? (String) issuer : null, haveIssuer, null, pqPinsOf(opts), null);
    }

    /**
     * Decide whether {@code action} ({@code verb}, {@code resource}, optional {@code params}, {@code reversibility_class}) is authorized
     * by a GNAP-issued capability chain. FAILS CLOSED. The chain must verify, the root policy envelope must permit the action AND every
     * delegated hop's recorded {@code gnap_access} rights must permit it too. {@code opts}: expectedRootIssuer, pqPins.
     */
    public static Map<String, Object> authorizeGnapAction(Object chain, Map<String, Object> action, Map<String, Object> opts) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return obj("allowed", false, "reason", "empty chain");
        String vc = chainReason(chain, opts == null ? new LinkedHashMap<>() : opts);
        if (!vc.isEmpty()) return obj("allowed", false, "reason", "capability chain invalid: " + vc);
        List<Object> ch = list(chain);
        Map<String, Object> env = Authorize.readEnvelope(ch.get(0));
        if (env == null) return obj("allowed", false, "reason", "root grant carries no policy envelope");

        Map<String, Object> act = obj("verb", action.get("verb"), "resource", action.get("resource"));
        if (action.containsKey("params")) act.put("params", action.get("params"));
        if (action.containsKey("reversibility_class")) act.put("reversibility_class", action.get("reversibility_class"));
        Map<String, Object> ctx = obj("action", act);

        if (!Predicates.evaluatePredicates(env.get("predicates"), ctx)) {
            String why = Predicates.denialReason(env.get("predicates"), ctx);
            return obj("allowed", false, "reason", "root authority denies: " + (why != null ? why : "no predicate matched"));
        }
        Object leaf = ch.get(ch.size() - 1);
        Object caveats = Js.member(leaf, "caveats");
        if (caveats instanceof List) {
            for (Object cv : list(caveats)) {
                if (!(cv instanceof Map) || !GNAP_ACCESS_CAVEAT.equals(map(cv).get("type"))) continue;
                List<Object> hopPreds = accessArrayToPredicates(readAccessArray(map(cv).get("access")));
                if (!Predicates.evaluatePredicates(hopPreds, ctx)) {
                    String why = Predicates.denialReason(hopPreds, ctx);
                    return obj("allowed", false, "reason", "delegated hop denies: " + (why != null ? why : "no predicate matched"));
                }
            }
        }
        return obj("allowed", true);
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // bound token
    // ---------------------------------------------------------------------------------------------------------------------

    /** Encode a capability chain as a GNAP access-token {@code value}: base64url of the chain's JSON text (re-verified on use). */
    public static String encodeBoundToken(Object chain) { return Keys.b64u(Js.utf8(Js.stringify(chain))); }

    private static boolean strOrAbsent(Map<String, Object> m, String k) { return !m.containsKey(k) || m.get(k) instanceof String; }

    private static boolean isCapabilityShape(Object x) {
        if (!isRecord(x)) return false;
        Map<String, Object> m = map(x);
        return m.get("id") instanceof String && m.get("issuer") instanceof String && m.get("holder") instanceof String && m.get("body_digest") instanceof String
            && m.get("sig") instanceof String && m.get("caveats") instanceof List && strOrAbsent(m, "parent") && strOrAbsent(m, "alg")
            && strOrAbsent(m, "pq_pk") && strOrAbsent(m, "pq_sig");
    }

    /** Total, fail-closed decode of a bound token back into a capability chain (null on any deviation). */
    private static List<Object> decodeBoundToken(String value) {
        try {
            byte[] raw = Keys.unb64u(value);
            // TextDecoder (fatal, BOM not ignored): invalid UTF-8 is an error, a leading BOM is dropped
            CharBuffer cb = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw));
            String text = cb.toString();
            if (text.startsWith("\ufeff")) text = text.substring(1);
            Object parsed = Json.parse(text);
            if (!(parsed instanceof List)) return null;
            List<Object> chain = new ArrayList<>();
            for (Object hop : (List<?>) parsed) {
                if (!isCapabilityShape(hop)) return null;
                chain.add(hop);
            }
            return chain;
        } catch (RuntimeException | CharacterCodingException | StackOverflowError e) {
            return null;
        }
    }

    /**
     * Render a (verified) PCA capability chain as a GNAP grant response with a bound access token. {@code opts}: expiresIn, bearer,
     * instanceId, manageUri, continue.
     */
    public static Map<String, Object> capabilityToGrantResponse(Object chain, Map<String, Object> opts) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) throw new GnapError("capabilityToGrantResponse: empty chain");
        List<Object> ch = list(chain);
        Object leaf = ch.get(ch.size() - 1);
        if (!(leaf instanceof Map)) throw new GnapError("capabilityToGrantResponse: malformed leaf");
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        Map<String, Object> token = obj("value", encodeBoundToken(chain), "access", grantedAccessOf(chain),
            "key", Boolean.TRUE.equals(o.get("bearer")) ? (Object) Boolean.FALSE : (Object) holderJwk((String) map(leaf).get("holder")));
        if (o.containsKey("expiresIn")) token.put("expires_in", o.get("expiresIn"));
        if (o.containsKey("manageUri")) token.put("manage", obj("uri", o.get("manageUri")));
        Map<String, Object> res = obj("access_token", token);
        if (o.containsKey("continue")) res.put("continue", o.get("continue"));
        if (o.containsKey("instanceId")) res.put("instance_id", o.get("instanceId"));
        return res;
    }

    /**
     * Verify an incoming GNAP bound token, mapping it back to a PCA principal and capability. FAILS CLOSED: a token that is not a
     * decodable chain, or whose chain does not verify (optionally against {@code expectedRootIssuer}), returns {@code {ok:false}}.
     */
    public static Map<String, Object> verifyGnapToken(Object value, Map<String, Object> opts) {
        if (!(value instanceof String) || ((String) value).isEmpty()) return obj("ok", false, "reason", "token value is empty");
        List<Object> chain = decodeBoundToken((String) value);
        if (chain == null || chain.isEmpty()) return obj("ok", false, "reason", "token is not a decodable PCA capability chain");
        String vc = chainReason(chain, opts == null ? new LinkedHashMap<>() : opts);
        if (!vc.isEmpty()) return obj("ok", false, "reason", "capability chain invalid: " + vc);
        Map<String, Object> root = map(chain.get(0)), leaf = map(chain.get(chain.size() - 1));
        return obj("ok", true, "principal", root.get("issuer"), "capability", leaf, "chain", chain, "access", grantedAccessOf(chain));
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // jwsd detached JWS
    // ---------------------------------------------------------------------------------------------------------------------

    /** base64url(SHA-256(value)); a value that is not text is encoded as its JavaScript string (TextEncoder: null is "null"). */
    private static String athOf(Object accessTokenValue) { return Keys.b64u(Js.sha256(Js.utf8(Js.str(accessTokenValue)))); }

    /** JSON.parse(JSON.stringify(v)): the plain JSON a value stands for ({@code -0} prints as {@code 0}). */
    private static Object toPlain(Object v) {
        if (v instanceof Json.Num) return ((Json.Num) v).raw.equals("-0") ? new Json.Num("0") : v;
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(toPlain(x)); return out; }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : map(v).entrySet()) out.put(e.getKey(), toPlain(e.getValue()));
            return out;
        }
        return v;
    }

    /**
     * The JWS payload of a jwsd proof (RFC 9635 7.3.3): the SHA-256 digest of the request CONTENT, or nothing when the request has
     * none ({@link #ABSENT}). A String or byte[] is the exact content bytes, hashed with no normalization; any other value is
     * hashed as its strict canonical JSON, which is then the content the sender must transmit byte for byte.
     */
    public static byte[] gnapContentDigest(Object body) {
        if (body == ABSENT) return new byte[0];
        if (body instanceof String) return Js.sha256(Js.utf8((String) body));
        if (body instanceof byte[]) return Js.sha256((byte[]) body);
        return Js.sha256(Js.utf8(Json.canonicalizeStrict(toPlain(body))));
    }

    /**
     * Produce a GNAP {@code jwsd} detached-JWS proof over {@code args.body}, signed by the client key. {@code args}: body, key
     * ({secretKey, publicKey}), htm, uri, created (epoch SECONDS), kid, accessTokenValue. Returns {@code {detachedJws, header, holder}}.
     */
    public static Map<String, Object> signGnapRequest(Map<String, Object> args) {
        Object createdO = args.get("created");
        Object created = createdO != null ? createdO : (Object) new Json.Num(Long.toString(Math.floorDiv(System.currentTimeMillis(), 1000L)));
        Map<String, Object> key = map(args.get("key"));
        Keys.EdKey ed = edKey(key.get("secretKey"));
        Object pubO = key.get("publicKey");
        String holder = Keys.b64u(secretBytes(pubO));
        Map<String, Object> header = obj("alg", "EdDSA", "typ", JWSD_TYP, "htm", ((String) args.get("htm")).toUpperCase(java.util.Locale.ROOT),
            "uri", args.get("uri"), "created", created);
        if (args.containsKey("kid")) header.put("kid", args.get("kid"));
        if (args.containsKey("accessTokenValue")) header.put("ath", athOf(args.get("accessTokenValue")));
        byte[] payload = gnapContentDigest(args.containsKey("body") ? args.get("body") : ABSENT);
        String protectedB64u = Keys.b64u(Js.utf8(Js.stringify(header)));
        byte[] signingInput = (protectedB64u + "." + Keys.b64u(payload)).getBytes(StandardCharsets.US_ASCII);
        String sig = Keys.b64u(ed.sign(signingInput));
        return obj("detachedJws", protectedB64u + ".." + sig, "header", header, "holder", holder);
    }

    private static String canonicalB64uError(String seg) {
        for (int i = 0; i < seg.length(); i++) {
            char c = seg.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return "bad-character";
        }
        if (seg.length() % 4 == 1) return "non-canonical-base64url (impossible length)";
        return Pca.decodeB64uStrict(seg, -1) == null ? "non-canonical-base64url" : null;
    }

    private static final String JWS_PREFIX = "non-canonical compact JWS: ";

    /** The canonical-spelling gate for the protected and signature segments of a detached JWS; the header on success, else the message in {@code err[0]}. */
    private static Map<String, Object> canonicalSegments(String p, String s, String[] err) {
        if (p.length() + s.length() > 64 * 1024) { err[0] = JWS_PREFIX + "too-long"; return null; }
        if (p.isEmpty() || s.isEmpty()) { err[0] = JWS_PREFIX + "empty-segment"; return null; }
        String e = canonicalB64uError(p);
        if (e != null) { err[0] = JWS_PREFIX + e; return null; }
        byte[] bytes = Keys.unb64u(p);
        if (bytes.length >= 3 && (bytes[0] & 0xff) == 0xef && (bytes[1] & 0xff) == 0xbb && (bytes[2] & 0xff) == 0xbf) { err[0] = JWS_PREFIX + "bom"; return null; }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ex) { err[0] = JWS_PREFIX + "bad-utf8"; return null; }
        Object parsed;
        try { parsed = Json.parse(text); } catch (RuntimeException | StackOverflowError ex) { err[0] = JWS_PREFIX + "bad-json"; return null; }
        if (!(parsed instanceof Map)) { err[0] = JWS_PREFIX + "not-an-object"; return null; }
        e = canonicalB64uError(s);
        if (e != null) { err[0] = JWS_PREFIX + e; return null; }
        return map(parsed);
    }

    private static boolean edVerify(String holder, byte[] msg, String sigB64u) {
        try {
            byte[] sig = Pca.decodeB64uStrict(sigB64u, 64);
            byte[] pub = Pca.decodeB64uStrict(holder, 32);
            if (sig == null || pub == null) return false;
            Ed25519Signer v = new Ed25519Signer();
            v.init(false, new Ed25519PublicKeyParameters(pub, 0));
            v.update(msg, 0, msg.length);
            return v.verifySignature(sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** What the JOSE library accepts of the protected header before it checks the signature: a recognized {@code crit} only, an EdDSA alg. */
    private static boolean joseHeaderOk(Map<String, Object> h) {
        if (h.containsKey("crit")) {
            Object crit = h.get("crit");
            if (!(crit instanceof List) || ((List<?>) crit).isEmpty()) return false;
            for (Object c : (List<?>) crit) if (!"b64".equals(c)) return false;
            if (!(h.get("b64") instanceof Boolean)) return false;
        }
        return "EdDSA".equals(h.get("alg"));
    }

    private static Map<String, Object> fail(String reason) { return obj("ok", false, "reason", reason); }

    /**
     * Verify a GNAP {@code jwsd} detached-JWS proof and bind the request to the holder key. FAILS CLOSED on a bad signature, a
     * tampered body, a wrong holder, a mismatched {@code htm}/{@code uri}, a stale or future {@code created}, an {@code ath} that does not
     * bind the named access token, or a replayed proof. {@code args}: detachedJws, body, holder, htm, uri, maxAgeSec, now (epoch ms),
     * accessTokenValue, seenProof ({@link SeenProof}), replayCheck ({@code "unchecked"}). Throws {@link GnapError} when neither a
     * replay store nor the explicit opt-out is given.
     */
    public static Map<String, Object> verifyGnapRequest(Map<String, Object> args) {
        Object seen = args.get("seenProof");
        if (!(seen instanceof SeenProof) && !"unchecked".equals(args.get("replayCheck")))
            throw new GnapError("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'");
        Object dj = args.get("detachedJws");
        if (dj instanceof String && ((String) dj).length() > MAX_DETACHED_JWS_CHARS) return fail("detached JWS exceeds the size limit");
        try {
            if (!(dj instanceof String)) return fail("malformed jwsd request");
            String detached = (String) dj;
            String[] parts = detached.split("\\.", -1);
            if (parts.length != 3) return fail("not a compact JWS (expected three dot-separated parts)");
            String protectedB64u = parts[0], mid = parts[1], signature = parts[2];

            String holder = asEd25519(args.get("holder"));
            if (holder == null) return fail("holder is not a canonical base64url Ed25519 public key");

            String payloadB64u = Keys.b64u(gnapContentDigest(args.containsKey("body") ? args.get("body") : ABSENT));
            if (!mid.isEmpty() && !mid.equals(payloadB64u)) return fail("not a DETACHED compact JWS");

            String[] err = new String[1];
            Map<String, Object> header = canonicalSegments(protectedB64u, signature, err);
            if (header == null) return fail("non-canonical detached JWS: " + err[0]);
            String sigFail = "jwsd signature does not verify under the holder key (or body was tampered)";
            if (!joseHeaderOk(header)) return fail(sigFail);
            if (!edVerify(holder, (protectedB64u + "." + payloadB64u).getBytes(StandardCharsets.US_ASCII), signature)) return fail(sigFail);

            if (!JWSD_TYP.equals(header.get("typ"))) return fail("unexpected typ (not gnap-binding-jwsd)");
            if (!"EdDSA".equals(header.get("alg"))) return fail("unexpected alg (not EdDSA)");

            Object htm = header.get("htm");
            if (!(htm instanceof String) || !((String) htm).toUpperCase(java.util.Locale.ROOT).equals(((String) args.get("htm")).toUpperCase(java.util.Locale.ROOT)))
                return fail("htm does not match the request method");
            Object uri = header.get("uri");
            if (!(uri instanceof String) || !uri.equals(args.get("uri"))) return fail("uri does not match the request target");
            Object createdO = header.get("created");
            Double created = createdO instanceof Json.Num ? Js.num(createdO) : null;
            if (created == null || Double.isNaN(created) || Double.isInfinite(created)) return fail("missing or malformed created");

            Object nowO = args.get("now");
            double nowMs = nowO == null ? (double) System.currentTimeMillis() : Js.num(nowO);
            double nowSec = Math.floor(nowMs / 1000);
            Object maxO = args.get("maxAgeSec");
            double maxAge = maxO == null ? 300 : Js.num(maxO);
            if (!(Double.isFinite(nowSec) && created <= nowSec + 60)) return fail("created is in the future");
            if (!(Double.isFinite(maxAge) && nowSec - created <= maxAge)) return fail("jwsd proof is stale");

            Object ath = header.get("ath");
            if (args.containsKey("accessTokenValue")) {
                if (!(ath instanceof String) || !ath.equals(athOf(args.get("accessTokenValue")))) return fail("ath does not bind the named access token");
            }

            if (seen instanceof SeenProof) {
                boolean replayed;
                try { replayed = !Boolean.FALSE.equals(((SeenProof) seen).seen(athOf(detached), created + maxAge)); } catch (Exception e) { replayed = true; }
                if (replayed) return fail("jwsd proof replayed (or the replay store failed)");
            }

            Map<String, Object> out = obj("alg", "EdDSA", "typ", JWSD_TYP, "htm", htm, "uri", uri, "created", createdO);
            if (header.get("kid") instanceof String) out.put("kid", header.get("kid"));
            if (ath instanceof String) out.put("ath", ath);
            return obj("ok", true, "holder", holder, "header", out);
        } catch (RuntimeException | StackOverflowError e) {
            return fail("malformed jwsd request");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // continuation / step-up
    // ---------------------------------------------------------------------------------------------------------------------

    /**
     * Decide whether a grant request needs a continuation / step-up: it does when GNAP interaction is requested, when an explicit
     * higher tier is asked for, or when the request asks for rights BEYOND the issuer's own authority. {@code opts}: issuerChain, tier.
     * Returns {@code {required, reason, beyond, tier}}.
     */
    public static Map<String, Object> gnapRequestRequiresStepUp(Object req, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        List<Object> beyond = new ArrayList<>();
        if (Js.truthy(o.get("issuerChain"))) {
            List<Object> G = grantedAccessOf(o.get("issuerChain"));
            for (Object r : normalizeAccess(accessOf(req))) if (!accessWithin(G, map(r))) beyond.add(r);
        }
        if (req == null) throw new GnapError("grant request is null");
        boolean interactRequested = false;
        if (Js.has(req, "interact")) {
            Object it = map(req).get("interact");
            if (it == null) throw new GnapError("interact is null");
            Object start = Js.member(it, "start");
            interactRequested = start instanceof List && !((List<?>) start).isEmpty();
        }
        Object tierO = o.get("tier");
        Double tierN = tierO == null ? null : Js.num(tierO);
        boolean required = interactRequested || !beyond.isEmpty() || (tierN != null && tierN > 1);
        Object tier = tierO != null ? tierO : (Object) new Json.Num(beyond.isEmpty() ? "2" : "3");
        String reason = !required ? "no step-up required"
            : !beyond.isEmpty() ? "requested rights exceed the issuer's authority (" + beyond.size() + " right(s) beyond)"
            : interactRequested ? "GNAP interaction requested" : "tier " + Js.str(tier) + " step-up required";
        return obj("required", required, "reason", reason, "beyond", beyond, "tier", tier);
    }

    /**
     * Begin a GNAP continuation: emit the {@code continue} handle and the PCA step-up it resolves through. {@code args}: signerSet, t,
     * tier, continueUri, continueToken, wait, reason. Returns {@code {response, stepUp}}.
     */
    public static Map<String, Object> beginGnapContinuation(Map<String, Object> args) {
        Map<String, Object> cont = obj("uri", args.get("continueUri"), "access_token", obj("value", args.get("continueToken"), "bound", true));
        if (args.containsKey("wait")) cont.put("wait", args.get("wait"));
        Object reason = args.get("reason");
        return obj("response", obj("continue", cont),
            "stepUp", obj("tier", args.get("tier"), "t", args.get("t"), "signerSet", args.get("signerSet"),
                "reason", reason != null ? reason : "tier " + Js.str(args.get("tier")) + " co-signature required to continue", "continueToken", args.get("continueToken")));
    }

    private static int validT(Object t) {
        Double d = Js.num(t);
        if (d == null || (d != 1.0 && d != 2.0 && d != 3.0)) throw new IllegalArgumentException("shareMessage: t must be 1, 2 or 3");
        return (int) (double) d;
    }

    /**
     * One role's step-up co-signature share over the action's PCActn: the co-signature a guardian or principal device returns through
     * the GNAP continuation. It binds the signer set and {@code t} (replay-safe).
     */
    public static Map<String, Object> gnapStepUpShare(Map<String, Object> body, String role, Object secret, Object signerSet, Object t) {
        // the reference hashes a signer set that is not an array as the empty set
        List<Object> set = signerSet instanceof List ? list(signerSet) : new ArrayList<>();
        return SignersMore.signThresholdShare(role, Keys.ed25519(edKey(secret)), Pca.thresholdMessage(body), set, validT(t));
    }

    /**
     * Resolve a continuation: build the action's PCActn (agent leaf signature) and FOLD the step-up co-signatures into its
     * {@code threshold}, then verify the threshold {@code t} is reached. {@code args}: grant, chain, plan, nodeId, params, counter, aud,
     * now, ttlMs, agentLeafSecret, signerSet, t, cosignSecrets ([{role, secret}]). Returns {@code {pcactn, threshold, verdict}}.
     */
    public static Map<String, Object> completeGnapContinuation(Map<String, Object> args) {
        Object chainO = args.get("chain");
        if (!(chainO instanceof List) || ((List<?>) chainO).isEmpty()) throw new GnapError("completeGnapContinuation: empty chain");
        Keys.SuiteKey agent = Keys.ed25519(edKey(args.get("agentLeafSecret")));
        Issue.ActSpec s = new Issue.ActSpec();
        s.grant = map(args.get("grant"));
        s.chain = list(chainO);
        List<Map<String, Object>> nodes = new ArrayList<>();
        for (Object n : list(args.get("plan"))) nodes.add(map(n));
        s.plan = Issue.commitPlan(nodes);
        s.nodeId = (String) args.get("nodeId");
        if (args.containsKey("params")) s.params = map(args.get("params"));
        s.counter = Json.asLong(args.get("counter"));
        s.signer = agent;
        s.aud = (String) args.get("aud");
        if (args.containsKey("now")) s.iat = Json.asLong(args.get("now"));
        if (args.containsKey("ttlMs")) s.ttlMs = Json.asLong(args.get("ttlMs"));
        Map<String, Object> pcactn = Issue.buildPCActn(s);
        byte[] message = Pca.thresholdMessage(pcactn);
        int t = validT(args.get("t"));
        List<Object> signerSet = list(args.get("signerSet"));
        List<Object> shares = new ArrayList<>();
        shares.add(SignersMore.signThresholdShare("agent", agent, message, signerSet, t));
        for (Object cs : list(args.get("cosignSecrets")))
            shares.add(SignersMore.signThresholdShare((String) map(cs).get("role"), Keys.ed25519(edKey(map(cs).get("secret"))), message, signerSet, t));
        Map<String, Object> threshold = obj("shares", shares);
        Map<String, Object> verdict = GnapThreshold.verify(threshold, message, signerSet, t);
        Map<String, Object> withThreshold = new LinkedHashMap<>(pcactn);
        withThreshold.put("threshold", threshold);
        return obj("pcactn", withThreshold, "threshold", threshold, "verdict", verdict);
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // the profile
    // ---------------------------------------------------------------------------------------------------------------------

    /** The machine-readable Agent-GNAP profile spec. */
    public static Map<String, Object> agentGnapProfile() { return GnapProfile.profile(); }
}
