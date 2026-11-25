package net.atlasauth.pca.sdjwt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.jose.Jose;

/**
 * SD-JWT serialization of a PCA {@code PCActn} (IETF SD-JWT, RFC 9901 family): the issuer-signed JWT carries salted-hash digests of
 * the selectively disclosable capability claims, the holder presents a subset and appends a key-binding JWT (typ {@code kb+jwt}).
 * A bridge: the PCActn's own signature (a claim) stays the source of truth ({@link #verifyRecovered} re-verifies it with the core).
 * Port of {@code @atlasauth/pca-sdjwt}. Options are JSON-shaped maps with the reference's member names (a member that is absent differs
 * from one that is JSON null, as in the reference); keys are JWK maps ({@link #importEd25519PrivateKey}, {@link #importEd25519PublicKey}).
 * EdDSA is the only issuance algorithm; verification also accepts ES256 / RS256 / PS256 / ... keys through {@code algorithms}.
 * Verification fails closed: every refusal is {@code {ok:false, reason}}.
 */
public final class Sdjwt {
    private Sdjwt() {}

    public static final String SD_ALG = "sha-256";
    public static final String PCA_SD_JWT_TYP = "pca+sd-jwt";
    public static final String KB_JWT_TYP = "kb+jwt";
    public static final String DEFAULT_SIGNING_ALG = "EdDSA";

    /** The PCActn fields carried as selectively disclosable capability claims by default. */
    public static final List<String> PCA_CAPABILITY_CLAIMS = List.of("action", "grant_ref", "cap_chain", "plan", "attestation", "provenance",
        "freshness", "counter", "risk_claim", "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
        "alg", "pq_pk", "sig", "pq_sig", "threshold", "zk_compliance", "bond_ref");

    private static final Set<String> STANDARD_MAPPED = Set.of("aud", "iat", "exp");
    private static final String CLEAR_DISCRIMINATOR = "ver";
    private static final Set<String> CRITICAL_CLAIMS = Set.of("iss", "aud", "exp", "nbf", "cnf", "status");
    private static final Set<String> RESERVED_CLAIMS = Set.of("iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf");

    // ---- helpers ----

    private static final SecureRandom RANDOM = new SecureRandom();

    /** {@code base64url(SHA-256(ASCII(input)))}: each UTF-16 unit contributes its low byte, as an ASCII write does. */
    private static String sha256b64u(String ascii) {
        byte[] b = new byte[ascii.length()];
        for (int i = 0; i < b.length; i++) b[i] = (byte) ascii.charAt(i);
        return Jose.b64u(Jose.sha256(b));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static boolean isJwk(Object v) { Map<String, Object> m = asMap(v); return m != null && m.get("kty") instanceof String; }

    private static Double num(Object o) { return Jose.num(o); }

    private static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        if (d != null) return d != 0 && !d.isNaN();
        return true;
    }

    /** JavaScript ToNumber of a parsed JSON value (null is 0, a non-numeric string NaN). */
    private static double toNumber(Object v) {
        if (v == null) return 0;
        Double d = num(v);
        if (d != null) return d;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        if (v instanceof String) {
            String t = ((String) v).trim();
            if (t.isEmpty()) return 0;
            try {
                return Double.parseDouble(t);
            } catch (NumberFormatException e) {
                return Double.NaN;
            }
        }
        return Double.NaN;
    }

    private static boolean sameJs(Object a, Object b) {
        if (a == null || b == null) return a == null && b == null;
        if (a instanceof String || b instanceof String) return a.equals(b);
        if (a instanceof Boolean || b instanceof Boolean) return a.equals(b);
        Double x = num(a), y = num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    // ---- Ed25519 raw key <-> JWK ----

    /** A {@code {kty:'OKP', crv:'Ed25519', x}} JWK for a raw 32-byte Ed25519 public key. */
    public static Map<String, Object> ed25519PublicJwk(byte[] raw) {
        if (raw == null || raw.length != 32) throw new IllegalArgumentException("pca-sdjwt: Ed25519 public key must be 32 bytes");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kty", "OKP");
        m.put("crv", "Ed25519");
        m.put("x", Jose.b64u(raw));
        return m;
    }

    /** A private JWK (usable to sign) for a raw 32-byte Ed25519 SEED. */
    public static Map<String, Object> importEd25519PrivateKey(byte[] rawSeed) {
        if (rawSeed == null || rawSeed.length != 32) throw new IllegalArgumentException("pca-sdjwt: Ed25519 private seed must be 32 bytes");
        Map<String, Object> m = ed25519PublicJwk(Keys.edFromSeed(rawSeed).pub);
        m.put("d", Jose.b64u(rawSeed));
        return m;
    }

    /** A public JWK (usable to verify) for a raw 32-byte Ed25519 public key. */
    public static Map<String, Object> importEd25519PublicKey(byte[] raw) {
        if (raw == null || raw.length != 32) throw new IllegalArgumentException("pca-sdjwt: Ed25519 public key must be 32 bytes");
        return ed25519PublicJwk(raw);
    }

    /** The public members of a JWK (a key object imported from a JWK carries no private members or hints). */
    private static Map<String, Object> publicOnly(Map<String, Object> jwk) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : new String[] {"kty", "crv", "x", "y", "n", "e"}) if (jwk.containsKey(k)) out.put(k, jwk.get(k));
        return out;
    }

    // ---- issuance ----

    private static Map<String, Object> leafHolderJwk(Map<String, Object> pcActn) {
        Object chain = pcActn.get("cap_chain");
        Map<String, Object> leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? asMap(((List<?>) chain).get(((List<?>) chain).size() - 1)) : null;
        if (leaf == null || !(leaf.get("holder") instanceof String) || ((String) leaf.get("holder")).isEmpty()) {
            throw new IllegalArgumentException("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing");
        }
        return ed25519PublicJwk(Jose.decodeB64Lenient((String) leaf.get("holder")));
    }

    private static Map<String, Object> resolveCnfJwk(Map<String, Object> pcActn, Map<String, Object> kb) {
        if (!kb.containsKey("holderPublicKey")) return leafHolderJwk(pcActn);
        Object hp = kb.get("holderPublicKey");
        if (hp instanceof byte[]) return ed25519PublicJwk((byte[]) hp);
        if (isJwk(hp)) return asMap(hp);
        throw new IllegalArgumentException("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key");
    }

    private static Object numericDate(Object ms, String label, boolean ceil) {
        Double d = num(ms);
        if (d == null || d.isNaN() || d.isInfinite()) throw new IllegalArgumentException("pca-sdjwt: PCActn." + label + " must be a finite number (epoch ms)");
        double v = d / 1000;
        return ceil ? Math.ceil(v) : Math.floor(v);
    }

    private static Object jsonNum(double v) {
        if (v == Math.rint(v) && Math.abs(v) < 1e21) return new Json.Num(new java.math.BigDecimal(v).toPlainString());
        return v;
    }

    /** {@code JSON.stringify([salt, name, value])} -> {encoded, digest}. */
    private static String[] makeDisclosure(String name, Object value) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        List<Object> triple = new ArrayList<>();
        triple.add(Jose.b64u(salt));
        triple.add(name);
        triple.add(value);
        String encoded = Jose.b64u(Jose.utf8(Jose.stringify(triple)));
        return new String[] {encoded, sha256b64u(encoded)};
    }

    /**
     * Serializes a signed PCActn as an IETF SD-JWT: {@code <issuer JWT>~<Disclosure 1>~...~<Disclosure N>~}. Options: {@code issuerKey}
     * (private JWK, required), {@code disclosable} (claim names; null = all of {@link #PCA_CAPABILITY_CLAIMS}), {@code keyBinding}
     * ({@code {holderPublicKey?}} embeds a {@code cnf} key; absent / null / false = none), {@code iss}, {@code sub}, {@code typ},
     * {@code signingAlg}. No KB-JWT is attached at issuance.
     */
    @SuppressWarnings("unchecked")
    public static String issuePcaSdJwt(Map<String, Object> pcActn, Map<String, Object> options) {
        if (pcActn == null) throw new IllegalArgumentException("pca-sdjwt: pcActn must be an object");
        Object chainO = pcActn.get("cap_chain");
        if (!(chainO instanceof List) || ((List<?>) chainO).isEmpty()) throw new IllegalArgumentException("pca-sdjwt: pcActn.cap_chain must be a non-empty array");
        List<Object> chain = (List<Object>) chainO;
        Map<String, Object> root = asMap(chain.get(0)), leaf = asMap(chain.get(chain.size() - 1));
        if (root == null || !(root.get("issuer") instanceof String)) throw new IllegalArgumentException("pca-sdjwt: cap_chain root issuer is missing");
        if (leaf == null || !(leaf.get("holder") instanceof String)) throw new IllegalArgumentException("pca-sdjwt: cap_chain leaf holder is missing");
        if (!(pcActn.get("aud") instanceof String) || ((String) pcActn.get("aud")).isEmpty()) throw new IllegalArgumentException("pca-sdjwt: pcActn.aud is required");

        Object issO = options.get("iss"), subO = options.get("sub");
        Object iss = issO != null ? issO : root.get("issuer");
        Object sub = subO != null ? subO : leaf.get("holder");
        double iat = (Double) numericDate(pcActn.get("iat"), "iat", false);
        double exp = (Double) numericDate(pcActn.get("exp"), "exp", true);
        if (exp <= iat) exp = iat + 1;

        Set<String> disclosable = new HashSet<>();
        Object dis = options.get("disclosable");
        if (dis == null) disclosable.addAll(PCA_CAPABILITY_CLAIMS);
        else if (dis instanceof List) for (Object x : (List<Object>) dis) { if (x instanceof String) disclosable.add((String) x); }
        else throw new IllegalArgumentException("pca-sdjwt: disclosable must be an array");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss);
        payload.put("sub", sub);
        payload.put("aud", pcActn.get("aud"));
        payload.put("iat", jsonNum(iat));
        payload.put("exp", jsonNum(exp));
        if (pcActn.containsKey(CLEAR_DISCRIMINATOR)) payload.put(CLEAR_DISCRIMINATOR, pcActn.get(CLEAR_DISCRIMINATOR));
        payload.put("iat_ms", pcActn.get("iat"));
        payload.put("exp_ms", pcActn.get("exp"));
        payload.put("_sd_alg", SD_ALG);
        List<String> disclosures = new ArrayList<>();
        List<Object> sd = new ArrayList<>();
        for (Map.Entry<String, Object> e : pcActn.entrySet()) {
            String key = e.getKey();
            if (STANDARD_MAPPED.contains(key) || key.equals(CLEAR_DISCRIMINATOR)) continue;
            if (disclosable.contains(key)) {
                String[] d = makeDisclosure(key, e.getValue());
                disclosures.add(d[0]);
                sd.add(d[1]);
            } else payload.put(key, e.getValue());
        }
        if (!sd.isEmpty()) payload.put("_sd", sd);

        Object kbO = options.get("keyBinding");
        if (truthy(kbO)) {
            Map<String, Object> kb = asMap(kbO) != null ? asMap(kbO) : new LinkedHashMap<>();
            Map<String, Object> cnf = new LinkedHashMap<>();
            cnf.put("jwk", resolveCnfJwk(pcActn, kb));
            payload.put("cnf", cnf);
        }

        Object typO = options.get("typ"), algO = options.get("signingAlg");
        Map<String, Object> header = new LinkedHashMap<>();
        Object alg = algO != null ? algO : DEFAULT_SIGNING_ALG;
        if (!(alg instanceof String)) throw new Jose.JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        header.put("alg", alg);
        header.put("typ", typO != null ? typO : PCA_SD_JWT_TYP);
        String jwt = Jose.signJwt(header, payload, asMap(options.get("issuerKey")));
        StringBuilder sb = new StringBuilder(jwt).append('~');
        for (String d : disclosures) sb.append(d).append('~');
        return sb.toString();
    }

    // ---- parsing ----

    private static final class ParsedSdJwt {
        String jwt;
        List<String> disclosures;
        String kbJwt;
        String presentationHead;
    }

    private static ParsedSdJwt parseSdJwt(Object sdjwtO) {
        if (!(sdjwtO instanceof String) || ((String) sdjwtO).isEmpty()) throw new IllegalArgumentException("pca-sdjwt: empty SD-JWT");
        String sdjwt = (String) sdjwtO;
        String[] segments = sdjwt.split("~", -1);
        if (segments.length < 2) throw new IllegalArgumentException("pca-sdjwt: malformed SD-JWT (missing ~ separator)");
        String jwt = segments[0];
        if (jwt.isEmpty()) throw new IllegalArgumentException("pca-sdjwt: empty issuer JWT");
        String last = segments[segments.length - 1];
        List<String> disclosures = new ArrayList<>(Arrays.asList(segments).subList(1, segments.length - 1));
        for (String s : disclosures) if (s.isEmpty()) throw new IllegalArgumentException("pca-sdjwt: empty disclosure segment");
        Jose.assertCanonicalCompactJws(jwt);
        if (!last.isEmpty()) Jose.assertCanonicalCompactJws(last);
        ParsedSdJwt p = new ParsedSdJwt();
        p.jwt = jwt;
        p.disclosures = disclosures;
        if (last.isEmpty()) {
            p.presentationHead = sdjwt;
        } else {
            p.presentationHead = sdjwt.substring(0, sdjwt.length() - last.length());
            p.kbJwt = last;
        }
        return p;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> decodeDisclosureParts(String encoded) {
        Object parsed;
        try {
            parsed = Jose.decodeCanonicalJsonSegment(encoded);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("pca-sdjwt: disclosure is not canonical base64url strict JSON");
        }
        if (!(parsed instanceof List) || (((List<?>) parsed).size() != 2 && ((List<?>) parsed).size() != 3)) {
            throw new IllegalArgumentException("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair");
        }
        if (!(((List<Object>) parsed).get(0) instanceof String)) throw new IllegalArgumentException("pca-sdjwt: disclosure salt must be a string");
        return (List<Object>) parsed;
    }

    // ---- holder presentation ----

    @SuppressWarnings("unchecked")
    private static void collectDigests(Object node, List<String> out) {
        if (node instanceof List) {
            for (Object x : (List<Object>) node) collectDigests(x, out);
        } else if (node instanceof Map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) node).entrySet()) {
                String k = e.getKey();
                Object v = e.getValue();
                if (k.equals("_sd") && v instanceof List) {
                    for (Object x : (List<Object>) v) if (x instanceof String) out.add((String) x);
                } else if (k.equals("...") && v instanceof String) out.add((String) v);
                else collectDigests(v, out);
            }
        }
    }

    private static void include(String digest, Map<String, String> byDigest, Set<String> kept) {
        String encoded = byDigest.get(digest);
        if (encoded == null || kept.contains(digest)) return;
        kept.add(digest);
        List<Object> parts = decodeDisclosureParts(encoded);
        List<String> nested = new ArrayList<>();
        collectDigests(parts.get(parts.size() - 1), nested);
        for (String d : nested) include(d, byDigest, kept);
    }

    /** The names a {@code new Set(selectClaims)} holds: a list's elements, a string's code points, nothing for null; anything else throws. */
    private static Set<String> keepSet(Object select) {
        Set<String> keep = new HashSet<>();
        if (select == null) return keep;
        if (select instanceof List) {
            for (Object x : (List<?>) select) if (x instanceof String) keep.add((String) x);
            return keep;
        }
        if (select instanceof String) {
            String s = (String) select;
            for (int i = 0; i < s.length(); ) {
                int cp = s.codePointAt(i);
                keep.add(new String(Character.toChars(cp)));
                i += Character.charCount(cp);
            }
            return keep;
        }
        throw new IllegalArgumentException("object is not iterable");
    }

    /**
     * A holder presentation of an issued SD-JWT that discloses ONLY {@code selectClaims} (claim names; a list, or null for none) and drops
     * every other Disclosure; a selected claim is disclosed in full. Any existing KB-JWT is stripped. Options: {@code keyBinding}
     * {@code {holderKey (private JWK), audience, nonce, iat, alg}} appends a fresh KB-JWT over the new presentation.
     */
    @SuppressWarnings("unchecked")
    public static String present(Object sdjwt, Object selectClaims, Map<String, Object> options) {
        ParsedSdJwt parsed = parseSdJwt(sdjwt);
        Set<String> keep = keepSet(selectClaims);
        Map<String, String> byDigest = new LinkedHashMap<>();
        for (String e : parsed.disclosures) byDigest.put(sha256b64u(e), e);
        Set<String> kept = new LinkedHashSet<>();
        Object payload;
        try {
            String[] segs = parsed.jwt.split("\\.", -1);
            payload = Json.parseLenient(new String(Jose.decodeB64Lenient(segs.length > 1 ? segs[1] : ""), StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("pca-sdjwt: issuer JWT payload is not valid base64url JSON");
        }
        Map<String, Object> pm = asMap(payload);
        if (pm != null) {
            Object sdO = pm.get("_sd");
            if (sdO instanceof List) {
                for (Object digest : (List<Object>) sdO) {
                    if (!(digest instanceof String)) continue;
                    String encoded = byDigest.get(digest);
                    if (encoded == null) continue;
                    List<Object> parts = decodeDisclosureParts(encoded);
                    if (parts.get(1) instanceof String && parts.size() == 3 && keep.contains(parts.get(1))) include((String) digest, byDigest, kept);
                }
            }
            for (String key : pm.keySet()) {
                if (!key.equals("_sd") && keep.contains(key)) {
                    List<String> ds = new ArrayList<>();
                    collectDigests(pm.get(key), ds);
                    for (String d : ds) include(d, byDigest, kept);
                }
            }
        }
        StringBuilder head = new StringBuilder(parsed.jwt);
        for (String e : parsed.disclosures) if (kept.contains(sha256b64u(e))) head.append('~').append(e);
        head.append('~');
        Map<String, Object> kb = options == null ? null : asMap(options.get("keyBinding"));
        if (kb == null) return head.toString();

        Object iatO = kb.get("iat");
        Object now = iatO != null ? iatO : jsonNum(Math.floor(System.currentTimeMillis() / 1000.0));
        Map<String, Object> kbPayload = new LinkedHashMap<>();
        kbPayload.put("iat", now);
        if (kb.containsKey("audience")) kbPayload.put("aud", kb.get("audience"));
        kbPayload.put("sd_hash", sha256b64u(head.toString()));
        if (kb.containsKey("nonce")) kbPayload.put("nonce", kb.get("nonce"));
        Object algO = kb.get("alg");
        Object alg = algO != null ? algO : DEFAULT_SIGNING_ALG;
        if (!(alg instanceof String)) throw new Jose.JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        Map<String, Object> kbHeader = new LinkedHashMap<>();
        kbHeader.put("alg", alg);
        kbHeader.put("typ", KB_JWT_TYP);
        String kbJwt = Jose.signJwt(kbHeader, kbPayload, asMap(kb.get("holderKey")));
        return head + kbJwt;
    }

    // ---- verification ----

    private static final class SdJwtProcessingError extends RuntimeException {
        SdJwtProcessingError(String m) { super(m); }
    }

    private static final class DecodedDisclosure {
        final List<Object> parts;
        boolean used;
        DecodedDisclosure(List<Object> parts) { this.parts = parts; }
    }

    private static final class Processed {
        Map<String, Object> processed;
        Map<String, Object> disclosedTop;
    }

    /** RFC 9901 s7.1 payload processing (resolve {@code _sd} digests and {@code {"...": digest}} array elements). */
    private static Processed processDisclosures(Map<String, Object> payload, Map<String, DecodedDisclosure> byDigest) {
        Set<String> seen = new HashSet<>();
        Map<String, Object> disclosedTop = new LinkedHashMap<>();
        Object processed = walk(payload, true, byDigest, seen, disclosedTop);
        if (!(processed instanceof Map)) throw new SdJwtProcessingError("payload is not an object");
        Map<String, Object> p = asMap(processed);
        p.remove("_sd_alg");
        for (DecodedDisclosure d : byDigest.values()) {
            if (!d.used) throw new SdJwtProcessingError("a presented disclosure is not referenced by any digest in the payload");
        }
        Processed r = new Processed();
        r.processed = p;
        r.disclosedTop = disclosedTop;
        return r;
    }

    private static DecodedDisclosure claimDigest(String d, Map<String, DecodedDisclosure> byDigest, Set<String> seen) {
        if (seen.contains(d)) throw new SdJwtProcessingError("a digest appears more than once in the payload");
        seen.add(d);
        return byDigest.get(d);
    }

    @SuppressWarnings("unchecked")
    private static Object walk(Object node, boolean top, Map<String, DecodedDisclosure> byDigest, Set<String> seen, Map<String, Object> disclosedTop) {
        if (node instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object el : (List<Object>) node) {
                Map<String, Object> em = asMap(el);
                if (em != null && em.size() == 1 && em.containsKey("...")) {
                    Object digest = em.get("...");
                    if (!(digest instanceof String)) throw new SdJwtProcessingError("an array '...' entry must reference a string digest");
                    DecodedDisclosure d = claimDigest((String) digest, byDigest, seen);
                    if (d == null) continue;
                    if (d.parts.size() != 2) throw new SdJwtProcessingError("an array-element disclosure must be [salt, value]");
                    d.used = true;
                    out.add(walk(d.parts.get(1), false, byDigest, seen, disclosedTop));
                } else out.add(walk(el, false, byDigest, seen, disclosedTop));
            }
            return out;
        }
        if (node instanceof Map) {
            Map<String, Object> nm = (Map<String, Object>) node;
            Map<String, Object> out = new LinkedHashMap<>();
            for (String key : nm.keySet()) {
                if (key.equals("_sd")) continue;
                out.put(key, walk(nm.get(key), false, byDigest, seen, disclosedTop));
            }
            if (nm.containsKey("_sd")) {
                Object sd = nm.get("_sd");
                if (!(sd instanceof List)) throw new SdJwtProcessingError("_sd must be an array of strings");
                for (Object x : (List<Object>) sd) if (!(x instanceof String)) throw new SdJwtProcessingError("_sd must be an array of strings");
                for (Object digest : (List<Object>) sd) {
                    DecodedDisclosure d = claimDigest((String) digest, byDigest, seen);
                    if (d == null) continue;
                    if (d.parts.size() != 3) throw new SdJwtProcessingError("an object-property disclosure must be [salt, name, value]");
                    Object name = d.parts.get(1);
                    if (!(name instanceof String)) throw new SdJwtProcessingError("disclosure claim name must be a string");
                    String n = (String) name;
                    if (n.equals("_sd") || n.equals("...")) throw new SdJwtProcessingError("disclosure claim name '" + n + "' is reserved");
                    if (out.containsKey(n)) throw new SdJwtProcessingError("disclosure claim '" + n + "' collides with an existing claim");
                    if (top && CRITICAL_CLAIMS.contains(n)) throw new SdJwtProcessingError("'" + n + "' is security-critical and must not be selectively disclosable");
                    d.used = true;
                    Object value = walk(d.parts.get(2), false, byDigest, seen, disclosedTop);
                    out.put(n, value);
                    if (top) disclosedTop.put(n, value);
                }
            }
            return out;
        }
        return node;
    }

    private static Map<String, Object> failResult(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    private static final Pattern SECS = Pattern.compile("^(\\+|\\-)? ?(\\d+|\\d+\\.\\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$", Pattern.CASE_INSENSITIVE);

    /** The reference library's time-period parser (a clock tolerance given as text, e.g. "10 seconds"). */
    private static double secs(String str) {
        Matcher m = SECS.matcher(str);
        if (!m.matches() || (m.group(4) != null && m.group(1) != null)) throw new Jose.JoseException("Invalid time period format");
        double value = Double.parseDouble(m.group(2));
        double n;
        switch (m.group(3).toLowerCase(Locale.ROOT)) {
            case "sec": case "secs": case "second": case "seconds": case "s": n = Math.round(value); break;
            case "minute": case "minutes": case "min": case "mins": case "m": n = Math.round(value * 60); break;
            case "hour": case "hours": case "hr": case "hrs": case "h": n = Math.round(value * 3600); break;
            case "day": case "days": case "d": n = Math.round(value * 86400); break;
            case "week": case "weeks": case "w": n = Math.round(value * 604800); break;
            default: n = Math.round(value * 31557600); break;
        }
        return "-".equals(m.group(1)) || "ago".equals(m.group(4)) ? -n : n;
    }

    /** The JWT options of an issuer or KB verification (presentOnly: whether an audience option was given at all, then its value). */
    @SuppressWarnings("unchecked")
    private static Jose.JwtOptions jwtOptions(Map<String, Object> options, boolean hasAud, Object audValue, List<String> algs) {
        Jose.JwtOptions jo = new Jose.JwtOptions();
        jo.algorithms = algs;
        if (hasAud) {
            if (audValue instanceof String) jo.audience = List.of((String) audValue);
            else if (audValue instanceof List) {
                List<String> l = new ArrayList<>();
                for (Object x : (List<Object>) audValue) l.add(x instanceof String ? (String) x : "\u0000not-a-string");
                jo.audience = l;
            } else if (!truthy(audValue)) jo.audience = List.of(""); // presence is required, the value is not compared
            else jo.audience = List.of("\u0000never");               // a truthy non-string, non-list option never matches
        }
        if (options.containsKey("now")) {
            Object nw = options.get("now");
            Double d = nw == null ? Double.valueOf(0) : num(nw);
            jo.currentDateMs = d == null ? Double.NaN : d;
        }
        if (options.containsKey("clockToleranceSec")) {
            Object t = options.get("clockToleranceSec");
            if (t instanceof String) jo.clockTolerance = secs((String) t);
            else if (num(t) != null) jo.clockTolerance = num(t);
            else throw new Jose.JoseException("Invalid clockTolerance option type");
        }
        return jo;
    }

    @SuppressWarnings("unchecked")
    private static List<String> algorithmList(Object v, String dflt) {
        if (v == null) return List.of(dflt);
        if (!(v instanceof List)) throw new Jose.JoseException("\"algorithms\" option must be an array of strings");
        List<String> out = new ArrayList<>();
        for (Object x : (List<Object>) v) {
            if (!(x instanceof String)) throw new Jose.JoseException("\"algorithms\" option must be an array of strings");
            out.add((String) x);
        }
        return out;
    }

    private static String thumbX(Object k) {
        if (k instanceof byte[]) return Jose.b64u((byte[]) k);
        if (isJwk(k)) return asMap(k).get("x") instanceof String ? (String) asMap(k).get("x") : null;
        throw new Jose.JoseException("Invalid key input");
    }

    /**
     * Verifies a PCA SD-JWT, FAIL-CLOSED. Options: {@code issuerKey} (public JWK, required), {@code requiredDisclosures},
     * {@code expectedAudience}, {@code keyBindingKey} (JWK map or raw bytes; requires a KB-JWT bound to it), {@code expectedKbAudience},
     * {@code expectedNonce}, {@code requireKeyBinding}, {@code algorithms} (default EdDSA), {@code kbAlgorithms}, {@code now} (ms),
     * {@code kbMaxAgeSec}, {@code clockToleranceSec}. Returns {@code {ok:true, payload, processed, protectedHeader, disclosed, claims,
     * keyBinding}} or {@code {ok:false, reason}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyPcaSdJwt(Object sdjwt, Map<String, Object> options) {
        try {
            // a non-finite clock, tolerance or window would slip past the date checks
            for (String k : new String[] {"now", "clockToleranceSec", "kbMaxAgeSec"}) {
                Double nv = options.containsKey(k) ? num(options.get(k)) : null;
                // Number.isFinite: a present value that is not a finite number (a string, null, NaN, an infinity) is refused
                if (options.containsKey(k) && (nv == null || nv.isNaN() || nv.isInfinite())) return failResult("now, clockToleranceSec and kbMaxAgeSec must be finite");
            }
            // a time beyond +-8.64e15 ms is an invalid Date, which the JOSE layer reads as no clock at all: refused like a non-finite one
            if (options.containsKey("now") && num(options.get("now")) != null && !(Math.abs(num(options.get("now"))) <= 8.64e15)) return failResult("now is not a representable time");
            ParsedSdJwt parsed = parseSdJwt(sdjwt);
            List<String> algorithms = algorithmList(options.get("algorithms"), DEFAULT_SIGNING_ALG);
            Map<String, Object> issuerKey = asMap(options.get("issuerKey"));
            if (issuerKey == null) throw new Jose.JoseException("Invalid key input");

            Jose.VerifiedJwt verified = Jose.jwtVerify(parsed.jwt, publicOnly(issuerKey), jwtOptions(options, options.containsKey("expectedAudience"), options.get("expectedAudience"), algorithms));
            Map<String, Object> payload = verified.payload;
            Map<String, Object> protectedHeader = verified.protectedHeader;

            if (payload.containsKey("_sd_alg") && !SD_ALG.equals(payload.get("_sd_alg"))) return failResult("unsupported _sd_alg (require \"" + SD_ALG + "\")");
            Map<String, DecodedDisclosure> byDigest = new LinkedHashMap<>();
            for (String encoded : parsed.disclosures) {
                String digest = sha256b64u(encoded);
                if (byDigest.containsKey(digest)) return failResult("duplicate disclosure");
                byDigest.put(digest, new DecodedDisclosure(decodeDisclosureParts(encoded)));
            }
            Map<String, Object> processedPayload, disclosed;
            try {
                Processed r = processDisclosures(payload, byDigest);
                processedPayload = r.processed;
                disclosed = r.disclosedTop;
            } catch (SdJwtProcessingError e) {
                boolean unmatched = e.getMessage().contains("not referenced");
                return failResult(unmatched ? "a presented disclosure does not match any _sd digest (tampered)" : e.getMessage());
            }

            Object req = options.get("requiredDisclosures");
            if (req != null) {
                List<Object> names = new ArrayList<>();
                if (req instanceof List) names.addAll((List<Object>) req);
                else if (req instanceof String) { for (char c : ((String) req).toCharArray()) names.add(String.valueOf(c)); }
                else throw new IllegalArgumentException("requiredDisclosures is not iterable");
                for (Object required : names) {
                    String key = required instanceof String ? (String) required : required == null ? "null" : Json.canonicalize(required);
                    if (!disclosed.containsKey(key)) return failResult("required disclosure '" + key + "' was not presented");
                }
            }

            Map<String, Object> cnf = asMap(payload.get("cnf"));
            Map<String, Object> cnfJwk = cnf != null && isJwk(cnf.get("jwk")) ? asMap(cnf.get("jwk")) : null;
            Map<String, Object> keyBinding = new LinkedHashMap<>();
            keyBinding.put("presented", parsed.kbJwt != null);
            keyBinding.put("verified", false);

            if (parsed.kbJwt != null) {
                if (cnfJwk == null) return failResult("KB-JWT presented but issuer JWT has no cnf key");
                if (options.containsKey("keyBindingKey")) {
                    String want = thumbX(options.get("keyBindingKey")), have = thumbX(cnfJwk);
                    if (want == null || have == null || !want.equals(have)) return failResult("cnf key does not match the expected keyBindingKey");
                }
                Object kbAlgsO = options.get("kbAlgorithms");
                if ("oct".equals(cnfJwk.get("kty"))) return failResult("KB-JWT signature/claims invalid: Key for the EdDSA algorithm must be one of type KeyObject, CryptoKey, or JSON Web Key.");
                Map<String, Object> kbKey = publicOnly(cnfJwk);
                Jose.VerifiedJwt kb;
                try {
                    Object kbAud = options.get("expectedKbAudience");
                    Object aud = kbAud != null ? kbAud : options.get("expectedAudience");
                    boolean hasAud = kbAud != null || options.containsKey("expectedAudience");
                    kb = Jose.jwtVerify(parsed.kbJwt, kbKey, jwtOptions(options, hasAud, aud, algorithmList(kbAlgsO, DEFAULT_SIGNING_ALG)));
                } catch (RuntimeException e) {
                    return failResult("KB-JWT signature/claims invalid: " + e.getMessage());
                }
                if (!KB_JWT_TYP.equals(kb.protectedHeader.get("typ"))) return failResult("KB-JWT typ must be \"" + KB_JWT_TYP + "\"");
                Double kbIat = num(kb.payload.get("iat"));
                if (kbIat == null) return failResult("KB-JWT iat is required");
                if (options.containsKey("kbMaxAgeSec")) {
                    Object nw = options.get("now");
                    double nowMs = nw != null ? toNumber(nw) : System.currentTimeMillis();
                    double nowSec = Math.floor(nowMs / 1000);
                    if (Double.isNaN(kbIat) || Double.isInfinite(kbIat)) return failResult("KB-JWT iat is not a finite number");
                    if (!(nowSec - kbIat <= toNumber(options.get("kbMaxAgeSec")))) return failResult("KB-JWT is older than the accepted window");
                    Object tol = options.get("clockToleranceSec");
                    if (!(kbIat - nowSec <= (tol != null ? toNumber(tol) : 0))) return failResult("KB-JWT iat is in the future");
                }
                Object kbAudClaim = kb.payload.get("aud");
                if (!(kbAudClaim instanceof String) && !(kbAudClaim instanceof List)) return failResult("KB-JWT aud is required");
                if (!sha256b64u(parsed.presentationHead).equals(kb.payload.get("sd_hash"))) return failResult("KB-JWT sd_hash does not cover this presentation");
                if (options.containsKey("expectedNonce")) {
                    Object want = options.get("expectedNonce");
                    boolean has = kb.payload.containsKey("nonce");
                    boolean same = has && sameJs(kb.payload.get("nonce"), want);
                    if (!same) return failResult("KB-JWT nonce does not match");
                }
                keyBinding.put("verified", true);
                if (kbAudClaim instanceof String) keyBinding.put("aud", kbAudClaim);
                if (kb.payload.get("nonce") instanceof String) keyBinding.put("nonce", kb.payload.get("nonce"));
            } else if (options.containsKey("keyBindingKey") || truthy(options.get("requireKeyBinding"))) {
                return failResult("key binding required but no KB-JWT was presented");
            }

            Map<String, Object> claims = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : processedPayload.entrySet()) if (!RESERVED_CLAIMS.contains(e.getKey())) claims.put(e.getKey(), e.getValue());

            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("payload", payload);
            ok.put("processed", processedPayload);
            ok.put("protectedHeader", protectedHeader);
            ok.put("disclosed", disclosed);
            ok.put("claims", claims);
            ok.put("keyBinding", keyBinding);
            return ok;
        } catch (RuntimeException e) {
            return failResult(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    // ---- recovery through the core ----

    /** The outcome of {@link #verifyRecovered}: {@code allow}, the reason of the first failed check (or this package's own), the core checks. */
    public static final class RecoveredResult {
        public final boolean allow;
        public final String reason;
        public final Map<String, Boolean> checks;
        RecoveredResult(boolean allow, String reason, Map<String, Boolean> checks) { this.allow = allow; this.reason = reason; this.checks = checks; }
    }

    private static RecoveredResult deny(String reason) { return new RecoveredResult(false, reason, new LinkedHashMap<>()); }

    /**
     * Re-verifies a verified SD-JWT with the PCA core: rebuilds the PCActn from the recovered claims and runs the core verification.
     * FAIL-CLOSED: a withheld required claim, missing or inconsistent {@code iat_ms}/{@code exp_ms}, or an {@code iss}/{@code sub} that
     * disagrees with the chain denies. {@code grant} is the verifier's OWN stored grant; {@code audience} its audience id (null: not given, the core then denies); {@code nowMs} null = now; {@code insecureSkipPlanRootCheck} the loud opt-out of the plan-root check.
     */
    public static RecoveredResult verifyRecovered(Map<String, Object> res, Map<String, Object> grant, String audience, Long nowMs, boolean insecureSkipPlanRootCheck) {
        return verifyRecovered(res, grant, audience != null, audience, nowMs, insecureSkipPlanRootCheck);
    }

    /**
     * As above with the audience tri-state of the core: {@code audienceGiven} with a string must equal the PCActn's {@code aud};
     * {@code audienceGiven} with null is the explicit opt-out ("accept any audience"); not given fails closed.
     */
    @SuppressWarnings("unchecked")
    public static RecoveredResult verifyRecovered(Map<String, Object> res, Map<String, Object> grant, boolean audienceGiven, String audience, Long nowMs, boolean insecureSkipPlanRootCheck) {
        Map<String, Object> c = asMap(res.get("claims")), p = asMap(res.get("processed"));
        Map<String, Object> rest = new LinkedHashMap<>(c);
        Object iatMs = rest.remove("iat_ms"), expMs = rest.remove("exp_ms");
        Double iatD = num(iatMs), expD = num(expMs);
        if (iatD == null || expD == null) return deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn");
        Double pIat = num(p.get("iat")), pExp = num(p.get("exp"));
        if (pIat == null || Math.floor(iatD / 1000) != pIat) return deny("pca-sdjwt: iat_ms disagrees with iat");
        if (pExp == null || Math.max(Math.ceil(expD / 1000), Math.floor(iatD / 1000) + 1) != pExp) return deny("pca-sdjwt: exp_ms disagrees with exp");
        for (String k : new String[] {"action", "cap_chain", "plan", "sig", "grant_ref", "counter"}) {
            if (!rest.containsKey(k)) return deny("pca-sdjwt: required claim '" + k + "' was not disclosed");
        }
        if (!(p.get("aud") instanceof String)) return deny("pca-sdjwt: aud must be a string");
        Object chain = rest.get("cap_chain");
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return deny("pca-sdjwt: cap_chain is empty");
        List<Object> cl = (List<Object>) chain;
        Object first = cl.get(0), last = cl.get(cl.size() - 1);
        if (first == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'issuer')");
        Object issuer = asMap(first) == null ? null : asMap(first).get("issuer");
        if (!sameJs(p.get("iss"), issuer)) return deny("pca-sdjwt: iss does not match the chain root issuer");
        if (last == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'holder')");
        Object holder = asMap(last) == null ? null : asMap(last).get("holder");
        if (!sameJs(p.get("sub"), holder)) return deny("pca-sdjwt: sub does not match the chain leaf holder");
        Map<String, Object> pcActn = new LinkedHashMap<>(rest);
        if (p.containsKey("ver")) pcActn.put("ver", p.get("ver")); else pcActn.remove("ver");
        pcActn.put("aud", p.get("aud"));
        pcActn.put("iat", iatMs);
        pcActn.put("exp", expMs);
        try {
            net.atlasauth.pca.PcaCore.Options co = new net.atlasauth.pca.PcaCore.Options(grant);
            if (audienceGiven) { if (audience == null) co.audienceAny(); else co.audience(audience); }
            co.nowEpoch = nowMs != null ? nowMs : System.currentTimeMillis();
            co.planRoots = insecureSkipPlanRootCheck ? Pca.PlanRoots.SKIP : Pca.PlanRoots.NONE;
            net.atlasauth.pca.PcaCore.Result v = net.atlasauth.pca.PcaCore.verify(pcActn, co);
            Map<String, Boolean> checks = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : v.checks.entrySet()) checks.put(e.getKey(), !net.atlasauth.pca.PcaCore.FAIL.equals(e.getValue()));
            return new RecoveredResult(v.allow, v.reason, checks);
        } catch (RuntimeException e) {
            return deny("pca-sdjwt: core verification threw: " + e.getMessage());
        }
    }
}
