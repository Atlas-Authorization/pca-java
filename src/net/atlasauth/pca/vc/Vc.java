package net.atlasauth.pca.vc;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.dpop.Dpop;
import net.atlasauth.pca.jose.Jose;

/**
 * Emits the PCA agent passport in the converging verifiable-identity formats: a W3C Verifiable Credential 2.0 secured as an SD-JWT VC
 * (EdDSA), {@code did:key} identifiers (Ed25519, multicodec 0xed01 + base58btc), and RFC 9421 HTTP Message Signatures with the Web Bot
 * Auth {@code Signature-Agent} pattern. A bridge, not a replacement: the passport stays the source of truth. Port of
 * {@code @atlasauth/pca-vc}. Options and results are JSON-shaped maps with the reference's member names; keys are raw Ed25519 bytes
 * (a 32-byte seed to sign, a 32-byte public key to verify) or JWK maps. {@code now} (epoch milliseconds) is the clock hook of the
 * operations that read time.
 */
public final class Vc {
    private Vc() {}

    public static final String VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    public static final String AGENT_PASSPORT_CONTEXT = "https://atlasauth.net/credentials/agent-passport/v1";
    public static final String AGENT_PASSPORT_VC_TYPE = "AgentPassportCredential";

    private static final List<String> SD_DIGEST_FIELDS = List.of("weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement");
    private static final SecureRandom RANDOM = new SecureRandom();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Double num(Object o) { return Jose.num(o); }

    private static String sha256b64u(String ascii) {
        byte[] b = new byte[ascii.length()];
        for (int i = 0; i < b.length; i++) b[i] = (byte) ascii.charAt(i);
        return Jose.b64u(Jose.sha256(b));
    }

    private static String asString(Object v, String label) {
        if (!(v instanceof String)) throw new IllegalArgumentException("pca-vc: expected string for " + label);
        return (String) v;
    }

    // ---- base58btc / did:key ----

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int MAX_BASE58_INPUT = 1024;

    /** Base58 (Bitcoin alphabet) encoding, as multibase {@code z}. */
    public static String base58btcEncode(byte[] bytes) {
        int zeros = 0;
        while (zeros < bytes.length && bytes[zeros] == 0) zeros++;
        List<Integer> digits = new ArrayList<>();
        for (int i = zeros; i < bytes.length; i++) {
            int carry = bytes[i] & 0xff;
            for (int j = 0; j < digits.size(); j++) {
                carry += digits.get(j) << 8;
                digits.set(j, carry % 58);
                carry = carry / 58;
            }
            while (carry > 0) {
                digits.add(carry % 58);
                carry = carry / 58;
            }
        }
        StringBuilder out = new StringBuilder("1".repeat(zeros));
        for (int i = digits.size() - 1; i >= 0; i--) out.append(B58.charAt(digits.get(i)));
        return out.toString();
    }

    /** Inverse of {@link #base58btcEncode}; throws on a character outside the alphabet or an input over 1024 characters. */
    public static byte[] base58btcDecode(String str) {
        if (str.length() > MAX_BASE58_INPUT) throw new IllegalArgumentException("pca-vc: base58btc input too long");
        int zeros = 0;
        while (zeros < str.length() && str.charAt(zeros) == '1') zeros++;
        List<Integer> bytes = new ArrayList<>();
        for (int i = zeros; i < str.length(); i++) {
            int carry = B58.indexOf(str.charAt(i));
            if (carry < 0) throw new IllegalArgumentException("pca-vc: invalid base58btc character");
            for (int j = 0; j < bytes.size(); j++) {
                carry += bytes.get(j) * 58;
                bytes.set(j, carry & 0xff);
                carry >>= 8;
            }
            while (carry > 0) {
                bytes.add(carry & 0xff);
                carry >>= 8;
            }
        }
        byte[] out = new byte[zeros + bytes.size()];
        for (int i = 0; i < bytes.size(); i++) out[zeros + bytes.size() - 1 - i] = (byte) (int) bytes.get(i);
        return out;
    }

    /** A {@code did:key} identifier for an Ed25519 public key (32 raw bytes). */
    public static String didKeyFromEd25519(byte[] publicKey) {
        if (publicKey.length != 32) throw new IllegalArgumentException("pca-vc: Ed25519 public key must be 32 bytes");
        byte[] mc = new byte[34];
        mc[0] = (byte) 0xed;
        mc[1] = 0x01;
        System.arraycopy(publicKey, 0, mc, 2, 32);
        return "did:key:z" + base58btcEncode(mc);
    }

    /** The 32-byte Ed25519 public key of an Ed25519 {@code did:key}. Inverse of {@link #didKeyFromEd25519}. */
    public static byte[] ed25519FromDidKey(String did) {
        String prefix = "did:key:z";
        if (!did.startsWith(prefix)) throw new IllegalArgumentException("pca-vc: not a did:key:z… identifier");
        if (did.length() > prefix.length() + 64) throw new IllegalArgumentException("pca-vc: did:key is not an Ed25519 (0xed01) key");
        byte[] mc = base58btcDecode(did.substring(prefix.length()));
        if (mc.length != 34 || (mc[0] & 0xff) != 0xed || mc[1] != 0x01) throw new IllegalArgumentException("pca-vc: did:key is not an Ed25519 (0xed01) key");
        return java.util.Arrays.copyOfRange(mc, 2, 34);
    }

    // ---- bundled JSON-LD context ----

    private static final String V = "https://atlasauth.net/credentials/agent-passport/v1#";
    private static final String XSD = "http://www.w3.org/2001/XMLSchema#";

    private static Map<String, Object> term(String id, String type) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("@id", V + id);
        m.put("@type", XSD + type);
        return m;
    }

    /** The JSON-LD context for AgentPassportCredential, bundled so a verifier resolves it offline. Terms are protected. */
    public static final Map<String, Object> AGENT_PASSPORT_CONTEXT_DOC;
    static {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("@protected", true);
        inner.put("id", "@id");
        inner.put("type", "@type");
        inner.put("passport_id", term("passportId", "string"));
        inner.put("model_id", term("modelId", "string"));
        inner.put("operator", term("operator", "string"));
        inner.put("hardware_rooted", term("hardwareRooted", "boolean"));
        inner.put("weights_measured", term("weightsMeasured", "boolean"));
        inner.put("issued_at", term("issuedAt", "integer"));
        inner.put("weights_digest", term("weightsDigest", "string"));
        inner.put("system_prompt_digest", term("systemPromptDigest", "string"));
        inner.put("tool_manifest_digest", term("toolManifestDigest", "string"));
        inner.put("runtime_measurement", term("runtimeMeasurement", "string"));
        Map<String, Object> sd = new LinkedHashMap<>();
        sd.put("@id", V + "selectiveDisclosureDigest");
        sd.put("@container", "@set");
        inner.put("_sd", sd);
        Map<String, Object> cred = new LinkedHashMap<>();
        cred.put("@id", V + "AgentPassportCredential");
        cred.put("@context", inner);
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("@protected", true);
        ctx.put("AgentPassportCredential", cred);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", ctx);
        AGENT_PASSPORT_CONTEXT_DOC = java.util.Collections.unmodifiableMap(doc);
    }

    /** SHA-256 (hex) of the key-sorted JSON of {@link #AGENT_PASSPORT_CONTEXT_DOC}; changes whenever any term changes. */
    public static final String AGENT_PASSPORT_CONTEXT_DIGEST;
    static {
        StringBuilder hex = new StringBuilder();
        for (byte b : Jose.sha256(Jose.utf8(Json.canonicalize(AGENT_PASSPORT_CONTEXT_DOC)))) hex.append(String.format("%02x", b & 0xff));
        AGENT_PASSPORT_CONTEXT_DIGEST = hex.toString();
    }

    /** A document loader for JSON-LD processors: the bundled document for its IRI, null for anything else (never fetched). */
    public static Map<String, Object> resolveAgentPassportContext(Object iri) { return AGENT_PASSPORT_CONTEXT.equals(iri) ? AGENT_PASSPORT_CONTEXT_DOC : null; }

    // ---- key plumbing ----

    private static Map<String, Object> ed25519Jwk(byte[] raw, byte[] seed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kty", "OKP");
        m.put("crv", "Ed25519");
        m.put("x", Jose.b64u(raw));
        if (seed != null) m.put("d", Jose.b64u(seed));
        return m;
    }

    /** A signing key: a 32-byte seed or a private JWK map. */
    private static Map<String, Object> privateKey(Object key) {
        if (key instanceof byte[]) {
            byte[] seed = (byte[]) key;
            if (seed.length != 32) throw new IllegalArgumentException("pca-vc: Ed25519 seed must be 32 bytes");
            return ed25519Jwk(Keys.edFromSeed(seed).pub, seed);
        }
        Map<String, Object> m = asMap(key);
        if (m == null) throw new IllegalArgumentException("pca-vc: not a signing key");
        return m;
    }

    /** A verification key: a 32-byte public key or a public JWK map. */
    private static Map<String, Object> publicKey(Object key) {
        if (key instanceof byte[]) {
            if (((byte[]) key).length != 32) throw new IllegalArgumentException("pca-vc: Ed25519 public key must be 32 bytes");
            return ed25519Jwk((byte[]) key, null);
        }
        Map<String, Object> m = asMap(key);
        if (m == null) throw new IllegalArgumentException("pca-vc: not a verification key");
        return m;
    }

    // ---- W3C VC 2.0 as an SD-JWT VC ----

    /**
     * Emits an AgentPassport (a map) as a W3C VC 2.0 secured as an SD-JWT VC (EdDSA): {@code <jwt>~<disclosure>~...~}. The credential subject
     * carries a salted hash of each present passport digest in {@code _sd}; the model id, operator, hardware flag and passport id stay in the
     * clear. Options: {@code issuerKey} (32-byte seed or private JWK), {@code issuerDid}, {@code subjectDid}, {@code ttlSec} (null counts as 0),
     * {@code now} (ms).
     */
    public static String passportToVC(Map<String, Object> passport, Map<String, Object> args) {
        if (passport == null) throw new IllegalArgumentException("Cannot read properties of null");
        List<String> disclosures = new ArrayList<>();
        List<Object> sd = new ArrayList<>();
        for (String field : SD_DIGEST_FIELDS) {
            if (!passport.containsKey(field)) continue;
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            List<Object> triple = new ArrayList<>();
            triple.add(Jose.b64u(salt));
            triple.add(field);
            triple.add(passport.get(field));
            String disclosure = Jose.b64u(Jose.utf8(Jose.stringify(triple)));
            disclosures.add(disclosure);
            sd.add(sha256b64u(disclosure));
        }
        Map<String, Object> cs = new LinkedHashMap<>();
        if (args.containsKey("subjectDid")) cs.put("id", args.get("subjectDid"));
        for (String k : new String[] {"id", "model_id", "operator", "hardware_rooted", "issued_at"}) {
            String name = k.equals("id") ? "passport_id" : k;
            if (passport.containsKey(k)) cs.put(name, passport.get(k));
        }
        if (passport.containsKey("weights_measured")) cs.put("weights_measured", passport.get("weights_measured"));
        if (!sd.isEmpty()) cs.put("_sd", sd);

        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("@context", List.of(VC_CONTEXT, AGENT_PASSPORT_CONTEXT));
        vc.put("type", List.of("VerifiableCredential", AGENT_PASSPORT_VC_TYPE));
        vc.put("credentialSubject", cs);

        Object nowO = args.get("now");
        double nowMs = nowO != null ? num(nowO) : System.currentTimeMillis();
        double now = Math.floor(nowMs / 1000);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vc", vc);
        if (!sd.isEmpty()) payload.put("_sd_alg", "sha-256");
        if (args.containsKey("issuerDid")) payload.put("iss", args.get("issuerDid"));
        if (args.containsKey("subjectDid")) payload.put("sub", args.get("subjectDid"));
        payload.put("iat", intNum(now));
        if (args.containsKey("ttlSec")) {
            Object t = args.get("ttlSec");
            double ttl;
            if (t == null) ttl = 0;
            else if (t instanceof Boolean) ttl = (Boolean) t ? 1 : 0;
            else if (num(t) != null) ttl = num(t);
            else throw new Jose.JoseException("Invalid time period format");
            payload.put("exp", intNum(now + ttl));
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "vc+sd-jwt");
        String jwt = Jose.signJwt(header, payload, privateKey(args.get("issuerKey")));
        StringBuilder sb = new StringBuilder(jwt).append('~');
        for (String d : disclosures) sb.append(d).append('~');
        return sb.toString();
    }

    private static Object intNum(double v) {
        if (v == Math.rint(v) && Math.abs(v) < 1e21) return new Json.Num(new java.math.BigDecimal(v).toPlainString());
        return v;
    }

    /**
     * Verifies an SD-JWT VC produced by {@link #passportToVC} and reconstructs the passport: {@code {passport, issuerDid, subjectDid}}.
     * The signature is checked under {@code issuerVerifyKey} (EdDSA only); every presented disclosure must hash to a digest in
     * {@code credentialSubject._sd}. Options: {@code expectedIssuerDid}, {@code now} (ms). Throws on any failure.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyPassportVC(Object vcO, Object issuerVerifyKey, Map<String, Object> options) {
        if (!(vcO instanceof String)) throw new IllegalArgumentException("vc.split is not a function");
        String[] parts = ((String) vcO).split("~", -1);
        String jwt = parts[0];
        if (jwt.isEmpty()) throw new IllegalArgumentException("pca-vc: empty SD-JWT");
        List<String> disclosures = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) if (!parts[i].isEmpty()) disclosures.add(parts[i]);
        Jose.assertCanonicalCompactJws(jwt);
        for (String d : disclosures) Jose.decodeCanonicalBase64url(d);

        Jose.JwtOptions jo = new Jose.JwtOptions();
        jo.algorithms = List.of("EdDSA");
        if (options != null && options.get("now") != null) jo.currentDateMs = num(options.get("now"));
        Jose.VerifiedJwt res = Jose.jwtVerify(jwt, publicKey(issuerVerifyKey), jo);
        Map<String, Object> payload = res.payload;
        if (!"vc+sd-jwt".equals(res.protectedHeader.get("typ"))) throw new IllegalArgumentException("pca-vc: header typ must be 'vc+sd-jwt'");
        Map<String, Object> vcClaim = asMap(payload.get("vc"));
        if (vcClaim == null) throw new IllegalArgumentException("pca-vc: missing vc claim");
        Object ctx = vcClaim.get("@context");
        if (!(ctx instanceof List) || ((List<Object>) ctx).isEmpty() || !VC_CONTEXT.equals(((List<Object>) ctx).get(0))) throw new IllegalArgumentException("pca-vc: @context must begin with " + VC_CONTEXT);
        List<Object> cl = (List<Object>) ctx;
        if (cl.size() != 2 || !AGENT_PASSPORT_CONTEXT.equals(cl.get(1))) throw new IllegalArgumentException("pca-vc: @context must be exactly [" + VC_CONTEXT + ", " + AGENT_PASSPORT_CONTEXT + "]");
        Object types = vcClaim.get("type");
        if (!(types instanceof List) || !((List<Object>) types).contains("VerifiableCredential") || !((List<Object>) types).contains(AGENT_PASSPORT_VC_TYPE)) {
            throw new IllegalArgumentException("pca-vc: type must include VerifiableCredential and " + AGENT_PASSPORT_VC_TYPE);
        }
        Map<String, Object> cs = asMap(vcClaim.get("credentialSubject"));
        if (cs == null) throw new IllegalArgumentException("pca-vc: missing credentialSubject");
        if (cs.containsKey("_sd_alg")) throw new IllegalArgumentException("pca-vc: _sd_alg must be a top-level claim");
        if (payload.containsKey("_sd_alg") && !"sha-256".equals(payload.get("_sd_alg"))) throw new IllegalArgumentException("pca-vc: unsupported _sd_alg (require sha-256)");

        List<String> sdList = new ArrayList<>();
        if (cs.get("_sd") instanceof List) for (Object x : (List<Object>) cs.get("_sd")) if (x instanceof String) sdList.add((String) x);
        Map<String, String> recovered = new LinkedHashMap<>();
        Set<String> seen = new HashSet<>();
        for (String disclosure : disclosures) {
            String digest = sha256b64u(disclosure);
            if (!sdList.contains(digest)) throw new IllegalArgumentException("pca-vc: disclosure does not match any _sd digest");
            if (seen.contains(digest)) throw new IllegalArgumentException("pca-vc: duplicate disclosure");
            seen.add(digest);
            Object decoded;
            try {
                decoded = Json.parseLenient(new String(Keys.unb64u(disclosure), StandardCharsets.UTF_8));
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("pca-vc: malformed disclosure");
            }
            if (!(decoded instanceof List) || ((List<?>) decoded).size() != 3) throw new IllegalArgumentException("pca-vc: malformed disclosure");
            String name = asString(((List<Object>) decoded).get(1), "disclosure name");
            if (!SD_DIGEST_FIELDS.contains(name)) throw new IllegalArgumentException("pca-vc: unexpected disclosure claim '" + name + "'");
            if (recovered.containsKey(name)) throw new IllegalArgumentException("pca-vc: disclosure claim '" + name + "' appears more than once");
            recovered.put(name, asString(((List<Object>) decoded).get(2), "disclosure value"));
        }

        Map<String, Object> passport = new LinkedHashMap<>();
        passport.put("id", asString(cs.get("passport_id"), "passport_id"));
        passport.put("model_id", asString(cs.get("model_id"), "model_id"));
        passport.put("operator", asString(cs.get("operator"), "operator"));
        if (!(cs.get("hardware_rooted") instanceof Boolean)) throw new IllegalArgumentException("pca-vc: expected boolean for hardware_rooted");
        passport.put("hardware_rooted", cs.get("hardware_rooted"));
        if (num(cs.get("issued_at")) == null) throw new IllegalArgumentException("pca-vc: expected number for issued_at");
        passport.put("issued_at", cs.get("issued_at"));
        if (cs.containsKey("weights_measured")) {
            if (!(cs.get("weights_measured") instanceof Boolean)) throw new IllegalArgumentException("pca-vc: expected boolean for weights_measured");
            passport.put("weights_measured", cs.get("weights_measured"));
        }
        for (String field : SD_DIGEST_FIELDS) if (recovered.containsKey(field)) passport.put(field, recovered.get(field));

        String issuerDid = asString(payload.get("iss"), "iss");
        String subjectDid = asString(cs.get("id"), "credentialSubject.id");
        if (!subjectDid.equals(payload.get("sub"))) throw new IllegalArgumentException("pca-vc: sub does not match credentialSubject.id");
        if (options != null && options.containsKey("expectedIssuerDid") && !issuerDid.equals(options.get("expectedIssuerDid"))) {
            throw new IllegalArgumentException("pca-vc: iss does not match expectedIssuerDid");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("passport", passport);
        out.put("issuerDid", issuerDid);
        out.put("subjectDid", subjectDid);
        return out;
    }

    // ---- RFC 9421 HTTP Message Signatures + Web Bot Auth ----

    private static final String SIG_LABEL = "sig1";
    private static final String WS = "[\\u0009-\\u000d\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]";

    private static String jsTrim(String s) { return s.replaceAll("^" + WS + "+", "").replaceAll(WS + "+$", ""); }

    /** JavaScript String(v) of a parsed JSON value (template-literal interpolation). */
    private static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return Json.canonicalize(new Json.Num(Double.toString(d)));
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(jsString(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** Lower-case header keys; a later duplicate wins. */
    private static Map<String, String> normalizeHeaders(Object headers) {
        Map<String, Object> h = asMap(headers);
        if (h == null) throw new IllegalArgumentException("Cannot convert undefined or null to object");
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : h.entrySet()) {
            // a non-string header value only fails when the header is covered, which every normalized header is
            out.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue() instanceof String ? (String) e.getValue() : null);
        }
        return out;
    }

    private static String componentValue(String name, String method, String url, Map<String, String> headers) {
        if (name.equals("@method")) return method.toUpperCase(Locale.ROOT);
        if (name.equals("@target-uri")) return url;
        if (name.equals("@authority")) return Dpop.urlHost(url);
        String v = headers.get(name);
        if (v == null) throw new IllegalArgumentException("pca-vc: covered header '" + name + "' absent from request");
        return jsTrim(v);
    }

    private static String signatureBase(List<String> components, String sigParamsValue, String method, String url, Map<String, String> headers) {
        List<String> lines = new ArrayList<>();
        for (String c : components) lines.add("\"" + c + "\": " + componentValue(c, method, url, headers));
        lines.add("\"@signature-params\": " + sigParamsValue);
        return String.join("\n", lines);
    }

    /**
     * Signs an HTTP request per RFC 9421 (EdDSA) with the Web Bot Auth {@code Signature-Agent} pattern. {@code args}: {@code method}, {@code url},
     * {@code headers} (map), {@code key} (32-byte seed or private JWK), {@code keyid}, {@code created} (null = now), {@code signatureAgent}
     * (present, even null, adds the agent header, the covered component and the {@code web-bot-auth} tag), {@code now} (ms).
     * Returns {@code {signatureInput, signature, signatureAgent?}}.
     */
    public static Map<String, Object> signRequestMessage(Map<String, Object> args) {
        String method = (String) args.get("method");
        String url = (String) args.get("url");
        Object createdO = args.get("created");
        Object nowO = args.get("now");
        double nowMs = nowO != null ? num(nowO) : System.currentTimeMillis();
        String created = createdO != null ? jsString(createdO) : jsString(intNum(Math.floor(nowMs / 1000)));
        Map<String, String> headers = normalizeHeaders(args.get("headers"));
        if (!headers.containsKey("host")) headers.put("host", Dpop.urlHost(url));
        boolean agent = args.containsKey("signatureAgent");
        if (agent) headers.put("signature-agent", "\"" + jsString(args.get("signatureAgent")) + "\"");

        List<String> components = new ArrayList<>(List.of("@method", "@target-uri"));
        List<String> names = new ArrayList<>(headers.keySet());
        java.util.Collections.sort(names);
        components.addAll(names);
        StringBuilder inner = new StringBuilder("(");
        for (int i = 0; i < components.size(); i++) inner.append(i == 0 ? "" : " ").append('"').append(components.get(i)).append('"');
        inner.append(')');
        String params = ";created=" + created + ";keyid=\"" + jsString(args.get("keyid")) + "\";alg=\"ed25519\"";
        if (agent) params += ";tag=\"web-bot-auth\"";
        String sigParamsValue = inner + params;

        String base = signatureBase(components, sigParamsValue, method, url, headers);
        byte[] sig = Jose.signRaw("EdDSA", privateKey(args.get("key")), Jose.utf8(base));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("signatureInput", SIG_LABEL + "=" + sigParamsValue);
        result.put("signature", SIG_LABEL + "=:" + Base64.getEncoder().encodeToString(sig) + ":");
        if (agent) result.put("signatureAgent", "\"" + jsString(args.get("signatureAgent")) + "\"");
        return result;
    }

    private static final Pattern COMPONENT_TOKEN = Pattern.compile("^\"(.*)\"\\z");

    private static List<String> parseComponents(String sigParamsValue) {
        int open = sigParamsValue.indexOf('('), close = sigParamsValue.indexOf(')');
        if (open != 0 || close < 0) throw new IllegalArgumentException("pca-vc: malformed @signature-params");
        String inner = jsTrim(sigParamsValue.substring(open + 1, close));
        List<String> out = new ArrayList<>();
        if (inner.isEmpty()) return out;
        for (String tok : inner.split(WS + "+", -1)) {
            Matcher m = COMPONENT_TOKEN.matcher(tok);
            if (!m.find()) throw new IllegalArgumentException("pca-vc: malformed component identifier");
            out.add(m.group(1));
        }
        return out;
    }

    private static double toNumber(Object v) {
        if (v == null) return 0;
        Double d = num(v);
        if (d != null) return d;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        return Double.NaN;
    }

    /**
     * Verifies an RFC 9421 signature produced by {@link #signRequestMessage}. {@code args}: {@code method}, {@code url}, {@code headers},
     * {@code signatureInput}, {@code signature}, {@code signatureAgent}, {@code requiredComponents}, {@code maxAgeSec}, {@code nowSec},
     * {@code now} (ms; the clock when {@code nowSec} is absent). False on any mismatch.
     */
    @SuppressWarnings("unchecked")
    public static boolean verifyRequestSignature(Map<String, Object> args, Object verifyKey) {
        try {
            String signatureInput = (String) args.get("signatureInput");
            int eq = signatureInput.indexOf('=');
            if (eq < 0) return false;
            String sigParamsValue = signatureInput.substring(eq + 1);
            List<String> components = parseComponents(sigParamsValue);
            Object req = args.get("requiredComponents");
            if (req != null) for (Object need : (List<Object>) req) if (!components.contains(need)) return false;
            Matcher algParam = Pattern.compile(";alg=\"([^\"]*)\"").matcher(sigParamsValue);
            if (algParam.find() && !"ed25519".equals(algParam.group(1))) return false;
            if (args.containsKey("maxAgeSec")) {
                Matcher created = Pattern.compile(";created=(\\d+)").matcher(sigParamsValue);
                if (!created.find()) return false;
                double now = args.get("nowSec") != null ? num(args.get("nowSec")) : Math.floor((args.get("now") != null ? num(args.get("now")) : System.currentTimeMillis()) / 1000);
                double c = Double.parseDouble(created.group(1));
                if (!Double.isFinite(c) || !(Double.isFinite(now) && now - c <= toNumber(args.get("maxAgeSec"))) || !(c - now <= 5)) return false;
            }
            String url = (String) args.get("url");
            Map<String, String> headers = normalizeHeaders(args.get("headers"));
            if (!headers.containsKey("host")) headers.put("host", Dpop.urlHost(url));
            if (components.contains("signature-agent") && !headers.containsKey("signature-agent")) {
                if (!(args.get("signatureAgent") instanceof String)) return false; // absent: refused; a non-string value fails when the header is read
                headers.put("signature-agent", (String) args.get("signatureAgent"));
            }
            String base = signatureBase(components, sigParamsValue, (String) args.get("method"), url, headers);

            String signature = (String) args.get("signature");
            int sigEq = signature.indexOf('=');
            if (sigEq < 0) return false;
            String wrapped = jsTrim(signature.substring(sigEq + 1));
            Matcher m = Pattern.compile("^:(.*):\\z").matcher(wrapped);
            if (!m.find()) return false;
            byte[] sigBytes = nodeBase64(m.group(1));
            Map<String, Object> key = publicKey(verifyKey);
            return Jose.verifySignature("EdDSA", key, sigBytes, Jose.utf8(base));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Node-style lenient base64 (either alphabet, optional padding, stops at the first '='). */
    private static byte[] nodeBase64(String s) {
        int eq = s.indexOf('=');
        String t = (eq >= 0 ? s.substring(0, eq) : s).replace('-', '+').replace('_', '/');
        if (!t.matches("[A-Za-z0-9+/]*") || t.length() % 4 == 1) return new byte[0];
        StringBuilder p = new StringBuilder(t);
        while (p.length() % 4 != 0) p.append('=');
        return Base64.getDecoder().decode(p.toString());
    }
}
