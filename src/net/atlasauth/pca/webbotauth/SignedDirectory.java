package net.atlasauth.pca.webbotauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Signed key-directory responses (draft-meunier-http-message-signatures-directory section 5.2): the directory body is signed with RFC 9421,
 * covering {@code "@authority";req}, {@code tag="http-message-signatures-directory"}, {@code alg="ed25519"}, a {@code keyid} that is the RFC 7638
 * thumbprint of the signing key, with {@code created} and {@code expires}. One signature per key; a client keeps only the keys that have a valid one.
 */
public final class SignedDirectory {
    private SignedDirectory() {}

    public static final String DIRECTORY_SIGNATURE_TAG = "http-message-signatures-directory";
    private static final double DEFAULT_LIFETIME_SEC = 86_400;

    private static final Pattern X = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Pattern AUTHORITY = Pattern.compile("[a-z0-9.\\-\\[\\]:]+");
    private static final Pattern ENTRY = Pattern.compile("([a-z][a-z0-9_.*-]*)=\\(\"@authority\";req\\)((?:;[a-z]+=(?:[0-9]+|\"[A-Za-z0-9_.\\-]*\"))*)");
    private static final Pattern SIG = Pattern.compile("([a-z][a-z0-9_.*-]*)=:([A-Za-z0-9+/]+={0,2}):");
    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    static String thumbprintOfX(String x) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.utf8(("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}")));
            return Keys.b64u(h);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string {@code kid}. Throws IllegalArgumentException otherwise. */
    public static Map<String, Object> parseKeyDirectory(String text) {
        Object doc = Json.parseNoDuplicates(text); // a duplicate member is refused
        Object keys = doc instanceof Map ? ((Map<?, ?>) doc).get("keys") : null;
        if (!(keys instanceof List) || ((List<?>) keys).isEmpty()) throw new IllegalArgumentException("directory has no keys");
        for (Object k : (List<?>) keys) {
            if (!(k instanceof Map)) throw new IllegalArgumentException("directory contains a malformed key");
            Map<?, ?> j = (Map<?, ?>) k;
            if (!"OKP".equals(j.get("kty")) || !"Ed25519".equals(j.get("crv")) || !(j.get("kid") instanceof String) || ((String) j.get("kid")).isEmpty()) {
                throw new IllegalArgumentException("directory contains a malformed key");
            }
            if (!(j.get("x") instanceof String) || !X.matcher((String) j.get("x")).matches()) throw new IllegalArgumentException("directory contains a malformed key");
            for (String f : new String[] {"nbf", "exp"}) {
                if (j.containsKey(f)) {
                    Double d = JsVal.num(j.get(f));
                    if (d == null || Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("directory contains a malformed key");
                }
            }
        }
        return JsVal.map(doc);
    }

    /**
     * Sign a directory response. {@code input}: keys (list of signing keys, each a Keys.EdKey or a map with b64u {@code secretKey} seed), directory
     * (the document to serve, as built by buildKeyDirectory; every signing key must be in it), authority (lower-case host or host:port), created?,
     * expiresInSec?. Returns {body, headers}.
     */
    public static Map<String, Object> signDirectoryResponse(Map<String, Object> input) {
        Object keysO = input.get("keys");
        List<?> keys = keysO instanceof List ? (List<?>) keysO : List.of();
        if (keys.isEmpty()) throw new IllegalArgumentException("signDirectoryResponse: at least one signing key is required");
        Object authority = input.get("authority");
        if (!(authority instanceof String) || !AUTHORITY.matcher((String) authority).matches()) throw new IllegalArgumentException("signDirectoryResponse: authority must be a lower-case host or host:port");
        double created = input.get("created") != null ? WbaJs.number(input.get("created")) : (double) (System.currentTimeMillis() / 1000);
        double expires = created + (input.get("expiresInSec") != null ? WbaJs.number(input.get("expiresInSec")) : DEFAULT_LIFETIME_SEC);
        Object directory = input.get("directory");
        String body = JsVal.stringify(directory);
        List<String> inputs = new ArrayList<>(), sigs = new ArrayList<>();
        int i = 0;
        for (Object k : keys) {
            Keys.EdKey key = WebBotAuth.edKey(k);
            String x = Keys.b64u(key.pub);
            boolean found = false;
            Object dk = WbaJs.get(directory, "keys");
            if (dk instanceof List) for (Object j : (List<?>) dk) if (x.equals(WbaJs.get(j, "x"))) { found = true; break; }
            if (!found) throw new IllegalArgumentException("signDirectoryResponse: a signing key is not in the directory");
            String keyid = thumbprintOfX(x);
            String label = "sig" + (i + 1);
            i++;
            String params = "(\"@authority\";req);created=" + WbaJs.numStr(created) + ";expires=" + WbaJs.numStr(expires) + ";keyid=\"" + keyid + "\";alg=\"ed25519\";tag=\"" + DIRECTORY_SIGNATURE_TAG + "\"";
            String base = "\"@authority\";req: " + authority + "\n\"@signature-params\": " + params;
            inputs.add(label + "=" + params);
            sigs.add(label + "=:" + WbaJs.b64(key.sign(Json.utf8(base))) + ":");
        }
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/http-message-signatures-directory+json");
        headers.put("signature-input", String.join(", ", inputs));
        headers.put("signature", String.join(", ", sigs));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("body", body);
        out.put("headers", headers);
        return out;
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("valid", Boolean.FALSE);
        m.put("reason", reason);
        m.put("keys", new ArrayList<Object>());
        return m;
    }

    /**
     * Verify a signed directory response. {@code input}: authority, headers ({@code signature-input}, {@code signature}), body, now?, clockSkewSec?,
     * maxLifetimeSec? (default 86400). Fail closed: {valid:false, reason, keys:[]} for a missing or malformed signature header, a body that is not a
     * well-formed directory, or when NO signature is valid. When valid, {@code keys} holds only the directory keys that carry a valid signature.
     */
    public static Map<String, Object> verifyDirectoryResponse(Map<String, Object> input) {
        try {
            Object hdrs = input.get("headers");
            Object sigInputO = WbaJs.get(hdrs, "signature-input"), sigHeaderO = WbaJs.get(hdrs, "signature");
            if (!JsVal.truthy(sigInputO) || !JsVal.truthy(sigHeaderO)) return fail("missing signature-input or signature header");
            String sigInput = (String) sigInputO, sigHeader = (String) sigHeaderO;
            Map<String, Object> dir = parseKeyDirectory((String) input.get("body"));
            Map<String, byte[]> sigs = new HashMap<>();
            for (String part : sigHeader.split(", ", -1)) {
                Matcher m = SIG.matcher(part);
                if (!m.matches()) return fail("malformed signature header");
                sigs.put(m.group(1), WbaJs.nodeBase64(m.group(2)));
            }
            double now = input.get("now") != null ? WbaJs.number(input.get("now")) : (double) (System.currentTimeMillis() / 1000);
            double skew = input.get("clockSkewSec") != null ? WbaJs.number(input.get("clockSkewSec")) : 0;
            double maxLife = input.get("maxLifetimeSec") != null ? WbaJs.number(input.get("maxLifetimeSec")) : DEFAULT_LIFETIME_SEC;
            Map<String, Object> good = new LinkedHashMap<>();
            String lastReason = "no signature entry";
            for (String raw : sigInput.split(", ", -1)) {
                Matcher m = ENTRY.matcher(raw);
                if (!m.matches()) { lastReason = "malformed signature-input entry (must cover exactly \"@authority\";req)"; continue; }
                String label = m.group(1);
                Map<String, String> params = new HashMap<>();
                String[] ps = m.group(2).split(";", -1);
                for (int pi = 1; pi < ps.length; pi++) {
                    String p = ps[pi];
                    int eq = p.indexOf('=');
                    String k = p.substring(0, eq);
                    if (params.containsKey(k)) params.put("__dup", "1");
                    params.put(k, p.substring(eq + 1));
                }
                if (params.containsKey("__dup")) { lastReason = "duplicate signature parameter"; continue; }
                String tag = strParam(params, "tag");
                if (!DIRECTORY_SIGNATURE_TAG.equals(tag)) { lastReason = "wrong tag"; continue; }
                String alg = params.get("alg");
                if (alg != null && !alg.equals("\"ed25519\"")) { lastReason = "unsupported alg"; continue; }
                Double created = numParam(params, "created"), expires = numParam(params, "expires");
                if (created == null || expires == null) { lastReason = "created and expires are required"; continue; }
                if (!(Double.isFinite(now) && Double.isFinite(skew) && Double.isFinite(created) && created <= now + skew)) { lastReason = "signature created-time is in the future"; continue; }
                if (!(Double.isFinite(now) && Double.isFinite(skew) && Double.isFinite(expires) && now <= expires + skew)) { lastReason = "signature has expired"; continue; }
                if (!(expires - created <= maxLife)) { lastReason = "signature lifetime exceeds maxLifetimeSec"; continue; }
                String keyid = strParam(params, "keyid");
                if (keyid == null) { lastReason = "missing keyid"; continue; }
                Map<String, Object> key = null;
                for (Object j : (List<?>) dir.get("keys")) if (thumbprintOfX((String) ((Map<?, ?>) j).get("x")).equals(keyid)) { key = JsVal.map(j); break; }
                if (key == null) { lastReason = "keyid is not the thumbprint of any directory key"; continue; }
                Double nbf = JsVal.num(key.get("nbf")), exp = JsVal.num(key.get("exp"));
                if ((nbf != null && !(Double.isFinite(now) && Double.isFinite(skew) && now + skew >= nbf)) || (exp != null && !(Double.isFinite(now) && Double.isFinite(skew) && now - skew <= exp))) { lastReason = "directory key is outside its validity window"; continue; }
                byte[] sig = sigs.get(label);
                if (sig == null || sig.length != 64) { lastReason = "no valid signature bytes for the label"; continue; }
                String base = "\"@authority\";req: " + input.get("authority") + "\n\"@signature-params\": " + raw.substring(label.length() + 1);
                byte[] pk = WbaJs.nodeBase64((String) key.get("x"));
                if (!Jose.verifyEd25519Strict(pk, Json.utf8(base), sig)) { lastReason = "signature does not verify"; continue; }
                good.put((String) key.get("kid"), key);
            }
            if (good.isEmpty()) return fail(lastReason);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("valid", Boolean.TRUE);
            out.put("keys", new ArrayList<Object>(good.values()));
            return out;
        } catch (RuntimeException e) {
            return fail("verification failed (fail closed): " + e.getMessage());
        }
    }

    private static String strParam(Map<String, String> params, String k) {
        String v = params.get(k);
        return v != null && v.startsWith("\"") ? v.substring(1, v.length() - 1) : null;
    }

    private static Double numParam(Map<String, String> params, String k) {
        String v = params.get(k);
        return v != null && DIGITS.matcher(v).matches() ? Double.valueOf(v) : null;
    }
}
