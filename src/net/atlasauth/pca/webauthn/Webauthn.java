package net.atlasauth.pca.webauthn;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.Approval;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.jose.Jose;

/**
 * Phishing-resistant human co-sign for PCA step-up via WebAuthn / FIDO2: the server-side assertion verifier. The WebAuthn challenge is
 * the PCA step-up challenge (the action digest), so a valid assertion proves a human holding a hardware-bound credential approved THIS
 * action. Self-contained: ES256 (P-256, DER or raw r||s) and strict RFC 8032 EdDSA, SHA-256, and a minimal COSE_Key / CBOR reader.
 * Port of {@code @atlasauth/pca-webauthn}. Every verification entry point fails CLOSED and never throws on hostile input.
 *
 * <p>The assertion, the expectations and the payment expectation are JSON-shaped maps with the reference's member names: byte members
 * are {@code byte[]}, JSON numbers are {@link Json.Num} (or any {@link Number}), {@code onSignCountRegression} is a
 * {@code Consumer<Map<String,Object>>}. A member of the wrong type fails the check that names it, as in the reference.
 */
public final class Webauthn {
    private Webauthn() {}

    /** Input size caps (bytes). */
    public static final int MAX_AUTHENTICATOR_DATA_BYTES = 4096;
    public static final int MAX_CLIENT_DATA_BYTES = 8192;
    public static final int MAX_SIGNATURE_BYTES = 1024;

    // ---- helpers ----

    private static byte[] sha256(byte[] b) { return Jose.sha256(b); }

    private static boolean bytesEqual(byte[] a, byte[] b) { return a.length == b.length && MessageDigest.isEqual(a, b); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asRecord(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }

    private static Double num(Object o) {
        if (o instanceof Json.Num) return Double.parseDouble(((Json.Num) o).raw);
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    /** JavaScript String(v) for the values a parsed clientDataJSON can hold. */
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

    /** Tolerant base64url (URL alphabet, optional padding, '+' and '/' accepted) -> bytes, strictly canonical; null when undecodable. */
    private static byte[] base64urlToBytes(Object s) {
        if (!(s instanceof String)) return null;
        String t = ((String) s).replaceAll("=+$", "").replace('+', '-').replace('/', '_');
        return Pca.decodeB64uStrict(t, -1);
    }

    // ---- minimal COSE_Key / CBOR reader ----

    private static final class Item {
        final Object value; // Long | byte[] | Map<Long,Object>
        final int next;
        Item(Object value, int next) { this.value = value; this.next = next; }
    }

    private static int u8(byte[] b, int at) {
        if (at < 0 || at >= b.length) throw new IllegalArgumentException("Offset is outside the bounds of the DataView");
        return b[at] & 0xff;
    }

    private static Item readItem(byte[] b, int offset) {
        int initial = u8(b, offset);
        int major = initial >> 5, ai = initial & 0x1f;
        int p = offset + 1;
        long arg;
        if (ai < 24) arg = ai;
        else if (ai == 24) { arg = u8(b, p); p += 1; }
        else if (ai == 25) { arg = (u8(b, p) << 8) | u8(b, p + 1); p += 2; }
        else if (ai == 26) { arg = ((long) u8(b, p) << 24) | ((long) u8(b, p + 1) << 16) | ((long) u8(b, p + 2) << 8) | u8(b, p + 3); p += 4; }
        else throw new IllegalArgumentException("cose: unsupported CBOR argument encoding (8-byte or indefinite length)");
        switch (major) {
            case 0: return new Item(arg, p);
            case 1: return new Item(-1 - arg, p);
            case 2: {
                long end = p + arg;
                if (end > b.length) throw new IllegalArgumentException("cose: byte string length out of range");
                return new Item(Arrays.copyOfRange(b, p, (int) end), (int) end);
            }
            case 5: {
                Map<Long, Object> map = new LinkedHashMap<>();
                int q = p;
                for (long i = 0; i < arg; i++) {
                    Item key = readItem(b, q);
                    if (!(key.value instanceof Long)) throw new IllegalArgumentException("cose: non-integer map key");
                    Item val = readItem(b, key.next);
                    map.put((Long) key.value, val.value);
                    q = val.next;
                }
                return new Item(map, q);
            }
            default:
                throw new IllegalArgumentException("cose: unsupported CBOR major type " + major);
        }
    }

    private static final long COSE_KTY = 1, COSE_CRV = -1, COSE_X = -2, COSE_Y = -3;

    /**
     * Decodes a raw COSE_Key (an attested credential public key) into a JWK: ES256 (EC2 / P-256) or EdDSA (OKP / Ed25519), with
     * {@code alg}. Throws on malformed input or an unsupported key type.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> coseKeyToJwk(byte[] bytes) {
        if (bytes == null) throw new IllegalArgumentException("coseKeyToJwk: expected a Uint8Array");
        Object value = readItem(bytes, 0).value;
        if (!(value instanceof Map)) throw new IllegalArgumentException("coseKeyToJwk: COSE_Key is not a CBOR map");
        Map<Long, Object> m = (Map<Long, Object>) value;
        Object kty = m.get(COSE_KTY);
        Map<String, Object> jwk = new LinkedHashMap<>();
        if (Long.valueOf(2).equals(kty)) {
            Object crv = m.get(COSE_CRV), x = m.get(COSE_X), y = m.get(COSE_Y);
            if (!Long.valueOf(1).equals(crv)) throw new IllegalArgumentException("coseKeyToJwk: EC2 key is not P-256 (crv != 1)");
            if (!(x instanceof byte[]) || !(y instanceof byte[])) throw new IllegalArgumentException("coseKeyToJwk: EC2 key missing an x/y coordinate");
            if (((byte[]) x).length != 32 || ((byte[]) y).length != 32) throw new IllegalArgumentException("coseKeyToJwk: EC2 coordinate is not 32 bytes");
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("x", Jose.b64u((byte[]) x));
            jwk.put("y", Jose.b64u((byte[]) y));
            jwk.put("alg", "ES256");
            return jwk;
        }
        if (Long.valueOf(1).equals(kty)) {
            Object crv = m.get(COSE_CRV), x = m.get(COSE_X);
            if (!Long.valueOf(6).equals(crv)) throw new IllegalArgumentException("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)");
            if (!(x instanceof byte[])) throw new IllegalArgumentException("coseKeyToJwk: OKP key missing its public key");
            if (((byte[]) x).length != 32) throw new IllegalArgumentException("coseKeyToJwk: Ed25519 public key is not 32 bytes");
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", Jose.b64u((byte[]) x));
            jwk.put("alg", "EdDSA");
            return jwk;
        }
        throw new IllegalArgumentException("coseKeyToJwk: unsupported COSE key type (kty=" + (kty == null ? "undefined" : kty) + ")");
    }

    /** A credential key resolved to its signature algorithm and the bytes the verifier uses. */
    private static final class ResolvedKey {
        final String alg;
        final byte[] raw; // ES256: 0x04 || X || Y; EdDSA: the 32-byte key
        ResolvedKey(String alg, byte[] raw) { this.alg = alg; this.raw = raw; }
    }

    private static ResolvedKey resolveKey(Object pub) {
        Map<String, Object> jwk = pub instanceof byte[] ? coseKeyToJwk((byte[]) pub) : asRecord(pub);
        if (jwk == null) {
            if (pub == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'kty')");
            throw new IllegalArgumentException("resolveKey: unsupported public key");
        }
        Object kty = jwk.get("kty");
        if ("EC".equals(kty)) {
            if (!"P-256".equals(jwk.get("crv"))) throw new IllegalArgumentException("resolveKey: EC JWK is not P-256");
            byte[] x = base64urlToBytes(jwk.get("x")), y = base64urlToBytes(jwk.get("y"));
            if (x == null || y == null || x.length != 32 || y.length != 32) throw new IllegalArgumentException("resolveKey: invalid EC JWK coordinates");
            byte[] raw = new byte[65];
            raw[0] = 4;
            System.arraycopy(x, 0, raw, 1, 32);
            System.arraycopy(y, 0, raw, 33, 32);
            return new ResolvedKey("ES256", raw);
        }
        if ("OKP".equals(kty)) {
            if (!"Ed25519".equals(jwk.get("crv"))) throw new IllegalArgumentException("resolveKey: OKP JWK is not Ed25519");
            byte[] x = base64urlToBytes(jwk.get("x"));
            if (x == null || x.length != 32) throw new IllegalArgumentException("resolveKey: invalid OKP JWK public key");
            return new ResolvedKey("EdDSA", x);
        }
        throw new IllegalArgumentException("resolveKey: unsupported public key");
    }

    // ---- authenticatorData ----

    /** Parsed fixed header of authenticatorData: rpIdHash[32] || flags[1] || signCount[4]. */
    public static final class ParsedAuthenticatorData {
        public final byte[] rpIdHash;
        public final boolean up, uv, be, bs, at, ed;
        public final long signCount;
        ParsedAuthenticatorData(byte[] rpIdHash, int flags, long signCount) {
            this.rpIdHash = rpIdHash;
            this.up = (flags & 0x01) != 0;
            this.uv = (flags & 0x04) != 0;
            this.be = (flags & 0x08) != 0;
            this.bs = (flags & 0x10) != 0;
            this.at = (flags & 0x40) != 0;
            this.ed = (flags & 0x80) != 0;
            this.signCount = signCount;
        }

        /** {@code {rpIdHash, flags: {up, uv, be, bs, at, ed}, signCount}} as the reference returns it. */
        public Map<String, Object> toMap() {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("up", up); f.put("uv", uv); f.put("be", be); f.put("bs", bs); f.put("at", at); f.put("ed", ed);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rpIdHash", rpIdHash);
            m.put("flags", f);
            m.put("signCount", signCount);
            return m;
        }
    }

    /** Parses the fixed 37-byte header of authenticatorData; null when the buffer is missing or shorter than 37 bytes. */
    public static ParsedAuthenticatorData parseAuthenticatorData(byte[] authData) {
        if (authData == null || authData.length < 37) return null;
        long sc = ((long) (authData[33] & 0xff) << 24) | ((long) (authData[34] & 0xff) << 16) | ((long) (authData[35] & 0xff) << 8) | (authData[36] & 0xff);
        return new ParsedAuthenticatorData(Arrays.copyOfRange(authData, 0, 32), authData[32] & 0xff, sc);
    }

    // ---- step-up challenge binding ----

    /**
     * The WebAuthn challenge bytes for a PCA step-up: {@code sha256(thresholdMessage(pcactn))}, the bytes whose base64url form is the
     * FROST action digest. Accepts a PCActn (or body) map, the base64url digest string, or raw 32-byte digest bytes; throws for a digest that
     * is not 32 bytes / not canonical base64url.
     */
    @SuppressWarnings("unchecked")
    public static byte[] buildStepUpChallenge(Object pcActnOrDigest) {
        if (pcActnOrDigest instanceof byte[]) {
            byte[] d = (byte[]) pcActnOrDigest;
            if (d.length != 32) throw new IllegalArgumentException("buildStepUpChallenge: digest bytes must be 32 bytes");
            return d.clone();
        }
        if (pcActnOrDigest instanceof String) {
            byte[] b = Pca.decodeB64uStrict(pcActnOrDigest, 32);
            if (b == null) throw new IllegalArgumentException("buildStepUpChallenge: digest is not a canonical base64url 32-byte value");
            return b;
        }
        Map<String, Object> body;
        if (pcActnOrDigest instanceof Map) body = (Map<String, Object>) pcActnOrDigest;
        else if (pcActnOrDigest instanceof List) { // object rest of an array: its index members
            body = new LinkedHashMap<>();
            int i = 0;
            for (Object x : (List<Object>) pcActnOrDigest) body.put(Integer.toString(i++), x);
        } else if (pcActnOrDigest == null) throw new IllegalArgumentException("Cannot destructure null");
        else body = new LinkedHashMap<>(); // a number or boolean has no own members
        return sha256(Pca.thresholdMessage(body));
    }

    /** The challenge for an approval that commits to the canonical render: {@code SHA-256(domain || action_digest || H(R))}. */
    public static byte[] buildApprovalChallenge(Object pcActnOrDigest, Object renderDigest) {
        return net.atlasauth.pca.Keys.unb64u(Approval.challenge(Jose.b64u(buildStepUpChallenge(pcActnOrDigest)), renderDigest));
    }

    /** The base64url form of {@link #buildApprovalChallenge}. */
    public static String approvalChallengeForActn(Object pcActnOrDigest, Object renderDigest) {
        return Approval.challenge(Jose.b64u(buildStepUpChallenge(pcActnOrDigest)), renderDigest);
    }

    /** The base64url step-up challenge (the FROST {@code action_digest}) for a PCActn / body / digest. */
    public static String stepUpChallengeB64u(Object pcActnOrDigest) { return Jose.b64u(buildStepUpChallenge(pcActnOrDigest)); }

    // ---- Secure Payment Confirmation ----

    /** Null if the signed payment data equals the expectation ({@code topOrigin}, {@code total}, payee). Total over hostile {@code payment}. */
    public static String spcPaymentError(Object payment, Map<String, Object> e, String rpId) {
        Map<String, Object> p = asRecord(payment);
        if (p == null) return "clientData.payment is missing";
        if (!e.containsKey("payeeName") && !e.containsKey("payeeOrigin")) return "the expectation names no payee (refused: a payment approval must bind the payee)";
        if (!(p.get("rpId") instanceof String) || !p.get("rpId").equals(rpId)) return "clientData.payment.rpId is not the verifier rpId";
        if (!same(p, "topOrigin", e, "topOrigin")) return "clientData.payment.topOrigin is not the verifier approval origin";
        Map<String, Object> total = asRecord(p.get("total"));
        if (total == null) return "clientData.payment.total does not equal the canonical render";
        Map<String, Object> et = asRecord(e.get("total"));
        if (et == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'currency')");
        if (!same(total, "currency", et, "currency") || !same(total, "value", et, "value")) return "clientData.payment.total does not equal the canonical render";
        for (String k : new String[] {"payeeName", "payeeOrigin"}) {
            if (e.containsKey(k) && !same(p, k, e, k)) return "clientData.payment." + k + " does not equal the canonical render";
        }
        return null;
    }

    /** {@code a[ka] === b[kb]} for JSON strings: both absent is equal, one absent is not, strings by value, anything else never. */
    private static boolean same(Map<String, Object> a, String ka, Map<String, Object> b, String kb) {
        boolean pa = a.containsKey(ka), pb = b.containsKey(kb);
        if (!pa || !pb) return !pa && !pb;
        Object x = a.get(ka), y = b.get(kb);
        if (x instanceof String && y instanceof String) return x.equals(y);
        if (x == null && y == null) return true;
        if (x instanceof Boolean && y instanceof Boolean) return x.equals(y);
        Double dx = num(x), dy = num(y);
        return dx != null && dy != null && dx.doubleValue() == dy.doubleValue();
    }

    // ---- ECDSA P-256 ----

    private static final BigInteger N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    private static byte[] pad32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }

    /** Strict DER ECDSA signature (single-byte total length, minimal positive INTEGERs, no trailing bytes) -> {r, s}; null when invalid. */
    private static BigInteger[] parseDer(byte[] d) {
        if (d.length < 2 || (d[0] & 0xff) != 0x30 || (d[1] & 0xff) != d.length - 2) return null;
        int[] pos = {2};
        BigInteger r = derInt(d, pos);
        if (r == null) return null;
        BigInteger s = derInt(d, pos);
        if (s == null || pos[0] != d.length) return null;
        return new BigInteger[] {r, s};
    }

    private static BigInteger derInt(byte[] d, int[] pos) {
        int i = pos[0];
        if (d.length - i < 2 || (d[i] & 0xff) != 0x02) return null;
        int len = d[i + 1] & 0xff;
        if (len == 0 || i + 2 + len > d.length) return null;
        int b0 = d[i + 2] & 0xff;
        if ((b0 & 0x80) != 0) return null;
        if (b0 == 0 && len > 1 && (d[i + 3] & 0x80) == 0) return null;
        if (b0 == 0 && len == 1) { pos[0] = i + 3; return BigInteger.ZERO; }
        pos[0] = i + 2 + len;
        return new BigInteger(1, Arrays.copyOfRange(d, i + 2, i + 2 + len));
    }

    private static boolean verifyEs256(byte[] sig, byte[] msg, byte[] rawPoint, boolean lowS, boolean der) {
        try {
            BigInteger r, s;
            if (der) {
                BigInteger[] rs = parseDer(sig);
                if (rs == null) return false;
                r = rs[0];
                s = rs[1];
            } else {
                if (sig.length != 64) return false;
                r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
                s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
            }
            if (r.signum() == 0 || s.signum() == 0 || r.compareTo(N) >= 0 || s.compareTo(N) >= 0) return false;
            if (lowS && s.compareTo(N.shiftRight(1)) > 0) return false;
            byte[] raw = new byte[64];
            System.arraycopy(pad32(r), 0, raw, 0, 32);
            System.arraycopy(pad32(s), 0, raw, 32, 32);
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("x", Jose.b64u(Arrays.copyOfRange(rawPoint, 1, 33)));
            jwk.put("y", Jose.b64u(Arrays.copyOfRange(rawPoint, 33, 65)));
            return Jose.verifySignature("ES256", jwk, raw, msg);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- assertion verification ----

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    private static String errMsg(RuntimeException e) { return e.getMessage() == null ? "unknown" : e.getMessage(); }

    /**
     * Verifies a WebAuthn / FIDO2 assertion as a human step-up co-sign. {@code assertion}: {@code authenticatorData}, {@code clientDataJSON},
     * {@code signature} (byte[]) and {@code publicKey} (a JWK map or a raw COSE_Key byte[]). {@code expect}: {@code expectedChallenge}
     * (byte[] or base64url String), {@code rpId}, {@code origins} (list), {@code requireUV}, {@code requireLowS}, {@code storedSignCount}
     * (required), {@code onSignCountRegression}, {@code rejectCrossOrigin}, {@code payment}. Returns {@code {ok:true, alg, signCount, flags}}
     * or {@code {ok:false, reason}}; never throws.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAssertion(Map<String, Object> assertion, Map<String, Object> expect) {
        try {
            Object ad = assertion.get("authenticatorData"), cd = assertion.get("clientDataJSON"), sg = assertion.get("signature");
            Object publicKey = assertion.get("publicKey");
            if (!(ad instanceof byte[])) return fail("authenticatorData is not bytes");
            if (!(cd instanceof byte[])) return fail("clientDataJSON is not bytes");
            if (!(sg instanceof byte[])) return fail("signature is not bytes");
            byte[] authenticatorData = (byte[]) ad, clientDataJSON = (byte[]) cd, signature = (byte[]) sg;
            if (authenticatorData.length > MAX_AUTHENTICATOR_DATA_BYTES) return fail("authenticatorData is too large");
            if (clientDataJSON.length > MAX_CLIENT_DATA_BYTES) return fail("clientDataJSON is too large");
            if (signature.length > MAX_SIGNATURE_BYTES) return fail("signature is too large");
            Object rpIdO = expect.get("rpId");
            if (!(rpIdO instanceof String) || ((String) rpIdO).isEmpty()) return fail("rpId is required");
            String rpId = (String) rpIdO;
            Object origins = expect.get("origins");
            if (!(origins instanceof List) || ((List<?>) origins).isEmpty()) return fail("origins allowlist is empty");
            if (!expect.containsKey("storedSignCount")) return fail("storedSignCount is required (use 0 for a credential never used)");
            Object payExp = expect.get("payment");
            boolean spc = expect.containsKey("payment");

            // clientDataJSON (TextDecoder: fatal UTF-8, a leading BOM is consumed)
            String clientText;
            try {
                clientText = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(clientDataJSON)).toString();
            } catch (CharacterCodingException e) {
                return fail("clientDataJSON is not valid UTF-8");
            }
            if (clientText.startsWith("﻿")) clientText = clientText.substring(1);
            Object clientParsed;
            try {
                clientParsed = Json.parseNoDuplicates(clientText); // a duplicate member is refused, as the reference
            } catch (RuntimeException e) {
                return fail("clientDataJSON is not valid JSON");
            }
            Map<String, Object> client = asRecord(clientParsed);
            if (client == null) return fail("clientDataJSON is not a JSON object");
            String wantType = spc ? "payment.get" : "webauthn.get";
            if (!wantType.equals(client.get("type"))) return fail("clientData.type is not \"" + wantType + "\" (" + (client.containsKey("type") ? jsString(client.get("type")) : "undefined") + ")");
            if (spc) {
                String pe = spcPaymentError(client.get("payment"), asRecord(payExp), rpId);
                if (pe != null) return fail(pe);
            }

            byte[] gotChallenge = Pca.decodeB64uStrict(client.get("challenge"), -1);
            if (gotChallenge == null) return fail("clientData.challenge is missing or not canonical base64url");
            Object ec = expect.get("expectedChallenge");
            byte[] expChallenge = ec instanceof byte[] ? (byte[]) ec : Pca.decodeB64uStrict(ec, -1);
            if (expChallenge == null) return fail("expectedChallenge is not decodable");
            if (!bytesEqual(gotChallenge, expChallenge)) return fail("clientData.challenge does not match the step-up challenge");

            Object origin = client.get("origin");
            if (!Boolean.FALSE.equals(expect.get("rejectCrossOrigin"))) {
                Object co = client.get("crossOrigin");
                if (Boolean.TRUE.equals(co)) return fail("clientData.crossOrigin is true");
                if (client.containsKey("crossOrigin") && !Boolean.FALSE.equals(co)) return fail("clientData.crossOrigin is not a boolean");
            }
            if (!(origin instanceof String)) return fail("clientData.origin is missing");
            if (!((List<Object>) origins).contains(origin)) return fail("clientData.origin \"" + origin + "\" is not in the allowlist");

            // authenticatorData
            ParsedAuthenticatorData parsed = parseAuthenticatorData(authenticatorData);
            if (parsed == null) return fail("authenticatorData is too short (< 37 bytes)");
            if (!bytesEqual(parsed.rpIdHash, sha256(Jose.utf8(rpId)))) return fail("rpIdHash does not match sha256(rpId)");
            if (!parsed.up) return fail("User Present (UP) flag is not set");
            if (truthy(expect.get("requireUV")) && !parsed.uv) return fail("User Verified (UV) flag is required but not set");

            // signature over authenticatorData || sha256(clientDataJSON)
            byte[] cdHash = sha256(clientDataJSON);
            byte[] signedData = new byte[authenticatorData.length + cdHash.length];
            System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
            System.arraycopy(cdHash, 0, signedData, authenticatorData.length, cdHash.length);
            ResolvedKey key;
            try {
                key = resolveKey(publicKey);
            } catch (RuntimeException e) {
                return fail("public key could not be resolved: " + errMsg(e));
            }
            boolean valid;
            if (key.alg.equals("ES256")) {
                boolean isDer = signature.length > 0 && (signature[0] & 0xff) == 0x30 && signature.length != 64;
                valid = verifyEs256(signature, signedData, key.raw, Boolean.TRUE.equals(expect.get("requireLowS")), isDer);
            } else {
                valid = Jose.verifyEd25519Strict(key.raw, signedData, signature);
            }
            if (!valid) return fail("assertion signature did not verify");

            // signature counter (clone detection), only after the signature verified
            Double stored = num(expect.get("storedSignCount"));
            if (stored == null || stored != Math.rint(stored) || Double.isInfinite(stored) || stored < 0 || (stored == 0 && 1 / stored < 0) || stored > 4294967295d) {
                return fail("storedSignCount is not a uint32");
            }
            if ((parsed.signCount != 0 || stored != 0) && parsed.signCount <= stored) {
                Object hook = expect.get("onSignCountRegression");
                if (hook instanceof Consumer) {
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("storedSignCount", expect.get("storedSignCount"));
                    info.put("reportedSignCount", parsed.signCount);
                    ((Consumer<Map<String, Object>>) hook).accept(info);
                }
                return fail("signCount did not increase (possible cloned authenticator)");
            }

            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("alg", key.alg);
            ok.put("signCount", parsed.signCount);
            Map<String, Object> flags = new LinkedHashMap<>();
            flags.put("up", parsed.up); flags.put("uv", parsed.uv); flags.put("be", parsed.be); flags.put("bs", parsed.bs); flags.put("at", parsed.at); flags.put("ed", parsed.ed);
            ok.put("flags", flags);
            return ok;
        } catch (RuntimeException e) {
            return fail("verification error (fail closed): " + errMsg(e));
        }
    }

    /** JavaScript truthiness of a parsed JSON value. */
    private static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        if (d != null) return d != 0 && !d.isNaN();
        return true;
    }
}
