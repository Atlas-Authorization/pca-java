package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Exact-outcome tests for the attestation foundation: helpers, certificate model, JWS gate, JSON.parse wording, XML/C14N, factory. */
public class AttestFoundationTest {
    private static String reason(Runnable r) {
        try {
            r.run();
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[len];
        int skip = b.length > len ? b.length - len : 0;
        System.arraycopy(b, skip, out, len - (b.length - skip), b.length - skip);
        return out;
    }

    private static byte[] sha(String alg, byte[] b) throws Exception { return MessageDigest.getInstance(alg).digest(b); }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    // ---- binding bytes

    private static byte[] lp(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(4 + b.length).putInt(b.length).put(b).array();
    }

    @Test void bindingBytesAreTheDocumentedHash() throws Exception {
        AttestationBinding b = new AttestationBinding("holder-key", "grant-1", 7, "nonce-xyz");
        byte[] msg = cat("atlas-pca/attest-bind/v1\0".getBytes(StandardCharsets.UTF_8), lp("holder-key"), lp("grant-1"),
            ByteBuffer.allocate(8).putLong(7).array(), lp("nonce-xyz"));
        assertArrayEquals(sha("SHA-512", msg), AttestCommon.attestationBindingBytes(b));
        assertEquals(64, AttestCommon.attestationBindingBytes(b).length);
        // each field matters
        byte[] base = AttestCommon.attestationBindingBytes(b);
        assertFalse(Arrays.equals(base, AttestCommon.attestationBindingBytes(new AttestationBinding("holder-kez", "grant-1", 7, "nonce-xyz"))));
        assertFalse(Arrays.equals(base, AttestCommon.attestationBindingBytes(new AttestationBinding("holder-key", "grant-2", 7, "nonce-xyz"))));
        assertFalse(Arrays.equals(base, AttestCommon.attestationBindingBytes(new AttestationBinding("holder-key", "grant-1", 8, "nonce-xyz"))));
        assertFalse(Arrays.equals(base, AttestCommon.attestationBindingBytes(new AttestationBinding("holder-key", "grant-1", 7, "nonce-xyZ"))));
    }

    @Test void bindingRefusals() {
        assertEquals("binding: holderPub required", reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("", "g", 0, "n"))));
        assertEquals("binding: grantRef required", reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "", 0, "n"))));
        assertEquals("binding: nonce required", reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 0, ""))));
        String epoch = "binding: epoch must be a non-negative safe integer";
        assertEquals(epoch, reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", -1, "n"))));
        assertEquals(epoch, reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 1.5, "n"))));
        assertEquals(epoch, reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", Double.NaN, "n"))));
        assertEquals(epoch, reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 9007199254740992d, "n"))));
        assertEquals(64, AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 9007199254740991d, "n")).length);
        assertEquals(64, AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 0, "n")).length);
    }

    // ---- small helpers

    @Test void nodeBase64() {
        assertArrayEquals(bytes(1, 2, 3), AttestCommon.nodeB64("AQID"));
        assertArrayEquals(bytes(1, 2), AttestCommon.nodeB64("AQI="));
        assertArrayEquals(AttestCommon.nodeB64("+/8"), AttestCommon.nodeB64("-_8")); // either alphabet
        assertArrayEquals(bytes(1, 2, 3), AttestCommon.nodeB64("A Q\nI!D")); // characters outside the alphabet are skipped
        assertArrayEquals(bytes(1), AttestCommon.nodeB64("AQ==AQID")); // "=" ends the data
        assertEquals(0, AttestCommon.nodeB64("").length);
    }

    @Test void claimBytes() {
        assertArrayEquals(bytes(1, 2), AttestCommon.decodeClaimBytes("0x0102"));
        assertArrayEquals(bytes(10), AttestCommon.decodeClaimBytes("0X0A"));
        assertArrayEquals(bytes(10, 11), AttestCommon.decodeClaimBytes("  0a0b\u00a0"));
        assertArrayEquals(bytes(0xab, 0xcd), AttestCommon.decodeClaimBytes("abcd")); // hex wins over base64
        assertArrayEquals(bytes(1, 2, 3), AttestCommon.decodeClaimBytes("AQID"));
        assertNull(AttestCommon.decodeClaimBytes(""));
        assertNull(AttestCommon.decodeClaimBytes("!!!"));
        assertTrue(AttestCommon.isHexString("00ff"));
        assertFalse(AttestCommon.isHexString("0"));
        assertFalse(AttestCommon.isHexString("00fg"));
        assertFalse(AttestCommon.isHexString("00ff\n")); // an anchored match would accept a final newline
        assertTrue(AttestCommon.isHexChars("abc"));
        assertFalse(AttestCommon.isHexChars(""));
    }

    @Test void jsTrimAndNumbers() {
        assertEquals("x", AttestCommon.jsTrim("\u00a0 \ufeffx\u2028\t"));
        assertEquals("\u200bx", AttestCommon.jsTrim("\u200bx")); // zero width space is not JS whitespace
        assertEquals("", AttestCommon.jsTrim("  "));
        assertEquals("5", AttestCommon.jsNumString(5));
        assertEquals("0", AttestCommon.jsNumString(0));
        assertEquals("100", AttestCommon.jsNumString(100));
        assertEquals("0.1", AttestCommon.jsNumString(0.1));
        assertEquals("-2.5", AttestCommon.jsNumString(-2.5));
        assertEquals("123456789012345680000", AttestCommon.jsNumString(1.2345678901234568e20));
        assertEquals("1e+21", AttestCommon.jsNumString(1e21));
        assertEquals("1e-7", AttestCommon.jsNumString(1e-7));
        assertEquals("1.5e-7", AttestCommon.jsNumString(1.5e-7));
        assertEquals("0.000001", AttestCommon.jsNumString(1e-6));
        assertEquals("NaN", AttestCommon.jsNumString(Double.NaN));
        assertEquals("-Infinity", AttestCommon.jsNumString(Double.NEGATIVE_INFINITY));
    }

    @Test void jsonHelpers() {
        assertEquals(12.0, AttestCommon.asFinite(new Json.Num("12")));
        assertEquals(5.0, AttestCommon.asFinite(5L));
        assertNull(AttestCommon.asFinite(new Json.Num("1e999")));
        assertNull(AttestCommon.asFinite("5"));
        assertNull(AttestCommon.asFinite(null));
        assertEquals(Arrays.asList("a", "b"), AttestCommon.asStrList(Arrays.asList("a", "b")));
        assertNull(AttestCommon.asStrList(Arrays.asList("a", 1L)));
        assertNull(AttestCommon.asStrList("a"));
        assertNull(AttestCommon.asRec(Arrays.asList(1)));
        assertNull(AttestCommon.asStr(1L));
        Object parsed = AttestCommon.jsonLenient("{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8));
        assertEquals("2", ((Map<?, ?>) parsed).get("a").toString()); // the last duplicate wins, like JSON.parse
        assertEquals("[1,2]", Json.canonicalize(AttestCommon.jsonLenient("[1, 2]".getBytes(StandardCharsets.UTF_8))));
        assertEquals("a", reason(() -> { throw new AttestException("a"); }));
        assertFalse("no error".equals(reason(() -> AttestCommon.jsonLenient("{".getBytes(StandardCharsets.UTF_8)))));
        assertFalse("no error".equals(reason(() -> AttestCommon.jsonLenient("1 2".getBytes(StandardCharsets.UTF_8)))));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("a", 1L);
        m.put("b", 2L);
        Map<String, Object> ov = new LinkedHashMap<>();
        ov.put("b", 3L);
        ov.put("c", 4L);
        assertEquals("{\"a\":1,\"b\":3,\"c\":4}", Json.canonicalize(AttestCommon.mergeOverrides(m, ov)));
        assertEquals("{\"a\":1,\"b\":2}", Json.canonicalize(m)); // not mutated
        assertEquals(Arrays.asList("abc", "de"), AttestCommon.lowerAll(Arrays.asList("ABC", "De")));
        assertEquals("1a2", AttestCommon.normSerial("001A2"));
    }

    // ---- results

    @Test void hardwareResultWire() {
        assertEquals("{\"ok\":false,\"reason\":\"nope\"}", Json.canonicalize(HardwareResult.fail("nope").wire()));
        Map<String, Object> measured = HardwareResult.newMeasured("rt", "op");
        assertEquals("{\"model_id\":\"\",\"operator\":\"op\",\"runtime_measurement\":\"rt\",\"weights_digest\":\"\",\"weights_measured\":false}", Json.canonicalize(measured));
        Map<String, String> host = new LinkedHashMap<>();
        host.put("k", "v");
        assertEquals("{\"bound\":true,\"hostAsserted\":{\"k\":\"v\"},\"measured\":" + Json.canonicalize(measured) + ",\"ok\":true}",
            Json.canonicalize(HardwareResult.ok(true, measured, host).wire()));
        assertEquals("{\"bound\":false,\"ok\":true}", Json.canonicalize(HardwareResult.ok(false, null, null).wire()));
    }

    @Test void vendorVerifierOverridesAndFailClosed() {
        Map<String, Object> ov = new LinkedHashMap<>();
        ov.put("operator", "override-op");
        VendorImpl good = (ev, expected, now) -> HardwareResult.ok(true, HardwareResult.newMeasured("rt", "op"), null);
        HardwareResult r = new VendorVerifier("azure-maa", good, ov).verify(null, null, 0);
        assertTrue(r.ok);
        assertEquals("override-op", r.measured.get("operator"));
        assertEquals("rt", r.measured.get("runtime_measurement"));
        // overrides never touch a failed answer
        VendorImpl failing = (ev, expected, now) -> HardwareResult.fail("no");
        assertEquals("no", new VendorVerifier("azure-maa", failing, ov).verify(null, null, 0).reason);
        // an exception from the implementation is a failed result carrying the vendor prefix
        VendorImpl boom = (ev, expected, now) -> { throw new IllegalStateException("kaput"); };
        HardwareResult e = new VendorVerifier("nvidia-gpu-spdm", boom, null).verify(null, null, 0);
        assertFalse(e.ok);
        assertEquals("nvidia-spdm verification error (fail closed): kaput", e.reason);
        assertEquals("amd-snp verification error (fail closed): kaput", new VendorVerifier("amd-sev-snp", boom, null).verify(null, null, 0).reason);
        assertEquals("intel-dcap verification error (fail closed): kaput", new VendorVerifier("intel-tdx-dcap", boom, null).verify(null, null, 0).reason);
        assertEquals("gcp-confidential-space verification error (fail closed): kaput", new VendorVerifier("gcp-confidential-space", boom, null).verify(null, null, 0).reason);
        assertEquals("azure-maa verification error (fail closed): kaput", new VendorVerifier("azure-maa", boom, null).verify(null, null, 0).reason);
        assertEquals("azure-maa", new VendorVerifier("azure-maa", good, null).vendor());
    }

    @Test void defaultHardwareSeam() throws Exception {
        AttestationBinding[] seen = new AttestationBinding[1];
        Map<String, Object>[] evSeen = new Map[1];
        VendorImpl impl = (ev, expected, now) -> {
            seen[0] = expected;
            evSeen[0] = ev;
            return HardwareResult.ok(true, HardwareResult.newMeasured("rt", "op"), null);
        };
        VendorVerifier v = new VendorVerifier("azure-maa", impl, null);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("nonce", "n1");
        Passport.Attestation a = new DefaultHardware(v, null).attest(5).verify(doc, new Passport.Binding("sub", "passport:id", 0, "n1"));
        assertTrue(a.ok && a.bound);
        assertEquals("op", a.measured.get("operator"));
        assertEquals("sub", seen[0].holderPub);
        assertEquals("passport:id", seen[0].grantRef);
        assertEquals(0.0, seen[0].epoch);
        assertEquals("n1", seen[0].nonce);
        assertTrue(evSeen[0] == doc); // no extractor: the evidence document itself is the vendor evidence
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("x", 1L);
        new DefaultHardware(v, d -> inner).attest(5).verify(doc, new Passport.Binding("sub", "passport:id", 0, "n1"));
        assertTrue(evSeen[0] == inner);
    }

    @Test void factoryRefusesUnknownVendors() {
        assertEquals(Arrays.asList("amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm"), AttestFactory.ATTESTATION_VENDORS);
        assertEquals("unknown attestation vendor \"nope\"", reason(() -> AttestFactory.verifierFromConfig("nope", null)));
        assertEquals("unknown attestation vendor \"\"", reason(() -> AttestFactory.verifierFromConfig("", new LinkedHashMap<>())));
    }

    // ---- Azure runtime-data binding

    private static byte[] reportDataFor(byte[] runtime) throws Exception {
        byte[] rd = new byte[64];
        System.arraycopy(sha("SHA-256", runtime), 0, rd, 0, 32);
        return rd;
    }

    @Test void azureRuntimeDataBinding() throws Exception {
        AttestationBinding b = new AttestationBinding("holder", "grant", 3, "nonce");
        String hex = AttestCommon.toHexLower(AttestCommon.attestationBindingBytes(b));
        byte[] runtime = ("{\"user-data\":\"" + hex + "\",\"extra\":1}").getBytes(StandardCharsets.UTF_8);
        byte[] rd = reportDataFor(runtime);
        assertEquals("", AttestCommon.checkAzureRuntimeDataBinding(rd, runtime, b));
        assertEquals("report_data is not 64 bytes", AttestCommon.checkAzureRuntimeDataBinding(Arrays.copyOf(rd, 63), runtime, b));
        byte[] tail = rd.clone();
        tail[63] = 1;
        assertEquals("report_data[32:64] is not zero (not an Azure runtime-data hash)", AttestCommon.checkAzureRuntimeDataBinding(tail, runtime, b));
        byte[] wrongHash = rd.clone();
        wrongHash[0] ^= 1;
        assertEquals("sha256(runtime data) does not equal the quote report_data", AttestCommon.checkAzureRuntimeDataBinding(wrongHash, runtime, b));
        byte[] notJson = "xx".getBytes(StandardCharsets.UTF_8);
        assertEquals("runtime data is not valid JSON", AttestCommon.checkAzureRuntimeDataBinding(reportDataFor(notJson), notJson, b));
        byte[] arr = "[]".getBytes(StandardCharsets.UTF_8);
        assertEquals("runtime data is not a JSON object", AttestCommon.checkAzureRuntimeDataBinding(reportDataFor(arr), arr, b));
        byte[] shortUd = "{\"user-data\":\"00ff\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals("runtime data carries no 64-byte hex user-data", AttestCommon.checkAzureRuntimeDataBinding(reportDataFor(shortUd), shortUd, b));
        byte[] numUd = "{\"user-data\":5}".getBytes(StandardCharsets.UTF_8);
        assertEquals("runtime data carries no 64-byte hex user-data", AttestCommon.checkAzureRuntimeDataBinding(reportDataFor(numUd), numUd, b));
        AttestationBinding other = new AttestationBinding("holder", "grant", 3, "other-nonce");
        assertEquals("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)", AttestCommon.checkAzureRuntimeDataBinding(rd, runtime, other));
        assertEquals("binding not constructible: binding: holderPub required",
            AttestCommon.checkAzureRuntimeDataBinding(rd, runtime, new AttestationBinding("", "grant", 3, "nonce")));
        // upper-case hex is hex
        byte[] upper = ("{\"user-data\":\"" + hex.toUpperCase() + "\"}").getBytes(StandardCharsets.UTF_8);
        assertEquals("", AttestCommon.checkAzureRuntimeDataBinding(reportDataFor(upper), upper, b));
    }

    // ---- JWS gate

    @Test void canonicalBase64url() {
        assertArrayEquals(bytes(1, 2, 3), AttestJws.decodeCanonicalBase64url("AQID"));
        assertArrayEquals(bytes(1), AttestJws.decodeCanonicalBase64url("AQ"));
        assertEquals(0, AttestJws.decodeCanonicalBase64url("").length);
        assertEquals("non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.decodeCanonicalBase64url("AR")));
        assertEquals("non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.decodeCanonicalBase64url("AQJ")));
        assertEquals("non-canonical compact JWS: non-canonical-base64url (impossible length)", reason(() -> AttestJws.decodeCanonicalBase64url("A")));
        assertEquals("non-canonical compact JWS: non-canonical-base64url (impossible length)", reason(() -> AttestJws.decodeCanonicalBase64url("AQIDA")));
        assertEquals("non-canonical compact JWS: bad-character", reason(() -> AttestJws.decodeCanonicalBase64url("a+b")));
        assertEquals("non-canonical compact JWS: bad-character", reason(() -> AttestJws.decodeCanonicalBase64url("AQ=")));
        assertEquals("non-canonical compact JWS: bad-character", reason(() -> AttestJws.decodeCanonicalBase64url("AQ\n")));
    }

    private static String seg(String json) { return b64u(json.getBytes(StandardCharsets.UTF_8)); }

    @SuppressWarnings("unchecked")
    @Test void parseJwtFields() {
        String h = seg("{\"alg\":\"ES256\",\"kid\":\"k1\",\"x5c\":[\"a\",\"b\"]}");
        String p = seg("{\"x\":1}");
        AttestJws.JwtParsed t = AttestJws.parseJwt(h + "." + p + "." + b64u(bytes(1, 2, 3)), "P");
        assertEquals("ES256", t.alg);
        assertTrue(t.hasKid);
        assertEquals("k1", t.kid);
        assertTrue(t.hasX5c);
        assertEquals(Arrays.asList("a", "b"), t.x5c);
        assertEquals("{\"x\":1}", Json.canonicalize(t.payload));
        assertArrayEquals(bytes(1, 2, 3), t.signature);
        assertArrayEquals((h + "." + p).getBytes(StandardCharsets.UTF_8), t.signingInput);
        String sig = b64u(bytes(9));
        AttestJws.JwtParsed none = AttestJws.parseJwt(seg("{\"alg\":\"RS256\",\"kid\":5,\"x5c\":[\"a\",1]}") + "." + p + "." + sig, "P");
        assertFalse(none.hasKid);
        assertFalse(none.hasX5c);
        assertNull(none.x5c);
    }

    @Test void parseJwtRefusals() {
        String p = seg("{\"x\":1}");
        String h = seg("{\"alg\":\"ES256\"}");
        String s = b64u(bytes(1));
        assertEquals("P: empty token", reason(() -> AttestJws.parseJwt("", "P")));
        assertEquals("P: a compact JWS has exactly three dot-separated parts", reason(() -> AttestJws.parseJwt("a.b", "P")));
        assertEquals("P: a compact JWS has exactly three dot-separated parts", reason(() -> AttestJws.parseJwt("a.b.c.d", "P")));
        assertEquals("P: empty JWS segment", reason(() -> AttestJws.parseJwt("a..c", "P")));
        assertEquals("P: empty JWS segment", reason(() -> AttestJws.parseJwt(".b.c", "P")));
        assertEquals("P: empty JWS segment", reason(() -> AttestJws.parseJwt("a.b.", "P")));
        assertEquals("P: header is not a JSON object", reason(() -> AttestJws.parseJwt(seg("[]") + "." + p + "." + s, "P")));
        assertEquals("P: payload is not a JSON object", reason(() -> AttestJws.parseJwt(h + "." + seg("1") + "." + s, "P")));
        assertEquals("P: header has no alg", reason(() -> AttestJws.parseJwt(seg("{}") + "." + p + "." + s, "P")));
        assertEquals("P: header has no alg", reason(() -> AttestJws.parseJwt(seg("{\"alg\":\"\"}") + "." + p + "." + s, "P")));
        assertEquals("P: header has no alg", reason(() -> AttestJws.parseJwt(seg("{\"alg\":5}") + "." + p + "." + s, "P")));
        assertEquals("P: malformed JSON segment: Expected property name or '}' in JSON at position 1 (line 1 column 2)",
            reason(() -> AttestJws.parseJwt(seg("{") + "." + p + "." + s, "P")));
        assertEquals("P: malformed JSON segment: Unexpected token ']', \"[1,]\" is not valid JSON",
            reason(() -> AttestJws.parseJwt(h + "." + seg("[1,]") + "." + s, "P")));
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.parseJwt("AR." + p + "." + s, "P")));
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: bad-character", reason(() -> AttestJws.parseJwt(h + ".a+b." + s, "P")));
        assertEquals("P: malformed signature segment: non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.parseJwt(h + "." + p + ".AR", "P")));
        // an invalid header is reported before a bad payload
        assertEquals("P: malformed JSON segment: Unexpected end of JSON input", reason(() -> AttestJws.parseJwt(seg("nul") + "." + seg("{") + "." + s, "P")));
    }

    // ---- JSON.parse wording

    @Test void v8Wording() {
        assertEquals("", AttestV8Json.v8JsonError("{\"a\":[1,2.5e3,-0,true,false,null,\"x\\u00e9\\n\"]}"));
        assertEquals("", AttestV8Json.v8JsonError(" \t\r\n1 "));
        assertEquals("Unexpected end of JSON input", AttestV8Json.v8JsonError(""));
        assertEquals("Unexpected end of JSON input", AttestV8Json.v8JsonError("nul"));
        assertEquals("Expected property name or '}' in JSON at position 1 (line 1 column 2)", AttestV8Json.v8JsonError("{"));
        assertEquals("Expected property name or '}' in JSON at position 1 (line 1 column 2)", AttestV8Json.v8JsonError("{1:2}"));
        assertEquals("Unexpected token ']', \"[1,]\" is not valid JSON", AttestV8Json.v8JsonError("[1,]"));
        assertEquals("Unexpected number in JSON at position 1 (line 1 column 2)", AttestV8Json.v8JsonError("01"));
        assertEquals("No number after minus sign in JSON at position 1 (line 1 column 2)", AttestV8Json.v8JsonError("-"));
        assertEquals("Unterminated fractional number in JSON at position 2 (line 1 column 3)", AttestV8Json.v8JsonError("1."));
        assertEquals("Exponent part is missing a number in JSON at position 2 (line 1 column 3)", AttestV8Json.v8JsonError("1e"));
        assertEquals("Exponent part is missing a number in JSON at position 3 (line 1 column 4)", AttestV8Json.v8JsonError("1e+"));
        assertEquals("Unterminated string in JSON at position 2 (line 1 column 3)", AttestV8Json.v8JsonError("\"a"));
        assertEquals("Bad control character in string literal in JSON at position 1 (line 1 column 2)", AttestV8Json.v8JsonError("\"\u0001\""));
        assertEquals("Bad escaped character in JSON at position 2 (line 1 column 3)", AttestV8Json.v8JsonError("\"\\x\""));
        assertEquals("Bad Unicode escape in JSON at position 4 (line 1 column 5)", AttestV8Json.v8JsonError("\"\\u0g\""));
        assertEquals("Unterminated string in JSON at position 2 (line 1 column 3)", AttestV8Json.v8JsonError("\"\\"));
        assertEquals("Unexpected non-whitespace character after JSON at position 3 (line 1 column 4)", AttestV8Json.v8JsonError("{} x"));
        assertEquals("Expected ':' after property name in JSON at position 6 (line 2 column 5)", AttestV8Json.v8JsonError("{\n\"a\" 1}"));
        assertEquals("Expected ',' or '}' after property value in JSON at position 7 (line 1 column 8)", AttestV8Json.v8JsonError("{\"a\":1 2}"));
        assertEquals("Expected double-quoted property name in JSON at position 7 (line 1 column 8)", AttestV8Json.v8JsonError("{\"a\":1,}"));
        assertEquals("Expected ',' or ']' after array element in JSON at position 3 (line 1 column 4)", AttestV8Json.v8JsonError("[1 2]"));
        assertEquals("\"NaN\" is not valid JSON", AttestV8Json.v8JsonError("NaN"));
        assertEquals("\"undefined\" is not valid JSON", AttestV8Json.v8JsonError("undefined"));
        assertEquals("\"[object Object]\" is not valid JSON", AttestV8Json.v8JsonError("[object Object]"));
        // the context window of an unexpected token: short documents quote everything, long ones an ellipsis on the cut side
        assertEquals("Unexpected token 'x', \"x\" is not valid JSON", AttestV8Json.v8JsonError("x"));
        assertEquals("Unexpected token 'x', \"x234567890\"... is not valid JSON", AttestV8Json.v8JsonError("x2345678901234567890123"));
        String mid = "[0,0,0,0,0,0,0,x,0,0,0,0,0,0,0]";
        int mp = mid.indexOf('x');
        assertEquals("Unexpected token 'x', ...\"" + mid.substring(mp - 10, mp + 10) + "\"... is not valid JSON", AttestV8Json.v8JsonError(mid));
        String tail = "[0,0,0,0,0,0,0,0,0,0,0,x";
        int tp = tail.indexOf('x');
        assertEquals("Unexpected token 'x', ...\"" + tail.substring(tp - 10) + "\" is not valid JSON", AttestV8Json.v8JsonError(tail));
    }

    // ---- keys

    private static String jwkCoord(BigInteger v, int len) { return b64u(unsigned(v, len)); }

    @Test void ecJwkAndEs256() throws Exception {
        KeyPair kp = ecKey("secp256r1");
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        String x = jwkCoord(pub.getW().getAffineX(), 32);
        String y = jwkCoord(pub.getW().getAffineY(), 32);
        CertKey k = AttestJws.jwkEcKey("P-256", x, y);
        assertEquals("ec", k.typ);
        assertEquals("prime256v1", k.curve);
        assertArrayEquals(pub.getEncoded(), k.spki);
        assertEquals(AttestCommon.toHexLower(sha("SHA-256", pub.getEncoded())), k.spkiSha256());
        assertEquals(AttestCommon.toHexLower(sha("SHA-384", pub.getEncoded())), k.spkiSha384());
        assertArrayEquals(new String[] {"EC", "P-256"}, AttestJws.jwkKtyCrv(k));
        byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(kp.getPrivate());
        s.update(input);
        byte[] sig = s.sign();
        assertEquals(64, sig.length);
        assertTrue(AttestJws.jwsEs256Ok(sig, input, k));
        assertFalse(AttestJws.jwsEs256Ok(sig, "header.payloaD".getBytes(StandardCharsets.UTF_8), k));
        byte[] flipped = sig.clone();
        flipped[10] ^= 1;
        assertFalse(AttestJws.jwsEs256Ok(flipped, input, k));
        assertFalse(AttestJws.jwsEs256Ok(Arrays.copyOf(sig, 63), input, k));
        assertFalse(AttestJws.jwsEs256Ok(Arrays.copyOf(sig, 65), input, k));
        assertFalse(AttestJws.jwsRs256Ok(sig, input, k)); // an EC key is not an RS256 key
        // off the curve / unsupported curve
        String y2 = jwkCoord(pub.getW().getAffineY().xor(BigInteger.ONE), 32);
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("P-256", x, y2)));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("P-224", x, y)));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("secp256k1", x, y)));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("P-384", x, y)));
        // a P-384 key is not an ES256 key
        KeyPair kp384 = ecKey("secp384r1");
        ECPublicKey p384 = (ECPublicKey) kp384.getPublic();
        CertKey k384 = AttestJws.jwkEcKey("P-384", jwkCoord(p384.getW().getAffineX(), 48), jwkCoord(p384.getW().getAffineY(), 48));
        assertEquals("secp384r1", k384.curve);
        assertArrayEquals(new String[] {"EC", "P-384"}, AttestJws.jwkKtyCrv(k384));
        assertFalse(AttestJws.jwsEs256Ok(sig, input, k384));
    }

    @Test void rsaJwkAndRs256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        CertKey k = AttestJws.jwkRsaKey(b64u(unsigned(pub.getModulus(), 256)), b64u(pub.getPublicExponent().toByteArray()));
        assertEquals("rsa", k.typ);
        assertArrayEquals(pub.getEncoded(), k.spki);
        assertArrayEquals(new String[] {"RSA", "undefined"}, AttestJws.jwkKtyCrv(k));
        byte[] input = "a.b".getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(input);
        byte[] sig = s.sign();
        assertTrue(AttestJws.jwsRs256Ok(sig, input, k));
        assertFalse(AttestJws.jwsRs256Ok(sig, "a.c".getBytes(StandardCharsets.UTF_8), k));
        assertFalse(AttestJws.jwsRs256Ok(Arrays.copyOf(sig, 255), input, k));
        assertFalse(AttestJws.jwsEs256Ok(sig, input, k));
        String n = b64u(unsigned(pub.getModulus(), 256));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey("", "AQAB")));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, "")));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, b64u(bytes(1))))); // e = 1
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, b64u(bytes(2))))); // e = 2
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, b64u(bytes(0x80, 0, 0, 0))))); // e = 2^31
    }

    @Test void rawEcdsaAndPoints() throws Exception {
        for (String curve : new String[] {"secp256r1", "secp384r1"}) {
            KeyPair kp = ecKey(curve);
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
            Signature s = Signature.getInstance("SHA384withECDSAinP1363Format");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            byte[] digest = sha("SHA-384", msg);
            assertTrue(AttestCommon.verifyRawECDSA(pub, digest, sig), curve);
            byte[] other = digest.clone();
            other[0] ^= 1;
            assertFalse(AttestCommon.verifyRawECDSA(pub, other, sig), curve);
            assertFalse(AttestCommon.verifyRawECDSA(pub, digest, Arrays.copyOf(sig, sig.length - 1)), curve);
            assertFalse(AttestCommon.verifyRawECDSA(pub, digest, new byte[0]), curve);
            byte[] flip = sig.clone();
            flip[3] ^= 0x40;
            assertFalse(AttestCommon.verifyRawECDSA(pub, digest, flip), curve);
        }
        KeyPair kp = ecKey("secp256r1");
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] point = AttestCommon.ecPointOfKey(AttestCert.keyOfCert(AttestCert.parseCertDer(cert("p", "p", kp, kp))), "P-256");
        assertEquals(65, point.length);
        assertEquals(4, point[0]);
        assertArrayEquals(unsigned(pub.getW().getAffineX(), 32), Arrays.copyOfRange(point, 1, 33));
        assertArrayEquals(unsigned(pub.getW().getAffineY(), 32), Arrays.copyOfRange(point, 33, 65));
        ECPublicKey back = AttestCommon.pointToKey("P-256", point);
        assertNotNull(back);
        assertEquals(pub.getW(), back.getW());
        byte[] offCurve = point.clone();
        offCurve[64] ^= 1;
        assertNull(AttestCommon.pointToKey("P-256", offCurve));
        assertNull(AttestCommon.pointToKey("P-256", Arrays.copyOf(point, 64)));
        byte[] compressedTag = point.clone();
        compressedTag[0] = 2;
        assertNull(AttestCommon.pointToKey("P-256", compressedTag));
        assertNull(AttestCommon.pointToKey("P-384", point));
        assertEquals("P-256", AttestCommon.ecCurveName(pub.getParams()));
        assertEquals("prime256v1", AttestCommon.curveOpenSslName(pub.getParams()));
        assertEquals("public key is not on P-384 (got P-256)", reason(() -> AttestCommon.ecPointOfKey(CertKey.of(pub, pub.getEncoded()), "P-384")));
    }

    // ---- certificates

    private static byte[] aia(String url) {
        return ext("1.3.6.1.5.5.7.1.1", false, seq(seq(oid("1.3.6.1.5.5.7.48.1"), withTag(0x86, url.getBytes(StandardCharsets.US_ASCII)))));
    }

    private static byte[] ekuOcsp() { return ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.9"))); }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\n-----END CERTIFICATE-----\n";
    }

    @Test void certificateModel() throws Exception {
        KeyPair root = ecKey("secp256r1");
        KeyPair leaf = ecKey("secp256r1");
        byte[] rootDer = cert("Root", "Root", root, root, basicConstraints(true, -1), keyUsageCertSign());
        byte[] leafDer = cert("Leaf", "Root", leaf, root, aia("http://ocsp.example/x"), ekuOcsp());
        AttCert r = AttestCert.parseCertDer(rootDer);
        AttCert l = AttestCert.parseCertDer(leafDer);
        assertArrayEquals(rootDer, r.raw);
        assertArrayEquals(AttestDer.tbsOfCertificate(rootDer), r.rawTbs);
        assertEquals("1.2.840.10045.4.3.2", r.sigOid);
        assertNull(r.sigParams);
        assertTrue(r.selfIssued());
        assertFalse(l.selfIssued());
        assertEquals("102", r.serialHex());
        assertArrayEquals(root.getPublic().getEncoded(), r.rawSpki);
        assertArrayEquals(name("Root"), r.rawSubject);
        assertArrayEquals(name("Root"), l.rawIssuer);
        assertEquals("CN=Root", AttestCommon.nameText(r.rawSubject));
        CertKey rk = AttestCert.keyOfCert(r);
        assertEquals("ec", rk.typ);
        assertEquals("prime256v1", rk.curve);
        assertTrue(AttestCert.certSigOk(r, rk));
        assertTrue(AttestCert.certSigOkBy(l, r));
        assertFalse(AttestCert.certSigOkBy(r, l));
        assertFalse(AttestCert.certSigOkBy(AttestCert.parseCertDer(cert("Leaf", "Root", leaf, leaf)), r)); // signed by the wrong key
        assertEquals(Arrays.asList("http://ocsp.example/x"), l.ocspServers());
        assertTrue(l.hasOcspSigningEku());
        assertTrue(r.ocspServers().isEmpty());
        assertFalse(r.hasOcspSigningEku());
        assertNotNull(l.extValue("1.3.6.1.5.5.7.1.1"));
        assertNull(l.extValue("9.9.9"));
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leafDer, rootDer)));
        // trailing bytes after the certificate are ignored by d2i, refused by the strict readers
        byte[] padded = Arrays.copyOf(rootDer, rootDer.length + 1);
        assertArrayEquals(rootDer, AttestCert.parseCertDer(padded).raw);
        assertEquals("trailing bytes after the certificate", reason(() -> AttestDer.tbsOfCertificate(padded)));
        // a duplicated extension parses (lenient) but the strict table refuses it
        byte[] dup = cert("Dup", "Dup", root, root, basicConstraints(true, -1), basicConstraints(true, -1));
        assertNotNull(AttestCert.parseCertDer(dup));
        assertEquals("duplicate extension 2.5.29.19", reason(() -> AttestDer.parseCertExtensions(dup)));
        // the P-256 point
        byte[] point = AttestCommon.ecPointOfKey(rk, "P-256");
        assertEquals(65, point.length);
    }

    @Test void certificateParseRefusals() {
        KeyPair k = ecKey("secp256r1");
        byte[] der = cert("C", "C", k, k, basicConstraints(true, -1));
        byte[] tbs = AttestDer.tbsOfCertificate(der);
        assertEquals("error:0680007B:asn1 encoding routines::not enough data", reason(() -> AttestCert.parseCertDer(new byte[0])));
        assertEquals("error:068000A8:asn1 encoding routines::wrong tag", reason(() -> AttestCert.parseCertDer(integer(1))));
        assertEquals("error:068000A8:asn1 encoding routines::wrong tag", reason(() -> AttestCert.parseCertDer(seq(integer(1)))));
        assertEquals("error:0680007D:asn1 encoding routines::invalid bit string bits left",
            reason(() -> AttestCert.parseCertDer(seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 8, new byte[] {1})))));
        assertEquals("error:068000A8:asn1 encoding routines::wrong tag",
            reason(() -> AttestCert.parseCertDer(seq(tbs, SIG_ALG_ECDSA_SHA256, octets(new byte[] {1})))));
        assertEquals("error:0688010A:asn1 encoding routines::nested asn1 error",
            reason(() -> AttestCert.parseCertDer(seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1}), bytes(0x05, 0x00)))));
        // an empty serial
        byte[] emptySerial = seq(withTag(0xa0, integer(2)), withTag(0x02), SIG_ALG_ECDSA_SHA256, name("C"),
            seq(withTag(0x17, "250101000000Z".getBytes(StandardCharsets.US_ASCII)), withTag(0x17, "350101000000Z".getBytes(StandardCharsets.US_ASCII))),
            name("C"), k.getPublic().getEncoded());
        assertEquals("error:0688010A:asn1 encoding routines::illegal zero content",
            reason(() -> AttestCert.parseCertDer(seq(emptySerial, SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1})))));
        // a Name whose value is not a string type
        byte[] badName = seq(withTag(0x31, seq(oid("2.5.4.3"), integer(5))));
        byte[] badNameTbs = seq(withTag(0xa0, integer(2)), integer(1), SIG_ALG_ECDSA_SHA256, badName,
            seq(withTag(0x17, "250101000000Z".getBytes(StandardCharsets.US_ASCII)), withTag(0x17, "350101000000Z".getBytes(StandardCharsets.US_ASCII))),
            name("C"), k.getPublic().getEncoded());
        assertEquals("error:0688010A:asn1 encoding routines::nested asn1 error",
            reason(() -> AttestCert.parseCertDer(seq(badNameTbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1})))));
    }

    @Test void pemHandling() {
        KeyPair k = ecKey("secp256r1");
        byte[] a = cert("A", "A", k, k);
        byte[] b = cert("B", "B", k, k);
        String two = pem(a) + "noise\n" + pem(b);
        List<String> blocks = AttestCommon.pemCertBlocks(two);
        assertEquals(2, blocks.size());
        assertArrayEquals(a, AttestCert.certFromPem(two).raw); // the first block
        assertArrayEquals(b, AttestCert.certFromPem(blocks.get(1)).raw);
        assertEquals("error:0480006C:PEM routines::no start line", reason(() -> AttestCert.certFromPem("not a certificate")));
        assertEquals("error:0688010A:asn1 encoding routines::nested asn1 error", reason(() -> AttestCert.certFromPem(pem(Arrays.copyOf(a, a.length + 1)))));
        assertEquals("error:1E08010C:DECODER routines::unsupported",
            reason(() -> AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")));
        assertEquals("error:1E08010C:DECODER routines::unsupported",
            reason(() -> AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\nAQID\nAQI\n-----END CERTIFICATE-----"))); // padding missing
        assertTrue(AttestCommon.pemCertBlocks("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----").isEmpty());
    }

    // ---- names

    private static byte[] rdn(String oid, String value) { return withTag(0x31, seq(oid(oid), utf8(value))); }

    @Test void nameRendering() {
        assertEquals("CN=Test CA", AttestCommon.nameText(name("Test CA")));
        assertEquals("CN=a\nO=A\\,B\nOU=x\\+y", AttestCommon.nameText(seq(rdn("2.5.4.3", "a"), rdn("2.5.4.10", "A,B"), rdn("2.5.4.11", "x+y"))));
        assertEquals("CN=a + OU=b", AttestCommon.nameText(seq(withTag(0x31, seq(oid("2.5.4.3"), utf8("a")), seq(oid("2.5.4.11"), utf8("b"))))));
        assertEquals("1.2.3.4=x", AttestCommon.nameText(seq(rdn("1.2.3.4", "x"))));
        assertEquals("emailAddress=a@b", AttestCommon.nameText(seq(rdn("1.2.840.113549.1.9.1", "a@b"))));
        assertEquals("CN=\\ x\\ ", AttestCommon.nameText(seq(rdn("2.5.4.3", " x "))));
        assertEquals("CN=\\#x", AttestCommon.nameText(seq(rdn("2.5.4.3", "#x"))));
        assertEquals("CN=a\\01b", AttestCommon.nameText(seq(rdn("2.5.4.3", "a\u0001b"))));
        assertEquals("CN=\\\"q\\\"\\<\\>\\;\\\\", AttestCommon.nameText(seq(rdn("2.5.4.3", "\"q\"<>;\\"))));
        assertEquals("CN=\u00e9", AttestCommon.nameText(seq(rdn("2.5.4.3", "\u00e9"))));
        assertEquals("CN=ab", AttestCommon.nameText(seq(withTag(0x31, seq(oid("2.5.4.3"), withTag(0x13, "ab".getBytes(StandardCharsets.US_ASCII)))))));
        assertEquals("", AttestCommon.nameText(seq(withTag(0x31, seq(oid("2.5.4.3"), withTag(0x13, "a@b".getBytes(StandardCharsets.US_ASCII)))))));
        assertEquals("", AttestCommon.nameText(new byte[] {1, 2}));
        assertEquals("", AttestCommon.nameText(cat(name("x"), bytes(0))));
        assertEquals("", AttestCommon.nameText(seq(seq())));
        assertEquals("", AttestCommon.nameText(seq()));
    }

    // ---- XML / C14N

    @Test void xmlCanonicalForm() {
        AttestXml.Doc d = AttestXml.parseXml("<a xmlns=\"u\" b=\"2\" a=\"1\"><c>t&amp;&lt;&#x41;</c><d/></a>");
        assertEquals("", d.violation);
        assertEquals("<a xmlns=\"u\" a=\"1\" b=\"2\"><c>t&amp;&lt;A</c><d></d></a>", AttestXml.canonicalize(d.root, new LinkedHashMap<String, String>(), null));
        assertEquals("u", d.root.ns);
        assertEquals("a", d.root.local);
        assertEquals("u", d.root.elementChildren().get(0).ns);
        assertEquals("t&<A", d.root.elementChildren().get(0).textContent());
        assertEquals("2", d.root.attr("b"));
        assertEquals("", d.root.attr("zz"));
    }

    @Test void xmlNamespacesAndAttributeOrder() {
        AttestXml.Doc d = AttestXml.parseXml("<p:a xmlns:q=\"v\" xmlns:p=\"u\" z=\"1\" q:y=\"2\" p:x=\"3\"><p:b/><q:c xmlns:q=\"w\"/></p:a>");
        assertEquals("<p:a xmlns:p=\"u\" xmlns:q=\"v\" z=\"1\" p:x=\"3\" q:y=\"2\"><p:b></p:b><q:c xmlns:q=\"w\"></q:c></p:a>",
            AttestXml.canonicalize(d.root, new LinkedHashMap<String, String>(), null));
        AttestXml.Node b = d.root.elementChildren().get(0);
        assertEquals("u", b.ns);
        assertEquals(1, d.root.elementChildrenNs("u", "b").size());
        assertEquals(0, d.root.elementChildrenNs("v", "b").size());
        assertEquals(2, d.root.descendantsNs("u", "b") + d.root.descendantsNs("w", "c"));
        Map<String, String> scope = b.scope();
        assertEquals("u", scope.get("p"));
        assertEquals("v", scope.get("q"));
        // an apex element renders every in-scope namespace of its ancestors
        assertEquals("<p:b xmlns:p=\"u\" xmlns:q=\"v\"></p:b>", AttestXml.canonicalize(b, d.root.scope(), null));
    }

    @Test void xmlEnvelopedSkipAndRemove() {
        AttestXml.Doc d = AttestXml.parseXml("<r><s>1</s><t>2</t></r>");
        AttestXml.Node s = d.root.elementChildren().get(0);
        assertEquals("<r><t>2</t></r>", AttestXml.canonicalize(d.root, new LinkedHashMap<String, String>(), s));
        d.root.removeChild(s);
        assertEquals("<r><t>2</t></r>", AttestXml.canonicalize(d.root, new LinkedHashMap<String, String>(), null));
    }

    @Test void xmlEscapingAndCdata() {
        AttestXml.Doc d = AttestXml.parseXml("<a q=\"&quot;&#x9;&#xA;&#xD;&amp;&lt;\">x<![CDATA[<y>&]]>z\r\n&gt;</a>");
        assertEquals("<a q=\"&quot;&#x9;&#xA;&#xD;&amp;&lt;\">x&lt;y&gt;&amp;z&#xD;\n&gt;</a>", AttestXml.canonicalize(d.root, new LinkedHashMap<String, String>(), null));
    }

    @Test void xmlProfileViolations() {
        assertEquals("XML comments are not permitted", AttestXml.parseXml("<a><!-- c --></a>").violation);
        assertEquals("XML processing instructions are not permitted", AttestXml.parseXml("<?pi x?><a/>").violation);
        assertEquals("DTD / DOCTYPE is not permitted", AttestXml.parseXml("<!DOCTYPE a [<!ENTITY e \"x\">]><a/>").violation);
        assertEquals("xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)", AttestXml.parseXml("<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" xml:lang=\"en\"/>").violation);
        // the FIRST violation in document order is the one recorded
        assertEquals("XML comments are not permitted", AttestXml.parseXml("<!-- c --><?pi?><a/>").violation);
        assertEquals("XML processing instructions are not permitted", AttestXml.parseXml("<?pi?><!-- c --><a/>").violation);
        assertEquals("", AttestXml.parseXml("<a><b/></a>").violation);
    }

    @Test void xmlRefusals() {
        assertEquals("namespace prefix xml is not bound", reason(() -> AttestXml.parseXml("<a xml:lang=\"en\"/>")));
        assertEquals("end tag </b> does not match <a>", reason(() -> AttestXml.parseXml("<a></b>")));
        assertEquals("element <a> is not closed", reason(() -> AttestXml.parseXml("<a>")));
        assertEquals("no document element", reason(() -> AttestXml.parseXml("  ")));
        assertEquals("more than one document element", reason(() -> AttestXml.parseXml("<a/><b/>")));
        assertEquals("text outside the document element", reason(() -> AttestXml.parseXml("x<a/>")));
        assertEquals("text outside the document element", reason(() -> AttestXml.parseXml("<a/>x")));
        assertEquals("namespace prefix p is not bound", reason(() -> AttestXml.parseXml("<p:a/>")));
        assertEquals("namespace prefix q is not bound", reason(() -> AttestXml.parseXml("<a q:x=\"1\"/>")));
        assertEquals("attribute x is repeated", reason(() -> AttestXml.parseXml("<a x=\"1\" x=\"2\"/>")));
        assertEquals("unquoted attribute value", reason(() -> AttestXml.parseXml("<a x=1/>")));
        assertEquals("unterminated attribute value", reason(() -> AttestXml.parseXml("<a x=\"1/>")));
        assertEquals("'<' in an attribute value", reason(() -> AttestXml.parseXml("<a x=\"<\"/>")));
        assertEquals("malformed attribute", reason(() -> AttestXml.parseXml("<a x/>")));
        assertEquals("malformed start tag", reason(() -> AttestXml.parseXml("<a / >")));
        assertEquals("malformed start tag", reason(() -> AttestXml.parseXml("< a/>")));
        assertEquals("unterminated start tag", reason(() -> AttestXml.parseXml("<a x=\"1\"")));
        assertEquals("unterminated comment", reason(() -> AttestXml.parseXml("<a><!-- x</a>")));
        assertEquals("unterminated processing instruction", reason(() -> AttestXml.parseXml("<a><? x</a>")));
        assertEquals("unterminated DOCTYPE", reason(() -> AttestXml.parseXml("<!DOCTYPE a")));
        assertEquals("misplaced or unterminated CDATA section", reason(() -> AttestXml.parseXml("<a><![CDATA[x</a>")));
        assertEquals("misplaced or unterminated CDATA section", reason(() -> AttestXml.parseXml("<![CDATA[x]]><a/>")));
        assertEquals("unexpected end tag", reason(() -> AttestXml.parseXml("</a>")));
        assertEquals("undefined entity &foo;", reason(() -> AttestXml.parseXml("<a>&foo;</a>")));
        assertEquals("unterminated entity reference", reason(() -> AttestXml.parseXml("<a>&amp</a>")));
        assertEquals("invalid character reference &#0;", reason(() -> AttestXml.parseXml("<a>&#0;</a>")));
        assertEquals("invalid character reference &#xD800;", reason(() -> AttestXml.parseXml("<a>&#xD800;</a>")));
        assertEquals("invalid character reference &#x110000;", reason(() -> AttestXml.parseXml("<a>&#x110000;</a>")));
        assertEquals("invalid character reference &#+65;", reason(() -> AttestXml.parseXml("<a>&#+65;</a>")));
        assertEquals("invalid character reference &#;", reason(() -> AttestXml.parseXml("<a>&#;</a>")));
        assertEquals("invalid character reference &#X41;", reason(() -> AttestXml.parseXml("<a>&#X41;</a>")));
        assertEquals("A", AttestXml.parseXml("<a>&#65;</a>").root.textContent());
        assertEquals("A", AttestXml.parseXml("<a>&#x41;</a>").root.textContent());
        assertEquals("A", AttestXml.parseXml("<a>&#0000000065;</a>").root.textContent());
        assertEquals("\ud83d\ude00", AttestXml.parseXml("<a>&#x1F600;</a>").root.textContent());
        assertEquals("a b", AttestXml.parseXml("<a x=\"1\" >a b</a >").root.textContent());
    }

    @Test void curvesAndHashesSelfCheck() throws Exception {
        List<String> names = new ArrayList<>();
        for (String c : new String[] {"secp256r1", "secp384r1", "secp521r1"}) names.add(AttestCommon.ecCurveName(((ECPublicKey) ecKey(c).getPublic()).getParams()));
        assertEquals(Arrays.asList("P-256", "P-384", "P-521"), names);
        assertArrayEquals(sha("SHA-256", bytes(1)), AttestCommon.sha256Sum(bytes(1)));
        assertArrayEquals(sha("SHA-384", bytes(1)), AttestCommon.sha384Sum(bytes(1)));
        assertArrayEquals(sha("SHA-512", bytes(1)), AttestCommon.sha512Sum(bytes(1)));
        assertTrue(AttestCommon.timingSafeEq(bytes(1, 2), bytes(1, 2)));
        assertFalse(AttestCommon.timingSafeEq(bytes(1, 2), bytes(1, 3)));
        assertFalse(AttestCommon.timingSafeEq(bytes(1, 2), bytes(1)));
        assertEquals("00ff", AttestCommon.toHexLower(bytes(0, 255)));
        assertArrayEquals(bytes(0, 255, 0xab), AttestCommon.hexDecode("00FFab"));
    }
}
