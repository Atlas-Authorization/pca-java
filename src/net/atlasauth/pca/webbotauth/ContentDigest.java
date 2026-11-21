package net.atlasauth.pca.webbotauth;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RFC 9530 Content-Digest: the dictionary field whose members are hash algorithm names with byte-sequence values over the message content.
 * Only sha-256 and sha-512 (the algorithms the RFC marks Active) are produced or accepted. Cover {@code content-digest} in the signature so
 * it protects the body too; {@link #verifyContentDigest} then checks the body against the covered field and FAILS CLOSED.
 */
public final class ContentDigest {
    private ContentDigest() {}

    public static final List<String> CONTENT_DIGEST_ALGS = List.of("sha-256", "sha-512");
    public static final String CONTENT_DIGEST_HEADER = "Content-Digest";

    private static final Pattern MEMBER = Pattern.compile("([a-z*][a-z0-9_\\-.*]*)=:([A-Za-z0-9+/]*={0,2}):");

    private static byte[] bytesOf(Object body) {
        if (body instanceof String) return Json.utf8(((String) body));
        if (body instanceof byte[]) return (byte[]) body;
        throw new IllegalArgumentException("body must be a string or bytes");
    }

    private static String nodeAlg(String alg) {
        if ("sha-256".equals(alg)) return "SHA-256";
        if ("sha-512".equals(alg)) return "SHA-512";
        throw new IllegalArgumentException("unsupported algorithm");
    }

    /** The raw digest bytes of {@code body} (a String, hashed as UTF-8, or byte[]) under {@code alg}. */
    public static byte[] contentDigestBytes(Object body, String alg) {
        try {
            return MessageDigest.getInstance(nodeAlg(alg)).digest(bytesOf(body));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The Content-Digest field value, e.g. {@code sha-256=:X48E9q...=:} (members in the given order, repeats dropped). */
    public static String contentDigestHeader(Object body, List<String> algs) {
        if (algs.isEmpty()) throw new IllegalArgumentException("contentDigestHeader: name at least one algorithm");
        Set<String> seen = new HashSet<>();
        List<String> parts = new ArrayList<>();
        for (String alg : algs) {
            if (!CONTENT_DIGEST_ALGS.contains(alg)) throw new IllegalArgumentException("contentDigestHeader: unsupported algorithm " + alg);
            if (!seen.add(alg)) continue;
            parts.add(alg + "=:" + WbaJs.b64(contentDigestBytes(body, alg)) + ":");
        }
        return String.join(", ", parts);
    }

    public static String contentDigestHeader(Object body) { return contentDigestHeader(body, List.of("sha-256")); }

    /** Parse the dictionary: key to byte sequence. Throws IllegalArgumentException on anything that is not {@code key=:base64:} (parameters refused). */
    public static Map<String, byte[]> parseContentDigest(String value) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (String raw : value.split(",", -1)) {
            String member = WbaJs.trim(raw);
            if (member.isEmpty()) throw new IllegalArgumentException("empty dictionary member");
            Matcher m = MEMBER.matcher(member);
            if (!m.matches()) throw new IllegalArgumentException("malformed Content-Digest member \"" + member + "\"");
            String key = m.group(1), b64 = m.group(2);
            if (b64.length() % 4 != 0) throw new IllegalArgumentException("member \"" + key + "\" is not canonical base64");
            byte[] bytes = WbaJs.nodeBase64(b64);
            if (!WbaJs.b64(bytes).equals(b64)) throw new IllegalArgumentException("member \"" + key + "\" is not canonical base64");
            if (out.containsKey(key)) throw new IllegalArgumentException("member \"" + key + "\" appears twice");
            out.put(key, bytes);
        }
        return out;
    }

    /**
     * Check {@code body} against a Content-Digest field value ({@code header} null = absent). Every supported member present must match; unsupported
     * members are ignored (RFC 9530 section 2); at least one supported member must be present; every algorithm in {@code require} (null = none) must
     * be among the matched ones. Returns {valid, reason?, matched?}; never throws on a bad header.
     */
    public static Map<String, Object> verifyContentDigest(String header, Object body, List<String> require) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            if (header == null || WbaJs.trim(header).isEmpty()) return fail("missing Content-Digest");
            Map<String, byte[]> members = parseContentDigest(header);
            List<Object> matched = new ArrayList<>();
            for (String alg : CONTENT_DIGEST_ALGS) {
                byte[] got = members.get(alg);
                if (got == null) continue;
                if (!MessageDigest.isEqual(got, contentDigestBytes(body, alg))) return fail(alg + " digest does not match the content");
                matched.add(alg);
            }
            if (matched.isEmpty()) return fail("no supported digest algorithm (sha-256 or sha-512)");
            if (require != null) for (String alg : require) if (!matched.contains(alg)) return fail("required " + alg + " digest is absent");
            out.put("valid", Boolean.TRUE);
            out.put("matched", matched);
            return out;
        } catch (RuntimeException e) {
            return fail("malformed Content-Digest: " + e.getMessage());
        }
    }

    public static Map<String, Object> verifyContentDigest(String header, Object body) { return verifyContentDigest(header, body, null); }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("valid", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }
}
