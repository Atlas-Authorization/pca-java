package net.atlasauth.pca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline Sigstore bundle verification for build provenance (track K9; port of the TypeScript
 * {@code packages/pca-attest-eat/src/sigstore.ts}, replayed on {@code conformance/sigstore-vectors.json}).
 *
 * <p>Verifies a Sigstore bundle carrying a DSSE in-toto Statement against a pinned {@code trusted_root.json}, with no
 * network: every RFC 3161 timestamp (CMS SignedData over TSTInfo, pinned TSA chain at genTime) and the Rekor v1 SET when
 * present, at least one verified time; one Rekor entry ({@code dsse/0.0.1}, {@code intoto/0.0.2} or Rekor v2
 * {@code hashedrekord/0.0.2} over the DSSE PAE), RFC 9162 inclusion to a checkpoint signed by the pinned log (Ed25519 signed
 * note under the base-URL host for v2, ECDSA for v1); the certificate path to a pinned Fulcio CA at every verified time,
 * code-signing EKU, the embedded SCT when the root lists CT logs; the entry body names this envelope; the DSSE signature;
 * the Fulcio identity extensions; the Statement. {@link #verifySigstoreBundle} then reads the SLSA v1 predicate into the
 * facts {@link ProvenanceGate#provenanceGate} checks. Only the JDK is used (sigstore-java needs the artifact digest, exposes
 * no verified time sources, and would add a large dependency tree to a plain-source SDK). Never throws on a bundle.
 */
public final class Sigstore {
    private Sigstore() {}

    public static final List<String> BUNDLE_MEDIA_TYPES = List.of(
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+json");
    public static final String INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
    private static final String OID_FULCIO = "1.3.6.1.4.1.57264.1.";
    private static final String OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";
    private static final String OID_SAN = "2.5.29.17";
    private static final String EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    private static final String EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    private static final String OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    private static final String OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
    private static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final Map<String, String> DIGEST_OIDS = Map.of(
        "2.16.840.1.101.3.4.2.1", "sha256", "2.16.840.1.101.3.4.2.2", "sha384", "2.16.840.1.101.3.4.2.3", "sha512");
    private static final long MAX_SAFE = 9_007_199_254_740_991L;

    // ---- trusted root ------------------------------------------------------------------------------------------------

    /** A pinned log; {@code v2Name} (the host of its base URL) is non-null for Rekor v2 (Ed25519, signed-note) logs. */
    public static final class PinnedLog {
        public final byte[] keyId;
        public final PublicKey key;
        public final long start, end;
        public final String v2Name;
        PinnedLog(byte[] keyId, PublicKey key, long[] v, String v2Name) { this.keyId = keyId; this.key = key; this.start = v[0]; this.end = v[1]; this.v2Name = v2Name; }
    }

    public static final class PinnedCa {
        public final List<X509Certificate> chain;
        public final long start, end;
        PinnedCa(List<X509Certificate> chain, long[] v) { this.chain = chain; this.start = v[0]; this.end = v[1]; }
    }

    public static final class PinnedRoots {
        public final List<PinnedLog> tlogs, ctlogs;
        public final List<PinnedCa> cas, tsas;
        PinnedRoots(List<PinnedLog> tlogs, List<PinnedLog> ctlogs, List<PinnedCa> cas, List<PinnedCa> tsas) { this.tlogs = tlogs; this.ctlogs = ctlogs; this.cas = cas; this.tsas = tsas; }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
    private static Map<String, Object> objOrEmpty(Object o) { Map<String, Object> m = obj(o); return m != null ? m : Map.of(); }
    private static List<?> arr(Object o) { return o instanceof List ? (List<?>) o : List.of(); }
    private static Object at(Object o, String k) { Map<String, Object> m = obj(o); return m == null ? null : m.get(k); }

    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/]*={0,2}");
    static byte[] b64(Object s) {
        if (!(s instanceof String) || !B64.matcher((String) s).matches() || ((String) s).length() % 4 != 0) throw new IllegalArgumentException("not base64");
        return Base64.getDecoder().decode((String) s);
    }

    private static long[] validity(Object v) {
        Object s = at(v, "start"), e = at(v, "end");
        if (!(s instanceof String)) throw new IllegalArgumentException("validFor.start missing");
        long start = OffsetDateTime.parse((String) s).toInstant().toEpochMilli();
        long end = e instanceof String ? OffsetDateTime.parse((String) e).toInstant().toEpochMilli() : Long.MAX_VALUE;
        return new long[] {start, end};
    }

    static byte[] sha(String alg, byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance(alg.toUpperCase(Locale.ROOT).replace("SHA", "SHA-"));
            for (byte[] p : parts) d.update(p);
            return d.digest();
        } catch (java.security.NoSuchAlgorithmException x) {
            throw new IllegalArgumentException(x);
        }
    }

    private static PublicKey spki(String alg, byte[] der) throws Exception { return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der)); }

    private static PinnedLog pinnedLog(Object t, boolean transparency) throws Exception {
        Map<String, Object> pk = obj(at(t, "publicKey"));
        if (pk == null || obj(at(t, "logId")) == null) throw new IllegalArgumentException("log entry malformed");
        byte[] der = b64(pk.get("rawBytes"));
        byte[] keyId = b64(at(at(t, "logId"), "keyId"));
        long[] valid = validity(pk.get("validFor"));
        Object kd = pk.get("keyDetails");
        if ("PKIX_ECDSA_P256_SHA_256".equals(kd)) {
            if (!Arrays.equals(sha("sha256", der), keyId)) throw new IllegalArgumentException("log id is not the SHA-256 of its key");
            return new PinnedLog(keyId, spki("EC", der), valid, null);
        }
        if ("PKCS1_RSA_PKCS1V5".equals(kd)) {
            if (transparency) return null;
            // PKCS#1 RSAPublicKey -> SPKI {rsaEncryption, NULL}
            byte[] alg = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
            byte[] bits = new byte[der.length + 1];
            System.arraycopy(der, 0, bits, 1, der.length);
            byte[] s = enc(0x30, cat(alg, enc(0x03, bits)));
            if (!Arrays.equals(sha("sha256", s), keyId)) throw new IllegalArgumentException("log id is not the SHA-256 of its key");
            return new PinnedLog(keyId, spki("RSA", s), valid, null);
        }
        if ("PKIX_ED25519".equals(kd)) {
            if (!transparency) return null;
            PublicKey key = spki("Ed25519", der);
            byte[] raw = Arrays.copyOfRange(der, der.length - 32, der.length);
            Object bu = at(t, "baseUrl");
            String name = bu instanceof String ? URI.create((String) bu).getHost() : "";
            if (name == null || name.isEmpty() || !Arrays.equals(sha("sha256", (name + "\n").getBytes(StandardCharsets.UTF_8), new byte[] {1}, raw), keyId))
                throw new IllegalArgumentException("log id is not the signed-note key hash of its key");
            return new PinnedLog(keyId, key, valid, name);
        }
        return null;
    }

    private static X509Certificate x509(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static PinnedCa pinnedChain(Object c) throws Exception {
        List<?> certs = arr(at(at(c, "certChain"), "certificates"));
        if (certs.isEmpty()) throw new IllegalArgumentException("certificate authority entry malformed");
        List<X509Certificate> chain = new ArrayList<>();
        for (Object x : certs) chain.add(x509(b64(at(x, "rawBytes"))));
        return new PinnedCa(List.copyOf(chain), validity(at(c, "validFor")));
    }

    /**
     * Parse a Sigstore {@code trusted_root.json} (v0.1) tree ({@link Json#parseLenient}): transparency logs, CT logs, Fulcio CAs,
     * timestamp authorities. Throws IllegalArgumentException on anything malformed. A root with no CT log does not require SCTs.
     */
    public static PinnedRoots parseTrustedRoot(Object json) {
        try {
            Map<String, Object> j = obj(json);
            if (j == null || !"application/vnd.dev.sigstore.trustedroot+json;version=0.1".equals(j.get("mediaType"))) throw new IllegalArgumentException("not a trusted root v0.1");
            List<PinnedLog> tlogs = new ArrayList<>(), ctlogs = new ArrayList<>();
            List<PinnedCa> cas = new ArrayList<>(), tsas = new ArrayList<>();
            for (Object t : arr(j.get("tlogs"))) { PinnedLog l = pinnedLog(t, true); if (l != null) tlogs.add(l); }
            for (Object t : arr(j.get("ctlogs"))) { PinnedLog l = pinnedLog(t, false); if (l != null) ctlogs.add(l); }
            for (Object c : arr(j.get("certificateAuthorities"))) cas.add(pinnedChain(c));
            for (Object c : arr(j.get("timestampAuthorities"))) tsas.add(pinnedChain(c));
            if (tlogs.isEmpty() || cas.isEmpty()) throw new IllegalArgumentException("a trusted root needs a transparency log and a CA");
            return new PinnedRoots(List.copyOf(tlogs), List.copyOf(ctlogs), List.copyOf(cas), List.copyOf(tsas));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("trusted root malformed: " + e.getMessage(), e);
        }
    }

    // ---- DER ---------------------------------------------------------------------------------------------------------

    private static final class Tlv {
        final int tag, start, body, end;
        Tlv(int tag, int start, int body, int end) { this.tag = tag; this.start = start; this.body = body; this.end = end; }
    }

    private static Tlv tlv(byte[] b, int off) { return tlv(b, off, b.length); }
    private static Tlv tlv(byte[] b, int off, int limit) {
        if (off + 2 > limit) throw new IllegalArgumentException("DER truncated");
        int tag = b[off] & 0xff;
        if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("DER multi-byte tag");
        long len = b[off + 1] & 0xff;
        int body = off + 2;
        if ((len & 0x80) != 0) {
            int n = (int) (len & 0x7f);
            if (n == 0 || n > 4 || body + n > limit) throw new IllegalArgumentException("DER length");
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + (b[body + i] & 0xff);
            body += n;
        }
        if (body + len > limit) throw new IllegalArgumentException("DER overrun");
        return new Tlv(tag, off, body, (int) (body + len));
    }

    private static List<Tlv> kids(byte[] b, Tlv t) {
        List<Tlv> out = new ArrayList<>();
        for (int o = t.body; o < t.end; ) {
            Tlv c = tlv(b, o, t.end);
            out.add(c);
            o = c.end;
        }
        return out;
    }

    private static String oidText(byte[] b, Tlv t) {
        if (t.tag != 0x06 || t.end <= t.body) throw new IllegalArgumentException("not an OID");
        List<Long> parts = new ArrayList<>();
        long v = 0;
        for (int i = t.body; i < t.end; i++) {
            if (v > (Long.MAX_VALUE >> 7)) throw new IllegalArgumentException("OID arc too large");
            v = v * 128 + (b[i] & 0x7f);
            if ((b[i] & 0x80) == 0) { parts.add(v); v = 0; }
        }
        if (parts.isEmpty()) throw new IllegalArgumentException("OID truncated");
        long first = parts.remove(0);
        long a = Math.min(2, first / 40);
        StringBuilder sb = new StringBuilder().append(a).append('.').append(first - a * 40);
        for (long p : parts) sb.append('.').append(p);
        return sb.toString();
    }

    private static byte[] slice(byte[] b, int from, int to) { return Arrays.copyOfRange(b, from, to); }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    private static byte[] enc(int tag, byte[] content) {
        int n = content.length;
        byte[] len = n < 0x80 ? new byte[] {(byte) n} : n < 0x100 ? new byte[] {(byte) 0x81, (byte) n}
            : n < 0x10000 ? new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n} : new byte[] {(byte) 0x83, (byte) (n >> 16), (byte) (n >> 8), (byte) n};
        return cat(new byte[] {(byte) tag}, len, content);
    }

    private static final class Ext {
        final String oid; final byte[] value; final Tlv tlv;
        Ext(String oid, byte[] value, Tlv tlv) { this.oid = oid; this.value = value; this.tlv = tlv; }
    }

    private static final class ParsedCert {
        byte[] der; List<Tlv> tbsKids; Tlv extsWrapper; List<Ext> exts;
        Ext ext(String oid) { for (Ext e : exts) if (e.oid.equals(oid)) return e; return null; }
    }

    private static ParsedCert parseCert(byte[] der) {
        Tlv cert = tlv(der, 0);
        if (cert.tag != 0x30 || cert.end != der.length) throw new IllegalArgumentException("certificate is not one SEQUENCE");
        Tlv tbs = kids(der, cert).get(0);
        if (tbs.tag != 0x30) throw new IllegalArgumentException("no TBSCertificate");
        ParsedCert pc = new ParsedCert();
        pc.der = der;
        pc.tbsKids = kids(der, tbs);
        for (Tlv k : pc.tbsKids) if (k.tag == 0xa3) { pc.extsWrapper = k; break; }
        if (pc.extsWrapper == null) throw new IllegalArgumentException("no extensions");
        Tlv seq = kids(der, pc.extsWrapper).get(0);
        if (seq.tag != 0x30) throw new IllegalArgumentException("extensions malformed");
        pc.exts = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Tlv e : kids(der, seq)) {
            List<Tlv> parts = kids(der, e);
            Tlv oct = parts.get(parts.size() - 1);
            if (oct.tag != 0x04) throw new IllegalArgumentException("extension value is not an OCTET STRING");
            String oid = oidText(der, parts.get(0));
            if (!seen.add(oid)) throw new IllegalArgumentException("duplicate extension " + oid);
            pc.exts.add(new Ext(oid, slice(der, oct.body, oct.end), e));
        }
        return pc;
    }

    private static String utf8Strict(byte[] b) {
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(b)).toString();
            return s.startsWith("﻿") ? s.substring(1) : s; // TextDecoder drops a leading BOM
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("not UTF-8");
        }
    }

    /** Fulcio extension {@code .1.n}: raw UTF-8 for n &lt;= 6, a DER UTF8String for n &gt;= 8. */
    private static String fulcioExt(ParsedCert c, int n) {
        Ext e = c.ext(OID_FULCIO + n);
        if (e == null) return null;
        if (n <= 6) return utf8Strict(e.value);
        Tlv t = tlv(e.value, 0);
        if (t.tag != 0x0c || t.end != e.value.length) throw new IllegalArgumentException("extension .1." + n + " is not a DER UTF8String");
        return utf8Strict(slice(e.value, t.body, t.end));
    }

    /** Exactly one SAN, a URI or an email. */
    private static String sanIdentity(ParsedCert c) {
        Ext e = c.ext(OID_SAN);
        if (e == null) throw new IllegalArgumentException("no subjectAltName");
        Tlv seq = tlv(e.value, 0);
        List<Tlv> names = kids(e.value, seq);
        if (seq.tag != 0x30 || names.size() != 1) throw new IllegalArgumentException("subjectAltName must hold exactly one name");
        Tlv n = names.get(0);
        if (n.tag != 0x86 && n.tag != 0x81) throw new IllegalArgumentException("subjectAltName must be a URI or an email");
        return utf8Strict(slice(e.value, n.body, n.end));
    }

    // ---- crypto helpers ----------------------------------------------------------------------------------------------

    /** Verify {@code sig} over {@code data}: {@code hash} null = Ed25519, else ECDSA (DER) or RSA PKCS#1 v1.5 by the key type. */
    private static boolean sigOk(String hash, PublicKey k, byte[] data, byte[] sig) {
        try {
            String ka = k.getAlgorithm();
            String alg;
            if (hash == null) {
                if (!("EdDSA".equals(ka) || "Ed25519".equals(ka))) return false;
                alg = "Ed25519";
            } else if ("EC".equals(ka)) alg = hash.toUpperCase(Locale.ROOT) + "withECDSA";
            else if ("RSA".equals(ka)) alg = hash.toUpperCase(Locale.ROOT) + "withRSA";
            else return false;
            Signature s = Signature.getInstance(alg);
            s.initVerify(k);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean inside(X509Certificate c, long at) { return c.getNotBefore().getTime() <= at && at <= c.getNotAfter().getTime(); }
    private static boolean isCa(X509Certificate c) { return c.getBasicConstraints() >= 0; }

    /** {@code c} names {@code up} as issuer (and {@code up} may sign certificates) and carries its signature. */
    private static boolean issuedBy(X509Certificate c, X509Certificate up) {
        if (!c.getIssuerX500Principal().equals(up.getSubjectX500Principal()) || !akidOk(c, up)) return false;
        boolean[] ku = up.getKeyUsage();
        if (ku != null && (ku.length < 6 || !ku[5])) return false;
        try {
            c.verify(up.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** OpenSSL X509_check_akid: when {@code c} has an AKI keyIdentifier and {@code up} a SKI, they must be equal; malformed = not issued. */
    private static boolean akidOk(X509Certificate c, X509Certificate up) {
        byte[] aki = c.getExtensionValue("2.5.29.35"), ski = up.getExtensionValue("2.5.29.14");
        if (aki == null || ski == null) return true;
        try {
            Tlv ao = tlv(aki, 0), seq = tlv(aki, ao.body, ao.end), so = tlv(ski, 0), id = tlv(ski, so.body, so.end);
            if (ao.tag != 0x04 || seq.tag != 0x30 || so.tag != 0x04 || id.tag != 0x04) return false;
            for (Tlv k : kids(aki, seq)) if (k.tag == 0x80) return Arrays.equals(slice(aki, k.body, k.end), slice(ski, id.body, id.end));
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean hasEku(X509Certificate c, String eku) {
        try {
            List<String> l = c.getExtendedKeyUsage();
            return l != null && l.contains(eku);
        } catch (Exception e) {
            return false;
        }
    }

    /** Chain (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at {@code at}. */
    private static boolean chainOk(List<X509Certificate> chain, long at) {
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            X509Certificate up = i + 1 < chain.size() ? chain.get(i + 1) : c;
            if (!issuedBy(c, up) || !inside(c, at)) return false;
            if (i > 0 && !isCa(c)) return false;
        }
        return true;
    }

    // ---- SCT (RFC 6962 3.2) ------------------------------------------------------------------------------------------

    private static int u16(byte[] b, int o) { return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff); }

    private static String verifySct(ParsedCert leaf, X509Certificate issuer, PinnedRoots roots) {
        Ext e = leaf.ext(OID_SCT_LIST);
        if (e == null) return "no embedded SCT";
        Tlv outer = tlv(e.value, 0);
        if (outer.tag != 0x04) return "SCT list is not an OCTET STRING";
        byte[] list = slice(e.value, outer.body, outer.end);
        if (list.length < 2 || u16(list, 0) != list.length - 2) return "SCT list length";
        byte[] der = leaf.der;
        Tlv extSeq = kids(der, leaf.extsWrapper).get(0);
        ByteArrayOutputStream kept = new ByteArrayOutputStream();
        for (Tlv k : kids(der, extSeq)) if (k.start != e.tlv.start) kept.write(der, k.start, k.end - k.start);
        ByteArrayOutputStream tbsBody = new ByteArrayOutputStream();
        for (Tlv k : leaf.tbsKids) {
            if (k == leaf.extsWrapper) { byte[] w = enc(0xa3, enc(0x30, kept.toByteArray())); tbsBody.write(w, 0, w.length); }
            else tbsBody.write(der, k.start, k.end - k.start);
        }
        byte[] tbs = enc(0x30, tbsBody.toByteArray());
        byte[] issuerKeyHash = sha("sha256", issuer.getPublicKey().getEncoded());
        String why = "no SCT from a pinned CT log";
        for (int o = 2; o < list.length; ) {
            if (o + 2 > list.length) return "SCT truncated";
            int n = u16(list, o);
            if (o + 2 + n > list.length || n < 47) return "SCT truncated";
            byte[] s = slice(list, o + 2, o + 2 + n);
            o += 2 + n;
            if (s[0] != 0) continue;
            byte[] logId = slice(s, 1, 33);
            long ts = ByteBuffer.wrap(s, 33, 8).getLong();
            int extLen = u16(s, 41);
            if (43 + extLen > s.length) return "SCT truncated";
            byte[] ext = slice(s, 43, 43 + extLen);
            int p = 43 + extLen;
            if (p + 4 > s.length) return "SCT truncated";
            int hashAlg = s[p] & 0xff, sigAlg = s[p + 1] & 0xff, sigLen = u16(s, p + 2);
            if (p + 4 + sigLen != s.length) return "SCT malformed";
            byte[] sig = slice(s, p + 4, p + 4 + sigLen);
            PinnedLog log = null;
            for (PinnedLog l : roots.ctlogs) if (Arrays.equals(l.keyId, logId)) { log = l; break; }
            if (log == null) continue;
            if (hashAlg != 4 || (sigAlg != 3 && sigAlg != 1)) { why = "SCT is not SHA-256 with ECDSA or RSA"; continue; }
            if (ts < log.start || ts > log.end) { why = "SCT log key not valid at its timestamp"; continue; }
            byte[] head = new byte[12];
            System.arraycopy(s, 33, head, 2, 8); // v1, certificate_timestamp, timestamp
            head[11] = 1; // precert_entry
            byte[] signed = cat(head, issuerKeyHash, new byte[] {(byte) (tbs.length >> 16), (byte) (tbs.length >> 8), (byte) tbs.length}, tbs,
                new byte[] {(byte) (ext.length >> 8), (byte) ext.length}, ext);
            if (sigOk("sha256", log.key, signed, sig)) return null;
            why = "SCT signature invalid";
        }
        return why;
    }

    // ---- RFC 3161 timestamps -----------------------------------------------------------------------------------------

    private static String digestOf(byte[] b, Tlv t) {
        String alg = DIGEST_OIDS.get(oidText(b, kids(b, t).get(0)));
        if (alg == null) throw new IllegalArgumentException("unsupported digest algorithm");
        return alg;
    }

    private static final Pattern GEN_TIME = Pattern.compile("(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(?:\\.(\\d{1,9}))?Z");

    private static long generalizedTime(byte[] b, Tlv t) {
        if (t.tag != 0x18) throw new IllegalArgumentException("genTime is not a GeneralizedTime");
        Matcher m = GEN_TIME.matcher(new String(b, t.body, t.end - t.body, StandardCharsets.ISO_8859_1));
        if (!m.matches()) throw new IllegalArgumentException("genTime malformed");
        long ms = java.time.LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
            Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6))).toInstant(java.time.ZoneOffset.UTC).toEpochMilli();
        // the reference's floor(Number("0.<frac>") * 1000), in the same double arithmetic
        return m.group(7) != null ? ms + (long) Math.floor(Double.parseDouble("0." + m.group(7)) * 1000) : ms;
    }

    /**
     * Verify an RFC 3161 TimeStampResp (or bare TimeStampToken) over {@code data} (the raw signature bytes): CMS SignedData
     * with TSTInfo content, messageImprint = hash of {@code data}, signed attributes carrying the content type and the
     * TSTInfo digest, the signature over the DER SET of signed attributes under the leaf of a pinned TSA whose chain and
     * validFor cover genTime, with the timeStamping EKU. Returns genTime (ms); throws IllegalArgumentException otherwise.
     */
    public static long verifyRfc3161(byte[] token, byte[] data, List<PinnedCa> tsas) {
        Tlv ci = tlv(token, 0);
        if (ci.end != token.length || ci.tag != 0x30) throw new IllegalArgumentException("timestamp is not one SEQUENCE");
        List<Tlv> parts = kids(token, ci);
        if (!parts.isEmpty() && parts.get(0).tag == 0x30 && parts.get(0).end - parts.get(0).body >= 3 && token[kids(token, parts.get(0)).get(0).start] == 0x02) {
            Tlv st = kids(token, parts.get(0)).get(0);
            byte[] status = slice(token, st.body, st.end);
            if (!(status.length == 1 && (status[0] == 0 || status[0] == 1))) throw new IllegalArgumentException("timestamp status is not granted");
            if (parts.size() < 2) throw new IllegalArgumentException("no timeStampToken");
            ci = parts.get(1);
            parts = kids(token, ci);
        }
        if (parts.size() < 2 || !OID_SIGNED_DATA.equals(oidText(token, parts.get(0))) || parts.get(1).tag != 0xa0) throw new IllegalArgumentException("not CMS SignedData");
        Tlv sd = kids(token, parts.get(1)).get(0);
        List<Tlv> sdk = kids(token, sd);
        Tlv encap = null;
        for (int i = 2; i < sdk.size(); i++) if (sdk.get(i).tag == 0x30) { encap = sdk.get(i); break; }
        if (encap == null) throw new IllegalArgumentException("no encapsulated content");
        List<Tlv> ek = kids(token, encap);
        if (ek.size() < 2 || !OID_TST_INFO.equals(oidText(token, ek.get(0))) || ek.get(1).tag != 0xa0) throw new IllegalArgumentException("content is not TSTInfo");
        Tlv octet = kids(token, ek.get(1)).get(0);
        if (octet.tag != 0x04) throw new IllegalArgumentException("TSTInfo is not an OCTET STRING");
        byte[] tstBytes = slice(token, octet.body, octet.end);
        Tlv tst = tlv(tstBytes, 0);
        List<Tlv> tk = kids(tstBytes, tst);
        List<Tlv> mi = kids(tstBytes, tk.get(2));
        String miAlg = digestOf(tstBytes, mi.get(0));
        if (!Arrays.equals(sha(miAlg, data), slice(tstBytes, mi.get(1).body, mi.get(1).end))) throw new IllegalArgumentException("messageImprint is not the hash of the signature");
        long genTime = generalizedTime(tstBytes, tk.get(4));
        Tlv signerInfos = sdk.get(sdk.size() - 1);
        if (signerInfos.tag != 0x31) throw new IllegalArgumentException("no signerInfos");
        List<Tlv> sis = kids(token, signerInfos);
        if (sis.size() != 1) throw new IllegalArgumentException("exactly one SignerInfo is required");
        List<Tlv> si = kids(token, sis.get(0));
        String dAlg = digestOf(token, si.get(2));
        Tlv attrs = si.get(3);
        if (attrs.tag != 0xa0) throw new IllegalArgumentException("signed attributes are required");
        boolean ctOk = false, mdOk = false;
        for (Tlv a : kids(token, attrs)) {
            List<Tlv> av = kids(token, a);
            List<Tlv> vals = kids(token, av.get(1));
            String o = oidText(token, av.get(0));
            if (vals.size() != 1) throw new IllegalArgumentException("an attribute must have one value");
            if (o.equals(OID_CONTENT_TYPE)) ctOk = OID_TST_INFO.equals(oidText(token, vals.get(0)));
            if (o.equals(OID_MESSAGE_DIGEST)) mdOk = Arrays.equals(sha(dAlg, tstBytes), slice(token, vals.get(0).body, vals.get(0).end));
        }
        if (!ctOk || !mdOk) throw new IllegalArgumentException("signed attributes do not commit to the TSTInfo");
        byte[] signedAttrs = cat(new byte[] {0x31}, slice(token, attrs.start + 1, attrs.end));
        Tlv sigT = si.get(5);
        if (sigT.tag != 0x04) throw new IllegalArgumentException("signature is not an OCTET STRING");
        byte[] sig = slice(token, sigT.body, sigT.end);
        for (PinnedCa tsa : tsas) {
            if (genTime < tsa.start || genTime > tsa.end) continue;
            X509Certificate leaf = tsa.chain.get(0);
            if (!hasEku(leaf, EKU_TIME_STAMPING)) continue;
            if (!sigOk(dAlg, leaf.getPublicKey(), signedAttrs, sig)) continue;
            if (!chainOk(tsa.chain, genTime)) continue;
            return genTime;
        }
        throw new IllegalArgumentException("no pinned timestamp authority signed it (valid at its time)");
    }

    // ---- Rekor -------------------------------------------------------------------------------------------------------

    private static final Pattern SIZE = Pattern.compile("[1-9][0-9]*");
    private static final Pattern NOTE_SIG = Pattern.compile("— (\\S+) ([A-Za-z0-9+/=]+)");

    /** Signed-note checkpoint: origin, size, root, a blank line, then {@code — <name> <b64(hint4 || sig)>} lines. Null when good. */
    private static String verifyCheckpoint(String text, PinnedLog log, long size, byte[] root) {
        int cut = text.indexOf("\n\n");
        if (cut < 0) return "checkpoint has no signature block";
        String body = text.substring(0, cut + 1);
        String[] lines = body.split("\n", -1);
        if (lines.length < 4 || lines[0].isEmpty()) return "checkpoint body too short or without an origin";
        if (!SIZE.matcher(lines[1]).matches() || !new BigInteger(lines[1]).equals(BigInteger.valueOf(size))) return "checkpoint size differs from the proof";
        if (!Arrays.equals(b64(lines[2]), root)) return "checkpoint root differs from the proof";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        for (String l : text.substring(cut + 2).split("\n", -1)) {
            Matcher m = NOTE_SIG.matcher(l);
            if (!m.matches()) continue;
            byte[] raw = b64(m.group(2));
            if (raw.length < 5 || !Arrays.equals(slice(raw, 0, 4), slice(log.keyId, 0, 4))) continue;
            if (log.v2Name != null && !m.group(1).equals(log.v2Name)) continue;
            if (sigOk(log.v2Name != null ? null : "sha256", log.key, bodyBytes, slice(raw, 4, raw.length))) return null;
        }
        return "no checkpoint signature by the pinned log key";
    }

    private static final Pattern DEC = Pattern.compile("0|[1-9][0-9]{0,15}");
    private static long decInt(Object v) {
        if (!(v instanceof String) || !DEC.matcher((String) v).matches()) throw new IllegalArgumentException("not a decimal integer string");
        long n = Long.parseLong((String) v);
        if (n > MAX_SAFE) throw new IllegalArgumentException("integer out of range");
        return n;
    }

    /** DSSE PAE (secure-systems-lab/dsse protocol.md). */
    public static byte[] dssePae(String payloadType, byte[] payload) {
        byte[] t = payloadType.getBytes(StandardCharsets.UTF_8);
        return cat(("DSSEv1 " + t.length + " ").getBytes(StandardCharsets.UTF_8), t, (" " + payload.length + " ").getBytes(StandardCharsets.UTF_8), payload);
    }

    private static String leafHashAlg(PublicKey k) {
        if (!(k instanceof ECPublicKey)) return null;
        int bits = ((ECPublicKey) k).getParams().getCurve().getField().getFieldSize();
        return bits == 256 ? "sha256" : bits == 384 ? "sha384" : null;
    }

    // ---- the verifier ------------------------------------------------------------------------------------------------

    /** {@code {ok, core, statement}} or {@code {ok: false, code, detail}}. */
    public static final class CoreResult {
        public final boolean ok;
        /** identity, oidc_issuer, source_*, predicate_type, subjects, signed_time, rekor_log_index, rekor, timestamps; null on refusal. */
        public final Map<String, Object> core;
        public final Map<String, Object> statement;
        public final String code, detail;
        CoreResult(boolean ok, Map<String, Object> core, Map<String, Object> statement, String code, String detail) { this.ok = ok; this.core = core; this.statement = statement; this.code = code; this.detail = detail; }
    }

    /** {@code {ok, facts}} (the {@code facts} of {@link ProvenanceGate#provenanceGate}) or {@code {ok: false, code, detail}}. */
    public static final class Result {
        public final boolean ok;
        public final Map<String, Object> facts;
        public final String code, detail;
        Result(boolean ok, Map<String, Object> facts, String code, String detail) { this.ok = ok; this.facts = facts; this.code = code; this.detail = detail; }
    }

    private static CoreResult no(String code, String detail) { return new CoreResult(false, null, null, code, detail); }

    /**
     * Verify a Sigstore bundle (a {@link Json#parseLenient} tree) carrying a DSSE in-toto statement against pinned roots.
     * Never throws; every refusal has the reference's code and a detail.
     */
    public static CoreResult verifySigstoreBundleCore(Object bundle, PinnedRoots roots) {
        String stage = "malformed";
        try {
            Map<String, Object> b = obj(bundle);
            if (b == null || roots == null || obj(b.get("verificationMaterial")) == null) return no("malformed", "not a bundle");
            Object mt = b.get("mediaType");
            if (!BUNDLE_MEDIA_TYPES.contains(mt)) return no("media_type", "unsupported media type " + mt);
            Map<String, Object> vm = obj(b.get("verificationMaterial"));
            boolean v03 = !BUNDLE_MEDIA_TYPES.get(0).equals(mt);
            Object certRaw = v03 ? at(vm.get("certificate"), "rawBytes") : at(arr(at(vm.get("x509CertificateChain"), "certificates")).stream().findFirst().orElse(null), "rawBytes");
            if (certRaw == null) return no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)");
            Map<String, Object> env = obj(b.get("dsseEnvelope"));
            if (env == null || b.containsKey("messageSignature")) return no("envelope", "not a DSSE bundle");
            if (!INTOTO_PAYLOAD_TYPE.equals(env.get("payloadType"))) return no("envelope", "payloadType is not application/vnd.in-toto+json");
            List<?> sigs0 = arr(env.get("signatures"));
            if (!(env.get("signatures") instanceof List) || sigs0.size() != 1 || obj(sigs0.get(0)) == null) return no("envelope", "a DSSE envelope must carry exactly one signature");
            byte[] payload = b64(env.get("payload"));
            byte[] dsseSig = b64(at(sigs0.get(0), "sig"));
            byte[] pae = dssePae(INTOTO_PAYLOAD_TYPE, payload);
            stage = "cert_parse";
            byte[] leafDer = b64(certRaw);
            X509Certificate leaf = x509(leafDer);
            ParsedCert pc = parseCert(leafDer);
            String alg = leafHashAlg(leaf.getPublicKey());

            // ---- the log entry and its log
            stage = "tlog_count";
            List<?> entries = arr(vm.get("tlogEntries"));
            if (entries.size() != 1 || obj(entries.get(0)) == null) return no("tlog_count", "exactly one transparency log entry is required");
            Map<String, Object> t = obj(entries.get(0));
            stage = "tlog_kind";
            Map<String, Object> kvo = obj(t.get("kindVersion"));
            String kv = kvo != null ? kvo.get("kind") + "/" + kvo.get("version") : "";
            if (!List.of("dsse/0.0.1", "intoto/0.0.2", "hashedrekord/0.0.2").contains(kv)) return no("tlog_kind", "unsupported entry " + kv);
            boolean v2 = kv.equals("hashedrekord/0.0.2");
            stage = "tlog_key";
            byte[] keyId = b64(at(t.get("logId"), "keyId"));
            PinnedLog log = null;
            for (PinnedLog l : roots.tlogs) if (Arrays.equals(l.keyId, keyId)) { log = l; break; }
            if (log == null) return no("tlog_key", "the entry names a log the verifier did not pin");
            if (v2 != (log.v2Name != null)) return no("tlog_key", "the entry type does not match the log version");
            long logIndex = decInt(t.get("logIndex"));
            byte[] body = b64(t.get("canonicalizedBody"));

            // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
            stage = "tsa";
            List<Long> times = new ArrayList<>();
            for (Object ts : arr(at(vm.get("timestampVerificationData"), "rfc3161Timestamps"))) times.add(verifyRfc3161(b64(at(ts, "signedTimestamp")), dsseSig, roots.tsas));
            int tsaCount = times.size();
            boolean set = false;
            if (!v2 && obj(t.get("inclusionPromise")) != null) {
                stage = "tlog_set";
                long integrated = decInt(t.get("integratedTime"));
                StringBuilder hex = new StringBuilder();
                for (byte x : keyId) hex.append(String.format("%02x", x & 0xff));
                // canonicalizedBody passed b64() above, so it needs no JSON escaping
                String setMsg = "{\"body\":\"" + t.get("canonicalizedBody") + "\",\"integratedTime\":" + integrated + ",\"logID\":\"" + hex + "\",\"logIndex\":" + logIndex + "}";
                if (!sigOk("sha256", log.key, setMsg.getBytes(StandardCharsets.UTF_8), b64(at(t.get("inclusionPromise"), "signedEntryTimestamp")))) return no("tlog_set", "signed entry timestamp invalid");
                times.add(integrated * 1000);
                set = true;
            }
            if (times.isEmpty()) return no("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp");
            for (long when : times) if (when < log.start || when > log.end) return no("tlog_key", "the log key was not valid at a signing time");

            // ---- inclusion
            stage = "tlog_inclusion";
            Map<String, Object> ip = obj(t.get("inclusionProof"));
            if (ip == null || !(ip.get("hashes") instanceof List) || obj(ip.get("checkpoint")) == null) return no("tlog_inclusion", "no inclusion proof");
            byte[] root = b64(ip.get("rootHash"));
            long size = decInt(ip.get("treeSize"));
            List<byte[]> hashes = new ArrayList<>();
            for (Object h : (List<?>) ip.get("hashes")) hashes.add(b64(h));
            if (!ProvenanceGate.verifyRfc9162Inclusion(ProvenanceGate.rfc9162LeafHash(body), decInt(ip.get("logIndex")), size, hashes, root)) return no("tlog_inclusion", "the inclusion proof does not lead to the root");
            stage = "tlog_checkpoint";
            String cpe = verifyCheckpoint(String.valueOf(at(ip.get("checkpoint"), "envelope")), log, size, root);
            if (cpe != null) return no("tlog_checkpoint", cpe);

            // ---- certificate path at every verified time (hybrid model), CT
            stage = "cert_chain";
            X509Certificate issuer = null;
            for (PinnedCa ca : roots.cas) {
                boolean covered = true;
                for (long when : times) if (when < ca.start || when > ca.end) covered = false;
                if (!covered) continue;
                X509Certificate first = ca.chain.get(0);
                if (!issuedBy(leaf, first)) continue;
                boolean ok = true;
                for (long when : times) if (!chainOk(ca.chain, when)) ok = false;
                for (X509Certificate c : ca.chain) if (!isCa(c)) ok = false;
                if (ok) { issuer = first; break; }
            }
            if (issuer == null) return no("cert_chain", "no pinned CA issued the certificate, valid at every signing time");
            if (isCa(leaf)) return no("cert_chain", "the leaf is a CA certificate");
            for (long when : times) if (!inside(leaf, when)) return no("cert_time", "the certificate was not valid at a signing time");
            if (!hasEku(leaf, EKU_CODE_SIGNING)) return no("cert_eku", "the certificate lacks the code-signing EKU");
            if (!roots.ctlogs.isEmpty()) {
                stage = "sct";
                String sct = verifySct(pc, issuer, roots);
                if (sct != null) return no("sct", sct);
            }

            // ---- the entry body names this envelope
            stage = "tlog_body";
            Map<String, Object> eb = objOrEmpty(Json.parseLenient(new String(body, StandardCharsets.UTF_8)));
            Map<String, Object> spec = objOrEmpty(eb.get("spec"));
            if (!(eb.get("kind") + "/" + eb.get("apiVersion")).equals(kv)) return no("tlog_body", "the entry body is not the kind the bundle names");
            String payloadSha = hex(sha("sha256", payload));
            if (kv.equals("dsse/0.0.1")) {
                Map<String, Object> ph = objOrEmpty(spec.get("payloadHash"));
                if (!"sha256".equals(ph.get("algorithm")) || !payloadSha.equals(ph.get("value"))) return no("tlog_body", "the entry names another payload");
                List<?> sigs = arr(spec.get("signatures"));
                if (sigs.size() != 1 || obj(sigs.get(0)) == null) return no("tlog_body", "the entry must name exactly one signature");
                if (!Arrays.equals(b64(at(sigs.get(0), "signature")), dsseSig)) return no("tlog_body", "the entry names another signature");
                if (!Arrays.equals(pemDer(new String(b64(at(sigs.get(0), "verifier")), StandardCharsets.UTF_8)), leafDer)) return no("tlog_body", "the entry names another certificate");
            } else if (kv.equals("intoto/0.0.2")) {
                // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
                Map<String, Object> c = objOrEmpty(spec.get("content"));
                Map<String, Object> ph = objOrEmpty(c.get("payloadHash"));
                if (!"sha256".equals(ph.get("algorithm")) || !payloadSha.equals(ph.get("value"))) return no("tlog_body", "the entry names another payload");
                List<?> sigs = arr(at(c.get("envelope"), "signatures"));
                if (sigs.size() != 1 || obj(sigs.get(0)) == null) return no("tlog_body", "the entry must name exactly one signature");
                if (!Arrays.equals(b64(new String(b64(at(sigs.get(0), "sig")), StandardCharsets.ISO_8859_1)), dsseSig)) return no("tlog_body", "the entry names another signature");
                if (!Arrays.equals(pemDer(new String(b64(at(sigs.get(0), "publicKey")), StandardCharsets.UTF_8)), leafDer)) return no("tlog_body", "the entry names another certificate");
            } else {
                // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
                Map<String, Object> h = objOrEmpty(spec.get("hashedRekordV002"));
                Map<String, Object> data = objOrEmpty(h.get("data"));
                Object da = data.get("algorithm");
                String hashName = "SHA2_256".equals(da) ? "sha256" : "SHA2_384".equals(da) ? "sha384" : "SHA2_512".equals(da) ? "sha512" : null;
                if (hashName == null || !hashName.equals(alg)) return no("tlog_body", "the entry digest algorithm is not the signing key's");
                if (!Arrays.equals(b64(data.get("digest")), sha(hashName, pae))) return no("tlog_body", "the entry names another envelope");
                Map<String, Object> sg = objOrEmpty(h.get("signature"));
                if (!Arrays.equals(b64(sg.get("content")), dsseSig)) return no("tlog_body", "the entry names another signature");
                if (!Arrays.equals(b64(at(at(sg.get("verifier"), "x509Certificate"), "rawBytes")), leafDer)) return no("tlog_body", "the entry names another certificate");
            }

            // ---- DSSE signature
            stage = "signature";
            if (alg == null) return no("signature", "unsupported leaf key type");
            if (!sigOk(alg, leaf.getPublicKey(), pae, dsseSig)) return no("signature", "DSSE signature invalid");

            // ---- identity
            stage = "identity";
            String identity = sanIdentity(pc);
            String issV2 = fulcioExt(pc, 8), issV1 = fulcioExt(pc, 1);
            if (issV2 != null && issV1 != null && !issV2.equals(issV1)) return no("identity", "the two issuer extensions disagree");
            String oidcIssuer = issV2 != null ? issV2 : issV1;
            if (oidcIssuer == null || oidcIssuer.isEmpty()) return no("identity", "no OIDC issuer extension");
            String sourceRepo = fulcioExt(pc, 12), sourceDigest = fulcioExt(pc, 13), sourceRef = fulcioExt(pc, 14);

            // ---- statement
            stage = "statement";
            Map<String, Object> st = obj(Json.parseLenient(utf8Strict(payload)));
            if (st == null || !ProvenanceGate.INTOTO_STATEMENT_V1.equals(st.get("_type"))) return no("statement", "not an in-toto Statement v1");
            if (!(st.get("subject") instanceof List) || ((List<?>) st.get("subject")).isEmpty()) return no("statement", "no subject");
            List<Object> subjects = new ArrayList<>();
            for (Object s : (List<?>) st.get("subject")) {
                Map<String, Object> d = objOrEmpty(at(s, "digest"));
                for (String a : List.of("sha256", "sha512")) if (d.get(a) instanceof String) {
                    Map<String, Object> sd = new LinkedHashMap<>();
                    sd.put("alg", a);
                    sd.put("digest", d.get(a));
                    subjects.add(sd);
                }
            }
            if (subjects.isEmpty() || subjects.size() > 64) return no("statement", "no sha256/sha512 subject digest (or more than 64)");
            if (!(st.get("predicateType") instanceof String)) return no("statement", "no predicateType");
            long min = Long.MAX_VALUE;
            for (long when : times) min = Math.min(min, when);
            Map<String, Object> core = new LinkedHashMap<>();
            core.put("identity", identity);
            core.put("oidc_issuer", oidcIssuer);
            if (sourceRepo != null) core.put("source_repo", sourceRepo);
            if (sourceRef != null) core.put("source_ref", sourceRef);
            if (sourceDigest != null) core.put("source_digest", sourceDigest);
            core.put("predicate_type", st.get("predicateType"));
            core.put("subjects", subjects);
            core.put("signed_time", Math.floorDiv(min, 1000L));
            core.put("rekor_log_index", logIndex);
            core.put("rekor", v2 ? "v2" : "v1");
            Map<String, Object> tsm = new LinkedHashMap<>();
            tsm.put("tsa", (long) tsaCount);
            tsm.put("set", set);
            core.put("timestamps", tsm);
            return new CoreResult(true, core, st, null, null);
        } catch (Exception | StackOverflowError e) {
            return no(stage, "fail closed: " + e.getMessage());
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    private static final Pattern PEM = Pattern.compile("-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?");
    private static byte[] pemDer(String pem) {
        Matcher m = PEM.matcher(pem);
        return m.matches() ? b64(m.group(1).replace("\n", "")) : new byte[0];
    }

    /** {@link #verifySigstoreBundleCore}, then the SLSA v1 predicate: the {@code facts} {@link ProvenanceGate#provenanceGate} checks. */
    public static Result verifySigstoreBundle(Object bundle, PinnedRoots roots) {
        CoreResult r = verifySigstoreBundleCore(bundle, roots);
        if (!r.ok) return new Result(false, null, r.code, r.detail);
        Map<String, Object> st = r.statement, c = r.core;
        if (!ProvenanceGate.SLSA_PROVENANCE_V1.equals(st.get("predicateType"))) return new Result(false, null, "predicate", "predicate " + st.get("predicateType") + " is not SLSA provenance v1");
        Map<String, Object> pr = objOrEmpty(st.get("predicate"));
        Map<String, Object> bd = objOrEmpty(pr.get("buildDefinition"));
        Map<String, Object> rd = objOrEmpty(pr.get("runDetails"));
        Object builderId = at(rd.get("builder"), "id");
        if (!(bd.get("buildType") instanceof String) || !(builderId instanceof String) || obj(bd.get("externalParameters")) == null)
            return new Result(false, null, "predicate", "buildType, externalParameters and builder.id are required (SLSA Build L1)");
        List<?> deps = arr(bd.get("resolvedDependencies"));
        Map<String, Object> dep0 = deps.isEmpty() ? null : obj(deps.get(0));
        Object depCommit = dep0 == null ? null : at(dep0.get("digest"), "gitCommit");
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("v", 1L);
        f.put("predicate_type", ProvenanceGate.SLSA_PROVENANCE_V1);
        f.put("build_type", bd.get("buildType"));
        f.put("builder_id", builderId);
        f.put("subjects", c.get("subjects"));
        f.put("identity", c.get("identity"));
        f.put("oidc_issuer", c.get("oidc_issuer"));
        for (String k : List.of("source_repo", "source_ref", "source_digest")) if (c.containsKey(k)) f.put(k, c.get(k));
        if (dep0 != null && dep0.get("uri") instanceof String) {
            Map<String, Object> ps = new LinkedHashMap<>();
            ps.put("uri", dep0.get("uri"));
            if (depCommit instanceof String) ps.put("git_commit", depCommit);
            f.put("provenance_source", ps);
        }
        f.put("integrated_time", c.get("signed_time"));
        f.put("rekor_log_index", c.get("rekor_log_index"));
        return new Result(true, f, null, null);
    }
}
