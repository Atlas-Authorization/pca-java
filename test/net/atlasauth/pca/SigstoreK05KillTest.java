package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Sigstore}. Three levers:
 * <ul>
 *   <li>the k05 oracle (test-data/k05-sigstore.json.gz) replayed for the exact refusal DETAIL and thrown message (the diff test
 *       compares codes only); details the reference takes from the JavaScript runtime or OpenSSL are skipped;
 *   <li>a synthetic Sigstore PKI generated here (Fulcio-like CA and leaf with embedded SCTs, an ECDSA Rekor v1 log with SET,
 *       inclusion proof and signed checkpoint): whole bundles that verify, then one change at a time, each with its exact verdict;
 *   <li>a synthetic RFC 3161 timestamp authority: TimeStampTokens built byte by byte, every refusal message, chain / AKI / key
 *       usage / EKU / key-type rules.
 * </ul>
 * Trusted roots are parsed inside each test (a cached parse is covered only by the first test that ran it).
 */
public class SigstoreK05KillTest {
    static final String EKU_TS = "1.3.6.1.5.5.7.3.8", EKU_CS = "1.3.6.1.5.5.7.3.3";
    static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String SIGNED_DATA = "1.2.840.113549.1.7.2", TST_INFO = "1.2.840.113549.1.9.16.1.4";
    static final String CONTENT_TYPE = "1.2.840.113549.1.9.3", MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    static final String SCT_OID = "1.3.6.1.4.1.11129.2.4.2";
    static final long GEN_MS = 1767225600000L; // 2026-01-01T00:00:00Z
    static final byte[] DATA = "the signature".getBytes(StandardCharsets.UTF_8);
    static final String V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
    static final String IDENTITY = "https://github.com/o/r/.github/workflows/w.yml@refs/heads/main";
    static final String ISSUER = "https://token.actions.githubusercontent.com";
    static final String NOT_ISSUED = "no pinned CA issued the certificate, valid at every signing time";
    static final String NO_TSA = "no pinned timestamp authority signed it (valid at its time)";

    static final KeyPair ROOT = ecKey("secp256r1"), TSA = ecKey("secp256r1"), CA = ecKey("secp256r1"), LEAF = ecKey("secp256r1");
    static final KeyPair TLOG = ecKey("secp256r1"), CT = ecKey("secp256r1");
    static final KeyPair RSA = gen("RSA"), ED = gen("Ed25519");

    // ---- small helpers ----

    static KeyPair gen(String alg) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
            if (alg.equals("RSA")) g.initialize(2048);
            return g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) d.update(p);
            return d.digest();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sign(String alg, PrivateKey k, byte[] data) {
        try {
            Signature s = Signature.getInstance(alg);
            s.initSign(k);
            s.update(data);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static X509Certificate x509(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (java.security.cert.CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    static byte[] u16(int n) { return new byte[] {(byte) (n >> 8), (byte) n}; }

    static byte[] set(byte[]... p) { return withTag(0x31, p); }

    static byte[] ctx0(byte[]... p) { return withTag(0xa0, p); }

    static byte[] gtime(String s) { return withTag(0x18, s.getBytes(StandardCharsets.US_ASCII)); }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> mm(Object o) { return (Map<String, Object>) o; }

    /** {tag, body start, end} of the TLV at {@code off}. */
    static int[] tl(byte[] b, int off) {
        int len = b[off + 1] & 0xff, body = off + 2;
        if ((len & 0x80) != 0) {
            int n = len & 0x7f;
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | (b[body + i] & 0xff);
            body += n;
        }
        return new int[] {b[off] & 0xff, body, body + len};
    }

    /** The PKCS#1 RSAPublicKey inside an RSA SPKI. */
    static byte[] pkcs1(PublicKey k) {
        byte[] s = k.getEncoded();
        int[] outer = tl(s, 0), alg = tl(s, outer[1]), bitStr = tl(s, alg[2]);
        return Arrays.copyOfRange(s, bitStr[1] + 1, bitStr[2]);
    }

    // ---- trusted roots ----

    static Map<String, Object> logEntry(String keyDetails, byte[] raw, byte[] keyId, String baseUrl) {
        Map<String, Object> e = m("publicKey", m("rawBytes", b64(raw), "keyDetails", keyDetails, "validFor", m("start", "2020-01-01T00:00:00Z")),
            "logId", m("keyId", b64(keyId)));
        if (baseUrl != null) e.put("baseUrl", baseUrl);
        return e;
    }

    static Map<String, Object> ecLog(KeyPair k) { return logEntry("PKIX_ECDSA_P256_SHA_256", k.getPublic().getEncoded(), sha256(k.getPublic().getEncoded()), null); }

    static Map<String, Object> rsaLog(KeyPair k) { return logEntry("PKCS1_RSA_PKCS1V5", pkcs1(k.getPublic()), sha256(k.getPublic().getEncoded()), null); }

    static Map<String, Object> caEntry(byte[] cert) {
        return m("certChain", m("certificates", List.of(m("rawBytes", b64(cert)))), "validFor", m("start", "2020-01-01T00:00:00Z"));
    }

    static byte[] caCert() { return cert("ca", "ca", CA, CA, basicConstraints(true, -1), keyUsageCertSign()); }

    static Map<String, Object> trustedRoot(List<Object> tlogs, List<Object> ctlogs, List<Object> cas) {
        return m("mediaType", "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs", tlogs, "ctlogs", ctlogs,
            "certificateAuthorities", cas, "timestampAuthorities", List.of());
    }

    static String rootRefusal(Map<String, Object> root) {
        return assertThrows(IllegalArgumentException.class, () -> Sigstore.parseTrustedRoot(root)).getMessage();
    }

    // ---- the synthetic bundle ----

    /** One SCT of the embedded list; {@code raw} (when set) is used as the SCT bytes as they are. */
    static final class Sct {
        byte[] raw;
        byte[] logId;
        long ts = GEN_MS;
        byte[] ext = new byte[0];
        int sigAlg = 3;
        KeyPair key = CT;
        String jca = "SHA256withECDSA";
    }

    static byte[] sctBytes(Sct c, byte[] precert) {
        if (c.raw != null) return c.raw;
        byte[] logId = c.logId != null ? c.logId : sha256(c.key.getPublic().getEncoded());
        byte[] ts = java.nio.ByteBuffer.allocate(8).putLong(c.ts).array();
        byte[] head = cat(new byte[] {0, 0}, ts, new byte[] {0, 1});
        byte[] signed = cat(head, sha256(CA.getPublic().getEncoded()), new byte[] {(byte) (precert.length >> 16), (byte) (precert.length >> 8), (byte) precert.length},
            precert, u16(c.ext.length), c.ext);
        byte[] sig = sign(c.jca, c.key.getPrivate(), signed);
        return cat(new byte[] {0}, logId, ts, u16(c.ext.length), c.ext, new byte[] {4, (byte) c.sigAlg}, u16(sig.length), sig);
    }

    static byte[] tbs(List<byte[]> exts) {
        byte[] e = exts.isEmpty() ? new byte[0] : withTag(0xa3, seq(cat(exts.toArray(new byte[0][]))));
        return seq(withTag(0xa0, integer(2)), integer(259), SIG_ALG_ECDSA_SHA256, name("ca"),
            seq(withTag(0x17, "250101000000Z".getBytes(StandardCharsets.US_ASCII)), withTag(0x17, "350101000000Z".getBytes(StandardCharsets.US_ASCII))),
            name("leaf"), LEAF.getPublic().getEncoded(), e);
    }

    static byte[] uriName(String u) { return withTag(0x86, u.getBytes(StandardCharsets.US_ASCII)); }

    static byte[] san(byte[]... names) { return ext("2.5.29.17", false, seq(names)); }

    static final String STATEMENT = "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"a\",\"digest\":{\"sha256\":\"" + "a".repeat(64)
        + "\"}}],\"predicateType\":\"PT\",\"predicate\":{\"buildDefinition\":{\"buildType\":\"bt\",\"externalParameters\":{}},\"runDetails\":{\"builder\":{\"id\":\"bid\"}}}}";

    static final class Bun {
        String kind = "dsse";
        byte[] san = san(uriName(IDENTITY)); // null: no SAN
        byte[] eku = ext("2.5.29.37", false, seq(oid(EKU_CS))); // null: no EKU
        List<byte[]> extra = new ArrayList<>();
        List<Sct> scts = new ArrayList<>(List.of(new Sct()));
        byte[] sctTail = new byte[0];
        byte[] sctExtnValue; // replaces the whole SCT extension value
        boolean rsaCt;
        byte[] outerAlg = SIG_ALG_ECDSA_SHA256;
        boolean corruptSig;
        String payload = STATEMENT.replace("PT", "https://slsa.dev/provenance/v1");
        Object bodySigs; // replaces the entry body's signatures

        Map<String, Object> bundle, entry, roots;

        Bun build() {
            List<byte[]> exts = new ArrayList<>();
            if (san != null) exts.add(san);
            if (eku != null) exts.add(eku);
            exts.add(ext("1.3.6.1.4.1.57264.1.1", false, ISSUER.getBytes(StandardCharsets.UTF_8)));
            exts.addAll(extra);
            byte[] precert = tbs(exts);
            byte[] list = new byte[0];
            for (Sct c : scts) {
                byte[] s = sctBytes(c, precert);
                list = cat(list, u16(s.length), s);
            }
            list = cat(list, sctTail);
            exts.add(ext(SCT_OID, false, sctExtnValue != null ? sctExtnValue : octets(cat(u16(list.length), list))));
            byte[] tbs = tbs(exts);
            byte[] sig = sign("SHA256withECDSA", CA.getPrivate(), tbs);
            if (corruptSig) sig[0] = 0x31;
            byte[] leaf = seq(tbs, outerAlg, bits((byte) 0, sig));

            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
            byte[] dsseSig = sign("SHA256withECDSA", LEAF.getPrivate(), Sigstore.dssePae("application/vnd.in-toto+json", payloadBytes));
            String pem = "-----BEGIN CERTIFICATE-----\n" + b64(leaf) + "\n-----END CERTIFICATE-----\n";
            Map<String, Object> ph = m("algorithm", "sha256", "value", hex(sha256(payloadBytes)));
            Map<String, Object> body = kind.equals("dsse")
                ? m("apiVersion", "0.0.1", "kind", "dsse", "spec", m("payloadHash", ph, "signatures",
                    bodySigs != null ? bodySigs : List.of(m("signature", b64(dsseSig), "verifier", b64(pem.getBytes(StandardCharsets.UTF_8))))))
                : m("apiVersion", "0.0.2", "kind", "intoto", "spec", m("content", m("payloadHash", ph, "envelope", m("signatures",
                    bodySigs != null ? bodySigs : List.of(m("sig", b64(b64(dsseSig).getBytes(StandardCharsets.UTF_8)), "publicKey", b64(pem.getBytes(StandardCharsets.UTF_8))))))));
            byte[] bodyBytes = Json.canonicalize(body).getBytes(StandardCharsets.UTF_8);
            byte[] root = ProvenanceGate.rfc9162LeafHash(bodyBytes);
            byte[] keyId = sha256(TLOG.getPublic().getEncoded());
            String setMsg = "{\"body\":\"" + b64(bodyBytes) + "\",\"integratedTime\":1767225600,\"logID\":\"" + hex(keyId) + "\",\"logIndex\":0}";
            byte[] setSig = sign("SHA256withECDSA", TLOG.getPrivate(), setMsg.getBytes(StandardCharsets.UTF_8));
            String cpBody = "rekor.example\n1\n" + b64(root) + "\n";
            byte[] cpSig = sign("SHA256withECDSA", TLOG.getPrivate(), cpBody.getBytes(StandardCharsets.UTF_8));
            String envelope = cpBody + "\n— rekor.example " + b64(cat(Arrays.copyOf(keyId, 4), cpSig)) + "\n";
            entry = m("logIndex", "0", "logId", m("keyId", b64(keyId)), "kindVersion", m("kind", kind, "version", kind.equals("dsse") ? "0.0.1" : "0.0.2"),
                "integratedTime", "1767225600", "inclusionPromise", m("signedEntryTimestamp", b64(setSig)),
                "inclusionProof", m("logIndex", "0", "rootHash", b64(root), "treeSize", "1", "hashes", new ArrayList<Object>(), "checkpoint", m("envelope", envelope)),
                "canonicalizedBody", b64(bodyBytes));
            bundle = m("mediaType", V03,
                "verificationMaterial", m("certificate", m("rawBytes", b64(leaf)), "tlogEntries", List.of(entry), "timestampVerificationData", m("rfc3161Timestamps", List.of())),
                "dsseEnvelope", m("payload", b64(payloadBytes), "payloadType", "application/vnd.in-toto+json", "signatures", List.of(m("sig", b64(dsseSig), "keyid", ""))));
            roots = trustedRoot(List.of(ecLog(TLOG)), List.of(rsaCt ? rsaLog(RSA) : ecLog(CT)), List.of(caEntry(caCert())));
            return this;
        }

        Sigstore.CoreResult verify() { return Sigstore.verifySigstoreBundleCore(bundle, Sigstore.parseTrustedRoot(roots)); }

        Bun leaf(byte[] der) {
            mm(mm(bundle.get("verificationMaterial")).get("certificate")).put("rawBytes", b64(der));
            return this;
        }
    }

    static void refused(Sigstore.CoreResult r, String code, String detail) {
        assertFalse(r.ok, "accepted: " + r.core);
        assertEquals(code + " | " + detail, r.code + " | " + r.detail);
    }

    static void accepted(Sigstore.CoreResult r) {
        assertTrue(r.ok, r.code + " | " + r.detail);
        assertEquals(IDENTITY, r.core.get("identity"));
        assertEquals(1767225600L, r.core.get("signed_time"));
        assertEquals(0L, r.core.get("rekor_log_index"));
        assertEquals(Map.of("tsa", 0L, "set", true), r.core.get("timestamps"));
    }

    // ---- whole bundles ----

    @Test void syntheticBundleVerifiesWithEcAndRsaCtLogs() {
        Bun b = new Bun().build();
        Sigstore.CoreResult r = b.verify();
        accepted(r);
        assertEquals(ISSUER, r.core.get("oidc_issuer"));
        assertEquals("v1", r.core.get("rekor"));
        assertEquals(List.of(m("alg", "sha256", "digest", "a".repeat(64))), r.core.get("subjects"));
        Bun rsa = new Bun();
        rsa.rsaCt = true;
        rsa.scts.get(0).key = RSA;
        rsa.scts.get(0).jca = "SHA256withRSA";
        rsa.scts.get(0).sigAlg = 1;
        accepted(rsa.build().verify());
        Bun intoto = new Bun();
        intoto.kind = "intoto";
        accepted(intoto.build().verify());
        Sigstore.Result f = Sigstore.verifySigstoreBundle(b.bundle, Sigstore.parseTrustedRoot(b.roots));
        assertTrue(f.ok, f.code + " " + f.detail);
        assertEquals("bid", f.facts.get("builder_id"));
    }

    @Test void predicateRefusalNamesThePredicate() {
        Bun b = new Bun();
        b.payload = STATEMENT.replace("PT", "x");
        b.build();
        Sigstore.Result f = Sigstore.verifySigstoreBundle(b.bundle, Sigstore.parseTrustedRoot(b.roots));
        assertEquals("false predicate predicate x is not SLSA provenance v1", f.ok + " " + f.code + " " + f.detail);
        Bun arr = new Bun();
        arr.payload = "[]";
        refused(arr.build().verify(), "statement", "not an in-toto Statement v1");
    }

    @Test void bundleShapeRefusals() {
        Bun b = new Bun().build();
        Sigstore.PinnedRoots roots = Sigstore.parseTrustedRoot(b.roots);
        refused(Sigstore.verifySigstoreBundleCore(null, roots), "malformed", "not a bundle");
        refused(Sigstore.verifySigstoreBundleCore(b.bundle, null), "malformed", "not a bundle");
        b.bundle.remove("mediaType");
        refused(Sigstore.verifySigstoreBundleCore(b.bundle, roots), "media_type", "unsupported media type undefined");

        Bun k = new Bun().build();
        k.entry.remove("kindVersion");
        refused(k.verify(), "tlog_kind", "unsupported entry ");
        Bun li = new Bun().build();
        li.entry.put("logIndex", "9999999999999999");
        refused(li.verify(), "tlog_key", "fail closed: integer out of range");
        Bun np = new Bun().build();
        np.entry.remove("inclusionProof");
        refused(np.verify(), "tlog_inclusion", "no inclusion proof");
        Bun nh = new Bun().build();
        mm(nh.entry.get("inclusionProof")).put("hashes", "x");
        refused(nh.verify(), "tlog_inclusion", "no inclusion proof");
        Bun cp = new Bun().build();
        mm(mm(cp.entry.get("inclusionProof")).get("checkpoint")).put("envelope", "\n\nx");
        refused(cp.verify(), "tlog_checkpoint", "checkpoint body too short or without an origin");
        Bun cr = new Bun().build();
        mm(mm(cr.entry.get("inclusionProof")).get("checkpoint")).put("envelope", "rekor.example\n1\n" + b64(new byte[32]) + "\n\nx");
        refused(cr.verify(), "tlog_checkpoint", "checkpoint root differs from the proof");
        Bun is = new Bun();
        is.kind = "intoto";
        is.bodySigs = List.of("x");
        refused(is.build().verify(), "tlog_body", "the entry must name exactly one signature");
    }

    // ---- the leaf: parse, issuance, identity ----

    static byte[] miniCert(byte[]... exts) { return seq(seq(withTag(0xa3, seq(exts))), seq(), bits((byte) 0, new byte[] {1})); }

    @Test void leafParseRefusals() {
        Bun b = new Bun().build();
        byte[] leaf = Base64.getDecoder().decode((String) mm(mm(b.bundle.get("verificationMaterial")).get("certificate")).get("rawBytes"));
        refused(b.leaf(cat(leaf, new byte[] {0})).verify(), "cert_parse", "fail closed: certificate is not one SEQUENCE");
        byte[] e = seq(oid("1.2.3"), octets(new byte[0]));
        refused(b.leaf(seq(seq(withTag(0xa3, seq(e))), seq())).verify(), "cert_parse", "fail closed: certificate is not tbs, algorithm, signature");
        refused(b.leaf(seq(integer(1), seq(), bits((byte) 0, new byte[] {1}))).verify(), "cert_parse", "fail closed: no TBSCertificate");
        refused(b.leaf(miniCert(seq(oid("1.2.3"), bool(true), octets(new byte[0]), octets(new byte[0])))).verify(), "cert_parse", "fail closed: extension malformed");
        refused(b.leaf(miniCert(seq(oid("1.2.3"), integer(1)))).verify(), "cert_parse", "fail closed: extension value is not an OCTET STRING");
        // the first arc of 128 (0x81 0x00) prints as 2.48
        byte[] big = seq(withTag(0x06, new byte[] {(byte) 0x81, 0}), octets(new byte[0]));
        refused(b.leaf(miniCert(big, big)).verify(), "cert_parse", "fail closed: duplicate extension 2.48");
    }

    @Test void leafIssuance() {
        Bun bad = new Bun();
        bad.corruptSig = true; // not a DER ECDSA signature: the JDK verifier throws
        refused(bad.build().verify(), "cert_chain", NOT_ISSUED);
        Bun alg = new Bun();
        alg.outerAlg = seq(oid("1.2.840.10045.4.3.2"), new byte[] {5, 0}); // the same algorithm, other bytes than the TBS copy
        Sigstore.CoreResult r = alg.build().verify();
        assertFalse(r.ok);
        assertTrue(r.code.equals("cert_chain") || r.code.equals("cert_parse"), r.code + " " + r.detail);
        Bun eku = new Bun();
        eku.eku = ext("2.5.29.37", false, set()); // malformed: Node checkIssued is false (OpenSSL marks the certificate invalid)
        refused(eku.build().verify(), "cert_chain", NOT_ISSUED);
        Bun noEku = new Bun();
        noEku.eku = null; // getExtendedKeyUsage returns null
        refused(noEku.build().verify(), "cert_eku", "the certificate lacks the code-signing EKU");
        Bun otherEku = new Bun();
        otherEku.eku = ext("2.5.29.37", false, seq(oid(EKU_TS)));
        refused(otherEku.build().verify(), "cert_eku", "the certificate lacks the code-signing EKU");
        Bun otherName = new Bun();
        otherName.san = san(withTag(0x80, new byte[] {1})); // not a GeneralName OpenSSL decodes
        refused(otherName.build().verify(), "cert_chain", NOT_ISSUED);
    }

    @Test void identityRefusals() {
        Bun none = new Bun();
        none.san = null;
        refused(none.build().verify(), "identity", "fail closed: no subjectAltName");
        Bun two = new Bun();
        two.san = san(uriName(IDENTITY), uriName(IDENTITY));
        refused(two.build().verify(), "identity", "fail closed: subjectAltName must hold exactly one name");
        Bun dns = new Bun();
        dns.san = san(withTag(0x82, "x.example".getBytes(StandardCharsets.US_ASCII)));
        refused(dns.build().verify(), "identity", "fail closed: subjectAltName must be a URI or an email");
        Bun edi = new Bun();
        edi.san = san(withTag(0xa5)); // an empty ediPartyName does not decode: Node checkIssued is false
        refused(edi.build().verify(), "cert_chain", NOT_ISSUED);
    }

    // ---- SCTs ----

    static Sigstore.CoreResult withScts(java.util.function.Consumer<Bun> edit) {
        Bun b = new Bun();
        edit.accept(b);
        return b.build().verify();
    }

    static byte[] rawSct(int len, int version, int extLen) {
        byte[] s = new byte[len];
        s[0] = (byte) version;
        if (len >= 43) {
            s[41] = (byte) (extLen >> 8);
            s[42] = (byte) extLen;
        }
        if (len >= 47 && extLen == 0) s[43] = 4;
        return s;
    }

    @Test void sctListParsing() {
        refused(withScts(b -> b.sctExtnValue = octets(new byte[0])), "sct", "SCT list length");
        refused(withScts(b -> b.sctExtnValue = octets(new byte[] {0})), "sct", "SCT list length");
        // an SCT of an unknown log, then one stray byte
        refused(withScts(b -> { b.scts.get(0).logId = new byte[32]; b.sctTail = new byte[] {0}; }), "sct", "SCT truncated");
        // shorter than the 47-byte minimum (even of an unknown version)
        refused(withScts(b -> b.scts.set(0, raw(rawSct(10, 1, 0)))), "sct", "SCT truncated");
        // exactly 47 bytes of an unknown log: parsed, skipped, the list ends
        refused(withScts(b -> b.scts.set(0, raw(rawSct(47, 0, 0)))), "sct", "no SCT from a pinned CT log");
        refused(withScts(b -> b.scts.set(0, raw(rawSct(47, 0, 4)))), "sct", "SCT truncated");
        refused(withScts(b -> b.scts.set(0, raw(rawSct(47, 0, 2)))), "sct", "SCT truncated");
    }

    static Sct raw(byte[] s) {
        Sct c = new Sct();
        c.raw = s;
        return c;
    }

    @Test void sctTimestampRange() {
        accepted(withScts(b -> b.scts.get(0).ts = 9007199254740991L));
        refused(withScts(b -> b.scts.get(0).ts = 9007199254740992L), "sct", "SCT timestamp out of range");
        refused(withScts(b -> b.scts.get(0).ts = Long.MIN_VALUE), "sct", "SCT timestamp out of range");
    }

    @Test void sctSignedDataLengths() {
        // a precertificate TBS over 64 KiB (the 24-bit length's top byte is 1) and SCT extensions over 255 bytes
        accepted(withScts(b -> b.extra.add(ext("1.2.3.4.5", false, new byte[70000]))));
        accepted(withScts(b -> b.scts.get(0).ext = new byte[300]));
    }

    // ---- trusted roots ----

    @Test void trustedRootRefusals() {
        List<Object> cas = List.of(caEntry(caCert()));
        // Ed25519 log: no baseUrl means no note name, even when the key hash happens to be over the empty name
        byte[] edDer = ED.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(edDer, edDer.length - 32, edDer.length);
        byte[] emptyNameId = sha256("\n".getBytes(StandardCharsets.UTF_8), new byte[] {1}, raw);
        assertEquals("log id is not the signed-note key hash of its key",
            rootRefusal(trustedRoot(List.of(logEntry("PKIX_ED25519", edDer, emptyNameId, null)), List.of(), cas)));
        byte[] namedId = sha256("log.example\n".getBytes(StandardCharsets.UTF_8), new byte[] {1}, raw);
        Sigstore.PinnedRoots v2 = Sigstore.parseTrustedRoot(trustedRoot(List.of(logEntry("PKIX_ED25519", edDer, namedId, "https://LOG.example/x")), List.of(), cas));
        assertEquals("log.example", v2.tlogs.get(0).v2Name);
        assertEquals("Invalid URL", rootRefusal(trustedRoot(List.of(logEntry("PKIX_ED25519", edDer, namedId, "x")), List.of(), cas))); // no host
        assertEquals("log id is not the SHA-256 of its key",
            rootRefusal(trustedRoot(List.of(logEntry("PKIX_ECDSA_P256_SHA_256", TLOG.getPublic().getEncoded(), new byte[32], null)), List.of(), cas)));
        assertEquals("log id is not the SHA-256 of its key",
            rootRefusal(trustedRoot(List.of(ecLog(TLOG)), List.of(logEntry("PKCS1_RSA_PKCS1V5", pkcs1(RSA.getPublic()), new byte[32], null)), cas)));
        Map<String, Object> noLogId = ecLog(TLOG);
        noLogId.remove("logId");
        assertEquals("log entry malformed", rootRefusal(trustedRoot(List.of(noLogId), List.of(), cas)));
        Map<String, Object> noStart = ecLog(TLOG);
        mm(mm(noStart.get("publicKey")).get("validFor")).remove("start");
        assertEquals("validFor.start missing", rootRefusal(trustedRoot(List.of(noStart), List.of(), cas)));
        Map<String, Object> badStart = ecLog(TLOG);
        mm(mm(badStart.get("publicKey")).get("validFor")).put("start", "2020-01-01");
        assertEquals("validFor.start missing", rootRefusal(trustedRoot(List.of(badStart), List.of(), cas)));
        Map<String, Object> badEnd = ecLog(TLOG);
        mm(mm(badEnd.get("publicKey")).get("validFor")).put("end", "never");
        assertEquals("validFor.end malformed", rootRefusal(trustedRoot(List.of(badEnd), List.of(), cas)));
        Map<String, Object> notB64 = ecLog(TLOG);
        mm(notB64.get("publicKey")).put("rawBytes", "@@@@");
        assertEquals("not base64", rootRefusal(trustedRoot(List.of(notB64), List.of(), cas)));
        // a JDK parse failure keeps its message (and its cause)
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Sigstore.parseTrustedRoot(trustedRoot(List.of(ecLog(TLOG)), List.of(), List.of(m("certChain", m("certificates", List.of(m("rawBytes", "AAAA"))),
                "validFor", m("start", "2020-01-01T00:00:00Z"))))));
        assertNotNull(e.getCause());
        assertNotNull(e.getCause().getMessage());
        assertEquals("trusted root malformed: " + e.getCause().getMessage(), e.getMessage());
    }

    @Test void shaNamesTheJdkDigest() throws Exception {
        assertArrayEquals(MessageDigest.getInstance("SHA-384").digest(DATA), Sigstore.sha("sha384", DATA));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Sigstore.sha("sha-256", DATA)); // SHA--256
        assertTrue(e.getCause() instanceof java.security.NoSuchAlgorithmException, String.valueOf(e.getCause()));
    }

    // ---- RFC 3161 ----

    static byte[] tsaRoot(byte[]... exts) { return cert("root", "root", ROOT, ROOT, exts); }

    static byte[] tsaRoot() { return tsaRoot(basicConstraints(true, -1), keyUsageCertSign()); }

    static byte[] tsaLeaf(KeyPair k, byte[]... exts) { return cert("tsa", "root", k, ROOT, exts); }

    static byte[] tsEku() { return ext("2.5.29.37", false, seq(oid(EKU_TS))); }

    static List<Sigstore.PinnedCa> tsas(byte[] leaf, byte[] root) {
        return List.of(new Sigstore.PinnedCa(List.of(x509(leaf), x509(root)), new long[] {0, Long.MAX_VALUE}));
    }

    static List<Sigstore.PinnedCa> goodTsas() { return tsas(tsaLeaf(TSA, tsEku()), tsaRoot()); }

    static final class Tok {
        byte[] imprintAlg = seq(oid(SHA256));
        byte[] imprint = sha256(DATA);
        byte[] genTime = gtime("20260101000000Z");
        byte[] digestAlg = seq(oid(SHA256));
        int attrsTag = 0xa0;
        byte[] ctValue = oid(TST_INFO);
        byte[] mdValue; // null: the TSTInfo digest
        int sigTag = 0x04;
        KeyPair signer = TSA;
        String jca = "SHA256withECDSA";
        int signerCount = 1;
        boolean signerInfosSet = true;
        int status = -1; // >= 0: wrapped in a TimeStampResp with this status

        byte[] build() {
            byte[] tst = seq(integer(1), oid("1.2.3.4"), seq(imprintAlg, octets(imprint)), integer(7), genTime);
            byte[] md = mdValue != null ? mdValue : octets(sha256(tst));
            byte[] attrs = cat(seq(oid(CONTENT_TYPE), set(ctValue)), seq(oid(MESSAGE_DIGEST), set(md)));
            byte[] sig = sign(jca, signer.getPrivate(), set(attrs));
            byte[] si = seq(integer(1), seq(), digestAlg, withTag(attrsTag, attrs), seq(oid("1.2.840.10045.4.3.2")), withTag(sigTag, sig));
            byte[] sis = !signerInfosSet ? integer(0) : signerCount == 1 ? set(si) : set(si, si);
            byte[] sd = seq(integer(3), set(seq(oid(SHA256))), seq(oid(TST_INFO), ctx0(octets(tst))), sis);
            byte[] ci = seq(oid(SIGNED_DATA), ctx0(sd));
            return status >= 0 ? seq(seq(integer(status)), ci) : ci;
        }
    }

    static String why(byte[] token, List<Sigstore.PinnedCa> tsas) {
        return assertThrows(IllegalArgumentException.class, () -> Sigstore.verifyRfc3161(token, DATA, tsas)).getMessage();
    }

    static String why(byte[] token) { return why(token, List.of()); }

    static String why(Tok t) { return why(t.build(), goodTsas()); }

    @Test void timestampVerifies() {
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(new Tok().build(), DATA, goodTsas()));
        Tok resp = new Tok();
        resp.status = 0;
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(resp.build(), DATA, goodTsas()));
        Tok frac = new Tok();
        frac.genTime = gtime("20260101000000.5Z");
        assertEquals(GEN_MS + 500, Sigstore.verifyRfc3161(frac.build(), DATA, goodTsas()));
        Tok micro = new Tok();
        micro.genTime = gtime("20260101000000.123456Z");
        assertEquals(GEN_MS + 123, Sigstore.verifyRfc3161(micro.build(), DATA, goodTsas()));
        Tok rsa = new Tok();
        rsa.signer = RSA;
        rsa.jca = "SHA256withRSA";
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(rsa.build(), DATA, tsas(tsaLeaf(RSA, tsEku()), tsaRoot())));
    }

    @Test void timestampStructureRefusals() {
        assertEquals("not CMS SignedData", why(seq()));
        assertEquals("not CMS SignedData", why(seq(oid(SIGNED_DATA))));
        assertEquals("not CMS SignedData", why(seq(oid("1.2.3"), ctx0())));
        assertEquals("not an OID", why(seq(integer(1), ctx0())));
        assertEquals("not an OID", why(seq(seq(withTag(0x02)), seq()))); // a 2-byte first SEQUENCE is no TimeStampResp status
        assertEquals("no timeStampToken", why(seq(seq(integer(0)))));
        Tok st = new Tok();
        st.status = 2;
        assertEquals("timestamp status is not granted", why(st));
        byte[] sdNoEncap = seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), integer(2))));
        assertEquals("no encapsulated content", why(sdNoEncap));
        assertEquals("content is not TSTInfo", why(seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), seq(oid("1.2.3"), ctx0()))))));
        assertEquals("content is not TSTInfo", why(seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), seq())))));
        assertEquals("content is not TSTInfo", why(seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), seq(oid(TST_INFO)))))));
        assertEquals("not an OID", why(seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), seq(integer(1)))))));
        assertEquals("TSTInfo is not an OCTET STRING", why(seq(oid(SIGNED_DATA), ctx0(seq(integer(3), set(), seq(oid(TST_INFO), ctx0(integer(1))))))));
    }

    static byte[] oidToken(byte[] body) { return seq(withTag(0x06, body), ctx0()); }

    @Test void oidEncodingRules() {
        assertEquals("OID arc is not minimally encoded", why(oidToken(new byte[] {(byte) 0x80, 1})));
        assertEquals("OID arc is not minimally encoded", why(oidToken(new byte[] {0x2a, (byte) 0x80, 1})));
        assertEquals("OID arc is not minimally encoded", why(oidToken(new byte[] {0x2a, (byte) 0x80, (byte) 0x81, 1})));
        assertEquals("not CMS SignedData", why(oidToken(new byte[] {(byte) 0x81, (byte) 0x80, 1}))); // 0x80 inside an arc is fine
        assertEquals("OID ends inside an arc", why(oidToken(new byte[] {0x2a, (byte) 0x86})));
        // a 128-byte OID (long-form length) whose first byte is a padding 0x80
        byte[] longOid = new byte[128];
        Arrays.fill(longOid, (byte) 0x81);
        longOid[0] = (byte) 0x80;
        longOid[127] = 1;
        assertEquals("OID arc is not minimally encoded", why(oidToken(longOid)));
        // an arc reaching 2^56 before its last byte
        byte[] huge = new byte[10];
        huge[0] = (byte) 0x81;
        for (int i = 1; i < 9; i++) huge[i] = (byte) 0x80;
        assertEquals("OID arc too large", why(oidToken(huge)));
    }

    @Test void timestampContentRefusals() {
        Tok imp = new Tok();
        imp.imprint = new byte[32];
        assertEquals("messageImprint is not the hash of the signature", why(imp));
        Tok alg = new Tok();
        alg.imprintAlg = seq(oid("1.2.3"));
        assertEquals("unsupported digest algorithm", why(alg));
        Tok dalg = new Tok();
        dalg.digestAlg = seq(oid("1.2.3"));
        assertEquals("unsupported digest algorithm", why(dalg));
        Tok utc = new Tok();
        utc.genTime = withTag(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII));
        assertEquals("genTime is not a GeneralizedTime", why(utc));
        Tok mal = new Tok();
        mal.genTime = gtime("2026-01-01");
        assertEquals("genTime malformed", why(mal));
        Tok feb30 = new Tok();
        feb30.genTime = gtime("20260230000000Z");
        assertEquals("genTime is not a real date", why(feb30));
        Tok y99 = new Tok();
        y99.genTime = gtime("00991231235959Z"); // the reference's Date.UTC reads years 0..99 as 1900..1999: not a real date
        assertEquals("genTime is not a real date", why(y99));
        Tok y100 = new Tok();
        y100.genTime = gtime("01000101000000Z");
        assertEquals("no pinned timestamp authority signed it (valid at its time)", why(y100));
        Tok noSis = new Tok();
        noSis.signerInfosSet = false;
        assertEquals("no signerInfos", why(noSis));
        Tok two = new Tok();
        two.signerCount = 2;
        assertEquals("exactly one SignerInfo is required", why(two));
        Tok attrs = new Tok();
        attrs.attrsTag = 0xa1;
        assertEquals("signed attributes are required", why(attrs));
        Tok vals = new Tok();
        vals.ctValue = cat(oid(TST_INFO), oid(TST_INFO));
        assertEquals("an attribute must have one value", why(vals));
        Tok md = new Tok();
        md.mdValue = octets(new byte[32]);
        assertEquals("signed attributes do not commit to the TSTInfo", why(md));
        Tok sig = new Tok();
        sig.sigTag = 0x03;
        assertEquals("signature is not an OCTET STRING", why(sig));
        List<Sigstore.PinnedCa> later = List.of(new Sigstore.PinnedCa(goodTsas().get(0).chain, new long[] {GEN_MS + 1, Long.MAX_VALUE}));
        assertEquals(NO_TSA, why(new Tok().build(), later));
    }

    @Test void timestampAuthorityRules() {
        byte[] tok = new Tok().build();
        byte[] kid = {1, 2, 3, 4};
        byte[] aki = ext("2.5.29.35", false, seq(withTag(0x80, kid)));
        byte[] ski = ext("2.5.29.14", false, octets(kid));
        byte[] bc = basicConstraints(true, -1), ku = keyUsageCertSign();
        // AKI keyIdentifier = SKI: issued; an AKI with only the root's serial (258), or a root with no SKI: issued. Another serial: Node checkIssued is false
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(tok, DATA, tsas(tsaLeaf(TSA, tsEku(), aki), tsaRoot(bc, ku, ski))));
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(tok, DATA, tsas(tsaLeaf(TSA, tsEku(), ext("2.5.29.35", false, seq(withTag(0x82, new byte[] {1, 2})))), tsaRoot(bc, ku, ski))));
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku(), ext("2.5.29.35", false, seq(withTag(0x82, new byte[] {5})))), tsaRoot(bc, ku, ski))));
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(tok, DATA, tsas(tsaLeaf(TSA, tsEku(), aki), tsaRoot(bc, ku))));
        // another SKI, or a malformed AKI / SKI: not issued
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku(), aki), tsaRoot(bc, ku, ext("2.5.29.14", false, octets(new byte[] {9, 9}))))));
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku(), ext("2.5.29.35", false, set())), tsaRoot(bc, ku, ski))));
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku(), ext("2.5.29.35", false, new byte[] {0x30, 5, (byte) 0x80, 1})), tsaRoot(bc, ku, ski))));
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku(), aki), tsaRoot(bc, ku, ext("2.5.29.14", false, integer(5))))));
        // the issuer must be a CA allowed to sign certificates (keyCertSign only: crlSign is not needed)
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku()), tsaRoot(ku))));
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, tsEku()), tsaRoot(bc, keyUsageDigitalSignature()))));
        // the leaf needs the timeStamping EKU (an unparseable EKU is none) and an ECDSA or RSA key
        assertEquals(NO_TSA, why(tok, tsas(tsaLeaf(TSA, ext("2.5.29.37", false, set())), tsaRoot())));
        Tok ed = new Tok();
        ed.signer = ED;
        ed.jca = "Ed25519";
        assertEquals(NO_TSA, why(ed.build(), tsas(tsaLeaf(ED, tsEku()), tsaRoot())));
    }

    // ---- the oracle: exact details and thrown messages ----

    /** Reference messages that come from the JavaScript runtime, OpenSSL or WHATWG URL parsing (not portable text). */
    static final Pattern RUNTIME = Pattern.compile("error:|Cannot read|Unexpected|not valid JSON|The encoded data|Failed to read|Invalid URL|signed-note");

    static boolean portable(Object msg) { return msg instanceof String && !RUNTIME.matcher((String) msg).find(); }

    @Test void oracleRefusalDetails() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (String fn : List.of("verifySigstoreBundleCore", "verifySigstoreBundle")) {
            for (Map<String, Object> c : K05SigstoreDiffTest.of(fn)) {
                Map<?, ?> out = K05SigstoreDiffTest.map(c.get("out"));
                if (out == null || !Boolean.FALSE.equals(out.get("ok")) || !portable(out.get("detail"))) continue;
                List<?> a = K05SigstoreDiffTest.args(c);
                if ("media_type".equals(out.get("code"))) {
                    Map<?, ?> b = K05SigstoreDiffTest.map(a.get(0));
                    Object mt = b.get("mediaType");
                    if (b.containsKey("mediaType") && !(mt == null || mt instanceof String || mt instanceof Boolean)) continue; // JS number / object text
                }
                Sigstore.PinnedRoots r = K05SigstoreDiffTest.root(a.get(1));
                String got;
                if (fn.equals("verifySigstoreBundle")) {
                    Sigstore.Result v = Sigstore.verifySigstoreBundle(a.get(0), r);
                    got = v.ok + " " + v.code + " | " + v.detail;
                } else {
                    Sigstore.CoreResult v = Sigstore.verifySigstoreBundleCore(a.get(0), r);
                    got = v.ok + " " + v.code + " | " + v.detail;
                }
                String want = "false " + out.get("code") + " | " + out.get("detail");
                if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
                ran++;
            }
        }
        assertTrue(ran > 3000, "ran " + ran);
        assertTrue(bad.isEmpty(), bad.size() + " divergent detail(s):\n" + String.join("\n", bad.subList(0, Math.min(40, bad.size()))));
    }

    @Test void oracleThrownMessages() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : K05SigstoreDiffTest.of("parseTrustedRoot")) {
            Object out = c.get("out");
            if (!K05SigstoreDiffTest.throwsOut(out)) continue;
            Object want = K05SigstoreDiffTest.map(out).get("$throws");
            if (!portable(want)) continue;
            String got;
            try { Sigstore.parseTrustedRoot(K05SigstoreDiffTest.args(c).get(0)); got = "accepted"; } catch (RuntimeException e) { got = e.getMessage(); }
            if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
            ran++;
        }
        for (Map<String, Object> c : K05SigstoreDiffTest.of("verifyRfc3161")) {
            Object out = c.get("out");
            if (!K05SigstoreDiffTest.throwsOut(out)) continue;
            Object want = K05SigstoreDiffTest.map(out).get("$throws");
            if (!portable(want)) continue;
            List<?> a = K05SigstoreDiffTest.args(c);
            Sigstore.PinnedRoots r = K05SigstoreDiffTest.root(a.get(2));
            if (r == null) continue; // a root the Java parse refused (the diff test covers that case)
            String got;
            try {
                got = "accepted " + Sigstore.verifyRfc3161(Base64.getDecoder().decode((String) a.get(0)), Base64.getDecoder().decode((String) a.get(1)), r.tsas);
            } catch (RuntimeException e) { got = e.getMessage(); }
            if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
            ran++;
        }
        assertTrue(ran > 400, "ran " + ran);
        assertTrue(bad.isEmpty(), bad.size() + " divergent message(s):\n" + String.join("\n", bad.subList(0, Math.min(40, bad.size()))));
    }
}
