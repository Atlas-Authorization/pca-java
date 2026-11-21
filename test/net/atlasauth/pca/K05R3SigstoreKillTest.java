package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static net.atlasauth.pca.SigstoreK05KillTest.*;
import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Round 3 mutation kills for {@link Sigstore}, each pinned to packages/pca-attest-eat/src/sigstore.ts. Checks no bundle can reach
 * (the verifier already filtered their input) are called directly through reflection; everything else goes through whole bundles
 * from the {@link SigstoreK05KillTest} fixtures.
 */
public class K05R3SigstoreKillTest {
    static final char DASH = (char) 0x2014;
    static final byte[] KID = {1, 2, 3, 4};

    static byte[] utf(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    static Object call(String method, Class<?>[] types, Object... args) throws Exception {
        Method f = Sigstore.class.getDeclaredMethod(method, types);
        f.setAccessible(true);
        return f.invoke(null, args);
    }

    static Object parsedCert(byte[] der) throws Exception { return call("parseCert", new Class<?>[] {byte[].class}, (Object) der); }

    // ---- trusted root: the Ed25519 log (sigstore.ts:129-136) ----

    static Sigstore.PinnedRoots edRoot(byte[] der, String baseUrl) {
        byte[] raw = Arrays.copyOfRange(der, der.length - 32, der.length);
        byte[] id = sha256(utf("log.example\n"), new byte[] {1}, raw);
        return Sigstore.parseTrustedRoot(trustedRoot(List.of(logEntry("PKIX_ED25519", der, id, baseUrl)), List.of(), List.of(caEntry(caCert()))));
    }

    @Test void ed25519LogKeyIsParsedAndKept() {
        byte[] der = ED.getPublic().getEncoded();
        assertArrayEquals(der, edRoot(der, "https://log.example/x").tlogs.get(0).key.getEncoded());
        // the id hash matches, but the bytes are no SPKI: createPublicKey refuses them
        byte[] junk = new byte[44];
        Arrays.fill(junk, (byte) 7);
        assertThrows(IllegalArgumentException.class, () -> edRoot(junk, "https://log.example/x"));
    }

    @Test void baseUrlIsPreprocessedLikeWhatwgUrl() {
        byte[] der = ED.getPublic().getEncoded();
        assertEquals("log.example", edRoot(der, (char) 1 + " https://log.example/x " + (char) 31).tlogs.get(0).v2Name);
        assertEquals("log.example", edRoot(der, "https://log.exa\tm\npl\re/x").tlogs.get(0).v2Name);
    }

    // ---- DER lengths (sigstore.ts:174) and OIDs (sigstore.ts:196, 205) ----

    @Test void longFormLengths() {
        assertEquals("DER length", why(new byte[] {0x30, (byte) 0x81}));
        assertEquals("DER length", why(new byte[] {0x30, (byte) 0x85, 0, 0, 0, 0, 0}));
        assertEquals("not CMS SignedData", why(new byte[] {0x30, (byte) 0x84, 0, 0, 0, 0}));
        assertEquals("not CMS SignedData", why(new byte[] {0x30, (byte) 0x81, 0}));
    }

    @Test void paddingByteAfterAnOddArcIsNotMinimal() {
        assertEquals("OID arc is not minimally encoded", why(oidToken(new byte[] {0x2b, (byte) 0x80, 1})));
    }

    @Test void firstArcSplitsAtFortyAndEighty() {
        Bun b = new Bun().build();
        byte[] forty = seq(withTag(0x06, new byte[] {40}), octets(new byte[0]));
        refused(b.leaf(miniCert(forty, forty)).verify(), "cert_parse", "fail closed: duplicate extension 1.0");
        byte[] eighty = seq(withTag(0x06, new byte[] {80}), octets(new byte[0]));
        refused(b.leaf(miniCert(eighty, eighty)).verify(), "cert_parse", "fail closed: duplicate extension 2.0");
    }

    // ---- leaf parse (sigstore.ts:223-229; the per-extension shape is OpenSSL's rule there) ----

    static byte[] certWithExtsBlock(byte[]... blockKids) { return seq(seq(withTag(0xa3, blockKids)), seq(), bits((byte) 0, new byte[] {1})); }

    @Test void extensionsBlockShape() {
        Bun b = new Bun().build();
        refused(b.leaf(certWithExtsBlock()).verify(), "cert_parse", "fail closed: extensions malformed");
        refused(b.leaf(certWithExtsBlock(seq(), seq())).verify(), "cert_parse", "fail closed: extensions malformed");
        refused(b.leaf(certWithExtsBlock(integer(1))).verify(), "cert_parse", "fail closed: extensions malformed");
    }

    @Test void extensionShape() {
        Bun b = new Bun().build();
        refused(b.leaf(miniCert(integer(1))).verify(), "cert_parse", "fail closed: extension is not a SEQUENCE");
        refused(b.leaf(miniCert(seq(oid("1.2.3")))).verify(), "cert_parse", "fail closed: extension malformed");
        refused(b.leaf(miniCert(seq())).verify(), "cert_parse", "fail closed: extension malformed");
    }

    // ---- identity (sigstore.ts:247, 252, 263) ----

    @Test void sanThatIsNotUtf8IsRefused() {
        Bun b = new Bun();
        b.san = san(withTag(0x86, new byte[] {(byte) 0xff}));
        refused(b.build().verify(), "identity", "fail closed: not UTF-8");
    }

    @Test void fulcioExtensionIsRawUpToSixAndDerFromSeven() throws Exception {
        Object pc = parsedCert(miniCert(ext("1.3.6.1.4.1.57264.1.6", false, utf("raw6")), ext("1.3.6.1.4.1.57264.1.7", false, utf8("der7"))));
        Class<?>[] types = {pc.getClass(), int.class};
        assertEquals("raw6", call("fulcioExt", types, pc, 6));
        assertEquals("der7", call("fulcioExt", types, pc, 7));
    }

    /** generalNamesDecode refuses a non-SEQUENCE SAN first, so no bundle reaches this check: called directly. */
    @Test void sanIdentityWantsASequence() throws Exception {
        Object pc = parsedCert(miniCert(ext("2.5.29.17", false, withTag(0x31, uriName(IDENTITY)))));
        Throwable t = assertThrows(InvocationTargetException.class, () -> call("sanIdentity", new Class<?>[] {pc.getClass()}, pc)).getCause();
        assertEquals(IllegalArgumentException.class, t.getClass());
        assertEquals("subjectAltName must hold exactly one name", t.getMessage());
    }

    // ---- GeneralNames when checking the issuer ----

    @Test void sanWithTrailingBytesIsNotIssued() {
        Bun b = new Bun();
        b.san = ext("2.5.29.17", false, cat(seq(uriName(IDENTITY)), new byte[] {0}));
        refused(b.build().verify(), "cert_chain", NOT_ISSUED);
    }

    @Test void registeredIdDecodesButIsNoIdentity() {
        Bun b = new Bun();
        b.san = san(withTag(0x88, new byte[] {0x2a}));
        refused(b.build().verify(), "identity", "fail closed: subjectAltName must be a URI or an email");
    }

    // ---- key usage and AKI ----

    @Test void anIssuerWithoutKeyUsageMayIssue() {
        assertEquals(GEN_MS, Sigstore.verifyRfc3161(new Tok().build(), DATA, tsas(tsaLeaf(TSA, tsEku()), tsaRoot(basicConstraints(true, -1)))));
    }

    /** Only getExtensionValue is read. The JDK always wraps a value in an OCTET STRING: this is how the wrapper check is reached. */
    static final class ExtCert extends X509Certificate {
        final String oid;
        final byte[] value;
        ExtCert(String oid, byte[] value) { this.oid = oid; this.value = value; }
        public byte[] getExtensionValue(String o) { return oid.equals(o) ? value : null; }
        public void checkValidity() { throw new UnsupportedOperationException(); }
        public void checkValidity(Date d) { throw new UnsupportedOperationException(); }
        public int getVersion() { throw new UnsupportedOperationException(); }
        public BigInteger getSerialNumber() { throw new UnsupportedOperationException(); }
        public Principal getIssuerDN() { throw new UnsupportedOperationException(); }
        public Principal getSubjectDN() { throw new UnsupportedOperationException(); }
        public Date getNotBefore() { throw new UnsupportedOperationException(); }
        public Date getNotAfter() { throw new UnsupportedOperationException(); }
        public byte[] getTBSCertificate() { throw new UnsupportedOperationException(); }
        public byte[] getSignature() { throw new UnsupportedOperationException(); }
        public String getSigAlgName() { throw new UnsupportedOperationException(); }
        public String getSigAlgOID() { throw new UnsupportedOperationException(); }
        public byte[] getSigAlgParams() { throw new UnsupportedOperationException(); }
        public boolean[] getIssuerUniqueID() { throw new UnsupportedOperationException(); }
        public boolean[] getSubjectUniqueID() { throw new UnsupportedOperationException(); }
        public boolean[] getKeyUsage() { throw new UnsupportedOperationException(); }
        public int getBasicConstraints() { throw new UnsupportedOperationException(); }
        public byte[] getEncoded() { throw new UnsupportedOperationException(); }
        public void verify(PublicKey k) { throw new UnsupportedOperationException(); }
        public void verify(PublicKey k, String p) { throw new UnsupportedOperationException(); }
        public String toString() { return "ExtCert " + oid; }
        public PublicKey getPublicKey() { throw new UnsupportedOperationException(); }
        public boolean hasUnsupportedCriticalExtension() { throw new UnsupportedOperationException(); }
        public Set<String> getCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
        public Set<String> getNonCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
    }

    // ---- sigOk: a hash is for an EC or RSA key only ----

    /** Reports its algorithm as "XX" for the first {@code lies} reads, then as the RSA key it is. */
    static final class ShiftyRsaKey implements RSAPublicKey {
        final RSAPublicKey k = (RSAPublicKey) RSA.getPublic();
        int lies;
        ShiftyRsaKey(int lies) { this.lies = lies; }
        public String getAlgorithm() { return lies-- > 0 ? "XX" : "RSA"; }
        public String getFormat() { return k.getFormat(); }
        public byte[] getEncoded() { return k.getEncoded(); }
        public BigInteger getModulus() { return k.getModulus(); }
        public BigInteger getPublicExponent() { return k.getPublicExponent(); }
    }

    @Test void aKeyThatIsNeitherEcNorRsaNeverVerifiesWithAHash() {
        Bun b = new Bun().build();
        byte[] keyId = sha256(TLOG.getPublic().getEncoded());
        String setMsg = "{\"body\":\"" + b.entry.get("canonicalizedBody") + "\",\"integratedTime\":1767225600,\"logID\":\"" + hex(keyId) + "\",\"logIndex\":0}";
        b.entry.put("inclusionPromise", m("signedEntryTimestamp", b64(sign("SHA256withRSA", RSA.getPrivate(), utf(setMsg)))));
        Sigstore.PinnedRoots r = Sigstore.parseTrustedRoot(b.roots);
        long[] always = {0, Long.MAX_VALUE};
        Sigstore.PinnedRoots lying = new Sigstore.PinnedRoots(List.of(new Sigstore.PinnedLog(keyId, new ShiftyRsaKey(1), always, null)), r.ctlogs, r.cas, r.tsas);
        refused(Sigstore.verifySigstoreBundleCore(b.bundle, lying), "tlog_set", "signed entry timestamp invalid");
        // control: read as RSA from the start, the same signature verifies (the checkpoint is the next refusal)
        Sigstore.PinnedRoots honest = new Sigstore.PinnedRoots(List.of(new Sigstore.PinnedLog(keyId, new ShiftyRsaKey(0), always, null)), r.ctlogs, r.cas, r.tsas);
        refused(Sigstore.verifySigstoreBundleCore(b.bundle, honest), "tlog_checkpoint", "no checkpoint signature by the pinned log key");
    }

    // ---- checkpoints (sigstore.ts:447-451) ----

    @Test void signatureLinesAreReadOnlyAfterTheBlankLine() {
        Bun b = new Bun().build();
        Map<String, Object> ip = mm(b.entry.get("inclusionProof"));
        // an origin shaped like a signature line whose base64 does not decode: scanned, it would throw
        String body = DASH + " x abc\n1\n" + ip.get("rootHash") + "\n";
        byte[] sig = sign("SHA256withECDSA", TLOG.getPrivate(), utf(body));
        byte[] hint = Arrays.copyOf(sha256(TLOG.getPublic().getEncoded()), 4);
        mm(ip.get("checkpoint")).put("envelope", body + "\n" + DASH + " rekor.example " + b64(cat(hint, sig)) + "\n");
        accepted(b.verify());
    }

    /** A key id whose fourth byte is 0: a 3-byte line padded by the slice would match its hint. */
    @Test void tooShortSignatureIsSkipped() throws Exception {
        byte[] root = new byte[32];
        Sigstore.PinnedLog log = new Sigstore.PinnedLog(Arrays.copyOf(new byte[] {1, 2, 3}, 32), TLOG.getPublic(), new long[] {0, Long.MAX_VALUE}, null);
        String text = "o\n1\n" + b64(root) + "\n\n" + DASH + " n " + b64(new byte[] {1, 2, 3}) + "\n";
        Object got = call("verifyCheckpoint", new Class<?>[] {String.class, Sigstore.PinnedLog.class, long.class, byte[].class}, text, log, 1L, root);
        assertEquals("no checkpoint signature by the pinned log key", got);
    }

    // ---- bundle shape (sigstore.ts:511, 520) ----

    @Test void aMediaTypeThatIsNotAStringNeverMatches() {
        Bun b = new Bun().build();
        b.bundle.put("mediaType", new Object() {
            @Override public boolean equals(Object o) { return true; }
            @Override public int hashCode() { return 1; }
            @Override public String toString() { return "odd"; }
        });
        refused(Sigstore.verifySigstoreBundleCore(b.bundle, Sigstore.parseTrustedRoot(b.roots)), "media_type", "unsupported media type odd");
    }

    @Test void envelopeNeedsExactlyOneSignature() {
        String want = "a DSSE envelope must carry exactly one signature";
        for (Object sigs : new Object[] {List.of(), List.of(m("sig", "AAAA"), m("sig", "AAAA")), List.of("x"), "x"}) {
            Bun b = new Bun().build();
            mm(b.bundle.get("dsseEnvelope")).put("signatures", sigs);
            refused(b.verify(), "envelope", want);
        }
    }

    // ---- CA validFor bounds are inclusive (sigstore.ts:585) ----

    static void caValidFor(Bun b, Map<String, Object> validFor) {
        mm(((List<?>) b.roots.get("certificateAuthorities")).get(0)).put("validFor", validFor);
    }

    @Test void caValidityIncludesBothEnds() {
        Bun b = new Bun().build();
        caValidFor(b, m("start", "2026-01-01T00:00:00Z", "end", "2026-01-01T00:00:00Z"));
        accepted(b.verify());
        caValidFor(b, m("start", "2026-01-01T00:00:01Z"));
        refused(b.verify(), "cert_chain", NOT_ISSUED);
        caValidFor(b, m("start", "2020-01-01T00:00:00Z", "end", "2025-12-31T23:59:59Z"));
        refused(b.verify(), "cert_chain", NOT_ISSUED);
    }

    // ---- the leaf's curve picks the hash (sigstore.ts:471-475, 635-636) ----

    /** A keyless bundle for any leaf key, no CT logs: Rekor v1 dsse with a SET, or (v2Alg set) Rekor v2 hashedrekord with a TSA time. */
    static final class Mini {
        KeyPair leafKey = LEAF;
        String jca = "SHA256withECDSA";
        String v2Alg;
        String v2Digest = "sha256";
        Map<String, Object> bundle, roots;

        Mini build() {
            boolean v2 = v2Alg != null;
            byte[] leaf = cert("leaf", "ca", leafKey, CA, san(uriName(IDENTITY)), ext("2.5.29.37", false, seq(oid(EKU_CS))), ext("1.3.6.1.4.1.57264.1.1", false, utf(ISSUER)));
            byte[] payload = utf(STATEMENT);
            byte[] pae = Sigstore.dssePae("application/vnd.in-toto+json", payload);
            byte[] sig = sign(jca, leafKey.getPrivate(), pae);
            String pem = "-----BEGIN CERTIFICATE-----\n" + b64(leaf) + "\n-----END CERTIFICATE-----\n";
            Map<String, Object> body = v2
                ? m("apiVersion", "0.0.2", "kind", "hashedrekord", "spec", m("hashedRekordV002", m(
                    "data", m("algorithm", v2Alg, "digest", b64(Sigstore.sha(v2Digest, pae))),
                    "signature", m("content", b64(sig), "verifier", m("x509Certificate", m("rawBytes", b64(leaf)))))))
                : m("apiVersion", "0.0.1", "kind", "dsse", "spec", m("payloadHash", m("algorithm", "sha256", "value", hex(sha256(payload))),
                    "signatures", List.of(m("signature", b64(sig), "verifier", b64(utf(pem))))));
            byte[] bodyBytes = utf(Json.canonicalize(body));
            byte[] root = ProvenanceGate.rfc9162LeafHash(bodyBytes);
            byte[] edDer = ED.getPublic().getEncoded();
            byte[] keyId = v2 ? sha256(utf("log.example\n"), new byte[] {1}, Arrays.copyOfRange(edDer, edDer.length - 32, edDer.length)) : sha256(TLOG.getPublic().getEncoded());
            String cpBody = "log.example\n1\n" + b64(root) + "\n";
            byte[] cpSig = v2 ? sign("Ed25519", ED.getPrivate(), utf(cpBody)) : sign("SHA256withECDSA", TLOG.getPrivate(), utf(cpBody));
            String envelope = cpBody + "\n" + DASH + " log.example " + b64(cat(Arrays.copyOf(keyId, 4), cpSig)) + "\n";
            Map<String, Object> entry = m("logIndex", "0", "logId", m("keyId", b64(keyId)), "kindVersion", m("kind", v2 ? "hashedrekord" : "dsse", "version", v2 ? "0.0.2" : "0.0.1"),
                "inclusionProof", m("logIndex", "0", "rootHash", b64(root), "treeSize", "1", "hashes", new ArrayList<Object>(), "checkpoint", m("envelope", envelope)),
                "canonicalizedBody", b64(bodyBytes));
            List<Object> stamps = new ArrayList<>();
            if (v2) {
                Tok t = new Tok();
                t.imprint = sha256(sig);
                stamps.add(m("signedTimestamp", b64(t.build())));
            } else {
                String setMsg = "{\"body\":\"" + b64(bodyBytes) + "\",\"integratedTime\":1767225600,\"logID\":\"" + hex(keyId) + "\",\"logIndex\":0}";
                entry.put("integratedTime", "1767225600");
                entry.put("inclusionPromise", m("signedEntryTimestamp", b64(sign("SHA256withECDSA", TLOG.getPrivate(), utf(setMsg)))));
            }
            bundle = m("mediaType", V03,
                "verificationMaterial", m("certificate", m("rawBytes", b64(leaf)), "tlogEntries", List.of(entry), "timestampVerificationData", m("rfc3161Timestamps", stamps)),
                "dsseEnvelope", m("payload", b64(payload), "payloadType", "application/vnd.in-toto+json", "signatures", List.of(m("sig", b64(sig), "keyid", ""))));
            Map<String, Object> tlog = v2 ? logEntry("PKIX_ED25519", edDer, keyId, "https://log.example/") : ecLog(TLOG);
            roots = trustedRoot(List.of(tlog), List.of(), List.of(caEntry(caCert())));
            roots.put("timestampAuthorities", List.of(m("certChain", m("certificates", List.of(m("rawBytes", b64(tsaLeaf(TSA, tsEku()))), m("rawBytes", b64(tsaRoot())))),
                "validFor", m("start", "2020-01-01T00:00:00Z"))));
            return this;
        }

        Sigstore.CoreResult verify() { return Sigstore.verifySigstoreBundleCore(bundle, Sigstore.parseTrustedRoot(roots)); }
    }

    static Mini mini(String curve, String jca, String v2Alg, String v2Digest) {
        Mini x = new Mini();
        x.leafKey = ecKey(curve);
        x.jca = jca;
        x.v2Alg = v2Alg;
        x.v2Digest = v2Digest;
        return x.build();
    }

    static void ok(Sigstore.CoreResult r, String rekor) {
        assertTrue(r.ok, r.code + " | " + r.detail);
        assertEquals(rekor, r.core.get("rekor"));
    }

    @Test void leafCurvePicksTheDsseHash() {
        ok(mini("secp256r1", "SHA256withECDSA", null, "sha256").verify(), "v1");
        ok(mini("secp384r1", "SHA384withECDSA", null, "sha256").verify(), "v1");
        refused(mini("secp384r1", "SHA256withECDSA", null, "sha256").verify(), "signature", "DSSE signature invalid");
        refused(mini("secp521r1", "SHA384withECDSA", null, "sha256").verify(), "signature", "unsupported leaf key type");
    }

    @Test void rekorV2EntryNamesTheLeafsHash() {
        ok(mini("secp256r1", "SHA256withECDSA", "SHA2_256", "sha256").verify(), "v2");
        ok(mini("secp384r1", "SHA384withECDSA", "SHA2_384", "sha384").verify(), "v2");
        String want = "the entry digest algorithm is not the signing key's";
        refused(mini("secp384r1", "SHA384withECDSA", "SHA2_512", "sha384").verify(), "tlog_body", want);
        refused(mini("secp384r1", "SHA384withECDSA", "MD5", "sha384").verify(), "tlog_body", want);
        refused(mini("secp256r1", "SHA256withECDSA", "SHA2_384", "sha256").verify(), "tlog_body", want);
    }
}
