package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * NVIDIA collateral, CRL coverage (PCA 0.5 hardening): a verified CRL from a certificate's issuer must exist for every non-root chain
 * certificate that names a CRL distribution point ({@code requireCrlFor} default {@code "cdp"}), for every non-root certificate
 * ({@code "all"}) or for the listed chain indices. Before this, any one fresh CRL (for example the root's alone) satisfied the check and a
 * revoked device certificate passed.
 */
class AttestNvidiaCrlCoverageTest {
    static final AttestNvidiaTest.Gpu G = AttestNvidiaRimKillTest.G;
    static final long NOW = AttestNvidiaRimKillTest.NOW;
    static final KeyPair INTER = ecKey("secp384r1");

    /** CRL distribution points: one DistributionPoint with a fullName URI. */
    static final byte[] CDP = ext("2.5.29.31", false, seq(seq(withTag(0xa0, withTag(0xa0, withTag(0x86, "http://crl.example/nv.crl".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))))));
    static final byte[] CA = basicConstraints(true, -1);

    static AttCert interCert(boolean withCdp) {
        return AttestCert.parseCertDer(withCdp ? cert("NV Inter", "NV Root", INTER, G.root, CA, keyUsageCertSign(), CDP) : cert("NV Inter", "NV Root", INTER, G.root, CA, keyUsageCertSign()));
    }

    static AttCert leafCert(boolean withCdp) {
        return AttestCert.parseCertDer(withCdp ? cert("GH100 A01 FSP BROM", "NV Inter", G.leaf, INTER, CDP) : cert("GH100 A01 FSP BROM", "NV Inter", G.leaf, INTER));
    }

    static final String MISSING_LEAF = "no verified CRL from the issuer of chain certificate 'CN=GH100 A01 FSP BROM'";
    static final String MISSING_INTER = "no verified CRL from the issuer of chain certificate 'CN=NV Inter'";

    static String rev(List<AttCert> chain, Object how, byte[]... crls) {
        return AttestNvidiaRim.checkChainRevocation(chain, Arrays.asList(crls), NOW, new ArrayList<>(), how);
    }

    @Test
    void aRootCrlAloneNoLongerCoversACdpChain() {
        List<AttCert> chain = Arrays.asList(leafCert(true), interCert(true), AttestCert.parseCertDer(G.rootDer));
        byte[] rootCrl = AttestNvidiaRimKillTest.crlOf(G.root);
        byte[] interCrl = AttestNvidiaRimKillTest.crlOf(INTER);
        // 1: only the root's CRL (valid, fresh): the device and intermediate certificates are not covered
        assertEquals(MISSING_LEAF, rev(chain, "cdp", rootCrl));
        // 2: the intermediate's CRL covers the leaf, the root's covers the intermediate
        assertEquals("", rev(chain, "cdp", interCrl, rootCrl));
        assertEquals(MISSING_INTER, rev(chain, "cdp", interCrl));
        // 3: a revoked leaf on the intermediate's CRL still fails as revoked (the test certificates all carry serial 258)
        assertEquals("chain certificate 'CN=GH100 A01 FSP BROM' is revoked", rev(chain, "cdp", AttestNvidiaRimKillTest.crlOf(INTER, new byte[] {1, 2}), rootCrl));
        // nothing names a distribution point (the plain test chain): no coverage is demanded
        assertEquals("", rev(AttestNvidiaRimKillTest.CHAIN, "cdp", rootCrl));
    }

    @Test
    void allAndExplicitIndicesDemandCoverageWithoutADistributionPoint() {
        List<AttCert> chain = Arrays.asList(leafCert(true), interCert(false), AttestCert.parseCertDer(G.rootDer)); // only the leaf names a CDP
        byte[] rootCrl = AttestNvidiaRimKillTest.crlOf(G.root);
        byte[] interCrl = AttestNvidiaRimKillTest.crlOf(INTER);
        // 4: 'cdp' demands the leaf only, 'all' also the intermediate (no CDP, no CRL from the root)
        assertEquals("", rev(chain, "cdp", interCrl));
        assertEquals(MISSING_INTER, rev(chain, "all", interCrl));
        assertEquals("", rev(chain, "all", interCrl, rootCrl));
        assertEquals("", rev(chain, Arrays.<Object>asList(0L), interCrl));
        assertEquals(MISSING_INTER, rev(chain, Arrays.<Object>asList(1L), interCrl));
        assertEquals(MISSING_LEAF, rev(chain, Arrays.<Object>asList(0L, 1L), rootCrl));
        assertEquals("", rev(chain, Collections.<Object>emptyList(), rootCrl));
        assertEquals("", rev(chain, "none", interCrl));
        assertEquals("", rev(chain, "none", rootCrl));
    }

    @Test
    void anIndexThatIsNotANonRootCertificateFailsAndAMalformedOptionThrows() {
        List<AttCert> chain = Arrays.asList(leafCert(true), interCert(true), AttestCert.parseCertDer(G.rootDer));
        byte[] rootCrl = AttestNvidiaRimKillTest.crlOf(G.root);
        byte[] interCrl = AttestNvidiaRimKillTest.crlOf(INTER);
        // 5: the root (index 2), a negative index and a far index are refused with the same wording
        assertEquals("requireCrlFor index 2 is not a non-root chain certificate", rev(chain, Arrays.<Object>asList(2L), interCrl, rootCrl));
        assertEquals("requireCrlFor index -1 is not a non-root chain certificate", rev(chain, Arrays.<Object>asList(0L, -1L), interCrl, rootCrl));
        assertEquals("requireCrlFor index 7 is not a non-root chain certificate", rev(chain, Arrays.<Object>asList(7L), interCrl, rootCrl));
        assertEquals("", rev(chain, Arrays.<Object>asList(0L, 1L), interCrl, rootCrl));
        // the option is validated when the hook is built
        String[][] bads = {{"\"bogus\"", "bogus"}, {"\"ALL\"", "ALL"}, {"5", "5"}, {"true", "true"}, {"[\"a\"]", "a"}, {"[1.5]", "1.5"}, {"[null]", ""}, {"{\"a\":1}", "[object Object]"}, {"[0,-1]", "0,-1"}};
        for (String[] b : bads) {
            String bad = b[0], msg = "nvidiaCollateralHook: malformed requireCrlFor '" + b[1] + "'";
            AttestException e = assertThrows(AttestException.class, () -> AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"aa\"],\"requireCrlFor\":" + bad + "}")), bad);
            assertEquals(msg, e.getMessage(), bad);
        }
        for (String good : new String[] {"null", "\"cdp\"", "\"all\"", "[]", "[0,1]"}) {
            AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"aa\"],\"requireCrlFor\":" + good + "}"));
        }
    }

    @Test
    void theHookDemandsCoverageOnlyWhereCrlsAreRequired() {
        List<AttCert> chain = Arrays.asList(leafCert(true), interCert(true), AttestCert.parseCertDer(G.rootDer));
        String rootCrl = AttestNvidiaRimKillTest.b64(AttestNvidiaRimKillTest.crlOf(G.root));
        String interCrl = AttestNvidiaRimKillTest.b64(AttestNvidiaRimKillTest.crlOf(INTER));
        String leafRevoked = AttestNvidiaRimKillTest.b64(AttestNvidiaRimKillTest.crlOf(INTER, new byte[] {1, 2}));
        String d = AttestNvidiaRimKillTest.DRIVER, v = AttestNvidiaRimKillTest.VBIOS;
        java.util.function.BiFunction<String, List<String>, String> run = (extra, crls) ->
            AttestNvidiaRimKillTest.run(extra, AttestNvidiaRimKillTest.bundle(d, v, crls, null), chain);
        // the default ('cdp', CRLs required): the root's CRL alone is refused, the intermediate's plus the root's passes
        assertEquals("revocation: " + MISSING_LEAF, run.apply("", Arrays.asList(rootCrl)));
        assertEquals("", run.apply("", Arrays.asList(interCrl, rootCrl)));
        assertEquals("revocation: " + MISSING_LEAF, run.apply(",\"revocation\":\"crl\"", Arrays.asList(rootCrl)));
        assertEquals("revocation: " + MISSING_LEAF, run.apply(",\"revocation\":\"both\"", Arrays.asList(rootCrl)));
        assertEquals("revocation: requireCrlFor index 2 is not a non-root chain certificate", run.apply(",\"requireCrlFor\":[2]", Arrays.asList(interCrl, rootCrl)));
        assertEquals("", run.apply(",\"requireCrlFor\":[]", Arrays.asList(rootCrl)));
        // 6: OCSP-only mode, or CRLs not required: the CRLs that are supplied are enforced, but no coverage is demanded
        assertEquals("revocation (OCSP): no OCSP responses supplied", run.apply(",\"revocation\":\"ocsp\"", Arrays.asList(rootCrl)));
        assertEquals("", run.apply(",\"requireCrls\":false", Arrays.asList(rootCrl)));
        assertEquals("revocation: chain certificate 'CN=GH100 A01 FSP BROM' is revoked", run.apply(",\"requireCrls\":false", Arrays.asList(leafRevoked)));
        assertEquals("revocation: chain certificate 'CN=GH100 A01 FSP BROM' is revoked", run.apply(",\"revocation\":\"ocsp\"", Arrays.asList(leafRevoked)));
    }

    /** Fail closed: a CRL distribution point extension whose content cannot be parsed still counts as naming one, and a certificate whose extensions cannot be parsed is not a certificate. */
    @Test
    void anUnparsableDistributionPointStillRequiresACrl() {
        byte[] garbage = ext("2.5.29.31", false, new byte[] {0x01, 0x02, 0x03});
        AttCert leaf = AttestCert.parseCertDer(cert("GH100 A01 FSP BROM", "NV Inter", G.leaf, INTER, garbage));
        List<AttCert> chain = Arrays.asList(leaf, interCert(false), AttestCert.parseCertDer(G.rootDer));
        byte[] rootCrl = AttestNvidiaRimKillTest.crlOf(G.root);
        assertEquals(MISSING_LEAF, rev(chain, "cdp", rootCrl));
        assertEquals("", rev(chain, "cdp", AttestNvidiaRimKillTest.crlOf(INTER)));
        // an extension whose OID is not a valid OBJECT IDENTIFIER makes the whole certificate unparsable: it can never reach the chain
        byte[] badOid = seq(withTag(0x04, new byte[] {0x01}), octets(new byte[] {0x05}));
        assertThrows(AttestException.class, () -> AttestCert.parseCertDer(cert("GH100 A01 FSP BROM", "NV Inter", G.leaf, INTER, badOid)));
    }
}
