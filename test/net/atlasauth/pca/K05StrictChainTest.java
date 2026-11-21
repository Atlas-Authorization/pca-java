package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.basicConstraints;
import static net.atlasauth.pca.AttestTestDer.cert;
import static net.atlasauth.pca.AttestTestDer.ecKey;
import static net.atlasauth.pca.AttestTestDer.ext;
import static net.atlasauth.pca.AttestTestDer.keyUsageCertSign;
import static net.atlasauth.pca.AttestTestDer.keyUsageDigitalSignature;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * strictChainError (packages/pca/src/x509-strict.ts:266), and the chains the MAA, GCP and NVIDIA kill tests run through it:
 * each case signs properly up to a pinned root, so only the chain profile can refuse it.
 */
public class K05StrictChainTest {
    static final String LEAF = "GH100 A01 FSP BROM";

    static final class Case {
        final String name;
        final List<byte[]> ders;
        /** The profile reason; "" for a chain that passes. */
        final String reason;
        /** NVIDIA refuses this issuer earlier, with its own reason (attest-nvidia-spdm.ts: issuer.ca, which is X509_check_ca). */
        final boolean notCa;

        Case(String name, String reason, boolean notCa, byte[]... ders) {
            this.name = name;
            this.reason = reason;
            this.notCa = notCa;
            this.ders = List.of(ders);
        }
    }

    static byte[] unknownCritical() { return ext("1.2.3.4", true, new byte[] {0x05, 0x00}); }

    static byte[] ekuCritical() { return ext("2.5.29.37", true, seq(oid("1.3.6.1.5.5.7.3.1"))); }

    /** Every case's last certificate is the self-signed root, a proper CA holding rootKey. */
    static List<Case> cases(KeyPair leafKey, KeyPair rootKey, String curve) {
        KeyPair a = ecKey(curve);
        KeyPair b = ecKey(curve);
        byte[] root = cert("root", "root", rootKey, rootKey, basicConstraints(true, -1), keyUsageCertSign());
        byte[] ca = cert("inter", "root", a, rootKey, basicConstraints(true, -1), keyUsageCertSign());
        byte[] leaf = cert(LEAF, "inter", leafKey, a);
        List<Case> out = new ArrayList<>();
        out.add(new Case("plain chain", "", false, leaf, ca, root));
        out.add(new Case("EKU critical is allowed", "", false, cert(LEAF, "inter", leafKey, a, ekuCritical()),
            cert("inter", "root", a, rootKey, basicConstraints(true, -1), keyUsageCertSign(), ekuCritical()), root));
        out.add(new Case("an unknown extension that is not critical", "", false,
            cert(LEAF, "inter", leafKey, a, ext("1.2.3.4", false, new byte[] {0x05, 0x00})), ca, root));
        out.add(new Case("pathLen exactly met", "", false, leaf,
            cert("inter", "root", a, rootKey, basicConstraints(true, 0), keyUsageCertSign()), root));
        out.add(new Case("leaf CA:TRUE", "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)", false,
            cert(LEAF, "inter", leafKey, a, basicConstraints(true, -1)), ca, root));
        out.add(new Case("issuer CA:FALSE", "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)", true,
            leaf, cert("inter", "root", a, rootKey, basicConstraints(false, -1)), root));
        out.add(new Case("issuer without BasicConstraints", "issuer certificate at depth 1 has no BasicConstraints (not a CA)", true,
            leaf, cert("inter", "root", a, rootKey), root));
        out.add(new Case("keyUsage without keyCertSign", "issuer certificate at depth 1 keyUsage lacks keyCertSign", true,
            leaf, cert("inter", "root", a, rootKey, basicConstraints(true, -1), keyUsageDigitalSignature()), root));
        out.add(new Case("pathLen exceeded", "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)", false,
            cert(LEAF, "inter2", leafKey, b),
            cert("inter2", "inter", b, a, basicConstraints(true, -1), keyUsageCertSign()),
            cert("inter", "root", a, rootKey, basicConstraints(true, 0), keyUsageCertSign()), root));
        out.add(new Case("critical 1.2.3.4 on the leaf", "certificate at depth 0 has an unrecognised critical extension 1.2.3.4", false,
            cert(LEAF, "inter", leafKey, a, unknownCritical()), ca, root));
        out.add(new Case("critical 1.2.3.4 on the intermediate", "certificate at depth 1 has an unrecognised critical extension 1.2.3.4", false,
            leaf, cert("inter", "root", a, rootKey, basicConstraints(true, -1), keyUsageCertSign(), unknownCritical()), root));
        return out;
    }

    @Test
    void theProfileReasons() {
        for (Case c : cases(ecKey("secp256r1"), ecKey("secp256r1"), "secp256r1")) {
            assertEquals(c.reason, AttestDer.strictChainError(c.ders), c.name);
        }
        KeyPair k = ecKey("secp256r1");
        byte[] lone = cert("x", "x", k, k, basicConstraints(true, -1));
        assertEquals("", AttestDer.strictChainError(List.of(lone)), "a lone CA has no leaf role");
        assertEquals("certificate at depth 0 has an unrecognised critical extension 1.2.3.4",
            AttestDer.strictChainError(List.of(cert("x", "x", k, k, unknownCritical()))), "a lone certificate still has its extensions read");
        assertEquals("", AttestDer.strictChainError(List.of()));
    }

    @Test
    void aReadFailureIsAFailure() {
        assertTrue(AttestDer.strictChainError(List.of(new byte[] {1, 2, 3})).startsWith("certificate extension parse failed: "));
        KeyPair k = ecKey("secp256r1");
        byte[] good = cert("x", "x", k, k);
        // the second read of the list is the extension pass: one that fails there reaches its catch
        List<byte[]> flips = new AbstractList<byte[]>() {
            int reads;

            @Override public byte[] get(int i) { return reads++ == 0 ? good : new byte[] {1, 2, 3}; }

            @Override public int size() { return 1; }
        };
        assertTrue(AttestDer.strictChainError(flips).startsWith("certificate extension parse failed: "));
    }

    @Test
    void parsedCertificatesCarryTheirRawBytes() {
        KeyPair k = ecKey("secp256r1");
        AttCert c = AttestCert.parseCertDer(cert("x", "x", k, k, unknownCritical()));
        assertEquals("certificate at depth 0 has an unrecognised critical extension 1.2.3.4", AttestDer.strictChainErrorOf(List.of(c)));
    }
}
