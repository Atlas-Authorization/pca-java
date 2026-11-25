package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.interfaces.ECPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/** Guard-deletion audit (AttestB): refusals restored after the mutation program removed them. */
public class K05GuardAuditAttestBTest {
    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @Test
    void maaRefusesAnEmptyX5cChain() {
        AttestMaa v = (AttestMaa) AttestMaa.create(map("trustedIssuers", List.of("https://i"),
            "trustAnchors", map("rootSpkiSha256", List.of("00".repeat(32))), "policy", map("sevSnpMeasurements", List.of("aa"))));
        AttestMaa.Leaf leaf = v.verifyX5cChain(List.of(), 0L);
        assertNull(leaf.cert);
        assertEquals("empty x5c certificate chain", leaf.why);
    }

    @Test
    void gcpRefusesAnEmptyJwkX5cChain() {
        AttestGcp v = (AttestGcp) AttestGcp.create(map("trustedIssuers", List.of("https://i"),
            "trustAnchors", map("trustedKeySpki", List.of("ab")), "policy", map("imageDigests", List.of("sha256:abc"))));
        assertEquals("empty x5c certificate chain", v.verifyJwkX5cChain(List.of(), 0L));
    }

    @Test
    void rawEcdsaRefusesAnEmptySignature() {
        ECPoint q = AttestCommonK05bKillTest.find(AttestCommonK05bKillTest.P256, p -> true);
        ECPublicKey pub = AttestCommon.ecKeyOf("P-256", AttestCommonK05bKillTest.x(q), AttestCommonK05bKillTest.y(q));
        assertNotNull(pub);
        assertFalse(AttestCommon.verifyRawECDSA(pub, new byte[32], new byte[0]));
    }
}
