package net.atlasauth.pca;

import static net.atlasauth.pca.IntentV2KillTest.list;
import static net.atlasauth.pca.IntentV2KillTest.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Guard-deletion audit (Rest): the explicit refusals restored in K3, K4, RuntimeClaim and Passport keep their verdicts on malformed input. */
public class K05GuardAuditRestTest {
    @Test void k4MalformedInputsAreRefusedWithTheirReasons() {
        assertEquals("binding_malformed", K4.verifyBinding(null, map(), "h", "n", null));
        assertEquals("config_malformed", K4.pricingConfigError(null));
        assertEquals("config_malformed", K4.pricingConfigError(5L));
        assertEquals("response_malformed", K4.verifyGranted(map(), map(), null, List.of(), null));
    }

    @Test void k3MalformedBatchCursorAndAuthorityAreRefused() {
        K3.BatchVerdict b = K3.verifyBatch(null, 0, null, "s");
        assertFalse(b.ok);
        assertEquals("malformed batch", b.reason);
        assertEquals("malformed", K3.verifyListCursor("a.b.c", "s", null).reason);
        assertEquals("malformed", K3.verifyListCursor("nodot", "s", null).reason);
        assertEquals("malformed", K3.verifyListCursor(".sig", "s", null).reason);
        assertEquals("incomparable", K3.compareAuthority(null, null));
        assertNull(K3.authorityDigest(null));
        assertNull(K3.authorityDigest(map("verbs", 1L, "resources", list())));
        assertFalse(K3.verifyBody("d", map(), null, "x"));
        assertFalse(K3.verifyBody("d", map(), "x", 5L));
    }

    @Test void runtimeClaimAndPassportRefuseNonObjects() {
        assertEquals("none", RuntimeClaim.verifiedClass(null, List.of(), "d", List.of(), 1L));
        assertEquals("none", RuntimeClaim.verifiedClass("x", List.of(), "d", List.of(), 1L));
        assertEquals("malformed", Passport.verify(null, new Passport.Options()));
    }
}
