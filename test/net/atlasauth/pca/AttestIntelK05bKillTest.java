package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

/** AttestIntel / AttestIntelCollateral: a missing or non-string binding, a refusal's empty status, and the SEAM attributes byte range. */
public class AttestIntelK05bKillTest {
    static final String V = "intel-tdx-dcap";

    @Test
    void bindingMustBeAString() {
        String want = "createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'";
        assertEquals(want, AttestMaaTest.constructError(V, "{}"));
        assertEquals(want, AttestMaaTest.constructError(V, "{\"binding\":5}"));
    }

    @Test
    void refusalCarriesNoStatusOrAdvisories() {
        AttestIntelCollateral.Result r = AttestIntelCollateral.verifyIntelTdxCollateral(new byte[0], null, 0L, null, "", false);
        assertFalse(r.ok);
        assertEquals("collateral incomplete (fail closed)", r.reason);
        assertEquals("", r.status);
        assertEquals(new ArrayList<String>(), r.advisoryIds);
    }

    @Test
    void seamAttributesStartAtByte112() {
        assertEquals("TCB evaluation: TD report SEAM attributes do not match the TDX module identity",
            AttestIntelCollateralK05KillTest.reason(f -> f.body[112] = 1));
    }
}
