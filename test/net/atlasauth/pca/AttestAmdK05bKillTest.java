package net.atlasauth.pca;

import static net.atlasauth.pca.AttestVendorRows.BINDING;
import static net.atlasauth.pca.AttestVendorRows.NOW;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/** A default SNP policy allows no measurement (fail closed); the exact bounds of the reserved signature-block bytes. */
public class AttestAmdK05bKillTest {
    static final String RESERVED = "report signature block has non-zero reserved bytes";
    static final String BAD_SIG = "report signature does not verify under VCEK";

    @Test
    void defaultPolicyAllowsNoMeasurement() {
        AttestAmd.SnpReport r = new AttestAmd.SnpReport();
        r.measurement = new byte[48];
        assertEquals("measurement not in policy allowlist", new AttestAmd.SnpPolicy().check(r));
    }

    /** raw with byte off set to a non-zero value different from the genuine one (deterministic whatever the signature bytes are). */
    static byte[] poke(byte[] raw, int off) {
        byte[] t = raw.clone();
        t[off] = (byte) (raw[off] == 1 ? 2 : 1);
        return t;
    }

    @Test
    void reservedBytesAreExactlyThePaddingAndTheTail() {
        AttestAmdTest.Genuine g = new AttestAmdTest.Genuine();
        AttestAmd v = (AttestAmd) AttestHarness.amd(g.config(""));
        byte[] raw = g.report();
        byte[] vcek = g.vcekDer();
        String askArk = g.askArkPem();
        assertEquals("", v.verifyReport(raw, vcek, askArk, NOW, BINDING)[0]);
        // the little-endian r and s values (48 bytes each): a changed byte breaks the signature, it is not reserved
        int[] value = {AttestAmd.OFF_SIG_R, AttestAmd.OFF_SIG_R + 47, AttestAmd.OFF_SIG_S, AttestAmd.OFF_SIG_S + 47};
        for (int off : value) {
            byte[] t = poke(raw, off);
            assertNotEquals(raw[off], t[off]);
            assertArrayEquals(new Object[] {BAD_SIG, null}, v.verifyReport(t, vcek, askArk, NOW, BINDING), "offset " + off);
        }
        // the 24 padding bytes after r and after s, and every byte after the s field (to the end of the report)
        int[] reserved = {AttestAmd.OFF_SIG_R + 48, AttestAmd.OFF_SIG_R + 71, AttestAmd.OFF_SIG_S + 48, AttestAmd.OFF_SIG_S + 71,
            AttestAmd.OFF_SIG_S + 72, raw.length - 1};
        for (int off : reserved) {
            assertArrayEquals(new Object[] {RESERVED, null}, v.verifyReport(poke(raw, off), vcek, askArk, NOW, BINDING), "offset " + off);
        }
    }
}
