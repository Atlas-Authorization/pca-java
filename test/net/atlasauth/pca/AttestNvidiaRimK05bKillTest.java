package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** RIM hash alternatives sorted numerically from an order that is neither sorted nor reversed; Date.UTC for a negative year. */
public class AttestNvidiaRimK05bKillTest {
    @Test
    void hashAlternativesSortNumerically() {
        String r = AttestNvidiaRimKillTest.res("index=\"3\" active=\"true\" alternatives=\"3\" size=\"1\" Hash2=\"02\" Hash10=\"0A\" Hash1=\"01\"");
        assertEquals("GB100|9|3:true:3:1:[01, 02, 0a]", AttestNvidiaRimKillTest.valid(AttestNvidiaRimKillTest.sign(AttestNvidiaRimKillTest.doc("GB100", "9", r))));
    }

    @Test
    void dateUtcAddsNoCenturyToANegativeYear() {
        assertEquals(-62198755200000L, AttestNvidiaRim.dateUtc(-1, 1, 1, 0, 0, 0)); // Date.UTC(-1, 0, 1)
        assertEquals(-2208988800000L, AttestNvidiaRim.dateUtc(0, 1, 1, 0, 0, 0)); // Date.UTC(0, 0, 1): 1900
    }
}
