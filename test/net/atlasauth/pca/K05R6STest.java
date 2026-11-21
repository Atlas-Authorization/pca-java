package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Round 2, tag S: the siblings of earlier survivors (equivocation, jsLeq floors, scalarEq, FP-absorbed split, hex4, registry kid). */
public class K05R6STest {
    static Object j(String s) { return Json.parseLenient(s); }

    // ---- IntentRevocation.checkSessionRevocation: two sets under one epoch number ----------------------------------

    @Test void twoDifferentSetsUnderOneEpochNumberAreEquivocation() {
        // an epoch is numbered by its set size (evidence(no, ids) needs no == ids.length), so two sets under one number have the same
        // size and the append-only rule refuses the swap before the equivocation clause (which no valid pair can reach) is evaluated
        assertEquals("the epoch drops 'b', revoked in the last accepted epoch (not append-only)",
            K05R5G6DeepTest.check(K05R5G6DeepTest.evidence(1, "a"), K05R5G6DeepTest.evidence(1, "b"), true, "zzz"));
        assertEquals("the epoch drops 'b', revoked in the last accepted epoch (not append-only)",
            K05R5G6DeepTest.check(K05R5G6DeepTest.evidence(2, "a", "c"), K05R5G6DeepTest.evidence(2, "a", "b"), true, "zzz"));
        // the same set under one number, and a different number, are not
        assertEquals(null, K05R5G6DeepTest.check(K05R5G6DeepTest.evidence(2, "a", "b"), K05R5G6DeepTest.evidence(2, "a", "b"), true, "zzz"));
        assertEquals(null, K05R5G6DeepTest.check(K05R5G6DeepTest.evidence(2, "a", "b"), K05R5G6DeepTest.evidence(1, "a"), true, "zzz"));
    }

    // ---- Actions.jsLeq: a floor class that no reversibility class names -------------------------------------------

    @Test void aProfileWhoseClassIsUnknownIsNeverBelowAFloorWithoutAClass() throws Exception {
        Actions.Profile bogus = new Actions.Profile(0, "bogus", 0, 0, List.of(), List.of(), List.of());
        assertFalse(K05R5G3MiscTest.leq(bogus, "{'risk':0,'blast_ppm':0,'esc':0,'caveats':[],'context':[],'prules':[]}"));
        assertFalse(K05R5G3MiscTest.leq(bogus, "{'risk':0,'rev':'nonsense','blast_ppm':0,'esc':0,'caveats':[],'context':[],'prules':[]}"));
    }

    // ---- IntentArtifacts.scalarEq ---------------------------------------------------------------------------------

    @Test void scalarsAreEqualOnlyWithTheSameTypeAndValue() {
        Json.Num two = new Json.Num("2");
        assertTrue(IntentArtifacts.scalarEq("a", "a"));
        assertFalse(IntentArtifacts.scalarEq("a", "b"));
        assertFalse(IntentArtifacts.scalarEq("a", null));
        assertFalse(IntentArtifacts.scalarEq(null, "a"));
        assertFalse(IntentArtifacts.scalarEq(5L, "5"));
        assertFalse(IntentArtifacts.scalarEq("5", 5L));
        assertFalse(IntentArtifacts.scalarEq("true", Boolean.TRUE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, "true"));
        assertTrue(IntentArtifacts.scalarEq(Boolean.TRUE, Boolean.TRUE));
        assertTrue(IntentArtifacts.scalarEq(Boolean.FALSE, Boolean.FALSE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, Boolean.FALSE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, null));
        assertFalse(IntentArtifacts.scalarEq(null, Boolean.TRUE));
        assertFalse(IntentArtifacts.scalarEq(1L, Boolean.TRUE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, 1L));
        assertTrue(IntentArtifacts.scalarEq(two, 2L));
        assertTrue(IntentArtifacts.scalarEq(2L, two));
        assertFalse(IntentArtifacts.scalarEq(2L, 3L));
        assertTrue(IntentArtifacts.scalarEq(null, null));
        assertFalse(IntentArtifacts.scalarEq(null, 5L));
        assertFalse(IntentArtifacts.scalarEq(5L, null));
    }

    // ---- Optimistic.settlementWireCheck: a reward too small to move the floating-point sum -------------------------

    @Test void anonymousChallengeRefusesAnyRewardOrCompensationEvenOneTheSumAbsorbs() {
        String head = Track3KillTest.SLASH;
        String tail = ",\"victimAccount\":\"v\",\"treasuryAccount\":\"t\",\"challengerAccount\":null}}";
        // 1e-15 + 100 == 100 in binary64, so conservation holds numerically, yet the anonymous split pays nothing but the treasury
        String cr = "{\"amount\":100,\"challengerReward\":0.000000000000001,\"victimCompensation\":0,\"treasuryRemainder\":100" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + cr), "k"));
        String vc = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":0.000000000000001,\"treasuryRemainder\":100" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + vc), "k"));
        String all = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":100" + tail;
        assertEquals("signature", Optimistic.settlementWireCheck(j(head + all), "k"));
    }

    // ---- Json: \\u escapes ----------------------------------------------------------------------------------------

    static int hex4(String text) throws Exception {
        Class<?> pc = Class.forName("net.atlasauth.pca.Json$Parser");
        Constructor<?> k = pc.getDeclaredConstructor(String.class, boolean.class);
        k.setAccessible(true);
        Object parser = k.newInstance(text, true);
        Method h = pc.getDeclaredMethod("hex4");
        h.setAccessible(true);
        return (Integer) h.invoke(parser);
    }

    @Test void fourHexDigitsAreTheirNumericValue() throws Exception {
        assertEquals(0, hex4("0000"));
        assertEquals(0xe9, hex4("00e9"));
        assertEquals(0xABCD, hex4("ABCD"));
        assertEquals(0xffff, hex4("ffff"));
        assertEquals(0x1234, hex4("1234"));
    }

    @Test void aBadUnicodeEscapeIsRefused() {
        assertEquals("\u00e9", Json.parse("\"\\u00e9\""));
        for (String bad : new String[] {"\"\\u00g9\"", "\"\\u00G9\"", "\"\\u00\"", "\"\\u\uFF11000\"", "\"\\u00-9\""})
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
    }

    @Test void aMinusSignIsPartOfTheNumber() {
        assertEquals("-5", ((Json.Num) Json.parse("-5")).raw);
        assertThrows(IllegalArgumentException.class, () -> Json.parse("-"));
    }

    // ---- ActionRegistry.verifyRegistrySig: the key's kid is compared with the signature's -------------------------

    @Test void aKeyNamedKidDoesNotMatchEverySignature() {
        assertEquals("no registry key with kid 'other'", ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY,
            ActionRegistryRestKillTest.sig("other"), ActionRegistryRestKillTest.keyWithKid("kid")));
        assertEquals("no registry key with kid 'kid'", ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY,
            ActionRegistryRestKillTest.sig("kid"), ActionRegistryRestKillTest.keyWithKid("other")));
    }
}
