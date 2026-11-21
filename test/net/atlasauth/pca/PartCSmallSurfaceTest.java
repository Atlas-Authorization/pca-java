package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The small public names the reference exports that were missing here: pcactnDigest, recharge, pqPinFor, the guardian tree-head equivocation check, the trait lattice, the need param. */
class PartCSmallSurfaceTest {
    static Json.Num n(String s) { return new Json.Num(s); }

    @Test void pcactnDigestIsTheCanonicalHashOfTheArtifact() {
        Map<String, Object> pc = AuthorizeBaseKillTest.pcactn();
        assertEquals(Pca.hashCanonical(pc), Pca.pcactnDigest(pc));
        Map<String, Object> other = new LinkedHashMap<>(pc);
        other.put("counter", 99L);
        assertFalse(Pca.pcactnDigest(pc).equals(Pca.pcactnDigest(other)));
    }

    @Test void rechargeAddsRhoUpToBMaxAndResetsTheClock() {
        Map<String, Object> b = Issue.obj("B", n("0.2"), "tau", n("10"), "asOf", n("10"));
        Map<String, Object> r = RiskBudgets.recharge(b, 0.5, 1.0, 99);
        assertEquals(0.7, IntentJs.num(r.get("B")), 1e-12);
        assertEquals(99.0, IntentJs.num(r.get("tau")));
        assertEquals(99.0, IntentJs.num(r.get("asOf")));
        assertEquals(1.0, IntentJs.num(RiskBudgets.recharge(b, 5, 1.0, 99).get("B")), 0.0); // never above bMax
        assertEquals(0.2, IntentJs.num(RiskBudgets.recharge(b, -3, 1.0, 99).get("B")), 1e-12); // a negative rho adds nothing
    }

    @Test void pqPinForTurnsAValidBindingIntoAPinAndRefusesEverythingElse() {
        Keys.EdKey id = Keys.edGenerate();
        byte[] pq = new byte[1952];
        Arrays.fill(pq, (byte) 7);
        String pqPk = Pca.b64(pq);
        Map<String, Object> binding = SignersMore.signPqBinding(id, pqPk, 3, "https://rs.example");
        Map<String, Object> pin = SignersMore.pqPinFor(binding, "https://rs.example");
        assertNotNull(pin);
        assertEquals(Map.of(id.id(), pqPk), pin);
        assertNull(SignersMore.pqPinFor(binding, "https://other.example"), "a binding is for one audience");
        assertNull(SignersMore.pqPinFor(binding, ""), "the audience is required");
        Map<String, Object> bumped = new LinkedHashMap<>(binding);
        bumped.put("epoch", 4L);
        assertNull(SignersMore.pqPinFor(bumped, "https://rs.example"), "the epoch is signed");
        Map<String, Object> shortKey = new LinkedHashMap<>(binding);
        shortKey.put("pq", Pca.b64(new byte[10]));
        assertNull(SignersMore.pqPinFor(shortKey, "https://rs.example"));
        Map<String, Object> zero = new LinkedHashMap<>(binding);
        zero.put("epoch", 0L);
        assertNull(SignersMore.pqPinFor(zero, "https://rs.example"));
        assertNull(SignersMore.pqPinFor(null, "https://rs.example"));
        assertNull(SignersMore.pqPinFor("x", "https://rs.example"));
    }

    private static Map<String, Object> head(Keys.EdKey g, long size, String root, String instance) {
        Map<String, Object> h = Issue.obj("instance_id", instance, "principal", "p1", "size", size, "root", root, "prev_root", "", "timestamp", 1L);
        return Ledger.signTreeHead(g.seed, h, null);
    }

    @Test void twoSignedHeadsOfTheSameSizeWithDifferentRootsAreAnEquivocation() {
        Keys.EdKey g = Keys.edGenerate();
        String r1 = Pca.b64(new byte[32]), r2 = Pca.b64(new byte[] {1, 2, 3});
        Map<String, Object> a = head(g, 5, r1, "i"), b = head(g, 5, r2, "i");
        assertTrue(Ledger.detectTreeHeadEquivocation(a, b, g.id()));
        assertFalse(Ledger.detectTreeHeadEquivocation(a, a, g.id()), "the same head is not a split view");
        assertFalse(Ledger.detectTreeHeadEquivocation(a, head(g, 6, r2, "i"), g.id()), "different sizes are growth, not a split view");
        assertFalse(Ledger.detectTreeHeadEquivocation(a, head(g, 5, r2, "j"), g.id()), "different instances are different logs");
        assertFalse(Ledger.detectTreeHeadEquivocation(a, b, Keys.edGenerate().id()), "both heads must verify under the pinned guardian");
        Map<String, Object> forged = new LinkedHashMap<>(b);
        forged.put("root", Pca.b64(new byte[] {9}));
        assertFalse(Ledger.detectTreeHeadEquivocation(a, forged, g.id()), "a tampered head proves nothing");
        assertFalse(Ledger.detectTreeHeadEquivocation(null, b, g.id()));
    }

    @Test void theTraitLatticeIsPublic() {
        assertEquals(3, Actions.RISK_MAX);
        assertEquals(Actions.RISK_MAX + 1, Actions.RISK_NAMES.size());
        assertEquals(Actions.ESC_MAX + 1, Actions.ESC_TIERS.size());
        Actions.Profile bottom = Actions.Profile.BOTTOM;
        assertTrue(Actions.Profile.joinAll(new ArrayList<>()).profileEq(bottom));
        assertTrue(bottom.leq(bottom));
        assertEquals("pca_need", A2a.PCA_NEED_PARAM);
        assertEquals(IntentJs.hashCanonical("x"), IntentClassifier.classifierContentDigest("x"));
    }
}
