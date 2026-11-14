package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** 0.5 mutation survivors of Assurance, PlanRegistry and RevocationStaleness (shard 9). */
public class AssurancePlanK05bKillTest {
    static final long T0 = PlanRegistryKillTest.T0;

    static Map<String, Object> map(Object... kv) { return PlanRegistryKillTest.map(kv); }

    static Map<String, Object> awaiting(String level) { return map("outcome", "pass", "level", level, "awaiting_audit", Boolean.TRUE); }

    // ---- Assurance ---------------------------------------------------------------------------------------------------

    @Test void anAbsentDimensionAsksForNothing() {
        // dimension(null) is null, never the text "null" (which would be an unknown attestation level)
        assertNull(Assurance.unmet(new LinkedHashMap<>(), Assurance.Requirement.fromJson(new LinkedHashMap<String, Object>())));
        assertNull(Assurance.unmet(new LinkedHashMap<>(), Assurance.Requirement.fromJson(map("allowAwaitingAudit", Boolean.TRUE))));
    }

    @Test void onlyTheListedThresholdEntryMayRestOnCryptoAwaitingAudit() {
        Assurance.Requirement listed = new Assurance.Requirement().threshold(List.of("frost"));
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("threshold", awaiting("frost"));
        assertNull(Assurance.unmet(report, listed));
        // another entry awaiting audit is refused, even when its level is a listed threshold scheme
        report.put("zk_compliance", awaiting("frost"));
        assertEquals("assurance: zk_compliance rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            Assurance.unmet(report, listed));
        // no threshold list: the threshold entry itself is refused
        Map<String, Object> only = new LinkedHashMap<>();
        only.put("threshold", awaiting("frost"));
        assertEquals("assurance: threshold rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            Assurance.unmet(only, new Assurance.Requirement()));
    }

    // ---- PlanRegistry ------------------------------------------------------------------------------------------------

    @Test void onlyADraftIsValidatedAndTheValidatorIsNotAsked() {
        List<Object> calls = new ArrayList<>();
        PlanRegistry.Validator recording = r -> { calls.add(r); return "outside the grant"; };
        // a seeded committed plan whose nodes do not hash to its root: the state refusal comes first
        PlanRegistry seeded = PlanRegistryKillTest.seeded(new MemoryAtomicKv(), PlanRegistryKillTest.list(PlanRegistryKillTest.node("a")), "committed", recording);
        assertEquals(PlanRegistryKillTest.no("committed", "plan R is committed: cannot validate"), seeded.validate("g", "R").toMap());

        // a sound plan past draft: refused on its state, the validator never runs
        MemoryAtomicKv kv = new MemoryAtomicKv();
        PlanRegistry plain = new PlanRegistry(kv, null, () -> T0, null);
        String root = plain.draft("g", PlanRegistryKillTest.list(PlanRegistryKillTest.node("n1"))).record.root();
        assertTrue(plain.validate("g", root).ok);
        PlanRegistry checked = new PlanRegistry(kv, null, () -> T0, recording);
        assertEquals(PlanRegistryKillTest.no("validated", "plan " + root + " is validated: cannot validate"), checked.validate("g", root).toMap());
        assertTrue(plain.commit("g", root).ok);
        assertEquals(PlanRegistryKillTest.no("committed", "plan " + root + " is committed: cannot validate"), checked.validate("g", root).toMap());
        assertTrue(calls.isEmpty(), "the validator runs only on a draft");
    }

    @Test void anExpiredApprovalPrintsItsTimeAsJavaScriptDoes() {
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        String root = reg.draft("g", PlanRegistryKillTest.list(PlanRegistryKillTest.node("n1"))).record.root();
        assertTrue(reg.validate("g", root).ok);
        assertTrue(reg.commit("g", root).ok);
        // stored as the plain decimal 0.0000001; String(1e-7) is "1e-7"
        assertTrue(reg.authorize("g", root, map("by", "alice", "expiresAt", new Json.Num("1e-7"))).ok);
        PlanRegistry.PlanStatus s = reg.status("g", root, T0);
        assertFalse(s.executable);
        assertEquals("plan " + root + ": the principal's approval expired at 1e-7", s.reason);
    }

    // ---- RevocationStaleness -----------------------------------------------------------------------------------------

    @Test void aPolicyThatIsOffAcceptsABareRootForAnIrreversibleAction() {
        RevocationStaleness off = new RevocationStaleness();
        assertFalse(off.isOn());
        RevocationStaleness.Check c = RevocationStaleness.checkState(off, RevocationStaleness.State.root("r", T0), T0, "g1", "irreversible", null, null, null);
        assertTrue(c.ok, c.reason);
        assertNull(c.reason);
        // the same state under a policy that is on is refused
        RevocationStaleness.Check on = RevocationStaleness.checkState(off.maxRevocationAgeMs(60_000), RevocationStaleness.State.root("r", T0), T0, "g1", "irreversible", null, null, null);
        assertFalse(on.ok);
        assertEquals("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)", on.reason);
    }

    @Test void onlyAnEpochKindReadsTheEpochMember() {
        RevocationStaleness.State root = RevocationStaleness.State.of(map("kind", "root", "root", "r", "issued_at", IntentJs.ofLong(5), "epoch", map("epoch", IntentJs.ofLong(1))));
        assertFalse(root.signed);
        assertNull(root.epoch);
        assertEquals("r", root.root);
        assertNull(RevocationStaleness.State.of(map("kind", "other", "epoch", map("epoch", IntentJs.ofLong(1)))));
        assertNull(RevocationStaleness.State.of(map("epoch", map("epoch", IntentJs.ofLong(1)))));
    }
}
