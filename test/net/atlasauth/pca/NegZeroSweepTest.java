package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The strict profile refuses -0 wherever a wire integer is validated (mirrors the TS -0 sweep); 0 itself still passes. */
public class NegZeroSweepTest {
    static Json.Num n(String raw) { return new Json.Num(raw); }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @Test void freshAtWireRefusesNegZero() {
        for (String k : new String[] {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"}) {
            Map<String, Object> t = map("v", n("1"), "scope", "s", "policy_digest", "d", "revocation_epoch", n("0"), "ledger_tree_size", n("0"),
                "budget_version", n("0"), "policy_revision", n("0"), "issued_at", n("0"));
            assertFalse(String.valueOf(K3.validateFreshAtWire(t)).contains("non-negative safe integer"), k);
            t.put(k, n("-0"));
            assertEquals("'fresh_at." + k + "' must be a non-negative safe integer", K3.validateFreshAtWire(t), k);
        }
    }

    @Test void ledgerConsistencyRefusesNegZeroSizes() {
        Map<String, Object> ok = map("oldSize", n("0"), "newSize", n("0"), "path", new ArrayList<>());
        assertTrue(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, Ledger.EMPTY_TREE_ROOT, ok));
        assertFalse(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, Ledger.EMPTY_TREE_ROOT, map("oldSize", n("-0"), "newSize", n("0"), "path", new ArrayList<>())));
        assertFalse(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, Ledger.EMPTY_TREE_ROOT, map("oldSize", n("0"), "newSize", n("-0"), "path", new ArrayList<>())));
    }

    @Test void revocationEpochRefusesNegZero() {
        for (String k : new String[] {"epoch", "set_size", "issued_at", "not_after"}) {
            Map<String, Object> ep = map("guardian", "g", "instance_id", "i", "grant_ref", "r", "epoch", n("0"), "set_size", n("0"), "root", "x",
                "issued_at", n("0"), "not_after", n("0"), "sig", "s");
            assertNotEquals("malformed revocation epoch", RevocationStaleness.checkRevocationEpoch(ep, new RevocationStaleness.EpochOptions("g", 0)).reason, k);
            ep.put(k, n("-0"));
            assertEquals("malformed revocation epoch", RevocationStaleness.checkRevocationEpoch(ep, new RevocationStaleness.EpochOptions("g", 0)).reason, k);
        }
    }

    @Test void settlementGuardianEpochRefusesNegZero() {
        Map<String, Object> r = map("claimId", "c", "action", "open", "amount", n("5"), "from", "a", "to", "b", "at", n("1"), "evidenceDigest", "",
            "sig", "s", "guardian_epoch", n("0"));
        assertNotEquals("shape", Optimistic.settlementWireCheck(r, "g"));
        r.put("guardian_epoch", n("-0"));
        assertEquals("shape", Optimistic.settlementWireCheck(r, "g"));
    }

    @SuppressWarnings("unchecked")
    @Test void policyTemplateIntegerSlotsRefuseNegZero() throws Exception {
        String src = Files.readString(Path.of(PolicyAuthoringTest.DIR + "policy-link-vectors.json"));
        Map<String, Object> def = (Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) Json.parseLenient(src)).get("template")).get("def");
        PolicyAuthoring.Result r = PolicyAuthoring.instantiateTemplate(def, map("acct", "a42", "cap", n("-0"), "region", "eu", "verbs", new ArrayList<>(java.util.List.of("mail.send"))));
        assertEquals("slot 'cap' must be a safe integer", r.reason);
        ((Map<String, Object>) ((Map<String, Object>) def.get("slots")).get("cap")).put("min", n("-0"));
        assertEquals("slot 'cap'.min must be a safe integer", PolicyAuthoring.templateDefError(def));
    }
}
