package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The ledger corpus (ledger-vectors.json): every vector must reproduce the reference verdict exactly; each table's size must equal the file's counts. */
public class LedgerVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("ledger-vectors.json");

    private static String s(Object o) { return (String) o; }

    private static void chk(String table, Map<String, Object> v, boolean got) {
        assertEquals(Track3Vectors.expectOk(v) && !Track3Vectors.lacks(v), got, table + "/" + v.get("name"));
    }

    @Test void emptyTreeRootAndDomainsMatchTheCorpus() {
        assertEquals(DOC.get("empty_tree_root"), Ledger.EMPTY_TREE_ROOT);
        Map<String, Object> d = Track3Vectors.mapOrNull(DOC.get("domains"));
        assertEquals(d.get("sth"), Ledger.STH_DOMAIN);
        assertEquals(d.get("sth_witness"), Ledger.STH_WITNESS_DOMAIN);
        assertEquals(d.get("ledger_head"), Ledger.LEDGER_HEAD_DOMAIN);
        assertEquals(d.get("optimistic_claim"), Optimistic.CLAIM_DOMAIN);
        assertEquals(d.get("settlement"), Optimistic.SETTLEMENT_DOMAIN);
    }

    @Test void inclusion() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_inclusion")) chk("inclusion", v, Ledger.verifyLedgerInclusion(s(v.get("root")), v.get("proof"), v.get("leaf")));
    }

    @Test void consistency() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_consistency")) chk("consistency", v, Ledger.verifyLedgerConsistency(v.get("old_root"), v.get("new_root"), v.get("proof")));
    }

    @Test void treeHead() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_tree_head")) chk("tree_head", v, Ledger.verifyTreeHead(v.get("sth"), s(v.get("guardian_public")), null, Track3Vectors.pins(v)));
    }

    @Test void cosign() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_cosign")) chk("cosign", v, Ledger.verifyTreeHead(v.get("sth"), s(v.get("guardian_public")), Track3Vectors.mapOrNull(v.get("policy")), Track3Vectors.pins(v)));
    }

    @Test void headConsistency() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_head_consistency")) {
            chk("head_consistency", v, Ledger.verifyHeadConsistency(v.get("older"), v.get("newer"), v.get("proof"), s(v.get("guardian_public")), null, Track3Vectors.pins(v)));
        }
    }

    @Test void checkpointChain() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_checkpoint_chain")) {
            Ledger.CheckpointVerdict got = Ledger.verifyCheckpointChain(v.get("chain"), s(v.get("guardian_public")), Track3Vectors.mapOrNull(v.get("policy")), Track3Vectors.pins(v));
            Map<String, Object> exp = Track3Vectors.mapOrNull(v.get("expect"));
            boolean ok = Boolean.TRUE.equals(exp.get("ok")) && !Track3Vectors.lacks(v);
            assertEquals(ok, got.ok, "chain/" + v.get("name"));
            if (!ok && !Track3Vectors.lacks(v)) assertEquals(Json.asLong(exp.get("at")), got.at, "chain/" + v.get("name") + " at");
        }
    }

    @Test void witnessedHead() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_witnessed_head")) chk("witnessed_head", v, Ledger.verifyWitnessedHead(v.get("head"), s(v.get("witness_public")), Track3Vectors.pins(v)));
    }

    @Test void equivocation() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "ledger_equivocation")) {
            boolean want = Boolean.TRUE.equals(Track3Vectors.mapOrNull(v.get("expect")).get("equivocation")) && !Track3Vectors.lacks(v);
            assertEquals(want, Ledger.detectEquivocation(v.get("a"), v.get("b"), s(v.get("witness_public")), Track3Vectors.pins(v)), "equivocation/" + v.get("name"));
        }
    }

    /** Hostile shapes never throw and are never accepted. */
    @Test void hostileInputsAreRefused() {
        for (String text : List.of("null", "1", "\"x\"", "[]", "{}", "{\"size\":1e999}", "[null]", "{\"sth\":null,\"proof\":null}")) {
            Object v = Json.parseLenient(text);
            assertFalse(Ledger.verifyLedgerConsistency(v, v, v), text);
            assertFalse(Ledger.verifyTreeHead(v, "k", null), text);
            assertFalse(Ledger.verifyTreeHead(v, "k", Map.of("threshold", new Json.Num("0"))), text);
            assertFalse(Ledger.verifyWitnessedHead(v, "k"), text);
            assertFalse(Ledger.verifyWitnessCosignature(v, v, "k"), text);
            assertFalse(Ledger.verifyHeadConsistency(v, v, v, "k", null), text);
            assertFalse(Ledger.detectEquivocation(v, v, "k"), text);
            assertFalse(Ledger.verifyCheckpointChain(v, "k", null).ok, text);
            assertFalse(Ledger.verifyLedgerInclusion("r", v, v), text);
            assertFalse("ok".equals(Optimistic.fraudProofWireCheck(v, v)), text);
            assertFalse("ok".equals(Optimistic.settlementWireCheck(v, "k")), text);
            assertFalse("ok".equals(Optimistic.claimCheck(v, "d", "k", 0, Optimistic.DEFAULT_POLICY)), text);
        }
    }
}
