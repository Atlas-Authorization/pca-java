package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Differential tests of chain compaction, receipts and reputation / underwriting against the TypeScript reference. */
public class CoreSweepDiffTest {
    static final String MODULE = "ref-core-sweep-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    static List<Object> chain(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("not an array");
        return (List<Object>) o;
    }

    static double d(Object o) {
        Double x = IntentJs.num(o);
        if (x == null) throw new IllegalArgumentException("not a number");
        return x;
    }

    static Double dOrNull(Object o) { return IntentJs.num(o); }

    static Map<String, Object> err() { Map<String, Object> e = new LinkedHashMap<>(); e.put("$err", "Error"); return e; }

    // ---- chain compaction ----

    @Test void hopsRootAndCompactChain() throws Exception {
        OracleCases.each(MODULE, "hopsRoot", a -> ChainCompact.hopsRoot(chain(a.get(0))));
        OracleCases.each(MODULE, "compactChain", a -> ChainCompact.compactChain(chain(a.get(0))));
        OracleCases.each(MODULE, "hopLeaf", a -> ChainCompact.hopLeaf(m(a.get(0))));
        OracleCases.each(MODULE, "compactChainShapeError", a -> ChainCompact.compactChainShapeError(a.get(0)));
    }

    @Test void chainMemo() throws Exception {
        OracleCases.each(MODULE, "chainMemo", a -> {
            ChainCompact.Memo[] memo = new ChainCompact.Memo[1];
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "new": {
                            Map<String, Object> c = op.get(1) == null ? new LinkedHashMap<>() : m(op.get(1));
                            memo[0] = new ChainCompact.Memo(c.containsKey("maxEntries") ? (Integer) (int) d(c.get("maxEntries")) : null, c.containsKey("ttlMs") ? dOrNull(c.get("ttlMs")) : null);
                            break;
                        }
                        case "remember": v = memo[0].rememberVerified(chain(op.get(1)), (String) op.get(2), d(op.get(3))); break;
                        case "resolve": {
                            double now = IntentJs.num(op.get(2)) == null ? Double.NaN : IntentJs.num(op.get(2));
                            ChainCompact.Memo.Resolved r = memo[0].resolve(op.get(1), now);
                            Map<String, Object> res = new LinkedHashMap<>();
                            res.put("ok", r.ok);
                            if (r.ok) {
                                Map<String, Object> view = new LinkedHashMap<>();
                                List<Object> hashes = new ArrayList<>(), counts = new ArrayList<>();
                                for (int i = 0; i < r.view.n(); i++) {
                                    hashes.add(r.view.hash(i));
                                    counts.add(r.view.count(i));
                                }
                                view.put("n", r.view.n());
                                view.put("hashes", hashes);
                                view.put("counts", counts);
                                view.put("leaf", r.view.leaf());
                                res.put("view", view);
                            } else {
                                res.put("reason", r.reason);
                            }
                            v = res;
                            break;
                        }
                        case "prune": memo[0].prune(d(op.get(1))); break;
                        case "forget": v = memo[0].forget((String) op.get(1)); break;
                        case "size": v = memo[0].size(); break;
                        default: throw new IllegalStateException("op");
                    }
                    out.add(v);
                } catch (Throwable t) {
                    out.add(err());
                }
            }
            return out;
        });
    }

    // ---- receipts ----

    static Map<String, Object> checksOf(Object verify) { return m(verify) == null ? null : m(m(verify).get("checks")); }

    static boolean allowOf(Object verify) { return Boolean.TRUE.equals(m(verify).get("allow")); }

    @Test void receipts() throws Exception {
        OracleCases.each(MODULE, "receiptFor", a -> Receipts.receiptFor((String) a.get(0), (long) d(a.get(1)), m(a.get(2)), allowOf(a.get(3)), checksOf(a.get(3)), dOrNull(a.get(4))));
        OracleCases.each(MODULE, "receiptChain", a -> {
            List<Object>[] log = new List[] {new ArrayList<Object>()};
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "append": {
                            log[0] = Receipts.appendReceipt(log[0], m(op.get(1)), allowOf(op.get(2)), checksOf(op.get(2)), dOrNull(op.get(3)));
                            v = log[0].get(log[0].size() - 1);
                            break;
                        }
                        case "head": v = Receipts.receiptHead(log[0]); break;
                        case "verify": v = Receipts.verifyReceiptChain(log[0]); break;
                        case "set": log[0] = (List<Object>) StoreJs.deepCopy(op.get(1)); break;
                        case "tamper": {
                            log[0] = (List<Object>) StoreJs.deepCopy(log[0]);
                            Map<String, Object> r = m(log[0].get((int) d(op.get(1))));
                            if ("$del".equals(op.get(3))) r.remove((String) op.get(2)); else r.put((String) op.get(2), op.get(3));
                            break;
                        }
                        case "swap": {
                            List<Object> l = (List<Object>) StoreJs.deepCopy(log[0]);
                            int i = (int) d(op.get(1)), j = (int) d(op.get(2));
                            Object t = l.get(i);
                            l.set(i, l.get(j));
                            l.set(j, t);
                            log[0] = l;
                            break;
                        }
                        case "drop": log[0].remove((int) d(op.get(1))); break;
                        case "truncate": log[0] = new ArrayList<>(log[0].subList(0, (int) d(op.get(1)))); break;
                        default: throw new IllegalStateException("op");
                    }
                    out.add(v);
                } catch (Throwable t) {
                    out.add(err());
                }
            }
            return out;
        });
    }

    // ---- reputation ----

    @Test void reputationAndPricing() throws Exception {
        OracleCases.each(MODULE, "reputation", a -> Reputation.reputation(m(a.get(0))));
        OracleCases.each(MODULE, "priceCoverage", a -> Reputation.priceCoverage(m(a.get(0)) == null ? null : dOrNull(m(a.get(0)).get("score")), d(a.get(1)), m(a.get(2))));
    }

    @Test void quotes() throws Exception {
        Keys.EdKey uw = Keys.edFromSeed(CoreStoresDiffTest.seed("sweep/underwriter"));
        OracleCases.each(MODULE, "issueCoverageQuote", a -> Reputation.issueCoverageQuote(m(a.get(0)), d(a.get(1)), uw, d(a.get(2)), d(a.get(3)), m(a.get(4))));
        OracleCases.each(MODULE, "verifyCoverageQuote", a -> {
            String u = "@u".equals(a.get(1)) ? uw.id() : (String) a.get(1);
            Double now = dOrNull(a.get(2));
            return Reputation.verifyCoverageQuote(a.get(0), u, now == null ? Double.NaN : now);
        });
    }

    @Test void pool() throws Exception {
        OracleCases.each(MODULE, "pool", a -> {
            Reputation.Pool[] pool = new Reputation.Pool[1];
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "new": pool[0] = new Reputation.Pool(d(op.get(1))); v = pool[0].state(); break;
                        case "quote": v = pool[0].quote(dOrNull(m(op.get(1)).get("score")), d(op.get(2)), m(op.get(3))); break;
                        case "collect": v = pool[0].collectPremium(dOrNull(m(op.get(1)).get("score")), d(op.get(2)), m(op.get(3))); break;
                        case "canCover": v = pool[0].canCover(d(op.get(1))); break;
                        case "pay": v = pool[0].payClaim(d(op.get(1))); break;
                        case "state": v = pool[0].state(); break;
                        default: throw new IllegalStateException("op");
                    }
                    out.add(v);
                } catch (Throwable t) {
                    out.add(err());
                }
            }
            return out;
        });
    }

    // ---- frontier signals and budget forecast ----

    @Test void frontierSignals() throws Exception {
        OracleCases.each(MODULE, "semanticSignal", a -> FrontierSignals.semanticSignal(a.get(0)));
        OracleCases.each(MODULE, "progressSignal", a -> FrontierSignals.progressSignal(a.get(0)));
        OracleCases.each(MODULE, "objectiveSignal", a -> FrontierSignals.objectiveSignal(a.get(0)));
        OracleCases.each(MODULE, "tightenRiskInputs", a -> FrontierSignals.tightenRiskInputs(m(a.get(0)), m(a.get(1))));
    }

    @Test void budgetForecast() throws Exception {
        OracleCases.each(MODULE, "recommendPolicy", a -> BudgetForecast.recommendPolicy(d(a.get(0)), d(a.get(1)), dOrNull(a.get(2))));
        OracleCases.each(MODULE, "autonomyBoundOf", a -> BudgetForecast.autonomyBoundOf(m(a.get(0))));
    }

    @Test void budgetAlgebra() throws Exception {
        OracleCases.each(MODULE, "subBudget", a -> RiskBudgets.subBudget(m(a.get(0)), d(a.get(1))));
        OracleCases.each(MODULE, "debitConsolidated", a -> RiskBudgets.debitConsolidated(m(a.get(0)), m(a.get(1)), d(a.get(2))));
        OracleCases.each(MODULE, "debitConsolidatedPath", a -> RiskBudgets.debitConsolidatedPath(chain(a.get(0)), d(a.get(1))));
        OracleCases.each(MODULE, "rechargeFull", a -> RiskBudgets.rechargeFull(d(a.get(0)), d(a.get(1))));
    }

    @Test void approvals() throws Exception {
        OracleCases.each(MODULE, "approveClass", a -> {
            List<String> verbs = new ArrayList<>();
            for (Object v : chain(a.get(0))) verbs.add((String) v);
            return Approvals.approveClass(verbs, d(a.get(1)), (String) a.get(2), d(a.get(3)), (String) a.get(4));
        });
        OracleCases.each(MODULE, "classApprovalCovers", a -> Approvals.classApprovalCovers(m(a.get(0)), (String) a.get(1), (String) a.get(2), d(a.get(3))));
        OracleCases.each(MODULE, "coveredByAny", a -> Approvals.coveredByAny(chain(a.get(0)), (String) a.get(1), (String) a.get(2), d(a.get(3))));
        OracleCases.each(MODULE, "recordDecision", a -> Approvals.recordDecision(m(a.get(0)), (String) a.get(1), (String) a.get(2), d(a.get(3))));
        OracleCases.each(MODULE, "pendingRequests", a -> Approvals.pendingRequests(chain(a.get(0))));
        OracleCases.each(MODULE, "applyCosign", a -> Approvals.applyCosign(m(a.get(0)), m(a.get(1)), d(a.get(2)), Boolean.TRUE.equals(a.get(3))));
    }

    @Test void appendSettlementAnchorsACommitment() {
        MerkleLog log = new MerkleLog();
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("claimId", "c1");
        rec.put("action", "open");
        Map<String, Object> a = BondSettlement.appendSettlement(log::appendCommitment, rec, "salt-1");
        assertEquals("0", ((Json.Num) a.get("index")).raw);
        assertEquals(BondSettlement.settlementCommit("salt-1", rec), a.get("commit"));
        assertEquals(1, log.size());
        assertTrue(BondSettlement.verifySettlementCommit((String) a.get("commit"), "salt-1", rec));
        Map<String, Object> b = BondSettlement.appendSettlement(log::appendCommitment, rec, null);
        assertEquals("1", ((Json.Num) b.get("index")).raw);
        assertTrue(!"salt-1".equals(b.get("salt")));
        assertThrows(IllegalStateException.class, () -> BondSettlement.settlementCommit("", rec));
    }
}
