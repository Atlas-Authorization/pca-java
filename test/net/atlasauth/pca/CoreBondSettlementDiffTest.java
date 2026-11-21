package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Differential test of bond settlement against the TypeScript reference: the slash split and money arithmetic, bond sizing, evidence digests,
 * settlement records, claim / fraud-proof / dispute verdicts, and scripted op sequences over a {@link StoreBondLedger} on a memory store.
 */
public class CoreBondSettlementDiffTest {
    static final String MODULE = "ref-core-bond-settlement-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static double d(Object o) {
        Double x = IntentJs.num(o);
        if (x == null) throw new IllegalArgumentException("not a number");
        return x;
    }

    static Double dOrNull(Object o) { return IntentJs.num(o); }

    static byte[] seed(String label) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    static String codeOf(Throwable t) {
        if (t instanceof BondStoreError) return ((BondStoreError) t).code();
        return t instanceof IllegalArgumentException ? "RangeError" : "Error";
    }

    static Map<String, Object> err(String name) { Map<String, Object> e = new LinkedHashMap<>(); e.put("$err", name); return e; }

    // ---- pure functions ----

    @Test void computeSlashSplit() throws Exception {
        OracleCases.each(MODULE, "computeSlashSplit", a -> BondSettlement.computeSlashSplit(d(a.get(0)), m(a.get(1)), m(a.get(2))).toJson());
    }

    @Test void quantizeUp() throws Exception {
        OracleCases.each(MODULE, "quantizeUp", a -> BondSettlement.quantizeUp(d(a.get(0))));
    }

    @Test void toMicros() throws Exception {
        OracleCases.each(MODULE, "toMicros", a -> {
            Long v = BondSettlement.toMicros(d(a.get(0)));
            if (v == null) return null;
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("$bigint", v.toString());
            return o;
        });
    }

    @Test void exactAdd() throws Exception {
        OracleCases.each(MODULE, "exactAdd", a -> BondSettlement.exactAdd(d(a.get(0)), d(a.get(1)), (int) d(a.get(2))));
    }

    @Test void applyBondMoves() throws Exception {
        OracleCases.each(MODULE, "applyBondMoves", a -> {
            Map<String, Object> bal = m(a.get(0));
            Map<String, Double> out = BondDoc.applyBondMoves(acct -> {
                Double v = bal.containsKey(acct) ? IntentJs.num(bal.get(acct)) : null;
                return v == null ? 0 : v;
            }, l(a.get(1)));
            return new LinkedHashMap<String, Object>(out);
        });
    }

    @Test void bondAmount() throws Exception {
        OracleCases.each(MODULE, "bondAmount", a -> BondSettlement.bondAmount(m(a.get(0)), d(a.get(1))));
    }

    @Test void evidenceDigests() throws Exception {
        OracleCases.each(MODULE, "settlementEvidenceDigest", a -> BondSettlement.settlementEvidenceDigest(m(a.get(0)), m(a.get(1))));
        OracleCases.each(MODULE, "revocationEvidenceDigest", a -> BondSettlement.revocationEvidenceDigest(m(a.get(0)), (String) a.get(1)));
        OracleCases.each(MODULE, "disputeEvidenceDigest", a -> BondSettlement.disputeEvidenceDigest(m(a.get(0)), m(a.get(1))));
    }

    @Test void records() throws Exception {
        OracleCases.each(MODULE, "verifySettlement", a -> BondSettlement.verifySettlement(a.get(0), (String) a.get(1), policyPins(a.get(2))));
        OracleCases.each(MODULE, "settlementRecordDigest", a -> BondSettlement.settlementRecordDigest(m(a.get(0))));
        OracleCases.each(MODULE, "settlementCommit", a -> BondSettlement.settlementCommit((String) a.get(0), m(a.get(1))));
        OracleCases.each(MODULE, "verifySettlementCommit", a -> BondSettlement.verifySettlementCommit(a.get(0) instanceof String ? (String) a.get(0) : null, (String) a.get(1), m(a.get(2))));
    }

    /** The reference reads the pins from the policy object's pqPins member: the Java API takes the pin table itself. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> policyPins(Object policy) { return policy instanceof Map ? (Map<String, Object>) ((Map<String, Object>) policy).get("pqPins") : null; }

    static Optimistic.ChallengeWindowPolicy policyOf(Object o) {
        Map<String, Object> p = m(o);
        return p == null ? null : new Optimistic.ChallengeWindowPolicy(d(p.get("minWindowMs")), d(p.get("maxWindowMs")), d(p.get("maxSkewMs")), d(p.get("defaultWindowMs")));
    }

    @Test void verifyClaim() throws Exception {
        OracleCases.each(MODULE, "verifyClaim", a -> OptimisticAdjudication.verifyClaim(a.get(0), m(a.get(1)), (String) a.get(2), d(a.get(3)), policyOf(a.get(4))));
    }

    @Test void verifyFraudProof() throws Exception {
        OracleCases.each(MODULE, "verifyFraudProof", a -> OptimisticAdjudication.verifyFraudProof(m(a.get(0)), a.get(1), m(a.get(2)), a.get(3)));
    }

    static OptimisticAdjudication.ObjectiveOracle oracleOf(Object table) {
        Map<String, Object> t = m(table);
        return t == null ? null : (input, snapshot) -> m(t.get(input));
    }

    @Test void adjudicateDispute() throws Exception {
        OracleCases.each(MODULE, "adjudicateDispute", a -> OptimisticAdjudication.adjudicateDispute(m(a.get(0)), a.get(1), m(a.get(2)), a.get(3), oracleOf(a.get(4)), dOrNull(a.get(5))));
    }

    // ---- scripted ledger sequences ----

    /** Replaces every "@name" string by a copy of the fixture (an unknown name is an absent value). */
    static Object resolve(Map<String, Object> fx, Object v) {
        if (v instanceof String && ((String) v).startsWith("@")) return StoreJs.deepCopy(fx.get(((String) v).substring(1)));
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(resolve(fx, x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(v).entrySet()) out.put(e.getKey(), resolve(fx, e.getValue()));
            return out;
        }
        return v;
    }

    static Map<String, Object> params(Map<String, Object> fx, Object raw) {
        Map<String, Object> q = m(resolve(fx, raw));
        if (q != null && q.containsKey("oracleTable")) {
            Object table = q.remove("oracleTable");
            q.put("oracle", oracleOf(table));
        }
        return q;
    }

    static List<Object> run(List<?> args) {
        Map<String, Object> fx = m(args.get(0)), cfg = m(args.get(1));
        MemoryAtomicKv kv = new MemoryAtomicKv();
        double[] clock = {1_800_000_000_000.0};
        StoreBondLedger.Options o = new StoreBondLedger.Options();
        o.store = new KvBondStore(kv);
        o.guardianKey = Keys.edFromSeed(seed("bond/guardian"));
        o.clock = () -> clock[0];
        if (cfg.containsKey("epoch")) o.guardianEpoch = (long) d(cfg.get("epoch"));
        if (cfg.containsKey("escrow")) o.escrowAccount = (String) cfg.get("escrow");
        if (cfg.containsKey("bondPolicy")) o.bondPolicy = m(cfg.get("bondPolicy"));
        if (cfg.containsKey("splitPolicy")) o.slashSplitPolicy = m(cfg.get("splitPolicy"));
        if (cfg.containsKey("windowMs")) {
            Map<String, Object> w = m(cfg.get("windowMs"));
            o.windowPolicy = new Optimistic.ChallengeWindowPolicy(d(w.get("min")), d(w.get("max")), d(w.get("skew")), d(w.get("default")));
        }
        StoreBondLedger ledger = new StoreBondLedger(o);
        List<Object> out = new ArrayList<>();
        for (Object oo : l(args.get(2))) {
            List<Object> op = l(oo);
            try {
                Object v;
                switch ((String) op.get(0)) {
                    case "clock": { Double t = IntentJs.num(op.get(1)); clock[0] = t == null ? Double.NaN : t; v = null; break; }
                    case "deposit": v = ledger.deposit((String) op.get(1), d(op.get(2))); break;
                    case "balance": v = ledger.balanceOf((String) op.get(1)); break;
                    case "status": v = ledger.bondStatus((String) op.get(1)); break;
                    case "bond": v = ledger.getBond((String) op.get(1)); break;
                    case "challenge": v = ledger.challengeStatus((String) op.get(1)); break;
                    case "pub": v = ledger.guardianPublicKey(); break;
                    case "openClaim": {
                        Map<String, Object> p = params(fx, op.get(1));
                        v = ledger.openClaim(m(p.get("claim")), m(p.get("pcactn")), (String) p.get("signerPublic"), d(p.get("amount")), (String) p.get("depositor"), dOrNull(p.get("exposure")));
                        break;
                    }
                    case "openBond": {
                        Map<String, Object> p = params(fx, op.get(1));
                        v = ledger.openBond((String) p.get("claimId"), d(p.get("amount")), (String) p.get("depositor"), dOrNull(p.get("exposure")));
                        break;
                    }
                    case "release": v = ledger.release((String) op.get(1)); break;
                    case "releaseUnreg": v = ledger.releaseUnregistered((String) op.get(1)); break;
                    case "slash": v = ledger.slashBond(params(fx, op.get(1))); break;
                    case "slashDispute": v = ledger.slashBondOnDispute(params(fx, op.get(1))); break;
                    case "slashRevoke": v = ledger.slashBondOnRevocation(params(fx, op.get(1))); break;
                    case "slashCounter": v = ledger.slashCounterBond(params(fx, op.get(1))); break;
                    case "kvSet": kv.set(KvBondStore.DOC_KEY, StoreJs.deepCopy(op.get(1))); v = null; break;
                    case "kvGet": v = StoreJs.deepCopy(kv.get(KvBondStore.DOC_KEY)); break;
                    default: throw new IllegalStateException("op");
                }
                out.add(v);
            } catch (Throwable t) {
                out.add(err(codeOf(t)));
            }
        }
        return out;
    }

    @Test void ledger() throws Exception {
        OracleCases.each(MODULE, "ledger", CoreBondSettlementDiffTest::run);
    }
}
