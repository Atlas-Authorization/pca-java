package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import net.atlasauth.pca.ratchet.Accumulator;
import net.atlasauth.pca.ratchet.AccumulatorError;
import net.atlasauth.pca.ratchet.Adapters;
import net.atlasauth.pca.ratchet.Binding;
import net.atlasauth.pca.ratchet.Ratchet;
import net.atlasauth.pca.ratchet.RatchetError;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the capability ratchet and risk accumulator through the native port. */
public class RatchetDiffTest {
    private static final String M = "ref-ratchet";

    /** A refusal carrying the reference's stable error code. */
    private static final class CodedEx extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;

        CodedEx(String code, Throwable cause) {
            super(cause);
            this.code = code;
        }

        @Override public String code() { return code; }
    }

    private static <T> T coded(Callable<T> f) throws Exception {
        try {
            return f.call();
        } catch (RatchetError e) {
            throw new CodedEx(e.code, e);
        } catch (AccumulatorError e) {
            throw new CodedEx(e.code, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static byte[] bytes(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).size() == 1 && ((Map<?, ?>) o).get("$bytes") instanceof String) return Keys.unb64u((String) ((Map<?, ?>) o).get("$bytes"));
        return null;
    }

    private static boolean isBig(Object o) { return o instanceof Map && ((Map<?, ?>) o).size() == 1 && ((Map<?, ?>) o).get("$bigint") instanceof String; }

    /** {"$bigint": "n"} to BigInteger; anything else is left as it is. */
    private static Object rev(Object o) { return isBig(o) ? new BigInteger((String) ((Map<?, ?>) o).get("$bigint")) : o; }

    private static BigInteger big(Object o) {
        if (!isBig(o)) throw new IllegalArgumentException("not a bigint");
        return (BigInteger) rev(o);
    }

    private static Object jb(BigInteger b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("$bigint", b.toString());
        return m;
    }

    private static List<Object> revList(Object o) {
        List<Object> out = new ArrayList<>();
        for (Object x : (List<?>) o) out.add(rev(x));
        return out;
    }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @Test void leafNullifier() throws Exception { OracleCases.each(M, "leafNullifier", a -> Ratchet.leafNullifier((String) a.get(0), a.get(1))); }
    @Test void counterToLeafIndex() throws Exception { OracleCases.each(M, "counterToLeafIndex", a -> coded(() -> Adapters.counterToLeafIndex(a.get(0), a.get(1)))); }
    @Test void leafIndexToCounter() throws Exception { OracleCases.each(M, "leafIndexToCounter", a -> coded(() -> Adapters.leafIndexToCounter(a.get(0)))); }
    @Test void leafIndexForAction() throws Exception { OracleCases.each(M, "leafIndexForAction", a -> coded(() -> Adapters.leafIndexForAction(m(a.get(0)), a.get(1)))); }
    @Test void riskToUnits() throws Exception { OracleCases.each(M, "riskToUnits", a -> jb(coded(() -> Adapters.riskToUnits(a.get(0))))); }
    @Test void budgetCeilingUnits() throws Exception { OracleCases.each(M, "budgetCeilingUnits", a -> jb(coded(() -> Adapters.budgetCeilingUnits(m(a.get(0)))))); }

    @Test void quantizer() throws Exception {
        OracleCases.each(M, "quantizer", a -> {
            Adapters.RiskQuantizer q = new Adapters.RiskQuantizer();
            List<Object> out = new ArrayList<>();
            for (Object r : (List<?>) a.get(0)) {
                try {
                    out.add(jb(q.next(r)));
                } catch (RuntimeException e) {
                    Map<String, Object> err = new LinkedHashMap<>();
                    err.put("$err", true);
                    out.add(err);
                }
            }
            out.add(jb(q.totalUnits()));
            return out;
        });
    }

    // ---- ratchet scenarios -------------------------------------------------------------------------------------------------

    private static Object deepCopy(Object o) {
        if (o instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) out.put((String) e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (o instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) o) out.add(deepCopy(x));
            return out;
        }
        return o;
    }

    private static Object step(Object container, Object key) {
        if (container instanceof Map) return ((Map<?, ?>) container).get(String.valueOf(key));
        if (container instanceof List) {
            int i = (int) (double) OracleCases.num(key);
            List<?> l = (List<?>) container;
            return i >= 0 && i < l.size() ? l.get(i) : null;
        }
        return null;
    }

    /** The reference's clonePath: a copy of {@code v} with the member at {@code path} replaced (or removed for "__DEL__"); an empty path writes the member "undefined". */
    @SuppressWarnings("unchecked")
    private static Object clonePath(Object v, List<?> path, Object value) {
        Object c = deepCopy(v);
        Object t = c;
        for (int i = 0; i < path.size() - 1; i++) t = step(t, path.get(i));
        if (t == null) return c;
        Object lastKey = path.isEmpty() ? "undefined" : path.get(path.size() - 1);
        boolean del = "__DEL__".equals(value);
        if (t instanceof Map) {
            if (del) ((Map<String, Object>) t).remove(String.valueOf(lastKey));
            else ((Map<String, Object>) t).put(String.valueOf(lastKey), value);
        } else if (t instanceof List) {
            List<Object> l = (List<Object>) t;
            int i = (int) (double) OracleCases.num(lastKey);
            if (i >= 0 && i < l.size()) l.set(i, del ? null : value);
        }
        return c;
    }

    private static Map<String, Object> err(Object code) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("$err", code);
        return e;
    }

    @Test void ratchetScenarios() throws Exception {
        OracleCases.each(M, "ratchet", a -> {
            Map<String, Object> spec = m(a.get(0));
            Binding.SpentLeafStore store = "throws".equals(spec.get("store")) ? (n, r) -> { throw new IllegalStateException("boom"); } : Binding.memorySpentLeafStore();
            Ratchet.RatchetState state = null;
            String root = null;
            List<Object> sigs = new ArrayList<>();
            List<Object> out = new ArrayList<>();
            for (Object so : (List<?>) spec.get("ops")) {
                Map<String, Object> s = m(so);
                try {
                    switch ((String) s.get("op")) {
                        case "derive": {
                            Ratchet.Derived d = Ratchet.deriveRatchetRoot(bytes(s.get("seed")), s.get("depth"));
                            state = d.state;
                            root = d.rootCommitment;
                            Map<String, Object> r = new LinkedHashMap<>();
                            r.put("root", d.rootCommitment);
                            r.put("leafPubKeys", new ArrayList<Object>(d.state.leafPubKeys));
                            r.put("available", new ArrayList<Object>(Ratchet.availableLeaves(d.state)));
                            out.add(r);
                            break;
                        }
                        case "sign": {
                            Ratchet.Signed r = Ratchet.signAtLeaf(state, s.get("leaf"), bytes(s.get("msg")));
                            state = r.newState;
                            sigs.add(r.signature);
                            Map<String, Object> o = new LinkedHashMap<>();
                            o.put("signature", r.signature);
                            out.add(o);
                            break;
                        }
                        case "avail": out.add(new ArrayList<Object>(Ratchet.availableLeaves(state))); break;
                        case "isAvail": out.add(Ratchet.isLeafAvailable(state, s.get("leaf"))); break;
                        case "verify":
                        case "once": {
                            Object ref = s.get("sigRef");
                            int ri = (int) (double) OracleCases.num(ref);
                            Object sig = ri >= 0 && ri < sigs.size() ? sigs.get(ri) : null;
                            Object set = s.get("set");
                            if (set != null) for (Object e : (List<?>) set) sig = clonePath(sig, (List<?>) ((List<?>) e).get(0), ((List<?>) e).get(1));
                            String rc = "other".equals(s.get("root")) ? "other-root" : root;
                            out.add("verify".equals(s.get("op")) ? (Object) Ratchet.verifyLeafSignature(rc, s.get("leaf"), bytes(s.get("msg")), sig)
                                : Binding.verifyLeafSignatureOnce(rc, s.get("leaf"), bytes(s.get("msg")), sig, store));
                            break;
                        }
                        default: throw new IllegalStateException("bad op");
                    }
                } catch (RatchetError e) {
                    out.add(err(e.code));
                } catch (RuntimeException e) {
                    out.add(err(true));
                }
            }
            return out;
        });
    }

    // ---- accumulator ------------------------------------------------------------------------------------------------------------

    @Test void commitRisk() throws Exception {
        OracleCases.each(M, "commitRisk", a -> {
            Accumulator.RiskCommitment c = coded(() -> Accumulator.commitRisk(rev(a.get(0)), big(a.get(1))));
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("commitment", c.commitment);
            o.put("blinding", jb(c.blinding));
            return o;
        });
    }

    @Test void addCommitments() throws Exception { OracleCases.each(M, "addCommitments", a -> Accumulator.addCommitments((List<?>) a.get(0))); }

    @Test void openCommitment() throws Exception {
        OracleCases.each(M, "openCommitment", a -> Accumulator.openCommitment(a.get(0), rev(a.get(1)), isBig(a.get(2)) ? big(a.get(2)) : null));
    }

    @Test void verifyRiskRange() throws Exception { OracleCases.each(M, "verifyRiskRange", a -> Accumulator.verifyRiskRange(a.get(0), a.get(1))); }
    @Test void verifyBudget() throws Exception { OracleCases.each(M, "verifyBudget", a -> Accumulator.verifyBudget(a.get(0), rev(a.get(1)), a.get(2))); }
    @Test void verifyBoundedBudget() throws Exception { OracleCases.each(M, "verifyBoundedBudget", a -> Accumulator.verifyBoundedBudget(a.get(0), a.get(1), rev(a.get(2)), a.get(3))); }

    @Test void proveBudgetRefusals() throws Exception {
        OracleCases.each(M, "proveBudget", a -> {
            List<BigInteger> blinds = new ArrayList<>();
            for (Object b : (List<?>) a.get(1)) blinds.add(big(b));
            return coded(() -> Accumulator.proveBudget(revList(a.get(0)), blinds, rev(a.get(2))));
        });
    }

    @Test void proveRiskRangeRefusals() throws Exception { OracleCases.each(M, "proveRiskRange", a -> coded(() -> Accumulator.proveRiskRange(rev(a.get(0)), big(a.get(1))))); }

    private static byte[] authoritySecret() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/ratchet-authority".getBytes(StandardCharsets.UTF_8));
    }

    @Test void issueRiskCommitmentRefusals() throws Exception {
        byte[] auth = authoritySecret();
        OracleCases.each(M, "issueRiskCommitment", a -> coded(() -> Binding.issueRiskCommitment(rev(a.get(0)), (String) a.get(1), "short".equals(arg(a, 2)) ? new byte[3] : auth)));
    }

    @Test void verifyRiskAttestation() throws Exception { OracleCases.each(M, "verifyRiskAttestation", a -> Binding.verifyRiskAttestation(a.get(0), a.get(1), a.get(2))); }
    @Test void verifyAttestedBudget() throws Exception { OracleCases.each(M, "verifyAttestedBudget", a -> Binding.verifyAttestedBudget(a.get(0), a.get(1), a.get(2), rev(a.get(3)), a.get(4))); }

    // ---- round trips the oracle cannot compare (the provers are randomized) -------------------------------------------------------

    private static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    @Test void rangeProofRoundTrip() {
        BigInteger b = BigInteger.valueOf(12345);
        String c = Accumulator.commitRisk(n(7), b).commitment;
        Map<String, Object> proof = Accumulator.proveRiskRange(n(7), b);
        assertTrue(Accumulator.verifyRiskRange(c, proof));
        assertFalse(Accumulator.verifyRiskRange(Accumulator.commitRisk(n(8), b).commitment, proof));
        // a value outside [0, 2^32) yields a well-formed proof the verifier rejects
        BigInteger big = BigInteger.ONE.shiftLeft(32);
        assertFalse(Accumulator.verifyRiskRange(Accumulator.commitRisk(big, b).commitment, Accumulator.proveRiskRange(big, b)));
    }

    @Test void boundedBudgetRoundTrip() {
        BigInteger b1 = BigInteger.valueOf(5), b2 = BigInteger.valueOf(6);
        List<Object> commitments = new ArrayList<>(List.of(Accumulator.commitRisk(n(3), b1).commitment, Accumulator.commitRisk(n(4), b2).commitment));
        List<Object> ranges = new ArrayList<>(List.of(Accumulator.proveRiskRange(n(3), b1), Accumulator.proveRiskRange(n(4), b2)));
        List<Object> risks = new ArrayList<>(List.of(n(3), n(4)));
        Map<String, Object> ok = Accumulator.proveBudget(risks, List.of(b1, b2), n(10));
        assertTrue(Accumulator.verifyBoundedBudget(commitments, ranges, n(10), ok));
        assertTrue(Accumulator.verifyBudget(Accumulator.addCommitments(commitments), n(7), Accumulator.proveBudget(risks, List.of(b1, b2), n(7))));
        // over budget: well-formed proof, rejected
        assertFalse(Accumulator.verifyBudget(Accumulator.addCommitments(commitments), n(6), Accumulator.proveBudget(risks, List.of(b1, b2), n(6))));
        assertFalse(Accumulator.verifyBoundedBudget(commitments, ranges, n(9), ok));
        assertThrows(AccumulatorError.class, () -> Accumulator.proveBudget(risks, List.of(b1), n(10)));
    }

    @Test void attestedBudgetRoundTrip() throws Exception {
        byte[] auth = authoritySecret();
        String pk = Keys.edFromSeed(auth).id();
        Binding.Issued i1 = Binding.issueRiskCommitment(n(3), "digest-1", auth);
        Binding.Issued i2 = Binding.issueRiskCommitment(n(4), "digest-2", auth);
        Map<String, Object> proof = Accumulator.proveBudget(new ArrayList<Object>(List.of(n(3), n(4))), List.of(i1.blinding, i2.blinding), n(10));
        List<Object> items = new ArrayList<>();
        for (Binding.Issued i : List.of(i1, i2)) {
            Map<String, Object> it = new LinkedHashMap<>();
            it.put("commitment", i.commitment);
            it.put("rangeProof", i.rangeProof);
            it.put("attestation", i.attestation);
            items.add(it);
        }
        assertTrue(Binding.verifyRiskAttestation(i1.commitment, i1.attestation, pk));
        assertFalse(Binding.verifyRiskAttestation(i2.commitment, i1.attestation, pk));
        assertTrue(Binding.verifyAttestedBudget(items, List.of("digest-1", "digest-2"), pk, n(10), proof));
        assertFalse(Binding.verifyAttestedBudget(items, List.of("digest-2", "digest-1"), pk, n(10), proof));
    }

    @Test void ratchetPuncturesAndDetectsReuse() {
        byte[] seed = new byte[32];
        seed[0] = 5;
        Ratchet.Derived d = Ratchet.deriveRatchetRoot(seed, n(3));
        byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
        Ratchet.Signed s = Ratchet.signAtLeaf(d.state, n(2), msg);
        assertTrue(Ratchet.verifyLeafSignature(d.rootCommitment, n(2), msg, s.signature));
        assertFalse(Ratchet.isLeafAvailable(s.newState, n(2)));
        assertEquals(7, Ratchet.availableLeaves(s.newState).size());
        assertEquals("leaf_punctured", assertThrows(RatchetError.class, () -> Ratchet.signAtLeaf(s.newState, n(2), msg)).code);
        Binding.SpentLeafStore store = Binding.memorySpentLeafStore();
        assertEquals(true, Binding.verifyLeafSignatureOnce(d.rootCommitment, n(2), msg, s.signature, store).get("ok"));
        assertEquals("replay", Binding.verifyLeafSignatureOnce(d.rootCommitment, n(2), msg, s.signature, store).get("reason"));
    }
}
