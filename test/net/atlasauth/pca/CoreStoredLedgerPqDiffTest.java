package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * StoredLedger with post-quantum and hybrid checkpoint suites: reopening documents the reference signed under different pin and suite
 * settings must give the reference's outcomes (differential), and a Java-signed hybrid / pure ML-DSA chain must verify on reopen under the
 * pin and be refused without it or under another pin.
 */
public class CoreStoredLedgerPqDiffTest {
    static final String MODULE = "ref-core-stored-ledger-pq-java";
    static final String HYBRID = "hybrid-ed25519-ml-dsa-65", PURE = "ml-dsa-65";

    static Keys.PqKey pq(int b) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) b);
        return Keys.pqFromSeed(Pq.Prim.ML_DSA_65, s);
    }

    static String codeOf(Throwable t) { return t instanceof LedgerStoreError ? ((LedgerStoreError) t).code() : "Error"; }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Keys.SuiteKey suiteOf(Object mode, Keys.EdKey g, Keys.PqKey key) {
        if ("hybrid".equals(mode)) return Keys.suite(HYBRID, g, key);
        if ("ml".equals(mode)) return Keys.suite(PURE, null, key);
        return null;
    }

    @Test void referenceSignedDocuments() throws Exception {
        OracleCases.each(MODULE, "storedLedgerPq", a -> {
            Map<String, Object> pins = m(a.get(0));
            MemoryAtomicKv kv = new MemoryAtomicKv();
            KvLedgerStore store = new KvLedgerStore(kv);
            Keys.EdKey g = Keys.edFromSeed(CoreStoresDiffTest.seed("stored-ledger-guardian"));
            Keys.PqKey key = pq(7);
            Map<String, StoredLedger> hs = new HashMap<>();
            long[] calls = {0};
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(1)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    String head = (String) op.get(0);
                    if (head.equals("kvSet")) {
                        kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op.get(1)));
                    } else if (head.equals("open")) {
                        Map<String, Object> c = op.get(2) == null ? new LinkedHashMap<>() : m(op.get(2));
                        StoredLedger.Options o = new StoredLedger.Options();
                        o.store = store;
                        o.guardianKey = g;
                        o.instanceId = "inst";
                        o.principal = "pr";
                        o.clock = () -> 1_800_000_000_000.0 + 1000.0 * calls[0]++;
                        o.suite = suiteOf(c.get("suite"), g, key);
                        o.pin = c.get("pin") == null ? null : m(pins.get((String) c.get("pin")));
                        StoredLedger h = StoredLedger.open(o);
                        hs.put((String) op.get(1), h);
                        Map<String, Object> r = new LinkedHashMap<>();
                        r.put("size", h.size());
                        r.put("guardian", h.guardian());
                        v = r;
                    } else {
                        StoredLedger h = hs.get(head);
                        switch ((String) op.get(1)) {
                            case "append": { Map<String, Object> r = new LinkedHashMap<>(); String c = (String) op.get(2); r.put("index", h.append(c)); r.put("commit", c); v = r; break; }
                            case "checkpoint": {
                                Map<String, Object> s = h.checkpoint();
                                Map<String, Object> r = new LinkedHashMap<>();
                                r.put("size", s.get("size"));
                                r.put("alg", s.get("alg"));
                                r.put("pq", s.containsKey("pq_sig"));
                                r.put("root", s.get("root"));
                                r.put("prev_root", s.get("prev_root"));
                                v = r;
                                break;
                            }
                            case "latest": v = h.latestCheckpoint(); break;
                            case "chain": v = new ArrayList<Object>(h.checkpointChain()); break;
                            case "head": v = h.head(); break;
                            case "size": v = h.size(); break;
                            default: throw new IllegalStateException("op");
                        }
                    }
                    out.add(v);
                } catch (Throwable t) {
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("$err", codeOf(t));
                    out.add(e);
                }
            }
            return out;
        });
    }

    private static StoredLedger.Options options(LedgerStore store, Keys.EdKey g, Keys.SuiteKey suite, Map<String, Object> pin) {
        StoredLedger.Options o = new StoredLedger.Options();
        o.store = store;
        o.guardianKey = g;
        o.instanceId = "inst";
        o.principal = "pr";
        o.clock = () -> 1_800_000_000_000.0;
        o.suite = suite;
        o.pin = pin;
        return o;
    }

    private void roundTrip(String alg, Keys.EdKey g, Keys.SuiteKey suite, Keys.PqKey key) {
        Map<String, Object> pin = Keys.pqPin(Keys.suite(HYBRID, g, key));
        MemoryAtomicKv kv = new MemoryAtomicKv();
        KvLedgerStore store = new KvLedgerStore(kv);
        StoredLedger l = StoredLedger.open(options(store, g, suite, pin));
        for (int i = 0; i < 3; i++) l.append("c" + i);
        Map<String, Object> a = l.checkpoint();
        for (int i = 3; i < 6; i++) l.append("c" + i);
        Map<String, Object> b = l.checkpoint();
        assertEquals(alg, a.get("alg"));
        assertEquals(alg, b.get("alg"));
        assertEquals(HYBRID.equals(alg), b.containsKey("pq_sig"));
        assertTrue(Ledger.verifyHeadConsistency(a, b, l.consistencyProofFrom(3), g.id(), null, pin));
        assertTrue(!Ledger.verifyTreeHead(b, g.id(), null, null), "no pin: refused");
        assertEquals(Json.canonicalize(b), Json.canonicalize(StoredLedger.open(options(store, g, suite, pin)).latestCheckpoint()));
        assertEquals(Json.canonicalize(b), Json.canonicalize(StoredLedger.open(options(store, g, null, pin)).latestCheckpoint()), "an auditor needs only the pin");
        assertEquals("forged_checkpoint", assertThrows(LedgerStoreError.class, () -> StoredLedger.open(options(store, g, null, null))).code());
        Map<String, Object> other = Keys.pqPin(Keys.suite(HYBRID, g, pq(9)));
        assertEquals("forged_checkpoint", assertThrows(LedgerStoreError.class, () -> StoredLedger.open(options(store, g, null, other))).code());
    }

    @Test void hybridChainRoundTrips() {
        Keys.EdKey g = Keys.edFromSeed(CoreStoresDiffTest.seed("w11-pq-hybrid"));
        Keys.PqKey key = pq(3);
        roundTrip(HYBRID, g, Keys.suite(HYBRID, g, key), key);
    }

    @Test void pureMlDsaChainRoundTrips() {
        Keys.EdKey g = Keys.edFromSeed(CoreStoresDiffTest.seed("w11-pq-pure"));
        Keys.PqKey key = pq(4);
        roundTrip(PURE, g, Keys.suite(PURE, null, key), key);
    }

    @Test void aPqSuiteNeedsAPin() {
        Keys.EdKey g = Keys.edFromSeed(CoreStoresDiffTest.seed("w11-pq-pin"));
        KvLedgerStore store = new KvLedgerStore(new MemoryAtomicKv());
        assertEquals("pin_missing", assertThrows(LedgerStoreError.class, () -> StoredLedger.open(options(store, g, Keys.suite(HYBRID, g, pq(5)), null))).code());
        assertNotNull(StoredLedger.open(options(store, g, Keys.ed25519(g), null)));
    }

    @Test void aPinThatDoesNotMatchTheSigningKeyIsRefusedAndNothingIsStored() {
        Keys.EdKey g = Keys.edFromSeed(CoreStoresDiffTest.seed("w11-pq-mismatch"));
        KvLedgerStore store = new KvLedgerStore(new MemoryAtomicKv());
        Map<String, Object> wrong = Keys.pqPin(Keys.suite(HYBRID, g, pq(9)));
        StoredLedger l = StoredLedger.open(options(store, g, Keys.suite(HYBRID, g, pq(8)), wrong));
        l.append("a");
        l.append("b");
        assertEquals("forged_checkpoint", assertThrows(LedgerStoreError.class, l::checkpoint).code());
        assertEquals(0, store.checkpointCount());
    }
}
