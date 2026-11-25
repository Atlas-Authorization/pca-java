package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Differential test of the durable core stores against the TypeScript reference: every oracle case is one scripted op sequence over a
 * fresh store; each op's result (or typed error code) must equal the reference's.
 */
public class CoreStoresDiffTest {
    static final String MODULE = "ref-core-stores-java";

    // ---- shared glue ----

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static byte[] seed(String label) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    /** The reference's Number.isSafeInteger argument check: anything else is a RangeError. */
    static long safe(Object o) {
        if (o instanceof Json.Num && "-0".equals(((Json.Num) o).raw)) return 0; // Number.isSafeInteger(-0) holds in the reference
        if (!Json.isSafeInt(o)) throw new IllegalArgumentException("not a safe integer");
        return Json.asLong(o);
    }

    static Map<String, Object> err(String name) { Map<String, Object> e = new LinkedHashMap<>(); e.put("$err", name); return e; }

    static String codeOf(Throwable t) {
        if (t instanceof LedgerStoreError) return ((LedgerStoreError) t).code();
        if (t instanceof BondStoreError) return ((BondStoreError) t).code();
        if (t instanceof BudgetLedgerError) return ((BudgetLedgerError) t).code();
        return t instanceof IllegalArgumentException ? "RangeError" : "Error";
    }

    interface Op { Object run(List<Object> op) throws Exception; }

    static List<Object> script(List<?> args, Op f, boolean byMessage) {
        List<Object> out = new ArrayList<>();
        for (Object o : l(args.get(0))) {
            try {
                out.add(f.run(l(o)));
            } catch (Throwable t) {
                out.add(err(byMessage ? String.valueOf(t.getMessage()) : codeOf(t)));
            }
        }
        return out;
    }

    static List<String> strings(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("not an array");
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) o) {
            if (!(x instanceof String)) throw new IllegalArgumentException("not a string");
            out.add((String) x);
        }
        return out;
    }

    static List<Object> maps(List<Map<String, Object>> in) { return new ArrayList<Object>(in); }

    // ---- ledger store ----

    @Test void ledgerStore() throws Exception {
        OracleCases.each(MODULE, "ledgerStore", a -> {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            KvLedgerStore s = new KvLedgerStore(kv);
            return script(a, op -> {
                switch ((String) op.get(0)) {
                    case "size": return s.size();
                    case "read": return s.read(safe(op.get(1)), safe(op.get(2)));
                    case "append": return s.append(safe(op.get(1)), strings(op.get(2))).toJson();
                    case "cpCount": return s.checkpointCount();
                    case "cps": return maps(s.checkpoints(safe(op.get(1))));
                    case "appendCp": return s.appendCheckpoint(safe(op.get(1)), m(op.get(2))).toJson();
                    case "kvSet": kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op.get(1))); return null;
                    default: throw new IllegalStateException("op");
                }
            }, false);
        });
    }

    // ---- stored ledger ----

    @Test void storedLedger() throws Exception {
        OracleCases.each(MODULE, "storedLedger", a -> {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            KvLedgerStore store = new KvLedgerStore(kv);
            Map<String, StoredLedger> handles = new HashMap<>();
            long[] calls = {0};
            Keys.EdKey gkey = Keys.edFromSeed(seed("stored-ledger-guardian"));
            return script(a, op -> {
                String head = (String) op.get(0);
                if (head.equals("open")) {
                    StoredLedger.Options o = new StoredLedger.Options();
                    o.store = store;
                    o.guardianKey = op.size() > 2 && "other-key".equals(op.get(2)) ? Keys.edFromSeed(seed("other")) : gkey;
                    o.instanceId = op.size() > 3 && op.get(3) != null ? (String) op.get(3) : "inst";
                    o.principal = "pr";
                    o.clock = () -> 1_800_000_000_000.0 + 1000.0 * calls[0]++;
                    StoredLedger h = StoredLedger.open(o);
                    handles.put((String) op.get(1), h);
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("size", h.size());
                    r.put("guardian", h.guardian());
                    return r;
                }
                if (head.equals("kvSet")) { kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op.get(1))); return null; }
                if (head.equals("kvGet")) return StoreJs.deepCopy(kv.get(KvLedgerStore.DOC_KEY));
                StoredLedger h = handles.get(head);
                switch ((String) op.get(1)) {
                    case "append": { Map<String, Object> r = new LinkedHashMap<>(); String c = (String) op.get(2); r.put("index", h.append(c)); r.put("commit", c); return r; }
                    case "checkpoint": return h.checkpoint();
                    case "catchUp": h.catchUp(); return null;
                    case "head": return h.head();
                    case "size": return h.size();
                    case "incl": return h.inclusionProof(safe(op.get(2)));
                    case "consFrom": return h.consistencyProofFrom(safe(op.get(2)));
                    case "commits": return new ArrayList<Object>(h.commits());
                    case "latest": return h.latestCheckpoint();
                    case "chain": return maps(h.checkpointChain());
                    case "guardian": return h.guardian();
                    default: throw new IllegalStateException("op");
                }
            }, false);
        });
    }

    // ---- bond store ----

    @Test void bondStore() throws Exception {
        OracleCases.each(MODULE, "bondStore", a -> {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            KvBondStore s = new KvBondStore(kv);
            return script(a, op -> {
                switch ((String) op.get(0)) {
                    case "read": return s.read((String) op.get(1), (String) op.get(2)).toJson();
                    case "commit": return s.commit(m(op.get(1)), StoreJs.dbl(op.get(2))).toJson();
                    case "deposit": return StoreJs.num(s.deposit((String) op.get(1), StoreJs.dbl(op.get(2))));
                    case "kvSet": kv.set(KvBondStore.DOC_KEY, StoreJs.deepCopy(op.get(1))); return null;
                    case "kvGet": return StoreJs.deepCopy(kv.get(KvBondStore.DOC_KEY));
                    default: throw new IllegalStateException("op");
                }
            }, false);
        });
    }

    // ---- budget ledger ----

    @SuppressWarnings("unchecked")
    static BudgetLedger.ReserveRequest request(Object o) {
        Map<String, Object> m = m(o);
        BudgetLedger.ReserveRequest r = new BudgetLedger.ReserveRequest();
        r.event = m(m.get("event"));
        r.accumulators = m.get("accumulators") instanceof List ? (List<Map<String, Object>>) (List<?>) m.get("accumulators") : null;
        r.schema = m.get("schema");
        if (m.containsKey("expectedVersion")) r.expectedVersion = safe(m.get("expectedVersion"));
        if (m.containsKey("expiresAt")) r.expiresAt = safe(m.get("expiresAt"));
        return r;
    }

    static List<Budgets.Reservation> reservations(Object o) {
        List<Budgets.Reservation> out = new ArrayList<>();
        for (Object x : l(o)) out.add(new Budgets.Reservation((String) m(x).get("key"), (String) m(x).get("id")));
        return out;
    }

    @Test void budgetLedger() throws Exception {
        Keys.EdKey rkey = Keys.edFromSeed(seed("release-signer"));
        OracleCases.each(MODULE, "budgetLedger", a -> {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            KvBudgetLedger[] ledger = new KvBudgetLedger[1];
            KvLedgerStore log = new KvLedgerStore(new MemoryAtomicKv());
            return script(a, op -> {
                switch ((String) op.get(0)) {
                    case "new": ledger[0] = new KvBudgetLedger(kv, (Boolean) op.get(1)); return ledger[0].durable();
                    case "snapshot": return ledger[0].snapshot((String) op.get(1)).toJson();
                    case "reserve": return ledger[0].reserve((String) op.get(1), request(op.get(2))).toJson();
                    case "start": return ledger[0].start((String) op.get(1), (String) op.get(2)).toJson();
                    case "commit": return ledger[0].commit((String) op.get(1), (String) op.get(2)).toJson();
                    case "release": return ledger[0].release((String) op.get(1), (String) op.get(2), op.get(3) == null ? null : m(op.get(3))).toJson();
                    case "expire": return ledger[0].expire((String) op.get(1), safe(op.get(2))).toJson();
                    case "signRelease": return Budgets.signRelease((String) op.get(1), (String) op.get(2), (String) op.get(3), safe(op.get(4)), rkey);
                    case "verifyRelease": return Budgets.verifyRelease(op.get(1), "signer".equals(op.get(2)) ? rkey.id() : (String) op.get(2));
                    case "releaseCommit": { List<Object> r = new ArrayList<>(); r.add(Budgets.releaseDigest(m(op.get(1)))); r.add(Budgets.releaseCommit(m(op.get(1)))); return r; }
                    case "anchor": { List<Object> r = new ArrayList<>(); r.add(Budgets.anchorRelease(log, m(op.get(1)))); r.add(log.size()); return r; }
                    case "scopeKey": return Budgets.scopeKey((String) op.get(1), (String) op.get(2));
                    case "kvSet": kv.set((String) op.get(1), StoreJs.deepCopy(op.get(2))); return null;
                    case "admit": {
                        Map<String, Object> ad = m(op.get(1));
                        Map<String, String> ids = new LinkedHashMap<>();
                        for (Map.Entry<String, Object> e : m(ad.get("ids")).entrySet()) ids.put(e.getKey(), (String) e.getValue());
                        @SuppressWarnings("unchecked") List<Map<String, Object>> accs = (List<Map<String, Object>>) (List<?>) ad.get("accumulators");
                        boolean allow = (Boolean) ad.get("allow");
                        Budgets.Admission r = Budgets.admitAggregateAction(ledger[0], ids, accs, null, m(ad.get("event")), state -> {
                            Map<String, Object> v = new LinkedHashMap<>();
                            v.put("allow", allow);
                            v.put("state", state);
                            return v;
                        }, ad.containsKey("expiresAt") ? safe(ad.get("expiresAt")) : null, ad.containsKey("maxAttempts") ? (int) safe(ad.get("maxAttempts")) : null);
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("admitted", r.admitted);
                        if (r.reason != null) out.put("reason", r.reason);
                        if (r.verdict != null) out.put("verdict", r.verdict);
                        if (r.reservations != null) {
                            List<Object> rs = new ArrayList<>();
                            for (Budgets.Reservation x : r.reservations) { Map<String, Object> e = new LinkedHashMap<>(); e.put("key", x.key); e.put("id", x.id); rs.add(e); }
                            out.put("reservations", rs);
                        }
                        if (r.state != null) out.put("state", r.state);
                        return out;
                    }
                    case "startAgg": return Budgets.startAggregate(ledger[0], reservations(op.get(1)));
                    case "settleAgg": {
                        List<Object> r = new ArrayList<>();
                        for (BudgetLedger.SettleOutcome x : Budgets.settleAggregate(ledger[0], reservations(op.get(1)), (String) op.get(2), null)) r.add(x.toJson());
                        return r;
                    }
                    default: throw new IllegalStateException("op");
                }
            }, false);
        });
    }

    // ---- mesh witness ----

    @Test void meshWitness() throws Exception {
        OracleCases.each(MODULE, "meshWitness", a -> {
            Map<String, MemoryMeshWitnessStore> stores = new HashMap<>();
            Map<String, MeshWitness> witnesses = new HashMap<>();
            Map<String, MeshDomain> domains = new HashMap<>();
            return script(a, op -> {
                switch ((String) op.get(0)) {
                    case "store": stores.put((String) op.get(1), new MemoryMeshWitnessStore()); return true;
                    case "witness": {
                        MeshWitness.Options o = new MeshWitness.Options();
                        if (op.get(2) != null) o.store = stores.get((String) op.get(2));
                        MeshWitness w = new MeshWitness(Keys.edFromSeed(seed((String) op.get(3))), o);
                        witnesses.put((String) op.get(1), w);
                        return w.id;
                    }
                    case "witnessClock": {
                        MeshWitness.Options o = new MeshWitness.Options();
                        double now = StoreJs.dbl(op.get(3));
                        o.clock = () -> now;
                        if (op.get(4) != null) o.maxClockSkewMs = StoreJs.dbl(op.get(4));
                        witnesses.put((String) op.get(1), new MeshWitness(Keys.edFromSeed(seed((String) op.get(2))), o));
                        return true;
                    }
                    case "restart": {
                        MeshWitness.Options o = new MeshWitness.Options();
                        o.store = stores.get((String) op.get(2));
                        MeshWitness w = new MeshWitness(Keys.edFromSeed(seed((String) op.get(3))), o);
                        witnesses.put((String) op.get(1), w);
                        return w.exportState();
                    }
                    case "domain": { MeshDomain d = new MeshDomain((String) op.get(1), Keys.edFromSeed(seed((String) op.get(2)))); domains.put((String) op.get(1), d); return d.id; }
                    case "record": {
                        String label = (String) op.get(2);
                        Map<String, Object> cap = new LinkedHashMap<>();
                        cap.put("id", label);
                        Map<String, Object> cav = new LinkedHashMap<>();
                        cav.put("type", "scope");
                        List<Object> acts = new ArrayList<>();
                        acts.add(label);
                        cav.put("actions", acts);
                        List<Object> cavs = new ArrayList<>();
                        cavs.add(cav);
                        cap.put("caveats", cavs);
                        return domains.get((String) op.get(1)).record(cap);
                    }
                    case "revoke": domains.get((String) op.get(1)).revoke((String) op.get(2)); return null;
                    case "publish": {
                        List<MeshWitness> ws = new ArrayList<>();
                        for (Object w : l(op.get(3))) ws.add(witnesses.get((String) w));
                        return domains.get((String) op.get(1)).publishHead(ws, StoreJs.dbl(op.get(2)), op.get(4) == null ? null : (int) safe(op.get(4)));
                    }
                    case "lastSeen": return witnesses.get((String) op.get(1)).lastSeen((String) op.get(2));
                    case "export": return witnesses.get((String) op.get(1)).exportState();
                    case "import": witnesses.get((String) op.get(1)).importState(m(op.get(2))); return null;
                    case "load": return stores.get((String) op.get(1)).load();
                    case "save": stores.get((String) op.get(1)).save(m(op.get(2))); return null;
                    case "domainId": return domains.get((String) op.get(1)).id;
                    default: throw new IllegalStateException("op");
                }
            }, true);
        });
    }
}
