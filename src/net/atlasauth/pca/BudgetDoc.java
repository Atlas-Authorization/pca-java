package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One key's reservations and the pure transitions over them; every reference budget store is these plus a per-key lock. */
public final class BudgetDoc {
    public long ver = 0;
    public final List<Map<String, Object>> events = new ArrayList<>();

    public static BudgetDoc empty() { return new BudgetDoc(); }

    static final int ID_MAX = 256;

    /** A non-empty string of at most 256 characters without control characters. */
    public static boolean idOk(Object s) {
        if (!(s instanceof String)) return false;
        String v = (String) s;
        if (v.isEmpty() || v.length() > ID_MAX) return false;
        for (int i = 0; i < v.length(); i++) if (v.charAt(i) <= 0x1f) return false;
        return true;
    }

    public Map<String, Object> encode() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1));
        m.put("ver", StoreJs.num(ver));
        List<Object> es = new ArrayList<>();
        for (Map<String, Object> e : events) es.add(StoreJs.deepCopy(e));
        m.put("events", es);
        return m;
    }

    /** Decode a stored document (null = empty); fails closed with {@code store_corrupt}. The result shares nothing with {@code raw}. */
    public static BudgetDoc decode(Object raw) {
        if (raw == null) return empty();
        Map<String, Object> m = StoreJs.map(raw);
        if (m == null || !StoreJs.isInt(m.get("v")) || StoreJs.lng(m.get("v")) != 1 || !StoreJs.isInt(m.get("ver")) || !(m.get("events") instanceof List)) throw new BudgetLedgerError("store_corrupt", "budget document has the wrong shape");
        BudgetDoc d = empty();
        d.ver = StoreJs.lng(m.get("ver"));
        for (Object e : (List<?>) m.get("events")) {
            Map<String, Object> em = StoreJs.map(e);
            if (em == null || !(em.get("id") instanceof String)) throw new BudgetLedgerError("store_corrupt", "budget document has the wrong shape");
            d.events.add(StoreJs.map(StoreJs.deepCopy(em)));
        }
        return d;
    }

    private Map<String, Object> find(String id) {
        for (Map<String, Object> e : events) if (id.equals(e.get("id"))) return e;
        return null;
    }

    private static boolean sameEvent(Map<String, Object> a, Map<String, Object> b) {
        return Pca.hashCanonical(core(a)).equals(Pca.hashCanonical(core(b)));
    }

    private static Map<String, Object> core(Map<String, Object> e) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : new String[] {"id", "verb", "resource", "params", "t"}) if (e.containsKey(k)) m.put(k, e.get(k));
        return m;
    }

    public BudgetLedger.ReserveOutcome reserveInDoc(BudgetLedger.ReserveRequest req) {
        Map<String, Object> e = req == null ? null : req.event;
        if (e == null || !idOk(e.get("id")) || !(e.get("verb") instanceof String) || !(e.get("resource") instanceof String) || !StoreJs.isInt(e.get("t"))
            || !(e.get("params") instanceof Map || e.get("params") instanceof List)) throw new IllegalArgumentException("reserve: a malformed event");
        if (req.accumulators == null) throw new IllegalArgumentException("reserve: accumulators must be an array");
        if (req.expectedVersion != null && req.expectedVersion < 0) throw new IllegalArgumentException("reserve: expectedVersion must be a non-negative safe integer");
        String id = (String) e.get("id");
        Map<String, Object> prior = find(id);
        if (prior != null) {
            return sameEvent(prior, e) ? new BudgetLedger.ReserveOutcome("replayed", ver, null, (String) prior.get("status"), null, null, null)
                : new BudgetLedger.ReserveOutcome("id_conflict", ver, null, null, null, null, null);
        }
        if (req.expectedVersion != null && req.expectedVersion != ver) return new BudgetLedger.ReserveOutcome("conflict", ver, null, null, null, null, null);
        Map<String, Long> post = new LinkedHashMap<>();
        for (Map<String, Object> a : req.accumulators) {
            if (a.get("domain_max") == null) throw new IllegalArgumentException("reserve: accumulator " + a.get("id") + " has no domain_max (the cap)");
            if (!IntentAcc.accSelects(a, (String) e.get("verb"), req.schema)) continue;
            Long p = IntentHistory.accPost(a, events, (String) e.get("verb"), StoreJs.map(e.get("params")), e.get("t"), req.schema);
            if (p == null) throw new BudgetLedgerError("store_corrupt", "unreadable history");
            double cap = StoreJs.dbl(a.get("domain_max"));
            if (!(p <= cap)) return new BudgetLedger.ReserveOutcome("over_cap", ver, null, null, (String) a.get("id"), p, cap);
            post.put((String) a.get("id"), p);
        }
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", id);
        entry.put("verb", e.get("verb"));
        entry.put("resource", e.get("resource"));
        entry.put("params", StoreJs.deepCopy(e.get("params")));
        entry.put("t", e.get("t"));
        entry.put("status", "reserved");
        if (req.expiresAt != null) entry.put("exp", StoreJs.num((long) req.expiresAt));
        events.add(entry);
        ver += 1;
        return new BudgetLedger.ReserveOutcome("reserved", ver, post, null, null, null, null);
    }

    public BudgetLedger.SettleOutcome startInDoc(String id) {
        Map<String, Object> e = find(id);
        if (e == null) return new BudgetLedger.SettleOutcome("unknown", ver, null);
        if ("released".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("refused", ver, "released");
        if (e.containsKey("started") || "committed".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("replayed", ver, null);
        e.put("started", Boolean.TRUE);
        ver += 1;
        return new BudgetLedger.SettleOutcome("settled", ver, null);
    }

    public BudgetLedger.SettleOutcome commitInDoc(String id) {
        Map<String, Object> e = find(id);
        if (e == null) return new BudgetLedger.SettleOutcome("unknown", ver, null);
        if ("committed".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("replayed", ver, null);
        if (!"reserved".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("refused", ver, (String) e.get("status"));
        e.put("status", "committed");
        ver += 1;
        return new BudgetLedger.SettleOutcome("settled", ver, null);
    }

    public BudgetLedger.SettleOutcome releaseInDoc(String key, String id, Map<String, Object> evidence) {
        Map<String, Object> e = find(id);
        if (e == null) return new BudgetLedger.SettleOutcome("unknown", ver, null);
        if ("released".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("replayed", ver, null);
        if (!"reserved".equals(e.get("status"))) return new BudgetLedger.SettleOutcome("refused", ver, (String) e.get("status"));
        if (evidence != null && (!key.equals(evidence.get("key")) || !id.equals(evidence.get("id")))) throw new IllegalArgumentException("release: the evidence is for another reservation");
        e.put("status", "released");
        if (evidence != null) e.put("rel", StoreJs.deepCopy(evidence));
        ver += 1;
        return new BudgetLedger.SettleOutcome("settled", ver, null);
    }

    public BudgetLedger.Expired expireInDoc(long now) {
        if (now < -9007199254740991L || now > 9007199254740991L) throw new IllegalArgumentException("expire: now must be a safe integer");
        List<String> released = new ArrayList<>();
        for (Map<String, Object> e : events) {
            Double exp = e.containsKey("exp") ? StoreJs.dbl(e.get("exp")) : null;
            if ("reserved".equals(e.get("status")) && !e.containsKey("started") && exp != null && exp <= now) {
                e.put("status", "released");
                Map<String, Object> rel = new LinkedHashMap<>();
                rel.put("reason", "expired");
                rel.put("at", StoreJs.num(now));
                e.put("rel", rel);
                released.add((String) e.get("id"));
            }
        }
        if (!released.isEmpty()) ver += 1;
        return new BudgetLedger.Expired(released, ver);
    }
}
