package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Guardian-set high availability and the fenced leader lease against the reference corpus (ref-ha, 753 cases): the pure decisions, the fence
 * guard, the scripted lease lifecycles (store faults, a lost compare-and-swap, a store clock moving during the sign step, corrupt records) and
 * the raw compare-and-swap of the key/value lease store. A value the reference stores goes through JSON text first, as its in-memory store does.
 */
class HaRefDiffTest {
    static final String MODULE = "ref-ha";
    static final int TOTAL = 753;
    static final String KEY = Ha.DEFAULT_LEASE_KEY;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    /** The corpus spelling of a non-finite number, {"$num": text}, as that double (throughout a value). */
    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble(((String) map.get("$num")));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    /** The inverse for a result: a non-finite number becomes {"$num": text}. */
    @SuppressWarnings("unchecked")
    private static Object enc(Object v) {
        if (v instanceof Double && (((Double) v).isNaN() || ((Double) v).isInfinite())) {
            Double d = (Double) v;
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("$num", d.isNaN() ? "NaN" : d > 0 ? "Infinity" : "-Infinity");
            return o;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(enc(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), enc(e.getValue()));
            return out;
        }
        return v;
    }

    /** What the reference's in-memory store keeps: the value as JSON text (a non-finite number is null there). */
    private static Object stored(Object v) { return Json.parseLenient(Json.stringify(v)); }

    /** One fresh store; the clock, the fault kind and the one-shot lost compare-and-swap are the case's to move. */
    private static final class Rig implements Ha.LeaseStore {
        final MemoryAtomicKv kv = new MemoryAtomicKv();
        double clock = 0;
        String fault = "none";
        boolean loseOnce = false;
        final Ha.KvLeaseStore kvs = new Ha.KvLeaseStore(kv, null, () -> clock);

        @Override public Object read() { if (fault.equals("read")) throw new RuntimeException("boom"); return kvs.read(); }
        @Override public double now() { if (fault.equals("now")) throw new RuntimeException("boom"); return kvs.now(); }
        @Override public boolean cas(Object e, Object n) {
            if (fault.equals("cas")) throw new RuntimeException("boom");
            if (loseOnce) { loseOnce = false; return false; }
            return kvs.cas(e, n);
        }
    }

    private static List<Object> lease(List<Object> ops) {
        Rig rig = new Rig();
        Map<String, Object> refs = new LinkedHashMap<>();
        List<Object> out = new ArrayList<>();
        for (Object o : ops) {
            List<Object> op = l(o);
            try {
                switch ((String) op.get(0)) {
                    case "clock": rig.clock = ((Number) (op.get(1) instanceof Double ? op.get(1) : IntentJs.num(op.get(1)))).doubleValue(); out.add(null); break;
                    case "fault": if (op.get(1).equals("loseCas")) rig.loseOnce = true; else rig.fault = (String) op.get(1); out.add(null); break;
                    case "raw": rig.kv.set(KEY, stored(op.get(1))); out.add(null); break;
                    case "read": out.add(rig.kv.get(KEY)); break;
                    case "acquire": {
                        Map<String, Object> r = Ha.acquireLease(rig, op.get(2), op.get(3));
                        if (Boolean.TRUE.equals(r.get("ok"))) refs.put((String) op.get(1), r.get("lease"));
                        out.add(r);
                        break;
                    }
                    case "renew": {
                        Map<String, Object> r = Ha.renewLease(rig, res(refs, op.get(1)), op.get(2));
                        if (Boolean.TRUE.equals(r.get("ok")) && op.get(1) instanceof String) refs.put((String) op.get(1), r.get("lease"));
                        out.add(r);
                        break;
                    }
                    case "release": {
                        Map<String, Object> r = Ha.releaseLease(rig, res(refs, op.get(1)));
                        if (Boolean.TRUE.equals(r.get("ok")) && op.get(1) instanceof String) refs.put((String) op.get(1), r.get("lease"));
                        out.add(r);
                        break;
                    }
                    case "fence": out.add(Ha.assertFence(rig, res(refs, op.get(1)), op.get(2))); break;
                    case "signer": {
                        Object lz = op.get(1) == null ? null : res(refs, op.get(1));
                        double advance = IntentJs.num(op.get(3));
                        boolean boom = Boolean.TRUE.equals(op.get(4));
                        Ha.Fenced<String> f = Ha.fencedSigner(rig, () -> lz, () -> {
                            rig.clock += advance;
                            if (boom) throw new RuntimeException("sign");
                            return "signed";
                        }, op.get(2));
                        Map<String, Object> res = new LinkedHashMap<>();
                        try {
                            Ha.Signed<String> r = f.call();
                            res.put("ok", true);
                            res.put("result", r.result);
                            res.put("epoch", r.epoch);
                        } catch (Ha.FenceError e) {
                            res.put("ok", false);
                            res.put("reason", e.reason);
                        } catch (Exception e) {
                            res.put("ok", false);
                            res.put("error", e.getMessage());
                        }
                        out.add(res);
                        break;
                    }
                    default: throw new IllegalArgumentException("bad op");
                }
            } catch (RuntimeException e) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("$err", e.getMessage());
                out.add(err);
            }
        }
        return out;
    }

    private static Object res(Map<String, Object> refs, Object x) { return x instanceof String ? refs.get(x) : x; }

    private static Object kvCas(Object prev, Object exp, Object next) {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        if (prev != null) kv.set(KEY, stored(prev));
        Ha.KvLeaseStore s = new Ha.KvLeaseStore(kv, null, () -> 0);
        boolean ok = s.cas(exp, next);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", ok);
        out.put("stored", kv.get(KEY));
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("liveGuardians", x -> enc(Ha.liveGuardians(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("quorumStatus", x -> enc(Ha.quorumStatus(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("degradeMode", x -> Ha.degradeMode(nums(x.get(0)), nums(x.get(1))));
        f.put("selectSigners", x -> enc(Ha.selectSigners(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("failoverPlan", x -> enc(Ha.failoverPlan(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("validateGuardianSet", x -> Ha.validateGuardianSet(nums(x.get(0))));
        f.put("fenceGuard", x -> {
            Ha.FenceGuard g = Ha.createFenceGuard(nums(x.get(0)));
            List<Object> admits = new ArrayList<>();
            for (Object e : l(nums(x.get(1)))) admits.add(g.admit(e));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("admits", admits);
            out.put("highest", g.highest());
            return out;
        });
        f.put("lease", x -> enc(lease(l(nums(x.get(0))))));
        f.put("kvCas", x -> enc(kvCas(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("constants", x -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("MAX_LEASE_TTL_MS", Ha.MAX_LEASE_TTL_MS);
            out.put("DEFAULT_LEASE_SKEW_MS", Ha.DEFAULT_LEASE_SKEW_MS);
            return out;
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
