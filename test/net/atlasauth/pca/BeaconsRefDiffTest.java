package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/**
 * Liveness beacons and the dead-man kill switch against the reference corpus (ref-beacons, 174 cases): issue, the signed message, the
 * reference, verification, monotonic acceptance, the frozen check and the durable acceptor (including a failing store and junk in the
 * sequence slot). A corpus argument cannot carry a signed zero, so the two cases named negzero get -0 here. The 1 verification the reference
 * accepts only through its legacy unbound-PQ option is asserted REFUSED.
 */
class BeaconsRefDiffTest {
    static final String MODULE = "ref-beacons";
    static final int TOTAL = 174;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    /** A store that can be told to fail its next update. */
    private static final class FlakyKv implements AtomicKv {
        final MemoryAtomicKv inner = new MemoryAtomicKv();
        boolean failNext;

        @Override public Object get(String key) { return inner.get(key); }

        @Override public void set(String key, Object value) { inner.set(key, value); }

        @Override public Object update(String key, UnaryOperator<Object> fn) {
            if (failNext) { failNext = false; throw new IllegalStateException("kv down"); }
            return inner.update(key, fn);
        }
    }

    private static Object acceptor(List<?> x) {
        FlakyKv kv = new FlakyKv();
        Beacons.Acceptor a = Beacons.createBeaconAcceptor(kv);
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) arg(x, 0)) {
            List<?> op = (List<?>) o;
            switch ((String) op.get(0)) {
                case "accept": out.add(a.accept(nums(op.get(1)), m(nums(op.get(2))))); break;
                case "raw": kv.set(Beacons.seqKey(m(op.get(1))), nums(op.get(2))); out.add(null); break;
                case "fail": kv.failNext = true; out.add(null); break;
                default: out.add(Issue.obj("$err", "op")); break;
            }
        }
        return out;
    }

    private static Object ctor(List<?> x) {
        Object spec = arg(x, 0);
        AtomicKv kv = "ok".equals(spec) || (m(spec) != null && "fn".equals(m(spec).get("update"))) ? new MemoryAtomicKv() : null;
        try {
            Beacons.createBeaconAcceptor(kv);
            return Issue.obj("built", true);
        } catch (RuntimeException e) {
            return Issue.obj("built", false);
        }
    }

    private static Object issue(Map<String, Object> c) {
        Map<String, Object> a = m(nums(((List<?>) c.get("args")).get(0)));
        Map<String, Object> args = new LinkedHashMap<>(a);
        args.put("issuerSecret", bytes(a.get("issuerSecret")));
        args.put("suite", suite(a.get("suite")));
        if (((String) c.get("name")).contains("negzero")) args.put("seq", -0.0); // a signed zero cannot be spelled in the corpus
        return Beacons.issueLivenessBeacon(args);
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("GLOBAL_SCOPE", Beacons.GLOBAL_SCOPE, "BEACON_EPOCH_MS", Beacons.BEACON_EPOCH_MS,
            "BEACON_MAX_VALIDITY_MS", Beacons.BEACON_MAX_VALIDITY_MS, "BEACON_CLOCK_SKEW_MS", Beacons.BEACON_CLOCK_SKEW_MS));
        f.put("livenessBeaconMessage", x -> Beacons.livenessBeaconMessage(m(nums(arg(x, 0)))));
        f.put("beaconRef", x -> Beacons.ref(m(nums(arg(x, 0)))));
        f.put("verifyLivenessBeacon", x -> Beacons.verifyLivenessBeacon(nums(arg(x, 0)), m(nums(arg(x, 1)))));
        f.put("acceptBeacon", x -> Beacons.acceptBeacon(nums(arg(x, 0)), nums(arg(x, 1))));
        f.put("isFrozenLiveness", x -> Beacons.isFrozenLiveness((List<?>) nums(arg(x, 0)), m(nums(arg(x, 1)))));
        f.put("acceptor", BeaconsRefDiffTest::acceptor);
        f.put("ctor", BeaconsRefDiffTest::ctor);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>(), handled = new TreeSet<>(f.keySet());
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        handled.add("issueLivenessBeacon");
        assertEquals(handled, fns);

        List<String> bad = new ArrayList<>();
        int refused = 0;
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) bad.addAll(replay(c, e.getValue()));
        }
        for (Map<String, Object> c : OracleCases.of(MODULE, "issueLivenessBeacon")) bad.addAll(replay(c, x -> issue(c)));
        for (Map<String, Object> c : OracleCases.of(MODULE, "verifyLivenessBeacon")) if (m(m(arg((List<?>) c.get("args"), 1))).get("allowUnboundPq") != null && Boolean.TRUE.equals(m(c.get("out")).get("ok"))) refused++;
        assertEquals(1, refused);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /** Replay one case; the legacy unbound-PQ acceptance is expected refused ("bad signature"); the negzero acceptance gets its -0. */
    private static List<String> replay(Map<String, Object> c, OracleCases.Fn fn) {
        Object want = c.get("out");
        List<?> args = (List<?>) c.get("args");
        String fnName = (String) c.get("fn");
        if (fnName.equals("verifyLivenessBeacon") && m(arg(args, 1)) != null && Boolean.TRUE.equals(m(arg(args, 1)).get("allowUnboundPq")) && Boolean.TRUE.equals(m(want).get("ok"))) {
            want = Issue.obj("ok", false, "reason", "bad signature");
        }
        OracleCases.Fn run = fn;
        if (fnName.equals("acceptBeacon") && ((String) c.get("name")).contains("negzero")) {
            run = x -> { Map<String, Object> next = new LinkedHashMap<>(m(nums(arg(x, 1)))); next.put("seq", -0.0); return Beacons.acceptBeacon(nums(arg(x, 0)), next); };
        }
        String d = OracleCases.diff(c, want, run);
        List<String> out = new ArrayList<>();
        if (d != null) out.add(d);
        return out;
    }
}
