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
 * The frontier signal typing against the reference corpus (ref-frontier-signals, 690 cases): semanticSignal, progressSignal, objectiveSignal
 * and tightenRiskInputs, whose signed zeros are compared bit for bit (min(0, -0) is -0).
 */
class FrontierSignalsRefDiffTest {
    static final String MODULE = "ref-frontier-signals";
    static final int TOTAL = 690;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

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
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    /** A risk-input argument as the reference reads it: null throws, a non-object has no members. */
    private static Map<String, Object> side(Object o) {
        if (o == null) return null;
        Map<String, Object> r = m(nums(o));
        return r != null ? r : new LinkedHashMap<>();
    }

    private static Object tighten(List<?> x) { return FrontierSignals.tightenRiskInputs(side(x.get(0)), side(x.get(1))); }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("semanticSignal", x -> FrontierSignals.semanticSignal(nums(x.get(0))));
        f.put("progressSignal", x -> FrontierSignals.progressSignal(nums(x.get(0))));
        f.put("objectiveSignal", x -> FrontierSignals.objectiveSignal(nums(x.get(0))));
        f.put("tightenRiskInputs", FrontierSignalsRefDiffTest::tighten);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    /** The comparison above is numeric (-0 equals 0): the sign of every zero in the result is checked here. */
    @Test void signedZeros() throws Exception {
        int zeros = 0;
        for (Map<String, Object> c : OracleCases.of(MODULE, "tightenRiskInputs")) {
            Map<String, Object> want = m(c.get("out"));
            if (want == null || want.containsKey("$throws")) continue;
            Map<String, Object> got = m(OracleCases.toJson(tighten((List<?>) c.get("args"))));
            for (String k : want.keySet()) {
                double w = IntentJs.num(want.get(k)), g = IntentJs.num(got.get(k));
                if (w == 0) zeros++;
                assertEquals(Double.doubleToRawLongBits(w), Double.doubleToRawLongBits(g), c.get("name") + " " + k);
            }
        }
        org.junit.jupiter.api.Assertions.assertTrue(zeros > 0);
    }
}
