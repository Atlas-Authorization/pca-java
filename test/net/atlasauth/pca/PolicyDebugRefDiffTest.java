package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** The policy debugger against the reference corpus (ref-policy-debug, 553 cases): explainRisk, explainDecision, applyDelta, counterfactual, auditPCActn. */
class PolicyDebugRefDiffTest {
    static final String MODULE = "ref-policy-debug";
    static final int TOTAL = 553;

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

    @SuppressWarnings("unchecked")
    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("explainRisk", x -> enc(PolicyDebug.explainRisk(nums(x.get(0)), nums(x.get(1)), nums(x.get(2)))));
        f.put("explainDecision", x -> enc(PolicyDebug.explainDecision(m(nums(x.get(0))))));
        f.put("applyDelta", x -> enc(PolicyDebug.applyDelta(m(nums(x.get(0))), m(nums(x.get(1))))));
        f.put("counterfactual", x -> enc(PolicyDebug.counterfactual(m(nums(x.get(0))), (List<Object>) nums(x.get(1)))));
        f.put("auditPCActn", x -> enc(PolicyDebug.auditPCActn(x.get(0), m(nums(x.get(1))), CoreVerifyDiffTest.options(m(x.get(2))))));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
