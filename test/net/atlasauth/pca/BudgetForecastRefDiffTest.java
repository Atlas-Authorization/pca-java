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
 * The budget forecaster against the reference corpus (ref-budget-forecast, 326 cases): forecast over the compiled policies of the
 * simulator fixtures (default, custom and empty catalogs), recommendPolicy and autonomyBoundOf with their edges. Every function,
 * every case.
 */
class BudgetForecastRefDiffTest {
    static final String MODULE = "ref-budget-forecast";
    static final int TOTAL = 326;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** A corpus number as a double: a JSON number, {"$num": text} for a non-finite one; anything else is not a number (NaN, which the function refuses). */
    private static double num(Object o) {
        Map<String, Object> w = m(o);
        if (w != null && w.size() == 1 && w.get("$num") instanceof String) return Double.parseDouble((String) w.get("$num"));
        Double d = OracleCases.num(o);
        return d == null ? Double.NaN : d;
    }

    private static Object out(double d) {
        if (Double.isNaN(d)) return Issue.obj("$num", "NaN");
        if (Double.isInfinite(d)) return Issue.obj("$num", d > 0 ? "Infinity" : "-Infinity");
        return d;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("forecast", x -> {
            List<Map<String, Object>> plan = new ArrayList<>();
            for (Object a : (List<?>) x.get(1)) plan.add(m(a));
            Catalog cat = null;
            if (x.get(3) != null) {
                List<Object> rows = new ArrayList<>();
                for (Object a : (List<?>) x.get(3)) rows.add(Catalog.defineAction(a));
                cat = Catalog.buildCatalog(rows);
            }
            return BudgetForecast.forecast(CoreResearchDiffTest.compile(x.get(0)), plan, x.get(2) == null ? null : num(x.get(2)), cat);
        });
        f.put("recommendPolicy", x -> BudgetForecast.recommendPolicy(num(x.get(0)), num(x.get(1)), x.get(2) == null ? null : num(x.get(2))));
        f.put("autonomyBoundOf", x -> {
            Map<String, Object> p = new LinkedHashMap<>(m(x.get(0)));
            // a non-finite bMax is spelled {"$num": text} in the corpus; the function reads JSON numbers, so it is handed the double
            if (m(p.get("bMax")) != null) p.put("bMax", num(p.get("bMax")));
            return out(BudgetForecast.autonomyBoundOf(p));
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
