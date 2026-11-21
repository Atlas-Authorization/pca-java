package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The connector action catalog against the reference corpus (ref-catalog, 75 cases): every function, every case, every scenario
 * op. A catalog is an object of methods, so the corpus drives one through a list of ops and records one result per op
 * ({@code {"$err": true}} where the reference throws).
 */
class CatalogRefDiffTest {
    static final String MODULE = "ref-catalog";
    static final int TOTAL = 75;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    private static String str(List<?> a, int i) { return arg(a, i) instanceof String ? (String) arg(a, i) : null; }

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

    private static Object op(Catalog cat, List<?> op) {
        switch ((String) op.get(0)) {
            case "get": return cat.getJson(str(op, 1));
            case "forConnector": return cat.forConnector(str(op, 1));
            case "all": return cat.allJson();
            case "resolve": return cat.resolveJson(str(op, 1), str(op, 2));
            case "resolveAction": return Catalog.resolveAction(cat, str(op, 1));
            case "digest": return Catalog.catalogDigest(cat);
            case "assertPinned":
                Catalog.assertCatalogPinned(cat, "$self".equals(op.get(1)) ? Catalog.catalogDigest(cat) : op.get(1));
                return true;
            case "extend": {
                Catalog e = Catalog.extendCatalog(cat, (List<?>) nums(op.get(1)));
                return Issue.obj("all", e.allJson(), "digest", Catalog.catalogDigest(e));
            }
            default: throw new IllegalArgumentException("bad op"); // the corpus carries one unknown op, recorded as an error
        }
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("defineAction", x -> Catalog.defineAction(nums(arg(x, 0))));
        f.put("uncataloguedSpec", x -> Catalog.uncataloguedSpec((String) arg(x, 0)));
        f.put("builtin", x -> Issue.obj("actions", Catalog.DEFAULT_CATALOG.allJson(), "digest", Catalog.catalogDigest(Catalog.DEFAULT_CATALOG), "blast", Catalog.BLAST));
        f.put("catalog", x -> {
            Catalog cat = arg(x, 0) == null ? Catalog.buildCatalog() : Catalog.buildCatalog((List<?>) nums(arg(x, 0)));
            List<Object> out = new ArrayList<>();
            for (Object o : (List<?>) arg(x, 1)) {
                try { out.add(op(cat, (List<?>) o)); } catch (RuntimeException e) { out.add(Issue.obj("$err", true)); }
            }
            return out;
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    /** The typed view agrees with the JSON rows, and a typed catalog is the same catalog as one built from its rows. */
    @Test void typedViewMatchesTheRows() {
        assertEquals(21, Catalog.BUILTIN.size());
        for (Catalog.Spec s : Catalog.BUILTIN) {
            assertTrue(IntentJs.jsonEquals(s.toJson(), Catalog.DEFAULT_CATALOG.getJson(s.verb)), s.verb);
            assertEquals(s.verb, Catalog.buildCatalog(Catalog.DEFAULT_CATALOG.allJson()).get(s.verb).verb);
        }
        assertEquals(Catalog.catalogDigest(Catalog.DEFAULT_CATALOG), Catalog.catalogDigest(Catalog.buildCatalog(Catalog.DEFAULT_CATALOG.allJson())));
    }
}
