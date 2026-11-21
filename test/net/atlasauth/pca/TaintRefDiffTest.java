package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/** The taint lattice, the label registry, ref classification and the labelled taint result against the reference corpus (ref-taint, 2344 cases). */
class TaintRefDiffTest {
    static final String MODULE = "ref-taint";
    static final int TOTAL = 2344;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Taint.LabelContext ctx(Object cO) {
        Map<String, Object> c = m(cO);
        Taint.TrustedInputRegistry reg = null;
        Map<String, Object> rs = m(c.get("registry"));
        if (rs != null) {
            Object mode = rs.get("mode");
            if ("fixed".equals(mode)) { Object fx = rs.get("fixed"); reg = d -> fx; }
            else if ("throws".equals(mode)) reg = d -> { throw new RuntimeException("registry boom"); };
            else {
                Taint.InMemoryTrustedInputRegistry im = new Taint.InMemoryTrustedInputRegistry();
                if (rs.get("records") != null) for (Object rec : l(rs.get("records"))) im.record(l(rec).get(0), l(rec).get(1));
                reg = im;
            }
        }
        Predicate<String> graph = null;
        Map<String, Object> gs = m(c.get("graph"));
        if (gs != null) {
            boolean boom = Boolean.TRUE.equals(gs.get("throws"));
            List<Object> nodes = l(gs.get("nodes"));
            graph = id -> { if (boom) throw new RuntimeException("graph boom"); return nodes.contains(id); };
        }
        return new Taint.LabelContext(reg, graph);
    }

    private static List<Object> registry(List<Object> ops) {
        Taint.InMemoryTrustedInputRegistry r = new Taint.InMemoryTrustedInputRegistry();
        List<Object> out = new ArrayList<>();
        for (Object o : ops) {
            List<Object> op = l(o);
            switch ((String) op.get(0)) {
                case "lookup": out.add(r.lookup((String) op.get(1))); break;
                case "size": out.add(r.size()); break;
                case "emptyLookup": out.add(Taint.EMPTY_REGISTRY.lookup((String) op.get(1))); break;
                case "record": r.record(op.get(1), op.get(2)); out.add(null); break;
                case "recordTrusted": r.recordTrusted(op.get(1)); out.add(null); break;
                case "recordFirstParty": r.recordFirstParty(op.get(1)); out.add(null); break;
                case "recordTool": r.recordTool(op.get(1), op.get(2)); out.add(null); break;
                case "recordWeb": r.recordWeb(op.get(1)); out.add(null); break;
                default: throw new IllegalArgumentException("bad op");
            }
        }
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("TAINT_LEVELS", new ArrayList<Object>(List.of(Taint.LEVELS)));
            out.put("BOTTOM", Taint.bottom());
            out.put("TOP", Taint.top());
            return out;
        });
        f.put("isTaintLevel", x -> Taint.isTaintLevel(x.get(0)));
        f.put("labelRank", x -> Taint.labelRank(x.get(0)));
        f.put("taintValue", x -> Taint.taintValue(x.get(0)));
        f.put("joinLabel", x -> Taint.joinLabel(x.get(0), x.get(1)));
        f.put("joinLabels", x -> Taint.joinLabels(l(x.get(0))));
        f.put("registry", x -> registry(l(x.get(0))));
        f.put("classifyRef", x -> Taint.classifyRef(x.get(0), ctx(x.get(1))));
        f.put("computeTaint", x -> Taint.computeTaint(x.get(0), ctx(x.get(1))));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
