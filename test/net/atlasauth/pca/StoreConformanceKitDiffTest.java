package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.storeconformance.Cli;
import net.atlasauth.pca.storeconformance.Kit;
import net.atlasauth.pca.storeconformance.Op;
import org.junit.jupiter.api.Test;

/** Replays the reference oracles for the store conformance kit: the history model, linearizability checker, parser and report folding, and the command line. */
class StoreConformanceKitDiffTest {
    private static final String MODULE = "ref-store-conformance";
    private static final String CLI_MODULE = "ref-store-conformance-java";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static double d(Object o) { return Op.numOf(o); }
    private static List<Op> ops(Object o) { return Kit.opsOf(o); }
    private static List<Object> opsJson(List<Op> ops) { List<Object> out = new ArrayList<>(); for (Op o : ops) out.add(o.toJson()); return out; }

    @Test void step() throws Exception {
        OracleCases.each(MODULE, "step", a -> {
            List<Object> out = new ArrayList<>();
            for (double v : Kit.step(d(a.get(0)), Op.fromJson(a.get(1)))) out.add(Op.numJson(v));
            return out;
        });
    }

    @Test void overlappingTrues() throws Exception {
        OracleCases.each(MODULE, "overlappingTrues", a -> { List<Op> p = Kit.overlappingTrues(ops(a.get(0))); return p == null ? null : opsJson(p); });
    }

    @Test void prune() throws Exception { OracleCases.each(MODULE, "prune", a -> opsJson(Kit.prune(ops(a.get(0))))); }
    @Test void fastCheck() throws Exception { OracleCases.each(MODULE, "fastCheck", a -> Kit.fastCheck(ops(a.get(0)))); }
    @Test void search() throws Exception { OracleCases.each(MODULE, "search", a -> Kit.searchLinearizable(ops(a.get(0)), d(a.get(1)))); }
    @Test void decideKey() throws Exception { OracleCases.each(MODULE, "decideKey", a -> Kit.decideKey(ops(a.get(0)), d(a.get(1))).toJson()); }

    @Test void deletion() throws Exception {
        OracleCases.each(MODULE, "deletion", a -> { List<Op> o = ops(a.get(0)); return opsJson(Kit.deletion(o, o.get((int) d(a.get(1))))); });
    }

    @Test void minimize() throws Exception { OracleCases.each(MODULE, "minimize", a -> opsJson(Kit.minimize(ops(a.get(0)), d(a.get(1))))); }
    @Test void checkKey() throws Exception { OracleCases.each(MODULE, "checkKey", a -> Kit.checkKey(ops(a.get(0)), Kit.CheckOptions.fromJson(a.get(1))).toJson()); }
    @Test void checkHistory() throws Exception { OracleCases.each(MODULE, "checkHistory", a -> Kit.checkHistory(ops(a.get(0)), Kit.CheckOptions.fromJson(a.get(1))).toJson()); }
    @Test void formatOps() throws Exception { OracleCases.each(MODULE, "formatOps", a -> new ArrayList<Object>(Kit.formatOps(ops(a.get(0))))); }
    @Test void parseHistory() throws Exception { OracleCases.each(MODULE, "parseHistory", a -> Kit.parseHistory((String) a.get(0)).toJson()); }

    @Test void prng() throws Exception {
        OracleCases.each(MODULE, "prng", a -> {
            Kit.Prng r = new Kit.Prng(d(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (Object n : l(a.get(1))) out.add(r.rand(d(n)));
            return out;
        });
    }

    @Test void overall() throws Exception {
        OracleCases.each(MODULE, "overall", a -> {
            Object x = a.get(0);
            if (x instanceof List) {
                List<Object> tests = new ArrayList<>();
                for (Object s : l(x)) { Map<String, Object> t = new LinkedHashMap<>(); t.put("status", s); tests.add(t); }
                return Kit.overall(tests);
            }
            return Kit.overall(l(m(x).get("tests")));
        });
    }

    @Test void formatReport() throws Exception { OracleCases.each(MODULE, "formatReport", a -> Kit.formatReport(a.get(0), d(a.get(1)))); }
    @Test void reportJson() throws Exception { OracleCases.each(MODULE, "reportJson", a -> Kit.reportJson(a.get(0))); }

    @Test void cliConsts() throws Exception {
        OracleCases.each(CLI_MODULE, "consts", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("DEFAULT_SEARCH_BUDGET", Kit.DEFAULT_SEARCH_BUDGET);
            o.put("ALL_TESTS", new ArrayList<Object>(Kit.ALL_TESTS));
            o.put("USAGE", Cli.USAGE);
            return o;
        });
    }

    @Test void parseCli() throws Exception {
        OracleCases.each(CLI_MODULE, "parseCli", a -> Cli.parseCli(strs(a.get(0))));
    }

    @Test void cliMain() throws Exception {
        OracleCases.each(CLI_MODULE, "main", a -> {
            List<Object> out = new ArrayList<>(), err = new ArrayList<>();
            int code = Cli.main(strs(a.get(0)), out::add, err::add);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("code", code);
            r.put("out", out);
            r.put("err", err);
            return r;
        });
    }

    private static List<String> strs(Object o) { List<String> r = new ArrayList<>(); for (Object x : l(o)) r.add((String) x); return r; }
}
