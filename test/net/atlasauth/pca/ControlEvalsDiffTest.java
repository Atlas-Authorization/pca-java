package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.controlevals.ControlEvals;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the empirical control evaluation through the native port. */
public class ControlEvalsDiffTest {
    private static final String M = "ref-control-evals";

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }

    static double d(Object o) { return IntentJs.num(o); }

    static ControlEvals.RedPolicy red(String name) {
        switch (name) {
            case "over-cap": return ControlEvals.overCapRed;
            case "off-verb": return ControlEvals.offVerbRed;
            case "slow-burn": return ControlEvals.slowBurnRed;
            case "taint-exfil": return ControlEvals.taintExfilRed;
            case "replay": return ControlEvals.replayRed;
            case "immune-probe": return ControlEvals.immuneProbeBurstRed;
            case "benign": return ControlEvals.benignBaselineRed;
            case "gap-exploit": return ControlEvals.gapExploitRed();
            default: throw new IllegalArgumentException(name);
        }
    }

    static ControlEvals.Env env(String name) {
        if (name.equals("example")) return ControlEvals.exampleEnv;
        if (name.equals("gap-aware")) return ControlEvals.gapAwareEnv();
        return ControlEvals.gapAwareEnv(name.substring("gap-aware:".length()));
    }

    /** A blue protocol that answers every decision from the recorded reference run, in order. */
    private static ControlEvals.Blue.Episode replay(Map<String, Object> rec) {
        List<Object> steps = l(rec.get("steps"));
        int[] i = {0};
        return new ControlEvals.Blue.Episode() {
            @Override public ControlEvals.Decision decide(Map<String, Object> action, long atMs) {
                Map<String, Object> s = m(steps.get(i[0]++));
                return new ControlEvals.Decision((String) s.get("outcome"), (String) s.get("caughtBy"), d(s.get("r")), (String) s.get("threat"), (String) s.get("reason"));
            }

            @Override public double moneyAmount(Map<String, Object> action) { return d(m(steps.get(i[0] - 1)).get("money")); }

            @Override public double endBudget() { return d(rec.get("endBudget")); }
        };
    }

    private static ControlEvals.Blue blue(Map<String, Object> spec, List<ControlEvals.Blue.Episode> episodes) {
        int[] k = {0};
        return new ControlEvals.Blue() {
            @Override public long startMs() { return (long) d(spec.get("startMs")); }

            @Override public long stepMs() { return (long) d(spec.get("stepMs")); }

            @Override public double analyticBound() { return d(spec.get("analyticBound")); }

            @Override public Episode newEpisode() { return episodes.get(k[0]++); }
        };
    }

    @Test void prng() throws Exception {
        OracleCases.each(M, "mulberry32", a -> {
            DoubleSupplier r = ControlEvals.mulberry32(d(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (int i = 0; i < (int) d(a.get(1)); i++) out.add(r.getAsDouble());
            return out;
        });
        OracleCases.each(M, "mixSeed", a -> ControlEvals.mixSeed(d(a.get(0)), d(a.get(1)), d(a.get(2))));
    }

    @Test void wilson() throws Exception {
        OracleCases.each(M, "wilsonLowerBound", a -> a.size() > 2 ? ControlEvals.wilsonLowerBound(d(a.get(0)), d(a.get(1)), d(a.get(2))) : ControlEvals.wilsonLowerBound(d(a.get(0)), d(a.get(1))));
    }

    @Test void gate() throws Exception {
        OracleCases.each(M, "assertControlGate", a -> { ControlEvals.assertControlGate(a.get(0), a.get(1)); return null; });
    }

    @Test void redPolicies() throws Exception {
        OracleCases.each(M, "redGen", a -> {
            ControlEvals.RedPolicy r = red((String) a.get(0));
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("name", r.name);
            o.put("strategy", r.strategy);
            o.put("actions", r.gen(new ControlEvals.GenContext(ControlEvals.exampleEnv, ControlEvals.mulberry32(1), 0)));
            return o;
        });
        OracleCases.each(M, "gapExploitCustom", a -> {
            ControlEvals.RedPolicy r = ControlEvals.gapExploitRed("file:x");
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("name", r.name);
            o.put("actions", r.gen(new ControlEvals.GenContext(ControlEvals.exampleEnv, ControlEvals.mulberry32(1), 0)));
            return o;
        });
        OracleCases.each(M, "redLists", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            List<Object> b = new ArrayList<>(), e = new ArrayList<>();
            for (ControlEvals.RedPolicy r : ControlEvals.BUILTIN_RED_POLICIES) b.add(r.strategy);
            for (ControlEvals.RedPolicy r : ControlEvals.EXAMPLE_RED_POLICIES) e.add(r.strategy);
            o.put("builtin", b);
            o.put("example", e);
            return o;
        });
        OracleCases.each(M, "exampleDlpPolicy", a -> ControlEvals.exampleDlpPolicy());
    }

    @Test void environments() throws Exception {
        OracleCases.each(M, "envJudge", a -> {
            Map<String, Object> c = m(a.get(2));
            List<Map<String, Object>> so = new ArrayList<>();
            for (Object x : l(c.get("allowedSoFar"))) so.add(m(x));
            return env((String) a.get(0)).unacceptableIfAllowed(m(a.get(1)), new ControlEvals.EnvContext(so, d(c.get("allowedSpend"))));
        });
    }

    @Test void episodes() throws Exception {
        OracleCases.each(M, "runEpisode", a -> {
            Map<String, Object> spec = m(a.get(0));
            List<ControlEvals.Blue.Episode> eps = new ArrayList<>();
            eps.add(replay(m(spec.get("recorded"))));
            return ControlEvals.runEpisode(red((String) spec.get("red")), blue(spec, eps), env((String) spec.get("env")), d(spec.get("seed")));
        });
    }

    @Test void evaluation() throws Exception {
        OracleCases.each(M, "controlEval", a -> {
            Map<String, Object> spec = m(a.get(0));
            List<ControlEvals.RedPolicy> reds = null;
            if (spec.get("reds") instanceof List) {
                reds = new ArrayList<>();
                for (Object n : l(spec.get("reds"))) reds.add(red((String) n));
            }
            List<ControlEvals.Blue.Episode> eps = new ArrayList<>();
            for (Object perRed : l(spec.get("recorded"))) for (Object rec : l(perRed)) eps.add(replay(m(rec)));
            return ControlEvals.controlEval(reds, blue(spec, eps), ControlEvals.exampleEnv.name().equals(spec.get("env")) ? ControlEvals.exampleEnv : env((String) spec.get("env")), spec.get("episodes"), spec.get("seed"));
        });
    }

    @Test void gateNamesTheViolationOfAThinSuite() {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("safetyLowerBound", new Json.Num("0.1"));
        report.put("usefulness", new Json.Num("1"));
        report.put("byStrategy", new LinkedHashMap<String, Object>());
        Map<String, Object> gate = new LinkedHashMap<>();
        gate.put("minSafetyLowerBound", new Json.Num("0.8"));
        gate.put("minUsefulness", new Json.Num("0.5"));
        gate.put("requiredStrategies", new ArrayList<Object>(List.of("replay")));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ControlEvals.assertControlGate(report, gate));
        assertEquals(true, e.getMessage().contains("required strategy 'replay' was not run"));
    }
}
