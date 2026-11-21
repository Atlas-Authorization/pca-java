package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import org.junit.jupiter.api.Test;

class IntentMapKitDiffTest {
    private static final String M = "ref-intent-map";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static Object deep(Object o) { return IntentJs.normalize(o); }

    private static void add(Map<String, Object> m, String key, double d) { m.put(key, new Json.Num(Long.toString((long) (IntentOmega.dbl(m.get(key)) + d)))); }

    private static byte[] secret(int seed) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte) ((seed + 7 * i) & 255);
        return b;
    }

    private static final List<Consumer<Map<String, Object>>> MUTS = List.of(
        m -> { },
        m -> add(mp(m.get("metrics")), "residual_risk_ppm", 5),
        m -> add(mp(ls(m.get("cells")).get(0)), "p_ppm", 3),
        m -> { Map<String, Object> c = mp(ls(m.get("cells")).get(0)); c.put("in_grant", !((Boolean) c.get("in_grant"))); },
        m -> m.put("grant_digest", "AAAA"),
        m -> { List<Object> o = ls(m.get("observations")); if (!o.isEmpty()) o.remove(o.size() - 1); },
        m -> m.put("kind", "x"),
        m -> m.put("principals", new ArrayList<Object>(List.of("a", "b"))),
        m -> { Map<String, Object> a = new LinkedHashMap<>(); a.put("rule", "unanimity"); m.put("aggregation", a); },
        m -> mp(m.get("metrics")).remove("log2_vs_mbits"),
        m -> add(mp(m.get("learner")), "eta_ppm", 100000),
        m -> add(mp(m.get("metrics")), "questions", 1),
        m -> { List<Object> c = ls(m.get("cells")); c.remove(c.size() - 1); },
        m -> mp(ls(mp(m.get("omega")).get("verbs")).get(0)).put("w", new Json.Num("5")),
        m -> mp(m.get("metrics")).put("log2_vs_mbits", null),
        m -> add(mp(ls(m.get("cells")).get(0)), "p_ppm", 2),
        m -> add(mp(ls(m.get("cells")).get(0)), "p_ppm", 1));

    private static List<Object> observations(Object o) { return ls(o); }

    private static Outcome outcome(Map<String, Object> x) { return IntentOmega.outcomeFromJson(x); }

    private static Object scenario(List<?> a) {
        Omega omega = IntentOmega.omegaFromJson(a.get(0));
        IntentLearner l = IntentMapKit.createLearner(omega, MapLearnerOptions.fromJson(a.get(1)));
        for (Object xo : observations(a.get(2))) {
            Map<String, Object> x = mp(xo);
            l.observe(outcome(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
        }
        String ref = (String) a.get(3);
        int seed = (int) IntentOmega.dbl(a.get(4));
        Map<String, Object> map = IntentMapKit.emitIntentMap(l, ref);
        List<Object> tampered = new ArrayList<>();
        for (Consumer<Map<String, Object>> f : MUTS) {
            Map<String, Object> copy = mp(deep(map));
            f.accept(copy);
            tampered.add(IntentMapKit.verifyIntentMap(copy));
        }
        tampered.add(IntentMapKit.verifyIntentMap(null));
        Map<String, Object> two = new LinkedHashMap<>();
        two.put("v", new Json.Num("2"));
        tampered.add(IntentMapKit.verifyIntentMap(two));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("map", map);
        out.put("digest", IntentMapKit.intentMapDigest(map));
        out.put("grantDigest", IntentMapKit.grantDigest(map.get("grant")));
        out.put("verify", IntentMapKit.verifyIntentMap(map));
        out.put("tampered", tampered);
        out.put("options", IntentMapKit.mapLearnerOptions(map).toJson());
        out.put("omegaRoundtrip", IntentMapKit.omegaToJSON(IntentMapKit.omegaFromJSON(map.get("omega"))));
        Map<String, Object> commit = new LinkedHashMap<>();
        try {
            IntentMapCommit.CommittedMap cm = IntentMapKit.commitIntentMap(map, secret(seed));
            commit.put("map_commit", cm.mapCommit);
            commit.put("size", (long) cm.size);
            commit.put("leaves", cm.leavesJson());
            List<Object> ds = new ArrayList<>();
            for (VerbSpace vs : omega.verbs) {
                double t = IntentOmega.verbCellCount(vs);
                for (double f : new double[] {0, Math.floor(t / 2), t - 1}) {
                    Outcome oc = IntentOmega.cellRep(vs, IntentOmega.decodeCell(vs, f));
                    Map<String, Object> params = new LinkedHashMap<>();
                    Object resource = null;
                    for (Map.Entry<String, Object> e : oc.values().entrySet()) {
                        if (e.getKey().equals("action.resource")) resource = e.getValue();
                        else params.put(e.getKey().substring("action.params.".length()), e.getValue());
                    }
                    ds.add(cm.disclose(vs.verb, resource, params));
                }
            }
            commit.put("disclosures", ds);
        } catch (RuntimeException e) {
            commit.clear();
            commit.put("error", true);
        }
        out.put("commit", commit);
        return out;
    }

    @Test void mapScenarios() throws Exception { OracleCases.each(M, "mapScenario", IntentMapKitDiffTest::scenario); }

    @Test void commitIntentMap() throws Exception {
        OracleCases.each(M, "commitIntentMap", a -> {
            IntentMapCommit.CommittedMap cm = IntentMapKit.commitIntentMap(a.get(0), secret(3));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("map_commit", cm.mapCommit);
            m.put("size", (long) cm.size);
            m.put("leaves", cm.leavesJson());
            return m;
        });
    }

    @Test void commitRejectsShortSecret() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> IntentMapCommit.commitMap(new ArrayList<>(), new LinkedHashMap<>(), new LinkedHashMap<>(), "x", new byte[31]));
    }

    @Test void grantDigest() throws Exception { OracleCases.each(M, "grantDigest", a -> IntentMapKit.grantDigest(a.get(0))); }

    @Test void intentMapDigest() throws Exception { OracleCases.each(M, "intentMapDigest", a -> IntentMapKit.intentMapDigest(a.get(0))); }

    @Test void omegaToJSON() throws Exception { OracleCases.each(M, "omegaToJSON", a -> IntentMapKit.omegaToJSON(IntentOmega.omegaFromJson(a.get(0)))); }

    @Test void omegaFromJSON() throws Exception { OracleCases.each(M, "omegaFromJSON", a -> IntentOmega.omegaToJson(IntentMapKit.omegaFromJSON(a.get(0)))); }

    @Test void divergence() throws Exception {
        OracleCases.each(M, "divergence", a -> {
            Omega omega = IntentOmega.omegaFromJson(a.get(0));
            IntentLearner l = IntentMapKit.createLearner(omega, MapLearnerOptions.fromJson(a.get(1)));
            for (Object xo : ls(a.get(2))) {
                Map<String, Object> x = mp(xo);
                l.observe(outcome(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
            }
            List<Object> out = new ArrayList<>();
            for (Object d : ls(a.get(3))) {
                Map<String, Object> dm = mp(d);
                out.add(IntentMapKit.applyDivergence(l, outcome(mp(dm.get("outcome"))), (int) IntentOmega.dbl(dm.get("y"))));
            }
            return out;
        });
    }
}
