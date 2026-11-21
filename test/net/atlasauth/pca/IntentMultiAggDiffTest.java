package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentMultiAgg;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import org.junit.jupiter.api.Test;

class IntentMultiAggDiffTest {
    private static final String M = "ref-intent-multi-agg";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static Map<String, Object> buildMap(Object omega, Object mapOpts, Object observations, Object ref) {
        IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts));
        for (Object xo : ls(observations)) {
            Map<String, Object> x = mp(xo);
            l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
        }
        return IntentMapKit.emitIntentMap(l, (String) ref);
    }

    private static List<Object> maps(Object omega, Object principals, Object mapOpts) {
        List<Object> out = new ArrayList<>();
        for (Object p : ls(principals)) out.add(buildMap(omega, mapOpts, mp(p).get("observations"), mp(p).get("ref")));
        return out;
    }

    private static void add(Map<String, Object> m, String key, double d) { m.put(key, new Json.Num(Long.toString((long) (IntentOmega.dbl(m.get(key)) + d)))); }

    private static final List<Consumer<Map<String, Object>>> MUTS = List.of(
        m -> { },
        m -> add(mp(m.get("metrics")), "residual_risk_ppm", 7),
        m -> { Map<String, Object> c = mp(ls(m.get("cells")).get(0)); c.put("in_grant", !((Boolean) c.get("in_grant"))); },
        m -> m.put("aggregation", null),
        m -> { Map<String, Object> a = mp(m.get("aggregation")); a.put("rule", "quorum"); a.put("k", new Json.Num("1")); },
        m -> mp(m.get("aggregation")).put("vetoers", new ArrayList<Object>()));

    /** The oracle hands the reference its options object ({orgs?}), and the scenarios pass a bare ref-to-org map there, so the reference sees no orgs. */
    private static Map<String, Object> orgsOf(Object o) { return o == null || mp(o).get("orgs") == null ? new LinkedHashMap<>() : mp(mp(o).get("orgs")); }

    @Test void aggregateScenario() throws Exception {
        OracleCases.each(M, "aggregateScenario", a -> {
            List<Object> ms = maps(a.get(0), a.get(1), a.get(4));
            Map<String, Object> rule = mp(a.get(2));
            Map<String, Object> orgs = orgsOf(a.get(3));
            Map<String, Object> agg = IntentMultiAgg.aggregateIntentMaps(ms, rule, orgs);
            List<Object> tampered = new ArrayList<>();
            for (Consumer<Map<String, Object>> f : MUTS) {
                Map<String, Object> copy = mp(IntentJs.normalize(agg));
                f.accept(copy);
                tampered.add(IntentMultiAgg.verifyAggregate(copy, ms, orgs));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("aggregate", agg);
            out.put("digest", IntentMapKit.intentMapDigest(agg));
            out.put("rule", IntentMultiAgg.ruleOf(agg));
            out.put("verify", IntentMultiAgg.verifyAggregate(agg, ms, orgs));
            out.put("tampered", tampered);
            out.put("wrongInputs", IntentMultiAgg.verifyAggregate(agg, new ArrayList<>(ms.subList(0, Math.max(0, ms.size() - 1))), orgs));
            out.put("combined", "unanimity".equals(rule.get("kind")) && !rule.containsKey("vetoers") ? IntentMultiAgg.combineIntentMaps(ms, orgs) : null);
            return out;
        });
    }

    @Test void aggregateTwoOmegas() throws Exception {
        OracleCases.each(M, "aggregateTwoOmegas", a -> {
            List<Object> ps = ls(a.get(2));
            List<Object> ms = new ArrayList<>();
            ms.add(buildMap(a.get(0), null, mp(ps.get(0)).get("observations"), mp(ps.get(0)).get("ref")));
            ms.add(buildMap(a.get(1), null, new ArrayList<>(), mp(ps.get(1)).get("ref")));
            return IntentMultiAgg.aggregateIntentMaps(ms, mp(a.get(3)), null);
        });
    }

    @Test void aggregateOfAggregate() throws Exception {
        OracleCases.each(M, "aggregateOfAggregate", a -> {
            List<Object> ms = maps(a.get(0), a.get(1), null);
            Map<String, Object> agg = IntentMultiAgg.aggregateIntentMaps(ms, mp(a.get(2)), null);
            List<Object> two = new ArrayList<>();
            two.add(agg);
            two.add(ms.get(0));
            return IntentMultiAgg.aggregateIntentMaps(two, mp(a.get(2)), null);
        });
    }

    @Test void liftOfAggregate() throws Exception {
        OracleCases.each(M, "liftOfAggregate", a -> {
            List<Object> ms = maps(a.get(0), a.get(1), null);
            Map<String, Object> agg = IntentMultiAgg.aggregateIntentMaps(ms.subList(0, 1), mp(a.get(2)), null);
            return IntentMultiAgg.liftIntentMap(agg, IntentOmega.omegaFromJson(a.get(0)));
        });
    }

    @Test void crossScenario() throws Exception {
        OracleCases.each(M, "crossScenario", a -> {
            List<Object> ms = new ArrayList<>();
            for (Object s : ls(a.get(0))) {
                Map<String, Object> sp = mp(s);
                ms.add(buildMap(sp.get("omega"), sp.get("mapOpts"), sp.get("observations"), sp.get("ref")));
            }
            Map<String, Object> rule = mp(a.get(1));
            Map<String, Object> orgs = orgsOf(a.get(2));
            IntentMultiAgg.CrossOrg r = IntentMultiAgg.crossOrgAggregate(ms, rule, orgs);
            List<Object> tampered = new ArrayList<>();
            for (Consumer<Map<String, Object>> f : MUTS) {
                Map<String, Object> copy = mp(IntentJs.normalize(r.aggregate));
                f.accept(copy);
                tampered.add(IntentMultiAgg.verifyCrossOrgAggregate(copy, ms, orgs));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("aggregate", r.aggregate);
            out.put("lifted", r.lifted);
            out.put("omega", IntentOmega.omegaToJson(r.omega));
            out.put("digest", IntentMapKit.intentMapDigest(r.aggregate));
            out.put("verify", IntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, ms, orgs));
            out.put("tampered", tampered);
            out.put("wrong", IntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, new ArrayList<>(ms.subList(Math.min(1, ms.size()), ms.size())), orgs));
            return out;
        });
    }

    @Test void liftScenario() throws Exception {
        OracleCases.each(M, "liftScenario", a -> {
            Map<String, Object> map = buildMap(a.get(0), a.get(1), a.get(2), a.get(3));
            Omega target = IntentOmega.omegaFromJson(a.get(4));
            return IntentMultiAgg.liftIntentMap(map, target);
        });
    }

    @Test void omegaKey() throws Exception { OracleCases.each(M, "omegaKey", a -> IntentMultiAgg.omegaKey(IntentOmega.omegaFromJson(a.get(0)))); }
}
