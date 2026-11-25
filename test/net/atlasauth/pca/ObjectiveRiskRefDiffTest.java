package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The objective risk functional against the reference corpus (ref-objective-risk, 4052 cases, 27 functions): canonical action, inverse registry and
 * reversibility, resource graph and blast radius, native and BYO embedders, goal commitment and distance, split-conformal calibration, harm currency,
 * the composed risk and the dispute-game oracle. A graph with a non-finite harm weight and a calibration set with a non-finite score cannot be digested:
 * the reference throws there and so must the native.
 */
class ObjectiveRiskRefDiffTest {
    static final String MODULE = "ref-objective-risk";
    static final int TOTAL = 4052;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

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

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    // ---- the specs of the objects the reference builds ----

    private static ObjectiveRisk.InMemoryInverseRegistry registry(Object sO) {
        Map<String, Object> s = m(sO);
        List<String> trusted = new ArrayList<>();
        if (s.get("trusted") != null) for (Object t : l(s.get("trusted"))) trusted.add((String) t);
        ObjectiveRisk.InMemoryInverseRegistry r = new ObjectiveRisk.InMemoryInverseRegistry(trusted);
        if (s.get("entries") != null) for (Object e : l(s.get("entries"))) r.register((String) l(e).get(0), m(l(e).get(1)));
        return r;
    }

    private static ObjectiveRisk.ResourceGraph graph(Object sO) {
        Map<String, Object> s = m(sO);
        ObjectiveRisk.ResourceGraph g = new ObjectiveRisk.ResourceGraph();
        if (s.get("nodes") != null) for (Object n : l(s.get("nodes"))) g.addNode(m(n));
        if (s.get("edges") != null) for (Object e : l(s.get("edges"))) g.addEdge(m(e));
        return g;
    }

    private static ObjectiveRisk.Embedder embedder(Object esO) {
        Map<String, Object> es = m(esO);
        String scheme = (String) es.get("scheme");
        if ("native".equals(scheme)) return ObjectiveRisk.nativeHashEmbedder(es.get("config"));
        if ("fixed".equals(scheme)) {
            String id = (String) es.get("modelId");
            Object config = es.get("config"), vector = es.get("vector");
            double dims = dbl(es.get("dims"));
            return new ObjectiveRisk.Embedder() {
                @Override public String modelId() { return id; }
                @Override public Object config() { return config; }
                @Override public double dims() { return dims; }
                @Override public Object embed(Map<String, Object> a) { return vector; }
            };
        }
        return byo(es.get("descriptor"), (String) es.get("claimedModelId"), es.get("infer"));
    }

    private static ObjectiveRisk.Embedder byo(Object descriptor, String claimed, Object inferO) {
        Map<String, Object> i = m(inferO);
        double dims = descriptor instanceof Map ? dbl(m(descriptor).get("dims")) : Double.NaN;
        return ObjectiveRisk.byoEmbedder(descriptor, j -> {
            if (Boolean.TRUE.equals(i.get("throws"))) throw new RuntimeException("infer boom");
            if (Boolean.TRUE.equals(i.get("notArray"))) return "x";
            if (Boolean.TRUE.equals(i.get("byLen"))) {
                List<Object> v = new ArrayList<>();
                for (int k = 0; k < (int) dims; k++) v.add((long) (j.length() + k));
                return v;
            }
            return i.get("vector");
        }, claimed);
    }

    private static ObjectiveRisk.Context ctx(Object cO) {
        Map<String, Object> c = m(cO);
        ObjectiveRisk.Context x = new ObjectiveRisk.Context();
        x.registry = registry(c.get("registry"));
        Set<String> kinds = new HashSet<>();
        for (Object k : l(c.get("authorizedKinds"))) kinds.add((String) k);
        x.authorizedKinds = kinds;
        x.graph = graph(c.get("graph"));
        x.scope = Zk.truthy(c.get("scope")) ? m(c.get("scope")) : null;
        x.embedder = embedder(c.get("embedder"));
        x.goal = c.get("goal");
        x.commitments = m(c.get("commitments"));
        x.denominations = l(c.get("denominations"));
        x.weights = m(c.get("weights"));
        x.taint = c.get("taint");
        x.age = c.get("age");
        x.attestedUncertainty = c.get("attestedUncertainty");
        x.calibration = Zk.truthy(c.get("calibration")) ? l(c.get("calibration")) : null;
        return x;
    }

    private static Map<String, Object> scope(Object s) { return m(s); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ca(Object o) { return (Map<String, Object>) o; }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("METRIC", ObjectiveRisk.METRIC);
            out.put("DEFAULT_EPSILON", ObjectiveRisk.DEFAULT_EPSILON);
            out.put("NATIVE_SCHEME", ObjectiveRisk.NATIVE_SCHEME);
            out.put("DEFAULT_MAX_PARAM_LEAVES", ObjectiveRisk.DEFAULT_MAX_PARAM_LEAVES);
            out.put("DEFAULT_NATIVE_CONFIG", ObjectiveRisk.defaultNativeConfig());
            return out;
        });
        f.put("canonicalAction", x -> enc(ObjectiveRisk.canonicalAction(nums(x.get(0)))));
        f.put("canonicalActionJson", x -> ObjectiveRisk.canonicalActionJson(nums(x.get(0))));
        f.put("canonicalActionDigest", x -> ObjectiveRisk.canonicalActionDigest(nums(x.get(0))));
        f.put("registryOps", x -> {
            List<String> trusted = new ArrayList<>();
            for (Object t : l(x.get(0))) trusted.add((String) t);
            ObjectiveRisk.InMemoryInverseRegistry r = new ObjectiveRisk.InMemoryInverseRegistry(trusted);
            List<Object> out = new ArrayList<>();
            for (Object o : l(x.get(1))) {
                List<Object> op = l(o);
                switch ((String) op.get(0)) {
                    case "register": r.register((String) op.get(1), m(op.get(2))); out.add(null); break;
                    case "lookup": out.add(r.lookup(op.get(1))); break;
                    case "trustedVerifiers": out.add(new ArrayList<Object>(r.trustedVerifiers())); break;
                    default: out.add(r.digest());
                }
            }
            return out;
        });
        f.put("registryDigest", x -> registry(x.get(0)).digest());
        f.put("reversibility", x -> {
            Set<String> kinds = new HashSet<>();
            for (Object k : l(x.get(2))) kinds.add((String) k);
            return ObjectiveRisk.reversibility(x.get(0), registry(x.get(1)), kinds);
        });
        f.put("graphBuild", x -> {
            ObjectiveRisk.ResourceGraph g = graph(x.get(0));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("size", g.size());
            out.put("digest", g.digest());
            return out;
        });
        f.put("graphReachable", x -> new ArrayList<Object>(graph(x.get(0)).reachable(x.get(1), scope(nums(x.get(2))))));
        f.put("graphNode", x -> graph(x.get(0)).node(x.get(1)));
        f.put("blastRadius", x -> enc(ObjectiveRisk.blastRadius(x.get(0), graph(x.get(1)), scope(nums(x.get(2))))));
        f.put("nativeEmbed", x -> {
            ObjectiveRisk.Embedder e = ObjectiveRisk.nativeHashEmbedder(x.get(0));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("modelId", e.modelId());
            out.put("dims", e.dims());
            out.put("config", e.config());
            out.put("vector", e.embed(ca(x.get(1))));
            return out;
        });
        f.put("byoModelId", x -> ObjectiveRisk.byoModelId(nums(x.get(0))));
        f.put("byoEmbed", x -> {
            ObjectiveRisk.Embedder e = byo(x.get(0), (String) x.get(1), x.get(2));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("modelId", e.modelId());
            out.put("dims", e.dims());
            out.put("vector", e.embed(ca(x.get(3))));
            return out;
        });
        f.put("validateVector", x -> {
            List<Object> out = new ArrayList<>();
            for (long v : ObjectiveRisk.validateVector(nums(x.get(0)), dbl(nums(x.get(1))))) out.add(v);
            return out;
        });
        f.put("conformanceCheck", x -> ObjectiveRisk.conformanceCheck(embedder(x.get(0)), l(x.get(1))));
        f.put("commitGoal", x -> enc(ObjectiveRisk.commitGoal(embedder(x.get(0)), nums(x.get(1)), x.get(2))));
        f.put("verifyGoalCommitment", x -> ObjectiveRisk.verifyGoalCommitment(nums(x.get(0)), embedder(x.get(1))));
        f.put("vectorDistance", x -> ObjectiveRisk.vectorDistance(l(nums(x.get(0))), l(nums(x.get(1))), nums(x.get(2))));
        f.put("committedDistanceChecked", x -> enc(ObjectiveRisk.committedDistanceChecked(ca(x.get(0)), nums(x.get(1)), embedder(x.get(2)))));
        f.put("committedDistance", x -> ObjectiveRisk.committedDistance(nums(x.get(0)), nums(x.get(1)), embedder(x.get(2))));
        f.put("calibrate", x -> ObjectiveRisk.calibrate(nums(x.get(0)), l(nums(x.get(1)))));
        f.put("conformalThreshold", x -> enc(ObjectiveRisk.conformalThreshold(l(nums(x.get(0))), nums(x.get(1)))));
        f.put("calibrationDigest", x -> ObjectiveRisk.calibrationDigest(l(nums(x.get(0)))));
        f.put("harmReport", x -> ObjectiveRisk.harmReport(nums(x.get(0)), l(nums(x.get(1)))));
        f.put("objectiveRisk", x -> enc(ObjectiveRisk.objectiveRisk(nums(x.get(0)), ctx(nums(x.get(1))))));
        f.put("objectiveRiskOracle", x -> enc(ObjectiveRisk.objectiveRiskOracle(ctx(nums(x.get(0)))).resolve(x.get(1), x.get(2))));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        // every argument is read through the corpus' non-finite spelling and every result is written back in it
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), x -> enc(e.getValue().apply((List<?>) nums(x))));
    }
}
