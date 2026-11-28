package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.analyzer.Analyzer;
import net.atlasauth.pca.analyzer.CaveatAnalysis;
import net.atlasauth.pca.analyzer.Constitution;
import net.atlasauth.pca.analyzer.Coverage;
import net.atlasauth.pca.analyzer.DagExposure;
import net.atlasauth.pca.analyzer.Enumerate;
import net.atlasauth.pca.analyzer.Exposure;
import net.atlasauth.pca.analyzer.Field;
import net.atlasauth.pca.analyzer.Filter;
import net.atlasauth.pca.analyzer.Flip;
import net.atlasauth.pca.analyzer.Narrowing;
import net.atlasauth.pca.analyzer.Residual;
import net.atlasauth.pca.analyzer.TestRunner;
import net.atlasauth.pca.analyzer.Validate;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the policy analyzer (see the oracle header for the case shapes and the porting table). */
class AnalyzerDiffTest {
    private static final String MODULE = "ref-analyzer";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static Object at(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }
    private static Map<String, Object> opt(List<?> a, int i) { Object o = at(a, i); return o instanceof Map ? m(o) : null; }
    private static Map<String, Object> obj(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }

    private static final Map<String, Keys.EdKey> KEYS = new HashMap<>();

    /** The key of a label: seed = sha256("atlas-pca-conformance/" + label). */
    private static synchronized Keys.EdKey key(String label) throws Exception {
        Keys.EdKey k = KEYS.get(label);
        if (k == null) {
            k = Keys.edFromSeed(MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)));
            KEYS.put(label, k);
        }
        return k;
    }

    /** "$key:LABEL" stands for the public key of LABEL. */
    private static String keyed(Object v) throws Exception {
        if (v instanceof String && ((String) v).startsWith("$key:")) return key(((String) v).substring(5)).id();
        return (String) v;
    }

    /** The reference's {"$num": "Infinity"} spelling of a non-finite number, and the inverse. */
    private static Object out(Object v) {
        if (v instanceof Json.Num || v instanceof Double) {
            double d = v instanceof Double ? (Double) v : Double.parseDouble(((Json.Num) v).raw);
            if (Double.isNaN(d) || Double.isInfinite(d)) return obj("$num", Double.isNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity");
            return v;
        }
        if (v instanceof Map) { Map<String, Object> r = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(v).entrySet()) r.put(e.getKey(), out(e.getValue())); return r; }
        if (v instanceof List) { List<Object> r = new ArrayList<>(); for (Object x : l(v)) r.add(out(x)); return r; }
        return v;
    }

    private static Object revive(Object v) {
        if (v instanceof Map && m(v).size() == 1 && m(v).get("$num") instanceof String) return new Json.Num((String) m(v).get("$num"));
        if (v instanceof Map) { Map<String, Object> r = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(v).entrySet()) r.put(e.getKey(), revive(e.getValue())); return r; }
        if (v instanceof List) { List<Object> r = new ArrayList<>(); for (Object x : l(v)) r.add(revive(x)); return r; }
        return v;
    }

    private static void each(String fn, OracleCases.Fn f) throws Exception { OracleCases.each(MODULE, fn, a -> out(f.apply(a))); }

    private static Field.NumInterval iv(Object o) {
        if (o == null) return Field.FULL_INTERVAL;
        Map<String, Object> x = m(o);
        return new Field.NumInterval(OracleCases.num(x.get("lo")), Boolean.TRUE.equals(x.get("loInclusive")), OracleCases.num(x.get("hi")), Boolean.TRUE.equals(x.get("hiInclusive")));
    }

    // ---- pure pieces ----

    @Test void analyzeCaveats() throws Exception { each("analyzeCaveats", a -> CaveatAnalysis.analyzeCaveats(a.get(0)).toJson()); }
    @Test void numericConjunctionSatisfiable() throws Exception { each("numericConjunctionSatisfiable", a -> Field.numericConjunctionSatisfiable(l(a.get(0)))); }
    @Test void predicateNumericSatisfiable() throws Exception { each("predicateNumericSatisfiable", a -> Analyzer.predicateNumericSatisfiable(a.get(0))); }
    @Test void tightenInterval() throws Exception { each("tightenInterval", a -> Field.tightenInterval(iv(a.get(0)), a.get(1), a.get(2)).toJson()); }
    @Test void intervalEmpty() throws Exception { each("intervalEmpty", a -> Field.intervalEmpty(iv(a.get(0)))); }
    @Test void fieldProbes() throws Exception { each("fieldProbes", a -> Field.fieldProbes(l(a.get(0)))); }
    @Test void vetoesFromConstitution() throws Exception { each("vetoesFromConstitution", a -> Constitution.vetoesFromConstitution(a.get(0))); }
    @Test void toModel() throws Exception { each("toModel", a -> Enumerate.toModel(a.get(0)).toJson()); }

    private static Enumerate.Probes probesOf(Object inO) {
        Map<String, Object> in = m(inO);
        Enumerate.ProbeInputs pi = new Enumerate.ProbeInputs();
        for (Object s : l(in.get("predicateSets"))) pi.predicateSets.add(l(s));
        if (in.get("extraVerbs") != null) pi.extraVerbs.addAll(l(in.get("extraVerbs")));
        if (in.get("extraResources") != null) pi.extraResources.addAll(l(in.get("extraResources")));
        if (in.get("extraFieldConditions") != null) for (Object c : l(in.get("extraFieldConditions"))) pi.extraFieldConditions.add(new Object[] {m(c).get("path"), m(c).get("cond")});
        pi.varyReversibility = Boolean.TRUE.equals(in.get("varyReversibility"));
        return Enumerate.collectProbes(pi);
    }

    @Test void collectProbes() throws Exception {
        each("collectProbes", a -> {
            Enumerate.Probes p = probesOf(a.get(0));
            List<Object> fields = new ArrayList<>();
            for (Enumerate.FieldProbe f : p.fields) {
                List<Object> vals = new ArrayList<>();
                for (Object v : f.values) vals.add(v == Enumerate.ABSENT ? obj("$absent", true) : v);
                fields.add(obj("path", f.path, "values", vals));
            }
            return obj("verbs", new ArrayList<Object>(p.verbs), "resources", new ArrayList<Object>(p.resources), "revClasses", new ArrayList<Object>(p.revClasses), "fields", fields);
        });
    }

    @Test void representatives() throws Exception {
        each("representatives", a -> {
            Enumerate.Probes p = probesOf(a.get(0));
            if (Enumerate.productSize(p) > 400) throw new IllegalStateException("grid too large for the corpus");
            List<Object> out = new ArrayList<>();
            for (Enumerate.Rep r : Enumerate.representatives(p)) {
                Map<String, Object> rep = obj("verb", r.verb, "resource", r.resource);
                if (r.revClass != null) rep.put("revClass", r.revClass);
                rep.put("assignments", new LinkedHashMap<>(r.assignments));
                rep.put("action", Enumerate.repToAction(r));
                out.add(rep);
            }
            return out;
        });
    }

    // ---- concrete decisions ----

    @Test void decideAction() throws Exception { each("decideAction", a -> Enumerate.decideAction(Enumerate.toModel(a.get(0)), a.get(1))); }
    @Test void admitsConcrete() throws Exception { each("admitsConcrete", a -> Analyzer.admitsConcrete(a.get(0), m(a.get(1)))); }
    @Test void witnessOf() throws Exception { each("witnessOf", a -> Coverage.witnessOf(Enumerate.toModel(a.get(0)), m(a.get(1)))); }

    @Test void vetoApplies() throws Exception {
        each("vetoApplies", a -> {
            Map<String, Object> x = new LinkedHashMap<>(m(a.get(1)));
            if (!x.containsKey("params")) x.put("params", obj());
            Object subject = m(a.get(1)).get("subject") == null ? obj() : m(a.get(1)).get("subject");
            Object env = m(a.get(1)).get("env") == null ? obj() : m(a.get(1)).get("env");
            return Enumerate.vetoApplies(a.get(0), obj("action", x, "subject", subject, "env", env));
        });
    }

    // ---- reachable, vacuity, relations, intent ----

    @Test void reachable() throws Exception { each("reachable", a -> Analyzer.reachable(a.get(0), opt(a, 1), opt(a, 2))); }
    @Test void alwaysDenies() throws Exception { each("alwaysDenies", a -> Analyzer.alwaysDenies(a.get(0), (String) a.get(1), opt(a, 2))); }
    @Test void alwaysAllows() throws Exception { each("alwaysAllows", a -> Analyzer.alwaysAllows(a.get(0), (String) a.get(1), opt(a, 2))); }
    @Test void subsumes() throws Exception { each("subsumes", a -> Analyzer.subsumes(a.get(0), a.get(1), opt(a, 2))); }
    @Test void disjoint() throws Exception { each("disjoint", a -> Analyzer.disjoint(a.get(0), a.get(1), opt(a, 2))); }
    @Test void equivalent() throws Exception { each("equivalent", a -> Analyzer.equivalent(a.get(0), a.get(1), opt(a, 2))); }
    @Test void intentConformance() throws Exception { each("intentConformance", a -> Analyzer.intentConformance(a.get(0), opt(a, 1), opt(a, 2))); }

    // ---- exposure ----

    @Test void thresholdsOf() throws Exception { each("thresholdsOf", a -> Exposure.thresholdsOf(Enumerate.toModel(a.get(0)), (String) a.get(1))); }
    @Test void maxExposure() throws Exception { each("maxExposure", a -> Exposure.maxExposure(a.get(0), opt(a, 1))); }
    @Test void escalationSurface() throws Exception { each("escalationSurface", a -> Exposure.escalationSurface(a.get(0), opt(a, 1))); }
    @Test void delegationEnvelope() throws Exception { each("delegationEnvelope", a -> Exposure.delegationEnvelope(l(a.get(0)), opt(a, 1))); }
    @Test void diffPolicies() throws Exception { each("diffPolicies", a -> Exposure.diffPolicies(a.get(0), a.get(1), opt(a, 2))); }
    @Test void diffGate() throws Exception { each("diffGate", a -> Exposure.diffGate(m(revive(a.get(0))), opt(a, 1))); }

    @Test void findWithBackend() throws Exception {
        each("findWithBackend", a -> {
            Map<String, Object> spec = m(a.get(1));
            Exposure.WitnessBackend backend = new Exposure.WitnessBackend() {
                @Override public String name() { return (String) spec.get("name"); }
                @Override public Map<String, Object> find(Map<String, Object> q) { return m(spec.get("result")); }
            };
            return Exposure.findWithBackend(backend, m(a.get(0)));
        });
    }

    @Test void dagExposure() throws Exception { each("dagExposure", a -> DagExposure.dagExposure(m(a.get(0)))); }

    // ---- residual, discovery, filters ----

    @Test void residual() throws Exception { each("residual", a -> Residual.residual(a.get(0), opt(a, 1), opt(a, 2))); }
    @Test void residualPolicy() throws Exception { each("residualPolicy", a -> Residual.residualPolicy(m(a.get(0)))); }
    @Test void evaluateResidual() throws Exception { each("evaluateResidual", a -> Residual.evaluateResidual(m(a.get(0)), m(a.get(1)))); }
    @Test void whatMayIDo() throws Exception { each("whatMayIDo", a -> Residual.whatMayIDo(a.get(0), l(a.get(1)), opt(a, 2), opt(a, 3))); }
    @Test void toFilter() throws Exception { each("toFilter", a -> Filter.toFilter(Residual.residual(a.get(0), opt(a, 1), opt(a, 2)), opt(a, 3))); }
    @Test void toUcast() throws Exception { each("toUcast", a -> Filter.toUcast(m(a.get(0)))); }
    @Test void evalFilter() throws Exception { each("evalFilter", a -> Filter.evalFilter(m(a.get(0)), m(a.get(1)))); }
    @Test void evalUcast() throws Exception { each("evalUcast", a -> Filter.evalUcast(m(a.get(0)), m(a.get(1)))); }

    // ---- narrowing, coverage, flip, validation, tests ----

    @Test void suggestNarrowing() throws Exception { each("suggestNarrowing", a -> Narrowing.suggestNarrowing(a.get(0), l(a.get(1)), opt(a, 2))); }

    @Test void signAccessRequest() throws Exception {
        each("signAccessRequest", a -> Narrowing.signAccessRequest(m(a.get(0)), key((String) a.get(1)), key((String) a.get(1)).id()));
    }

    @Test void verifyAccessRequest() throws Exception { each("verifyAccessRequest", a -> Narrowing.verifyAccessRequest(a.get(0), keyed(at(a, 1)))); }
    @Test void coverage() throws Exception { each("coverage", a -> Coverage.coverage(a.get(0), l(a.get(1)), opt(a, 2))); }
    @Test void coverageGate() throws Exception { each("coverageGate", a -> Coverage.coverageGate(m(a.get(0)), opt(a, 1))); }
    @Test void minimalFlip() throws Exception { each("minimalFlip", a -> Flip.minimalFlip(a.get(0), opt(a, 1), opt(a, 2))); }
    @Test void verbShapes() throws Exception { each("verbShapes", a -> Validate.verbShapes(a.get(0))); }
    @Test void verbShapesFromActionDefs() throws Exception { each("verbShapesFromActionDefs", a -> Validate.verbShapesFromActionDefs(l(a.get(0)))); }
    @Test void validatePolicyAgainstSchema() throws Exception { each("validatePolicyAgainstSchema", a -> Validate.validatePolicyAgainstSchema(a.get(0), a.get(1), opt(a, 2))); }
    @Test void policyTestsDoc() throws Exception { each("policyTestsDoc", a -> TestRunner.policyTestsDoc(a.get(0), l(a.get(1)))); }
    @Test void runPolicyTests() throws Exception { each("runPolicyTests", a -> TestRunner.runPolicyTests(a.get(0), m(a.get(1)), opt(a, 2) != null && Boolean.TRUE.equals(opt(a, 2).get("requireDigest")))); }
    @Test void generateBoundaryTests() throws Exception { each("generateBoundaryTests", a -> TestRunner.generateBoundaryTests(a.get(0), opt(a, 1))); }
    @Test void decideAll() throws Exception { each("decideAll", a -> TestRunner.decideAll(a.get(0), m(a.get(1)))); }
    @Test void signPolicyTests() throws Exception { each("signPolicyTests", a -> TestRunner.signPolicyTests(m(a.get(0)), key((String) a.get(1)), key((String) a.get(1)).id())); }
    @Test void verifyPolicyTests() throws Exception { each("verifyPolicyTests", a -> TestRunner.verifyPolicyTests(a.get(0), keyed(a.get(1)))); }
}
