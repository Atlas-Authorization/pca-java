package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Dimensions beyond the action's own parameters: world state (an observed quantity such as slack against an optimum),
 * argument provenance, and classifier labels. Each lives under its own path prefix; an outcome is lifted onto them from an
 * environment of observed values.
 */
public final class IntentWorld {
    private IntentWorld() {}

    public static final String WORLD_PREFIX = "env.world.";
    public static final String PROV_PREFIX = "env.prov.";
    public static final String CLASS_PREFIX = "env.class.";

    /** A numeric world dimension; {@code cuts} may be null, {@code dist} null = uniform. */
    public static NumDim worldDim(String name, double lo, double hi, Collection<Double> cuts, String dist) {
        Set<Double> uniq = new LinkedHashSet<>();
        if (cuts != null) for (double c : cuts) uniq.add(c + 0.0);
        List<Double> kept = new ArrayList<>();
        for (double c : uniq) if (c >= lo && c <= hi) kept.add(c);
        return new NumDim(WORLD_PREFIX + name, lo, hi, IntentOmega.toArray(IntentOmega.sortedNums(kept)), dist != null ? dist : "uniform");
    }

    /** Excess over an optimum: cut at 0 and at each slack, log-uniform. */
    public static NumDim excessDim(String name, double hi, List<Double> slacks) {
        List<Double> cuts = new ArrayList<>();
        cuts.add(0.0);
        if (slacks != null) cuts.addAll(slacks);
        return worldDim(name, 0, hi, cuts, "loguniform");
    }

    /** The condition "the observed quantity is at most the slack". */
    public static Map<String, Object> optimalityCondition(String name, double slack) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("field", WORLD_PREFIX + name);
        m.put("op", "lte");
        m.put("value", new Json.Num(net.atlasauth.pca.AttestCommon.jsNumString(slack)));
        return m;
    }

    public static CatDim provenanceDim(String paramPath) {
        List<CatValue> v = new ArrayList<>();
        v.add(new CatValue("exact", "first_party"));
        v.add(new CatValue("exact", "trusted"));
        v.add(new CatValue("other", IntentOmega.OTHER));
        return new CatDim(PROV_PREFIX + paramPath, v);
    }

    public static CatDim classifierDim(String id, List<String> labels) {
        TreeSet<String> sorted = new TreeSet<>(net.atlasauth.pca.IntentJs::compareUtf8);
        sorted.addAll(labels);
        List<CatValue> v = new ArrayList<>();
        for (String l : sorted) v.add(new CatValue("exact", l));
        v.add(new CatValue("other", IntentOmega.OTHER));
        return new CatDim(CLASS_PREFIX + id, v);
    }

    /** The space with {@code dims} added to one verb (a duplicate path throws), dimensions re-sorted by path. */
    public static Omega withDims(Omega omega, String verb, List<Dim> dims) {
        List<VerbSpace> verbs = new ArrayList<>();
        boolean found = false;
        for (VerbSpace vs : omega.verbs) {
            if (!vs.verb.equals(verb)) {
                verbs.add(new VerbSpace(vs.verb, vs.reversibility, vs.weight, new ArrayList<>(vs.dims)));
                continue;
            }
            found = true;
            Set<String> have = new LinkedHashSet<>();
            for (Dim d : vs.dims) have.add(d.path);
            for (Dim d : dims) if (have.contains(d.path)) throw new IllegalArgumentException("withDims: " + verb + " already has a dimension " + d.path);
            List<Dim> all = new ArrayList<>(vs.dims);
            all.addAll(dims);
            all.sort((a, b) -> a.path.compareTo(b.path));
            verbs.add(new VerbSpace(vs.verb, vs.reversibility, vs.weight, all));
        }
        if (!found) throw new IllegalArgumentException("withDims: no verb " + verb + " in the space");
        return new Omega(verbs, omega.approximate);
    }

    private static Object get(Object root, String... segs) {
        Object cur = root;
        for (String s : segs) {
            if (!(cur instanceof Map) || !((Map<?, ?>) cur).containsKey(s)) return null;
            cur = ((Map<?, ?>) cur).get(s);
        }
        return cur;
    }

    /** Lift an outcome onto the world / provenance / classifier dimensions from the environment {world?, prov?, class?}. */
    public static Outcome liftOutcome(Outcome o, Map<String, Object> env, List<String> dimPaths) {
        Map<String, Object> values = new LinkedHashMap<>(o.values());
        for (String p : dimPaths) {
            if (p.startsWith(WORLD_PREFIX)) {
                Object v = get(env.get("world"), p.substring(WORLD_PREFIX.length()));
                if (IntentOmega.isNumber(v)) values.put(p, IntentOmega.dbl(v));
                else if (v instanceof String) values.put(p, v);
            } else if (p.startsWith(PROV_PREFIX)) {
                Object v = get(env.get("prov"), p.substring(PROV_PREFIX.length()).split("\\.", -1));
                values.put(p, v instanceof String ? v : "agent");
            } else if (p.startsWith(CLASS_PREFIX)) {
                Object v = get(env.get("class"), p.substring(CLASS_PREFIX.length()));
                if (v instanceof String) values.put(p, v);
            }
        }
        return new Outcome(o.verb(), values);
    }
}
