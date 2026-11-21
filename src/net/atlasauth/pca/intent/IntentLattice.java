package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLayers.CeilingAdmitters;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The layered lattice over a task learner: deny anywhere wins (a cell outside a ceiling is denied with reason {@code ceiling} and is never a question),
 * the effective grant, the uncertain cells (the only cells ever asked about), the wallet-side decision for a concrete outcome, and an organisation layer
 * that is itself a learned map.
 */
public final class IntentLattice {
    private IntentLattice() {}

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add((double) x);
        return o;
    }

    private static VerbSpace verbOf(IntentLearner l, String verb) {
        for (VerbSpace v : l.omega.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    /** {effective, uncertain, ceiling}: cell keys {verb, cell} (ceiling ones with their layer) of the learner's cells under the ceilings. */
    public static Map<String, Object> latticeView(IntentLearner task, CeilingAdmitters ceilings) {
        List<Object> effective = new ArrayList<>(), uncertain = new ArrayList<>(), ceiling = new ArrayList<>();
        for (IntentLearner.CellView c : task.cells()) {
            VerbSpace vs = verbOf(task, c.verb);
            String layer = IntentLayers.ceilingOf(ceilings, vs, IntentOmega.cellRep(vs, c.cell));
            Map<String, Object> key = lm();
            key.put("verb", c.verb);
            key.put("cell", ints(c.cell));
            if (layer != null) {
                key.put("layer", layer);
                ceiling.add(key);
                continue;
            }
            if (c.vetoed) continue;
            if (c.inGrant) effective.add(key);
            else if (c.p > 1e-12 && c.p < task.tau - 1e-12) uncertain.add(key);
        }
        Map<String, Object> out = lm();
        out.put("effective", effective);
        out.put("uncertain", uncertain);
        out.put("ceiling", ceiling);
        return out;
    }

    /** The wallet-side decision for a concrete outcome against a task learner: {decision, layer?, by?}. */
    public static Map<String, Object> decideOutcomeLayers(IntentLearner task, CeilingAdmitters ceilings, Outcome o) {
        Map<String, Object> r = lm();
        VerbSpace vs = verbOf(task, o.verb());
        if (vs == null) { r.put("decision", "intent_denied"); return r; }
        String layer = IntentLayers.ceilingOf(ceilings, vs, o);
        if (layer != null) { r.put("decision", "ceiling"); r.put("layer", layer); return r; }
        if (task.isVetoed(o) || task.acceptance(o) <= 1e-12) { r.put("decision", "intent_denied"); return r; }
        if (task.admitsOutcome(o)) { r.put("decision", "admit"); r.put("by", 0.0); return r; }
        r.put("decision", "intent_required");
        return r;
    }

    /** An org layer that is itself a learned map over a shared space: the joint grant of the approvers' maps under the org's rule. Returns {map, policy}. */
    public static Map<String, Object> orgLayerFromMaps(List<Object> maps, Map<String, Object> rule) {
        Map<String, Object> map = IntentMultiAgg.aggregateIntentMaps(maps, rule, null);
        Map<String, Object> r = lm();
        r.put("map", map);
        r.put("policy", map.get("grant"));
        return r;
    }
}
