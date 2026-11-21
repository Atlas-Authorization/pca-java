package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;

/**
 * The facts the default provenance gate reads, derived from signed action defs. "Unconfirmed means maximally dangerous": a def without a
 * valid signed confirmation reports no effects and the top trait set, and its {@code provenance_min} relaxations are ignored.
 */
public final class ActionProvenance {
    private ActionProvenance() {}

    /** The gate facts of one def under a trait registry: {@code {effects, traits, params?}}. */
    public static Map<String, Object> provenanceInfoOf(Map<String, Object> d, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        List<String> traits = ActionEffective.traitsOf(d, reg, attestationVerified);
        if (!ActionEffective.isConfirmed(d, attestationVerified)) return J.obj("effects", new ArrayList<>(), "traits", J.objs(traits));
        Map<String, Object> n = Actions.normalize(d);
        Map<String, Object> params = new LinkedHashMap<>();
        for (Map.Entry<String, Object> p : J.m(n.get("params")).entrySet()) if (J.get(p.getValue(), "provenance_min") != null) params.put(p.getKey(), J.get(p.getValue(), "provenance_min"));
        Map<String, Object> out = J.obj("effects", new ArrayList<>(J.a(n.get("effects"))), "traits", J.objs(traits));
        if (!params.isEmpty()) out.put("params", params);
        return out;
    }

    /**
     * The {@code provenance.actions} resolver: the facts of the def whose verb (or alias) is the operation's verb; null for an unknown verb
     * (the gate then treats the action as sensitive). Two defs claiming one name throw at build time.
     */
    public static Function<String, Map<String, Object>> provenanceActions(List<?> defs, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Map<String, Object>> byVerb = new LinkedHashMap<>();
        for (Object dO : defs) {
            Map<String, Object> d = J.m(dO);
            Map<String, Object> n = Actions.normalize(d);
            Map<String, Object> info = provenanceInfoOf(d, reg, attestationVerified);
            List<Object> names = new ArrayList<>();
            names.add(n.get("verb"));
            names.addAll(J.a(n.get("aliases")));
            for (Object v : names) {
                if (byVerb.containsKey(v)) throw new IllegalStateException("provenanceActions: two definitions claim the verb '" + v + "'");
                byVerb.put((String) v, info);
            }
        }
        return byVerb::get;
    }
}
