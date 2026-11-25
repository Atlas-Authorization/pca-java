package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;

/**
 * The facade's view of an action def: the spec rows a facade compiles permissions and limits from (reversibility class, blast preset,
 * the amount parameter), DERIVED from the effective profile of the def instead of written by hand.
 */
public final class ActionFacade {
    private ActionFacade() {}

    /**
     * One def to one facade row. Reversibility and blast are the EFFECTIVE values (declared joined with the floor of the trait closure).
     * {@code reviewed} prices the def as REVIEWED (its declared + implied traits), not as unconfirmed (only for the release-attested catalog).
     */
    public static Map<String, Object> specOfDef(Map<String, Object> d, Actions.Registry reg, boolean reviewed, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Object> full = ActionEffective.effective(d, reg, attestationVerified);
        Map<String, Object> e = reviewed ? J.m(full.get("hint")) : full;
        String verb = (String) d.get("verb");
        int dot = verb.indexOf('.');
        String connector = dot < 0 ? verb : verb.substring(0, dot), action = dot < 0 ? "" : verb.substring(dot + 1);
        String amountField;
        try { amountField = ActionDerive.paramByRole(d, "money.amount"); } catch (Actions.ActionKitError x) { amountField = null; }
        Map<String, Object> eff = J.m(e.get("eff"));
        Map<String, Object> out = J.obj("connector", connector, "action", action, "verb", verb, "reversibility", eff.get("rev"), "blastRadius", J.num(eff.get("blast_ppm")) / 1_000_000);
        if (amountField != null) out.put("amountField", amountField);
        out.put("description", d.get("description") != null ? d.get("description") : d.get("title"));
        if (d.get("aliases") instanceof List && !J.a(d.get("aliases")).isEmpty()) {
            List<String> sorted = new ArrayList<>();
            for (Object a : J.a(d.get("aliases"))) sorted.add((String) a);
            sorted.sort(null);
            out.put("aliases", J.objs(sorted));
        }
        out.put("traits", e.get("closure"));
        return out;
    }

    /** The facade rows of a pack, in the pack's own order. */
    public static List<Object> facadeSpecs(List<?> defs, Actions.Registry reg, boolean reviewed, Predicate<Map<String, Object>> attestationVerified) {
        List<Object> out = new ArrayList<>();
        for (Object d : defs) out.add(specOfDef(J.m(d), reg, reviewed, attestationVerified));
        return out;
    }
}
