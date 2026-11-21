package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.function.ToDoubleFunction;
import net.atlasauth.pca.intent.IntentOmega.Outcome;

/**
 * Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor, and the regret of a
 * choice the grant admits (utility is the principal's, supplied by the caller).
 */
public final class IntentProvenance {
    private IntentProvenance() {}

    private static final List<String> FRICTION_ORDER = List.of("tap", "hold", "typed", "device");

    /** The fixed banner for a tainted value (web / agent / tool); null for trusted and first-party values. */
    public static String provenanceBanner(String level, String what) {
        String w = what == null ? "value" : what;
        if ("web".equals(level)) return "This " + w + " was suggested by content on the page, not by you.";
        if ("agent".equals(level)) return "This " + w + " came from your agent, not from you or the site.";
        if ("tool".equals(level)) return "This " + w + " came from another service, not from you or this site.";
        return null;
    }

    /** True for the tainted levels (tool, web, agent). */
    public static boolean isTainted(String level) { return "tool".equals(level) || "web".equals(level) || "agent".equals(level); }

    /** The friction a value needs: the maximum of {@code base} and the provenance floor (tainted critical: typed; tainted material: hold; else tap). */
    public static String provenanceFriction(String base, String sensitivity, String level) {
        String floor = !isTainted(level) ? "tap" : "critical".equals(sensitivity) ? "typed" : "hold";
        return FRICTION_ORDER.get(Math.max(FRICTION_ORDER.indexOf(base), FRICTION_ORDER.indexOf(floor)));
    }

    /** One choice: the options feasible at the time, the chosen one, membership in the effective grant and the principal's utility. */
    public record RegretCase(List<Outcome> feasible, Outcome chosen, Predicate<Outcome> admits, ToDoubleFunction<Outcome> utility) {}

    /** Within-grant regret of one choice: {regret, best, admitted}. Only options inside the grant compete. */
    public static Map<String, Object> withinGrantRegret(RegretCase c) {
        boolean admitted = c.admits().test(c.chosen());
        Outcome best = null;
        double bestU = Double.NEGATIVE_INFINITY;
        for (Outcome o : c.feasible()) {
            if (!c.admits().test(o)) continue;
            double u = c.utility().applyAsDouble(o);
            if (u > bestU) { bestU = u; best = o; }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("regret", !admitted || best == null ? 0.0 : Math.max(0, bestU - c.utility().applyAsDouble(c.chosen())));
        r.put("best", best == null ? null : IntentOmega.outcomeToJson(best));
        r.put("admitted", admitted);
        return r;
    }

    /** Aggregate regret over choices: {cases, admitted, positive, mean, max, regret_est_ppm} (ppm of the utility scale {@code scale}). */
    public static Map<String, Object> regretReport(List<RegretCase> cases, double scale) {
        int admitted = 0, positive = 0;
        double sum = 0, max = 0;
        for (RegretCase c : cases) {
            Map<String, Object> r = withinGrantRegret(c);
            if (!Boolean.TRUE.equals(r.get("admitted"))) continue;
            admitted++;
            double reg = (Double) r.get("regret");
            sum += reg;
            if (reg > 0) positive++;
            if (reg > max) max = reg;
        }
        double mean = admitted > 0 ? sum / admitted : 0;
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("cases", (double) cases.size());
        o.put("admitted", (double) admitted);
        o.put("positive", (double) positive);
        o.put("mean", mean);
        o.put("max", max);
        o.put("regret_est_ppm", IntentMapKit.jsRound((mean / (scale > 0 ? scale : 1)) * 1_000_000));
        return o;
    }
}
