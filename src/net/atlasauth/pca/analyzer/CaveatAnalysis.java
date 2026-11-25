package net.atlasauth.pca.analyzer;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;

/**
 * Static satisfiability of a PCA envelope caveat set (the leaf's cumulative, conjunctive caveats): is there ANY runtime context
 * under which they all hold? The one caveat tied to the action itself, {@code reversibility_max}, is returned as a cap.
 * Unknown or malformed caveats fail closed.
 */
public final class CaveatAnalysis {
    /** Some context satisfies every caveat. */
    public final boolean sat;
    public final String reason;
    /** Strictest {@code reversibility_max} cap as an index into {@link Analyzer#REVERSIBILITY_ORDER}, or null. */
    public final Integer revCap;

    CaveatAnalysis(boolean sat, String reason, Integer revCap) { this.sat = sat; this.reason = reason; this.revCap = revCap; }

    private static CaveatAnalysis no(String reason) { return new CaveatAnalysis(false, reason, null); }

    /** {sat, reason?, revCap?} as a JSON object. */
    public Map<String, Object> toJson() {
        Map<String, Object> m = Js.obj("sat", sat);
        if (reason != null) m.put("reason", reason);
        if (revCap != null) m.put("revCap", Js.n(revCap));
        return m;
    }

    /** JavaScript {@code String(x)} of a JSON value ({@code present} false = undefined). */
    static String jsString(Object x, boolean present) {
        if (!present) return "undefined";
        if (x == null) return "null";
        Double d = Js.num(x);
        if (d != null) return Double.isNaN(d) ? "NaN" : Double.isInfinite(d) ? (d > 0 ? "Infinity" : "-Infinity") : AttestCommon.jsNumString(d == 0 ? 0.0 : d);
        if (x instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object e : (List<?>) x) {
                if (!first) sb.append(',');
                first = false;
                if (e != null) sb.append(jsString(e, true));
            }
            return sb.toString();
        }
        if (x instanceof Map) return "[object Object]";
        return x.toString();
    }

    private static Double fin(Object v) { return Js.isFin(v) ? Js.num(v) : null; }

    private static String s(double d) { return AttestCommon.jsNumString(d == 0 ? 0.0 : d); }

    public static CaveatAnalysis analyzeCaveats(Object caveats) {
        if (!(caveats instanceof List)) return no("caveats are not an array");
        double notBeforeMax = Double.NEGATIVE_INFINITY;
        double expiresMin = Double.POSITIVE_INFINITY;
        Integer revCap = null;
        for (Object cv : (List<?>) caveats) {
            if (!(cv instanceof Map) || !(Js.get(cv, "type") instanceof String)) return no("malformed caveat (not an object with a string type)");
            String type = (String) Js.get(cv, "type");
            switch (type) {
                case "expires": {
                    Double at = fin(Js.get(cv, "at"));
                    if (at == null) return no("expires.at is not a finite number");
                    expiresMin = Math.min(expiresMin, at);
                    break;
                }
                case "not_before": {
                    Double at = fin(Js.get(cv, "at"));
                    if (at == null) return no("not_before.at is not a finite number");
                    notBeforeMax = Math.max(notBeforeMax, at);
                    break;
                }
                case "rate": {
                    Double max = fin(Js.get(cv, "max")), per = fin(Js.get(cv, "per_secs"));
                    if (max == null || per == null || per <= 0) return no("rate caveat requires finite max and per_secs > 0");
                    if (max < 1) return no("rate.max " + s(max) + " < 1 forbids every action");
                    break;
                }
                case "max_blast_radius": {
                    Double max = fin(Js.get(cv, "max"));
                    if (max == null) return no("max_blast_radius.max is not a finite number");
                    if (max < 0) return no("max_blast_radius.max < 0 forbids every action");
                    break;
                }
                case "reversibility_max": {
                    String cls = jsString(Js.get(cv, "class"), Js.has(cv, "class"));
                    int idx = Analyzer.REVERSIBILITY_ORDER.indexOf(cls);
                    if (idx < 0) return no("reversibility_max.class '" + cls + "' is unknown");
                    revCap = revCap == null ? idx : Math.min(revCap, idx);
                    break;
                }
                case "delegation_depth": {
                    Double max = fin(Js.get(cv, "max"));
                    if (max == null) return no("delegation_depth.max is not a finite number");
                    if (max < 0) return no("delegation_depth.max < 0 forbids every action");
                    break;
                }
                case "budget_alloc": {
                    Double lim = fin(Js.get(cv, "limit"));
                    if (lim == null || lim < 0) return no("budget_alloc.limit must be a finite number >= 0");
                    break;
                }
                default:
                    return no("unknown caveat type '" + type + "' (fail closed)");
            }
        }
        if (notBeforeMax != Double.NEGATIVE_INFINITY && expiresMin != Double.POSITIVE_INFINITY && notBeforeMax >= expiresMin) {
            return no("not_before (" + s(notBeforeMax) + ") >= expires (" + s(expiresMin) + "): the validity window is empty");
        }
        return new CaveatAnalysis(true, null, revCap);
    }
}
