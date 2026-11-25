package net.atlasauth.pca.intent;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Deterministic plain-language rendering of grants, questions and actions, and the back-translation diff. Every sentence is a
 * fixed template over the data (no model anywhere), so the same grant always renders the same text. Anything the templates do
 * not know is rendered as an explicit "not understood" line. Policies, caveats and conditions are JSON trees.
 */
public final class IntentRender {
    private IntentRender() {}

    /** A JavaScript {@code undefined} (an absent member), distinct from JSON null. */
    static final Object UNDEF = new Object();

    static Object prop(Object o, String k) {
        if (o == null) throw new NullPointerException("cannot read " + k + " of null");
        if (!(o instanceof Map)) return UNDEF;
        Map<?, ?> m = (Map<?, ?>) o;
        return m.containsKey(k) ? m.get(k) : UNDEF;
    }

    static boolean isNum(Object o) { return o instanceof Json.Num || o instanceof Number; }

    /** {@code String(v)} for a JSON tree value. */
    static String str(Object v) {
        if (v == UNDEF) return "undefined";
        if (v == null) return "null";
        if (isNum(v)) return AttestCommon.jsNumString(IntentOmega.dbl(v));
        if (v instanceof String || v instanceof Boolean) return v.toString();
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null && x != UNDEF) sb.append(str(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** {@code Number(v)} for a JSON tree value (NaN when not numeric). */
    static double toNumber(Object v) {
        if (v == UNDEF) return Double.NaN;
        if (v == null) return 0;
        if (isNum(v)) return IntentOmega.dbl(v);
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        if (v instanceof String) {
            String s = ((String) v).strip();
            if (s.isEmpty()) return 0;
            if (s.matches("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")) return Double.parseDouble(s);
            if (s.matches("[+-]?Infinity")) return s.startsWith("-") ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
            return Double.NaN;
        }
        if (v instanceof List) { // ToNumber of an array reads its string form: [] is 0, a one-element array is that element
            List<?> l = (List<?>) v;
            return l.isEmpty() ? 0 : l.size() == 1 ? (l.get(0) == null ? 0 : toNumber(l.get(0))) : Double.NaN;
        }
        return Double.NaN;
    }

    /** {@code new Date(ms).toISOString()}; throws for an invalid date like the reference. */
    static String isoString(double ms) {
        if (Double.isNaN(ms) || Double.isInfinite(ms) || Math.abs(ms) > 8.64e15) throw new IllegalArgumentException("Invalid time value");
        long t = (long) ms;
        ZonedDateTime z = Instant.ofEpochMilli(t).atZone(ZoneOffset.UTC);
        int y = z.getYear();
        String year = y >= 0 && y <= 9999 ? String.format("%04d", y) : (y < 0 ? "-" : "+") + String.format("%06d", Math.abs(y));
        return String.format("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, z.getMonthValue(), z.getDayOfMonth(), z.getHour(), z.getMinute(), z.getSecond(), z.getNano() / 1_000_000);
    }

    static String replaceFirst(String s, char a, char b) {
        int i = s.indexOf(a);
        return i < 0 ? s : s.substring(0, i) + b + s.substring(i + 1);
    }

    /** {@code d.replace(/\.$/, '').replace(/^./, c => c.toLowerCase())}. */
    static String lowerFirst(String d) {
        String s = d.endsWith(".") ? d.substring(0, d.length() - 1) : d;
        if (s.isEmpty()) return s;
        char c = s.charAt(0);
        if (c == '\n' || c == '\r' || c == ' ' || c == ' ') return s;
        return String.valueOf(c).toLowerCase(java.util.Locale.ROOT) + s.substring(1);
    }

    static String stripDot(String d) { return d.endsWith(".") ? d.substring(0, d.length() - 1) : d; }

    public static String labelOf(String path) {
        if (path.equals("action.resource")) return "resource";
        String[] parts = path.split("\\.", -1);
        return parts[parts.length - 1].replace('_', ' ');
    }

    static String fmt(Object v) {
        if (v instanceof String) return "\"" + v + "\"";
        if (v instanceof List) {
            List<String> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(fmt(x));
            return String.join(", ", out);
        }
        return str(v);
    }

    private static final String UNREADABLE = "an unreadable condition (not understood)";

    public static String renderCondition(Object c) {
        if (!(c instanceof Map) && !(c instanceof List)) return UNREADABLE;
        if (!(c instanceof Map)) return UNREADABLE;
        Map<?, ?> m = (Map<?, ?>) c;
        if (m.containsKey("all_of") || m.containsKey("any_of") || m.containsKey("not")) {
            if (m.containsKey("all_of")) return "all of: " + joined(m.get("all_of"), " and ");
            if (m.containsKey("any_of")) return "either " + joined(m.get("any_of"), " or ");
            return "it is not the case that " + renderCondition(m.get("not"));
        }
        if (!(m.get("field") instanceof String)) return UNREADABLE;
        String field = (String) m.get("field");
        String L = "the " + labelOf(field);
        Object op = m.get("op");
        String V = m.containsKey("ref") ? "the " + labelOf((String) m.get("ref")) : fmt(m.containsKey("value") ? m.get("value") : UNDEF);
        String o = op instanceof String ? (String) op : "\u0000";
        switch (o) {
            case "eq": return L + " is " + V;
            case "ne": return L + " is not " + V;
            case "in": return L + " is one of " + V;
            case "nin": return L + " is none of " + V;
            case "lt": return L + " is less than " + V;
            case "lte": return L + " is at most " + V;
            case "gt": return L + " is more than " + V;
            case "gte": return L + " is at least " + V;
            case "prefix": return L + " starts with " + V;
            case "exists": return Boolean.FALSE.equals(m.get("value")) ? L + " is absent" : L + " is present";
            case "like": return L + " matches the pattern " + V;
            case "matches": return L + " matches the regular expression " + V;
            case "is_a": return L + " is of type " + V;
            case "member_of": return L + " belongs to " + V;
            default: return L + " has an unrecognised test \"" + str(m.containsKey("op") ? op : UNDEF) + "\" (not understood)";
        }
    }

    /** {@code (xs ?? []).map(renderCondition).map(s => "(s)").join(sep)}; a non-array throws like {@code .map} would. */
    private static String joined(Object xs, String sep) {
        if (xs == null) return "";
        if (!(xs instanceof List)) throw new IllegalArgumentException("map is not a function");
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) xs) out.add("(" + renderCondition(x) + ")");
        return String.join(sep, out);
    }

    private static String renderResource(Object r) {
        if (r == UNDEF || "*".equals(r)) return "on any resource";
        if (!(r instanceof String)) return "on an unreadable resource matcher (not understood)";
        String s = (String) r;
        if (s.startsWith("re:")) return "on resources matching the regular expression \"" + s.substring(3) + "\"";
        if (s.endsWith("*")) return "on resources under \"" + s.substring(0, s.length() - 1) + "\"";
        return "only on resource \"" + s + "\"";
    }

    private static String renderVerb(Object v, Catalog catalog) {
        if (v instanceof List) {
            List<String> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(oneVerb(str(x), catalog));
            return String.join("; or ", out);
        }
        return oneVerb(str(v), catalog);
    }

    private static String oneVerb(String x, Catalog catalog) {
        if (x.equals("*")) return "ANY action of any connector";
        Catalog.Spec s = catalog.get(x);
        return s != null ? lowerFirst(s.description) + " [" + x + ", " + replaceFirst(s.reversibility, '_', '-') + "]" : "\"" + x + "\" [uncatalogued: treated as irreversible]";
    }

    public static String renderCaveat(Object c) {
        Object type = c == null ? UNDEF : prop(c, "type");
        String t = type instanceof String ? (String) type : "\u0000";
        switch (t) {
            case "expires": return "The grant expires at " + isoString(toNumber(prop(c, "at"))) + ".";
            case "not_before": return "The grant is not valid before " + isoString(toNumber(prop(c, "at"))) + ".";
            case "rate": return "At most " + str(prop(c, "max")) + " actions in any " + str(prop(c, "per_secs")) + " seconds.";
            case "max_blast_radius": return "No action whose blast radius exceeds " + str(prop(c, "max")) + " (on a 0–1 scale).";
            case "reversibility_max": return "Nothing more severe than \"" + replaceFirst(str(prop(c, "class")), '_', '-') + "\" (reversible < rate-limited < irreversible).";
            case "delegation_depth": return "It may be re-delegated at most " + str(prop(c, "max")) + " level(s) deep.";
            case "budget_alloc": return "A trust-budget allocation of " + str(prop(c, "limit")) + " is carried for sub-delegation.";
            default: return "An unrecognised constraint of type \"" + str(type) + "\" (NOT UNDERSTOOD: do not rely on this grant until it is explained).";
        }
    }

    public static String renderGrant(Object policy) { return renderGrant(policy, Catalog.DEFAULT); }

    /** A grant as numbered plain-language sentences. */
    @SuppressWarnings("unchecked")
    public static String renderGrant(Object policy, Catalog catalog) {
        Map<String, Object> np = IntentPolicy.normalizePolicy(policy);
        List<Object> predicates = (List<Object>) np.get("predicates");
        List<Object> caveats = (List<Object>) np.get("caveats");
        if (predicates.isEmpty()) return "This grant allows nothing.";
        List<String> lines = new ArrayList<>();
        lines.add("The agent may do the following, and nothing else:");
        for (int i = 0; i < predicates.size(); i++) {
            Object p = predicates.get(i);
            Object where = prop(p, "where");
            List<String> conds = new ArrayList<>();
            if (where != UNDEF && where != null) {
                if (!(where instanceof List)) throw new IllegalArgumentException("map is not a function");
                for (Object c : (List<?>) where) conds.add(renderCondition(c));
            }
            lines.add((i + 1) + ". " + renderVerb(prop(p, "verb"), catalog) + ", " + renderResource(prop(p, "resource"))
                + (conds.isEmpty() ? "" : ", only when " + String.join(", and ", conds)) + ".");
        }
        if (!caveats.isEmpty()) {
            lines.add("Limits that apply to everything above:");
            for (Object c : caveats) lines.add("- " + renderCaveat(c));
        }
        return String.join("\n", lines);
    }

    // ---- outcome / question rendering ----

    private static String renderDimCell(Dim d, int i) {
        String L = labelOf(d.path);
        if (d instanceof NumDim n) {
            NumCell c = IntentOmega.numCells(n).get(i);
            if (c.lo() == c.hi()) return L + " exactly " + AttestCommon.jsNumString(c.lo());
            return "any " + L + " from " + AttestCommon.jsNumString(c.lo()) + " to " + AttestCommon.jsNumString(c.hi()) + " (e.g. " + AttestCommon.jsNumString(i > 0 ? c.lo() : c.hi()) + ")";
        }
        IntentOmega.CatValue v = ((CatDim) d).values.get(i);
        if (v.kind().equals("exact")) return L + " \"" + v.value() + "\"";
        if (v.kind().equals("prefix")) return "a " + L + " under \"" + v.value() + "\" (not otherwise named)";
        return "a " + L + " not named anywhere in the grant or your request";
    }

    public static String renderQuestion(VerbSpace vs, int[] cell) { return renderQuestion(vs, cell, Catalog.DEFAULT); }

    public static String renderQuestion(VerbSpace vs, int[] cell, Catalog catalog) {
        Catalog.Spec s = catalog.get(vs.verb);
        String what = s != null ? stripDot(s.description) + " [" + vs.verb + "]" : "perform \"" + vs.verb + "\"";
        List<String> parts = new ArrayList<>();
        for (int k = 0; k < vs.dims.size(); k++) parts.add(renderDimCell(vs.dims.get(k), cell[k]));
        return "Should the agent be allowed to: " + what + (parts.isEmpty() ? "" : ", with " + String.join(", ", parts)) + "?";
    }

    // ---- back-translation diff ----

    /** What a rendering asserts about one dimension (numeric: [min, max] of accepted values; categorical: value labels). */
    public static final class DimClaim {
        public final String path;
        public final boolean any;
        public final double[] range;
        public final List<String> values;
        DimClaim(String path, boolean any, double[] range, List<String> values) { this.path = path; this.any = any; this.range = range; this.values = values; }

        boolean sameAs(DimClaim o) {
            return path.equals(o.path) && any == o.any && java.util.Arrays.equals(range, o.range) && java.util.Objects.equals(values, o.values);
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("path", path);
            m.put("any", any);
            if (range != null) m.put("range", new ArrayList<Object>(List.of(range[0], range[1])));
            if (values != null) m.put("values", new ArrayList<Object>(values));
            return m;
        }
    }

    public static final class VerbClaim {
        public final String verb;
        public final boolean allowed, boxShaped;
        public final List<DimClaim> dims;
        VerbClaim(String verb, boolean allowed, boolean boxShaped, List<DimClaim> dims) { this.verb = verb; this.allowed = allowed; this.boxShaped = boxShaped; this.dims = dims; }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verb", verb);
            m.put("allowed", allowed);
            m.put("boxShaped", boxShaped);
            List<Object> ds = new ArrayList<>();
            for (DimClaim d : dims) ds.add(d.toJson());
            m.put("dims", ds);
            return m;
        }
    }

    /** What the policy asserts over the space, verb by verb and dimension by dimension. */
    public static List<VerbClaim> claimsOf(Object policy, Omega omega) {
        IntentPolicy.Admitter a = IntentPolicy.admitter(policy);
        List<VerbClaim> out = new ArrayList<>();
        for (VerbSpace vs : omega.verbs) {
            double n = IntentOmega.verbCellCount(vs);
            List<int[]> acc = new ArrayList<>();
            for (double c = 0; c < n; c++) {
                int[] idx = IntentOmega.decodeCell(vs, c);
                if (a.admits(vs, IntentOmega.cellRep(vs, idx))) acc.add(idx);
            }
            List<java.util.TreeSet<Integer>> proj = new ArrayList<>();
            for (int k = 0; k < vs.dims.size(); k++) {
                java.util.TreeSet<Integer> s = new java.util.TreeSet<>();
                for (int[] x : acc) s.add(x[k]);
                proj.add(s);
            }
            double boxCount = 1;
            for (java.util.TreeSet<Integer> s : proj) boxCount *= s.size();
            List<DimClaim> dims = new ArrayList<>();
            for (int k = 0; k < vs.dims.size(); k++) {
                Dim d = vs.dims.get(k);
                java.util.TreeSet<Integer> s = proj.get(k);
                int total = IntentOmega.cellCount(d);
                boolean any = s.size() == total;
                if (d instanceof NumDim nd) {
                    double[] range = null;
                    if (!s.isEmpty()) {
                        List<NumCell> cells = IntentOmega.numCells(nd);
                        range = new double[] {cells.get(s.first()).lo(), cells.get(s.last()).hi()};
                    }
                    dims.add(new DimClaim(d.path, any, range, null));
                } else {
                    List<String> vals = new ArrayList<>();
                    for (int i : s) {
                        IntentOmega.CatValue v = ((CatDim) d).values.get(i);
                        vals.add(v.kind().equals("prefix") ? v.value() + "*" : v.value());
                    }
                    dims.add(new DimClaim(d.path, any, null, vals));
                }
            }
            out.add(new VerbClaim(vs.verb, !acc.isEmpty(), acc.size() == boxCount, dims));
        }
        return out;
    }

    /** One difference between two readings, with the sentence shown to the principal. */
    public record ClaimDiff(String verb, String kind, String path, String text) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verb", verb);
            m.put("kind", kind);
            if (path != null) m.put("path", path);
            m.put("text", text);
            return m;
        }
    }

    private static String dimText(DimClaim c) {
        if (c == null) return "anything";
        if (c.any) return "any value";
        if (c.range != null) return AttestCommon.jsNumString(c.range[0]) + " to " + AttestCommon.jsNumString(c.range[1]);
        return c.values != null && !c.values.isEmpty() ? String.join(", ", c.values) : "nothing";
    }

    private interface Wording {
        String extra(String verb);
        String missing(String verb);
        String shape(String verb);
        String dim(String verb, String path, String a, String b);
    }

    private static List<ClaimDiff> diffClaims(List<VerbClaim> g, List<VerbClaim> s, Wording w) {
        List<ClaimDiff> out = new ArrayList<>();
        for (int i = 0; i < g.size(); i++) {
            VerbClaim gc = g.get(i);
            VerbClaim sc = s.get(i);
            if (gc.allowed && !sc.allowed) { out.add(new ClaimDiff(gc.verb, "extra-verb", null, w.extra(gc.verb))); continue; }
            if (!gc.allowed && sc.allowed) { out.add(new ClaimDiff(gc.verb, "missing-verb", null, w.missing(gc.verb))); continue; }
            if (!gc.allowed) continue;
            if (gc.boxShaped != sc.boxShaped) out.add(new ClaimDiff(gc.verb, "shape", null, w.shape(gc.verb)));
            for (int k = 0; k < gc.dims.size(); k++) {
                DimClaim gd = gc.dims.get(k);
                DimClaim sd = sc.dims.get(k);
                if (gd.sameAs(sd)) continue;
                String kind = "different";
                if (gd.range != null && sd.range != null) {
                    kind = gd.range[0] <= sd.range[0] && gd.range[1] >= sd.range[1] ? "looser" : gd.range[0] >= sd.range[0] && gd.range[1] <= sd.range[1] ? "tighter" : "different";
                } else if (gd.values != null && sd.values != null) {
                    kind = gd.values.containsAll(sd.values) ? "looser" : sd.values.containsAll(gd.values) ? "tighter" : "different";
                } else if (gd.any && !sd.any) kind = "looser";
                out.add(new ClaimDiff(gc.verb, kind, gd.path, w.dim(gc.verb, gd.path, dimText(gd), dimText(sd))));
            }
        }
        return out;
    }

    /** Render the grant and the intent slots into the same claim form over the space and list every difference. */
    public static List<ClaimDiff> backTranslationDiff(Object grant, Object slots, Omega omega) {
        return diffClaims(claimsOf(grant, omega), claimsOf(IntentDerive.slotsToPolicy(slots), omega), new Wording() {
            public String extra(String v) { return "The grant allows " + v + ", which your request did not mention."; }
            public String missing(String v) { return "Your request mentions " + v + ", but the grant does not allow it."; }
            public String shape(String v) { return "The grant's rule for " + v + " is a combination of cases that your request did not describe."; }
            public String dim(String v, String path, String a, String b) { return "For " + v + ", the grant allows " + labelOf(path) + " " + a + "; your request said " + b + "."; }
        });
    }

    public static List<ClaimDiff> claimDiff(Object a, Object b, Omega omega) { return claimDiff(a, b, omega, "the first reading", "the second reading"); }

    /** The same claim diff between two grants; {@code kind} is from a's point of view (looser = a allows more). */
    public static List<ClaimDiff> claimDiff(Object a, Object b, Omega omega, String n0, String n1) {
        return diffClaims(claimsOf(a, omega), claimsOf(b, omega), new Wording() {
            public String extra(String v) { return n0 + " allows " + v + "; " + n1 + " does not."; }
            public String missing(String v) { return n1 + " allows " + v + "; " + n0 + " does not."; }
            public String shape(String v) { return n0 + " and " + n1 + " describe " + v + " with differently shaped rules."; }
            public String dim(String v, String path, String x, String y) { return "For " + v + ", " + n0 + " allows " + labelOf(path) + " " + x + "; " + n1 + " allows " + y + "."; }
        });
    }

    public static String renderAction(VerbSpace vs, Map<String, Object> values) { return renderAction(vs, values, Catalog.DEFAULT); }

    /** A concrete action in plain language; values are printed verbatim, so nothing is hidden. */
    public static String renderAction(VerbSpace vs, Map<String, Object> values, Catalog catalog) {
        Catalog.Spec s = catalog.get(vs.verb);
        String what = s != null ? (s.description.endsWith(".") ? s.description.substring(0, s.description.length() - 1) : s.description) + " [" + vs.verb + ", " + replaceFirst(vs.reversibility, '_', '-') + "]" : "perform \"" + vs.verb + "\" [uncatalogued: treated as irreversible]";
        List<String> parts = new ArrayList<>();
        for (String k : new java.util.TreeSet<>(values.keySet())) {
            Object v = values.get(k);
            parts.add(labelOf(k) + " " + (v instanceof String ? "\"" + v + "\"" : str(v instanceof Double ? (Object) new Json.Num(AttestCommon.jsNumString((Double) v)) : v)));
        }
        return "The agent wants to: " + what + (parts.isEmpty() ? "" : ", with " + String.join(", ", parts)) + ".";
    }
}
