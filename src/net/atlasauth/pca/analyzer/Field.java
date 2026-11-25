package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The interval + finite-set engine for a single {@code where} field: one representative value per cell of the partition a
 * conjunction of threshold / membership / prefix tests induces (a sound and complete probe set for the decided fragment), and the
 * standalone numeric-conjunction satisfiability check.
 */
public final class Field {
    private Field() {}

    /** A sentinel string that equals, prefixes and is prefixed by no policy literal. */
    public static final String FRESH_STRING = "\u0000atlas-analyzer::fresh-unmatched\u0000";

    /** A group condition ({@code all_of} / {@code any_of} / {@code not}). */
    static boolean isGroup(Object c) {
        return c instanceof Map && (Js.has(c, "all_of") || Js.has(c, "any_of") || Js.has(c, "not"));
    }

    /** A leaf condition: an object with a string {@code field} that is no group. */
    static boolean isLeaf(Object c) {
        return c instanceof Map && !isGroup(c) && Js.get(c, "field") instanceof String;
    }

    private static List<Double> numericCellReps(List<Double> thresholds) {
        List<Double> sorted = new ArrayList<>();
        Set<Double> seen = new HashSet<>();
        for (double t : thresholds) {
            double k = t == 0 ? 0.0 : t;
            if (!Double.isNaN(k) && !Double.isInfinite(k) && seen.add(k)) sorted.add(k);
        }
        Collections.sort(sorted);
        List<Double> out = new ArrayList<>();
        if (sorted.isEmpty()) return out;
        out.add(sorted.get(0) - 1);
        for (int i = 0; i < sorted.size(); i++) {
            double ti = sorted.get(i);
            out.add(ti);
            if (i + 1 < sorted.size()) out.add((ti + sorted.get(i + 1)) / 2);
        }
        out.add(sorted.get(sorted.size() - 1) + 1);
        return out;
    }

    private static String typeOf(Object x) {
        if (x instanceof String) return "string";
        if (x instanceof Boolean) return "boolean";
        if (Js.isNum(x)) return "number";
        return "object";
    }

    /** A stable key for de-duplicating representative values of mixed type. */
    static String valueKey(Object x) {
        if (FRESH_STRING.equals(x)) return "s:__fresh__";
        return typeOf(x) + ":" + Js.stringify(x);
    }

    /** The representative probe values of one field given the conditions on it (the caller adds the absent value itself). */
    public static List<Object> fieldProbes(List<?> conditions) {
        List<Object> literals = new ArrayList<>();
        List<Double> thresholds = new ArrayList<>();
        List<String> prefixes = new ArrayList<>();
        for (Object c : conditions) {
            if (!isLeaf(c) || Js.has(c, "ref")) continue;
            Object v = Js.get(c, "value");
            Object op = Js.get(c, "op");
            String o = op instanceof String ? (String) op : "";
            switch (o) {
                case "eq":
                case "ne":
                    literals.add(v);
                    if (Js.isFin(v)) thresholds.add(Js.num(v));
                    break;
                case "in":
                case "nin":
                    if (v instanceof List) for (Object x : (List<?>) v) {
                        literals.add(x);
                        if (Js.isFin(x)) thresholds.add(Js.num(x));
                    }
                    break;
                case "lt":
                case "lte":
                case "gt":
                case "gte":
                    if (Js.isFin(v)) thresholds.add(Js.num(v));
                    break;
                case "prefix":
                case "like":
                case "matches":
                case "is_a":
                    if (v instanceof String) {
                        literals.add(v);
                        if (o.equals("prefix")) prefixes.add((String) v);
                    }
                    break;
                case "member_of":
                    if (v instanceof String) literals.add(v);
                    else if (v instanceof List) for (Object x : (List<?>) v) if (x instanceof String) literals.add(x);
                    break;
                default:
                    break;
            }
        }
        List<Object> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        List<Object> all = new ArrayList<>(literals);
        for (double n : numericCellReps(thresholds)) all.add(Js.n(n));
        for (String p : prefixes) { all.add(p); all.add(p + "x"); }
        all.add(FRESH_STRING);
        for (Object x : all) if (seen.add(valueKey(x))) out.add(x);
        return out;
    }

    // ---- standalone numeric-conjunction satisfiability ----

    /** A numeric interval with open / closed ends. */
    public static final class NumInterval {
        public final double lo, hi;
        public final boolean loInclusive, hiInclusive;
        public NumInterval(double lo, boolean loInclusive, double hi, boolean hiInclusive) {
            this.lo = lo; this.loInclusive = loInclusive; this.hi = hi; this.hiInclusive = hiInclusive;
        }
        /** {lo, loInclusive, hi, hiInclusive} as a JSON object. */
        public Map<String, Object> toJson() {
            return Js.obj("lo", Js.n(lo), "loInclusive", loInclusive, "hi", Js.n(hi), "hiInclusive", hiInclusive);
        }
    }

    public static final NumInterval FULL_INTERVAL = new NumInterval(Double.NEGATIVE_INFINITY, false, Double.POSITIVE_INFINITY, false);

    /** Tighten an interval by one numeric condition; non-numeric operands leave it as it is. */
    public static NumInterval tightenInterval(NumInterval iv, Object op, Object value) {
        if (!Js.isFin(value)) return iv;
        double v = Js.num(value);
        double lo = iv.lo, hi = iv.hi;
        boolean li = iv.loInclusive, hiI = iv.hiInclusive;
        switch (op instanceof String ? (String) op : "") {
            case "eq":
                if (v > lo || (v == lo && !li)) { lo = v; li = true; }
                if (v < hi || (v == hi && !hiI)) { hi = v; hiI = true; }
                break;
            case "gte":
                if (v > lo) { lo = v; li = true; }
                break;
            case "gt":
                if (v > lo || (v == lo && li)) { lo = v; li = false; }
                break;
            case "lte":
                if (v < hi) { hi = v; hiI = true; }
                break;
            case "lt":
                if (v < hi || (v == hi && hiI)) { hi = v; hiI = false; }
                break;
            default:
                break;
        }
        return new NumInterval(lo, li, hi, hiI);
    }

    /** Empty iff lo > hi, or lo == hi with an exclusive end. */
    public static boolean intervalEmpty(NumInterval iv) {
        if (iv.lo > iv.hi) return true;
        if (iv.lo == iv.hi) return !(iv.loInclusive && iv.hiInclusive);
        return false;
    }

    /** Is the numeric part of the conjunction (per field) satisfiable? Non-numeric, {@code ref} and group conditions are ignored. */
    public static boolean numericConjunctionSatisfiable(List<?> conditions) {
        Map<String, NumInterval> byField = new LinkedHashMap<>();
        for (Object c : conditions) {
            if (!isLeaf(c) || Js.has(c, "ref")) continue;
            String f = (String) Js.get(c, "field");
            byField.put(f, tightenInterval(byField.getOrDefault(f, FULL_INTERVAL), Js.get(c, "op"), Js.get(c, "value")));
        }
        for (NumInterval iv : byField.values()) if (intervalEmpty(iv)) return false;
        return true;
    }
}
