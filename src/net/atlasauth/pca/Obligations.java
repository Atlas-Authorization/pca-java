package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Decision obligations (the PEP side): validate, merge, gate and outcome. A PEP that cannot perform every obligation on an allow
 * turns the allow into a deny. Total. Replays packages/pca/conformance/obligations-vectors.json. A null list is the empty list.
 */
public final class Obligations {
    private Obligations() {}

    public static final List<String> KINDS = List.of("log", "notify", "redact", "watermark", "require_receipt");
    public static final int MAX = 16;
    private static final Pattern FIELD_RE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,63}(\\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}");

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    @SuppressWarnings("unchecked")
    private static String paramsError(String kind, Map<String, Object> p) {
        List<String> allowed = switch (kind) {
            case "log" -> List.of("sink");
            case "notify" -> List.of("to");
            case "redact" -> List.of("fields");
            case "watermark" -> List.of("id");
            default -> List.<String>of();
        };
        for (String k : p.keySet()) if (!allowed.contains(k)) return "unknown parameter '" + k + "' for '" + kind + "'";
        if (kind.equals("log") && p.containsKey("sink") && !str(p.get("sink"), 128)) return "log.sink must be a non-empty string of at most 128 characters";
        if (kind.equals("notify") && !str(p.get("to"), 256)) return "notify.to is required (a non-empty string of at most 256 characters)";
        if (kind.equals("watermark") && !str(p.get("id"), 128)) return "watermark.id is required (a non-empty string of at most 128 characters)";
        if (kind.equals("redact")) {
            Object f = p.get("fields");
            if (!(f instanceof List) || ((List<Object>) f).isEmpty() || ((List<Object>) f).size() > 32) return "redact.fields must be 1..32 dotted field paths";
            Set<Object> seen = new HashSet<>();
            for (Object x : (List<Object>) f) {
                if (!(x instanceof String) || !FIELD_RE.matcher((String) x).matches()) return "redact.fields must be 1..32 dotted field paths";
                seen.add(x);
            }
            if (seen.size() != ((List<Object>) f).size()) return "redact.fields has a duplicate";
        }
        return null;
    }

    /** null = well formed. */
    @SuppressWarnings("unchecked")
    public static String error(Object v) {
        if (!(v instanceof Map)) return "an obligation must be an object";
        Map<String, Object> o = (Map<String, Object>) v;
        for (String k : o.keySet()) if (!k.equals("kind") && !k.equals("params") && !k.equals("due")) return "unknown member '" + k + "'";
        Object kind = o.get("kind");
        if (!(kind instanceof String) || !KINDS.contains(kind)) return "unknown obligation kind '" + (kind instanceof String ? kind : "") + "'";
        if (o.containsKey("due") && !nat(o.get("due"))) return "due must be a non-negative safe integer";
        Object p = o.containsKey("params") ? o.get("params") : new LinkedHashMap<String, Object>();
        if (!(p instanceof Map)) return "params must be an object";
        return paramsError((String) kind, (Map<String, Object>) p);
    }

    /** null = a well-formed, duplicate-free list of at most 16. null (absent) is the empty list. */
    @SuppressWarnings("unchecked")
    public static String listError(Object list) {
        if (list == null) return null;
        if (!(list instanceof List)) return "obligations must be an array";
        List<Object> l = (List<Object>) list;
        if (l.size() > MAX) return "more than " + MAX + " obligations";
        Set<String> seen = new HashSet<>();
        try {
            for (int i = 0; i < l.size(); i++) {
                String e = error(l.get(i));
                if (e != null) return "obligations[" + i + "]: " + e;
                if (!seen.add(key((Map<String, Object>) l.get(i)))) return "obligations[" + i + "] duplicates an earlier obligation";
            }
        } catch (RuntimeException e) {
            return "evaluation error (fail closed)";
        }
        return null;
    }

    /** The canonical identity of a well-formed obligation (kind, parameters, due). */
    public static String key(Map<String, Object> o) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("kind", o.get("kind"));
        h.put("params", o.containsKey("params") ? o.get("params") : new LinkedHashMap<String, Object>());
        if (o.containsKey("due")) h.put("due", o.get("due"));
        return Json.canonicalizeStrict(h);
    }

    /** {@code reason} is null when {@code ok}. */
    public static final class Merge {
        public final boolean ok;
        public final List<Object> obligations;
        public final String reason;
        Merge(boolean ok, List<Object> obligations, String reason) { this.ok = ok; this.obligations = obligations; this.reason = reason; }
    }

    /** The union of the lists, deduplicated and sorted by canonical key in UTF-8 byte order. */
    @SuppressWarnings("unchecked")
    public static Merge merge(List<Object> lists) {
        try {
            Map<String, Object> by = new LinkedHashMap<>();
            for (Object l : lists) {
                String e = listError(l);
                if (e != null) return new Merge(false, null, e);
                if (l != null) for (Object o : (List<Object>) l) by.put(key((Map<String, Object>) o), o);
            }
            if (by.size() > MAX) return new Merge(false, null, "more than " + MAX + " obligations after merging");
            List<String> keys = new ArrayList<>(by.keySet());
            keys.sort(Json::compareUtf8);
            List<Object> out = new ArrayList<>();
            for (String k : keys) out.add(by.get(k));
            return new Merge(true, out, null);
        } catch (RuntimeException e) {
            return new Merge(false, null, "evaluation error (fail closed)");
        }
    }

    public static final class Gate {
        public final String decision, reason;
        public final List<Object> perform;
        public final List<String> unsupported;
        Gate(String decision, List<Object> perform, List<String> unsupported, String reason) { this.decision = decision; this.perform = perform; this.unsupported = unsupported; this.reason = reason; }
    }

    private static Gate deny(List<String> unsupported, String reason) { return new Gate("deny", List.of(), unsupported, reason); }

    /** The PEP rule: an allow (or an answered escalate) with any obligation outside {@code supported} is a deny; so is any malformed input. */
    @SuppressWarnings("unchecked")
    public static Gate gate(String decision, Object answered, Object obligations, Object supported) {
        try {
            String eff = net.atlasauth.pca.Decision.pepDecision(decision, answered);
            if (!"allow".equals(eff)) return new Gate("escalate".equals(eff) ? "escalate" : "deny", List.of(), List.of(), null);
            String e = listError(obligations);
            if (e != null) return deny(List.of(), "malformed obligations: " + e);
            if (!(supported instanceof List)) return deny(List.of(), "the supported obligation kinds are malformed");
            for (Object s : (List<Object>) supported) if (!(s instanceof String)) return deny(List.of(), "the supported obligation kinds are malformed");
            List<Object> list = obligations == null ? List.of() : (List<Object>) obligations;
            TreeSet<String> missing = new TreeSet<>(Json::compareUtf8);
            for (Object o : list) {
                String kind = (String) ((Map<String, Object>) o).get("kind");
                if (!((List<Object>) supported).contains(kind)) missing.add(kind);
            }
            if (!missing.isEmpty()) return deny(new ArrayList<>(missing), "the enforcement point does not support obligation(s) " + String.join(", ", missing));
            return new Gate("allow", list, List.of(), null);
        } catch (RuntimeException e) {
            return deny(List.of(), "evaluation error (fail closed)");
        }
    }

    /** {@code status} is null on {@code ok}. */
    public static final class Outcome {
        public final String outcome, status;
        public final List<Integer> overdue;
        Outcome(String outcome, List<Integer> overdue, String status) { this.outcome = outcome; this.overdue = overdue; this.status = status; }
    }

    private static Outcome unmet(List<Integer> overdue) { return new Outcome("escalate", overdue, "obligation_unmet"); }

    /** Which obligations are overdue (due &lt;= now, not in {@code fulfilled})? Malformed input is overdue-everything. */
    @SuppressWarnings("unchecked")
    public static Outcome outcome(Object obligations, Object fulfilled, Object now) {
        try {
            List<Object> list = obligations instanceof List ? (List<Object>) obligations : List.of();
            boolean bad = listError(obligations) != null || !(fulfilled instanceof List) || !nat(now);
            if (!bad) for (Object i : (List<Object>) fulfilled) bad |= !nat(i);
            if (bad) {
                List<Integer> all = new ArrayList<>();
                for (int i = 0; i < list.size(); i++) all.add(i);
                return unmet(all);
            }
            Set<Long> done = new HashSet<>();
            for (Object i : (List<Object>) fulfilled) done.add(Json.asLong(i));
            long t = Json.asLong(now);
            List<Integer> overdue = new ArrayList<>();
            for (int i = 0; i < list.size(); i++) {
                Map<String, Object> o = (Map<String, Object>) list.get(i);
                if (o.containsKey("due") && Json.asLong(o.get("due")) <= t && !done.contains((long) i)) overdue.add(i);
            }
            return overdue.isEmpty() ? new Outcome("ok", List.of(), null) : unmet(overdue);
        } catch (RuntimeException e) {
            return unmet(List.of());
        }
    }
}
