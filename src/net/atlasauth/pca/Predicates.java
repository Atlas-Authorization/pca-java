package net.atlasauth.pca;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The deterministic predicate DSL (packages/pca/src/predicates.ts {@code evaluatePredicates}): the ONE evaluator the
 * Intent Layer v2 {@code layers} check runs each ceiling through. Pure data, total, fail closed.
 *
 * <p>A predicate is {@code {verb, resource?, where?}}: {@code verb} a string ({@code "*"} = any) or a list of them;
 * {@code resource} exact, {@code "*"}, a trailing-{@code *} prefix or {@code re:<pattern>} (full match, linear-time
 * {@link SafeRegex}); {@code where} a list of conditions that must all hold. A condition is a leaf
 * {@code {field, op, value | ref, collection?}} over a dotted path rooted at {@code action}, {@code subject} or
 * {@code env}, or a grouping {@code all_of} / {@code any_of} / {@code not} evaluated three-valued (an undecidable child
 * never satisfies a {@code not}). Operators: eq, ne, in, nin, lt, lte, gt, gte, prefix, exists, like, matches, is_a,
 * member_of. Numbers compare by binary64 value; strings by UTF-8 bytes; equality by the canonical JSON text.
 *
 * <p>The context is a JSON-tree map {@code {action: {verb, resource, params?}, subject?, env?}}.
 */
public final class Predicates {
    private Predicates() {}

    public static final int MAX_PATTERN_SUBJECT_LEN = 512;
    public static final int MAX_LIKE_PATTERN_LEN = 512;
    public static final int MAX_MATCHES_PATTERN_LEN = 200;
    public static final int MAX_MEMBER_CLOSURE_NODES = 10_000;
    public static final int MAX_RE_RESOURCE_LEN = 512;

    /** Three-valued condition truth. */
    public enum Tri { TRUE, FALSE, UNKNOWN }

    private static final Set<String> ROOTS = Set.of("action", "subject", "env");
    private static final Set<String> FORBIDDEN = Set.of("__proto__", "constructor", "prototype");

    private static boolean isObjRec(Object x) { return x instanceof Map; }
    /** JavaScript {@code typeof x === 'object' && x !== null} (maps and lists). */
    private static boolean isJsObject(Object x) { return x instanceof Map || x instanceof List; }

    /** The resolved value of a dotted path: {@code found} plus the value (own members only). */
    public static final class Resolved {
        public final boolean found;
        public final Object value;
        Resolved(boolean found, Object value) { this.found = found; this.value = value; }
    }
    private static final Resolved NOT_FOUND = new Resolved(false, null);

    /** Resolve a dotted path into the context. Own members only; an unknown root is not found. */
    public static Resolved resolvePath(Map<String, Object> ctx, Object path) {
        if (!(path instanceof String) || ((String) path).isEmpty()) return NOT_FOUND;
        String[] segs = ((String) path).split("\\.", -1);
        if (!ROOTS.contains(segs[0])) return NOT_FOUND;
        if (ctx == null || !ctx.containsKey(segs[0])) return NOT_FOUND;
        Object cur = ctx.get(segs[0]);
        for (int i = 1; i < segs.length; i++) {
            String s = segs[i];
            if (FORBIDDEN.contains(s) || !isJsObject(cur)) return NOT_FOUND;
            if (cur instanceof List) {
                if (!s.matches("0|[1-9][0-9]*")) return NOT_FOUND;
                List<?> l = (List<?>) cur;
                double idx = Double.parseDouble(s);
                if (idx >= l.size()) return NOT_FOUND;
                cur = l.get((int) idx);
            } else {
                Map<?, ?> m = (Map<?, ?>) cur;
                if (!m.containsKey(s)) return NOT_FOUND;
                cur = m.get(s);
            }
        }
        return new Resolved(true, cur);
    }

    /** Equal lenient canonical texts (see {@link IntentJs#jsonEquals}). */
    private static boolean deepEq(Object a, Object b) { return IntentJs.jsonEquals(a, b); }

    /** -1 / 0 / 1, or null when the values have no order (mixed types, non-finite numbers, lone surrogates). */
    private static Integer ordered(Object a, Object b) {
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        if (x != null && y != null) {
            if (!IntentJs.isFinite(a) || !IntentJs.isFinite(b)) return null;
            return x < y ? -1 : x > y ? 1 : 0;
        }
        if (a instanceof String && b instanceof String) {
            if (Json.hasLoneSurrogate((String) a) || Json.hasLoneSurrogate((String) b)) return null;
            return Integer.signum(Json.compareUtf8((String) a, (String) b));
        }
        return null;
    }

    // ---- like (anchored glob over UTF-16 code units) ----
    private static final int LIT = 0, ONE = 1, STAR = 2;

    /** Tokens as {kind, char}; null on a dangling trailing backslash. Consecutive stars collapse. */
    private static int[][] parseGlob(String glob) {
        List<int[]> out = new ArrayList<>();
        for (int i = 0; i < glob.length(); i++) {
            char ch = glob.charAt(i);
            if (ch == '\\') {
                if (i + 1 >= glob.length()) return null;
                out.add(new int[] {LIT, glob.charAt(i + 1)});
                i++;
            } else if (ch == '*') {
                if (out.isEmpty() || out.get(out.size() - 1)[0] != STAR) out.add(new int[] {STAR, 0});
            } else if (ch == '?') out.add(new int[] {ONE, 0});
            else out.add(new int[] {LIT, ch});
        }
        return out.toArray(new int[0][]);
    }

    static Boolean globMatch(String glob, String s) {
        int[][] toks = parseGlob(glob);
        if (toks == null) return null;
        int ti = 0, si = 0, starTi = -1, starSi = 0;
        while (si < s.length()) {
            int[] t = ti < toks.length ? toks[ti] : null;
            if (t != null && t[0] == STAR) {
                starTi = ++ti;
                starSi = si;
            } else if (t != null && (t[0] == ONE || s.charAt(si) == t[1])) {
                ti++;
                si++;
            } else if (starTi >= 0) {
                ti = starTi;
                si = ++starSi;
            } else return false;
        }
        while (ti < toks.length && toks[ti][0] == STAR) ti++;
        return ti == toks.length;
    }

    private static Boolean typeTagMatch(Object v, String t) {
        if (v instanceof String) return v.equals(t) || ((String) v).startsWith(t + "::");
        if (isObjRec(v)) {
            Map<?, ?> m = (Map<?, ?>) v;
            boolean decidable = false, matched = false;
            if (m.containsKey("type") && m.get("type") instanceof String) {
                String ty = (String) m.get("type");
                decidable = true;
                if (ty.equals(t) || ty.startsWith(t + "::")) matched = true;
            }
            if (m.containsKey("tags") && m.get("tags") instanceof List) {
                decidable = true;
                for (Object x : (List<?>) m.get("tags")) if (t.equals(x)) matched = true;
            }
            return decidable ? matched : null;
        }
        return null;
    }

    private static List<String> neighboursOf(Map<?, ?> adj, String node) {
        List<String> out = new ArrayList<>();
        if (FORBIDDEN.contains(node) || !adj.containsKey(node)) return out;
        Object raw = adj.get(node);
        if (raw instanceof String) out.add((String) raw);
        else if (raw instanceof List) for (Object x : (List<?>) raw) if (x instanceof String) out.add((String) x);
        return out;
    }

    private static Set<String> memberClosure(String start, Map<?, ?> adj) {
        Set<String> seen = new HashSet<>();
        seen.add(start);
        ArrayDeque<String> queue = new ArrayDeque<>();
        queue.add(start);
        int visited = 0;
        while (!queue.isEmpty() && visited < MAX_MEMBER_CLOSURE_NODES) {
            visited++;
            String node = queue.poll();
            for (String n : neighboursOf(adj, node)) if (seen.add(n)) queue.add(n);
        }
        return seen;
    }

    private static boolean paramsUnavailable(Map<String, Object> ctx) {
        Object a = ctx == null ? null : ctx.get("action");
        Object p = a instanceof Map ? ((Map<?, ?>) a).get("params") : null;
        return !isJsObject(p);
    }

    private static boolean paramsRooted(String path) { return path.equals("action.params") || path.startsWith("action.params."); }

    private static Tri tri(boolean b) { return b ? Tri.TRUE : Tri.FALSE; }

    private static Tri triLeaf(Map<?, ?> c, Map<String, Object> ctx) {
        Object field = c.get("field"), op = c.get("op");
        if (!(field instanceof String) || ((String) field).isEmpty()) return Tri.UNKNOWN;
        if (!(op instanceof String)) return Tri.UNKNOWN;
        String f0 = (String) field;
        if (paramsRooted(f0) && paramsUnavailable(ctx)) return Tri.UNKNOWN;
        Object ref = c.get("ref");
        if (ref instanceof String && paramsRooted((String) ref) && paramsUnavailable(ctx)) return Tri.UNKNOWN;
        Resolved f = resolvePath(ctx, f0);
        if (op.equals("exists")) return tri(Boolean.FALSE.equals(c.get("value")) ? !f.found : f.found);
        if (!f.found) return Tri.UNKNOWN;
        Object v = f.value;
        boolean hasRef = c.containsKey("ref");

        if (op.equals("member_of")) {
            if (!(v instanceof String)) return Tri.UNKNOWN;
            Object coll = c.get("collection");
            if (!(coll instanceof String) || ((String) coll).isEmpty()) return Tri.UNKNOWN;
            Resolved cr = resolvePath(ctx, coll);
            if (!cr.found || !isObjRec(cr.value)) return Tri.UNKNOWN;
            Object target;
            if (hasRef) {
                Resolved r = resolvePath(ctx, ref);
                if (!r.found) return Tri.UNKNOWN;
                target = r.value;
            } else {
                if (!c.containsKey("value")) return Tri.UNKNOWN;
                target = c.get("value");
            }
            List<String> targets = new ArrayList<>();
            if (target instanceof List) { for (Object x : (List<?>) target) if (x instanceof String) targets.add((String) x); }
            else if (target instanceof String) targets.add((String) target);
            if (targets.isEmpty()) return Tri.UNKNOWN;
            Set<String> reach = memberClosure((String) v, (Map<?, ?>) cr.value);
            for (String t : targets) if (reach.contains(t)) return Tri.TRUE;
            return Tri.FALSE;
        }

        Object operand;
        if (hasRef) {
            Resolved r = resolvePath(ctx, ref);
            if (!r.found) return Tri.UNKNOWN;
            operand = r.value;
        } else {
            if (!c.containsKey("value")) return Tri.UNKNOWN;
            operand = c.get("value");
        }

        switch ((String) op) {
            case "eq": return tri(deepEq(v, operand));
            case "ne": return tri(!deepEq(v, operand));
            case "in":
            case "nin": {
                if (!(operand instanceof List)) return Tri.UNKNOWN;
                boolean any = false;
                for (Object x : (List<?>) operand) if (deepEq(v, x)) { any = true; break; }
                return tri(op.equals("in") == any);
            }
            case "lt": case "lte": case "gt": case "gte": {
                Integer o = ordered(v, operand);
                if (o == null) return Tri.UNKNOWN;
                switch ((String) op) {
                    case "lt": return tri(o < 0);
                    case "lte": return tri(o <= 0);
                    case "gt": return tri(o > 0);
                    default: return tri(o >= 0);
                }
            }
            case "prefix":
                if (!(v instanceof String) || !(operand instanceof String)) return Tri.UNKNOWN;
                return tri(((String) v).startsWith((String) operand));
            case "like": {
                if (!(v instanceof String) || !(operand instanceof String)) return Tri.UNKNOWN;
                String sv = (String) v, so = (String) operand;
                if (so.length() > MAX_LIKE_PATTERN_LEN || sv.length() > MAX_PATTERN_SUBJECT_LEN) return Tri.UNKNOWN;
                Boolean m = globMatch(so, sv);
                return m == null ? Tri.UNKNOWN : tri(m);
            }
            case "matches": {
                if (!(v instanceof String) || !(operand instanceof String)) return Tri.UNKNOWN;
                String sv = (String) v, so = (String) operand;
                if (so.length() > MAX_MATCHES_PATTERN_LEN || sv.length() > MAX_PATTERN_SUBJECT_LEN) return Tri.UNKNOWN;
                if (!SafeRegex.isSafeSource(so)) return Tri.UNKNOWN;
                if (!SafeRegex.charge(so, sv.length())) return Tri.UNKNOWN;
                Boolean r = SafeRegex.fullMatch(so, sv);
                return r == null ? Tri.UNKNOWN : tri(r);
            }
            case "is_a": {
                if (!(operand instanceof String) || ((String) operand).isEmpty()) return Tri.UNKNOWN;
                Boolean t = typeTagMatch(v, (String) operand);
                return t == null ? Tri.UNKNOWN : tri(t);
            }
            default:
                return Tri.UNKNOWN;
        }
    }

    /** Three-valued evaluation of a condition (leaf or grouping). Total. */
    public static Tri evaluateConditionTri(Object c, Map<String, Object> ctx) {
        return SafeRegex.withBudget(() -> conditionInner(c, ctx));
    }

    private static Tri conditionInner(Object c, Map<String, Object> ctx) {
        try {
            if (!isJsObject(c)) return Tri.UNKNOWN;
            if (c instanceof Map) {
                Map<?, ?> m = (Map<?, ?>) c;
                if (m.containsKey("all_of") || m.containsKey("any_of") || m.containsKey("not")) {
                    if (m.containsKey("all_of")) {
                        Object xs = m.get("all_of");
                        if (!(xs instanceof List) || ((List<?>) xs).isEmpty()) return Tri.UNKNOWN;
                        boolean sawUnknown = false;
                        for (Object x : (List<?>) xs) {
                            Tri t = evaluateConditionTri(x, ctx);
                            if (t == Tri.FALSE) return Tri.FALSE;
                            if (t == Tri.UNKNOWN) sawUnknown = true;
                        }
                        return sawUnknown ? Tri.UNKNOWN : Tri.TRUE;
                    }
                    if (m.containsKey("any_of")) {
                        Object xs = m.get("any_of");
                        if (!(xs instanceof List) || ((List<?>) xs).isEmpty()) return Tri.UNKNOWN;
                        boolean sawUnknown = false;
                        for (Object x : (List<?>) xs) {
                            Tri t = evaluateConditionTri(x, ctx);
                            if (t == Tri.TRUE) return Tri.TRUE;
                            if (t == Tri.UNKNOWN) sawUnknown = true;
                        }
                        return sawUnknown ? Tri.UNKNOWN : Tri.FALSE;
                    }
                    Tri inner = evaluateConditionTri(m.get("not"), ctx);
                    return inner == Tri.TRUE ? Tri.FALSE : inner == Tri.FALSE ? Tri.TRUE : Tri.UNKNOWN;
                }
                return triLeaf(m, ctx);
            }
            return Tri.UNKNOWN; // an array is no condition (no string field)
        } catch (RuntimeException | StackOverflowError e) {
            return Tri.UNKNOWN;
        }
    }

    /** One condition: true iff cleanly decided true. */
    public static boolean evaluateCondition(Object c, Map<String, Object> ctx) { return evaluateConditionTri(c, ctx) == Tri.TRUE; }

    private static boolean verbMatches(Object p, String verb) {
        if (p instanceof String) return p.equals("*") || p.equals(verb);
        if (p instanceof List) {
            for (Object x : (List<?>) p) if (x instanceof String && (x.equals("*") || x.equals(verb))) return true;
        }
        return false;
    }

    private static boolean resourceMatches(Map<?, ?> p, String resource) {
        if (!p.containsKey("resource")) return true;
        Object pattern = p.get("resource");
        if (!(pattern instanceof String)) return false;
        String pat = (String) pattern;
        if (pat.equals("*")) return true;
        if (pat.startsWith("re:")) {
            String src = pat.substring(3);
            if (src.length() > 200) return false;
            if (resource.length() > MAX_RE_RESOURCE_LEN) return false;
            if (!SafeRegex.isSafeSource(src)) return false;
            if (!SafeRegex.charge(src, resource.length())) return false;
            return Boolean.TRUE.equals(SafeRegex.fullMatch(src, resource));
        }
        if (pat.endsWith("*")) return resource.startsWith(pat.substring(0, pat.length() - 1));
        return pat.equals(resource);
    }

    /** Does a single predicate permit the action? */
    public static boolean predicateMatches(Object p, Map<String, Object> ctx) {
        return SafeRegex.withBudget(() -> predicateInner(p, ctx));
    }

    private static boolean predicateInner(Object p, Map<String, Object> ctx) {
        try {
            if (!isJsObject(p)) return false;
            if (!(p instanceof Map)) return false; // an array has no verb
            Map<?, ?> pm = (Map<?, ?>) p;
            Object a = ctx == null ? null : ctx.get("action");
            if (!(a instanceof Map)) return false;
            Object verb = ((Map<?, ?>) a).get("verb"), resource = ((Map<?, ?>) a).get("resource");
            if (!(verb instanceof String) || !(resource instanceof String)) return false;
            if (!verbMatches(pm.get("verb"), (String) verb)) return false;
            if (!resourceMatches(pm, (String) resource)) return false;
            if (pm.containsKey("where")) {
                Object w = pm.get("where");
                if (!(w instanceof List)) return false;
                for (Object c : (List<?>) w) if (!evaluateCondition(c, ctx)) return false;
            }
            return true;
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        }
    }

    /** An action is allowed iff it matches AT LEAST ONE predicate. Default-deny: an empty or non-list set allows nothing. */
    public static boolean evaluatePredicates(Object predicates, Map<String, Object> ctx) {
        return SafeRegex.withBudget(() -> {
            try {
                if (!(predicates instanceof List) || ((List<?>) predicates).isEmpty()) return false;
                for (Object p : (List<?>) predicates) if (predicateMatches(p, ctx)) return true;
                return false;
            } catch (RuntimeException e) {
                return false;
            }
        });
    }

    // ---- limit-naming denial reasons (0.5) ----

    private static final Map<String, String> OP_TEXT = Map.ofEntries(
        Map.entry("eq", "=="), Map.entry("ne", "!="), Map.entry("lt", "<"), Map.entry("lte", "<="), Map.entry("gt", ">"),
        Map.entry("gte", ">="), Map.entry("in", "in"), Map.entry("nin", "not in"), Map.entry("prefix", "starts with"),
        Map.entry("like", "like"), Map.entry("matches", "matches"), Map.entry("is_a", "is a"), Map.entry("member_of", "member of"));
    private static final int MAX_SHOWN_STRING = 64;
    private static final int MAX_SHOWN_ITEMS = 8;

    private static boolean isGroup(Object c) {
        return c instanceof Map && (((Map<?, ?>) c).containsKey("all_of") || ((Map<?, ?>) c).containsKey("any_of") || ((Map<?, ?>) c).containsKey("not"));
    }

    /** A scalar operand in a denial reason: safe integers, booleans, null and plain short strings are spelled out. */
    static String showValue(Object v, int depth) {
        if (v == null) return "null";
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num || v instanceof Number) return Json.isSafeInt(v) ? Long.toString(Json.asLong(v)) : "<number>";
        if (v instanceof String) {
            String s = (String) v;
            if (s.length() > MAX_SHOWN_STRING) return "\"...\"";
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (ch < 0x20 || ch == '"' || ch == '\\' || (ch >= 0xD800 && ch <= 0xDFFF)) return "\"...\"";
            }
            return "\"" + s + "\"";
        }
        if (v instanceof List && depth == 0) {
            List<?> l = (List<?>) v;
            if (l.size() > MAX_SHOWN_ITEMS) return "[...]";
            List<String> parts = new ArrayList<>();
            for (Object x : l) parts.add(showValue(x, 1));
            return "[" + String.join(", ", parts) + "]";
        }
        return "<value>";
    }

    /** The condition as the limit a reader recognises: {@code amount <= 500}, {@code currency in ["usd", "eur"]}. */
    static String describeCondition(Object c, int depth) {
        if (!isJsObject(c)) return "<condition>";
        if (isGroup(c)) {
            Map<?, ?> m = (Map<?, ?>) c;
            if (depth >= 2) return "(...)";
            if (m.get("all_of") instanceof List) return "all of (" + describeAll((List<?>) m.get("all_of"), depth) + ")";
            if (m.get("any_of") instanceof List) return "any of (" + describeAll((List<?>) m.get("any_of"), depth) + ")";
            if (m.containsKey("not")) return "not (" + describeCondition(m.get("not"), depth + 1) + ")";
            return "<condition>";
        }
        Map<?, ?> m = c instanceof Map ? (Map<?, ?>) c : Map.of();
        String f = m.get("field") instanceof String ? (String) m.get("field") : "<field>";
        String name = f.startsWith("action.params.") ? f.substring("action.params.".length()) : f;
        Object op = m.get("op");
        if ("exists".equals(op)) return Boolean.FALSE.equals(m.get("value")) ? name + " absent" : name + " present";
        String text = op instanceof String ? OP_TEXT.get(op) : null;
        if (text == null) return name + " <condition>";
        String operand = m.containsKey("ref") ? (m.get("ref") instanceof String ? (String) m.get("ref") : "<ref>")
            : m.containsKey("value") ? showValue(m.get("value"), 0) : "<value>";
        return name + " " + text + " " + operand;
    }

    private static String describeAll(List<?> xs, int depth) {
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < xs.size() && i < MAX_SHOWN_ITEMS; i++) parts.add(describeCondition(xs.get(i), depth + 1));
        return String.join("; ", parts);
    }

    /** Inside an unmet top-level condition, the narrowest part that failed (an {@code all_of} points at its first unmet child). */
    private static Object narrowestUnmet(Object c, Map<String, Object> ctx, int depth) {
        if (depth < 4 && c instanceof Map && ((Map<?, ?>) c).get("all_of") instanceof List) {
            for (Object x : (List<?>) ((Map<?, ?>) c).get("all_of")) if (!evaluateCondition(x, ctx)) return narrowestUnmet(x, ctx, depth + 1);
        }
        return c;
    }

    /**
     * When a predicate's verb and resource are in scope but a {@code where} limit is not met, that limit described
     * ({@code amount <= 100}); null when no predicate is in scope (the plain "no predicate permits" wording stays).
     */
    public static String firstUnmetLimit(Object predicates, Map<String, Object> ctx) {
        return SafeRegex.withBudget(() -> {
            try {
                Object a = ctx == null ? null : ctx.get("action");
                if (!(a instanceof Map) || !(predicates instanceof List)) return null;
                Object verb = ((Map<?, ?>) a).get("verb"), resource = ((Map<?, ?>) a).get("resource");
                if (!(verb instanceof String) || !(resource instanceof String)) return null;
                for (Object p : (List<?>) predicates) {
                    if (!(p instanceof Map)) continue;
                    Map<?, ?> pm = (Map<?, ?>) p;
                    if (!verbMatches(pm.get("verb"), (String) verb) || !resourceMatches(pm, (String) resource)) continue;
                    if (!(pm.get("where") instanceof List)) continue;
                    for (Object c : (List<?>) pm.get("where"))
                        if (!evaluateCondition(c, ctx)) return describeCondition(narrowestUnmet(c, ctx, 0), 0);
                }
                return null;
            } catch (RuntimeException | StackOverflowError e) {
                return null;
            }
        });
    }

    /**
     * Why {@link #evaluatePredicates} denied, or null when it allows: {@code envelope grants no predicates} for an empty
     * set, {@code <limit> not satisfied for <verb> on <resource>} when a limit in scope is unmet, else
     * {@code no predicate permits <verb> on <resource>}.
     */
    public static String denialReason(Object predicates, Map<String, Object> ctx) {
        if (evaluatePredicates(predicates, ctx)) return null;
        if (!(predicates instanceof List) || ((List<?>) predicates).isEmpty()) return "envelope grants no predicates";
        Object a = ctx == null ? null : ctx.get("action");
        Map<?, ?> am = a instanceof Map ? (Map<?, ?>) a : Map.of();
        String vr = IntentRevocation.jsText(am.get("verb"), am.containsKey("verb")) + " on " + IntentRevocation.jsText(am.get("resource"), am.containsKey("resource"));
        String limit = firstUnmetLimit(predicates, ctx);
        return limit != null ? limit + " not satisfied for " + vr : "no predicate permits " + vr;
    }
}
