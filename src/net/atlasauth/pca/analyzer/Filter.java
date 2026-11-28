package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * DATA FILTERING: a residual compiled to a parameterized SQL WHERE clause (and a UCAST tree) so a list endpoint can push authorization into
 * its query. Soundness rule: the filter may only ever return a SUBSET of what the evaluator admits. Anything it cannot express exactly (a
 * regex resource, a {@code ref}, {@code like} / {@code matches} / {@code member_of}, string ordering, a field with no column) makes the whole
 * compile fail with a reason ({@code ok: false}); it never emits a looser filter. SQL's three-valued logic is Kleene's, the same as the
 * evaluator's: an unresolvable permit condition is NULL and the row is dropped; a veto is wrapped in {@code COALESCE(.., TRUE)}.
 *
 * <p>Expressions are JSON objects: {t: "true" | "false" | "cmp" | "in" | "prefix" | "null" | "and" | "or" | "not" | "coalesce", ...}.
 */
public final class Filter {
    private Filter() {}

    private static final class Unsupported extends RuntimeException {
        Unsupported(String m) { super(m); }
    }

    private static final Pattern COL_RE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}(\\.[A-Za-z_][A-Za-z0-9_]{0,62})?");

    private static boolean scalar(Object v) { return v instanceof Boolean || v instanceof String || Js.isFin(v); }

    private static String colOf(Object path, Map<String, Object> cols) {
        if (path instanceof String && cols == null) throw new IllegalStateException("columns is not an object");
        Object c = path instanceof String && cols.containsKey(path) ? cols.get(path) : null;
        if (!(c instanceof String) || !COL_RE.matcher((String) c).matches()) {
            throw new Unsupported("field '" + CaveatAnalysis.jsString(path, true) + "' has no usable column");
        }
        return (String) c;
    }

    private static Map<String, Object> T_(String t) { return Js.obj("t", t); }

    private static Map<String, Object> and(List<Map<String, Object>> xs) {
        if (xs.isEmpty()) return T_("true");
        if (xs.size() == 1) return xs.get(0);
        return Js.obj("t", "and", "xs", new ArrayList<Object>(xs));
    }

    private static Map<String, Object> or(List<Map<String, Object>> xs) {
        if (xs.isEmpty()) return T_("false");
        if (xs.size() == 1) return xs.get(0);
        return Js.obj("t", "or", "xs", new ArrayList<Object>(xs));
    }

    private static Map<String, Object> not(Map<String, Object> x) { return Js.obj("t", "not", "x", x); }
    private static Map<String, Object> coalesce(Map<String, Object> x, boolean def) { return Js.obj("t", "coalesce", "x", x, "def", def); }
    private static Map<String, Object> cmp(String col, String op, Object v) { return Js.obj("t", "cmp", "col", col, "op", op, "v", v); }
    private static Map<String, Object> isNull(String col, boolean isNull) { return Js.obj("t", "null", "col", col, "isNull", isNull); }

    private static Map<String, Object> cond(Object c, Map<String, Object> cols) {
        if (!(c instanceof Map || c instanceof List)) throw new Unsupported("malformed condition");
        if (Field.isGroup(c)) {
            Object all = Js.get(c, "all_of"), any = Js.get(c, "any_of");
            if (Js.has(c, "all_of") && all instanceof List && !((List<?>) all).isEmpty()) {
                List<Map<String, Object>> xs = new ArrayList<>();
                for (Object x : (List<?>) all) xs.add(cond(x, cols));
                return and(xs);
            }
            if (Js.has(c, "any_of") && any instanceof List && !((List<?>) any).isEmpty()) {
                List<Map<String, Object>> xs = new ArrayList<>();
                for (Object x : (List<?>) any) xs.add(cond(x, cols));
                return or(xs);
            }
            if (Js.has(c, "not")) return not(cond(Js.get(c, "not"), cols));
            throw new Unsupported("empty condition group");
        }
        if (!Field.isLeaf(c)) throw new Unsupported("malformed condition");
        if (Js.has(c, "ref")) throw new Unsupported("cross-field ref");
        String col = colOf(Js.get(c, "field"), cols);
        Object v = Js.get(c, "value");
        Object opO = Js.get(c, "op");
        String op = opO instanceof String ? (String) opO : "";
        switch (op) {
            case "eq":
            case "ne":
                if (!scalar(v)) throw new Unsupported(op + " against a non-scalar");
                return cmp(col, op, v);
            case "lt":
            case "lte":
            case "gt":
            case "gte":
                if (!Js.isFin(v)) throw new Unsupported("string ordering follows UTF-8 byte order, which SQL collations do not guarantee");
                return cmp(col, op, v);
            case "in":
            case "nin": {
                boolean ok = v instanceof List && !((List<?>) v).isEmpty();
                if (ok) for (Object x : (List<?>) v) if (!scalar(x)) { ok = false; break; }
                if (!ok) throw new Unsupported(op + " needs a non-empty list of scalars");
                return Js.obj("t", "in", "col", col, "vs", v, "neg", op.equals("nin"));
            }
            case "prefix":
                if (!(v instanceof String)) throw new Unsupported("prefix needs a string");
                return Js.obj("t", "prefix", "col", col, "prefix", v);
            case "exists":
                return isNull(col, Boolean.FALSE.equals(v));
            default:
                throw new Unsupported("operator '" + CaveatAnalysis.jsString(opO, Js.has(c, "op")) + "' has no exact SQL form");
        }
    }

    private static Map<String, Object> resourceExpr(Object p, Map<String, Object> cols) {
        boolean has = Js.has(p, "resource");
        Object r = Js.get(p, "resource");
        if (!has || "*".equals(r)) return T_("true");
        String col = colOf("action.resource", cols);
        String s = (String) r; // a non-string matcher is a compilation error, as in the reference
        if (s.startsWith("re:")) throw new Unsupported("regex resource matcher");
        if (s.endsWith("*")) return Js.obj("t", "prefix", "col", col, "prefix", s.substring(0, s.length() - 1));
        return cmp(col, "eq", s);
    }

    private static Map<String, Object> vetoExpr(Object v, Map<String, Object> cols) {
        Object when = Js.req(Js.get(v, "when"));
        List<Map<String, Object>> ws = new ArrayList<>();
        if (Js.has(when, "resource")) ws.add(coalesce(resourceExpr(when, cols), true));
        Object where = Js.get(when, "where");
        if (where instanceof List) for (Object c : (List<?>) where) ws.add(coalesce(cond(c, cols), true));
        List<Map<String, Object>> parts = new ArrayList<>();
        parts.add(and(ws));
        Object over = Js.get(v, "over");
        if (Js.truthy(over)) {
            String col = colOf(Js.get(over, "path"), cols);
            List<Map<String, Object>> os = new ArrayList<>();
            os.add(isNull(col, true));
            os.add(cmp(col, "lt", Js.n(0)));
            os.add(cmp(col, "gt", Js.get(over, "threshold")));
            parts.add(or(os));
        }
        Object unless = Js.get(v, "unless");
        if (!"approval".equals(Js.get(v, "kind")) && Js.truthy(unless) && unless instanceof List && !((List<?>) unless).isEmpty()) {
            List<Map<String, Object>> us = new ArrayList<>();
            for (Object c : (List<?>) unless) us.add(coalesce(cond(c, cols), false));
            parts.add(not(and(us)));
        }
        return and(parts);
    }

    private static Map<String, Object> partExpr(Object p, Map<String, Object> cols, String include) {
        List<Map<String, Object>> permits = new ArrayList<>();
        for (Object x : Js.list(Js.get(p, "predicates"))) {
            List<Map<String, Object>> parts = new ArrayList<>();
            parts.add(resourceExpr(x, cols));
            Object where = Js.get(x, "where");
            if (where instanceof List) for (Object c : (List<?>) where) parts.add(cond(c, cols));
            permits.add(and(parts));
        }
        List<Map<String, Object>> gates = new ArrayList<>();
        gates.add(or(permits));
        for (Object v : Js.list(Js.get(p, "vetoes"))) {
            Map<String, Object> e = vetoExpr(v, cols);
            // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
            if ("deny".equals(Js.get(v, "kind")) || include.equals("autonomous")) gates.add(not(e));
        }
        for (Object t : Js.list(Js.get(p, "tighten"))) {
            if (include.equals("autonomous")) gates.add(not(coalesce(cond(Js.get(t, "when"), cols), true)));
            else if ("deny".equals(Js.get(t, "signal"))) gates.add(not(coalesce(cond(Js.get(t, "when"), cols), true)));
        }
        return and(gates);
    }

    private static String render(Map<String, Object> e, boolean postgres, List<Object> params) {
        String t = (String) e.get("t");
        switch (t) {
            case "true": return "TRUE";
            case "false": return "FALSE";
            case "cmp": {
                String sym = java.util.Map.of("eq", "=", "ne", "<>", "lt", "<", "lte", "<=", "gt", ">", "gte", ">=").get(e.get("op"));
                return e.get("col") + " " + sym + " " + ph(e.get("v"), postgres, params);
            }
            case "in": {
                List<String> hs = new ArrayList<>();
                for (Object v : Js.list(e.get("vs"))) hs.add(ph(v, postgres, params));
                return e.get("col") + " " + (Boolean.TRUE.equals(e.get("neg")) ? "NOT IN" : "IN") + " (" + String.join(", ", hs) + ")";
            }
            case "prefix": {
                String pre = ((String) e.get("prefix")).replaceAll("[!%_]", "!$0") + "%";
                return e.get("col") + " LIKE " + ph(pre, postgres, params) + " ESCAPE '!'";
            }
            case "null": return e.get("col") + " IS " + (Boolean.TRUE.equals(e.get("isNull")) ? "" : "NOT ") + "NULL";
            case "and": case "or": {
                List<String> rs = new ArrayList<>();
                for (Object x : Js.list(e.get("xs"))) rs.add(render(Js.map(x), postgres, params));
                return "(" + String.join(t.equals("and") ? " AND " : " OR ", rs) + ")";
            }
            case "not": return "NOT (" + render(Js.map(e.get("x")), postgres, params) + ")";
            default: return "COALESCE(" + render(Js.map(e.get("x")), postgres, params) + ", " + (Boolean.TRUE.equals(e.get("def")) ? "TRUE" : "FALSE") + ")";
        }
    }

    private static String ph(Object v, boolean postgres, List<Object> params) {
        params.add(v);
        return postgres ? "$" + params.size() : "?";
    }

    /** Compile a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or say why it cannot be done exactly ({ok: false, reason}). Options: columns, dialect, include. */
    public static Map<String, Object> toFilter(Map<String, Object> res, Map<String, Object> o) {
        try {
            if ("never".equals(Js.get(res, "decision"))) return Js.obj("ok", true, "expr", T_("false"), "sql", "FALSE", "params", new ArrayList<Object>(), "ucast", toUcast(T_("false")));
            Object inc = Js.get(o, "include");
            String include = inc == null ? "autonomous" : inc instanceof String ? (String) inc : "";
            Map<String, Object> own = Js.copy(Js.get(res, "policy"));
            Object meet = own.remove("meet");
            List<Object> all = new ArrayList<>();
            all.add(own);
            if (meet != null) all.addAll(Js.list(meet));
            Object colsO = Js.get(o, "columns");
            List<Map<String, Object>> parts = new ArrayList<>();
            for (Object p : all) parts.add(partExpr(p, colsO instanceof Map ? Js.map(colsO) : null, include));
            Map<String, Object> expr = and(parts);
            List<Object> params = new ArrayList<>();
            Object d = Js.get(o, "dialect");
            String sql = render(expr, d == null || "postgres".equals(d), params);
            return Js.obj("ok", true, "expr", expr, "sql", sql, "params", params, "ucast", toUcast(expr));
        } catch (Unsupported e) {
            return Js.obj("ok", false, "reason", e.getMessage());
        } catch (RuntimeException | StackOverflowError e) {
            return Js.obj("ok", false, "reason", "filter compilation error");
        }
    }

    // ---- evaluation of an expression over a row (Kleene) ----

    private static Object get(Map<String, Object> row, String c) { return row.containsKey(c) ? row.get(c) : null; }

    private static String typeOf(Object x) {
        if (x instanceof String) return "string";
        if (x instanceof Boolean) return "boolean";
        if (Js.isNum(x)) return "number";
        return "object";
    }

    private static int cmpVals(Object a, Object b) {
        if (a instanceof String && b instanceof String) return ((String) a).compareTo((String) b);
        double x = Js.toNum(a), y = Js.toNum(b);
        return x < y ? -1 : x > y ? 1 : x == y ? 0 : 2; // 2: unordered (NaN)
    }

    /** Evaluate a filter expression over one row with Kleene semantics: TRUE, FALSE, or null (unknown). */
    public static Boolean evalFilter(Map<String, Object> e, Map<String, Object> row) {
        switch ((String) e.get("t")) {
            case "true": return true;
            case "false": return false;
            case "cmp": {
                Object a = get(row, (String) e.get("col"));
                Object b = e.get("v");
                if (a == null || !typeOf(a).equals(typeOf(b))) return null;
                String op = (String) e.get("op");
                if (op.equals("eq")) return Js.strictEq(a, b);
                if (op.equals("ne")) return !Js.strictEq(a, b);
                int c = cmpVals(a, b);
                if (c == 2) return false;
                return op.equals("lt") ? c < 0 : op.equals("lte") ? c <= 0 : op.equals("gt") ? c > 0 : c >= 0;
            }
            case "in": {
                Object a = get(row, (String) e.get("col"));
                if (a == null) return null;
                boolean hit = Js.includes(Js.list(e.get("vs")), a);
                return Boolean.TRUE.equals(e.get("neg")) ? !hit : hit;
            }
            case "prefix": {
                Object a = get(row, (String) e.get("col"));
                return a instanceof String ? (Boolean) ((String) a).startsWith((String) e.get("prefix")) : null;
            }
            case "null":
                return (get(row, (String) e.get("col")) == null) == Boolean.TRUE.equals(e.get("isNull"));
            case "and": {
                boolean unk = false;
                for (Object y : Js.list(e.get("xs"))) {
                    Boolean v = evalFilter(Js.map(y), row);
                    if (Boolean.FALSE.equals(v)) return false;
                    if (v == null) unk = true;
                }
                return unk ? null : (Boolean) true;
            }
            case "or": {
                boolean unk = false;
                for (Object y : Js.list(e.get("xs"))) {
                    Boolean v = evalFilter(Js.map(y), row);
                    if (Boolean.TRUE.equals(v)) return true;
                    if (v == null) unk = true;
                }
                return unk ? null : (Boolean) false;
            }
            case "not": {
                Boolean v = evalFilter(Js.map(e.get("x")), row);
                return v == null ? null : (Boolean) !v;
            }
            default: {
                Boolean v = evalFilter(Js.map(e.get("x")), row);
                return v == null ? (Boolean) Boolean.TRUE.equals(e.get("def")) : v;
            }
        }
    }

    // ---- UCAST ----

    private static boolean isEmpty(Map<String, Object> u, String op) {
        return "compound".equals(u.get("type")) && op.equals(u.get("operator")) && Js.list(u.get("value")).isEmpty();
    }

    private static Map<String, Object> compound(String op, List<Object> v) { return Js.obj("type", "compound", "operator", op, "value", v); }

    private static Map<String, Object> join(String op, List<Map<String, Object>> xs) {
        String other = op.equals("and") ? "or" : "and";
        List<Map<String, Object>> flat = new ArrayList<>();
        for (Map<String, Object> x : xs) {
            if ("compound".equals(x.get("type")) && op.equals(x.get("operator"))) for (Object y : Js.list(x.get("value"))) flat.add(Js.map(y));
            else flat.add(x);
        }
        for (Map<String, Object> x : flat) if (isEmpty(x, other)) return compound(other, new ArrayList<>());
        List<Object> kept = new ArrayList<>();
        for (Map<String, Object> x : flat) if (!isEmpty(x, op)) kept.add(x);
        if (kept.size() == 1) return Js.map(kept.get(0));
        return compound(op, kept);
    }

    private static Map<String, Object> and2(List<Map<String, Object>> xs) { return join("and", xs); }
    private static Map<String, Object> or2(List<Map<String, Object>> xs) { return join("or", xs); }
    private static Map<String, Object> not2(Map<String, Object> x) { List<Object> v = new ArrayList<>(); v.add(x); return compound("not", v); }
    private static Map<String, Object> f(String field, String op, Object value) { return Js.obj("type", "field", "field", field, "operator", op, "value", value); }
    private static Map<String, Object> notNull(String c) { return f(c, "ne", null); }
    @SafeVarargs
    private static List<Map<String, Object>> l(Map<String, Object>... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    private static List<Map<String, Object>> mapAll(Object xs, boolean positive) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object x : Js.list(xs)) out.add(positive ? T(Js.map(x)) : F(Js.map(x)));
        return out;
    }

    private static Map<String, Object> T(Map<String, Object> x) {
        String col = (String) x.get("col");
        switch ((String) x.get("t")) {
            case "true": return and2(new ArrayList<>());
            case "false": return or2(new ArrayList<>());
            case "cmp": return "ne".equals(x.get("op")) ? and2(l(notNull(col), f(col, "ne", x.get("v")))) : f(col, (String) x.get("op"), x.get("v"));
            case "in": return Boolean.TRUE.equals(x.get("neg")) ? and2(l(notNull(col), f(col, "nin", x.get("vs")))) : f(col, "in", x.get("vs"));
            case "prefix": return f(col, "startswith", x.get("prefix"));
            case "null": return Boolean.TRUE.equals(x.get("isNull")) ? f(col, "eq", null) : notNull(col);
            case "and": return and2(mapAll(x.get("xs"), true));
            case "or": return or2(mapAll(x.get("xs"), true));
            case "not": return F(Js.map(x.get("x")));
            default: return Boolean.TRUE.equals(x.get("def")) ? not2(F(Js.map(x.get("x")))) : T(Js.map(x.get("x")));
        }
    }

    private static Map<String, Object> F(Map<String, Object> x) {
        String col = (String) x.get("col");
        switch ((String) x.get("t")) {
            case "true": return or2(new ArrayList<>());
            case "false": return and2(new ArrayList<>());
            case "cmp": {
                String inv = java.util.Map.of("eq", "ne", "ne", "eq", "lt", "gte", "lte", "gt", "gt", "lte", "gte", "lt").get((String) x.get("op"));
                return and2(l(notNull(col), f(col, inv, x.get("v"))));
            }
            case "in": return Boolean.TRUE.equals(x.get("neg")) ? f(col, "in", x.get("vs")) : and2(l(notNull(col), f(col, "nin", x.get("vs"))));
            case "prefix": return and2(l(notNull(col), not2(f(col, "startswith", x.get("prefix")))));
            case "null": return Boolean.TRUE.equals(x.get("isNull")) ? notNull(col) : f(col, "eq", null);
            case "and": return or2(mapAll(x.get("xs"), false));
            case "or": return and2(mapAll(x.get("xs"), false));
            case "not": return T(Js.map(x.get("x")));
            default: return Boolean.TRUE.equals(x.get("def")) ? F(Js.map(x.get("x"))) : not2(T(Js.map(x.get("x")))); // coalesce(x, FALSE) is false exactly when x is not definitely true
        }
    }

    /** The filter as a UCAST tree whose rows are exactly those the SQL form selects (every node compiled to "definitely true" / "definitely false"). */
    public static Map<String, Object> toUcast(Map<String, Object> e) { return T(e); }

    /** Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false, {@code eq null} / {@code ne null} test for NULL). */
    public static boolean evalUcast(Map<String, Object> u, Map<String, Object> row) {
        if ("compound".equals(u.get("type"))) {
            List<Object> vs = Js.list(u.get("value"));
            String op = (String) u.get("operator");
            if (op.equals("and")) { for (Object c : vs) if (!evalUcast(Js.map(c), row)) return false; return true; }
            if (op.equals("or")) { for (Object c : vs) if (evalUcast(Js.map(c), row)) return true; return false; }
            return !evalUcast(Js.map(vs.get(0)), row);
        }
        Object a = get(row, (String) u.get("field"));
        Object v = u.get("value");
        String op = (String) u.get("operator");
        if (op.equals("eq") && v == null) return a == null;
        if (op.equals("ne") && v == null) return a != null;
        if (a == null) return false;
        switch (op) {
            case "eq": return Js.strictEq(a, v);
            case "ne": return typeOf(a).equals(typeOf(v)) && !Js.strictEq(a, v);
            case "lt": { int c = cmpVals(a, v); return typeOf(a).equals(typeOf(v)) && c != 2 && c < 0; }
            case "lte": { int c = cmpVals(a, v); return typeOf(a).equals(typeOf(v)) && c != 2 && c <= 0; }
            case "gt": { int c = cmpVals(a, v); return typeOf(a).equals(typeOf(v)) && c != 2 && c > 0; }
            case "gte": { int c = cmpVals(a, v); return typeOf(a).equals(typeOf(v)) && c != 2 && c >= 0; }
            case "in": return Js.includes(Js.list(v), a);
            case "nin": return !Js.includes(Js.list(v), a);
            default: return a instanceof String && ((String) a).startsWith((String) v); // startswith
        }
    }
}
