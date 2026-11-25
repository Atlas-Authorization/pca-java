package net.atlasauth.pca.policybridge;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cedar to PCA predicate translator: {@code permit}/{@code forbid (principal, action, resource) [when {..}] [unless {..}];}
 * units become permit predicates and deny predicates over the predicate DSL. Everything outside the documented subset is
 * reported and fails closed (a dropped {@code forbid} is an error). Mirrors {@code cedarToPca} / {@code translateCedar}.
 */
public final class Cedar {
    private Cedar() {}

    /** The reflexive adjacency map (child uid to parent uids) that {@code in} / member_of resolves against. */
    static final String ENTITY_PARENTS = "env.entity_parents";

    /** An error of the translation (the reference's thrown {@code Error}); its message lands in the report. */
    static final class CedarError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        CedarError(String m) { super(m, null, false, false); }
    }

    public static Map<String, Object> cedarToPca(String policyText) { return translateCedar(policyText, true); }

    /** {@code errorGuards=false} omits the trailing "no attribute was missing" guard (structure only; not exact). */
    public static Map<String, Object> translateCedar(String policyText, boolean errorGuards) {
        Map<String, Object> report = PolicyBridge.newReport("cedar");
        List<Object> predicates = new ArrayList<>(), denies = new ArrayList<>();
        String cleaned = stripComments(policyText);
        for (String stmt : Js.trimmedNonEmpty(Js.splitTopLevel(cleaned, ";"))) {
            try {
                translateStatement(stmt, predicates, denies, report, errorGuards);
            } catch (CedarError e) {
                PolicyBridge.list(report, "errors").add("policy \"" + Js.truncate(stmt) + "\": " + e.getMessage());
            } catch (StackOverflowError e) {
                PolicyBridge.list(report, "errors").add("policy \"" + Js.truncate(stmt) + "\": Maximum call stack size exceeded");
            }
        }
        return PolicyBridge.result(predicates, denies, report);
    }

    private static final Pattern COMMENT = Pattern.compile("//[^\\n]*");
    private static String stripComments(String text) { return COMMENT.matcher(text).replaceAll(""); }

    // ---- statement ----

    private static final Pattern ANNOT = Pattern.compile(Js.S + "*(?:@[A-Za-z_][A-Za-z0-9_]*" + Js.S + "*\\([^)]*\\)" + Js.S + "*)+");
    private static final Pattern HEAD = Pattern.compile(Js.S + "*(permit|forbid)" + Js.S + "*\\(", Pattern.CASE_INSENSITIVE);

    private static void translateStatement(String stmt, List<Object> permits, List<Object> denies, Map<String, Object> report, boolean errorGuards) {
        String body = stmt;
        Matcher annot = ANNOT.matcher(body);
        if (annot.lookingAt()) body = Js.slice(body, annot.end());

        Matcher head = HEAD.matcher(body);
        if (!head.lookingAt()) {
            PolicyBridge.list(report, "skipped").add("unrecognized statement: \"" + Js.truncate(stmt) + "\"");
            return;
        }
        String effect = head.group(1).toLowerCase(java.util.Locale.ROOT).equals("forbid") ? "forbid" : "permit";

        int openIdx = body.indexOf('(', head.start());
        int closeIdx = Js.matchDelim(body, openIdx, '(', ')');
        if (closeIdx < 0) throw new CedarError("unterminated scope parentheses");
        String scopeText = body.substring(openIdx + 1, closeIdx);
        String rest = body.substring(closeIdx + 1);

        Scope scope = parseScope(scopeText);

        List<Object> where = new ArrayList<>(scope.scopeConditions);
        List<Object> guards = new ArrayList<>();

        for (Block block : parseConditionBlocks(rest)) {
            Map<String, Object> parsed = parseExpr(block.text);
            if (parsed == null) {
                PolicyBridge.list(report, "skipped").add("unmodeled " + block.kind + "-condition \"" + Js.truncate(block.text) + "\" — policy dropped (fail closed)");
                dropPolicy(effect, stmt, report);
                return;
            }
            where.add(block.kind.equals("when") ? parsed : Js.obj("not", parsed));
            Map<String, Object> g = noError(parsed);
            if (g != null) guards.add(g);
        }

        int conditionCount = where.size();
        if (errorGuards && !guards.isEmpty()) where.add(guards.size() == 1 ? guards.get(0) : Js.obj("all_of", guards));

        Map<String, Object> predicate = new LinkedHashMap<>();
        predicate.put("verb", scope.verb);
        if (scope.resource != null) predicate.put("resource", scope.resource);
        if (!where.isEmpty()) predicate.put("where", where);

        String on = scope.resource != null && !scope.resource.isEmpty() ? " on " + scope.resource : "";
        if (effect.equals("permit")) {
            permits.add(predicate);
            PolicyBridge.list(report, "translated").add("permit → verb " + Js.jsonVerb(scope.verb) + on + " (" + conditionCount + " condition(s))");
        } else {
            denies.add(predicate);
            PolicyBridge.list(report, "translated").add("forbid → deny verb " + Js.jsonVerb(scope.verb) + on + " (" + conditionCount + " condition(s))");
        }
    }

    /** A dropped permit grants nothing; a dropped forbid is unsafe, so it is an error. */
    private static void dropPolicy(String effect, String stmt, Map<String, Object> report) {
        if (effect.equals("forbid")) {
            PolicyBridge.list(report, "errors").add("forbid could not be fully modeled and was dropped — treat result as fail-closed: \"" + Js.truncate(stmt) + "\"");
        }
    }

    // ---- scope ----

    private static final class Scope {
        Object verb = "*";
        String resource;
        final List<Object> scopeConditions = new ArrayList<>();
    }

    private static final Pattern SCOPE_CLAUSE = Pattern.compile(
        "(principal|action|resource)" + Js.WB_R + Js.S + "*(?:(==|in|is)" + Js.S + "*)?([\\s\\S]*)");

    private static Scope parseScope(String scopeText) {
        Scope result = new Scope();
        for (String clause : Js.trimmedNonEmpty(Js.splitTopLevel(scopeText, ","))) {
            Matcher m = SCOPE_CLAUSE.matcher(clause);
            if (!m.matches()) throw new CedarError("unparseable scope clause \"" + Js.truncate(clause) + "\"");
            String variable = m.group(1);
            String op = m.group(2);
            String operand = Js.trim(m.group(3) == null ? "" : m.group(3));

            if (op == null) continue;

            if (variable.equals("action")) {
                if (op.equals("==")) {
                    String id = entityId(operand);
                    if (id == null) throw new CedarError("action == expects an Action entity, got \"" + Js.truncate(operand) + "\"");
                    result.verb = id;
                } else if (op.equals("in") && operand.startsWith("[")) {
                    List<Object> verbs = new ArrayList<>();
                    for (String it : Js.trimmedNonEmpty(Js.splitTopLevel(Js.slice(operand, 1, -1), ","))) {
                        String id = entityId(it);
                        if (id == null) throw new CedarError("action in [...] expects Action entities, got \"" + Js.truncate(it) + "\"");
                        verbs.add(id);
                    }
                    result.verb = verbs;
                } else {
                    throw new CedarError("unsupported action scope operator \"" + op + "\"");
                }
            } else {
                String field = variable.equals("resource") ? "action.resource" : "subject.id";
                if (op.equals("==")) {
                    String eid = entityUid(operand);
                    if (variable.equals("resource")) {
                        if (eid == null) throw new CedarError("resource == expects an entity, got \"" + Js.truncate(operand) + "\"");
                        result.resource = eid;
                    } else {
                        if (eid == null) throw new CedarError("principal == expects an entity, got \"" + Js.truncate(operand) + "\"");
                        result.scopeConditions.add(Js.obj("field", field, "op", "eq", "value", eid));
                    }
                } else if (op.equals("is")) {
                    String type = typeName(operand);
                    if (type == null) throw new CedarError(variable + " is expects a type, got \"" + Js.truncate(operand) + "\"");
                    result.scopeConditions.add(Js.obj("field", field, "op", "is_a", "value", type));
                } else {
                    Map<String, Object> mem = memberOfCondition(field, operand);
                    if (mem == null) throw new CedarError(variable + " in expects an entity (hierarchy), got \"" + Js.truncate(operand) + "\"");
                    result.scopeConditions.add(mem);
                }
            }
        }
        return result;
    }

    // ---- conditions ----

    private static final class Block {
        final String kind, text;
        Block(String kind, String text) { this.kind = kind; this.text = text; }
    }

    private static final Pattern BLOCK = Pattern.compile(Js.WB_L + "(when|unless)" + Js.WB_R + Js.S + "*\\{");

    private static List<Block> parseConditionBlocks(String rest) {
        List<Block> blocks = new ArrayList<>();
        Matcher m = BLOCK.matcher(rest);
        int pos = 0;
        while (pos <= rest.length() && m.find(pos)) {
            String kind = m.group(1).equals("unless") ? "unless" : "when";
            int open = rest.indexOf('{', m.start());
            int close = Js.matchDelim(rest, open, '{', '}');
            if (close < 0) throw new CedarError("unterminated " + kind + " block");
            blocks.add(new Block(kind, rest.substring(open + 1, close)));
            pos = close + 1;
        }
        return blocks;
    }

    /** A boolean expression: {@code ||} (any_of) over {@code &&} (all_of) over parentheses over comparison atoms; null if outside the subset. */
    private static Map<String, Object> parseExpr(String text) {
        String t = Js.trim(text);
        if (t.isEmpty()) return null;

        List<String> ors = Js.trimmedNonEmpty(Js.splitTopLevel(t, "||"));
        if (ors.size() > 1) {
            List<Object> subs = new ArrayList<>();
            for (String s : ors) { Map<String, Object> c = parseExpr(s); if (c == null) return null; subs.add(c); }
            return Js.obj("any_of", subs);
        }
        List<String> ands = Js.trimmedNonEmpty(Js.splitTopLevel(t, "&&"));
        if (ands.size() > 1) {
            List<Object> subs = new ArrayList<>();
            for (String s : ands) { Map<String, Object> c = parseExpr(s); if (c == null) return null; subs.add(c); }
            return Js.obj("all_of", subs);
        }
        if (t.startsWith("(") && Js.matchDelim(t, 0, '(', ')') == t.length() - 1) return parseExpr(Js.slice(t, 1, -1));
        return parseAtom(t);
    }

    private static final String[][] CMP = { { "==", "eq" }, { "!=", "ne" }, { "<=", "lte" }, { ">=", "gte" }, { "<", "lt" }, { ">", "gt" } };
    private static final Pattern WORD_OP = Pattern.compile("([\\s\\S]*?" + Js.NS + ")" + Js.S + "+(in|is|like|has)" + Js.S + "+([\\s\\S]+)");

    private static Map<String, Object> parseAtom(String text) {
        String t = Js.trim(text);
        for (String[] c : CMP) {
            int idx = Js.indexOfTopLevel(t, c[0]);
            if (idx >= 0) {
                String lhs = Js.trim(t.substring(0, idx));
                String rhs = Js.trim(t.substring(idx + c[0].length()));
                return buildComparison(lhs, c[1], rhs);
            }
        }
        Matcher wm = WORD_OP.matcher(t);
        if (wm.matches()) return buildWordOp(Js.trim(wm.group(1)), wm.group(2), Js.trim(wm.group(3)));
        return null;
    }

    private static Map<String, Object> buildComparison(String lhsRaw, String op, String rhsRaw) {
        String field = toFieldPath(lhsRaw);
        if (field == null) return null;
        if (field.equals("action.verb")) {
            if (!op.equals("eq") && !op.equals("ne")) return null;
            String id = entityId(rhsRaw);
            return id == null ? null : Js.obj("field", field, "op", op, "value", id);
        }
        if (isPathExpr(rhsRaw)) {
            String refPath = toFieldPath(rhsRaw);
            if (refPath != null) return Js.obj("field", field, "op", op, "ref", refPath);
        }
        Object lit = toLiteral(rhsRaw);
        if (lit == NO_LITERAL) return null;
        return Js.obj("field", field, "op", op, "value", lit);
    }

    private static final Pattern HAS_ATTR = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private static Map<String, Object> buildWordOp(String lhsRaw, String kind, String rhsRaw) {
        if (kind.equals("has")) {
            if (!HAS_ATTR.matcher(rhsRaw).matches()) return null;
            String field = toFieldPath(lhsRaw + "." + rhsRaw);
            return field == null ? null : Js.obj("field", field, "op", "exists");
        }

        String field = toFieldPath(lhsRaw);
        if (field == null) return null;

        if (field.equals("action.verb")) {
            if (!kind.equals("in")) return null;
            String inner = rhsRaw.startsWith("[") && rhsRaw.endsWith("]") ? Js.slice(rhsRaw, 1, -1) : rhsRaw;
            List<Object> ids = new ArrayList<>();
            for (String x : Js.trimmedNonEmpty(Js.splitTopLevel(inner, ","))) {
                String id = entityId(x);
                if (id == null) return null;
                ids.add(id);
            }
            return !ids.isEmpty() ? Js.obj("field", field, "op", "in", "value", ids) : null;
        }

        if (kind.equals("is")) {
            String type = typeName(rhsRaw);
            return type == null ? null : Js.obj("field", field, "op", "is_a", "value", type);
        }

        if (kind.equals("like")) {
            if (rhsRaw.length() < 2 || !rhsRaw.startsWith("\"") || !rhsRaw.endsWith("\"")) return null;
            return Js.obj("field", field, "op", "like", "value", cedarLikeToGlob(rhsRaw.substring(1, rhsRaw.length() - 1)));
        }

        // kind == "in"
        if (rhsRaw.startsWith("[")) {
            String inner = rhsRaw.endsWith("]") ? Js.slice(rhsRaw, 1, -1) : Js.slice(rhsRaw, 1);
            List<String> items = Js.trimmedNonEmpty(Js.splitTopLevel(inner, ","));
            boolean allEntities = true;
            for (String it : items) if (entityUid(it) == null) { allEntities = false; break; }
            if (allEntities && !items.isEmpty()) {
                List<Object> uids = new ArrayList<>();
                for (String it : items) uids.add(entityUid(it));
                return Js.obj("field", field, "op", "member_of", "value", uids, "collection", ENTITY_PARENTS);
            }
            List<Object> values = new ArrayList<>();
            for (String it : items) {
                Object lit = toLiteral(it);
                if (lit == NO_LITERAL) return null;
                values.add(lit);
            }
            return Js.obj("field", field, "op", "in", "value", values);
        }
        return memberOfCondition(field, rhsRaw);
    }

    /** A member_of condition for {@code <field> in <entity|path>} (entity literal gives a value, a path gives a ref). */
    private static Map<String, Object> memberOfCondition(String field, String operand) {
        String eid = entityUid(operand);
        if (eid != null) return Js.obj("field", field, "op", "member_of", "value", eid, "collection", ENTITY_PARENTS);
        if (isPathExpr(operand)) {
            String ref = toFieldPath(operand);
            if (ref != null) return Js.obj("field", field, "op", "member_of", "ref", ref, "collection", ENTITY_PARENTS);
        }
        return null;
    }

    private static final Pattern PATH_START = Pattern.compile("(principal|resource|action|context)" + Js.WB_R);
    private static boolean isPathExpr(String expr) { return PATH_START.matcher(expr).lookingAt(); }

    private static final Pattern P_ATTR = Pattern.compile("principal\\.([A-Za-z_][A-Za-z0-9_.]*)");
    private static final Pattern R_ATTR = Pattern.compile("resource\\.([A-Za-z_][A-Za-z0-9_.]*)");
    private static final Pattern C_ATTR = Pattern.compile("context\\.([A-Za-z_][A-Za-z0-9_.]*)");

    /** Map a Cedar scope-variable expression to a PCA dotted field path; null if not a path. */
    private static String toFieldPath(String expr) {
        if (expr.equals("principal")) return "subject.id";
        if (expr.equals("resource")) return "action.resource";
        if (expr.equals("action")) return "action.verb";
        if (expr.equals("context")) return "env";
        Matcher mp = P_ATTR.matcher(expr);
        if (mp.matches()) return "subject." + mp.group(1);
        Matcher mr = R_ATTR.matcher(expr);
        if (mr.matches()) return "env.resource." + mr.group(1);
        Matcher mc = C_ATTR.matcher(expr);
        if (mc.matches()) return "env." + mc.group(1);
        return null;
    }

    // ---- literals / entities ----

    /** A Cedar type name ({@code User}, {@code Ns::User}), or null. */
    static String typeName(String expr) {
        String s = Js.trim(expr);
        int i = 0, n = s.length();
        while (true) {
            if (i >= n || !Js.isIdentStart(s.charAt(i))) return null;
            i++;
            while (i < n && Js.isIdentPart(s.charAt(i))) i++;
            if (i == n) return s;
            if (i + 1 < n && s.charAt(i) == ':' && s.charAt(i + 1) == ':') { i += 2; continue; }
            return null;
        }
    }

    /** Split {@code Prefix::"id"} into {prefix, id}, or null (prefix at least one character, no line terminator; id without a quote). */
    private static String[] entityParts(String expr) {
        String s = Js.trim(expr);
        int n = s.length();
        if (n < 4 || s.charAt(n - 1) != '"') return null;
        int j = s.lastIndexOf('"', n - 2);
        if (j < 3 || s.charAt(j - 1) != ':' || s.charAt(j - 2) != ':') return null;
        String prefix = s.substring(0, j - 2);
        for (int i = 0; i < prefix.length(); i++) {
            char c = prefix.charAt(i);
            if (c == '\n' || c == '\r' || c == ' ' || c == ' ') return null;
        }
        return new String[] { prefix, s.substring(j + 1, n - 1) };
    }

    /** The quoted id of an entity reference {@code Ns::Type::"id"}, or null. */
    static String entityId(String expr) {
        String[] p = entityParts(expr);
        return p == null ? null : p[1];
    }

    /** An entity reference rendered as its UID with quotes dropped: {@code Type::"id"} becomes {@code Type::id}. */
    static String entityUid(String expr) {
        String[] p = entityParts(expr);
        return p == null ? null : p[0] + "::" + p[1];
    }

    static final Object NO_LITERAL = new Object();
    private static final Pattern NUMBER = Pattern.compile("-?[0-9]+(?:\\.[0-9]+)?");

    private static Object toLiteral(String expr) {
        String s = Js.trim(expr);
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"' && s.indexOf('"', 1) == s.length() - 1) return s.substring(1, s.length() - 1);
        if (s.equals("true")) return Boolean.TRUE;
        if (s.equals("false")) return Boolean.FALSE;
        if (NUMBER.matcher(s).matches()) return Js.number(s);
        String eid = entityUid(s);
        if (eid != null) return eid;
        return NO_LITERAL;
    }

    /** A Cedar {@code like} pattern (only {@code *} is a wildcard; {@code \*} is a literal star) as the PCA glob. */
    static String cedarLikeToGlob(String inner) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < inner.length(); i++) {
            char ch = inner.charAt(i);
            if (ch == '\\') {
                if (i + 1 < inner.length()) {
                    char n = inner.charAt(i + 1);
                    if (n == '*') { out.append("\\*"); i++; continue; }
                    out.append(escapeGlobLiteral(n));
                    i++;
                    continue;
                }
                out.append("\\\\");
                continue;
            }
            if (ch == '*') { out.append('*'); continue; }
            out.append(escapeGlobLiteral(ch));
        }
        return out.toString();
    }

    private static String escapeGlobLiteral(char ch) { return ch == '*' || ch == '?' || ch == '\\' ? "\\" + ch : String.valueOf(ch); }

    // ---- Cedar evaluation-error semantics ----

    private static final Set<String> TOTAL_FIELDS = new HashSet<>(List.of("subject.id", "action.verb", "action.resource", "env"));

    /** Attribute reads that can raise a Cedar "attribute missing" error: principal.x, resource.x, context.x. */
    private static List<String> guardedPaths(String field) {
        if (field == null || TOTAL_FIELDS.contains(field) || field.startsWith("env.entity_parents")) return List.of();
        return field.startsWith("subject.") || field.startsWith("env.") ? List.of(field) : List.of();
    }

    private static Map<String, Object> exists(String field) { return Js.obj("field", field, "op", "exists"); }

    private static Map<String, Object> allOf(List<Map<String, Object>> xs) { return xs.size() == 1 ? xs.get(0) : Js.obj("all_of", new ArrayList<Object>(xs)); }
    private static Map<String, Object> anyOf(List<Map<String, Object>> xs) { return xs.size() == 1 ? xs.get(0) : Js.obj("any_of", new ArrayList<Object>(xs)); }

    /**
     * "Evaluating this expression raises no Cedar error", as a condition (null = it cannot). Cedar evaluates && and || left to
     * right and does not look at the right side once the left has decided, so it only needs its attributes present when the
     * left was true (&&) or false (||).
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> noError(Map<String, Object> c) {
        if (c.containsKey("not")) return noError((Map<String, Object>) c.get("not"));
        if (c.containsKey("all_of") || c.containsKey("any_of")) {
            boolean isAnd = c.containsKey("all_of");
            List<Object> kids = (List<Object>) (isAnd ? c.get("all_of") : c.get("any_of"));
            Map<String, Object> acc = null;
            for (int i = kids.size() - 1; i >= 0; i--) {
                Map<String, Object> kid = (Map<String, Object>) kids.get(i);
                Map<String, Object> n = noError(kid);
                Map<String, Object> cont = acc == null ? null : anyOf(List.of(isAnd ? Js.obj("not", kid) : kid, acc));
                acc = n == null ? cont : cont == null ? n : allOf(List.of(n, cont));
            }
            return acc;
        }
        String field = (String) c.get("field");
        String ref = (String) c.get("ref");
        if ("exists".equals(c.get("op")) && field != null) {
            int k = field.lastIndexOf('.');
            String base = k >= 0 && k < field.length() - 1 ? field.substring(0, k) : field;
            int parts = 1;
            for (int i = 0; i < base.length(); i++) if (base.charAt(i) == '.') parts++;
            boolean deep = parts >= (base.startsWith("env.resource") ? 3 : 2);
            List<Map<String, Object>> baseNeeds = new ArrayList<>();
            if (deep) for (String p : guardedPaths(base)) baseNeeds.add(exists(p));
            return baseNeeds.isEmpty() ? null : allOf(baseNeeds);
        }
        List<Map<String, Object>> needs = new ArrayList<>();
        for (String p : guardedPaths(field)) needs.add(exists(p));
        for (String p : guardedPaths(ref)) needs.add(exists(p));
        return needs.isEmpty() ? null : allOf(needs);
    }
}
