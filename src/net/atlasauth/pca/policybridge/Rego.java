package net.atlasauth.pca.policybridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OPA/Rego to PCA predicate translator. Models only the "allow rule as a conjunction of input comparisons" idiom and fails
 * closed on everything else: a rule with a conjunct outside the subset is dropped whole (never widened). Each allow rule is an
 * independent predicate. Mirrors {@code regoToPca}.
 */
public final class Rego {
    private Rego() {}

    private static final Pattern COMMENT = Pattern.compile("#[^\\n]*");
    private static final Pattern PACKAGE = Pattern.compile(Js.WB_L + "package" + Js.S + "+([A-Za-z_][A-Za-z0-9_.]*)");
    private static final Pattern DEFAULT = Pattern.compile(Js.WB_L + "default" + Js.S + "+allow" + Js.S + "*(?::?=)" + Js.S + "*(true|false)" + Js.WB_R);

    public static Map<String, Object> regoToPca(String moduleText) {
        Map<String, Object> report = PolicyBridge.newReport("rego");
        List<Object> predicates = new ArrayList<>();

        String src = COMMENT.matcher(moduleText).replaceAll("");

        Matcher pkg = PACKAGE.matcher(src);
        if (pkg.find()) PolicyBridge.list(report, "translated").add("package " + pkg.group(1));

        Matcher def = DEFAULT.matcher(src);
        boolean hasDef = def.find();
        if (hasDef && def.group(1).equals("true")) {
            PolicyBridge.list(report, "skipped").add("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny");
        } else if (!hasDef) {
            PolicyBridge.list(report, "skipped").add("no `default allow = false` found; assuming default-deny");
        }

        for (String body : extractAllowBodies(src, report)) translateRule(body, predicates, report);

        return PolicyBridge.result(predicates, new ArrayList<>(), report);
    }

    private static void translateRule(String body, List<Object> predicates, Map<String, Object> report) {
        Object verb = "*";
        String resource = null;
        List<Object> where = new ArrayList<>();

        for (String stmt : Js.trimmedNonEmpty(java.util.Arrays.asList(body.split("[\\n;]", -1)))) {
            Parsed parsed = parseStatement(stmt);
            if (parsed.kind == Kind.UNMODELED) {
                PolicyBridge.list(report, "skipped").add("unmodeled statement \"" + Js.truncate(stmt) + "\" — rule dropped (fail closed)");
                return;
            }
            if (parsed.kind == Kind.VERB) {
                if (verb.equals("*")) {
                    verb = parsed.verb;
                } else {
                    List<Object> have = asList(verb), next = asList(parsed.verb), both = new ArrayList<>();
                    for (Object v : have) if (next.contains(v)) both.add(v);
                    if (both.isEmpty()) {
                        PolicyBridge.list(report, "translated").add("rule can never match (contradictory action selectors), nothing emitted");
                        return;
                    }
                    verb = both.size() == 1 ? both.get(0) : both;
                }
            } else if (parsed.kind == Kind.RESOURCE) {
                if (resource != null && !resource.equals(parsed.resource)) {
                    PolicyBridge.list(report, "translated").add("rule can never match (contradictory resource selectors), nothing emitted");
                    return;
                }
                resource = parsed.resource;
            } else {
                where.add(parsed.condition);
            }
        }

        Map<String, Object> predicate = new LinkedHashMap<>();
        predicate.put("verb", verb);
        if (resource != null) predicate.put("resource", resource);
        if (!where.isEmpty()) predicate.put("where", where);
        predicates.add(predicate);
        PolicyBridge.list(report, "translated").add("allow → verb " + Js.jsonVerb(verb) + (resource != null && !resource.isEmpty() ? " on " + resource : "") + " (" + where.size() + " condition(s))");
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object verb) { return verb instanceof List ? (List<Object>) verb : List.of(verb); }

    private enum Kind { VERB, RESOURCE, CONDITION, UNMODELED }

    private static final class Parsed {
        final Kind kind;
        Object verb;
        String resource;
        Map<String, Object> condition;
        Parsed(Kind kind) { this.kind = kind; }
        static final Parsed UNMODELED = new Parsed(Kind.UNMODELED);
        static Parsed verb(Object v) { Parsed p = new Parsed(Kind.VERB); p.verb = v; return p; }
        static Parsed resource(String r) { Parsed p = new Parsed(Kind.RESOURCE); p.resource = r; return p; }
        static Parsed cond(Map<String, Object> c) { Parsed p = new Parsed(Kind.CONDITION); p.condition = c; return p; }
    }

    private static final Pattern NOT = Pattern.compile("not" + Js.S + "+([\\s\\S]+)");
    private static final Pattern UNMODELED_SYNTAX = Pattern.compile(
        ":=|" + Js.WB_L + "some" + Js.WB_R + "|" + Js.WB_L + "every" + Js.WB_R + "|\\[" + Js.DOT + "*\\|" + Js.DOT + "*\\]");
    private static final Pattern INDEXED = Pattern.compile(Js.WB_L + "input\\.[A-Za-z0-9_.]*\\[");
    private static final Pattern COMPARISON = Pattern.compile(
        "(?s)(input\\.[A-Za-z0-9_.]+)" + Js.S + "*(==|!=|<=|>=|<|>|" + Js.WB_L + "in" + Js.WB_R + ")" + Js.S + "*(.+)");
    private static final Pattern INPUT_PATH = Pattern.compile("input\\.[A-Za-z0-9_.]+");

    private static Parsed parseStatement(String stmt) {
        String s = Js.trim(stmt);

        Matcher nm = NOT.matcher(s);
        if (nm.matches()) {
            Parsed inner = parseStatement(Js.trim(nm.group(1)));
            if (inner.kind != Kind.CONDITION) return Parsed.UNMODELED;
            // `not input.p == lit` is unification and stays inside the negation (an absent path makes it undefined, so the not
            // holds); every other comparison resolves its arguments first, so an absent path leaves the statement undefined.
            Map<String, Object> c = inner.condition;
            if ("eq".equals(c.get("op")) && c.get("field") instanceof String) {
                List<Object> all = new ArrayList<>();
                all.add(Js.obj("field", c.get("field"), "op", "exists"));
                if (c.get("ref") instanceof String) all.add(Js.obj("field", c.get("ref"), "op", "exists"));
                all.add(c);
                return Parsed.cond(Js.obj("not", Js.obj("all_of", all)));
            }
            return Parsed.cond(Js.obj("not", c));
        }

        Parsed builtin = parseBuiltin(s);
        if (builtin != null) return builtin;

        if (UNMODELED_SYNTAX.matcher(s).find()) return Parsed.UNMODELED;
        if (s.indexOf('(') >= 0) return Parsed.UNMODELED;
        if (INDEXED.matcher(s).find()) return Parsed.UNMODELED;

        Matcher m = COMPARISON.matcher(s);
        if (!m.matches()) return Parsed.UNMODELED;
        String path = m.group(1);
        String opTok = m.group(2);
        String rhsRaw = Js.trim(m.group(3));
        String sub = path.substring("input.".length());

        if (opTok.equals("in")) {
            List<Object> set = parseSetLiteral(rhsRaw);
            if (set == null) return Parsed.UNMODELED;
            if (sub.equals("action")) {
                for (Object v : set) if (!(v instanceof String)) return Parsed.UNMODELED;
                return Parsed.verb(new ArrayList<>(set));
            }
            return Parsed.cond(Js.obj("field", "env." + sub, "op", "in", "value", set));
        }

        if ((opTok.equals("==") || opTok.equals("!=")) && INPUT_PATH.matcher(rhsRaw).matches()) {
            return Parsed.cond(Js.obj("field", "env." + sub, "op", opTok.equals("!=") ? "ne" : "eq", "ref", "env." + rhsRaw.substring("input.".length())));
        }

        Object lit = toLiteral(rhsRaw);
        if (lit == NO_LITERAL) return Parsed.UNMODELED;

        if (opTok.equals("==")) {
            if (sub.equals("action") && lit instanceof String) return Parsed.verb(lit);
            if (sub.equals("resource") && lit instanceof String) return Parsed.resource((String) lit);
            return Parsed.cond(Js.obj("field", "env." + sub, "op", "eq", "value", lit));
        }
        if (opTok.equals("!=")) return Parsed.cond(Js.obj("field", "env." + sub, "op", "ne", "value", lit));

        if (!(lit instanceof Number || lit instanceof net.atlasauth.pca.Json.Num)) return Parsed.UNMODELED;
        String cmp = opTok.equals("<") ? "lt" : opTok.equals("<=") ? "lte" : opTok.equals(">") ? "gt" : "gte";
        return Parsed.cond(Js.obj("field", "env." + sub, "op", cmp, "value", lit));
    }

    private static final Pattern STARTSWITH = Pattern.compile(
        "startswith\\(" + Js.S + "*(input\\.[A-Za-z0-9_.]+)" + Js.S + "*," + Js.S + "*\"([^\"]*)\"" + Js.S + "*\\)");
    private static final Pattern GLOB = Pattern.compile(
        "glob\\.match\\(" + Js.S + "*\"([^\"]*)\"" + Js.S + "*," + Js.S + "*(\\[" + Js.S + "*\\]|null)" + Js.S + "*," + Js.S + "*(input\\.[A-Za-z0-9_.]+)" + Js.S + "*\\)");
    private static final Pattern GLOB_META = Pattern.compile("[\\[\\]{}]");
    private static final Pattern WILDCARD = Pattern.compile("[*?\\\\]");

    /** A pure, anchored matcher builtin as a condition; null = not a builtin we model (fall through), UNMODELED = recognised but outside the subset. */
    private static Parsed parseBuiltin(String s) {
        Matcher sw = STARTSWITH.matcher(s);
        if (sw.matches()) {
            String sub = sw.group(1).substring("input.".length());
            return Parsed.cond(Js.obj("field", "env." + sub, "op", "prefix", "value", sw.group(2)));
        }
        Matcher gm = GLOB.matcher(s);
        if (gm.matches()) {
            String pattern = gm.group(1);
            if (GLOB_META.matcher(pattern).find()) return Parsed.UNMODELED;
            // An EMPTY delimiter list means OPA splits on ".", so a wildcard would be cut by a dot: only `null` makes `*` span all.
            if (gm.group(2).startsWith("[") && WILDCARD.matcher(pattern).find()) return Parsed.UNMODELED;
            String sub = gm.group(3).substring("input.".length());
            return Parsed.cond(Js.obj("field", "env." + sub, "op", "like", "value", pattern));
        }
        return null;
    }

    /** Find each {@code allow} rule body {@code { ... }}, brace-aware (set literals inside the body use braces). */
    private static final Pattern ALLOW = Pattern.compile(
        Js.WB_L + "allow" + Js.WB_R + Js.S + "*(?:(?::?=" + Js.S + "*true" + Js.WB_R + "|=" + Js.S + "*true" + Js.WB_R + "|" + Js.WB_L + "if" + Js.WB_R + ")" + Js.S + "*)?\\{");

    private static List<String> extractAllowBodies(String src, Map<String, Object> report) {
        List<String> bodies = new ArrayList<>();
        Matcher m = ALLOW.matcher(src);
        int pos = 0;
        while (pos <= src.length() && m.find(pos)) {
            int open = src.indexOf('{', m.start());
            int close = Js.matchDelim(src, open, '{', '}');
            if (close < 0) {
                PolicyBridge.list(report, "errors").add("unterminated `allow { ... }` block");
                break;
            }
            bodies.add(src.substring(open + 1, close));
            pos = close + 1;
        }
        return bodies;
    }

    // ---- literals ----

    private static final Object NO_LITERAL = new Object();
    private static final Pattern NUMBER = Pattern.compile("-?[0-9]+(?:\\.[0-9]+)?");

    private static Object toLiteral(String expr) {
        String s = Js.trim(expr);
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"' && s.indexOf('"', 1) == s.length() - 1) return s.substring(1, s.length() - 1);
        if (s.equals("true")) return Boolean.TRUE;
        if (s.equals("false")) return Boolean.FALSE;
        if (NUMBER.matcher(s).matches()) return Js.number(s);
        return NO_LITERAL;
    }

    /** A Rego set {@code {"a","b"}} or array {@code ["a","b"]} of scalar literals; null when it is neither or an item is not a scalar. */
    private static List<Object> parseSetLiteral(String expr) {
        String s = Js.trim(expr);
        boolean isSet = s.startsWith("{") && s.endsWith("}");
        boolean isArr = s.startsWith("[") && s.endsWith("]");
        if (!isSet && !isArr) return null;
        List<Object> values = new ArrayList<>();
        for (String it : Js.trimmedNonEmpty(Js.splitTopLevel(Js.slice(s, 1, -1), ","))) {
            Object lit = toLiteral(it);
            if (lit == NO_LITERAL) return null;
            values.add(lit);
        }
        return values;
    }
}
