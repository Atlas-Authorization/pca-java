package net.atlasauth.pca.policybridge;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.DateTimeException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;

/**
 * Strict CEL import (Google IAM Conditions, Kubernetes ValidatingAdmissionPolicy, SpiceDB caveat expressions): one boolean CEL
 * expression becomes a PCA condition or is REJECTED, naming the construct. There is no best-effort mode: a condition that was
 * dropped or approximated would widen what a policy admits. No CEL runs anywhere; the predicate DSL is the only evaluator.
 * Mirrors {@code celToCondition}, {@code celToPredicate}, {@code celConditionsToPca} and {@code parseCel}.
 *
 * <p>Results are JSON maps: {@code {ok:true, condition, fields}} / {@code {ok:false, code, message, at}}.
 */
public final class Cel {
    private Cel() {}

    private static final int MAX_EXPR = 4096;
    private static final int MAX_DEPTH = 32;
    private static final int MAX_NODES = 256;
    private static final int MAX_LIST = 64;
    private static final int MAX_STR = 256;
    private static final Set<String> FORBIDDEN = Set.of("__proto__", "constructor", "prototype");
    private static final Set<String> TYPES = Set.of("string", "int", "bool", "timestamp_ms");

    /** A refusal: a stable error code, the message and the offset in the expression. */
    private static final class Reject extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final String code;
        final int at;
        Reject(String code, String message, int at) { super(message, null, false, false); this.code = code; this.at = at; }
    }

    private static Reject rej(String code, String message, int at) { return new Reject(code, message, at); }

    private static Object n(long v) { return new Json.Num(Long.toString(v)); }

    // ---- tokens ----

    private static final class Tok {
        final char k; // 'i' id, 'n' int, 's' str, 'p' punct
        final String v;
        final int at;
        Tok(char k, String v, int at) { this.k = k; this.v = v; this.at = at; }
    }

    private static final String[] PUNCT = { "&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-" };

    private static String unsupportedChar(char c) {
        switch (c) {
            case '+': return "arithmetic (+)";
            case '*': return "arithmetic (*)";
            case '/': return "arithmetic (/)";
            case '%': return "arithmetic (%)";
            case '?': return "the conditional operator";
            case ':': return "the conditional operator / map literal";
            case '{': case '}': return "map or message literal";
            case '@': return "@";
            case '&': return "bitwise &";
            case '|': return "bitwise |";
            case '^': return "^";
            case '~': return "~";
            case '=': return "assignment";
            case '`': return "quoted identifier";
            default: return null;
        }
    }

    private static List<Tok> lex(String src) {
        List<Tok> out = new ArrayList<>();
        int i = 0;
        while (i < src.length()) {
            char c = src.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { i++; continue; }
            if (c == '/' && i + 1 < src.length() && src.charAt(i + 1) == '/') throw rej("unsupported", "comments", i);
            if (Js.isIdentStart(c)) {
                int j = i + 1;
                while (j < src.length() && Js.isIdentPart(src.charAt(j))) j++;
                String w = src.substring(i, j);
                char nx = j < src.length() ? src.charAt(j) : '\0';
                if ((w.equals("r") || w.equals("b") || w.equals("R") || w.equals("B")) && (nx == '"' || nx == '\'')) {
                    throw rej("unsupported", (w.toLowerCase(java.util.Locale.ROOT).equals("r") ? "raw string" : "bytes") + " literal", i);
                }
                out.add(new Tok('i', w, i));
                i = j;
                continue;
            }
            if (Js.isDigit(c)) {
                int j = i;
                while (j < src.length() && Js.isDigit(src.charAt(j))) j++;
                boolean has = j < src.length();
                char nxt = has ? src.charAt(j) : '\0';
                if (has && nxt == '.' && j + 1 < src.length() && Js.isDigit(src.charAt(j + 1))) throw rej("unsupported", "double literal", i);
                if (has && (nxt == 'e' || nxt == 'E')) throw rej("unsupported", "double literal", i);
                if (has && (nxt == 'u' || nxt == 'U')) throw rej("unsupported", "unsigned integer literal", i);
                if (has && (nxt == 'x' || nxt == 'X')) throw rej("unsupported", "hexadecimal literal", i);
                String w = src.substring(i, j);
                if (w.length() > 1 && w.charAt(0) == '0') throw rej("unsupported", "integer literal with a leading zero", i);
                out.add(new Tok('n', w, i));
                i = j;
                continue;
            }
            if (c == '"' || c == '\'') {
                String triple = "" + c + c + c;
                if (src.startsWith(triple, i)) throw rej("unsupported", "triple-quoted string", i);
                int j = i + 1;
                StringBuilder s = new StringBuilder();
                for (;;) {
                    if (j >= src.length()) throw rej("syntax", "unterminated string", i);
                    char d = src.charAt(j);
                    if (d == '\n' || d == '\r') throw rej("syntax", "unterminated string", i);
                    if (d == c) break;
                    if (d == '\\') {
                        char e = j + 1 < src.length() ? src.charAt(j + 1) : '\0';
                        boolean has = j + 1 < src.length();
                        String mapped = !has ? null : e == '\\' ? "\\" : e == '"' ? "\"" : e == '\'' ? "'" : e == 'n' ? "\n" : e == 't' ? "\t" : e == 'r' ? "\r" : null;
                        if (mapped == null) throw rej("unsupported", "string escape \\" + (has ? String.valueOf(e) : ""), j);
                        s.append(mapped);
                        j += 2;
                        continue;
                    }
                    s.append(d);
                    j++;
                }
                if (s.length() > MAX_STR) throw rej("too_complex", "string literal longer than " + MAX_STR, i);
                out.add(new Tok('s', s.toString(), i));
                i = j + 1;
                continue;
            }
            String p = null;
            for (String x : PUNCT) if (src.startsWith(x, i)) { p = x; break; }
            if (p == null) {
                String u = unsupportedChar(c);
                throw rej(u != null ? "unsupported" : "syntax", u != null ? u : "unexpected character '" + c + "'", i);
            }
            out.add(new Tok('p', p, i));
            i += p.length();
        }
        return out;
    }

    // ---- parser ----

    /** An AST node of the parsed subset (see {@link #toJson}). */
    private static final class Node {
        final String t; // or and not rel int str bool ts list var has method
        int at;
        String op, name, fn;
        Node l, r, e, target, arg;
        long iv;
        String sv;
        boolean bv;
        List<Node> items;
        Node(String t, int at) { this.t = t; this.at = at; }
        Node copyWithName(String name) { Node c = new Node("var", at); c.name = name; return c; }
    }

    private static final Set<String> RELOPS = Set.of("==", "!=", "<", "<=", ">", ">=");
    private static final Set<String> REJECTED_FUNCS = Set.of("size", "matches", "exists", "all", "exists_one", "map", "filter", "int", "uint", "double", "string", "bytes", "bool",
        "duration", "type", "dyn", "min", "max", "getHours", "getDayOfWeek", "getMinutes", "getSeconds", "getFullYear", "getMonth", "getDate", "getDayOfMonth", "getDayOfYear",
        "getMilliseconds", "extract", "format", "lowerAscii", "upperAscii", "trim", "split", "join", "replace", "substring", "indexOf", "lastIndexOf", "charAt", "isIpv4",
        "inIpRange", "cidr", "ip", "isCIDR", "containsIp", "url", "quantity", "semver", "optional");

    private static final class Parser {
        final String src;
        final List<Tok> toks;
        int pos = 0, nodes = 0;
        Parser(String src, List<Tok> toks) { this.src = src; this.toks = toks; }

        Tok peek() { return pos < toks.size() ? toks.get(pos) : null; }
        boolean isP(String v) { Tok t = peek(); return t != null && t.k == 'p' && t.v.equals(v); }
        boolean eat(String v) { if (isP(v)) { pos++; return true; } return false; }
        int peekAt(int dflt) { Tok t = peek(); return t == null ? dflt : t.at; }
        void need(String v) { if (!eat(v)) throw rej("syntax", "expected '" + v + "'", peekAt(src.length())); }
        void tick(int at) { if (++nodes > MAX_NODES) throw rej("too_complex", "more than " + MAX_NODES + " nodes", at); }

        Node expr(int d) {
            if (d > MAX_DEPTH) throw rej("too_complex", "nesting deeper than " + MAX_DEPTH, peekAt(0));
            return or(d);
        }

        Node or(int d) {
            Node l = and(d);
            while (isP("||")) {
                int at = peek().at;
                pos++;
                tick(at);
                Node n = new Node("or", at);
                n.l = l;
                n.r = and(d);
                l = n;
            }
            return l;
        }

        Node and(int d) {
            Node l = rel(d);
            while (isP("&&")) {
                int at = peek().at;
                pos++;
                tick(at);
                Node n = new Node("and", at);
                n.l = l;
                n.r = rel(d);
                l = n;
            }
            return l;
        }

        private boolean isRelTok(Tok u) { return u != null && ((u.k == 'p' && RELOPS.contains(u.v)) || (u.k == 'i' && u.v.equals("in"))); }

        Node rel(int d) {
            Node l = unary(d);
            Tok t = peek();
            if (t == null) return l;
            boolean isIn = t.k == 'i' && t.v.equals("in");
            if (!isIn && !(t.k == 'p' && RELOPS.contains(t.v))) return l;
            pos++;
            tick(t.at);
            Node n = new Node("rel", t.at);
            n.op = isIn ? "in" : t.v;
            n.l = l;
            n.r = unary(d);
            Tok u = peek();
            if (isRelTok(u)) throw rej("unsupported", "chained comparison", u.at);
            return n;
        }

        Node unary(int d) {
            Tok t = peek();
            if (t != null && t.k == 'p' && t.v.equals("!")) {
                pos++;
                tick(t.at);
                if (d + 1 > MAX_DEPTH) throw rej("too_complex", "nesting deeper than " + MAX_DEPTH, t.at);
                Node n = new Node("not", t.at);
                n.e = unary(d + 1);
                return n;
            }
            if (t != null && t.k == 'p' && t.v.equals("-")) {
                Tok nx = pos + 1 < toks.size() ? toks.get(pos + 1) : null;
                if (nx == null || nx.k != 'n') throw rej("unsupported", "unary minus on a non-literal", t.at);
                pos += 2;
                return intNode("-" + nx.v, t.at);
            }
            return member(d);
        }

        Node intNode(String text, int at) {
            tick(at);
            double v = Double.parseDouble(text);
            if (!(v == Math.rint(v) && Math.abs(v) <= 9007199254740991.0)) throw rej("unsupported", "integer literal outside the safe-integer range", at);
            Node n = new Node("int", at);
            n.iv = (long) v;
            return n;
        }

        List<Node> args(int d) {
            List<Node> a = new ArrayList<>();
            if (!isP(")")) { do a.add(expr(d + 1)); while (eat(",")); }
            need(")");
            return a;
        }

        Node member(int d) {
            Node n = primary(d);
            while (isP(".")) {
                Tok dot = peek();
                pos++;
                Tok id = peek();
                if (id == null || id.k != 'i') throw rej("syntax", "expected a name after '.'", dot.at);
                pos++;
                if (isP("(")) {
                    pos++;
                    List<Node> a = args(d);
                    if (!id.v.equals("startsWith") && !id.v.equals("endsWith") && !id.v.equals("contains")) throw rej("unsupported", "method '" + id.v + "'", id.at);
                    if (a.size() != 1) throw rej("syntax", "'" + id.v + "' takes one argument", id.at);
                    tick(id.at);
                    Node m = new Node("method", id.at);
                    m.target = n;
                    m.fn = id.v;
                    m.arg = a.get(0);
                    n = m;
                } else {
                    if (!n.t.equals("var")) throw rej("unsupported", "field selection on something that is not a declared variable", dot.at);
                    n = n.copyWithName(n.name + "." + id.v);
                }
            }
            if (isP("[")) throw rej("unsupported", "index operator", peek().at);
            return n;
        }

        Node primary(int d) {
            Tok t = peek();
            if (t == null) throw rej("syntax", "unexpected end of expression", src.length());
            if (t.k == 'n') { pos++; return intNode(t.v, t.at); }
            if (t.k == 's') { pos++; tick(t.at); Node s = new Node("str", t.at); s.sv = t.v; return s; }
            if (t.k == 'p' && t.v.equals("(")) { pos++; Node e = expr(d + 1); need(")"); return e; }
            if (t.k == 'p' && t.v.equals("[")) {
                pos++;
                List<Node> items = new ArrayList<>();
                if (!isP("]")) {
                    do {
                        if (items.size() >= MAX_LIST) throw rej("too_complex", "list longer than " + MAX_LIST, t.at);
                        items.add(expr(d + 1));
                    } while (eat(","));
                }
                need("]");
                tick(t.at);
                Node l = new Node("list", t.at);
                l.items = items;
                return l;
            }
            if (t.k == 'i') {
                pos++;
                if (t.v.equals("true") || t.v.equals("false")) { tick(t.at); Node b = new Node("bool", t.at); b.bv = t.v.equals("true"); return b; }
                if (t.v.equals("null")) throw rej("unsupported", "null", t.at);
                if (isP("(")) {
                    pos++;
                    List<Node> a = args(d);
                    if (t.v.equals("has")) {
                        if (a.size() != 1 || !a.get(0).t.equals("var")) throw rej("syntax", "has() takes one declared variable", t.at);
                        tick(t.at);
                        Node h = new Node("has", t.at);
                        h.e = a.get(0);
                        return h;
                    }
                    if (t.v.equals("timestamp")) {
                        Node s = a.isEmpty() ? null : a.get(0);
                        if (a.size() != 1 || s == null || !s.t.equals("str")) throw rej("unsupported", "timestamp() of a non-literal", t.at);
                        Node ts = new Node("ts", t.at);
                        ts.iv = parseTimestamp(s.sv, t.at);
                        return ts;
                    }
                    throw rej("unsupported", REJECTED_FUNCS.contains(t.v) ? "function '" + t.v + "'" : "unknown function '" + t.v + "'", t.at);
                }
                if (t.v.equals("in")) throw rej("syntax", "unexpected 'in'", t.at);
                tick(t.at);
                Node v = new Node("var", t.at);
                v.name = t.v;
                return v;
            }
            throw rej("syntax", "unexpected '" + t.v + "'", t.at);
        }

        Node root() {
            Node r = expr(0);
            if (pos < toks.size()) throw rej("syntax", "unexpected '" + toks.get(pos).v + "'", toks.get(pos).at);
            return r;
        }
    }

    private static final Pattern TIMESTAMP = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,3}))?Z");

    private static long parseTimestamp(String s, int at) {
        Matcher m = TIMESTAMP.matcher(s);
        if (!m.matches()) throw rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at);
        String frac = m.group(7) == null ? "" : m.group(7);
        while (frac.length() < 3) frac += "0";
        try {
            LocalDateTime t = LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
                Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6)), Integer.parseInt(frac) * 1_000_000);
            return t.toInstant(ZoneOffset.UTC).toEpochMilli();
        } catch (DateTimeException e) {
            throw rej("unsupported", "timestamp() is not a real instant", at);
        }
    }

    private static Node parse(String src) {
        if (src == null || src.isEmpty()) throw rej("syntax", "empty expression", 0);
        if (src.length() > MAX_EXPR) throw rej("too_complex", "expression longer than " + MAX_EXPR + " characters", 0);
        return new Parser(src, lex(src)).root();
    }

    /** The AST as the reference prints it (a node is {@code {t, ..., at}}). */
    private static Object toJson(Node x) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", x.t);
        switch (x.t) {
            case "or": case "and": m.put("l", toJson(x.l)); m.put("r", toJson(x.r)); break;
            case "not": m.put("e", toJson(x.e)); break;
            case "rel": m.put("op", x.op); m.put("l", toJson(x.l)); m.put("r", toJson(x.r)); break;
            case "int": case "ts": m.put("v", n(x.iv)); break;
            case "str": m.put("v", x.sv); break;
            case "bool": m.put("v", x.bv); break;
            case "list": { List<Object> l = new ArrayList<>(); for (Node i : x.items) l.add(toJson(i)); m.put("items", l); break; }
            case "var": m.put("name", x.name); break;
            case "has": m.put("e", toJson(x.e)); break;
            default: m.put("target", toJson(x.target)); m.put("fn", x.fn); m.put("arg", toJson(x.arg)); break;
        }
        m.put("at", n(x.at));
        return m;
    }

    /** Parse a CEL expression of the supported subset into its tree {@code {ok:true, ast}}, or the refusal. */
    public static Map<String, Object> parseCel(String expression) {
        try {
            return Js.obj("ok", true, "ast", toJson(parse(expression)));
        } catch (Reject e) {
            return fail(e);
        } catch (RuntimeException | StackOverflowError e) {
            return Js.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0));
        }
    }

    private static Map<String, Object> fail(Reject e) { return Js.obj("ok", false, "code", e.code, "message", e.getMessage(), "at", n(e.at)); }

    // ---- translation ----

    private static boolean isIdent(String s) {
        if (s.isEmpty() || !Js.isIdentStart(s.charAt(0))) return false;
        for (int i = 1; i < s.length(); i++) if (!Js.isIdentPart(s.charAt(i))) return false;
        return true;
    }

    private static boolean isDottedIdent(String s, int minParts, Set<String> roots) {
        String[] parts = s.split("\\.", -1);
        if (parts.length < minParts) return false;
        for (int i = 0; i < parts.length; i++) {
            if (i == 0 && roots != null) { if (!roots.contains(parts[0])) return false; continue; }
            if (!isIdent(parts[i])) return false;
        }
        return true;
    }

    private static boolean forbiddenPart(String s) {
        for (String p : s.split("\\.", -1)) if (FORBIDDEN.contains(p)) return true;
        return false;
    }

    private static final Set<String> PCA_ROOTS = Set.of("action", "subject", "env");

    private static String schemaError(Object s) {
        if (!(s instanceof Map)) return "the schema must be an object";
        Object vars = ((Map<?, ?>) s).get("vars");
        if (!(vars instanceof Map)) return "the schema needs a vars object";
        @SuppressWarnings("unchecked") Map<String, Object> vm = (Map<String, Object>) vars;
        for (String name : Js.entryKeys(vm)) {
            Object v = vm.get(name);
            if (!isDottedIdent(name, 1, null) || forbiddenPart(name)) return "bad variable name '" + name + "'";
            Object path = v instanceof Map ? ((Map<?, ?>) v).get("path") : null;
            if (!(v instanceof Map) || !(path instanceof String) || !isDottedIdent((String) path, 2, PCA_ROOTS) || forbiddenPart((String) path)) {
                return "variable '" + name + "' needs a path rooted at action, subject or env";
            }
            Object type = ((Map<?, ?>) v).get("type");
            if (!(type instanceof String) || !TYPES.contains(type)) return "variable '" + name + "' has an unsupported type";
            if (((Map<?, ?>) v).containsKey("optional") && !(((Map<?, ?>) v).get("optional") instanceof Boolean)) return "variable '" + name + "': optional must be a boolean";
        }
        return null;
    }

    /** A comparison operand: a declared variable or a typed literal. */
    private static final class Operand {
        final boolean isVar;
        final String type, path, name;
        final boolean optional;
        final Object value; // literal: Json.Num / String / Boolean
        Operand(boolean isVar, String type, String path, String name, boolean optional, Object value) {
            this.isVar = isVar; this.type = type; this.path = path; this.name = name; this.optional = optional; this.value = value;
        }
    }

    private static final class Translator {
        final Map<String, Object> vars;
        final Set<String> fields = new TreeSet<>();
        Translator(Map<String, Object> vars) { this.vars = vars; }

        Operand operand(Node n) {
            switch (n.t) {
                case "var": {
                    Object v = vars.containsKey(n.name) ? vars.get(n.name) : null;
                    if (v == null) throw rej("unknown_identifier", "'" + n.name + "' is not declared in the schema", n.at);
                    Map<?, ?> vm = (Map<?, ?>) v;
                    return new Operand(true, (String) vm.get("type"), (String) vm.get("path"), n.name, Boolean.TRUE.equals(vm.get("optional")), null);
                }
                case "int": return new Operand(false, "int", null, null, false, n(n.iv));
                case "str": return new Operand(false, "string", null, null, false, n.sv);
                case "bool": return new Operand(false, "bool", null, null, false, n.bv);
                case "ts": return new Operand(false, "timestamp_ms", null, null, false, n(n.iv));
                default: throw rej("unsupported", "a computed value as a comparison operand", n.at);
            }
        }

        String read(Operand o) { fields.add(o.path); return o.path; }

        void flat(Node n, String t, List<Node> out) {
            if (n.t.equals(t)) { flat(n.l, t, out); flat(n.r, t, out); } else out.add(n);
        }

        Map<String, Object> tr(Node n) {
            switch (n.t) {
                case "or": case "and": {
                    List<Node> parts = new ArrayList<>();
                    flat(n, n.t, parts);
                    List<Object> out = new ArrayList<>();
                    for (Node p : parts) out.add(tr(p));
                    return Js.obj(n.t.equals("or") ? "any_of" : "all_of", out);
                }
                case "not": return Js.obj("not", tr(n.e));
                case "has": {
                    Operand o = operand(n.e);
                    if (!o.optional) throw rej("has_requires_optional", "has(" + o.name + "): mark the variable optional in the schema (its container must always be present)", n.at);
                    return Js.obj("field", read(o), "op", "exists", "value", Boolean.TRUE);
                }
                case "var": {
                    Operand o = operand(n);
                    throw rej("unsupported", "a bare variable '" + n.name + "' as a condition" + (o.isVar && o.type.equals("bool") ? " (write " + n.name + " == true)" : ""), n.at);
                }
                case "method": {
                    Operand t = operand(n.target);
                    if (!t.isVar || !t.type.equals("string")) throw rej("type_mismatch", n.fn + " needs a string variable", n.at);
                    if (!n.arg.t.equals("str") || n.arg.sv.isEmpty()) throw rej("unsupported", n.fn + " of anything but a non-empty string literal", n.at);
                    String lit = n.arg.sv;
                    if (n.fn.equals("startsWith")) return Js.obj("field", read(t), "op", "prefix", "value", lit);
                    StringBuilder esc = new StringBuilder();
                    for (int i = 0; i < lit.length(); i++) {
                        char c = lit.charAt(i);
                        if (c == '\\' || c == '*' || c == '?') esc.append('\\');
                        esc.append(c);
                    }
                    String glob = n.fn.equals("endsWith") ? "*" + esc : "*" + esc + "*";
                    if (glob.length() > 512) throw rej("too_complex", "literal too long for a glob", n.at);
                    return Js.obj("field", read(t), "op", "like", "value", glob);
                }
                case "rel": return rel(n);
                default: throw rej("constant_expression", "a bare constant is not a condition", n.at);
            }
        }

        Map<String, Object> rel(Node n) {
            if (n.op.equals("in")) {
                Operand l = operand(n.l);
                if (!l.isVar) throw rej("constant_expression", "the left side of \"in\" must be a declared variable", n.at);
                if (!n.r.t.equals("list") || n.r.items.isEmpty()) throw rej("unsupported", "\"in\" against anything but a non-empty list literal", n.at);
                List<Operand> items = new ArrayList<>();
                for (Node i : n.r.items) items.add(operand(i));
                for (Operand i : items) if (i.isVar || !i.type.equals(l.type)) throw rej("type_mismatch", "list items must be " + l.type + " literals", n.at);
                String field = read(l);
                List<Object> values = new ArrayList<>();
                for (Operand i : items) values.add(i.value);
                return Js.obj("field", field, "op", "in", "value", values);
            }
            Operand l = operand(n.l);
            Operand r = operand(n.r);
            if (!l.isVar && !r.isVar) throw rej("constant_expression", "a comparison of two literals", n.at);
            if (!l.type.equals(r.type)) throw rej("type_mismatch", l.type + " against " + r.type, n.at);
            String ty = l.type;
            boolean eqOp = n.op.equals("==") || n.op.equals("!=");
            if (!eqOp && ty.equals("bool")) throw rej("type_mismatch", "ordering of booleans", n.at);
            String pcaOp = n.op.equals("==") ? "eq" : n.op.equals("!=") ? "ne" : n.op.equals("<") ? "lt" : n.op.equals("<=") ? "lte" : n.op.equals(">") ? "gt" : "gte";
            if (l.isVar && r.isVar) return Js.obj("field", read(l), "op", pcaOp, "ref", read(r));
            if (l.isVar) return Js.obj("field", read(l), "op", pcaOp, "value", r.value);
            String flip = pcaOp.equals("lt") ? "gt" : pcaOp.equals("lte") ? "gte" : pcaOp.equals("gt") ? "lt" : pcaOp.equals("gte") ? "lte" : pcaOp;
            return Js.obj("field", read(r), "op", flip, "value", l.value);
        }
    }

    /** Translate one boolean CEL expression over {@code schema} ({@code {vars: {name: {path, type, optional?}}}}) into a PCA condition. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> celToCondition(String expression, Object schema) {
        String se = schemaError(schema);
        if (se != null) return Js.obj("ok", false, "code", "bad_schema", "message", se, "at", n(0));
        try {
            Node ast = parse(expression);
            Translator t = new Translator((Map<String, Object>) ((Map<?, ?>) schema).get("vars"));
            Map<String, Object> condition = t.tr(ast);
            if (t.fields.isEmpty()) throw rej("constant_expression", "the expression reads no variable", 0);
            return Js.obj("ok", true, "condition", condition, "fields", new ArrayList<Object>(t.fields));
        } catch (Reject e) {
            return fail(e);
        } catch (RuntimeException | StackOverflowError e) {
            return Js.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0));
        }
    }

    /** One expression as a permit predicate for {@code verb} (a string or a list of strings) and optionally {@code resource}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> celToPredicate(String expression, Object schema, Object verb, String resource) {
        Map<String, Object> r = celToCondition(expression, schema);
        if (!Boolean.TRUE.equals(r.get("ok"))) return r;
        Map<String, Object> predicate = new LinkedHashMap<>();
        predicate.put("verb", verb);
        if (resource != null) predicate.put("resource", resource);
        List<Object> where = new ArrayList<>();
        where.add(r.get("condition"));
        predicate.put("where", where);
        return Js.obj("ok", true, "predicate", predicate, "fields", r.get("fields"));
    }

    /**
     * A batch (an IAM policy's bindings, a VAP's validations): every item ({@code {name, expression, verb, resource?}}) is
     * translated or reported. One rejection makes the report's errors non-empty, and {@link PolicyBridge#decide} then denies
     * everything (an incomplete import never grants).
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> celConditionsToPca(List<Map<String, Object>> items, Object schema) {
        List<Object> predicates = new ArrayList<>(), translated = new ArrayList<>(), errors = new ArrayList<>();
        for (Map<String, Object> it : items) {
            Object res = it.get("resource");
            Map<String, Object> r = celToPredicate((String) it.get("expression"), schema, it.get("verb"), (String) res);
            String name = String.valueOf(it.get("name"));
            if (Boolean.TRUE.equals(r.get("ok"))) {
                predicates.add(r.get("predicate"));
                List<Object> fs = (List<Object>) r.get("fields");
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < fs.size(); i++) { if (i > 0) sb.append(", "); sb.append(fs.get(i)); }
                translated.add(name + ": translated exactly (reads " + sb + ")");
            } else {
                errors.add(name + ": rejected (" + r.get("code") + ") at " + r.get("at") + ": " + r.get("message"));
            }
        }
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("source", "cel");
        report.put("translated", translated);
        report.put("skipped", new ArrayList<Object>());
        report.put("errors", errors);
        return PolicyBridge.result(predicates, new ArrayList<>(), report);
    }
}
