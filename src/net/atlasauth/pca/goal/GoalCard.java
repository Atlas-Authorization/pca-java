package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers. */
public final class GoalCard {
    private GoalCard() {}

    public static String q(Object x) { return G.quote(x); }

    private static String s(Object o) { return G.jsStr(o); }

    private static Map<String, Object> mm(Object o) { return G.obj(o, "value"); }

    public static String unit(Map<String, Object> u) { return G.kind(u).equals("money") ? s(u.get("ccy")) + " minor units" : G.kind(u); }

    public static String quantity(Map<String, Object> x) { return s(x.get("n")) + " " + unit(mm(x.get("u"))); }

    /** {@link #quantity}, under the name the package index exports. */
    public static String renderQuantity(Map<String, Object> x) { return quantity(x); }

    /** {@link #cond}, under the name the package index exports. */
    public static String renderCond(Map<String, Object> c) { return cond(c); }

    public static String value(Map<String, Object> v) {
        String k = G.kind(v);
        if (k.equals("q")) return quantity(mm(v.get("q")));
        if (k.equals("s")) return q(v.get("s"));
        return "{" + join(G.arr(v.get("items"), "items"), i -> value(mm(i)), ", ") + "}";
    }

    private static String join(List<Object> xs, Function<Object, String> f, String sep) {
        List<String> out = new ArrayList<>();
        for (Object x : xs) out.add(f.apply(x));
        return String.join(sep, out);
    }

    public static String term(Map<String, Object> t) {
        String k = G.kind(t);
        if (k.equals("param")) {
            Map<String, Object> ty = mm(t.get("ty"));
            return "param " + q(t.get("path")) + " (" + (G.kind(ty).equals("q") ? unit(mm(ty.get("u"))) : "text") + ")";
        }
        if (k.equals("lit")) return value(mm(t.get("v")));
        return "running total of bound " + q(t.get("bid")) + " (" + unit(mm(t.get("u"))) + ")";
    }

    private static final Map<String, String> OPW = new LinkedHashMap<>();
    static {
        OPW.put("eq", "="); OPW.put("ne", "!="); OPW.put("lt", "<"); OPW.put("lte", "<="); OPW.put("gt", ">"); OPW.put("gte", ">=");
        OPW.put("in", "is one of"); OPW.put("nin", "is none of");
    }

    public static String cond(Map<String, Object> c) {
        switch (G.kind(c)) {
            case "true": return "always";
            case "cmp": return term(mm(c.get("l"))) + " " + java.util.Objects.requireNonNullElse(OPW.get(s(c.get("op"))), "undefined") + " " + term(mm(c.get("r")));
            case "and": return "(" + cond(mm(c.get("a"))) + ") AND (" + cond(mm(c.get("b"))) + ")";
            case "or": return "(" + cond(mm(c.get("a"))) + ") OR (" + cond(mm(c.get("b"))) + ")";
            case "not": return "NOT (" + cond(mm(c.get("c"))) + ")";
            default: throw new IrError("unknown condition");
        }
    }

    public static String res(Map<String, Object> r) {
        switch (G.kind(r)) {
            case "exact": return "exactly " + q(r.get("id"));
            case "oneof": return "one of [" + join(G.arr(r.get("ids"), "ids"), GoalCard::q, ", ") + "]";
            case "related": return s(r.get("rel")) + " of " + q(r.get("anchor"));
            case "all_of": return "ALL OF (" + join(G.arr(r.get("parts"), "parts"), p -> res(mm(p)), " AND ") + ")";
            default: return "ANY RESOURCE (reason: " + q(r.get("reason")) + ")";
        }
    }

    public static String win(Map<String, Object> w) {
        switch (G.kind(w)) {
            case "task": return "per task";
            case "lifetime": return "over the lifetime";
            case "sliding": return "in any " + s(w.get("ms")) + " ms window";
            default: return "per " + s(w.get("ms")) + " ms period starting at " + s(w.get("t0"));
        }
    }

    public static String scope(Map<String, Object> sc) {
        return G.kind(sc).equals("fleet") ? "fleet [" + join(G.arr(sc.get("agents"), "agents"), GoalCard::q, ", ") + "]" : G.kind(sc);
    }

    public static String grantLine(Map<String, Object> x) {
        return "ALLOW " + q(x.get("gid")) + ": verb " + q(x.get("verb")) + " on " + res(mm(x.get("res"))) + " when " + cond(mm(x.get("cond")));
    }

    public static String prohibitLine(Map<String, Object> x) {
        Map<String, Object> t = mm(x.get("target"));
        String tgt = G.kind(t).equals("verb") ? "verb " + q(t.get("verb")) : "every verb of effect class " + q(t.get("cls"));
        return "NEVER " + q(x.get("pid")) + ": " + tgt + " on " + res(mm(x.get("res"))) + " when " + cond(mm(x.get("cond")));
    }

    public static String boundLine(Map<String, Object> b) {
        Map<String, Object> sel = mm(b.get("sel"));
        String over = G.kind(sel).equals("gids") ? "grants [" + join(G.arr(sel.get("gids"), "gids"), GoalCard::q, ", ") + "]" : "effect class " + q(sel.get("cls"));
        String agg = s(b.get("agg"));
        String of = agg.equals("count") ? "" : agg.equals("distinct") ? " of " + q(b.get("key")) : " of " + term(mm(b.get("value")));
        return "LIMIT " + q(b.get("bid")) + ": " + agg + of + " over " + over + ", " + win(mm(b.get("window"))) + ", scope " + scope(mm(b.get("scope")))
            + ", at most " + quantity(mm(b.get("cap"))) + "; beyond that: " + ("deny".equals(b.get("onExceed")) ? "deny" : "ask the principal");
    }

    public static String validityLine(Map<String, Object> v) {
        return "VALID from " + s(v.get("notBefore")) + " to " + s(v.get("notAfter")) + "; idle limit " + (G.toNum(v.get("maxIdle")) > 0 ? s(v.get("maxIdle")) + " ms" : "none");
    }

    public static String delegationLine(Map<String, Object> d) {
        return "DELEGATION depth at most " + s(d.get("maxDepth")) + ", narrow only " + s(d.get("narrowOnly")) + ", delegates may use grants ["
            + join(G.arr(d.get("mayTouch"), "mayTouch"), GoalCard::q, ", ") + "]";
    }

    public static String escalateLine(Map<String, Object> c) { return "ASK THE PRINCIPAL when " + cond(c); }

    public static String holeLine(Map<String, Object> h) {
        return "UNRESOLVED " + q(h.get("hid")) + ": " + q(h.get("q")) + " options [" + join(G.arr(h.get("domain"), "domain"), GoalCard::q, ", ") + "] affects "
            + (G.truthy(h.get("global")) ? "everything" : "[" + join(G.arr(h.get("affects"), "affects"), GoalCard::q, ", ") + "]");
    }

    /** One line per clause in canonical order, plus the warnings the principal must look at twice: {lines, warnings}. */
    public static Map<String, Object> renderCard(Map<String, Object> g) {
        List<Object> lines = new ArrayList<>();
        List<Object> warnings = new ArrayList<>();
        lines.add("Goal v" + s(g.get("v")) + " for principal " + q(g.get("principal")) + "; ontology " + q(g.get("ontDigest")) + "; request text digest " + q(g.get("nlDigest")));
        for (Object x : G.arr(g.get("sources"), "sources")) lines.add("Source " + q(x));
        List<Object> ack = G.arr(g.get("wildcardAck"), "wildcardAck");
        for (Object x : G.arr(g.get("grants"), "grants")) {
            Map<String, Object> gr = mm(x);
            lines.add(grantLine(gr));
            if (G.kind(gr.get("res")).equals("any")) warnings.add("grant " + q(gr.get("gid")) + " applies to every resource" + (ack.contains(gr.get("gid")) ? " (acknowledged)" : " (NOT acknowledged)"));
        }
        for (Object x : G.arr(g.get("prohibits"), "prohibits")) lines.add(prohibitLine(mm(x)));
        for (Object b : G.arr(g.get("bounds"), "bounds")) lines.add(boundLine(mm(b)));
        lines.add(validityLine(mm(g.get("validity"))));
        lines.add(delegationLine(mm(g.get("deleg"))));
        for (Object c : G.arr(g.get("escalateOn"), "escalateOn")) lines.add(escalateLine(mm(c)));
        for (Object a : ack) lines.add("Wildcard acknowledged for " + q(a));
        List<Object> holes = G.arr(g.get("holes"), "holes");
        for (Object h : holes) lines.add(holeLine(mm(h)));
        if (!holes.isEmpty()) warnings.add("this goal has unresolved questions and cannot be signed");
        return G.map("lines", lines, "warnings", warnings);
    }
}
