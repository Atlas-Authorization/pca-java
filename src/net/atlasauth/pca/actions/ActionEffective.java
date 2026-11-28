package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.Actions;

/**
 * From an action def to its trait set T(d), declared profile decl(d) and effective profile {@code eff_R(d) = decl(d) join F_R(T(d))}, plus the
 * structural param rules and the profile lattice over profile maps ({@code {risk, rev, blast_ppm, esc, caveats, context, prules}}).
 */
public final class ActionEffective {
    private ActionEffective() {}

    public static final List<String> PARAM_RULE_IDS = List.of("array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
        "pay_has_idempotency", "recipient_param_declared", "secret_not_logged");

    // ---- profile lattice ----
    private static int rank(Object rev) { return ActionsBridge.revRank((String) rev); }

    private static List<Object> union(Object a, Object b) {
        TreeSet<String> s = new TreeSet<>();
        for (Object x : J.a(a)) s.add((String) x);
        for (Object x : J.a(b)) s.add((String) x);
        return J.objs(new ArrayList<>(s));
    }

    private static boolean subset(Object a, Object b) { return J.a(b).containsAll(J.a(a)); }

    private static long l(Object o) { return J.num(o).longValue(); }

    /** The least upper bound of two profiles. */
    public static Map<String, Object> join(Map<String, Object> p, Map<String, Object> q) {
        return J.obj("risk", J.n(Math.max(l(p.get("risk")), l(q.get("risk")))), "rev", rank(p.get("rev")) >= rank(q.get("rev")) ? p.get("rev") : q.get("rev"),
            "blast_ppm", J.n(Math.max(l(p.get("blast_ppm")), l(q.get("blast_ppm")))), "esc", J.n(Math.max(l(p.get("esc")), l(q.get("esc")))),
            "caveats", union(p.get("caveats"), q.get("caveats")), "context", union(p.get("context"), q.get("context")), "prules", union(p.get("prules"), q.get("prules")));
    }

    public static boolean leq(Map<String, Object> p, Map<String, Object> q) {
        return l(p.get("risk")) <= l(q.get("risk")) && rank(p.get("rev")) <= rank(q.get("rev")) && l(p.get("blast_ppm")) <= l(q.get("blast_ppm")) && l(p.get("esc")) <= l(q.get("esc"))
            && subset(p.get("caveats"), q.get("caveats")) && subset(p.get("context"), q.get("context")) && subset(p.get("prules"), q.get("prules"));
    }

    public static boolean profileEq(Map<String, Object> p, Map<String, Object> q) { return leq(p, q) && leq(q, p); }

    // ---- effective ----

    /** What a verifier decides about a {@code confirmed} review: true iff its attestation is valid. Null = never confirmed. */
    public static boolean isConfirmed(Map<String, Object> d, Predicate<Map<String, Object>> attestationVerified) { return attestationVerified != null && attestationVerified.test(d); }

    /** The hint traits: declared plus implied by the def's own facts. */
    public static List<String> hintTraits(Map<String, Object> d) { return ActionsBridge.hintTraits(d); }

    /** T(d): the top of the registry unless a signed confirmation counts. */
    public static List<String> traitsOf(Map<String, Object> d, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        return isConfirmed(d, attestationVerified) ? hintTraits(d) : Actions.topTraits(reg);
    }

    private static Map<String, Object> view(Map<String, Object> decl, Actions.Registry reg, List<String> traits) {
        Map<String, Object> floor = Actions.floorOf(reg, traits).toMap();
        return J.obj("traits", J.objs(traits), "closure", J.objs(Actions.closure(reg, traits)), "floor", floor, "eff", join(decl, floor));
    }

    /** {traits, closure, floor, eff, confirmed, decl, hint: {traits, closure, floor, eff}, clamps}. */
    public static Map<String, Object> effective(Map<String, Object> d, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Object> decl = Actions.declProfile(d).toMap();
        Map<String, Object> hint = view(decl, reg, hintTraits(d));
        boolean confirmed = isConfirmed(d, attestationVerified);
        Map<String, Object> main = confirmed ? hint : view(decl, reg, Actions.topTraits(reg));
        List<Object> clamps = new ArrayList<>();
        Map<String, Object> hf = J.m(hint.get("floor"));
        if (d.get("reversibility") != null && rank(decl.get("rev")) < rank(hf.get("rev"))) clamps.add(J.obj("field", "rev", "declared", decl.get("rev"), "floor", hf.get("rev")));
        if (d.get("blast") != null && l(decl.get("blast_ppm")) < l(hf.get("blast_ppm"))) clamps.add(J.obj("field", "blast_ppm", "declared", decl.get("blast_ppm"), "floor", hf.get("blast_ppm")));
        Map<String, Object> out = new LinkedHashMap<>(main);
        out.put("confirmed", confirmed);
        out.put("decl", decl);
        out.put("hint", hint);
        out.put("clamps", clamps);
        return out;
    }

    /** The hint profile after adding trait {@code t} to the declared traits (never lower). Analysis only. */
    public static Map<String, Object> effWithTrait(Map<String, Object> d, String t, Actions.Registry reg) {
        Map<String, Object> c = new LinkedHashMap<>(d);
        List<Object> tr = new ArrayList<>(d.get("traits") instanceof List ? J.a(d.get("traits")) : List.of());
        tr.add(t);
        c.put("traits", tr);
        return J.m(J.m(effective(c, reg, null).get("hint")).get("eff"));
    }

    // ---- structural param rules ----

    private static List<Map.Entry<String, Map<String, Object>>> withRole(Map<String, Object> params, Predicate<String> pred) {
        List<Map.Entry<String, Map<String, Object>>> out = new ArrayList<>();
        for (Map.Entry<String, Object> e : params.entrySet()) {
            Object r = J.m(e.getValue()).get("role");
            if (r instanceof String && pred.test((String) r)) out.add(Map.entry(e.getKey(), J.m(e.getValue())));
        }
        return out;
    }

    /** The rules the def violates, among {@code ids}; null = all of them. */
    public static List<String> prulesViolations(Map<String, Object> d, List<String> ids) {
        Map<String, Object> n = Actions.normalize(d);
        Map<String, Object> params = J.m(n.get("params"));
        Map<String, Object> res = J.m(n.get("resource"));
        List<String> bad = new ArrayList<>();
        for (String id : ids == null ? PARAM_RULE_IDS : ids) {
            boolean ok = true;
            switch (id) {
                case "money_has_currency":
                    for (Map.Entry<String, Map<String, Object>> e : withRole(params, r -> r.equals("money.amount") || r.equals("money.fee"))) {
                        Object u = e.getValue().get("unit");
                        if (!(u instanceof Map) || !"money".equals(J.get(u, "kind"))) { ok = false; break; }
                        Object ccy = J.get(u, "ccy");
                        if (ccy instanceof String) continue;
                        Object c = params.get((String) J.get(ccy, "from"));
                        if (!(c instanceof Map) || !"money.currency".equals(J.get(c, "role")) || !"iso_currency".equals(J.get(c, "format"))) { ok = false; break; }
                    }
                    break;
                case "money_amount_bounded":
                    for (Map.Entry<String, Map<String, Object>> e : withRole(params, r -> r.equals("money.amount"))) {
                        Map<String, Object> p = e.getValue();
                        if (!"integer".equals(p.get("type")) || p.get("min") == null || p.get("max") == null) { ok = false; break; }
                    }
                    break;
                case "id_not_wildcard":
                    ok = !("*".equals(res.get("id")) && "one".equals(res.get("scope")));
                    break;
                case "recipient_param_declared":
                    ok = "resource".equals(n.get("audience")) || !withRole(params, r -> r.equals("party.payee") || r.startsWith("contact.")).isEmpty();
                    break;
                case "array_bounded":
                    for (Object p : params.values()) if ("array".equals(J.get(p, "type")) && J.get(p, "max_items") == null) { ok = false; break; }
                    break;
                case "export_bounded":
                    ok = "one".equals(res.get("scope"));
                    if (!ok) for (Map.Entry<String, Map<String, Object>> e : withRole(params, r -> r.equals("count.limit"))) if (e.getValue().get("max") != null) { ok = true; break; }
                    break;
                case "secret_not_logged":
                    for (Map.Entry<String, Map<String, Object>> e : withRole(params, r -> r.startsWith("credential."))) {
                        Object tg = e.getValue().get("tags");
                        if (!(tg instanceof List) || !J.a(tg).contains("secret")) { ok = false; break; }
                    }
                    break;
                case "pay_has_idempotency":
                    ok = !J.a(n.get("effects")).contains("pay") || !"none".equals(J.get(n.get("idempotency"), "mode"));
                    break;
                default:
                    break;
            }
            if (!ok) bad.add(id);
        }
        return bad;
    }

    public static List<String> prulesViolations(Map<String, Object> d) { return prulesViolations(d, null); }

    /** The rules the effective profile requires but the def does not satisfy (the load-time check). */
    public static List<String> requiredPrulesViolated(Map<String, Object> d, Map<String, Object> eff) {
        List<String> ids = new ArrayList<>();
        for (Object x : J.a(eff.get("prules"))) ids.add((String) x);
        return prulesViolations(d, ids);
    }
}
