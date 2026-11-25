package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.Facade;

/**
 * liftLegacy: the total, conservative lift of the facade's {@code {permissions, limits}} input to a Goal plus IR ontology. The corrected
 * semantics of the facade's old limit bugs live here: {@code $200/day} is a SLIDING 86 400 000 ms sum bound (not a per-call ceiling plus a
 * one-day lifetime); a {@code $} limit on a verb with no amount field is an error; every limit is its own bound, so adding a limit only
 * narrows. Money parameters are integers in MINOR units of USD (cents).
 */
public final class GoalLegacy {
    private GoalLegacy() {}

    private static final Pattern PATTERN_RESOURCE = Pattern.compile("[*?]|^re:");

    private static Map<String, Object> usd() { return G.map("k", "money", "ccy", "USD"); }

    private static Map<String, Object> cmp(String op, Map<String, Object> l, Map<String, Object> r) { return G.map("k", "cmp", "op", op, "l", l, "r", r); }

    private static Map<String, Object> usdLit(long n) { return G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", usd(), "n", G.num(n)))); }

    /** JavaScript Math.round: nearest integer, ties toward +infinity. */
    private static double jsRound(double v) {
        double f = Math.floor(v);
        return v - f >= 0.5 ? f + 1 : f;
    }

    /**
     * Lift a legacy permission map ({@code {connector: [action, ...]}}) and limits ({@code {verb or action: "$500/day"}}) to
     * {goal, ontology}. {@code limits}, {@code catalog}, {@code notAfter}, {@code notBefore} and {@code nlDigest} may be null.
     */
    public static Map<String, Object> liftLegacy(Map<String, Object> permissions, Map<String, Object> limits, Catalog catalog, String principal, Long notAfter, Long notBefore, String nlDigest) {
        Map<String, Object> raw = limits != null ? limits : new java.util.LinkedHashMap<String, Object>();
        // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
        List<Catalog.Spec> specs = Facade.compilePolicy(permissions, null, catalog, null, null, 0L).actions;
        List<Object> grants = new ArrayList<>();
        List<Object> bounds = new ArrayList<>();
        List<Object> verbs = new ArrayList<>();
        for (Catalog.Spec s : specs) {
            String gid = "g:" + s.verb;
            String amountPath = s.amountField != null && !s.amountField.isEmpty() ? s.amountField : null;
            List<Object> params = new ArrayList<>();
            if (amountPath != null) params.add(G.map("path", amountPath, "ty", G.map("k", "q", "u", usd())));
            verbs.add(G.map("verb", s.verb, "cls", s.reversibility, "params", params));
            String resource = s.resource != null ? s.resource : "*";
            if (PATTERN_RESOURCE.matcher(resource).find() && !resource.equals("*")) throw new IllegalArgumentException("liftLegacy: resource pattern '" + resource + "' of " + s.verb + " is not expressible; name exact resources or acknowledge a wildcard");
            // own(verb) ?? own(action): a null verb limit falls through to the action; a present null action limit is malformed (parseLimit refuses it)
            Object rawLimit = raw.get(s.verb);
            boolean has = rawLimit != null;
            if (!has) { has = raw.containsKey(s.action); rawLimit = raw.get(s.action); }
            Map<String, Object> cond = G.map("k", "true");
            if (has) {
                Facade.ParsedLimit lim = Facade.parseLimit(rawLimit);
                if (lim.unit.equals("usd")) {
                    if (amountPath == null) throw new IllegalArgumentException("liftLegacy: '$' limit on '" + s.verb + "' but the catalog gives that verb no amount field, so the limit could not be enforced");
                    double mm = jsRound(lim.amount * 100);
                    if (Double.isNaN(mm) || Double.isInfinite(mm) || Math.abs(mm) > G.MAX_SAFE) throw new IllegalArgumentException("liftLegacy: limit for " + s.verb + " is out of range");
                    long minor = (long) mm;
                    Map<String, Object> amt = G.map("k", "param", "path", amountPath, "ty", G.map("k", "q", "u", usd()));
                    cond = G.map("k", "and", "a", cmp("gte", amt, usdLit(0)), "b", cmp("lte", amt, usdLit(minor)));
                    if (lim.periodMs != null) {
                        bounds.add(G.map("bid", "b:" + s.verb, "sel", G.map("k", "gids", "gids", G.list(gid)), "agg", "sum", "value", amt, "key", "",
                            "window", G.map("k", "sliding", "ms", G.num(lim.periodMs)), "scope", G.map("k", "session"), "cap", G.map("u", usd(), "n", G.num(minor)), "onExceed", "deny"));
                    }
                } else {
                    if (lim.amount != Math.rint(lim.amount) || Math.abs(lim.amount) > G.MAX_SAFE) throw new IllegalArgumentException("liftLegacy: count limit for " + s.verb + " must be a whole number");
                    Map<String, Object> count = G.map("k", "count");
                    bounds.add(G.map("bid", "b:" + s.verb, "sel", G.map("k", "gids", "gids", G.list(gid)), "agg", "count",
                        "value", G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", count, "n", G.num(1)))), "key", "",
                        "window", lim.periodMs != null ? G.map("k", "sliding", "ms", G.num(lim.periodMs)) : G.map("k", "lifetime"), "scope", G.map("k", "session"),
                        "cap", G.map("u", count, "n", G.num((long) lim.amount)), "onExceed", "deny"));
                }
            }
            grants.add(G.map("gid", gid, "verb", s.verb, "res", resource.equals("*") ? G.map("k", "any", "reason", "legacy default: no resource scope given") : G.map("k", "exact", "id", resource), "cond", cond));
        }
        grants.sort((a, b) -> G.cmp((String) G.get(a, "gid"), (String) G.get(b, "gid")));
        bounds.sort((a, b) -> G.cmp((String) G.get(a, "bid"), (String) G.get(b, "bid")));
        for (int i = 1; i < grants.size(); i++) if (G.get(grants.get(i), "gid").equals(G.get(grants.get(i - 1), "gid"))) throw new IllegalArgumentException("liftLegacy: duplicate grant " + G.get(grants.get(i), "gid"));
        List<Object> mayTouch = new ArrayList<>(), wildcardAck = new ArrayList<>();
        for (Object g : grants) { mayTouch.add(G.get(g, "gid")); if ("any".equals(G.kind(G.get(g, "res")))) wildcardAck.add(G.get(g, "gid")); }
        Map<String, Object> goal = G.map("v", G.num(1), "principal", principal, "ontDigest", "legacy-catalog", "nlDigest", nlDigest != null ? nlDigest : "", "sources", new ArrayList<Object>(),
            "grants", grants, "prohibits", new ArrayList<Object>(), "bounds", bounds,
            "validity", G.map("notBefore", G.num(notBefore != null ? notBefore : 0), "notAfter", G.num(notAfter != null ? notAfter : G.MAX_SAFE), "maxIdle", G.num(0)),
            "deleg", G.map("maxDepth", G.num(16), "narrowOnly", true, "mayTouch", mayTouch),
            "escalateOn", new ArrayList<Object>(), "wildcardAck", wildcardAck, "holes", new ArrayList<Object>());
        verbs.sort((a, b) -> G.cmp((String) G.get(a, "verb"), (String) G.get(b, "verb")));
        List<Object> uniq = new ArrayList<>();
        for (int i = 0; i < verbs.size(); i++) if (i == 0 || !G.get(verbs.get(i - 1), "verb").equals(G.get(verbs.get(i), "verb"))) uniq.add(verbs.get(i));
        return G.map("goal", goal, "ontology", G.map("verbs", uniq, "rels", new ArrayList<Object>()));
    }
}
