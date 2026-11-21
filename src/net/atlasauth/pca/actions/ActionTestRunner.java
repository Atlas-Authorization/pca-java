package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.Actions;

/**
 * Executable examples and generic property checks of an action pack: every def's examples run through the real pipeline in process (derive the schema,
 * conform the params, expand the floors, decide), plus T2 monotonicity over trait additions and subsets, digest stability across the JSON and YAML forms,
 * and the schema round trip (the example conforms; every mutation of it is refused). The example policy ({@code under}) is a small allow selector evaluated
 * here; it can only pre-authorize. Examples and property checks describe the action AS REVIEWED (its hint view): they are authoring tests, not enforcement.
 */
public final class ActionTestRunner {
    private ActionTestRunner() {}

    private static final List<String> SEL_KEYS = List.of("trait", "verb", "where", "caveats", "context");
    private static final List<String> CAVEAT_KINDS = List.of("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap");

    private static Map<String, Object> hintOf(Map<String, Object> d, Actions.Registry reg) {
        Map<String, Object> e = ActionEffective.effective(d, reg, null);
        Map<String, Object> out = new LinkedHashMap<>(e);
        out.putAll(J.m(e.get("hint")));
        out.put("confirmed", Boolean.TRUE);
        return out;
    }

    /** The example policy as a list of selectors, or the reason it is malformed. Returns {@code {sels}} or {@code {error}}. */
    private static Object parseUnder(Object under, boolean present) {
        if (!present) return new ArrayList<Object>();
        if (!(under instanceof Map)) return "under must be {allow: selector | [selector]}";
        for (String k : J.m(under).keySet()) if (!k.equals("allow")) return "under must be {allow: selector | [selector]}";
        Object allow = J.m(under).get("allow");
        List<Object> list = allow instanceof List ? J.a(allow) : J.list(allow);
        List<Object> out = new ArrayList<>();
        for (Object s : list) {
            if (!(s instanceof Map)) return "an allow selector has trait, verb, where, caveats, context";
            Map<String, Object> m = J.m(s);
            for (String k : m.keySet()) if (!SEL_KEYS.contains(k)) return "an allow selector has trait, verb, where, caveats, context";
            if (m.containsKey("trait") == m.containsKey("verb")) return "an allow selector names exactly one of trait and verb";
            if (m.containsKey("where") && !(m.get("where") instanceof Map)) return "where must be an object";
            if (m.containsKey("caveats")) {
                boolean ok = m.get("caveats") instanceof List;
                if (ok) for (Object c : J.a(m.get("caveats"))) if (!CAVEAT_KINDS.contains(c)) ok = false;
                if (!ok) return "caveats must be known caveat kinds";
            }
            out.add(m);
        }
        return out;
    }

    private static String domainOf(String v) { return v.substring(v.lastIndexOf('@') + 1).toLowerCase(Locale.ROOT); }

    /** The caveats of the grant a matching allow selector stands for, or null when it does not match this call. */
    private static List<String> grantOf(Map<String, Object> sel, Map<String, Object> d, Map<String, Object> flat, Map<String, Object> eff) {
        if (sel.containsKey("trait")) {
            String t = (String) sel.get("trait");
            if (!J.a(eff.get("closure")).contains(t.contains(".") ? t : "pca." + t)) return null;
        }
        if (sel.containsKey("verb") && !sel.get("verb").equals(d.get("verb"))) return null;
        Set<String> caveats = new LinkedHashSet<>();
        if (sel.get("caveats") instanceof List) for (Object c : J.a(sel.get("caveats"))) caveats.add((String) c);
        Object where = sel.get("where");
        if (where instanceof Map) for (Map.Entry<String, Object> e : J.m(where).entrySet()) {
            String key = e.getKey();
            boolean dom = key.endsWith(".domain");
            String name = dom ? key.substring(0, key.length() - ".domain".length()) : key;
            Object pd = J.m(d.get("params")).get(name);
            if (pd == null) return null;
            Object v = flat.get(name);
            if (v == null && !flat.containsKey(name)) return null;
            Object cond = e.getValue();
            if (cond instanceof List) {
                if (!(v instanceof String) || !J.a(cond).contains(dom ? domainOf((String) v) : v)) return null;
            } else if (cond instanceof Map) {
                Double n = J.num(v);
                Map<String, Object> cm = J.m(cond);
                if (n == null || (cm.containsKey("max") && n > J.num(cm.get("max"))) || (cm.containsKey("min") && n < J.num(cm.get("min")))) return null;
            } else return null;
            String role = J.get(pd, "role") != null ? (String) J.get(pd, "role") : "";
            if (role.startsWith("contact.") || role.equals("party.payee")) caveats.add("recipient_scope");
            else if (role.equals("money.amount")) caveats.add("amount_cap");
            else if (role.equals("count.limit")) caveats.add("count_cap");
            else if (role.startsWith("id.")) caveats.add("resource_scope");
        }
        return new ArrayList<>(caveats);
    }

    private static String floorDecision(List<String> grantCaveats, int maxEsc, int preauth, Set<String> context, Map<String, Object> rho) {
        long esc = J.num(rho.get("esc")).longValue();
        if (esc > maxEsc) return "deny";
        for (Object c : J.a(rho.get("caveats"))) if (!grantCaveats.contains(c)) return "escalate";
        for (Object c : J.a(rho.get("context"))) if (!context.contains(c)) return "escalate";
        return esc > preauth ? "escalate" : "allow";
    }

    /** Decide one example: {@code {got, why}}. */
    public static Map<String, Object> decideExample(Map<String, Object> d, Map<String, Object> ex, Actions.Registry reg, List<?> defs) {
        Map<String, Object> doc = ActionDerive.toSchemaDoc(defs, reg, J.obj("site", "https://example.invalid", "aud", "example", "version", "0"), null);
        Map<String, Object> params = J.m(ex.get("params"));
        Map<String, Object> flat = ActionDerive.flattenParams(params);
        ActionSchema.Conform c = ActionSchema.conform(doc, (String) d.get("verb"), flat);
        if (!c.ok) return J.obj("got", "deny", "why", "schema_violation " + c.code + (c.path != null && !c.path.isEmpty() ? " (" + c.path + ")" : ""));
        Map<String, Object> op = ActionDerive.operationOf(d, params);
        if (!Boolean.TRUE.equals(op.get("ok"))) return J.obj("got", "deny", "why", op.get("reason"));
        Object sels = parseUnder(ex.get("under"), ex.containsKey("under"));
        if (sels instanceof String) return J.obj("got", "deny", "why", "bad example policy: " + sels);
        Map<String, Object> eff = hintOf(d, reg);
        Set<String> callCtx = new HashSet<>();
        Object idem = d.get("idempotency");
        if (idem != null && "natural".equals(J.get(idem, "mode"))) callCtx.add("idempotency");
        if (idem != null && "key_param".equals(J.get(idem, "mode")) && J.get(idem, "param") != null && flat.containsKey((String) J.get(idem, "param"))) callCtx.add("idempotency");
        Set<String> grantCaveats = new LinkedHashSet<>();
        int pre = 0;
        for (Object s0 : J.a(sels)) {
            Map<String, Object> s = J.m(s0);
            List<String> g = grantOf(s, d, flat, eff);
            if (g == null) continue;
            pre = 3;
            grantCaveats.addAll(g);
            if (s.get("context") instanceof List) for (Object k : J.a(s.get("context"))) callCtx.add((String) k);
        }
        Map<String, Object> rho = J.m(eff.get("eff"));
        List<String> gc = new ArrayList<>(grantCaveats);
        String got = floorDecision(gc, 3, pre, callCtx, rho);
        String why;
        if (got.equals("allow")) why = "floor satisfied";
        else {
            List<String> need = new ArrayList<>();
            for (Object k : J.a(rho.get("caveats"))) if (!gc.contains(k)) need.add((String) k);
            for (Object k : J.a(rho.get("context"))) if (!callCtx.contains(k)) need.add((String) k);
            why = "floor needs " + (need.isEmpty() ? "escalation tier " + J.jsStr(rho.get("esc")) : String.join(", ", need));
        }
        return J.obj("got", got, "why", why);
    }

    // ---- mutations of a conforming example ---------------------------------------------------------------------------------------

    private static List<Object[]> mutations(Map<String, Object> d, Map<String, Object> flat) {
        List<Object[]> out = new ArrayList<>();
        Map<String, Object> extra = new LinkedHashMap<>(flat);
        extra.put("zz_undeclared", "x");
        out.add(new Object[] {"extra param", extra});
        List<String> keys = new ArrayList<>(flat.keySet());
        keys.sort(null);
        Map<String, Object> ps = J.m(d.get("params"));
        for (String k : keys) {
            Object pd = ps.get(k);
            if (pd == null) continue;
            Map<String, Object> p = J.m(pd);
            if (!Boolean.FALSE.equals(p.get("required"))) {
                Map<String, Object> w = new LinkedHashMap<>(flat);
                w.remove(k);
                out.add(new Object[] {"missing " + k, w});
            }
            Object v = flat.get(k);
            Map<String, Object> sw = new LinkedHashMap<>(flat);
            sw.put(k, v instanceof String ? J.n(12345) : (J.num(v) != null || v instanceof Boolean) ? "x" : new LinkedHashMap<String, Object>());
            out.add(new Object[] {"type swap " + k, sw});
            if (J.num(v) != null && "integer".equals(p.get("type"))) {
                if (p.containsKey("max")) { Map<String, Object> m = new LinkedHashMap<>(flat); m.put(k, J.n((long) (J.num(p.get("max")) + 1))); out.add(new Object[] {"above max " + k, m}); }
                if (p.containsKey("min")) { Map<String, Object> m = new LinkedHashMap<>(flat); m.put(k, J.n((long) (J.num(p.get("min")) - 1))); out.add(new Object[] {"below min " + k, m}); }
            }
            if (v instanceof String && "string".equals(p.get("type"))) {
                if (p.get("values") != null) { Map<String, Object> m = new LinkedHashMap<>(flat); m.put(k, "not_a_listed_value_zz"); out.add(new Object[] {"outside values " + k, m}); }
                if (p.containsKey("max_len")) { Map<String, Object> m = new LinkedHashMap<>(flat); m.put(k, "x".repeat((int) (J.num(p.get("max_len")) + 1))); out.add(new Object[] {"too long " + k, m}); }
            }
        }
        return out;
    }

    private static List<String> coreTraitIds() { return new ArrayList<>(Actions.CORE_REGISTRY.traits.keySet()); }

    /**
     * Run examples and property checks for a set of defs (one pack). {@code propLimit} bounds the trait subsets tried per def (null = 256). The digest check across the
     * YAML form hands {@code {ns, actions: [def]}} to {@code yamlLoader} (a YAML front end: stringify, parse, load; null = the document is loaded as it is, which is
     * what a lossless YAML round trip yields). Returns {@code {examples, props, ok}}.
     */
    public static Map<String, Object> runDefTests(List<?> defs, Actions.Registry reg, Integer propLimit, Function<Map<String, Object>, Map<String, Object>> yamlLoader) {
        List<Object> examples = new ArrayList<>(), props = new ArrayList<>();
        int limit = propLimit != null ? propLimit : 256;
        for (Object d0 : defs) {
            Map<String, Object> d = J.m(d0);
            String verb = (String) d.get("verb");
            if (d.get("examples") instanceof List) {
                int index = 0;
                for (Object ex0 : J.a(d.get("examples"))) {
                    Map<String, Object> ex = J.m(ex0);
                    Map<String, Object> r = decideExample(d, ex, reg, defs);
                    examples.add(J.obj("verb", verb, "index", J.n(index), "expect", ex.get("expect"), "got", r.get("got"), "ok", r.get("got").equals(ex.get("expect")), "why", r.get("why")));
                    index++;
                }
            }
            // T2: adding any core trait never lowers the effective profile
            Map<String, Object> eff = hintOf(d, reg);
            Map<String, Object> effP = J.m(eff.get("eff"));
            List<String> lowered = new ArrayList<>();
            for (String t : coreTraitIds()) if (!ActionEffective.leq(effP, ActionEffective.effWithTrait(d, t, reg))) lowered.add(t);
            props.add(J.obj("verb", verb, "name", "adding a trait never lowers the profile", "ok", lowered.isEmpty(), "detail", String.join(", ", lowered)));

            // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
            List<Object> ts = J.a(eff.get("traits"));
            int bad = 0;
            long total = Math.min(1L << Math.min(ts.size(), 20), limit);
            Map<String, Object> top = Actions.floorOf(reg, ts).toMap();
            for (int mask = 0; mask < total; mask++) {
                List<Object> sub = new ArrayList<>();
                for (int i = 0; i < ts.size(); i++) if (((mask >> (i & 31)) & 1) != 0) sub.add(ts.get(i));
                if (!ActionEffective.leq(Actions.floorOf(reg, sub).toMap(), top)) bad++;
            }
            props.add(J.obj("verb", verb, "name", "floors are monotone over trait subsets", "ok", bad == 0, "detail", total + " subsets, " + bad + " violations"));

            // one digest across the JSON and YAML forms
            String want = Actions.defDigest(d);
            Map<String, Object> viaJson = ActionAuthor.loadActionsValue(d);
            Map<String, Object> doc = J.obj("ns", verb.split("\\.", -1)[0], "actions", J.list(d));
            Map<String, Object> viaYaml = yamlLoader != null ? yamlLoader.apply(doc) : ActionAuthor.loadActionsValue(doc);
            boolean okJ = digestOk(viaJson, want), okY = digestOk(viaYaml, want);
            props.add(J.obj("verb", verb, "name", "one digest across JSON and YAML forms", "ok", okJ && okY,
                "detail", okJ && okY ? "" : "json " + (okJ ? "ok" : firstMessage(viaJson)) + "; yaml " + (okY ? "ok" : firstMessage(viaYaml))));

            // schema round trip: each example conforms, every mutation is refused
            if (!(d.get("examples") instanceof List) || J.a(d.get("examples")).isEmpty()) {
                props.add(J.obj("verb", verb, "name", "schema round trip", "ok", Boolean.TRUE, "detail", "skipped: no examples"));
                continue;
            }
            Map<String, Object> sdoc = ActionDerive.toSchemaDoc(defs, reg, J.obj("site", "https://example.invalid", "aud", "example", "version", "0"), null);
            Set<String> accepted = new LinkedHashSet<>();
            int tried = 0;
            for (Object ex0 : J.a(d.get("examples"))) {
                Map<String, Object> flat = ActionDerive.flattenParams(J.m(J.get(ex0, "params")));
                if (!ActionSchema.conform(sdoc, verb, flat).ok) continue; // a deliberately non-conforming example is a deny example
                for (Object[] m : mutations(d, flat)) {
                    tried++;
                    @SuppressWarnings("unchecked") Map<String, Object> mp = (Map<String, Object>) m[1];
                    if (ActionSchema.conform(sdoc, verb, mp).ok) accepted.add((String) m[0]);
                }
            }
            props.add(J.obj("verb", verb, "name", "schema round trip", "ok", accepted.isEmpty(), "detail", accepted.isEmpty() ? tried + " mutations refused" : "accepted: " + String.join(", ", accepted)));
        }
        boolean ok = true;
        for (Object e : examples) if (!Boolean.TRUE.equals(J.get(e, "ok"))) ok = false;
        for (Object q : props) if (!Boolean.TRUE.equals(J.get(q, "ok"))) ok = false;
        return J.obj("examples", examples, "props", props, "ok", ok);
    }

    private static boolean digestOk(Map<String, Object> r, String want) {
        return J.a(r.get("errors")).isEmpty() && !J.a(r.get("defs")).isEmpty() && Actions.defDigest(J.m(J.a(r.get("defs")).get(0))).equals(want);
    }

    private static String firstMessage(Map<String, Object> r) {
        List<Object> errs = J.a(r.get("errors"));
        return errs.isEmpty() ? "digest differs" : String.valueOf(J.get(errs.get(0), "message"));
    }

    /** The report as plain lines, one PASS or FAIL per example and property, then a count. */
    public static String testText(Map<String, Object> r) {
        List<String> lines = new ArrayList<>();
        for (Object e : J.a(r.get("examples"))) {
            lines.add((Boolean.TRUE.equals(J.get(e, "ok")) ? "PASS" : "FAIL") + "  " + J.get(e, "verb") + " example " + ((long) J.num(J.get(e, "index")).doubleValue() + 1) + ": expected " + J.get(e, "expect") + ", got " + J.get(e, "got") + " (" + J.get(e, "why") + ")");
        }
        for (Object q : J.a(r.get("props"))) {
            String detail = (String) J.get(q, "detail");
            lines.add((Boolean.TRUE.equals(J.get(q, "ok")) ? "PASS" : "FAIL") + "  " + J.get(q, "verb") + " " + J.get(q, "name") + (detail != null && !detail.isEmpty() ? ": " + detail : ""));
        }
        long f = lines.stream().filter(l -> l.startsWith("FAIL")).count();
        lines.add((lines.size() - f) + " passed, " + f + " failed");
        return String.join("\n", lines);
    }
}
