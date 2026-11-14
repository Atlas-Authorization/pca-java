package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Typed missing context and the stored-wins merge (packages/pca/src/missing-context.ts). A condition that cannot be decided because a
 * value is absent names what is missing and who may supply it; a request-supplied value never replaces a bound one. Total.
 * Replays packages/pca/conformance/missing-context-vectors.json. Results are plain maps that mirror the vectors' expected objects.
 */
public final class MissingContext {
    private MissingContext() {}

    public static final List<String> SUPPLIERS = NullSafe.list(List.of("principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted"));
    private static final Set<String> FORBIDDEN = NullSafe.set(Set.of("__proto__", "constructor", "prototype"));
    private static final Pattern PATH_RE = Pattern.compile("(action\\.params|subject|env)(\\.[A-Za-z_][A-Za-z0-9_]*)*");

    /** Longest matching prefix (at a segment boundary) wins; a path matching nothing is {@code principal}. */
    public static String supplierOf(String path, Map<String, Object> table) {
        String best = null;
        for (String k : table.keySet()) if ((path.equals(k) || path.startsWith(k + ".")) && (best == null || k.length() > best.length())) best = k;
        return best == null ? "principal" : (String) table.get(best);
    }

    public static String supplierTableError(Object t) {
        if (!(t instanceof Map)) return "the supplier table must be an object";
        for (Map.Entry<?, ?> en : ((Map<?, ?>) t).entrySet()) {
            String k = (String) en.getKey();
            if (!PATH_RE.matcher(k).matches()) return "bad supplier path '" + k + "'";
            for (String s : k.split("\\.")) if (FORBIDDEN.contains(s)) return "bad supplier path '" + k + "'";
            if (!SUPPLIERS.contains(en.getValue())) return "bad supplier for '" + k + "'";
        }
        return null;
    }

    private static Object copy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> o = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) o.put((String) e.getKey(), copy(e.getValue()));
            return o;
        }
        if (v instanceof List) {
            List<Object> o = new ArrayList<>();
            for (Object x : (List<?>) v) o.add(copy(x));
            return o;
        }
        return v;
    }

    private static void leaves(Object v, String prefix, Map<String, Object> out, int depth) {
        if (depth <= 16 && v instanceof Map && !((Map<?, ?>) v).isEmpty()) {
            for (Map.Entry<?, ?> e : new TreeMap<Object, Object>((Map<?, ?>) v).entrySet()) {
                if (!FORBIDDEN.contains(e.getKey())) leaves(e.getValue(), prefix + "." + e.getKey(), out, depth + 1);
            }
        } else out.put(prefix, v);
    }

    @SuppressWarnings("unchecked")
    private static void setPath(Map<String, Object> root, String[] segs, Object value) {
        Map<String, Object> cur = root;
        for (int i = 0; i < segs.length - 1; i++) {
            if (!(cur.get(segs[i]) instanceof Map)) cur.put(segs[i], new LinkedHashMap<String, Object>());
            cur = (Map<String, Object>) cur.get(segs[i]);
        }
        cur.put(segs[segs.length - 1], value);
    }

    private static String h(Object v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", v);
        return Pca.hashCanonical(m);
    }

    /** {context, conflicts, dropped}. Bound wins; see the TypeScript module comment. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> bindContext(Object bound, Object supplied, Map<String, Object> table) {
        Object ctxo = copy(bound);
        List<Object> conflicts = new ArrayList<>(), dropped = new ArrayList<>();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("context", ctxo);
        out.put("conflicts", conflicts);
        out.put("dropped", dropped);
        if (!(supplied instanceof Map) || !(ctxo instanceof Map)) return out;
        Map<String, Object> ctx = (Map<String, Object>) ctxo;
        Map<String, Object> s = (Map<String, Object>) supplied;
        Map<String, Object> flat = new TreeMap<>();
        if (s.get("action") instanceof Map && ((Map<?, ?>) s.get("action")).get("params") instanceof Map) leaves(((Map<?, ?>) s.get("action")).get("params"), "action.params", flat, 0);
        if (s.get("subject") instanceof Map) leaves(s.get("subject"), "subject", flat, 0);
        if (s.get("env") instanceof Map) leaves(s.get("env"), "env", flat, 0);
        for (Map.Entry<String, Object> en : flat.entrySet()) {
            String path = en.getKey();
            if ("agent_declared_untrusted".equals(supplierOf(path, table))) { dropped.add(path); continue; }
            Predicates.Resolved r = Predicates.resolvePath(ctx, path);
            if (r.found) {
                if (!h(r.value).equals(h(en.getValue()))) conflicts.add(path);
                continue;
            }
            String[] segs = path.split("\\.", -1);
            boolean blocked = false;
            for (int i = 1; i < segs.length; i++) {   // from 1: a bound top-level env / subject / action that is not an object blocks too
                Predicates.Resolved r2 = Predicates.resolvePath(ctx, String.join(".", java.util.Arrays.copyOfRange(segs, 0, i)));
                if (r2.found && !(r2.value instanceof Map)) blocked = true;
            }
            if (blocked) { conflicts.add(path); continue; }
            // an absent action gets the empty verb / resource; setPath creates the params object (a present non-object params blocked above)
            if (path.startsWith("action.params") && ctx.get("action") == null) {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("verb", "");
                d.put("resource", "");
                ctx.put("action", d);
            }
            setPath(ctx, segs, copy(en.getValue()));
        }
        return out;
    }

    private static boolean isGroup(Map<?, ?> c) { return c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not"); }

    @SuppressWarnings("unchecked")
    private static void collect(Object co, Map<String, Object> ctx, Set<String> out, boolean[] ill, int depth) {
        if (depth > 64 || !(co instanceof Map)) { ill[0] = true; return; }
        Map<String, Object> c = (Map<String, Object>) co;
        if (isGroup(c)) {
            Object kids = c.containsKey("all_of") ? c.get("all_of") : c.containsKey("any_of") ? c.get("any_of") : java.util.Collections.singletonList(c.get("not"));   // List.of(null) throws: {"not": null} is ill-formed, not a crash
            if (!(kids instanceof List) || ((List<?>) kids).isEmpty()) { ill[0] = true; return; }
            for (Object k : (List<?>) kids) collect(k, ctx, out, ill, depth + 1);
            return;
        }
        if (Predicates.evaluateConditionTri(c, ctx) != Predicates.Tri.UNKNOWN) return;
        boolean absent = absentPath(c.get("field"), ctx, out);
        if (absentPath(c.get("ref"), ctx, out)) absent = true;
        // a field under action.params of a non-object params is already absent above; only the params value itself can be present but unusable.
        // decide refuses a bound context without an action object and the merge keeps it one, so the cast holds.
        if ("action.params".equals(c.get("field"))) {
            Object p = ((Map<?, ?>) ctx.get("action")).get("params");
            if (!(p instanceof Map) && !(p instanceof List)) { out.add("action.params"); absent = true; }
        }
        if (!absent) ill[0] = true;
    }

    /** A non-empty path the context does not resolve is missing: named in {@code out}. */
    private static boolean absentPath(Object p, Map<String, Object> ctx, Set<String> out) {
        if (!(p instanceof String) || ((String) p).isEmpty() || Predicates.resolvePath(ctx, p).found) return false;
        out.add((String) p);
        return true;
    }

    private static Map<String, Object> deny(String reason, List<Object> missing) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("decision", "deny");
        m.put("reason", reason);
        m.put("missing", missing);
        return m;
    }

    /** {decision, reason (absent for allow), missing: [{path, supplier}]}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> decide(Object where, Object bound, Object supplied, Object suppliers) {
        try {
            if (!(bound instanceof Map) || !(((Map<?, ?>) bound).get("action") instanceof Map)) return deny("bad_context", new ArrayList<>());
            Object table = suppliers == null ? new LinkedHashMap<String, Object>() : suppliers;
            String te = supplierTableError(table);
            if (te != null) return deny("bad supplier table: " + te, new ArrayList<>());
            if (!(where instanceof List) || ((List<?>) where).isEmpty()) return deny("condition_false", new ArrayList<>());
            Map<String, Object> b = bindContext(bound, supplied, (Map<String, Object>) table);
            List<Object> conflicts = (List<Object>) b.get("conflicts");
            if (!conflicts.isEmpty()) {
                List<String> cs = new ArrayList<>();
                for (Object o : conflicts) cs.add((String) o);
                return deny("context_shadow: " + String.join(",", cs), new ArrayList<>());
            }
            Map<String, Object> ctx = (Map<String, Object>) b.get("context");
            Map<String, Object> all = new LinkedHashMap<>();
            all.put("all_of", where);
            Predicates.Tri t = Predicates.evaluateConditionTri(all, ctx);
            Map<String, Object> ok = new LinkedHashMap<>();
            if (t == Predicates.Tri.TRUE) { ok.put("decision", "allow"); ok.put("missing", new ArrayList<Object>()); return ok; }
            if (t == Predicates.Tri.FALSE) return deny("condition_false", new ArrayList<>());
            Set<String> paths = new TreeSet<>();
            boolean[] ill = {false};
            for (Object c : (List<?>) where) collect(c, ctx, paths, ill, 0);
            if (paths.isEmpty() || ill[0]) return deny("ill_typed_context", new ArrayList<>());
            List<Object> missing = new ArrayList<>();
            List<String> untrusted = new ArrayList<>(), tags = new ArrayList<>();
            for (String p : paths) {
                String sup = supplierOf(p, (Map<String, Object>) table);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("path", p);
                m.put("supplier", sup);
                missing.add(m);
                tags.add(sup + ":" + p);
                if (sup.equals("agent_declared_untrusted")) untrusted.add(p);
            }
            if (!untrusted.isEmpty()) return deny("missing_context_untrusted: " + String.join(",", untrusted), missing);
            Map<String, Object> esc = new LinkedHashMap<>();
            esc.put("decision", "escalate");
            esc.put("reason", "escalate: missing_context " + String.join(",", tags));
            esc.put("missing", missing);
            return esc;
        } catch (RuntimeException | StackOverflowError ex) {
            return deny("evaluation error (fail closed)", new ArrayList<>());
        }
    }
}
