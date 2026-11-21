package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;

/**
 * Starter packs a platform can begin from: typical actions of five business types in the authoring YAML form, with custom traits and business rules (and
 * their examples). Every action is an AUTHORED draft: a template never confirms anything. The namespace is the platform's choice (verbs, resource types
 * and custom trait ids are derived from it). The text is the reference's, embedded verbatim with the namespace substituted.
 */
public final class ActionTemplates {
    private ActionTemplates() {}

    private static final Pattern NS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}");

    private static List<Object> all() { return J.a(Json.parse(ActionData.join(ActionData.TEMPLATES))); }

    /** The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved {@code pca}. */
    private static String checkNs(Object ns) {
        if (!(ns instanceof String) || !NS_RE.matcher((String) ns).matches()) throw new Actions.ActionKitError("bad_ns", "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)");
        if ("pca".equals(ns)) throw new Actions.ActionKitError("bad_ns", "the namespace 'pca' is reserved for core traits");
        return (String) ns;
    }

    private static Object subst(Object v, String ns) {
        if (v instanceof String) return ((String) v).replace(ActionData.PLACEHOLDER_NS, ns);
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(subst(x, ns));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), subst(e.getValue(), ns));
            return out;
        }
        return v;
    }

    /** The starter templates, as {@code {id, title, description, ns}} (use {@link #traits} and {@link #yaml} for the namespace-bound parts). */
    public static List<Object> starterTemplates() {
        List<Object> out = new ArrayList<>();
        for (Object t : all()) out.add(J.obj("id", J.get(t, "id"), "title", J.get(t, "title"), "description", J.get(t, "description"), "ns", J.get(t, "ns")));
        return out;
    }

    /** The starter template with this id, or null. */
    public static Map<String, Object> starterTemplate(String id) {
        for (Object t : starterTemplates()) if (J.get(t, "id").equals(id)) return J.m(t);
        return null;
    }

    private static Object raw(String id) {
        for (Object t : all()) if (J.get(t, "id").equals(id)) return t;
        throw new Actions.ActionKitError("unknown_template", "no starter template '" + id + "'");
    }

    /** The pack's custom traits under namespace {@code ns} (ids {@code <ns>.<name>}). */
    public static List<Object> traits(String id, Object ns) {
        String n = checkNs(ns);
        return J.a(subst(J.get(raw(id), "traits"), n));
    }

    /** The authoring YAML under namespace {@code ns}, with {@code rules:} blocks and their examples. */
    public static String yaml(String id, Object ns) {
        String n = checkNs(ns);
        return ((String) J.get(raw(id), "yaml")).replace(ActionData.PLACEHOLDER_NS, n);
    }
}
