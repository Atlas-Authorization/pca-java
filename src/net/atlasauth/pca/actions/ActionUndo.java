package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import net.atlasauth.pca.Actions;

/**
 * The structural half of the undo-window engine over action definitions: the class of a reversibility declaration for concrete params,
 * whether any value of it is reversible, and whether a compensating action can undo another without the agent's help (derived, never
 * authored by the agent). The confirmation-gated engine itself sits on top of these.
 */
public final class ActionUndo {
    private ActionUndo() {}

    /** The class of a reversibility declaration for concrete params (an unmapped or absent value takes {@code default}, else irreversible). */
    public static String reversibilityFor(Map<String, Object> d, Map<String, Object> params) {
        Object r = Actions.normalize(d).get("reversibility");
        if (r instanceof String) return (String) r;
        Object v = params.get((String) J.get(r, "by"));
        String k = v instanceof String ? (String) v : v instanceof Boolean || (J.isInt(v)) ? J.jsStr(v) : null;
        Map<String, Object> map = J.m(J.get(r, "map"));
        if (k != null && map.containsKey(k)) return (String) map.get(k);
        Object dflt = J.get(r, "default");
        return dflt != null ? (String) dflt : "irreversible";
    }

    /** True when some value of the declaration is {@code reversible} (a fixed class, a map value or the default). */
    public static boolean mayBeReversible(Map<String, Object> d) {
        Object r = d.get("reversibility");
        if (r == null) return false;
        if (r instanceof String) return "reversible".equals(r);
        return J.m(J.get(r, "map")).containsValue("reversible") || "reversible".equals(J.get(r, "default"));
    }

    private static boolean sameType(Object a, Map<String, Object> b) {
        return a != null && Objects.equals(J.get(a, "type"), b.get("type")) && Objects.equals(J.get(a, "items"), b.get("items"));
    }

    private static boolean isReadOnly(Object effects) {
        if (!(effects instanceof List) || ((List<?>) effects).isEmpty()) return false;
        for (Object e : (List<?>) effects) if (!"read".equals(e)) return false;
        return true;
    }

    /** Can {@code comp} undo {@code orig}? {@code {ok: true, shape: {copied, target?}}} or {@code {ok: false, reason}}. */
    public static Map<String, Object> compensationShape(Map<String, Object> orig, Map<String, Object> comp) {
        if (isReadOnly(comp.get("effects"))) return J.obj("ok", false, "reason", "the compensating action " + comp.get("verb") + " only reads");
        String ct = (String) J.get(comp.get("resource"), "type"), ot = (String) J.get(orig.get("resource"), "type");
        if (!ct.equals(ot)) return J.obj("ok", false, "reason", "the compensating action " + comp.get("verb") + " acts on " + ct + ", not " + ot);
        Map<String, Object> nc = Actions.normalize(comp);
        List<Object> copied = new ArrayList<>();
        String target = null;
        Object idemO = nc.get("idempotency");
        String idem = "key_param".equals(J.get(idemO, "mode")) ? (String) J.get(idemO, "param") : null;
        Map<String, Object> origParams = J.m(orig.get("params"));
        for (Map.Entry<String, Object> e : new TreeMap<>(J.m(nc.get("params"))).entrySet()) {
            String name = e.getKey();
            Map<String, Object> p = J.m(e.getValue());
            if (name.equals(idem)) continue;
            if (sameType(origParams.get(name), p)) { copied.add(name); continue; }
            if (!Boolean.TRUE.equals(p.get("required"))) continue;
            if (("id." + ct).equals(p.get("role")) && target == null) { target = name; continue; }
            return J.obj("ok", false, "reason", "the compensating action " + comp.get("verb") + " needs '" + name + "', which neither the original call nor its result supplies");
        }
        Map<String, Object> shape = J.obj("copied", copied);
        if (target != null) shape.put("target", target);
        return J.obj("ok", true, "shape", shape);
    }
}
