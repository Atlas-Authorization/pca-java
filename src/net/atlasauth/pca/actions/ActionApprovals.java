package net.atlasauth.pca.actions;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Approval;
import net.atlasauth.pca.Pca;

/**
 * The approval-render helpers over action defs. The canonical render itself is {@link Approval#render}; these bind it to an executed
 * PCActn, to the approver client's check, and to the pinned definitions a step-up renderer is derived from.
 */
public final class ActionApprovals {
    private ActionApprovals() {}

    /** The canonical approval render of a def for params ({@code confirmed}: the def carries a valid signed confirmation). */
    public static Map<String, Object> renderApproval(Map<String, Object> def, Object params, boolean confirmed) { return Approval.render(def, params, confirmed); }

    /** H(R) for an executed action: refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb. */
    public static String renderDigestForAction(Map<String, Object> def, Map<String, Object> params, Map<String, Object> pcactn, boolean confirmed) {
        Object action = pcactn.get("action");
        if (!def.get("verb").equals(J.get(action, "verb"))) throw new Actions.ActionKitError("render_verb_mismatch", "the PCActn is for '" + J.get(action, "verb") + "', the definition for '" + def.get("verb") + "'");
        Object pd = J.get(action, "params_digest");
        if (!(pd instanceof String) || !pd.equals(Pca.paramsDigest(params))) throw new Actions.ActionKitError("render_params_mismatch", "the supplied params are not the params the PCActn signed");
        return Approval.renderDigest(renderApproval(def, params, confirmed));
    }

    /** The approver client's check before it signs: re-render from the pinned def and the displayed params, and require the digest the request carries. */
    public static String approverRenderCheck(Map<String, Object> def, Map<String, Object> params, String requestedRenderDigest, boolean confirmed) {
        String d = Approval.renderDigest(renderApproval(def, params, confirmed));
        if (!d.equals(requestedRenderDigest)) throw new Actions.ActionKitError("render_mismatch", "the approval request commits to a render this definition and these params do not produce");
        return d;
    }

    private static boolean truthy(Object v) {
        if (v == null || Boolean.FALSE.equals(v) || "".equals(v)) return false;
        Double d = J.num(v);
        return d == null || !(d == 0 || d.isNaN());
    }

    /** Single-tap (one-gesture) approval is allowed only for a confirmed definition. */
    public static boolean singleTapAllowed(Map<String, Object> render) { return !truthy(render.get("unreviewed")); }

    /**
     * The step-up renderer derived from the PINNED definitions: the def is found by verb (or alias, first definition wins); a verb with no pinned
     * definition throws, which makes the review a deny.
     */
    public static Map<String, Object> renderFromDefs(List<?> defs, String verb, Map<String, Object> params, boolean confirmed) {
        Map<String, Object> byVerb = new LinkedHashMap<>();
        for (Object d : defs) {
            byVerb.put((String) J.get(d, "verb"), d);
            if (J.get(d, "aliases") instanceof List) for (Object a : J.a(J.get(d, "aliases"))) byVerb.putIfAbsent((String) a, d);
        }
        Object d = byVerb.get(verb);
        if (d == null) throw new Actions.ActionKitError("render_unknown_verb", "no pinned action definition for '" + verb + "'");
        return renderApproval(J.m(d), params == null ? new LinkedHashMap<String, Object>() : params, confirmed);
    }
}
