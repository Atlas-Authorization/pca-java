package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Approval;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Pca;

/**
 * The undo-window engine over action definitions. Reversibility counts only when it is CONFIRMED: the definition carries a valid signed review by a
 * pinned reviewer key, its effective class (declared joined with every trait floor, and for value-dependent reversibility the class of THESE params) is
 * {@code reversible}, and it names a compensating action that is itself confirmed and can be derived before the effect runs. The compensating call is
 * derived, never authored by the agent. Anything it cannot decide is "not undoable" (a null plan).
 */
public final class ActionUndoEngine {
    private final Map<String, Map<String, Object>> byVerb = new HashMap<>();
    private final Actions.Registry reg;
    private final Predicate<Map<String, Object>> verified;

    /** {@code verified}: the attestation check (null: nothing is confirmed, nothing is undoable); see {@link #attestationVerifier}. */
    public ActionUndoEngine(List<?> defs, Predicate<Map<String, Object>> verified, Actions.Registry reg) {
        this.reg = reg == null ? Actions.CORE_REGISTRY : reg;
        this.verified = verified;
        for (Object d : defs) byVerb.putIfAbsent((String) J.get(d, "verb"), J.m(d));
    }

    /** The engine over pinned reviewer keys ({@code pins} null: nothing is confirmed). */
    public static ActionUndoEngine undoEngine(List<?> defs, Object pins, Actions.Registry reg) {
        Actions.Registry r = reg == null ? Actions.CORE_REGISTRY : reg;
        return new ActionUndoEngine(defs, pins == null ? null : attestationVerifier(pins, r), r);
    }

    private boolean confirmed(Map<String, Object> d) {
        try { return ActionEffective.isConfirmed(d, verified); } catch (RuntimeException e) { return false; }
    }

    /** The plan {@code {def_digest, compensation: {verb, params, def_digest, target_param?}, render, render_digest}} for an operation {@code {verb, params?}}, or null. */
    public Map<String, Object> plan(Map<String, Object> op) {
        try {
            Map<String, Object> d = byVerb.get((String) op.get("verb"));
            Object p0 = op.get("params");
            Map<String, Object> params = p0 instanceof Map ? J.m(p0) : new LinkedHashMap<>();
            if (d == null || !confirmed(d) || readOnly(d.get("effects")) || d.get("compensates") == null) return null;
            Map<String, Object> eff = J.m(J.get(ActionEffective.effective(d, reg, verified), "eff"));
            if (!"reversible".equals(eff.get("rev")) || !"reversible".equals(ActionUndo.reversibilityFor(d, params))) return null;
            Map<String, Object> c = byVerb.get((String) d.get("compensates"));
            if (c == null || !confirmed(c)) return null;
            Map<String, Object> s = ActionUndo.compensationShape(d, c);
            if (!Boolean.TRUE.equals(s.get("ok"))) return null;
            Map<String, Object> shape = J.m(s.get("shape"));
            Map<String, Object> cparams = new LinkedHashMap<>();
            Map<String, Object> nc = J.m(Actions.normalize(c).get("params"));
            for (Object k0 : J.a(shape.get("copied"))) {
                String k = (String) k0;
                if (params.containsKey(k)) cparams.put(k, deepCopy(params.get(k)));
                else if (Boolean.TRUE.equals(J.get(nc.get(k), "required"))) return null; // the call left out what the undo needs
            }
            // an action that cannot be shown completely is never put to a human, so it gets no window either
            Map<String, Object> render = Approval.render(d, params, confirmed(d));
            Map<String, Object> comp = J.obj("verb", c.get("verb"), "params", cparams, "def_digest", Actions.defDigest(c));
            if (shape.get("target") != null) comp.put("target_param", shape.get("target"));
            return J.obj("def_digest", Actions.defDigest(d), "compensation", comp, "render", render, "render_digest", Approval.renderDigest(render));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean readOnly(Object effects) {
        if (!(effects instanceof List) || ((List<?>) effects).isEmpty()) return false;
        for (Object e : (List<?>) effects) if (!"read".equals(e)) return false;
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    /**
     * The attestation check a pinned-reviewer engine uses: the def is {@code confirmed}, carries a well-formed attestation over exactly its digest and
     * declared traits, against an accepted trait registry, signed by a key pinned with the reviewer role inside its validity. Never throws.
     */
    public static Predicate<Map<String, Object>> attestationVerifier(Object pins, Actions.Registry reg) {
        return d -> {
            try {
                return attested(d, pins, reg);
            } catch (RuntimeException e) {
                return false;
            }
        };
    }

    private static boolean attested(Map<String, Object> def, Object pins, Actions.Registry reg) {
        if (ActionConfirmation.reviewerPinsError(pins) != null) return false;
        Object review = def.get("review");
        if (!"confirmed".equals(J.get(review, "state"))) return false;
        Object a = J.get(review, "attestation");
        if (!(a instanceof Map)) return false;
        Map<String, Object> am = J.m(a);
        if (!(am.get("sig") instanceof String) || !(am.get("facts_digest") instanceof String)) return false;
        if (!(am.get("final_traits") instanceof List) || !(am.get("dismissed") instanceof List) || !J.isInt(am.get("ts")) || !(am.get("reviewer_kid") instanceof String)) return false;
        for (Object t : J.a(am.get("final_traits"))) if (!(t instanceof String)) return false;
        for (Object x : J.a(am.get("dismissed"))) if (!(x instanceof Map) || !(J.get(x, "trait") instanceof String) || !(J.get(x, "reason") instanceof String)) return false;
        if (!Actions.defDigest(def).equals(am.get("def_digest"))) return false;
        Set<Object> accepted = new java.util.HashSet<>();
        accepted.add(Actions.traitsDigest(reg));
        Object extra = J.get(pins, "traits_digests");
        if (extra instanceof List) accepted.addAll(J.a(extra));
        if (!accepted.contains(am.get("traits_digest"))) return false;
        if (!J.stringify(J.objs(J.sortUniq(am.get("final_traits")))).equals(J.stringify(J.objs(J.sortUniq(def.get("traits") instanceof List ? def.get("traits") : List.of()))))) return false;
        Set<Object> fin = new java.util.HashSet<>(J.a(am.get("final_traits")));
        for (Object x : J.a(am.get("dismissed"))) if (fin.contains(J.get(x, "trait")) || ActionConfirmation.blankReason((String) J.get(x, "reason"))) return false;
        Map<String, Object> key = null;
        for (Object k : J.a(J.get(pins, "keys"))) if (am.get("reviewer_kid").equals(J.get(k, "kid"))) { key = J.m(k); break; }
        if (key == null || !J.a(key.get("roles")).contains("reviewer")) return false;
        double ts = J.num(am.get("ts"));
        if ((key.containsKey("not_before") && ts < J.num(key.get("not_before"))) || (key.containsKey("not_after") && ts > J.num(key.get("not_after")))) return false;
        Map<String, Object> body = new LinkedHashMap<>(am);
        body.remove("sig");
        byte[] pk = Pca.decodeB64uStrict(key.get("pk"), 32), sg = Pca.decodeB64uStrict(am.get("sig"), 64);
        return pk != null && sg != null && EdStrict.verify(pk, ActionConfirmation.reviewMessage(body), sg);
    }
}
