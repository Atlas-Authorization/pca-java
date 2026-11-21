package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.AttestCommon;

/**
 * The author-facing semantic diff of two versions of one def (equal | narrow | widen | incomparable, with the reasons) and the per-verb
 * diff of two packs. Conservative: anything it cannot show to be no wider is widening.
 */
public final class ActionDefDiff {
    private ActionDefDiff() {}

    private static final List<String> SENSITIVITY = List.of("free", "material", "critical");
    private static final List<String> PROVENANCE = List.of("first_party", "tool", "agent");
    private static final Map<String, Integer> SCOPE_RANK = Map.of("one", 0, "set", 1, "tenant", 2, "global", 3);

    private static int rr(String rev) { return ActionsBridge.revRank(rev); }

    /** The diff of {@code b} against {@code a}: {@code {class, breaking, reasons}}. */
    public static Map<String, Object> diffDefs(Map<String, Object> a, Map<String, Object> b, Actions.Registry reg) {
        if (!Objects.equals(a.get("verb"), b.get("verb"))) {
            return J.obj("class", "widen", "breaking", true, "reasons", J.list("verb renamed: removed + added (grants on the old verb do not follow)"));
        }
        List<String> wide = new ArrayList<>(), narrow = new ArrayList<>(), incomp = new ArrayList<>();
        boolean breaking = false;
        Map<String, Object> na = Actions.normalize(a), nb = Actions.normalize(b);
        Map<String, Object> ea = J.m(J.m(ActionEffective.effective(a, reg, null)).get("hint")), eb = J.m(J.m(ActionEffective.effective(b, reg, null)).get("hint"));
        Map<String, Object> pa = J.m(ea.get("eff")), pb = J.m(eb.get("eff"));
        if (!ActionEffective.leq(pa, pb)) wide.add("the effective profile is not at least the old one");
        else if (!ActionEffective.profileEq(pa, pb)) narrow.add("the effective profile rose");

        List<Object> fa = J.a(na.get("effects")), fb = J.a(nb.get("effects"));
        for (Object e : fa) if (!fb.contains(e)) wide.add("effect " + e + " removed");
        for (Object e : fb) if (!fa.contains(e)) narrow.add("effect " + e + " added");
        List<Object> ta = J.a(na.get("traits")), tb = J.a(nb.get("traits"));
        for (Object t : ta) if (!tb.contains(t)) wide.add("declared trait " + t + " removed");
        for (Object t : tb) if (!ta.contains(t)) narrow.add("declared trait " + t + " added");
        Map<String, Object> pma = J.m(na.get("params")), pmb = J.m(nb.get("params"));
        String ra = ActionsBridge.worstReversibility(na.get("reversibility"), pma), rb = ActionsBridge.worstReversibility(nb.get("reversibility"), pmb);
        if (rr(rb) < rr(ra)) wide.add("reversibility lowered (" + ra + " to " + rb + ")");
        else if (rr(rb) > rr(ra)) narrow.add("reversibility raised (" + ra + " to " + rb + ")");
        long ba = J.num(J.get(na.get("blast"), "ppm")).longValue(), bb = J.num(J.get(nb.get("blast"), "ppm")).longValue();
        if (bb < ba) wide.add("blast lowered");
        else if (bb > ba) narrow.add("blast raised");
        int ia = "none".equals(J.get(na.get("idempotency"), "mode")) ? 0 : 1, ib = "none".equals(J.get(nb.get("idempotency"), "mode")) ? 0 : 1;
        if (ib < ia) wide.add("idempotency loosened");
        else if (ib > ia) narrow.add("idempotency added");

        Map<String, Object> resa = J.m(na.get("resource")), resb = J.m(nb.get("resource"));
        if (!Objects.equals(resa.get("type"), resb.get("type"))) incomp.add("resource type changed");
        int sa = SCOPE_RANK.get((String) resa.get("scope")), sb = SCOPE_RANK.get((String) resb.get("scope"));
        if (sb > sa) wide.add("resource scope widened");
        else if (sb < sa) narrow.add("resource scope narrowed");
        boolean inOld = ActionIdPattern.idPatternContains(resa.get("id"), resb.get("id")), inNew = ActionIdPattern.idPatternContains(resb.get("id"), resa.get("id"));
        if (!inOld) wide.add("the resource id pattern is not contained in the old one");
        else if (!inNew) narrow.add("the resource id pattern is narrower");

        for (String k : pma.keySet()) {
            Map<String, Object> x = J.m(pma.get(k));
            Object y = pmb.get(k);
            if (y == null) { narrow.add("param " + k + " removed"); breaking = true; continue; }
            paramDiff(k, x, J.m(y), wide, narrow, incomp);
            if (Boolean.FALSE.equals(x.get("required")) && Boolean.TRUE.equals(J.get(y, "required"))) breaking = true;
        }
        for (String k : pmb.keySet()) {
            if (pma.containsKey(k)) continue;
            if (Boolean.TRUE.equals(J.get(pmb.get(k), "required")) || (J.get(pmb.get(k), "required") != null && !Boolean.FALSE.equals(J.get(pmb.get(k), "required")))) { narrow.add("required param " + k + " added"); breaking = true; }
            else wide.add("optional param " + k + " added");
        }
        if ("confirmed".equals(J.get(a.get("review"), "state")) && !"confirmed".equals(J.get(b.get("review"), "state"))) narrow.add("review state left confirmed");

        String cls = !incomp.isEmpty() || (!wide.isEmpty() && !narrow.isEmpty()) ? "incomparable" : !wide.isEmpty() ? "widen" : !narrow.isEmpty() ? "narrow" : "equal";
        boolean cmpEq = cls.equals("equal") && !Actions.defDigest(a).equals(Actions.defDigest(b));
        List<String> reasons = new ArrayList<>();
        for (String r : wide) reasons.add("widen: " + r);
        for (String r : narrow) reasons.add("narrow: " + r);
        for (String r : incomp) reasons.add("incomparable: " + r);
        if (cmpEq) reasons.add("equal: only title or description changed");
        return J.obj("class", cls, "breaking", breaking, "reasons", J.objs(reasons));
    }

    private static String numText(Object v) { Double d = J.num(v); return v == null ? "undefined" : d == null ? String.valueOf(v) : AttestCommon.jsNumString(d); }

    private static void num(String k, String f, boolean lowerIsWider, Map<String, Object> x, Map<String, Object> y, List<String> wide, List<String> narrow) {
        Object o = x.get(f), n = y.get(f);
        Double od = J.num(o), nd = J.num(n);
        if (o == null && n == null) return;
        if (od != null && nd != null && od.doubleValue() == nd.doubleValue()) return;
        double ro = o == null ? (lowerIsWider ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY) : od, rn = n == null ? (lowerIsWider ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY) : nd;
        boolean widerNew = lowerIsWider ? rn < ro : rn > ro;
        (widerNew ? wide : narrow).add("param " + k + ": " + f + " " + numText(o) + " to " + numText(n));
    }

    private static int pl(Object v) { return v == null ? PROVENANCE.size() : PROVENANCE.indexOf(v); }

    private static String sens(Map<String, Object> p) { return p.get("sensitivity") instanceof String ? (String) p.get("sensitivity") : ActionsBridge.effectiveParamSensitivity(p); }

    private static int floorRank(Object r) {
        if (!(r instanceof String)) return 0;
        String f = ActionsBridge.roleSensitivityFloor((String) r);
        return f == null ? 0 : SENSITIVITY.indexOf(f);
    }

    private static void paramDiff(String k, Map<String, Object> x, Map<String, Object> y, List<String> wide, List<String> narrow, List<String> incomp) {
        if (!Objects.equals(x.get("type"), y.get("type"))) incomp.add("param " + k + ": type changed");
        num(k, "min", true, x, y, wide, narrow); num(k, "max", false, x, y, wide, narrow); num(k, "max_len", false, x, y, wide, narrow);
        num(k, "max_items", false, x, y, wide, narrow); num(k, "min_items", true, x, y, wide, narrow);
        Object ux = x.get("unit"), uy = y.get("unit");
        if (!J.sameJson(ux, true, uy, true)) incomp.add("param " + k + ": unit changed");
        Object vo = x.get("values"), vn = y.get("values");
        if (vo != null || vn != null) {
            if (vo == null) narrow.add("param " + k + ": values restricted");
            else if (vn == null) wide.add("param " + k + ": values unrestricted");
            else {
                List<String> added = new ArrayList<>(), removed = new ArrayList<>();
                for (Object v : J.a(vn)) if (!J.a(vo).contains(v)) added.add(String.valueOf(v));
                for (Object v : J.a(vo)) if (!J.a(vn).contains(v)) removed.add(String.valueOf(v));
                if (!added.isEmpty()) wide.add("param " + k + ": values added (" + String.join(", ", added) + ")");
                if (!removed.isEmpty()) narrow.add("param " + k + ": values removed (" + String.join(", ", removed) + ")");
            }
        }
        if (Boolean.TRUE.equals(x.get("required")) && Boolean.FALSE.equals(y.get("required"))) wide.add("param " + k + ": required to optional");
        if (Boolean.FALSE.equals(x.get("required")) && Boolean.TRUE.equals(y.get("required"))) narrow.add("param " + k + ": optional to required");
        if (pl(y.get("provenance_min")) > pl(x.get("provenance_min"))) wide.add("param " + k + ": provenance_min loosened");
        else if (pl(y.get("provenance_min")) < pl(x.get("provenance_min"))) narrow.add("param " + k + ": provenance_min tightened");
        int sx = SENSITIVITY.indexOf(sens(x)), sy = SENSITIVITY.indexOf(sens(y));
        if (sy < sx) wide.add("param " + k + ": sensitivity lowered");
        else if (sy > sx) narrow.add("param " + k + ": sensitivity raised");
        if (!Objects.equals(x.get("role"), y.get("role"))) {
            int fx = floorRank(x.get("role")), fy = floorRank(y.get("role"));
            if (fy < fx) wide.add("param " + k + ": role changed to a lower-floor role");
            else if (fy > fx) narrow.add("param " + k + ": role changed to a higher-floor role");
            else incomp.add("param " + k + ": role changed");
        }
    }

    /** Per-verb diff of two sets of defs: {@code {verb, class, breaking, reasons}} (a removed verb is {@code removed}, a new one {@code added}). */
    public static List<Object> diffPacks(List<?> olds, List<?> news, Actions.Registry reg) {
        TreeMap<String, Object> o = new TreeMap<>(), n = new TreeMap<>();
        for (Object d : olds) o.put((String) J.get(d, "verb"), d);
        for (Object d : news) n.put((String) J.get(d, "verb"), d);
        TreeSet<String> verbs = new TreeSet<>(o.keySet());
        verbs.addAll(n.keySet());
        List<Object> out = new ArrayList<>();
        for (String v : verbs) {
            Object x = o.get(v), y = n.get(v);
            if (x == null) out.add(J.obj("verb", v, "class", "added", "breaking", false, "reasons", new ArrayList<>()));
            else if (y == null) out.add(J.obj("verb", v, "class", "removed", "breaking", true, "reasons", J.list("verb removed")));
            else {
                Map<String, Object> d = diffDefs(J.m(x), J.m(y), reg);
                out.add(J.obj("verb", v, "class", d.get("class"), "breaking", d.get("breaking"), "reasons", d.get("reasons")));
            }
        }
        return out;
    }
}
