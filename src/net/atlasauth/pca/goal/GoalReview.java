package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Principal review and signing for a Goal IR. The PolicyCard is a deterministic, template-only (no model) rendering of the WHOLE goal:
 * every grant, prohibition, bound, validity window, delegation limit, escalation trigger, hole, wildcard and confirmed boundary example,
 * with exact numbers. Lossless-or-refuse: a card is never truncated; reviewer-fatigue limits REFUSE a goal or diff that is too large to
 * read. The semantic diff counts anything not PROVEN narrower as a widening. A GoalApproval is a pinned reviewer's signature over
 * {goal, policy, card, ontology, tests, instruction, model-set digests}; {@link #loadApprovedGoal} trusts nothing the submission claims
 * about itself: it recomputes every digest, recompiles, re-renders, re-runs the confirmed examples, then checks the signature.
 *
 * <p>The compiler is injected ({@link ReviewKernel}): the proved extracted compiler is not carried natively. A submission is
 * {goal, ontology, instruction, model_set, tests?}.
 */
public final class GoalReview {
    private GoalReview() {}

    /** The compiler and decision entry points the review flow needs. */
    public interface ReviewKernel {
        /** Goal, IR ontology -&gt; {ok: true, policy} | {ok: false, reasons}. Pure and total. */
        Map<String, Object> compile(Map<String, Object> goal, Map<String, Object> ont);

        /** Content digest of the compiled policy. */
        String policyDigest(Map<String, Object> policy);

        /** Error-level analyzer findings over the compiled policy; any finding refuses. The default has no analyzer. */
        default List<String> analyze(Map<String, Object> policy) { return new ArrayList<>(); }

        /** Whether {@link #decide} is available (needed to re-run the confirmed examples). */
        default boolean canDecide() { return false; }

        /** The decision ("allow" | "deny" | "escalate") for an action. */
        default String decide(Map<String, Object> goal, Map<String, Object> ont, Map<String, Object> act, Map<String, Object> hist) { throw new UnsupportedOperationException("no decide"); }

        /** Whether {@link #newlyAllowed} is available. */
        default boolean canListNewlyAllowed() { return false; }

        /** Actions allowed by {@code next} and not by {@code prev}: {witnesses, complete}. */
        default Map<String, Object> newlyAllowed(Map<String, Object> prev, Map<String, Object> next, Map<String, Object> ont, long limit) { throw new UnsupportedOperationException("no newlyAllowed"); }
    }

    // ---- limits (reviewer fatigue) ----

    private static Map<String, Long> reviewLimits() {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put("max_grants", 32L); m.put("max_prohibits", 64L); m.put("max_bounds", 32L); m.put("max_escalate_on", 32L); m.put("max_examples", 40L);
        m.put("max_card_lines", 200L); m.put("max_card_bytes", 24576L); m.put("max_diff_changes", 60L); m.put("max_diff_widenings", 12L); m.put("max_witnesses", 20L);
        return m;
    }

    /** The hard caps on what a human is asked to read, as a fresh map. */
    public static Map<String, Long> REVIEW_LIMITS() { return reviewLimits(); }

    /** Caller overrides may only TIGHTEN a limit (a larger number is ignored). {@code o} may be null. */
    public static Map<String, Long> effectiveLimits(Map<String, Object> o) {
        Map<String, Long> out = reviewLimits();
        if (o != null) for (String k : new ArrayList<>(out.keySet())) {
            Object v = o.get(k);
            Long x = v == null ? null : G.safeInt(v);
            if (x != null && x >= 0 && x < out.get(k)) out.put(k, x);
        }
        return out;
    }

    /** A review refusal with a stable code: card_too_large, unrenderable, holes, wildcard_unacknowledged, diff_too_large, too_many_widenings. */
    public static final class ReviewError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String code;

        public ReviewError(String code, String detail) { super("goal review: " + code + ": " + detail); this.code = code; }

        public String code() { return code; }
    }

    private static final String D_CARD = "atlas-pca/policy-card/v1";
    private static final String D_CLAUSE = "atlas-pca/goal-clause/v1";
    public static final String GOAL_APPROVAL_KIND = "goal-approval";
    /** An approval may not be valid for longer than this. */
    public static final long MAX_GOAL_APPROVAL_TTL_MS = 24L * 3_600_000L;
    private static final long DEFAULT_TTL_MS = 3_600_000L;

    /** The fields covered by the signature. */
    public static final List<String> GOAL_APPROVAL_SIGNED_FIELDS = List.of("v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest", "model_set_digest", "reviewer", "approved_at", "expires_at");

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static List<Object> list(Object o) { return G.arr(o, ""); }

    private static boolean isObj(Object o) { return o instanceof Map; }

    private static String jsonOf(Object v) {
        try { return Json.canonicalizeStrict(v); } catch (RuntimeException e) { throw new ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)"); }
    }

    private static Map<String, Object> line(String id, String kind, String text, Object clause, String severity) {
        return G.map("id", id, "kind", kind, "severity", severity, "text", text, "clause_digest", Pca.hashCanonical(G.map("d", D_CLAUSE, "kind", kind, "clause", clause)));
    }

    private interface Txt { String get(); }

    /** Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped. */
    private static String safeText(Txt f, Object clause) {
        try {
            String t = f.get();
            if (t.contains("undefined")) throw new IllegalStateException("unknown clause shape");
            return t;
        } catch (RuntimeException e) {
            if (e instanceof ReviewError) throw e;
            return jsonOf(clause);
        }
    }

    private static void big(String what, long n, long max) {
        if (n > max) throw new ReviewError("card_too_large", n + " " + what + " exceed the cap of " + max + ": split the goal into smaller goals");
    }

    private static String goalDigestOf(Map<String, Object> goal) {
        try { return GoalDigests.goalDigest(goal); } catch (RuntimeException e) { throw new ReviewError("unrenderable", "the Goal has no canonical form (float, undefined or cycle)"); }
    }

    private static Object sev(boolean red) { return red ? "red" : "info"; }

    /**
     * Render the card: {v, goal_digest, ontology_digest, nl_digest, principal, lines}. Deterministic, no model, no locale. Throws
     * ReviewError {@code holes} (unless {@code allowHoles}), {@code wildcard_unacknowledged}, {@code card_too_large}, {@code unrenderable}.
     * {@code tests} and {@code limits} may be null.
     */
    public static Map<String, Object> renderPolicyCard(Map<String, Object> goal, List<Object> tests, Map<String, Object> limits, boolean allowHoles) {
        Map<String, Long> L = effectiveLimits(limits);
        List<Object> ts = tests != null ? tests : new ArrayList<>();
        if (!isObj(goal) || !(goal.get("grants") instanceof List) || !(goal.get("prohibits") instanceof List) || !(goal.get("bounds") instanceof List) || !(goal.get("escalateOn") instanceof List)
            || !(goal.get("holes") instanceof List) || !isObj(goal.get("validity")) || !isObj(goal.get("deleg"))) throw new ReviewError("unrenderable", "not a Goal IR");
        List<Object> grants = list(goal.get("grants")), prohibits = list(goal.get("prohibits")), bounds = list(goal.get("bounds")), escalateOn = list(goal.get("escalateOn")), holes = list(goal.get("holes"));
        big("grants", grants.size(), L.get("max_grants"));
        big("prohibitions", prohibits.size(), L.get("max_prohibits"));
        big("bounds", bounds.size(), L.get("max_bounds"));
        big("escalation triggers", escalateOn.size(), L.get("max_escalate_on"));
        big("boundary examples", ts.size(), L.get("max_examples"));
        big("card lines", 3L + grants.size() + prohibits.size() + bounds.size() + escalateOn.size() + holes.size() + ts.size(), L.get("max_card_lines"));
        if (!holes.isEmpty() && !allowHoles) throw new ReviewError("holes", holes.size() + " unresolved question(s): a goal with holes is a draft and cannot be signed");
        Set<Object> ack = new LinkedHashSet<>();
        if (goal.get("wildcardAck") instanceof List) ack.addAll(list(goal.get("wildcardAck")));
        List<Object> lines = new ArrayList<>();
        lines.add(line("principal", "meta", "Acting for principal " + jsonOf(goal.get("principal")) + ". Nothing outside this card is allowed (default deny).", goal.get("principal"), "info"));
        for (Object go : grants) {
            Map<String, Object> g = mm(go);
            boolean wild = "any".equals(G.kind(G.get(g, "res")));
            if (wild && !ack.contains(g.get("gid"))) throw new ReviewError("wildcard_unacknowledged", "grant " + jsonOf(g.get("gid")) + " allows ANY resource without a wildcard acknowledgement");
            lines.add(line(G.jsStr(g.get("gid")), "grant", safeText(() -> GoalCard.grantLine(g) + "." + (wild ? " WILDCARD acknowledged by the principal." : ""), g), g, (String) sev(wild)));
        }
        for (Object po : prohibits) {
            Map<String, Object> p = mm(po);
            lines.add(line(G.jsStr(p.get("pid")), "prohibit", safeText(() -> GoalCard.prohibitLine(p) + ".", p), p, (String) sev("any".equals(G.kind(G.get(p, "res"))))));
        }
        for (Object bo : bounds) {
            Map<String, Object> b = mm(bo);
            lines.add(line(G.jsStr(b.get("bid")), "bound", safeText(() -> GoalCard.boundLine(b) + ".", b), b, "info"));
        }
        Map<String, Object> validity = mm(goal.get("validity")), deleg = mm(goal.get("deleg"));
        lines.add(line("validity", "validity", safeText(() -> GoalCard.validityLine(validity) + ".", validity), validity, "info"));
        lines.add(line("delegation", "delegation", safeText(() -> GoalCard.delegationLine(deleg) + ".", deleg), deleg, (String) sev(!G.truthy(deleg.get("narrowOnly")))));
        for (int i = 0; i < escalateOn.size(); i++) {
            Map<String, Object> c = mm(escalateOn.get(i));
            lines.add(line("escalate_on[" + i + "]", "escalate", safeText(() -> GoalCard.escalateLine(c) + ".", c), c, "info"));
        }
        for (int i = 0; i < holes.size(); i++) {
            Map<String, Object> h = mm(holes.get(i));
            lines.add(line("hole[" + i + "]", "hole", safeText(() -> GoalCard.holeLine(h) + ". Everything depending on it is dropped.", h), h, "red"));
        }
        for (Object to : ts) {
            Map<String, Object> t = mm(to);
            Map<String, Object> act = mm(t.get("act"));
            int adms = list(mm(t.get("hist")).get("adms")).size();
            String ans = "ask".equals(t.get("answer")) ? "ASKED about" : "allow".equals(t.get("answer")) ? "ALLOWED" : "DENIED";
            lines.add(line("example:" + G.jsStr(t.get("id")), "example", "EXAMPLE you confirmed: " + jsonOf(act.get("verb")) + " on " + jsonOf(act.get("res")) + " with " + jsonOf(act.get("params"))
                + (adms > 0 ? " after " + adms + " earlier admitted action(s)" : "") + " must be " + ans + ".", t, "info"));
        }
        big("card lines", lines.size(), L.get("max_card_lines"));
        Map<String, Object> card = G.map("v", G.num(1), "goal_digest", goalDigestOf(goal), "ontology_digest", goal.get("ontDigest"), "nl_digest", goal.get("nlDigest"), "principal", goal.get("principal"), "lines", lines);
        big("bytes of card", Json.canonicalizeStrict(card).getBytes(java.nio.charset.StandardCharsets.UTF_8).length, L.get("max_card_bytes"));
        return card;
    }

    public static String cardDigest(Map<String, Object> card) { return Pca.hashCanonical(G.map("d", D_CARD, "card", card)); }

    /** Plain-text form of a card for any console or terminal. Red lines are prefixed {@code !!}. */
    public static String cardToText(Map<String, Object> card) {
        List<String> out = new ArrayList<>();
        for (Object lo : list(card.get("lines"))) out.add(("red".equals(G.get(lo, "severity")) ? "!! " : "   ") + G.jsStr(G.get(lo, "text")));
        return String.join("\n", out);
    }

    // ---- semantic diff ----

    private static boolean same(Object a, Object b) { return jsonOf(a).equals(jsonOf(b)); }

    private static List<Object> conjuncts(Map<String, Object> c) {
        List<Object> out = new ArrayList<>();
        String k = G.kind(c);
        if (k.equals("and")) { out.addAll(conjuncts(mm(c.get("a")))); out.addAll(conjuncts(mm(c.get("b")))); }
        else if (!k.equals("true")) out.add(c);
        return out;
    }

    /** new.cond is old.cond AND more (or equal): provably no wider. */
    private static boolean whereNoWider(Map<String, Object> oldW, Map<String, Object> newW) {
        Set<String> have = new LinkedHashSet<>();
        for (Object c : conjuncts(newW)) have.add(jsonOf(c));
        for (Object c : conjuncts(oldW)) if (!have.contains(jsonOf(c))) return false;
        return true;
    }

    private static String grantDir(Map<String, Object> o, Map<String, Object> n) {
        if (same(o, n)) return "neutral";
        return java.util.Objects.equals(o.get("verb"), n.get("verb")) && same(o.get("res"), n.get("res")) && whereNoWider(mm(o.get("cond")), mm(n.get("cond"))) ? "narrow" : "unknown";
    }

    private static String prohibitDir(Map<String, Object> o, Map<String, Object> n) {
        if (same(o, n)) return "neutral";
        return same(o.get("target"), n.get("target")) && same(o.get("res"), n.get("res")) && whereNoWider(mm(n.get("cond")), mm(o.get("cond"))) ? "narrow" : "unknown";
    }

    private static String boundDir(Map<String, Object> o, Map<String, Object> n) {
        if (same(o, n)) return "neutral";
        Map<String, Object> ro = new LinkedHashMap<>(o), rn = new LinkedHashMap<>(n);
        ro.put("cap", null); rn.put("cap", null);
        if (!same(ro, rn) || !same(G.get(o.get("cap"), "u"), G.get(n.get("cap"), "u"))) return "unknown";
        double a = G.toNum(G.get(n.get("cap"), "n")), b = G.toNum(G.get(o.get("cap"), "n"));
        return a < b ? "narrow" : a > b ? "widen" : a == b ? "neutral" : "unknown";
    }

    private static double idle(Object x) { double d = G.toNum(x); return d == 0 ? Double.POSITIVE_INFINITY : d; }

    private static String validityDir(Map<String, Object> o, Map<String, Object> n) {
        if (same(o, n)) return "neutral";
        double nb = G.toNum(n.get("notBefore")), ob = G.toNum(o.get("notBefore")), na = G.toNum(n.get("notAfter")), oa = G.toNum(o.get("notAfter"));
        boolean nar = nb >= ob && na <= oa && idle(n.get("maxIdle")) <= idle(o.get("maxIdle"));
        boolean wid = nb <= ob && na >= oa && idle(n.get("maxIdle")) >= idle(o.get("maxIdle"));
        return nar ? "narrow" : wid ? "widen" : "unknown";
    }

    private static String delegationDir(Map<String, Object> o, Map<String, Object> n) {
        if (same(o, n)) return "neutral";
        List<Object> touchO = list(o.get("mayTouch")), touchN = list(n.get("mayTouch"));
        boolean sub = touchO.containsAll(touchN), sup = touchN.containsAll(touchO);
        double nd = G.toNum(n.get("maxDepth")), od = G.toNum(o.get("maxDepth"));
        boolean nar = nd <= od && sub && (G.truthy(n.get("narrowOnly")) || !G.truthy(o.get("narrowOnly")));
        boolean wid = nd >= od && sup && (G.truthy(o.get("narrowOnly")) || !G.truthy(n.get("narrowOnly")));
        return nar ? "narrow" : wid ? "widen" : "unknown";
    }

    private interface Dir { String of(Map<String, Object> o, Map<String, Object> n); }

    private interface Show { String of(String id, Map<String, Object> v); }

    private static List<Object[]> keyed(List<Object> xs, String field) {
        List<Object[]> r = new ArrayList<>();
        for (Object x : xs) r.add(new Object[] {G.jsStr(G.get(x, field)), x});
        return r;
    }

    private static void pairs(List<Object> out, List<Object[]> prev, List<Object[]> next, String kind, String added, String removed, Dir changed, Show text) {
        Map<String, Object> pm = new LinkedHashMap<>(), nm = new LinkedHashMap<>();
        for (Object[] e : prev) pm.put((String) e[0], e[1]);
        for (Object[] e : next) nm.put((String) e[0], e[1]);
        for (Object[] e : next) {
            String id = (String) e[0];
            Map<String, Object> v = mm(e[1]);
            Object o = pm.get(id);
            if (!pm.containsKey(id)) out.add(G.map("change", "added", "kind", kind, "id", id, "direction", added, "text", "ADDED " + text.of(id, v)));
            else if (!same(o, v)) out.add(G.map("change", "changed", "kind", kind, "id", id, "direction", changed.of(mm(o), v), "text", "CHANGED " + text.of(id, v) + " (was: " + text.of(id, mm(o)) + ")"));
        }
        for (Object[] e : prev) if (!nm.containsKey((String) e[0])) out.add(G.map("change", "removed", "kind", kind, "id", e[0], "direction", removed, "text", "REMOVED " + text.of((String) e[0], mm(e[1]))));
    }

    private static boolean isWide(Object c) { Object d = G.get(c, "direction"); return "widen".equals(d) || "unknown".equals(d); }

    /**
     * Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Throws ReviewError
     * {@code diff_too_large} / {@code too_many_widenings} past the fatigue caps. {@code kernel} (newlyAllowed), {@code limits} and {@code ontology} may be null.
     */
    public static Map<String, Object> diffGoals(Map<String, Object> prev, Map<String, Object> next, ReviewKernel kernel, Map<String, Object> limits, Map<String, Object> ontology) {
        Map<String, Long> L = effectiveLimits(limits);
        Show gl = (id, g) -> "grant " + jsonOf(id) + ": " + jsonOf(g.get("verb")) + " on " + GoalCard.res(mm(g.get("res"))) + " when " + GoalCard.cond(mm(g.get("cond")));
        Show pl = (id, p) -> {
            Map<String, Object> t = mm(p.get("target"));
            return "prohibition " + jsonOf(id) + ": " + ("verb".equals(G.kind(t)) ? jsonOf(t.get("verb")) : "effect class " + jsonOf(t.get("cls"))) + " on " + GoalCard.res(mm(p.get("res"))) + " when " + GoalCard.cond(mm(p.get("cond")));
        };
        Show bl = (id, b) -> "bound " + jsonOf(id) + ": " + GoalCard.boundLine(b) + " (" + GoalCard.quantity(mm(b.get("cap"))) + ")";
        List<Object> changes = new ArrayList<>();
        pairs(changes, keyed(list(prev.get("grants")), "gid"), keyed(list(next.get("grants")), "gid"), "grant", "widen", "narrow", GoalReview::grantDir, gl);
        pairs(changes, keyed(list(prev.get("prohibits")), "pid"), keyed(list(next.get("prohibits")), "pid"), "prohibit", "narrow", "widen", GoalReview::prohibitDir, pl);
        pairs(changes, keyed(list(prev.get("bounds")), "bid"), keyed(list(next.get("bounds")), "bid"), "bound", "narrow", "widen", GoalReview::boundDir, bl);
        List<Object[]> ep = new ArrayList<>(), en = new ArrayList<>();
        for (Object c : list(prev.get("escalateOn"))) ep.add(new Object[] {jsonOf(c), c});
        for (Object c : list(next.get("escalateOn"))) en.add(new Object[] {jsonOf(c), c});
        pairs(changes, ep, en, "escalate", "narrow", "widen", (o, n) -> "unknown", (id, c) -> "escalation when " + GoalCard.cond(c));
        if (!same(prev.get("validity"), next.get("validity"))) changes.add(G.map("change", "changed", "kind", "validity", "id", "validity", "direction", validityDir(mm(prev.get("validity")), mm(next.get("validity"))),
            "text", "CHANGED validity: " + jsonOf(next.get("validity")) + " (was: " + jsonOf(prev.get("validity")) + ")"));
        if (!same(prev.get("deleg"), next.get("deleg"))) changes.add(G.map("change", "changed", "kind", "delegation", "id", "delegation", "direction", delegationDir(mm(prev.get("deleg")), mm(next.get("deleg"))),
            "text", "CHANGED delegation: " + jsonOf(next.get("deleg")) + " (was: " + jsonOf(prev.get("deleg")) + ")"));
        // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
        if (!java.util.Objects.equals(prev.get("principal"), next.get("principal"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "principal", "direction", "unknown",
            "text", "CHANGED principal: " + jsonOf(next.get("principal")) + " (was: " + jsonOf(prev.get("principal")) + ")"));
        if (!java.util.Objects.equals(prev.get("ontDigest"), next.get("ontDigest"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "ontology", "direction", "unknown",
            "text", "CHANGED ontology: every term now means what the new vocabulary says (was " + jsonOf(prev.get("ontDigest")) + ", now " + jsonOf(next.get("ontDigest")) + ")"));
        if (!same(prev.get("wildcardAck"), next.get("wildcardAck"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "wildcard_ack", "direction", "unknown",
            "text", "CHANGED wildcard acknowledgements: " + jsonOf(next.get("wildcardAck")) + " (was: " + jsonOf(prev.get("wildcardAck")) + ")"));
        if (!java.util.Objects.equals(prev.get("nlDigest"), next.get("nlDigest"))) changes.add(G.map("change", "changed", "kind", "meta", "id", "instruction", "direction", "neutral", "text", "CHANGED the instruction text the goal was interpreted from"));
        int widenings = 0;
        for (Object c : changes) if (isWide(c)) widenings++;
        if (changes.size() > L.get("max_diff_changes")) throw new ReviewError("diff_too_large", changes.size() + " changes exceed the cap of " + L.get("max_diff_changes") + ": review the new goal as a whole instead");
        if (widenings > L.get("max_diff_widenings")) throw new ReviewError("too_many_widenings", widenings + " widenings exceed the cap of " + L.get("max_diff_widenings") + " per review");
        Map<String, Object> na = ontology != null && kernel != null && kernel.canListNewlyAllowed() ? kernel.newlyAllowed(prev, next, ontology, L.get("max_witnesses")) : null;
        List<Object> witnesses = new ArrayList<>();
        boolean complete = false;
        if (na != null) {
            List<Object> w = list(na.get("witnesses"));
            for (int i = 0; i < w.size() && i < L.get("max_witnesses"); i++) witnesses.add(w.get(i));
            complete = Boolean.TRUE.equals(na.get("complete")) && w.size() <= L.get("max_witnesses");
        }
        List<Object> ordered = new ArrayList<>();
        for (Object c : changes) if (isWide(c)) ordered.add(c);
        for (Object c : changes) if (!isWide(c)) ordered.add(c);
        return G.map("v", G.num(1), "from_goal_digest", goalDigestOf(prev), "to_goal_digest", goalDigestOf(next), "newly_allowed", witnesses, "newly_allowed_complete", complete, "changes", ordered, "widenings", G.num(widenings));
    }

    public static String diffToText(Map<String, Object> d) {
        List<String> out = new ArrayList<>();
        for (Object w : list(d.get("newly_allowed"))) out.add("!! NEWLY ALLOWED: " + jsonOf(G.get(w, "verb")) + " on " + jsonOf(G.get(w, "res")) + " with " + jsonOf(G.get(w, "params")));
        if (!Boolean.TRUE.equals(d.get("newly_allowed_complete"))) out.add("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.");
        for (Object c : list(d.get("changes"))) out.add((isWide(c) ? "!! " : "   ") + G.jsStr(G.get(c, "text")));
        return String.join("\n", out);
    }

    // ---- GoalApproval ----

    /** Options of {@link #approveGoal}; every field may be null. */
    public static final class ApproveOptions {
        public ReviewKernel kernel;
        public Long now;
        public Long ttlMs;
        public Map<String, Object> limits;
        /** The previously approved goal: when given, the diff must be reviewable (fatigue caps) or signing is refused. */
        public Map<String, Object> base;
    }

    /** Options of {@link #loadApprovedGoal}. {@code reviewers}: pinned b64u keys or {pk, ...} maps. */
    public static final class LoadOptions {
        public ReviewKernel kernel;
        public List<?> reviewers;
        public String ontologyDigest;
        public Long now;
        public Map<String, Object> limits;
    }

    private static Map<String, Object> bad(String reason) { return G.map("ok", false, "reason", reason); }

    private static final List<String[]> FIELD_REASON = List.of(
        new String[] {"goal_digest", "goal_digest_mismatch"}, new String[] {"policy_digest", "policy_digest_mismatch"}, new String[] {"ontology_digest", "ontology_mismatch"},
        new String[] {"tests_digest", "tests_digest_mismatch"}, new String[] {"nl_digest", "nl_digest_mismatch"}, new String[] {"model_set_digest", "model_set_digest_mismatch"},
        new String[] {"card_digest", "card_digest_mismatch"});

    /** {ok: true, digests, policy} | {ok: false, reason}. */
    private static Map<String, Object> derive(Object subO, ReviewKernel kernel, Map<String, Object> limits) {
        if (!isObj(subO)) return bad("malformed_submission");
        Map<String, Object> sub = mm(subO);
        if (!isObj(sub.get("goal")) || !isObj(sub.get("ontology")) || !(sub.get("instruction") instanceof String) || !(sub.get("model_set") instanceof List) || (sub.containsKey("tests") && !(sub.get("tests") instanceof List))) return bad("malformed_submission");
        for (Object m : list(sub.get("model_set"))) if (!(m instanceof String)) return bad("malformed_submission");
        Map<String, Object> goal = mm(sub.get("goal")), ontology = mm(sub.get("ontology"));
        List<Object> tests = sub.containsKey("tests") ? list(sub.get("tests")) : new ArrayList<>();
        Map<String, Object> card;
        try {
            card = renderPolicyCard(goal, tests, limits, false);
        } catch (ReviewError e) { return bad(e.code()); } catch (RuntimeException e) { return bad("malformed_goal"); }
        String gd, nl, ts, ms;
        try {
            gd = GoalDigests.goalDigest(goal);
            nl = GoalDigests.nlDigest((String) sub.get("instruction"));
            ts = GoalExamples.testsDigest(tests);
            List<String> models = new ArrayList<>();
            for (Object m : list(sub.get("model_set"))) models.add((String) m);
            ms = GoalDigests.modelSetDigest(models);
        } catch (RuntimeException e) { return bad("malformed_goal"); }
        if (!(goal.get("nlDigest") instanceof String) || !nl.equals(goal.get("nlDigest"))) return bad("instruction_mismatch");
        Map<String, Object> compiled;
        try { compiled = kernel.compile(goal, ontology); } catch (RuntimeException e) { return bad("compile_error"); }
        if (compiled == null || !Boolean.TRUE.equals(compiled.get("ok"))) return bad("compile_error");
        Map<String, Object> policy = mm(compiled.get("policy"));
        String pd;
        try {
            List<String> findings = kernel.analyze(policy);
            if (findings != null && !findings.isEmpty()) return bad("analyzer_error");
            pd = kernel.policyDigest(policy);
        } catch (RuntimeException e) { return bad("analyzer_error"); }
        if (!tests.isEmpty()) {
            if (!kernel.canDecide()) return bad("tests_unverifiable");
            // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
            for (Object to : tests) {
                Map<String, Object> t = mm(to);
                String got;
                try {
                    Map<String, Object> ont = ontology;
                    if (G.truthy(t.get("rels"))) { ont = new LinkedHashMap<>(ontology); ont.put("rels", t.get("rels")); }
                    got = kernel.decide(goal, ont, mm(t.get("act")), mm(t.get("hist")));
                } catch (RuntimeException e) { return bad("tests_unverifiable"); }
                if (!java.util.Objects.equals(got, GoalExamples.expectedDecision((String) t.get("answer")))) return bad("tests_contradicted");
            }
        }
        Map<String, Object> digests = G.map("goal_digest", gd, "policy_digest", pd, "card_digest", cardDigest(card), "ontology_digest", goal.get("ontDigest"), "tests_digest", ts, "nl_digest", nl, "model_set_digest", ms);
        return G.map("ok", true, "digests", digests, "policy", policy);
    }

    private static Map<String, Object> approveWith(Map<String, Object> sub, String reviewerId, java.util.function.Function<Map<String, Object>, Map<String, Object>> signer, ApproveOptions opts) {
        ApproveOptions o = opts != null ? opts : new ApproveOptions();
        long now = o.now != null ? o.now : System.currentTimeMillis();
        long ttl = o.ttlMs != null ? o.ttlMs : DEFAULT_TTL_MS;
        if (ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS || Math.abs(now) > G.MAX_SAFE) throw new IllegalArgumentException("approveGoal: invalid time or ttl");
        if (o.kernel == null) throw new IllegalArgumentException("approveGoal: a compiler kernel is required");
        Map<String, Object> d = derive(sub, o.kernel, o.limits);
        if (!Boolean.TRUE.equals(d.get("ok"))) throw new IllegalArgumentException("approveGoal: " + d.get("reason"));
        if (o.base != null) diffGoals(o.base, mm(sub.get("goal")), null, o.limits, null);
        Map<String, Object> body = new LinkedHashMap<>(mm(d.get("digests")));
        body.put("v", G.num(1)); body.put("reviewer", reviewerId); body.put("approved_at", G.num(now)); body.put("expires_at", G.num(now + ttl));
        return signer.apply(body);
    }

    /**
     * The human step: sign the exact goal with an Ed25519 seed. Re-derives everything the loader will; throws when the goal is not signable
     * (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a contradicted test, an instruction that
     * does not match {@code nlDigest}). A kernel is required.
     */
    public static Map<String, Object> approveGoal(Map<String, Object> sub, byte[] reviewerSeed, ApproveOptions opts) {
        return approveWith(sub, GoalSign.signerId(reviewerSeed), body -> GoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewerSeed), opts);
    }

    /** {@link #approveGoal} with a suite-agile (hybrid or post-quantum) signer. */
    public static Map<String, Object> approveGoal(Map<String, Object> sub, Keys.SuiteKey reviewer, ApproveOptions opts) {
        return approveWith(sub, reviewer.id(), body -> GoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewer), opts);
    }

    /**
     * The only door from a submitted goal to an enforceable one: recomputes every digest, recompiles, re-renders the card, re-runs the
     * confirmed examples, then checks the signature. Never throws: {ok: true, approved} | {ok: false, reason}.
     */
    public static Map<String, Object> loadApprovedGoal(Map<String, Object> sub, Map<String, Object> approval, LoadOptions opts) {
        try {
            long now = opts.now != null ? opts.now : System.currentTimeMillis();
            if (opts.reviewers == null || opts.reviewers.isEmpty()) return bad("no_reviewers_pinned");
            Map<String, Object> a = approval;
            if (a == null || !Long.valueOf(1).equals(G.safeInt(a.get("v"))) || !(a.get("sig") instanceof String) || !(a.get("reviewer") instanceof String) || G.safeInt(a.get("approved_at")) == null || G.safeInt(a.get("expires_at")) == null) return bad("malformed_approval");
            for (String[] f : FIELD_REASON) if (!(a.get(f[0]) instanceof String)) return bad("malformed_approval");
            if (opts.kernel == null) throw new IllegalArgumentException("a compiler kernel is required");
            Map<String, Object> d = derive(sub, opts.kernel, opts.limits);
            if (!Boolean.TRUE.equals(d.get("ok"))) return d;
            Map<String, Object> goal = mm(sub.get("goal"));
            if (opts.ontologyDigest != null && !opts.ontologyDigest.equals(goal.get("ontDigest"))) return bad("ontology_mismatch");
            Map<String, Object> digests = mm(d.get("digests"));
            for (String[] f : FIELD_REASON) if (!java.util.Objects.equals(a.get(f[0]), digests.get(f[0]))) return bad(f[1]);
            boolean pinned = false;
            for (Object p : opts.reviewers) if (java.util.Objects.equals(p instanceof String ? p : G.get(p, "pk"), a.get("reviewer"))) pinned = true;
            if (!pinned) return bad("reviewer_not_pinned");
            long approvedAt = G.safeInt(a.get("approved_at")), expiresAt = G.safeInt(a.get("expires_at"));
            if (expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_GOAL_APPROVAL_TTL_MS) return bad("ttl_too_long");
            if (approvedAt > now) return bad("not_yet_valid");
            if (now >= expiresAt) return bad("expired");
            if (!GoalSign.verifyGoalArtifact(GOAL_APPROVAL_KIND, a, "reviewer", opts.reviewers)) return bad("bad_signature");
            Map<String, Object> ref = G.map("goal_digest", digests.get("goal_digest"), "policy_digest", digests.get("policy_digest"));
            Map<String, Object> approved = G.map("goal", goal, "ontology", sub.get("ontology"), "policy", d.get("policy"), "ref", ref, "goal_string", Pca.intentGoalV3(ref),
                "intent_policy", G.map("approved_goal", ref), "instruction", sub.get("instruction"), "reviewer", a.get("reviewer"), "expires_at", a.get("expires_at"));
            return G.map("ok", true, "approved", approved);
        } catch (RuntimeException e) {
            return bad("malformed_approval");
        }
    }
}
