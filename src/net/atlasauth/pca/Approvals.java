package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Human approvals: standing "approve this class of action for N hours" grants, decisions, the budget effect of a human co-sign, and the
 * agent-facing half: review an intended action against a facade agent (auto / deny / step-up with its goal lineage and canonical render),
 * batch review, and time-boxing a grant. Nothing here authorizes anything; the resource server's verifier stays the authority.
 */
public final class Approvals {
    private Approvals() {}

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static double num(Object o) { Double d = StoreJs.dbl(o); return d == null ? Double.NaN : d; }

    /**
     * A standing approval {@code {id, verbs, resource?, grantedAt, ttlMs, by}} for the listed verbs, optionally narrowed to a resource pattern
     * ({@code *} suffix = prefix match), valid from {@code now} for {@code ttlMs}. {@code resource} may be null.
     */
    public static Map<String, Object> approveClass(List<String> verbs, double ttlMs, String by, double now, String resource) {
        List<String> sorted = new ArrayList<>(verbs);
        sorted.sort(Json::compareUtf8);
        Map<String, Object> idBody = new LinkedHashMap<>();
        idBody.put("d", "atlas-pca/class-approval/v1");
        idBody.put("verbs", new ArrayList<Object>(sorted));
        idBody.put("resource", resource);
        idBody.put("grantedAt", StoreJs.num(now));
        idBody.put("by", by);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", Pca.hashCanonical(idBody));
        m.put("verbs", new ArrayList<Object>(verbs));
        if (resource != null) m.put("resource", resource);
        m.put("grantedAt", StoreJs.num(now));
        m.put("ttlMs", StoreJs.num(ttlMs));
        m.put("by", by);
        return m;
    }

    private static boolean resourceMatches(String pattern, String resource) {
        if (pattern == null || pattern.equals("*")) return true;
        if (pattern.endsWith("*")) return resource.startsWith(pattern.substring(0, pattern.length() - 1));
        return pattern.equals(resource);
    }

    /** True while {@code a} is in force ({@code grantedAt <= now < grantedAt + ttlMs}) and covers the verb and the resource. */
    public static boolean classApprovalCovers(Map<String, Object> a, String verb, String resource, double now) {
        double granted = num(a.get("grantedAt")), ttl = num(a.get("ttlMs"));
        if (!(Double.isFinite(now) && Double.isFinite(granted) && Double.isFinite(ttl) && now >= granted && now < granted + ttl)) return false;
        if (!(a.get("verbs") instanceof List) || !((List<?>) a.get("verbs")).contains(verb)) return false;
        Object pattern = a.get("resource");
        return resourceMatches(pattern instanceof String ? (String) pattern : null, resource);
    }

    public static boolean coveredByAny(List<Object> approvals, String verb, String resource, double now) {
        for (Object a : approvals) if (classApprovalCovers(StoreJs.map(a), verb, resource, now)) return true;
        return false;
    }

    /** A human decision on a step-up request: {@code {requestId, decision: approve|deny, by, at}}. */
    public static Map<String, Object> recordDecision(Map<String, Object> request, String decision, String by, double at) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requestId", request.get("id"));
        m.put("decision", decision);
        m.put("by", by);
        m.put("at", StoreJs.num(at));
        return m;
    }

    /** The step-up requests among a batch of reviews ({@code {kind: step_up, request}}). */
    public static List<Object> pendingRequests(List<Object> reviews) {
        List<Object> out = new ArrayList<>();
        for (Object r : reviews) {
            Map<String, Object> m = StoreJs.map(r);
            if (m != null && "step_up".equals(m.get("kind"))) out.add(m.get("request"));
        }
        return out;
    }

    /**
     * The budget effect of a human co-sign, the ONLY way a budget rises: {@code full} re-confirms the goal ({@code B = bMax}); otherwise
     * {@code B = min(bMax, B + rho)}; {@code tau = asOf = now} either way. {@code policy} carries {@code rho} and {@code bMax}.
     */
    public static Map<String, Object> applyCosign(Map<String, Object> budget, Map<String, Object> policy, double now, boolean full) {
        if (full) return RiskBudgets.rechargeFull(num(policy.get("bMax")), now);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", StoreJs.num(Math.min(nz(num(policy.get("bMax"))), num(budget.get("B")) + nz(num(policy.get("rho"))))));
        m.put("tau", StoreJs.num(now));
        m.put("asOf", StoreJs.num(now));
        return m;
    }

    // ---- agent-facing half -------------------------------------------------------------------------------------------------

    /** Builds the canonical approval render of an action (what the approver must be shown); may throw, which makes the review a deny. */
    public interface Renderer { Map<String, Object> render(String verb, String resource, Map<String, Object> params); }

    /** Options of {@link #reviewAction}; every member is optional. */
    public static final class ReviewOptions {
        /** The clock (ms); the wall clock when null. */
        public Long now;
        /** Plaintext goal carried on a step-up request (shown to the approver). */
        public String goal;
        /** Standing class approvals that can downgrade a step-up to auto. */
        public List<Object> standing;
        /** Without a renderer (and without {@link #insecureUnboundApproval}) a step-up is a deny: what the approver sees is what is signed. */
        public Renderer renderer;
        /** DOCUMENTED INSECURE opt-out: keep the pre-render behaviour of an unbound request. */
        public boolean insecureUnboundApproval;
    }

    private static String jsStr(Object v, boolean present) { return present ? AttestNvidia.jsString(v) : "undefined"; }

    private static String jsText(double d) { return AttestCommon.jsNumString(d); }

    private static String formatLimit(Facade.ParsedLimit limit) {
        String base = "usd".equals(limit.unit) ? "$" + jsText(limit.amount) : jsText(limit.amount);
        if (limit.periodMs == null) return base;
        double ms = limit.periodMs;
        double hours = ms / 3_600_000d;
        String period = hours % 24 == 0 && hours >= 24 ? jsText(hours / 24) + "d" : hours >= 1 ? jsText(hours) + "h" : jsText(Math.floor(ms / 60_000d + 0.5)) + "m";
        return base + "/" + period;
    }

    /** JSON.stringify of a parsed value: JavaScript key order (index keys first) and number spelling. */
    private static String stringify(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean) return v.toString();
        if (v instanceof String) return Json.canonicalize(v);
        Double d = StoreJs.dbl(v);
        if (d != null) return Double.isNaN(d) || Double.isInfinite(d) ? "null" : jsText(d);
        StringBuilder b = new StringBuilder();
        if (v instanceof List) {
            b.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) b.append(','); first = false; b.append(stringify(x)); }
            return b.append(']').toString();
        }
        Map<?, ?> m = (Map<?, ?>) v;
        b.append('{');
        boolean first = true;
        for (String k : Decision.jsKeys(m)) { if (!first) b.append(','); first = false; b.append(Json.canonicalize(k)).append(':').append(stringify(m.get(k))); }
        return b.append('}').toString();
    }

    private static String summarizeParams(Map<String, Object> params, String amountField) {
        if (params == null) return null;
        if (amountField != null && params.containsKey(amountField)) return amountField + "=" + AttestNvidia.jsString(params.get(amountField));
        List<String> keys = Decision.jsKeys(params);
        if (keys.isEmpty()) return null;
        List<String> parts = new ArrayList<>();
        for (String k : keys.subList(0, Math.min(4, keys.size()))) {
            Object x = params.get(k);
            parts.add(k + "=" + (x == null || x instanceof Map || x instanceof List ? stringify(x) : AttestNvidia.jsString(x)));
        }
        return String.join(", ", parts);
    }

    private static Map<String, Object> node(String kind, String label, String detail) {
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("kind", kind);
        n.put("label", label);
        if (detail != null) n.put("detail", detail);
        return n;
    }

    /**
     * The goal lineage of one intended action ("you approved X because you asked to Y"): the grant's goal commitment, threaded through the
     * delegated authority that admits the verb, down to the action. {@code goal} (plaintext, may be null) is checked against the commitment
     * with the agent's salt: {@code goalVerified} says whether it opens it, so an inbox shows "unverified" rather than lie. Signs nothing.
     */
    public static Map<String, Object> buildGoalLineage(Facade.Handle agent, String verb, String resource, Map<String, Object> params, String goal) {
        Map<String, Object> env = Authorize.readEnvelope(agent.grant);
        String goalCommit = env != null && env.get("goal_commit") instanceof String ? (String) env.get("goal_commit") : "";
        boolean verified = goal != null && !goalCommit.isEmpty() && agent.goalSalt != null && !agent.goalSalt.isEmpty()
            && Issue.goalCommit(goal, agent.goalSalt).equals(goalCommit);
        Catalog.Spec spec = null;
        for (Catalog.Spec s : agent.policy.actions) if (s.verb.equals(verb)) { spec = s; break; }
        Facade.ParsedLimit limit = agent.policy.limits.get(verb);

        String goalLabel = goal != null ? "Pursue the goal: “" + goal + "”" : "Pursue the grant’s committed goal";
        String goalDetail = goal != null
            ? (verified ? "verified: this goal opens the signed grant commitment" : "unverified: the revealed goal does not open the grant commitment")
            : !goalCommit.isEmpty() ? "committed as " + goalCommit : null;
        String authorityLabel = "Delegated authority to " + verb + (limit != null ? " (up to " + formatLimit(limit) + ")" : "");
        String actionDetail = summarizeParams(params, spec != null ? spec.amountField : null);

        List<Object> chain = new ArrayList<>();
        chain.add(node("goal", goalLabel, goalDetail));
        chain.add(node("authority", authorityLabel, spec != null && spec.description != null && !spec.description.isEmpty() ? spec.description : null));
        chain.add(node("action", verb + " " + resource, actionDetail));

        String because = goal != null
            ? "Approving " + verb + " on " + resource + " because you asked to “" + goal + "”."
            : "Approving " + verb + " on " + resource + ", authorized under the grant’s committed goal.";
        Map<String, Object> out = new LinkedHashMap<>();
        if (goal != null) out.put("goal", goal);
        out.put("goalCommit", goalCommit);
        out.put("goalVerified", verified);
        out.put("chain", chain);
        out.put("because", because);
        return out;
    }

    /**
     * A lineage flattened to plain text lines (SMS, plain email, Slack fallback): {@code label — detail}, or the label alone when the
     * hop has no (truthy) detail. A label that is not a string is returned as is, like the reference.
     */
    public static List<Object> describeGoalLineage(Map<String, Object> lineage) {
        if (lineage == null) throw new IllegalArgumentException("describeGoalLineage: lineage required");
        if (!(lineage.get("chain") instanceof List)) throw new IllegalArgumentException("describeGoalLineage: chain must be a list");
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) lineage.get("chain")) {
            if (o == null) throw new IllegalArgumentException("describeGoalLineage: a hop must not be null");
            if (!(o instanceof Map)) { out.add(null); continue; }   // a primitive has no label or detail
            Map<?, ?> n = (Map<?, ?>) o;
            Object detail = n.get("detail"), label = n.get("label");
            if (truthy(detail)) out.add(jsStr(label, n.containsKey("label")) + " — " + AttestNvidia.jsString(detail));
            else out.add(label);
        }
        return out;
    }

    private static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = StoreJs.dbl(v);
        return d == null || !(d == 0 || Double.isNaN(d));
    }

    private static double riskForReview(Facade.Handle agent, String verb, Map<String, Object> params) {
        Catalog.Spec spec = null;
        for (Catalog.Spec s : agent.policy.actions) if (s.verb.equals(verb)) { spec = s; break; }
        Double kappa = Caveats.fin(agent.policy.riskPolicy.get("kappa"));
        if ("dollars".equals(agent.policy.budgetModel) && spec != null && spec.amountField != null) {
            double amt = params == null ? Double.NaN : Actions.jsNumber(params.get(spec.amountField), params.containsKey(spec.amountField));
            if (!Double.isNaN(amt) && !Double.isInfinite(amt) && kappa != null && kappa > 0) return Math.max(0, Math.min(1, amt / kappa));
        }
        return Math.max(0, Math.min(1, spec != null ? spec.blastRadius : 0.8));
    }

    private static Map<String, Object> review(String kind, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", kind);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /**
     * Review an intended action against the agent's grant. {@code {kind: auto}}: no human needed; {@code {kind: deny, reason}}: the grant's
     * predicates or caveats forbid it, or no complete approval render could be made (fail closed); {@code {kind: step_up, request}}:
     * admissible but needs a tier-2/3 co-sign, unless a standing class approval covers it. A step-up carries the canonical render and its
     * digest, unless {@code insecureUnboundApproval} is set and no renderer given. {@code opts} may be null.
     */
    public static Map<String, Object> reviewAction(Facade.Handle agent, String verb, String resource, Map<String, Object> params, ReviewOptions opts) {
        ReviewOptions op = opts != null ? opts : new ReviewOptions();
        long now = op.now != null ? op.now : System.currentTimeMillis();
        Facade.DryRun dr = agent.dryRun(verb, resource, params, now);
        if (!dr.allowed) return review("deny", dr.reason != null ? dr.reason : "denied by policy");
        if (dr.t == null || dr.t == 1) return review("auto", null);
        if (op.standing != null && coveredByAny(op.standing, verb, resource, (double) now)) return review("auto", null);
        int tier = dr.t;
        Map<String, Object> render = null;
        String renderDigest = null;
        if (op.renderer == null && !op.insecureUnboundApproval)
            return review("deny", "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true");
        if (op.renderer != null) {
            try {
                render = op.renderer.render(verb, resource, params);
                renderDigest = Approval.renderDigest(render);
            } catch (RuntimeException err) {
                return review("deny", "approval render failed (fail closed): " + (err.getMessage() != null ? err.getMessage() : ""));
            }
        }
        Map<String, Object> env = Authorize.readEnvelope(agent.grant);
        String goalCommit = env != null && env.get("goal_commit") instanceof String ? (String) env.get("goal_commit") : "";
        Map<String, Object> lineage = buildGoalLineage(agent, verb, resource, params, op.goal);
        Map<String, Object> idBody = new LinkedHashMap<>();
        idBody.put("d", "atlas-pca/stepup/v1");
        idBody.put("verb", verb);
        idBody.put("resource", resource);
        idBody.put("params", params);
        idBody.put("at", StoreJs.num(now));
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("id", Pca.hashCanonical(idBody));
        request.put("verb", verb);
        request.put("resource", resource);
        if (params != null) request.put("params", params);
        request.put("tier", StoreJs.num((long) tier));
        request.put("reason", dr.reason != null ? dr.reason : "requires tier " + tier + " co-sign");
        request.put("goalCommit", goalCommit);
        if (op.goal != null) request.put("goal", op.goal);
        request.put("lineage", lineage);
        request.put("r", StoreJs.num(riskForReview(agent, verb, params)));
        request.put("requestedAt", StoreJs.num(now));
        if (render != null && renderDigest != null) {
            request.put("render", render);
            request.put("renderDigest", renderDigest);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", "step_up");
        out.put("request", request);
        return out;
    }

    /** Review a batch of intended actions ({@code {verb, resource, params?}} each): the inbox's "N actions waiting". */
    public static List<Object> batchReview(Facade.Handle agent, List<Map<String, Object>> calls, ReviewOptions opts) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> c : calls) out.add(reviewAction(agent, (String) c.get("verb"), (String) c.get("resource"), StoreJs.map(c.get("params")), opts));
        return out;
    }

    /**
     * Narrow a capability to expire {@code ttlMs} after {@code now} by appending an {@code expires} caveat signed by the holder. Caveats are
     * conjunctive and append-only, so this can only restrict, never widen.
     */
    public static Map<String, Object> timeBox(Map<String, Object> parent, Keys.SuiteKey holder, double ttlMs, double now) {
        double at = now + ttlMs;
        if (Double.isNaN(at) || Double.isInfinite(at)) throw new IllegalArgumentException("timeBox: the expiry must be a finite number");
        Map<String, Object> cav = new LinkedHashMap<>();
        cav.put("type", "expires");
        cav.put("at", StoreJs.num(at));
        List<Object> added = new ArrayList<>();
        added.add(cav);
        return Issue.attenuate(parent, added, holder);
    }
}
