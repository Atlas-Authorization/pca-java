package net.atlasauth.pca.authzen;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, the Access Evaluations boxcar, the COAZ
 * MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over {path, body} maps and the three Search APIs.
 * Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any thrown error is
 * {@code decision: false}. Requests, bodies and responses are {@code Map<String,Object>} trees (parsed JSON; member names as on the wire).
 *
 * <p>The proof is verified by the native core verifier ({@link net.atlasauth.pca.PcaCore}). The Policy-VM decision and the static policy
 * admission default to {@link net.atlasauth.pca.Decide} and the analyzer's exact admission; a PDP may replace them through the config keys
 * {@code policyVm} ({@link PolicyVm}) and {@code admitsConcrete} ({@link Admits}). The verifier enforcement gates (taint / freshness /
 * attestation) of a resolved context are not supported: a context carrying {@code enforce} fails closed.
 *
 * <p>Config keys (reference names): resolve ({@link Resolver}, required), audience (String; present as null = accept any; absent =
 * fail closed when the PCActn carries an aud), authorizedPlanRoots (List), insecureSkipPlanRootCheck, now ({@link LongSupplier}),
 * toolCapability ({@link ToolCapability}), requireProof (default true), authorizer ({@link Authorizer}), requireAuthorizer (default true),
 * maxEvaluations (default 100). A resolved context is {grant, chain?, policy, plan?, risk?, budget?, enforce?, toAction?}.
 */
public final class Authzen {
    private Authzen() {}

    public static final String PCA_APPROVAL_KEY = "pca_approval";
    public static final String PCA_ACTION_KEY = "pca_action";
    public static final String PCA_PROVENANCE_KEY = "pca_provenance";
    public static final int DEFAULT_MAX_EVALUATIONS = 100;
    public static final String EVALUATION_PATH = "/access/v1/evaluation";
    public static final String EVALUATIONS_PATH = "/access/v1/evaluations";
    public static final String COAZ_TOOL_PATH = "/access/v1/mcp/tool/evaluation";
    public static final String SEARCH_SUBJECT_PATH = "/access/v1/search/subject";
    public static final String SEARCH_RESOURCE_PATH = "/access/v1/search/resource";
    public static final String SEARCH_ACTION_PATH = "/access/v1/search/action";
    public static final int MAX_SEARCH_LIMIT = 1000;

    /** Resolve the PCA authority for a request: a context map, or null to DENY. May throw (a throw fails closed). */
    @FunctionalInterface public interface Resolver { Map<String, Object> resolve(Map<String, Object> req) throws Exception; }
    /** The Core authorizer (replay counter, budget, revocation): input {operation, pcactn, provenance?}, result {allow, reason?}. */
    @FunctionalInterface public interface Authorizer { Map<String, Object> authorize(Map<String, Object> input) throws Exception; }
    /** An MCP tool name to the capability (verb) it requires. */
    @FunctionalInterface public interface ToolCapability { String capability(String toolName) throws Exception; }
    /** The Policy-VM: derive the decision input from the PCActn and the context {grant, chain, plan?, params, risk, budget, now, subject?, env?}, decide. Returns {releaseGuardianShare, admit, r, requiredThreshold, reasons}. */
    @FunctionalInterface public interface PolicyVm { Map<String, Object> decide(Map<String, Object> pcactn, Map<String, Object> ctx) throws Exception; }
    /** Static admission of a mapped action under a policy ("could this ever be allowed?"). */
    @FunctionalInterface public interface Admits { boolean admits(Object policy, Map<String, Object> action) throws Exception; }
    /** One search provider function. */
    @FunctionalInterface public interface SearchFn { Map<String, Object> search(Map<String, Object> req) throws Exception; }

    /** A JSON member that is absent (JavaScript undefined), distinct from null. */
    private static final Object UNDEF = new Object();

    // ---- helpers ----

    private static boolean isRec(Object x) { return x instanceof Map; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> rec(Object x) { return (Map<String, Object>) x; }

    private static boolean isStr(Object x) { return x instanceof String; }

    /** x[k] in JavaScript: UNDEF for an absent member or a primitive / array, a throw for null. */
    private static Object prop(Object x, String k) {
        if (x == null) throw new IllegalStateException("Cannot read properties of null (reading '" + k + "')");
        if (x instanceof Map && ((Map<?, ?>) x).containsKey(k)) return ((Map<?, ?>) x).get(k);
        return UNDEF;
    }

    private static boolean isNumber(Object x) { return x instanceof Json.Num || x instanceof Number; }

    private static boolean numEq(Object x, double v) { Double d = JsVal.num(x); return d != null && d == v; }

    /** A JavaScript template-literal rendering of a JSON value. */
    private static String js(Object v) {
        if (v == UNDEF) return "undefined";
        if (v == null) return "null";
        if (v instanceof Json.Num || v instanceof Number) return Json.canonicalize(v instanceof Json.Num ? v : new Json.Num(String.valueOf(v)));
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(js(x));
            }
            return sb.toString();
        }
        if (v instanceof Map) return "[object Object]";
        return String.valueOf(v);
    }

    private static String err(Throwable e) { return e.getMessage() == null ? "" : e.getMessage(); }

    private static Map<String, Object> obj() { return new LinkedHashMap<>(); }

    // ---- guards ----

    public static boolean isAuthzenSubject(Object x) { return isRec(x) && isStr(rec(x).get("type")) && isStr(rec(x).get("id")); }
    public static boolean isAuthzenAction(Object x) { return isRec(x) && isStr(rec(x).get("name")); }
    public static boolean isAuthzenResource(Object x) { return isRec(x) && isStr(rec(x).get("type")) && isStr(rec(x).get("id")); }

    public static boolean isAccessEvaluationRequest(Object x) {
        return isRec(x) && isAuthzenSubject(rec(x).get("subject")) && isAuthzenAction(rec(x).get("action")) && isAuthzenResource(rec(x).get("resource"))
            && (!rec(x).containsKey("context") || isRec(rec(x).get("context")));
    }

    public static boolean isAccessEvaluationsRequest(Object x) { return isRec(x) && rec(x).get("evaluations") instanceof List; }

    public static boolean isCoazToolAuthorizationRequest(Object x) {
        return isRec(x) && isAuthzenSubject(rec(x).get("subject")) && isRec(rec(x).get("tool")) && isStr(rec(x).get("tool") instanceof Map ? rec(rec(x).get("tool")).get("name") : null);
    }

    private static boolean isRequiredThreshold(Object x) {
        return isRec(x) && (numEq(rec(x).get("t"), 1) || numEq(rec(x).get("t"), 2) || numEq(rec(x).get("t"), 3)) && isStr(rec(x).get("proof"))
            && rec(x).get("optimisticAllowed") instanceof Boolean;
    }

    // ---- AARP ----

    /** The AARP pending-approval reference of a decision, or null. */
    public static Map<String, Object> approvalOf(Object resp) {
        Object ctx = prop(resp, "context");
        if (ctx == UNDEF) return null;
        Object p = prop(ctx, PCA_APPROVAL_KEY);
        if (p instanceof Map && Boolean.TRUE.equals(rec(p).get("approval_required")) && isStr(rec(p).get("auth_req_id"))) {
            Map<String, Object> m = rec(p);
            int tier = numEq(m.get("tier"), 3) ? 3 : 2;
            Object rt = m.get("required_threshold");
            Map<String, Object> out = obj();
            out.put("approval_required", Boolean.TRUE);
            out.put("auth_req_id", m.get("auth_req_id"));
            out.put("tier", JsVal.n(tier));
            if (isRequiredThreshold(rt)) out.put("required_threshold", rt);
            else {
                Map<String, Object> d = obj();
                d.put("t", JsVal.n(tier));
                d.put("proof", tier == 3 ? "strong" : "standard");
                d.put("optimisticAllowed", Boolean.FALSE);
                out.put("required_threshold", d);
            }
            out.put("goal_commit", isStr(m.get("goal_commit")) ? m.get("goal_commit") : "");
            out.put("risk", isNumber(m.get("risk")) ? m.get("risk") : JsVal.n(1));
            out.put("reason", isStr(m.get("reason")) ? m.get("reason") : "approval required");
            out.put("requested_at", isNumber(m.get("requested_at")) ? m.get("requested_at") : JsVal.n(0));
            return out;
        }
        return null;
    }

    public static boolean isApprovalRequired(Object resp) { return approvalOf(resp) != null; }

    // ---- mapping ----

    private static Map<String, Object> deny(String reason, String id, Integer status) {
        Map<String, Object> admin = obj();
        admin.put("denied", Boolean.TRUE);
        admin.put("reason", reason);
        Map<String, Object> user = obj();
        user.put("message", reason);
        Map<String, Object> context = obj();
        context.put("reason_admin", admin);
        context.put("reason_user", user);
        if (status != null) {
            Map<String, Object> e = obj();
            e.put("status", JsVal.n(status));
            e.put("message", reason);
            context.put("error", e);
        }
        if (id != null) context.put("id", id);
        Map<String, Object> r = obj();
        r.put("decision", Boolean.FALSE);
        r.put("context", context);
        return r;
    }

    private static Map<String, Object> permit(String reason) {
        Map<String, Object> admin = obj();
        admin.put("reason", reason);
        Map<String, Object> context = obj();
        context.put("reason_admin", admin);
        Map<String, Object> r = obj();
        r.put("decision", Boolean.TRUE);
        r.put("context", context);
        return r;
    }

    private static String pickReversibility(Map<String, Object> req) {
        Object fromAction = rec(req.get("action")).get("properties");
        if (isRec(fromAction) && isStr(rec(fromAction).get("reversibility_class"))) return (String) rec(fromAction).get("reversibility_class");
        Object fromCtx = req.get("context");
        if (isRec(fromCtx) && isStr(rec(fromCtx).get("reversibility_class"))) return (String) rec(fromCtx).get("reversibility_class");
        return null;
    }

    private static Map<String, Object> envFromContext(Object context) {
        if (!isRec(context)) return null;
        Map<String, Object> out = obj();
        for (Map.Entry<String, Object> e : rec(context).entrySet()) {
            if (e.getKey().equals(PCA_ACTION_KEY) || e.getKey().equals(PCA_APPROVAL_KEY)) continue;
            out.put(e.getKey(), e.getValue());
        }
        return out.isEmpty() ? null : out;
    }

    /**
     * The default AuthZEN to PCA action mapping: verb = action.name; resource = "type:id" (just the type when id is empty); params =
     * resource.properties overlaid by action.properties; subject = subject.properties; env = context minus the PCA keys.
     */
    public static Map<String, Object> defaultToAction(Map<String, Object> req) {
        Map<String, Object> res = rec(req.get("resource")), act = rec(req.get("action"));
        String type = (String) res.get("type"), id = (String) res.get("id");
        String resource = id.length() > 0 ? type + ":" + id : type;
        Map<String, Object> params = obj();
        if (isRec(res.get("properties"))) params.putAll(rec(res.get("properties")));
        if (isRec(act.get("properties"))) params.putAll(rec(act.get("properties")));
        Map<String, Object> out = obj();
        out.put("verb", act.get("name"));
        out.put("resource", resource);
        out.put("params", params);
        String rc = pickReversibility(req);
        if (rc != null) out.put("reversibilityClass", rc);
        Object subjProps = rec(req.get("subject")).get("properties");
        if (isRec(subjProps)) out.put("subject", subjProps);
        Map<String, Object> env = envFromContext(req.get("context"));
        if (env != null) out.put("env", env);
        return out;
    }

    private static final Object MALFORMED = new Object();

    /** The forwarded PCActn tree, null when absent, or {@link #MALFORMED}. */
    private static Object pcactnFromContext(Object context) {
        if (!isRec(context)) return null;
        Object raw = rec(context).get(PCA_ACTION_KEY);
        if (raw == null) return null;
        if (!(raw instanceof String)) return MALFORMED;
        try {
            if (Pca.artifactTooLarge((String) raw)) return MALFORMED;
            Object v = Json.parse((String) raw);
            return v instanceof Map ? v : MALFORMED;
        } catch (RuntimeException | StackOverflowError e) {
            return MALFORMED;
        }
    }

    private static Map<String, Object> paramsOf(Map<String, Object> action) { return isRec(action.get("params")) ? rec(action.get("params")) : obj(); }

    private static Object freshBudget(Object grant, long now) {
        Map<String, Object> env = Authorize.readEnvelope(grant);
        Object rp = env == null ? null : env.get("risk_policy");
        Object bMax = isRec(rp) ? rec(rp).get("bMax") : null;
        Map<String, Object> b = obj();
        Double d = JsVal.num(bMax);
        b.put("B", d != null && !Double.isNaN(d) && !Double.isInfinite(d) ? bMax : JsVal.n(0));
        b.put("tau", JsVal.n(now));
        b.put("asOf", JsVal.n(now));
        return b;
    }

    /** The AARP approval-required decision from a step-up Policy-VM result. */
    private static Map<String, Object> approvalRequired(Map<String, Object> p, Map<String, Object> decision, Object grant, long now) {
        Object thr = decision.get("requiredThreshold");
        double t = JsVal.num(rec(thr).get("t"));
        int tier = t >= 3 ? 3 : 2;
        Object reasons = decision.get("reasons");
        Object reason = reasons instanceof List && !((List<?>) reasons).isEmpty() && ((List<?>) reasons).get(0) != null ? ((List<?>) reasons).get(0) : "requires tier-" + tier + " co-sign";
        Map<String, Object> action = rec(p.get("action"));
        Map<String, Object> body = obj();
        body.put("d", "atlas-pca/authzen/aarp/v1");
        body.put("verb", action.get("verb"));
        body.put("resource", action.get("resource"));
        body.put("params_digest", action.get("params_digest"));
        if (p.containsKey("counter")) body.put("counter", p.get("counter"));
        body.put("at", JsVal.n(now));
        String authReqId = Pca.hashCanonical(body);
        Map<String, Object> env = Authorize.readEnvelope(grant);
        Map<String, Object> pending = obj();
        pending.put("approval_required", Boolean.TRUE);
        pending.put("auth_req_id", authReqId);
        pending.put("tier", JsVal.n(tier));
        pending.put("required_threshold", thr);
        pending.put("goal_commit", env != null && env.get("goal_commit") != null ? env.get("goal_commit") : "");
        pending.put("risk", decision.get("r"));
        pending.put("reason", reason);
        pending.put("requested_at", JsVal.n(now));
        Map<String, Object> admin = obj();
        admin.put("stage", "step_up");
        admin.put("risk", decision.get("r"));
        admin.put("threshold", thr);
        admin.put("reasons", reasons);
        Map<String, Object> user = obj();
        user.put("message", "approval required before this action can proceed");
        Map<String, Object> context = obj();
        context.put("id", authReqId);
        context.put("reason_admin", admin);
        context.put("reason_user", user);
        context.put(PCA_APPROVAL_KEY, pending);
        Map<String, Object> r = obj();
        r.put("decision", Boolean.FALSE);
        r.put("context", context);
        return r;
    }

    /** Merge boxcar defaults with one item; null when a required piece is still missing (fail closed). Throws for a null item. */
    private static Map<String, Object> mergeEvaluation(Map<String, Object> defaults, Object item) {
        if (item == null) throw new IllegalStateException("Cannot read properties of null (reading 'subject')");
        Map<String, Object> it = isRec(item) ? rec(item) : obj();
        Object subject = it.get("subject") != null ? it.get("subject") : defaults.get("subject");
        Object action = it.get("action") != null ? it.get("action") : defaults.get("action");
        Object resource = it.get("resource") != null ? it.get("resource") : defaults.get("resource");
        Object context = it.get("context") != null ? it.get("context") : defaults.get("context");
        boolean hasContext = it.get("context") != null || defaults.containsKey("context");
        if (!isAuthzenSubject(subject) || !isAuthzenAction(action) || !isAuthzenResource(resource)) return null;
        Map<String, Object> out = obj();
        out.put("subject", subject);
        out.put("action", action);
        out.put("resource", resource);
        if (hasContext && (it.get("context") != null || defaults.containsKey("context"))) out.put("context", context);
        return out;
    }

    // ---- the PDP ----

    /** The Policy Decision Point over a config (see the class comment). */
    public static AuthzenPdp authzenPdp(Map<String, Object> config) { return new AuthzenPdp(config); }

    public static final class AuthzenPdp {
        private final Map<String, Object> config;
        private final LongSupplier clock;

        AuthzenPdp(Map<String, Object> config) {
            this.config = config;
            this.clock = config.get("now") instanceof LongSupplier ? (LongSupplier) config.get("now") : System::currentTimeMillis;
        }

        private Object cfg(String k) { return config.get(k); }

        @SuppressWarnings("unchecked")
        private <T> T need(String key, Class<T> type) {
            Object v = config.get(key);
            if (!type.isInstance(v)) throw new IllegalStateException("authzen: config." + key + " is not provided (fail closed)");
            return (T) v;
        }

        /** AuthZEN Access Evaluation: one {subject, action, resource, context} to one decision. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> evaluate(Object reqO) {
            long now = clock.getAsLong();
            try {
                Map<String, Object> req = rec(reqO);
                Resolver resolver = need("resolve", Resolver.class);
                Map<String, Object> ctx = resolver.resolve(req);
                if (ctx == null) return deny("no PCA authority resolved for this request", null, null);

                Map<String, Object> mapped = ctx.get("toAction") instanceof java.util.function.Function
                    ? ((java.util.function.Function<Map<String, Object>, Map<String, Object>>) ctx.get("toAction")).apply(req) : defaultToAction(req);
                Object carried = pcactnFromContext(req.get("context"));
                if (carried == MALFORMED) return deny("context carries a malformed PCActn", null, null);

                // static path: no PCActn, "is this admissible under the declared authority at all?"
                if (carried == null) {
                    if (!Boolean.FALSE.equals(cfg("requireProof"))) return deny("a signed PCActn is required (requireProof)", null, null);
                    Admits admits = cfg("admitsConcrete") instanceof Admits ? (Admits) cfg("admitsConcrete") : net.atlasauth.pca.analyzer.Analyzer::admitsConcrete;
                    boolean admissible = admits.admits(ctx.get("policy"), mapped);
                    return admissible ? permit("statically admissible under the declared authority") : deny("action is not admissible under the declared authority", null, null);
                }

                // proof-carrying path: verify the PCActn, then run the Policy-VM decision
                Map<String, Object> p = rec(carried);
                if (!Boolean.FALSE.equals(cfg("requireAuthorizer")) && !(cfg("authorizer") instanceof Authorizer)) {
                    return deny("no replay/revocation authorizer is configured (requireAuthorizer)", null, null);
                }

                // The proof must be FOR the action asked about: verb + resource, and the request's attributes must hash to the signed params_digest.
                Object act = p.containsKey("action") ? p.get("action") : UNDEF;
                if (act == UNDEF || act == null) throw new IllegalStateException("Cannot read properties of " + (act == null ? "null" : "undefined") + " (reading 'verb')");
                Object verb = prop(act, "verb"), resource = prop(act, "resource");
                if (!(verb instanceof String && verb.equals(mapped.get("verb"))) || !(resource instanceof String && resource.equals(mapped.get("resource")))) {
                    return deny("the PCActn authorizes " + js(verb) + " on " + js(resource) + ", not the requested " + js(mapped.get("verb")) + " on " + js(mapped.get("resource")), null, null);
                }
                Map<String, Object> reqParams = paramsOf(mapped);
                if (!Pca.paramsDigest(reqParams).equals(prop(act, "params_digest"))) {
                    return deny("the request attributes do not match the PCActn's signed params_digest", null, null);
                }

                if (ctx.get("enforce") != null) throw new IllegalStateException("authzen: enforce gates are not supported by this verifier (fail closed)");
                net.atlasauth.pca.PcaCore.Options co = new net.atlasauth.pca.PcaCore.Options(ctx.get("grant") instanceof Map ? rec(ctx.get("grant")) : obj());
                co.nowEpoch = now;
                // a string must equal the PCActn's aud, an explicit null accepts any, an omitted audience fails closed when the PCActn carries one
                if (config.containsKey("audience")) { if (config.get("audience") == null) co.audienceAny(); else co.audience((String) config.get("audience")); }
                co.planRoots = Pca.PlanRoots.of(cfg("authorizedPlanRoots") instanceof List ? stringList((List<?>) cfg("authorizedPlanRoots")) : null, Boolean.TRUE.equals(cfg("insecureSkipPlanRootCheck")));
                net.atlasauth.pca.PcaCore.Result verify = net.atlasauth.pca.PcaCore.verify(p, co);
                if (!verify.allow) {
                    Map<String, Object> checks = obj();
                    checks.putAll(verify.checks);
                    Map<String, Object> admin = obj();
                    admin.put("denied", Boolean.TRUE);
                    admin.put("stage", "verify");
                    admin.put("checks", checks);
                    admin.put("reason", verify.reason == null || verify.reason.isEmpty() ? "PCActn verification failed" : verify.reason);
                    Map<String, Object> user = obj();
                    user.put("message", "the proof-carrying action did not verify");
                    Map<String, Object> context = obj();
                    context.put("reason_admin", admin);
                    context.put("reason_user", user);
                    Map<String, Object> r = obj();
                    r.put("decision", Boolean.FALSE);
                    r.put("context", context);
                    return r;
                }

                Object budget = ctx.get("budget") != null ? ctx.get("budget") : freshBudget(ctx.get("grant"), now);
                Map<String, Object> dctx = obj();
                dctx.put("grant", ctx.get("grant"));
                dctx.put("chain", ctx.get("chain") != null ? ctx.get("chain") : p.get("cap_chain"));
                if (ctx.get("plan") != null) dctx.put("plan", ctx.get("plan"));
                dctx.put("params", reqParams);
                dctx.put("risk", ctx.get("risk") != null ? ctx.get("risk") : obj());
                dctx.put("budget", budget);
                dctx.put("now", JsVal.n(now));
                if (mapped.get("subject") != null) dctx.put("subject", mapped.get("subject"));
                if (mapped.get("env") != null) dctx.put("env", mapped.get("env"));
                PolicyVm vm = cfg("policyVm") instanceof PolicyVm ? (PolicyVm) cfg("policyVm") : (pc, c) -> net.atlasauth.pca.Decide.decide(net.atlasauth.pca.Decide.deriveDecideInput(pc, c));
                Map<String, Object> decision = vm.decide(p, dctx);

                if (!JsVal.truthy(decision.get("releaseGuardianShare"))) {
                    Map<String, Object> admin = obj();
                    admin.put("denied", Boolean.TRUE);
                    admin.put("stage", "policy");
                    admin.put("reasons", decision.get("reasons"));
                    admin.put("risk", decision.get("r"));
                    Map<String, Object> user = obj();
                    user.put("message", "the policy does not permit this action");
                    Map<String, Object> context = obj();
                    context.put("reason_admin", admin);
                    context.put("reason_user", user);
                    Map<String, Object> r = obj();
                    r.put("decision", Boolean.FALSE);
                    r.put("context", context);
                    return r;
                }

                if (JsVal.truthy(decision.get("admit"))) {
                    if (cfg("authorizer") instanceof Authorizer) {
                        Map<String, Object> op = obj();
                        op.put("verb", mapped.get("verb"));
                        op.put("resource", mapped.get("resource"));
                        op.put("params", reqParams);
                        Map<String, Object> in = obj();
                        in.put("operation", op);
                        in.put("pcactn", p);
                        Object provenance = isRec(req.get("context")) ? rec(req.get("context")).get(PCA_PROVENANCE_KEY) : null;
                        if (provenance != null) in.put("provenance", provenance);
                        Map<String, Object> az = ((Authorizer) cfg("authorizer")).authorize(in);
                        if (!JsVal.truthy(az.get("allow"))) {
                            Map<String, Object> admin = obj();
                            admin.put("denied", Boolean.TRUE);
                            admin.put("stage", "authorize");
                            if (az.get("reason") != null) admin.put("reason", az.get("reason"));
                            Map<String, Object> user = obj();
                            user.put("message", "the proof-carrying action was not authorized");
                            Map<String, Object> context = obj();
                            context.put("reason_admin", admin);
                            context.put("reason_user", user);
                            Map<String, Object> r = obj();
                            r.put("decision", Boolean.FALSE);
                            r.put("context", context);
                            return r;
                        }
                    }
                    Map<String, Object> admin = obj();
                    admin.put("stage", "policy");
                    admin.put("risk", decision.get("r"));
                    admin.put("threshold", decision.get("requiredThreshold"));
                    Map<String, Object> context = obj();
                    context.put("reason_admin", admin);
                    Map<String, Object> r = obj();
                    r.put("decision", Boolean.TRUE);
                    r.put("context", context);
                    return r;
                }
                // Admissible but needs a guardian / human co-sign: AARP approval-required (step-up).
                return approvalRequired(p, decision, ctx.get("grant"), now);
            } catch (Exception | StackOverflowError e) {
                return deny("evaluation error (fail closed): " + err(e instanceof Exception ? e : new RuntimeException("unknown")), null, 500);
            }
        }

        private static List<String> stringList(List<?> l) {
            List<String> out = new ArrayList<>();
            for (Object o : l) if (o instanceof String) out.add((String) o);
            return out;
        }

        /** AuthZEN Access Evaluations: the boxcar endpoint with default inheritance and the evaluations_semantic. */
        public Map<String, Object> evaluations(Object reqO) {
            if (reqO == null) throw new IllegalStateException("Cannot read properties of null (reading 'evaluations')");
            Map<String, Object> req = isRec(reqO) ? rec(reqO) : obj();
            Object itemsO = req.get("evaluations");
            Map<String, Object> out = obj();
            if (!(itemsO instanceof List)) {
                out.put("evaluations", new ArrayList<Object>());
                return out;
            }
            List<?> items = (List<?>) itemsO;
            Object options = req.get("options");
            Object semantic = isRec(options) && rec(options).get("evaluations_semantic") != null ? rec(options).get("evaluations_semantic") : "execute_all";
            if (!"execute_all".equals(semantic) && !"deny_on_first_deny".equals(semantic) && !"permit_on_first_permit".equals(semantic)) return refuse(items, "unsupported evaluations_semantic");
            Object maxO = cfg("maxEvaluations");
            double max = maxO == null ? DEFAULT_MAX_EVALUATIONS : (maxO instanceof Double && ((Double) maxO).isInfinite() ? Double.POSITIVE_INFINITY : JsVal.num(maxO));
            if (items.size() > max) return refuse(items, "too many evaluations (limit " + (Double.isInfinite(max) ? "Infinity" : js(maxO)) + ")");
            List<Map<String, Object>> merged = new ArrayList<>();
            for (Object it : items) merged.add(mergeEvaluation(req, it));
            List<Object> res = new ArrayList<>();
            for (Map<String, Object> m : merged) {
                Map<String, Object> r = m == null ? deny("incomplete evaluation (missing subject/action/resource)", null, 400) : evaluate(m);
                res.add(r);
                if ("deny_on_first_deny".equals(semantic) && Boolean.FALSE.equals(r.get("decision"))) break;
                if ("permit_on_first_permit".equals(semantic) && Boolean.TRUE.equals(r.get("decision"))) break;
            }
            out.put("evaluations", res);
            return out;
        }

        private static Map<String, Object> refuse(List<?> items, String reason) {
            List<Object> l = new ArrayList<>();
            for (int i = 0; i < items.size(); i++) l.add(deny(reason, null, 400));
            Map<String, Object> out = obj();
            out.put("evaluations", l);
            return out;
        }

        /** COAZ profile: authorize an MCP tool invocation (tool to required capability to decision). */
        public Map<String, Object> evaluateTool(Map<String, Object> req) {
            Map<String, Object> tool = rec(req.get("tool"));
            String name = (String) tool.get("name");
            String capability;
            try {
                Object tc = cfg("toolCapability");
                capability = tc instanceof ToolCapability ? ((ToolCapability) tc).capability(name) : name;
            } catch (Exception e) {
                Map<String, Object> r = deny("evaluation error (fail closed): " + err(e), null, 500);
                Map<String, Object> out = obj();
                out.put("decision", Boolean.FALSE);
                out.put("tool", name);
                out.put("required_capability", "");
                out.put("context", r.get("context"));
                return out;
            }
            Map<String, Object> action = obj();
            action.put("name", capability);
            if (tool.containsKey("arguments")) action.put("properties", tool.get("arguments"));
            Map<String, Object> resource = obj();
            resource.put("type", "mcp_tool");
            resource.put("id", name);
            Map<String, Object> mapped = obj();
            mapped.put("subject", req.get("subject"));
            mapped.put("action", action);
            mapped.put("resource", resource);
            if (req.containsKey("context")) mapped.put("context", req.get("context"));
            Map<String, Object> resp = evaluate(mapped);
            Map<String, Object> out = obj();
            out.put("decision", resp.get("decision"));
            out.put("tool", name);
            out.put("required_capability", capability);
            if (resp.containsKey("context")) out.put("context", resp.get("context"));
            return out;
        }

        /** The framework-agnostic handler: {path, body} to {status, body}. A malformed body is a 400, any thrown error a 500 with no detail. */
        public Map<String, Object> handle(Map<String, Object> req) {
            try {
                return route(req);
            } catch (RuntimeException | StackOverflowError e) {
                return response(500, error("internal error"));
            }
        }

        private static Map<String, Object> error(String m) {
            Map<String, Object> b = obj();
            b.put("error", m);
            return b;
        }

        private static Map<String, Object> response(int status, Object body) {
            Map<String, Object> r = obj();
            r.put("status", JsVal.n(status));
            r.put("body", body);
            return r;
        }

        private Map<String, Object> route(Map<String, Object> req) {
            Object path = prop(req, "path");
            Object body = req.get("body");
            if (EVALUATION_PATH.equals(path)) {
                if (!isAccessEvaluationRequest(body)) return response(400, error("invalid AuthZEN Access Evaluation request"));
                return response(200, evaluate(body));
            }
            if (EVALUATIONS_PATH.equals(path)) {
                // AuthZEN section 7: an absent or empty `evaluations` array is a plain single Access Evaluation.
                if (isRec(body) && (!rec(body).containsKey("evaluations") || (rec(body).get("evaluations") instanceof List && ((List<?>) rec(body).get("evaluations")).isEmpty()))) {
                    if (!isAccessEvaluationRequest(body)) return response(400, error("invalid AuthZEN Access Evaluations request"));
                    return response(200, evaluate(body));
                }
                if (!isAccessEvaluationsRequest(body)) return response(400, error("invalid AuthZEN Access Evaluations request"));
                return response(200, evaluations(body));
            }
            if (COAZ_TOOL_PATH.equals(path)) {
                if (!isCoazToolAuthorizationRequest(body)) return response(400, error("invalid COAZ MCP-tool authorization request"));
                return response(200, evaluateTool(rec(body)));
            }
            return response(404, error("unknown AuthZEN path: " + js(path)));
        }
    }

    public static Map<String, Object> authzenHandler(AuthzenPdp pdp, Map<String, Object> req) { return pdp.handle(req); }

    // ---- search ----

    private static boolean str(Object x) { return x instanceof String && !((String) x).isEmpty(); }

    private static boolean entity(Object x, boolean needId) {
        if (!isRec(x)) return false;
        Map<String, Object> m = rec(x);
        return str(m.get("type")) && (!needId || str(m.get("id"))) && (!m.containsKey("properties") || isRec(m.get("properties")));
    }

    private static boolean action(Object x) {
        if (!isRec(x)) return false;
        Map<String, Object> m = rec(x);
        return str(m.get("name")) && (!m.containsKey("properties") || isRec(m.get("properties")));
    }

    private static boolean pageOk(Map<String, Object> b) {
        if (!b.containsKey("page")) return true;
        Object p = b.get("page");
        if (!isRec(p)) return false;
        Map<String, Object> m = rec(p);
        if (m.containsKey("token") && !(m.get("token") instanceof String)) return false;
        if (m.containsKey("limit")) {
            Object l = m.get("limit");
            if (!(l instanceof Json.Num || l instanceof Number) || !JsVal.isInteger(l) || Math.abs(JsVal.num(l)) > 9007199254740991.0 || JsVal.num(l) < 0 || JsVal.isNegZero(l)) return false;
        }
        return !m.containsKey("properties") || isRec(m.get("properties"));
    }

    private static boolean base(Map<String, Object> b) { return (!b.containsKey("context") || isRec(b.get("context"))) && pageOk(b); }

    public static boolean isSubjectSearch(Object b) { return isRec(b) && base(rec(b)) && entity(rec(b).get("subject"), false) && action(rec(b).get("action")) && entity(rec(b).get("resource"), true); }
    public static boolean isResourceSearch(Object b) { return isRec(b) && base(rec(b)) && entity(rec(b).get("subject"), true) && action(rec(b).get("action")) && entity(rec(b).get("resource"), false); }
    public static boolean isActionSearch(Object b) { return isRec(b) && base(rec(b)) && !rec(b).containsKey("action") && entity(rec(b).get("subject"), true) && entity(rec(b).get("resource"), true); }

    /** The metadata fragment for /.well-known/authzen-configuration: an endpoint per supported search ({@code provider}: searchSubject / searchResource / searchAction). */
    public static Map<String, Object> searchMetadata(String base, Map<String, Object> provider) {
        Map<String, Object> out = obj();
        if (provider.get("searchSubject") instanceof SearchFn) out.put("search_subject_endpoint", base + SEARCH_SUBJECT_PATH);
        if (provider.get("searchResource") instanceof SearchFn) out.put("search_resource_endpoint", base + SEARCH_RESOURCE_PATH);
        if (provider.get("searchAction") instanceof SearchFn) out.put("search_action_endpoint", base + SEARCH_ACTION_PATH);
        return out;
    }

    /** The queried entity's id is ignored if present (spec): strip it so a provider cannot be steered by it. */
    private static Map<String, Object> stripId(Map<String, Object> req, String key) {
        Map<String, Object> e = new LinkedHashMap<>(rec(req.get(key)));
        e.remove("id");
        Map<String, Object> out = new LinkedHashMap<>(req);
        out.put(key, e);
        return out;
    }

    private interface TypeOk { boolean ok(Object t); }

    private static Map<String, Object> shape(Map<String, Object> r, Object limit, TypeOk typeOk) {
        Object resultsO = prop(r, "results");
        if (!(resultsO instanceof List)) throw new IllegalStateException("r.results.filter is not a function");
        Set<String> seen = new LinkedHashSet<>();
        List<Object> results = new ArrayList<>();
        for (Object t : (List<?>) resultsO) {
            String k = JsVal.stringify(t);
            if (!typeOk.ok(t) || seen.contains(k)) continue;
            seen.add(k);
            results.add(t);
        }
        List<Object> capped = results;
        if (limit != UNDEF && limit != null && JsVal.num(limit) > 0) {
            int lim = (int) Math.min(JsVal.num(limit), Integer.MAX_VALUE);
            capped = new ArrayList<>(results.subList(0, Math.min(lim, results.size())));
        }
        // A provider that ignores the requested limit would make us hide results behind a page marker we cannot resume: fail closed.
        if (capped.size() < results.size()) throw new IllegalStateException("provider returned more than the page limit");
        Map<String, Object> out = obj();
        Object pg = r.get("page");
        if (JsVal.truthy(pg)) {
            Map<String, Object> pm = isRec(pg) ? rec(pg) : obj();
            Map<String, Object> page = obj();
            if (pm.containsKey("next_token")) page.put("next_token", pm.get("next_token"));
            page.put("count", JsVal.n(capped.size()));
            if (pm.containsKey("total")) page.put("total", pm.get("total"));
            if (JsVal.truthy(pm.get("properties"))) page.put("properties", pm.get("properties"));
            out.put("page", page);
        }
        if (JsVal.truthy(r.get("context"))) out.put("context", r.get("context"));
        out.put("results", capped);
        return out;
    }

    private static Map<String, Object> searchResponse(int status, Object body) { return AuthzenPdp.response(status, body); }

    private static TypeOk entityType(String type) {
        return e -> {
            if (e == null) throw new IllegalStateException("Cannot read properties of null (reading 'type')");
            return isRec(e) && type.equals(rec(e).get("type"));
        };
    }

    /** The search handler over a provider; returns null for a path that is not a search path, so it can be chained after the PDP handler. */
    public static Map<String, Object> authzenSearchHandler(Map<String, Object> provider, Map<String, Object> req) {
        try {
            Object path = prop(req, "path");
            Object body = req.get("body");
            Object limit = isRec(body) && isRec(rec(body).get("page")) && rec(rec(body).get("page")).containsKey("limit") ? rec(rec(body).get("page")).get("limit") : UNDEF;
            if (SEARCH_SUBJECT_PATH.equals(path)) {
                if (!(provider.get("searchSubject") instanceof SearchFn)) return searchResponse(404, AuthzenPdp.error("subject search is not supported"));
                if (!isSubjectSearch(body)) return searchResponse(400, AuthzenPdp.error("invalid AuthZEN subject search request"));
                String type = (String) rec(rec(body).get("subject")).get("type");
                return searchResponse(200, shape(((SearchFn) provider.get("searchSubject")).search(stripId(rec(body), "subject")), limit, entityType(type)));
            }
            if (SEARCH_RESOURCE_PATH.equals(path)) {
                if (!(provider.get("searchResource") instanceof SearchFn)) return searchResponse(404, AuthzenPdp.error("resource search is not supported"));
                if (!isResourceSearch(body)) return searchResponse(400, AuthzenPdp.error("invalid AuthZEN resource search request"));
                String type = (String) rec(rec(body).get("resource")).get("type");
                return searchResponse(200, shape(((SearchFn) provider.get("searchResource")).search(stripId(rec(body), "resource")), limit, entityType(type)));
            }
            if (SEARCH_ACTION_PATH.equals(path)) {
                if (!(provider.get("searchAction") instanceof SearchFn)) return searchResponse(404, AuthzenPdp.error("action search is not supported"));
                if (!isActionSearch(body)) return searchResponse(400, AuthzenPdp.error("invalid AuthZEN action search request"));
                return searchResponse(200, shape(((SearchFn) provider.get("searchAction")).search(rec(body)), limit, t -> true));
            }
            return null;
        } catch (Exception | StackOverflowError e) {
            return searchResponse(500, AuthzenPdp.error("internal error"));
        }
    }
}
