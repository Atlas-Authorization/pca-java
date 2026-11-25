package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The resource-server verifier with the full verdict: the equivalent of {@code verifyPCActn(pcactn, opts)} of the reference. One call reports
 * {@code allow}, the recomputed risk {@code r}, the {@code requiredThreshold}, every check as {@code pass | fail | not-enforced | unsupported},
 * the reasons (in order), the budget after the decision and, when asked for, the per-check assurance report. It never throws: any internal error
 * becomes a fail-closed verdict.
 *
 * <p>Options ({@code opts}, a JSON-shaped map; an absent key is "not given"): {@code grant} (the verifier's OWN stored grant, required),
 * {@code now}, {@code audience} (a string; JSON null is the explicit opt-out), {@code insecureSkipPlanRootCheck}, {@code context}
 * ({@code params, subject, env, plan, planAuthorized, reversibilityClass, risk, budget, recentActionTimes, revocationEpoch, beacon}),
 * {@code require} (default {@link #DEFAULT_REQUIRED_CHECKS}), {@code allowedSuites}, {@code pqPins}, {@code operation}, {@code intent},
 * {@code intentV2}, {@code freshAt}, {@code requireRiskInputs}, {@code assurance}, {@code requireAssurance}, {@code allowUnsupported},
 * {@code k1}. The hooks and the opt-in enforcement gates are code, so they come beside the map.
 *
 * <p>Not offered: the reference's legacy {@code allowUnboundPq} opt-out is never read; a pure-PQ or hybrid signer is always checked against
 * its {@code holder_pq} commitment.
 */
public final class ServerVerify {
    private ServerVerify() {}

    /** The minimum enforcement profile a resource server should demand. */
    public static final List<String> DEFAULT_REQUIRED_CHECKS = NullSafe.list(List.of("counter_format", "revocation", "plan_root_authorized",
        "audience", "validity", "grant_ref_bound"));

    private static final String PASS = "pass", FAIL = "fail", NOT_ENFORCED = "not-enforced", UNSUPPORTED = "unsupported";
    private static final String NO_BUDGET = "budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge";
    private static final String UNSUPPORTED_WHY = ": unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)";

    /** Verifies with no hooks and no enforcement gates. */
    public static Map<String, Object> verify(Object pcactn, Map<String, Object> opts) { return verify(pcactn, opts, null, null); }

    /**
     * Verifies {@code pcactn} (an object or its encoded JSON text) under {@code opts}. {@code hooks} are the attestation / threshold / revocation / zk
     * verifier hooks (null: none); {@code enforce} the opt-in gates forwarded to the core (null: none). The result is a JSON-shaped map:
     * {@code allow, r, requiredThreshold {t, proof, optimisticAllowed}, checks, reasons, budget?, assurance?, k1Bound?}.
     */
    public static Map<String, Object> verify(Object pcactn, Map<String, Object> opts, PcaCore.Hooks hooks, PcaCore.Enforce enforce) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        Map<String, Object> v;
        try {
            v = run(pcactn, o, hooks, enforce);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            v = failClosed("verifier error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), null);
        }
        // a verdict that stopped before the checks ran (undecodable, wire, verifier error) still reports its outcomes when asked
        if (wantsAssurance(o) && !v.containsKey("assurance")) {
            Assurance.Sources src = new Assurance.Sources();
            src.checks = checksOf(v);
            v.put("assurance", Assurance.report(src));
        }
        return v;
    }

    private static boolean wantsAssurance(Map<String, Object> o) { return Boolean.TRUE.equals(o.get("assurance")) || o.containsKey("requireAssurance"); }

    @SuppressWarnings("unchecked")
    private static Map<String, String> checksOf(Map<String, Object> v) { return (Map<String, String>) v.get("checks"); }

    @SuppressWarnings("unchecked")
    private static List<String> reasonsOf(Map<String, Object> v) { return (List<String>) v.get("reasons"); }

    private static Map<String, Object> worstThreshold() {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("t", 3);
        t.put("proof", "strong");
        t.put("optimisticAllowed", false);
        return t;
    }

    private static Map<String, Object> failClosed(String reason, Map<String, String> checks) {
        Map<String, String> c = new LinkedHashMap<>();
        if (checks != null) c.putAll(checks);
        c.put("malformed", FAIL);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("allow", false);
        out.put("r", 1.0);
        out.put("requiredThreshold", worstThreshold());
        out.put("checks", c);
        out.put("reasons", new ArrayList<>(List.of(reason)));
        return out;
    }

    private static String provedOf(String s) { return UNSUPPORTED.equals(s) ? NOT_ENFORCED : s; }

    /** {@code String(x)} of a JSON value (absent reads {@code undefined}). */
    private static String js(Map<?, ?> m, String k) { return IntentRevocation.jsText(m == null ? null : m.get(k), m != null && m.containsKey(k)); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOf(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** The verdict combinator state: ordered checks and ordered reasons. */
    private static final class VState {
        final Map<String, String> checks = new LinkedHashMap<>();
        final List<String> reasons = new ArrayList<>();
        void fail(String name, String why) { checks.put(name, FAIL); reasons.add(name + ": " + why); }
        void failRaw(String name, String reason) { checks.put(name, FAIL); reasons.add(reason); }
        void set(String name, String s) { checks.put(name, s); }
        void push(String m) { reasons.add(m); }
    }

    private static int classRank(Object c) {
        if (!(c instanceof String)) return 2;
        switch ((String) c) {
            case "reversible": return 0;
            case "rate_limited": case "costly": return 1;
            default: return 2;
        }
    }

    /** The threshold the hook reported, as the verified core reads it: floor, NaN unreported, the infinities clamped to the safe-integer extremes. */
    private static Double hookTInt(Double h) {
        if (h == null || h.isNaN()) return null;
        if (h >= 9007199254740991.0) return 9007199254740991.0;
        if (h <= -9007199254740991.0) return -9007199254740991.0;
        return Math.floor(h);
    }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<?>) o) out.add(x instanceof String ? (String) x : IntentRevocation.jsText(x, true));
        return out;
    }

    /** Decodes a wire string like the reference's {@code decodePCActn}: size cap first, then the strict profile, then an object. */
    private static Object decode(String s) {
        if (Pca.artifactTooLarge(s)) throw new DecodeError(Pca.ARTIFACT_SIZE_REASON);
        Object v;
        try {
            v = Json.parse(s);
        } catch (Json.StrictJsonError e) {
            String m = e.getMessage() == null ? "" : e.getMessage();
            int at = m.lastIndexOf(" at ");
            String head = at >= 0 ? m.substring(0, at) : m;
            if (head.startsWith("unexpected end")) head = "unexpected end of input";
            else if (head.equals("bad number")) head = "unexpected token";
            throw new DecodeError("strict JSON: " + head + " (at offset " + e.offset + ")");
        } catch (IllegalArgumentException e) {
            throw new DecodeError("strict JSON: " + e.getMessage() + " (at offset 0)");
        }
        if (!(v instanceof Map)) throw new DecodeError("decodePCActn: not an object");
        return v;
    }

    private static final class DecodeError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        DecodeError(String m) { super(m); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> run(Object pcactn, Map<String, Object> opts, PcaCore.Hooks hooks, PcaCore.Enforce enforce) {
        Object p0;
        try {
            p0 = pcactn instanceof String ? decode((String) pcactn) : pcactn;
        } catch (DecodeError e) {
            return failClosed("undecodable PCActn: " + e.getMessage(), null);
        }
        if (p0 == null || !(p0 instanceof Map || p0 instanceof List)) return failClosed("PCActn is not an object", null);

        Object nowRaw = opts.get("now") != null ? opts.get("now") : Long.valueOf(System.currentTimeMillis());
        Double nowNum = IntentJs.num(nowRaw);
        long nowL = nowNum == null ? Long.MAX_VALUE : (long) (double) nowNum;
        Object nowObj = nowNum == null ? nowRaw : (Object) nowNum;
        double nowD = nowNum == null ? Double.NaN : nowNum;
        if (!Double.isFinite(nowD)) return failClosed("the verifier clock is not a finite time", null);

        Object grantO = opts.get("grant");
        Map<String, Object> grant = mapOf(grantO);
        Map<String, Object> op = mapOf(opts.get("operation"));
        Map<String, Object> ctxIn = mapOf(opts.get("context"));
        Map<String, Object> ctx = new LinkedHashMap<>();
        if (ctxIn != null) ctx.putAll(ctxIn);
        // the operation's params are the action params (predicates, caveats, digest); a context that disagrees is flagged below
        boolean ctxHasParams = ctxIn != null && ctxIn.containsKey("params");
        Object ctxParams = ctxIn == null ? null : ctxIn.get("params");
        if (op != null && op.containsKey("params")) ctx.put("params", op.get("params"));

        // F-1: remember the threshold the hook says it enforced, so it can be compared with the SERVER-derived t below
        Double[] hookT = {null};
        PcaCore.Hooks h2 = new PcaCore.Hooks();
        if (hooks != null) {
            h2.attestation = hooks.attestation;
            h2.revocation = hooks.revocation;
            h2.zk = hooks.zk;
            h2.threshold = hooks.threshold;
        }
        final PcaCore.Hook userThreshold = hooks == null ? null : hooks.threshold;
        if (userThreshold != null) {
            h2.threshold = c -> {
                PcaCore.HookResult r = userThreshold.run(c);
                if (r != null && r.enforced) hookT[0] = r.t;
                return r;
            };
        }

        Map<String, Object> grantEnv = grant == null ? null : Authorize.readEnvelope(grant);
        boolean needsModelRules = false;
        if (grantEnv != null) {
            List<Object> envPreds = new ArrayList<>();
            envPreds.add(grantEnv.get("predicates"));
            needsModelRules = grantEnv.containsKey("units") || grantEnv.containsKey("tighten") || grantEnv.containsKey("model_polarity")
                || grantEnv.containsKey("actions") || !Decision.modelPathsRead(envPreds, List.of()).isEmpty();
        }
        IntentV2.Context v2 = null;
        Map<String, Object> optV2 = mapOf(opts.get("intentV2"));
        if (Zk.truthy(opts.get("intentV2")) || needsModelRules) {
            Map<String, Object> raw = optV2 == null ? new LinkedHashMap<>() : new LinkedHashMap<>(optV2);
            if (raw.get("params") == null) {
                if (ctx.containsKey("params")) raw.put("params", ctx.get("params")); else raw.remove("params");
            }
            if (raw.get("env") == null) {
                if (ctx.containsKey("env")) raw.put("env", ctx.get("env")); else raw.remove("env");
            }
            v2 = IntentV2.Context.fromJson(raw);
        }

        // ---- the core (plan_root_authorized is decided below from the verifier's own plan context)
        PcaCore.Options co = new PcaCore.Options(grant == null ? new LinkedHashMap<>() : grant);
        co.nowEpoch = nowL;
        if (opts.containsKey("audience")) {
            Object a = opts.get("audience");
            if (a == null) co.audienceAny();
            else if (a instanceof String) co.audience((String) a);
            else co.audience("\u0000not-a-string:" + UUID.randomUUID()); // a non-string audience never equals a signed one
        }
        co.hooks = h2;
        co.enforce = enforce;
        if (opts.get("allowedSuites") instanceof List) co.allowedSuites = strings(opts.get("allowedSuites"));
        co.planRoots = Pca.PlanRoots.SKIP;
        if (opts.get("intent") != null) co.intentPolicy = Pca.IntentPolicy.fromJson(opts.get("intent"));
        co.intentV2 = v2;
        if (opts.get("freshAt") != null) co.freshAt = K3.FreshAtPolicy.fromJson(opts.get("freshAt"));
        PcaCore.Result core = PcaCore.verify(p0, co);
        // a wire-form failure is terminal: nothing else is evaluated on a malformed object
        if (FAIL.equals(core.checks.get("wire"))) {
            Map<String, String> w = new LinkedHashMap<>();
            w.put("wire", FAIL);
            return failClosed(core.reason != null ? core.reason : "wire: malformed PCActn", w);
        }
        if (grant == null) {
            // the reference reads the stored grant's members and throws on anything that is not one
            throw new IllegalStateException(grantO == null ? "Cannot read properties of null (reading 'id')" : "Cannot read properties of undefined (reading 'length')");
        }
        Map<String, Object> p = (Map<String, Object>) p0;

        List<String> unsupported = new ArrayList<>();
        VState vs = new VState();
        for (Map.Entry<String, String> e : core.checks.entrySet()) {
            if (UNSUPPORTED.equals(e.getValue())) unsupported.add(e.getKey());
            vs.checks.put(e.getKey(), provedOf(e.getValue()));
        }
        if (!core.allow && core.reason != null) vs.reasons.add(core.reason);
        IntentV2.Decision v2d = null;
        if (p.containsKey("intent_session") || needsModelRules) {
            v2d = IntentV2.decide(p, grant, v2, nowL);
            // the core keeps only its FIRST failure reason; the v2 checks are the escalate-class ones, so every failed one is reported
            Authorize.foldV2Reasons(vs.reasons, v2d.checks);
        }

        // server-side PQ pin for a non-Ed25519 grant (fail closed: no pin for the issuer, or a different key, denies)
        Map<String, Object> pqPins = mapOf(opts.get("pqPins"));
        if (pqPins != null) {
            Object alg = grant.containsKey("alg") ? grant.get("alg") : "ed25519";
            Object issuer = grant.get("issuer");
            boolean hasPin = issuer instanceof String && pqPins.containsKey(issuer);
            Object pin = hasPin ? pqPins.get(issuer) : null;
            if ("ed25519".equals(alg)) {
                if (hasPin) vs.fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused");
                else vs.set("pq_pin", PASS);
            } else if (pin instanceof String && grant.get("pq_pk") instanceof String && pin.equals(grant.get("pq_pk"))) vs.set("pq_pin", PASS);
            else vs.fail("pq_pin", !hasPin ? "no server-side PQ pin for the grant issuer (suite " + IntentRevocation.jsText(alg, true) + ")"
                : "the grant pq_pk does not match the server-side pin");
        }

        // grant_ref binds the object to this grant
        if (p.containsKey("grant_ref") && p.get("grant_ref") != null && p.get("grant_ref").equals(grant.get("id"))) vs.set("grant_ref", PASS);
        else vs.fail("grant_ref", "does not reference the supplied grant");

        Map<String, Object> action = p.get("action") instanceof Map ? (Map<String, Object>) p.get("action") : new LinkedHashMap<>();
        Object signedDigest = action.get("params_digest");

        // the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
        if (op != null) {
            Object ov = op.get("verb"), orr = op.get("resource");
            String signed = js(action, "verb") + " on " + js(action, "resource");
            if (!(ov instanceof String) || !(orr instanceof String)) vs.fail("operation", "the server operation has no verb / resource (fail closed)");
            else if (!ov.equals(action.get("verb")) || !orr.equals(action.get("resource")))
                vs.fail("operation", "the proof is for " + signed + ", but this operation is " + ov + " on " + orr);
            else if (op.containsKey("params") && !Pca.hashCanonical(op.get("params")).equals(signedDigest))
                vs.fail("operation", "the proof's params_digest does not match the params of this " + ov + " operation");
            else if (op.containsKey("params") && ctxHasParams && !Pca.hashCanonical(ctxParams).equals(Pca.hashCanonical(op.get("params"))))
                vs.fail("operation", "context.params differ from the operation params");
            else vs.set("operation", PASS);
        }

        // params plaintext must open the committed digest
        if (ctx.containsKey("params")) {
            if (Pca.hashCanonical(ctx.get("params")).equals(signedDigest)) vs.set("params_digest", PASS);
            else vs.fail("params_digest", "supplied params do not hash to action.params_digest");
        } else vs.set("params_digest", NOT_ENFORCED);

        // the verifier's own copy of the plan must be the committed one
        Object planO = ctx.get("plan");
        boolean planSupplied = Zk.truthy(planO);
        Map<String, Object> planWire = p.get("plan") instanceof Map ? (Map<String, Object>) p.get("plan") : new LinkedHashMap<>();
        boolean rootMatches = false;
        List<Object> planNodes = planO instanceof List ? (List<Object>) planO : null;
        if (planSupplied) {
            if (planNodes == null) throw new IllegalStateException("ctx.plan.map is not a function");
            List<Object> leaves = new ArrayList<>();
            for (Object n : planNodes) {
                if (n == null) throw new IllegalStateException("Cannot read properties of null (reading 'id')");
                Map<String, Object> nm = mapOf(n);
                if (nm == null) nm = new LinkedHashMap<>();
                leaves.add(Pca.planLeaf(nm.get("id"), nm, Pca.conditionsDigest(nm.get("pre"), nm.get("post"))));
            }
            rootMatches = Pca.merkleRoot(leaves).equals(planWire.get("root"));
        }
        Object authO = ctx.get("planAuthorized");
        if (!planSupplied) {
            if (Boolean.TRUE.equals(opts.get("insecureSkipPlanRootCheck"))) vs.set("plan_root_authorized", NOT_ENFORCED);
            else vs.fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)");
        } else if (!rootMatches) vs.fail("plan_root_authorized", "known plan does not match plan.root");
        else if (Boolean.TRUE.equals(authO)) vs.set("plan_root_authorized", PASS);
        else if (Boolean.FALSE.equals(authO)) vs.fail("plan_root_authorized", "the plan root has not been authorized by the principal");
        else if (Boolean.TRUE.equals(opts.get("insecureSkipPlanRootCheck"))) vs.set("plan_root_authorized", NOT_ENFORCED);
        else vs.fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)");

        // the guardian-signed revocation epoch (reported as `freshness`)
        Map<String, Object> re = mapOf(ctx.get("revocationEpoch"));
        if (Zk.truthy(ctx.get("revocationEpoch"))) {
            String guardian = re != null && re.get("guardianPublic") instanceof String ? (String) re.get("guardianPublic") : null;
            RevocationStaleness.EpochOptions eo = new RevocationStaleness.EpochOptions(guardian, nowD);
            eo.grantRef = grant.get("id") instanceof String ? (String) grant.get("id") : null;
            eo.lastAcceptedEpoch = re == null ? null : IntentJs.num(re.get("lastAcceptedEpoch"));
            Object fr0 = p.get("freshness");
            eo.pcactnEpoch = fr0 instanceof Map ? IntentJs.num(((Map<?, ?>) fr0).get("epoch")) : null;
            if (re != null && re.get("maxAgeMs") != null) eo.maxAgeMs = IntentJs.num(re.get("maxAgeMs"));
            RevocationStaleness.Check r = RevocationStaleness.checkRevocationEpoch(re == null ? null : re.get("epoch"), eo);
            // an `enforce.freshness` failure from the core stands (a passing epoch never overwrites it)
            if (r.ok) {
                if (!FAIL.equals(vs.checks.get("freshness"))) vs.set("freshness", PASS);
            } else vs.fail("freshness", r.reason != null ? r.reason : "revocation epoch rejected");
        } else if (!vs.checks.containsKey("freshness")) vs.set("freshness", NOT_ENFORCED);

        // the dead-man liveness beacon
        {
            Map<String, Object> bc = mapOf(ctx.get("beacon"));
            boolean supplied = Zk.truthy(ctx.get("beacon"));
            boolean verOk = false, replayed = false, refBinds = false;
            String why = null;
            Object beaconO = bc == null ? null : bc.get("beacon");
            if (supplied) {
                Map<String, Object> chk = new LinkedHashMap<>();
                chk.put("issuers", bc == null ? null : bc.get("issuers"));
                chk.put("now", nowNum != null && nowNum == Math.rint(nowNum) ? (Object) IntentJs.ofLong((long) (double) nowNum) : nowObj);
                chk.put("instance", bc == null ? null : bc.get("instance"));
                chk.put("scope", grant.get("id"));
                if (bc != null && Zk.truthy(bc.get("pqPins"))) chk.put("pqPins", bc.get("pqPins"));
                Map<String, Object> r = Beacons.verifyLivenessBeacon(beaconO, chk);
                verOk = Boolean.TRUE.equals(r.get("ok"));
                if (!verOk && r.get("reason") instanceof String) why = (String) r.get("reason");
                Map<String, Object> bm = mapOf(beaconO);
                Double seq = bm == null ? null : IntentJs.num(bm.get("seq"));
                Double last = bc == null ? null : IntentJs.num(bc.get("lastAcceptedSeq"));
                replayed = verOk && bc != null && bc.get("lastAcceptedSeq") != null && seq != null && last != null && seq < last;
                Object fr0 = p.get("freshness");
                Object ref = fr0 instanceof Map ? ((Map<?, ?>) fr0).get("beacon_ref") : null;
                refBinds = verOk && !replayed && bm != null && ref instanceof String && ref.equals(Beacons.beaconRef(bm));
                if (!supplied || !verOk) {
                    vs.fail("beacon", why != null ? why : "beacon rejected");
                } else if (replayed) {
                    vs.fail("beacon", "beacon seq " + IntentRevocation.jsText(bm.get("seq"), true) + " is older than the last accepted "
                        + IntentRevocation.jsText(bc.get("lastAcceptedSeq"), true) + " (replay)");
                } else if (!refBinds) {
                    vs.fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon");
                } else vs.set("beacon", PASS);
            } else vs.set("beacon", NOT_ENFORCED);
        }

        // require-when-bound: a grant whose agent_binding constrains the model / measurement / operator / weights REQUIRES a bound attestation
        if (Authorize.requiresAttestation(grantEnv == null ? null : grantEnv.get("agent_binding")) && !PASS.equals(vs.checks.get("attestation")))
            vs.fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED");

        List<Object> chain = p.get("cap_chain") instanceof List ? (List<Object>) p.get("cap_chain") : new ArrayList<>();
        Object leaf = chain.isEmpty() ? null : chain.get(chain.size() - 1);
        int depth = Math.max(0, chain.size() - 1);
        // fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0)
        boolean budgetUndefined = !ctx.containsKey("budget");
        Object budgetCtx = ctx.get("budget");
        Object budgetIn;
        if (budgetCtx != null) budgetIn = budgetCtx;
        else {
            Map<String, Object> z = new LinkedHashMap<>();
            z.put("B", 0);
            z.put("tau", nowObj);
            z.put("asOf", nowObj);
            budgetIn = z;
        }
        vs.set("budget", Zk.truthy(budgetCtx) ? PASS : NOT_ENFORCED);
        if (budgetUndefined) vs.push(NO_BUDGET);

        // taint: ONLY a verifier-supplied value counts (the agent's own provenance.taint_level can only lower risk)
        Map<String, Object> risk = ctx.get("risk") instanceof Map ? new LinkedHashMap<>((Map<String, Object>) ctx.get("risk")) : new LinkedHashMap<>();
        if (opts.get("requireRiskInputs") instanceof List && !((List<?>) opts.get("requireRiskInputs")).isEmpty()) {
            List<String> missing = new ArrayList<>();
            for (String k : strings(opts.get("requireRiskInputs"))) {
                boolean supplied = Caveats.fin(risk.get(k)) != null || ("semanticDistance".equals(k) && ctx.containsKey("plan"));
                if (!supplied) missing.add(k);
            }
            if (!missing.isEmpty()) vs.fail("risk_inputs", "required risk input(s) not supplied by the server: " + String.join(", ", missing));
            else vs.set("risk_inputs", PASS);
        }

        // reversibility: the verifier's authoritative class wins; the agent may only be STRICTER
        Object declared = action.get("reversibility_class");
        Object reversibility = declared;
        if (ctx.get("reversibilityClass") != null) {
            Object sc = ctx.get("reversibilityClass");
            int dr = classRank(declared), sr = classRank(sc);
            if (dr < sr) vs.fail("reversibility", "declared class '" + IntentRevocation.jsText(declared, action.containsKey("reversibility_class"))
                + "' is less restrictive than the authoritative '" + IntentRevocation.jsText(sc, true) + "'");
            else vs.set("reversibility", PASS);
            reversibility = dr > sr ? declared : sc;
        }
        Object budgetForDecide = budgetIn;
        if (budgetUndefined) {
            Map<String, Object> bz = new LinkedHashMap<>(mapOf(budgetIn));
            bz.put("B", 0);
            budgetForDecide = bz;
        }
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("verb", action.get("verb"));
        inner.put("resource", action.get("resource"));
        if (ctx.containsKey("params")) inner.put("params", ctx.get("params"));
        if (reversibility != null) inner.put("reversibility_class", reversibility);
        Map<String, Object> actionCtx = new LinkedHashMap<>();
        actionCtx.put("action", inner);
        if (ctx.get("subject") != null) actionCtx.put("subject", ctx.get("subject"));
        Object predEnv = p.containsKey("intent_session") ? Authorize.v2Env(p, grant, v2, nowL, ctx.get("env")) : ctx.get("env");
        if (predEnv != null) actionCtx.put("env", predEnv);
        // signed `tool_binding` (D): binds the semantic firewall (tool_schema caveats) to the tool the agent signed
        if (p.get("tool_binding") instanceof String) actionCtx.put("toolBinding", p.get("tool_binding"));

        Map<String, Object> din = new LinkedHashMap<>();
        din.put("grant", grant);
        din.put("trustedRoot", grant);
        if (pqPins != null) din.put("pqPins", pqPins);
        din.put("action", actionCtx);
        if (planO instanceof List) din.put("plan", planO);
        if (planWire.containsKey("node_id")) din.put("nodeId", planWire.get("node_id"));
        din.put("risk", risk);
        din.put("budget", budgetForDecide);
        din.put("now", nowObj);
        Map<String, Object> cc = new LinkedHashMap<>();
        cc.put("delegationDepth", depth);
        if (ctx.get("recentActionTimes") != null) cc.put("recentActionTimes", ctx.get("recentActionTimes"));
        din.put("caveatContext", cc);
        Map<String, Object> k1opt = mapOf(opts.get("k1"));
        if (k1opt != null) {
            Map<String, Object> k1 = new LinkedHashMap<>(k1opt);
            k1.remove("narrow");
            k1.put("action_digest", CaveatLang.dischargeActionDigest(p));
            din.put("k1", k1);
        }
        if (IntentJs.num(p.get("caution")) != null) din.put("rFloor", p.get("caution"));
        Map<String, Object> d = Decide.decide(din);
        boolean release = Boolean.TRUE.equals(d.get("releaseGuardianShare"));

        // caveats added by delegation hops (beyond the root's) are conjunctive too
        List<Object> k1Bound = null;
        if (leaf != null) {
            if (!(grant.get("caveats") instanceof List)) throw new IllegalStateException("Cannot read properties of undefined (reading 'length')");
            Map<String, Object> leafM = mapOf(leaf);
            if (leafM == null || !(leafM.get("caveats") instanceof List)) throw new IllegalStateException("Cannot read properties of undefined (reading 'slice')");
            List<Object> gcs = (List<Object>) grant.get("caveats");
            List<Object> lcs = (List<Object>) leafM.get("caveats");
            List<Object> extra = new ArrayList<>(lcs.subList(Math.min(gcs.size(), lcs.size()), lcs.size()));
            // K1 caveat types (and the caveats of a verified narrow block) are evaluated over the whole chain: the stock evaluator would refuse them
            boolean useK1 = k1opt != null && k1opt.containsKey("narrow");
            for (Object c : lcs) if (CaveatLang.isK1Caveat(c)) useK1 = true;
            CaveatLang.K1Result k1r = null;
            if (useK1) {
                Map<String, Object> k1In = null;
                if (k1opt != null) {
                    k1In = new LinkedHashMap<>(k1opt);
                    k1In.put("action_digest", CaveatLang.dischargeActionDigest(p));
                }
                Map<String, Object> k1Ctx = new LinkedHashMap<>();
                k1Ctx.put("now", nowNum != null && nowNum == Math.rint(nowNum) ? (Object) IntentJs.ofLong((long) (double) nowNum) : nowObj);
                k1Ctx.put("action", inner);
                k1r = CaveatLang.evaluateK1(grant, chain, k1In, k1Ctx);
                k1Bound = new ArrayList<>();
                for (CaveatLang.BoundCaveat b : k1r.bound) {
                    Map<String, Object> bm = new LinkedHashMap<>();
                    bm.put("caveat", b.caveat);
                    bm.put("hop", b.hop);
                    bm.put("capHash", b.capHash);
                    k1Bound.add(bm);
                }
            }
            List<Object> evalList = new ArrayList<>();
            for (Object c : extra) if (!CaveatLang.isK1Caveat(c)) evalList.add(c);
            if (k1r != null) evalList.addAll(k1r.plain);
            Map<String, Object> cctx = new LinkedHashMap<>();
            cctx.put("now", nowObj);
            cctx.put("action", inner);
            cctx.put("delegation_depth", depth);
            cctx.put("blast_radius", risk.get("blastRadius"));
            cctx.put("reversibility_class", Authorize.resolveReversibilityClass(actionCtx, planNodes, planWire.get("node_id") instanceof String ? (String) planWire.get("node_id") : null));
            cctx.put("recent_action_times", ctx.get("recentActionTimes"));
            Caveats.Result cv = Authorize.evaluateAgentCaveats(evalList, cctx, actionCtx, Authorize.toolCallOf(actionCtx));
            if (cv.ok && (k1r == null || k1r.ok)) vs.set("delegated_caveats", PASS);
            else {
                List<String> allFailed = new ArrayList<>(cv.failed);
                if (k1r != null) allFailed.addAll(k1r.failed);
                vs.fail("delegated_caveats", "delegation caveat(s) not satisfied: " + String.join(", ", allFailed)
                    + (k1r != null && !k1r.ok ? " (" + String.join("; ", k1r.reasons) + ")" : ""));
            }
        }

        // policy: the check mirrors the Policy VM's release decision; its reasons (also the informational ones when released) are kept in order
        vs.set("policy", release ? PASS : FAIL);
        Object dr = d.get("reasons");
        if (dr instanceof List) for (Object x : (List<?>) dr) vs.push("policy: " + IntentRevocation.jsText(x, true));

        // threshold: t > 1 needs a proof we can only get from an enforced threshold hook, and the hook must report at least the SERVER-derived t (F-1)
        Map<String, Object> rt = mapOf(d.get("requiredThreshold"));
        int tReq = ((Number) rt.get("t")).intValue();
        String proof = String.valueOf(rt.get("proof"));
        String th = vs.checks.get("threshold");
        Double hookInt = hookTInt(hookT[0]);
        if (tReq > 1 && release) {
            if (PASS.equals(th)) {
                if (!(hookInt != null && hookInt >= tReq))
                    vs.failRaw("threshold", "threshold: threshold hook enforced t=" + (hookT[0] == null ? "unreported" : RevocationStaleness.jsNum(hookT[0]))
                        + " but the server requires t=" + tReq + " (below the server-derived threshold; derive t from server-held data)");
            } else if (FAIL.equals(th)) vs.failRaw("threshold", "threshold: t=" + tReq + " required and the threshold proof was rejected");
            else vs.failRaw("threshold", "threshold: t=" + tReq + " (" + proof + ") required but no threshold verifier is enforced");
        }

        List<String> required = DEFAULT_REQUIRED_CHECKS;
        if (opts.get("require") != null) {
            if (!(opts.get("require") instanceof List)) throw new IllegalStateException("required.map is not a function");
            required = strings(opts.get("require"));
        }
        boolean wantAssurance = wantsAssurance(opts);
        Assurance.Sources src = new Assurance.Sources();
        src.pcactn = p;
        if (hooks != null) { src.attestationHook = hooks.attestation; src.zkHook = hooks.zk; src.thresholdHook = hooks.threshold; src.revocationHook = hooks.revocation; }
        if (enforce != null && enforce.attestation != null) src.usedAttestationHook = enforce.attestation.verifier;
        src.thresholdT = hookT[0];
        if (v2d != null && v2d.legacyModelPolarity) {
            src.degraded = new LinkedHashMap<>();
            src.degraded.put("tighten", Authorize.DEGRADED_LEGACY_POLARITY);
        }
        if (Zk.truthy(opts.get("requireAssurance"))) {
            src.checks = new LinkedHashMap<>(vs.checks);
            String unmet = unmetAssurance(Assurance.report(src), opts.get("requireAssurance"));
            if (unmet == null) vs.set("assurance", PASS);
            else vs.failRaw("assurance", unmet);
        }

        boolean allow = !vs.checks.containsValue(FAIL) && release && core.allow;
        Map<String, String> checks = new LinkedHashMap<>(vs.checks);
        for (String n : unsupported) if (NOT_ENFORCED.equals(checks.get(n))) checks.put(n, UNSUPPORTED);
        List<String> reasons = vs.reasons;
        // a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
        List<String> allowUnsupported = strings(opts.get("allowUnsupported"));
        List<String> refused = new ArrayList<>();
        for (String n : unsupported) if (!allowUnsupported.contains(n)) refused.add(n);
        Map<String, Object> out = new LinkedHashMap<>();
        if (!refused.isEmpty()) {
            List<String> rs = new ArrayList<>(reasons);
            for (String n : refused) rs.add(n + UNSUPPORTED_WHY);
            out.put("allow", false);
            out.put("r", d.get("r"));
            out.put("requiredThreshold", rt);
            out.put("checks", checks);
            out.put("reasons", rs);
            enforceRequired(out, required);
            if (wantAssurance) out.put("assurance", finishAssurance(src, checksOf(out)));
            return out;
        }
        out.put("allow", allow);
        out.put("r", d.get("r"));
        out.put("requiredThreshold", rt);
        out.put("checks", checks);
        out.put("reasons", reasons);
        if (allow && Zk.truthy(budgetCtx)) out.put("budget", d.get("budget"));
        if (k1Bound != null) {
            boolean maxUses = false;
            for (Object b : k1Bound) {
                Object cv = ((Map<?, ?>) b).get("caveat");
                if (cv instanceof Map && "max_uses".equals(((Map<?, ?>) cv).get("type"))) maxUses = true;
            }
            if (maxUses) out.put("k1Bound", k1Bound);
        }
        enforceRequired(out, required);
        // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
        if (!Boolean.TRUE.equals(out.get("allow")) && Zk.truthy(budgetCtx)
            && Decision.ESCALATE.equals(Decision.decisionOf(false, checksOf(out), reasonsOf(out)))) out.put("budget", d.get("budget"));
        if (!Boolean.TRUE.equals(out.get("allow")) && reasonsOf(out).isEmpty()) reasonsOf(out).add("denied");
        if (wantAssurance) out.put("assurance", finishAssurance(src, checksOf(out)));
        return out;
    }

    private static Map<String, Object> finishAssurance(Assurance.Sources src, Map<String, String> checks) {
        src.checks = new LinkedHashMap<>(checks);
        return Assurance.refreshAssurance(Assurance.report(src), checks);
    }

    /**
     * The reference's {@code unmetAssurance} over a requirement given as JSON: the one {@link Assurance#unmet}, which refuses an unknown key or
     * value (a {@code threshold} that is not a list included) fail closed.
     */
    private static String unmetAssurance(Map<String, Object> report, Object reqO) {
        Map<String, Object> m = mapOf(reqO);
        if (m == null) return null;
        return Assurance.unmet(report, Assurance.Requirement.fromJson(m));
    }

    /**
     * Default-deny: turns every required check that is not {@code pass} into a failure, with the reference's reason. {@code v} is a verdict map
     * ({@code allow, checks, reasons}); it is updated in place and returned. {@code counter} resolves to the replay check when the verdict has
     * one, else to the format check.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> enforceRequired(Map<String, Object> v, List<String> required) {
        Map<String, String> checks = (Map<String, String>) v.get("checks");
        List<String> reasons = (List<String>) v.get("reasons");
        boolean allow = Boolean.TRUE.equals(v.get("allow"));
        Map<String, String> proved = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : checks.entrySet()) proved.put(e.getKey(), provedOf(e.getValue()));
        for (String raw : required) {
            String name = raw.equals("counter") && !checks.containsKey("counter") ? (checks.containsKey("replay") ? "replay" : "counter_format") : raw;
            String c = proved.get(name);
            if (PASS.equals(c)) continue;
            allow = false;
            if (FAIL.equals(c)) continue;
            String shown = UNSUPPORTED.equals(checks.get(name)) ? UNSUPPORTED : (c == null ? "absent" : c);
            proved.put(name, FAIL);
            reasons.add(name + ": required check is " + shown + " (default-deny: not enforced by this resource server)");
        }
        v.put("allow", allow);
        for (Map.Entry<String, String> e : proved.entrySet()) {
            String cur = checks.get(e.getKey());
            checks.put(e.getKey(), UNSUPPORTED.equals(cur) && NOT_ENFORCED.equals(e.getValue()) ? UNSUPPORTED : e.getValue());
        }
        return v;
    }
}
