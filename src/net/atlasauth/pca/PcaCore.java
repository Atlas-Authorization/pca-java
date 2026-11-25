package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The core verifier entry with the full option set: the equivalent of {@code verifyPCActnCore(pcactn, opts)} in the
 * reference. Unlike {@link Pca#verifyPcactn} it reports each check as {@code pass | fail | not-enforced | unsupported}, takes
 * the verifier hooks (attestation, threshold, revocation, zk), the opt-in enforcement gates (taint, freshness, attestation) and
 * the assurance report, and supports the explicit audience opt-out.
 *
 * <p>Check order (normative): wire (terminal on failure), version, audience, validity, cap_chain, pq_pin, grant_ref_bound,
 * plan_inclusion, plan_root_authorized, leaf_signature, counter_format, intent, the intent v2 checks, fresh_at, taint_gate,
 * freshness, attestation, threshold, revocation, zk_compliance, bond. {@code allow} is "no check failed"; the reason is the
 * first failure.
 *
 * <p>Not offered (the reference's legacy opt-out): {@code allowUnboundPq}. A pure-PQ or hybrid signer is always checked
 * against its {@code holder_pq} commitment.
 */
public final class PcaCore {
    private PcaCore() {}

    public static final String PASS = "pass", FAIL = "fail", NOT_ENFORCED = "not-enforced", UNSUPPORTED = "unsupported";

    /** What a hook receives: the PCActn, the verifier's grant and the verification clock. */
    public static final class Ctx {
        public final Map<String, Object> pcactn;
        public final Map<String, Object> grant;
        public final long nowEpoch;
        Ctx(Map<String, Object> pcactn, Map<String, Object> grant, long nowEpoch) { this.pcactn = pcactn; this.grant = grant; this.nowEpoch = nowEpoch; }
    }

    /** {@code {enforced: false}} or {@code {enforced: true, ok, reason?, t?}}; a threshold hook reports the {@code t} it enforced. */
    public static final class HookResult {
        public final boolean enforced, ok;
        public final String reason;
        public final Double t;
        private HookResult(boolean enforced, boolean ok, String reason, Double t) { this.enforced = enforced; this.ok = ok; this.reason = reason; this.t = t; }
        public static HookResult notEnforced() { return new HookResult(false, false, null, null); }
        public static HookResult enforced(boolean ok, String reason, Double t) { return new HookResult(true, ok, reason, t); }
        public static HookResult enforced(boolean ok) { return enforced(ok, null, null); }
    }

    @FunctionalInterface
    public interface Hook {
        HookResult run(Ctx ctx) throws Exception;
    }

    public static final class Hooks {
        public Hook attestation, threshold, revocation, zk;
    }

    /** {@code enforce.freshness}: reject a missing, stub or stale signed freshness anchor. Null fields take the reference defaults. */
    public static final class Freshness {
        public Double epochMs, clockSkewMs;
        public double maxAgeMs;
        public Long now;
        public Freshness(double maxAgeMs) { this.maxAgeMs = maxAgeMs; }
    }

    /** {@code enforce.taint}: re-classify every declared ref from server facts and refuse above {@code maxTaint}. */
    public static final class TaintGate {
        public final Taint.Context ctx;
        public final double maxTaint;
        public TaintGate(Taint.Context ctx, double maxTaint) { this.ctx = ctx; this.maxTaint = maxTaint; }
    }

    /** {@code enforce.attestation}: the real attestation verifier; with the gate on, a not-enforced result fails unless {@code required} is false. */
    public static final class AttestationGate {
        public final Hook verifier;
        public boolean required = true;
        public AttestationGate(Hook verifier) { this.verifier = verifier; }
    }

    public static final class Enforce {
        public Freshness freshness;
        public TaintGate taint;
        public AttestationGate attestation;
    }

    public static final class Options {
        /** The verifier's OWN stored grant. */
        public Map<String, Object> grant;
        /** The grant was lifted from the presented artifact: it is then not the trusted root and a PQ root verifies only under {@link #pqPins}. */
        public boolean grantFromArtifact;
        /** Verifier-side pins {@code issuer -> pq_pk}; an issuer with a pin also refuses a classical root ({@code pq_pin}). */
        public Map<String, Object> pqPins;
        /** The verification clock (epoch ms); null reads the system clock. */
        public Long nowEpoch;
        /** Audience: {@link #audience(String)} (must equal), {@link #audienceAny()} (explicit opt-out), or unset (fails when the PCActn carries an {@code aud}). */
        public String audience;
        public boolean audienceGiven;
        public Hooks hooks;
        public Enforce enforce;
        public List<String> allowedSuites;
        /** {@code authorizedPlanRoots} and {@code insecureSkipPlanRootCheck}; null behaves as {@link Pca.PlanRoots#NONE}. */
        public Pca.PlanRoots planRoots;
        public Pca.IntentPolicy intentPolicy;
        public IntentV2.Context intentV2;
        public K3.FreshAtPolicy freshAt;
        /** Attach the per-check assurance report. */
        public boolean assurance;
        public Assurance.Requirement requireAssurance;

        public Options(Map<String, Object> grant) { this.grant = grant; }
        public Options audience(String a) { this.audience = a; this.audienceGiven = true; return this; }
        public Options audienceAny() { this.audience = null; this.audienceGiven = true; return this; }
    }

    public static final class Result {
        public boolean allow;
        public final Map<String, String> checks = new LinkedHashMap<>();
        /** First failure; null when allowed. */
        public String reason;
        /** The per-check assurance report; null unless asked for. */
        public Map<String, Object> assurance;
        /** The {@code t} a passing threshold hook reported (null when none did). */
        public Double enforcedT;
    }

    /** The reference's CoreState: ordered checks, first failure reason, terminal wire failure. */
    private static final class State {
        final Map<String, String> checks = new LinkedHashMap<>();
        String reason;
        boolean terminal;
        void set(String n, String s) { checks.put(n, s); }
        void fail(String n, String why) { checks.put(n, FAIL); if (reason == null) reason = n + ": " + why; }
        boolean allow() { return !terminal && !checks.containsValue(FAIL); }
    }

    private static Result resultOf(State st) {
        Result r = new Result();
        r.checks.putAll(st.checks);
        r.allow = st.allow();
        r.reason = r.allow ? null : st.reason;
        return r;
    }

    private static String jsNum(double d) {
        return d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString((long) d) : Double.toString(d);
    }

    /** Verifies {@code pcactn} under the options; total: hostile input is a failed result, never an exception. */
    public static Result verify(Object pcactn, Options o) {
        try {
            return verifyUnchecked(pcactn, o);
        } catch (RuntimeException ex) {
            State w = new State();
            w.terminal = true;
            w.fail("wire", "malformed input (" + ex.getClass().getSimpleName() + ")");
            return resultOf(w);
        }
    }

    @SuppressWarnings("unchecked")
    private static Result verifyUnchecked(Object pcactn, Options o) {
        State st = new State();
        String wire = Pca.validateWireV2(pcactn);
        if (wire != null) {
            st.terminal = true;
            st.checks.put("wire", FAIL);
            st.reason = "wire: " + wire;
            return resultOf(st);
        }
        Map<String, Object> p = Pca.asMap(pcactn);
        Map<String, Object> grant = o.grant;
        long now = o.nowEpoch != null ? o.nowEpoch : System.currentTimeMillis();
        Ctx ctx = new Ctx(p, grant, now);
        Pca.PlanRoots planRoots = o.planRoots == null ? Pca.PlanRoots.NONE : o.planRoots;
        Hooks hooks = o.hooks;
        Double[] enforcedT = {null};
        st.set("wire", PASS);
        try {
            // version
            if (Json.asLong(p.get("ver")) == Pca.WIRE_VERSION) st.set("version", PASS);
            else st.fail("version", "unsupported ver " + Json.asLong(p.get("ver")) + " (this verifier requires " + Pca.WIRE_VERSION + ")");

            // audience: a string must equal, an explicit opt-out is not enforced, an omitted one fails when the PCActn carries an aud
            boolean hasAud = p.get("aud") instanceof String && !((String) p.get("aud")).isEmpty();
            if (o.audienceGiven && o.audience == null) st.set("audience", NOT_ENFORCED);
            else if (!o.audienceGiven) {
                if (hasAud) st.fail("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)");
                else st.set("audience", NOT_ENFORCED);
            } else if (o.audience.equals(p.get("aud"))) st.set("audience", PASS);
            else st.fail("audience", "aud does not match this resource server / instance");

            // validity
            boolean clockOk = Math.abs(now) <= 9007199254740991L;
            long iat = Json.asLong(p.get("iat")), exp = Json.asLong(p.get("exp"));
            if (!clockOk) st.fail("validity", "the verifier clock is not a safe integer epoch-ms");
            else if (!(exp > iat)) st.fail("validity", "exp must be greater than iat");
            else if (exp - iat > Pca.MAX_LIFETIME_MS) st.fail("validity", "lifetime exceeds " + Pca.MAX_LIFETIME_MS + " ms");
            else if (iat > now + Pca.MAX_SKEW_MS) st.fail("validity", "iat is in the future (clock skew)");
            else if (now > exp) st.fail("validity", "the PCActn has expired");
            else st.set("validity", PASS);

            // cap_chain: non-empty, rooted at the grant, then the walk
            List<Object> chain = Pca.asList(p.get("cap_chain"));
            if (chain.isEmpty()) st.fail("cap_chain", "empty chain");
            else if (!Pca.capHash(Pca.asMap(chain.get(0))).equals(Pca.capHash(grant))) st.fail("cap_chain", "chain root is not the grant");
            else {
                String why = Pca.verifyChain(chain, Pca.asStr(grant.get("issuer")), grant.get("issuer") instanceof String, o.allowedSuites,
                    o.grantFromArtifact ? o.pqPins : null, o.grantFromArtifact ? null : grant);
                if (why.isEmpty()) st.set("cap_chain", PASS); else st.fail("cap_chain", why);
            }
            // a PQ pin for the root issuer says its grants are post-quantum protected: a classical root naming it is refused
            if (o.pqPins != null && (grant.get("alg") == null || "ed25519".equals(grant.get("alg"))) && o.pqPins.containsKey(grant.get("issuer")))
                st.fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused");

            // grant_ref_bound
            Object gref = p.get("grant_ref");
            Object rootId = !chain.isEmpty() && chain.get(0) instanceof Map ? ((Map<?, ?>) chain.get(0)).get("id") : null;
            if (gref instanceof String && !((String) gref).isEmpty() && rootId instanceof String && gref.equals(rootId)) st.set("grant_ref_bound", PASS);
            else st.fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain");

            // plan inclusion + plan_root_authorized
            Map<String, Object> plan = Pca.asMap(p.get("plan"));
            Map<String, Object> action = Pca.asMap(p.get("action"));
            String cond = plan.get("conditions_digest") instanceof String ? (String) plan.get("conditions_digest") : Pca.conditionsDigest(null, null);
            boolean incl;
            try {
                incl = Pca.verifyInclusion(Pca.asStr(plan.get("root")), Pca.asMap(plan.get("inclusion_proof")), Pca.planLeaf(plan.get("node_id"), action, cond));
            } catch (RuntimeException e) { incl = false; }
            if (incl) st.set("plan_inclusion", PASS); else st.fail("plan_inclusion", "action is not a node of the committed plan");
            if (planRoots.authorized == null) {
                if (planRoots.skip) st.set("plan_root_authorized", NOT_ENFORCED);
                else st.fail("plan_root_authorized", "no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)");
            } else if (planRoots.authorized.contains(Pca.asStr(plan.get("root")))) st.set("plan_root_authorized", PASS);
            else st.fail("plan_root_authorized", "the plan root has not been authorized by the principal");

            // leaf signature (suite policy, F-2 binding, then the suite verification)
            boolean sigOk = false;
            String leafErr = null;
            if (!chain.isEmpty()) {
                Map<String, Object> leafCap = Pca.asMap(chain.get(chain.size() - 1));
                String holder = Pca.asStr(leafCap.get("holder"));
                boolean algPresent = p.containsKey("alg");
                if (Pca.suitePolicyError(p.get("alg"), algPresent, "leaf", o.allowedSuites) != null)
                    leafErr = "signature suite '" + (algPresent ? Pca.asStr(p.get("alg")) : "ed25519") + "' is not allowed by this verifier's suite policy";
                else leafErr = Pca.pqBindingError(p.get("alg"), algPresent, p.get("pq_pk"), leafCap.get("holder_pq"), "leaf");
                if (leafErr == null && p.get("sig") instanceof String)
                    sigOk = Pq.verifyLeafSuite(p.get("alg"), algPresent, holder,
                        Pq.resolvePqKey(holder, p.get("pq_pk"), leafCap.get("holder_pq"), null, null), Pca.thresholdMessage(p), p.get("sig"), p.get("pq_sig"));
            }
            if (leafErr != null) st.fail("leaf_signature", leafErr);
            else if (sigOk) st.set("leaf_signature", PASS);
            else st.fail("leaf_signature", "signature does not verify under the leaf holder key / suite");

            // counter_format
            if (Json.isSafeInt(p.get("counter")) && Json.asLong(p.get("counter")) >= 0) st.set("counter_format", PASS);
            else st.fail("counter_format", "missing or not a non-negative safe integer");

            // intent (reported iff the PCActn carries intent or the policy is active)
            Object session = p.containsKey("intent_session") ? Pca.asMap(p.get("intent_session")).get("session") : null;
            Object mapForm = p.containsKey("intent_session") ? Pca.asMap(p.get("intent_session")).get("map_form") : null;
            String intentWhy = Pca.decideIntent(p.get("intent"), p.containsKey("intent"), grant, o.intentPolicy, session instanceof String ? (String) session : null, mapForm);
            if (intentWhy != null) {
                if (intentWhy.isEmpty()) st.set("intent", PASS); else st.fail("intent", intentWhy);
            }
            for (IntentV2.Check c : IntentV2.decide(p, grant, o.intentV2, now).checks) {
                if (c.ok) st.set(c.name, PASS); else st.fail(c.name, c.reason == null ? "rejected" : c.reason);
            }
            K3.FreshAtCheck fa = K3.decideFreshAt(p.containsKey("fresh_at"), p.get("fresh_at"), o.freshAt, now);
            if (fa.status.equals("pass")) st.set("fresh_at", PASS);
            else if (fa.status.equals("fail")) st.fail("fresh_at", fa.reason);

            Enforce en = o.enforce;
            // M1 taint gate
            if (en != null && en.taint != null) {
                try {
                    String r = Taint.gate(p.get("provenance"), en.taint.ctx, en.taint.maxTaint);
                    if (r == null) st.set("taint_gate", PASS); else st.fail("taint_gate", r);
                } catch (RuntimeException e) {
                    st.fail("taint_gate", "taint gate error (fail closed): " + e.getMessage());
                }
            } else st.set("taint_gate", NOT_ENFORCED);

            // M3 freshness gate
            if (en != null && en.freshness != null) {
                Freshness g = en.freshness;
                double epochMs = g.epochMs != null ? g.epochMs : 60_000;
                double fnow = g.now != null ? g.now : now;
                double skew = g.clockSkewMs != null && !g.clockSkewMs.isNaN() && !g.clockSkewMs.isInfinite() ? Math.max(0, g.clockSkewMs) : 0;
                Object frO = p.get("freshness");
                Map<?, ?> fr = frO instanceof Map ? (Map<?, ?>) frO : null;
                Object br = fr == null ? null : fr.get("beacon_ref");
                boolean epochOk = fr != null && Json.isSafeInt(fr.get("epoch")) && Json.asLong(fr.get("epoch")) > 0;
                if (!(epochMs > 0) || Double.isNaN(g.maxAgeMs) || Double.isInfinite(g.maxAgeMs) || g.maxAgeMs < 0 || !Double.isFinite(fnow)) {
                    st.fail("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)");
                } else if (!(br instanceof String) || ((String) br).isEmpty() || !epochOk) {
                    st.fail("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)");
                } else {
                    double anchor = Json.asLong(fr.get("epoch")) * epochMs;
                    if (anchor > fnow + skew) st.fail("freshness", "freshness anchor is in the future");
                    else if (fnow - anchor > g.maxAgeMs) st.fail("freshness", "freshness anchor is stale (older than " + jsNum(g.maxAgeMs) + " ms)");
                    else st.set("freshness", PASS);
                }
            }

            // M5 attestation (the gate's verifier takes the slot of hooks.attestation), threshold, revocation
            AttestationGate attGate = en == null ? null : en.attestation;
            Hook attHook = attGate != null ? attGate.verifier : hooks == null ? null : hooks.attestation;
            runHook(st, ctx, "attestation", attHook, enforcedT);
            if (attGate != null && attGate.required && NOT_ENFORCED.equals(st.checks.get("attestation")))
                st.fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)");
            runHook(st, ctx, "threshold", hooks == null ? null : hooks.threshold, enforcedT);
            runHook(st, ctx, "revocation", hooks == null ? null : hooks.revocation, enforcedT);

            // zk_compliance: fail closed at the core
            if (p.containsKey("zk_compliance")) {
                runHook(st, ctx, "zk_compliance", hooks == null ? null : hooks.zk, enforcedT);
                String c = st.checks.get("zk_compliance");
                if (!PASS.equals(c) && !FAIL.equals(c))
                    st.fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof");
            }
            if (p.containsKey("bond_ref")) st.set("bond", NOT_ENFORCED);
        } catch (Exception e) {
            st.checks.put("malformed", FAIL); if (st.reason == null) st.reason = "malformed PCActn: " + e.getMessage(); // reason verbatim, as CoreMalformed
        }

        if (!o.assurance && o.requireAssurance == null) return withUnsupported(p, resultOf(st), enforcedT[0]);
        Assurance.Sources src = new Assurance.Sources();
        src.pcactn = p;
        if (hooks != null) { src.attestationHook = hooks.attestation; src.zkHook = hooks.zk; src.thresholdHook = hooks.threshold; src.revocationHook = hooks.revocation; }
        if (o.enforce != null && o.enforce.attestation != null) src.usedAttestationHook = o.enforce.attestation.verifier;
        if (o.requireAssurance != null) {
            src.checks = withUnsupported(p, resultOf(st), null).checks;
            String unmet = Assurance.unmet(Assurance.report(src), o.requireAssurance);
            if (unmet == null) st.set("assurance", PASS); else st.fail("assurance", unmet.startsWith("assurance: ") ? unmet.substring("assurance: ".length()) : unmet); // unmet already carries the check name
        }
        Result out = withUnsupported(p, resultOf(st), enforcedT[0]);
        src.checks = out.checks;
        out.assurance = Assurance.report(src);
        return out;
    }

    private static Result withUnsupported(Map<String, Object> p, Result r, Double t) {
        if (p.containsKey("bond_ref") && NOT_ENFORCED.equals(r.checks.get("bond"))) r.checks.put("bond", UNSUPPORTED);
        r.enforcedT = t;
        return r;
    }

    private static void runHook(State st, Ctx ctx, String name, Hook hook, Double[] enforcedT) throws Exception {
        HookResult res = hook == null ? HookResult.notEnforced() : hook.run(ctx);
        if (!res.enforced) st.set(name, NOT_ENFORCED);
        else if (res.ok) {
            st.set(name, PASS);
            if (name.equals("threshold") && res.t != null) enforcedT[0] = res.t;
        } else st.fail(name, res.reason != null ? res.reason : "rejected");
    }
}
