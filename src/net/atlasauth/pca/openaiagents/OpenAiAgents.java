package net.atlasauth.pca.openaiagents;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Approvals;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.PcaCore;

/**
 * OpenAI Agents SDK guard: makes every agent tool call proof-carrying and policy-gated at the LOCAL execution boundary. {@link #withPcaTool} wraps a tool's
 * {@code execute(input, runContext)} so it first REQUIRES a proof-carrying action (pulled from the run context by the PCA-Action convention), VERIFIES it
 * (fail closed: {@link PcaToolDenied}) and only then runs the original tool; guardrails trip a run that lacks a valid proof.
 *
 * <p>Structural, no vendor package: a tool is a functional interface over JSON trees ({@code Map<String, Object>}), the run context a JSON object whose
 * {@code "context"} member is the caller's bag (the proof rides there as {@code "pca"} / {@code "pcaProof"}).
 *
 * <p>Two modes. Full (the default): every call runs {@link Authorize#authorize}: the input must hash to the signed params digest, the grant's predicates,
 * limits and caveats are evaluated, revocation is required and a replay store makes each PCActn single-use; a missing component is refused. Signature-only:
 * the proof's signature, capability chain, plan inclusion, audience and validity window are checked, NOT that the grant permits this call. Either way this does
 * not replace the resource server when a tool makes a remote call: it makes the local boundary refuse to act without a valid PCActn.
 *
 * <p>Step-up: {@link #reviewToolCall} / {@link #pendingStepUps} / {@link #pcaNeedsApproval} / {@link #withApproval} map a risky tool to the SDK's
 * needsApproval interruption through {@link Approvals#reviewAction} (auto / deny / tier-2 or tier-3 co-sign).
 *
 * <p>Differences from the reference (all stricter or structural): a tool is a lambda (no name / extra members to carry), an audience is required when the tool
 * is wrapped (an absent one is not "fail closed at verify time" but a configuration error), the full-mode components are checked on each call (the options
 * come from a function evaluated per call), and the JS attach side ({@code withPCA} / {@code withPCATools}) is not ported.
 */
public final class OpenAiAgents {
    private OpenAiAgents() {}

    /** An Agents-SDK tool's {@code execute(input, runContext)}. */
    @FunctionalInterface
    public interface Tool { Object execute(Map<String, Object> input, Map<String, Object> runContext) throws Exception; }

    /** Finds the proof for a call from (input, runContext): a PCActn object or string; null fails closed. */
    @FunctionalInterface
    public interface ProofSource { Object find(Map<String, Object> input, Map<String, Object> runContext); }

    /** Records tool results as UNTRUSTED output (an {@link ArgProvenance.Recorder}'s {@code tool}). */
    @FunctionalInterface
    public interface ToolOutputRecorder { void tool(String name, Object output); }

    /** A verification outcome of a custom verifier. */
    public static final class VerifyOutcome {
        public final boolean allow;
        public final String reason;
        public final Map<String, String> checks;
        public VerifyOutcome(boolean allow, String reason, Map<String, String> checks) { this.allow = allow; this.reason = reason; this.checks = checks; }
    }

    /** Signature-only verification: the grant the proof must chain to. The plan-root policy defaults to "nothing authorized" (every call refused). */
    public static final class VerifyGrant {
        public Map<String, Object> grant;
        /** Verifier clock (epoch ms), evaluated per call; default the wall clock. */
        public LongSupplier now;
        public List<String> allowedSuites;
        public Pca.PlanRoots planRoots = Pca.PlanRoots.NONE;
        public VerifyGrant(Map<String, Object> grant) { this.grant = grant; }
    }

    /** Options of {@link #withPcaTool}; copy-on-merge. */
    public static final class WithPcaToolOptions {
        /** Find the proof for a call. Default {@link #proofFromRunContext}. */
        public ProofSource require;
        /** "full" (default) or "signature-only". */
        public String mode;
        /** Signature-only: the grant to chain to, or {@link #verifyFn} (exactly one). */
        public VerifyGrant verify;
        public Function<Map<String, Object>, VerifyOutcome> verifyFn;
        /** Full mode: builds the per-call {@link Authorize.Input}, including the operation this call executes (a call with none is refused); the guard sets its audience and the provenance bundle when the input carries none. A fresh input per call. */
        public BiFunction<Map<String, Object>, Map<String, Object>, Authorize.Input> authorize;
        /** This verifier's audience, matched against the PCActn's signed aud. Required. */
        public String audience;
        /** Defense in depth: the proof's action verb must equal this (bind the proof to THIS tool). */
        public String verb;
        /** Where the provenance bundle of this call is. Default {@link #provenanceFromRunContext}. */
        public ProofSource provenance;
        /** When set, every result the tool returns is recorded as UNTRUSTED tool output. */
        public ToolOutputRecorder recorder;
        public BiConsumer<PcaToolDenied, Map<String, Object>> onDeny;
        /** Observe a successful verification (the PCActn, the tool input) before the original execute runs. */
        public BiConsumer<Map<String, Object>, Map<String, Object>> onVerified;

        WithPcaToolOptions copy() {
            WithPcaToolOptions o = new WithPcaToolOptions();
            o.require = require; o.mode = mode; o.verify = verify; o.verifyFn = verifyFn; o.authorize = authorize; o.audience = audience; o.verb = verb;
            o.provenance = provenance; o.recorder = recorder; o.onDeny = onDeny; o.onVerified = onVerified;
            return o;
        }
    }

    /** What an Agents-SDK guardrail returns: a tripwire plus free-form info. */
    public static final class GuardrailOutput {
        public final boolean tripwireTriggered;
        public final Map<String, Object> outputInfo;
        public GuardrailOutput(boolean tripwireTriggered, Map<String, Object> outputInfo) { this.tripwireTriggered = tripwireTriggered; this.outputInfo = outputInfo; }
    }

    /** Options of {@link #pcaInputGuardrail} / {@link #pcaToolGuard}. */
    public static final class PcaGuardrailOptions {
        /** Find the proof for a run from the guardrail args ({@code {context, ...}}). Default {@link #guardrailProofFromContext}. */
        public Function<Map<String, Object>, Object> require;
        public VerifyGrant verify;
        public Function<Map<String, Object>, VerifyOutcome> verifyFn;
        public String audience;
        public String verb;
        public String name;
    }

    /** A guardrail: a name and an execute over the SDK's guardrail args. */
    public static final class AgentGuardrail {
        public final String name;
        public final Function<Map<String, Object>, GuardrailOutput> execute;
        AgentGuardrail(String name, Function<Map<String, Object>, GuardrailOutput> execute) { this.name = name; this.execute = execute; }
    }

    // ---- proof sources ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object first(Map<String, Object> d, String... keys) {
        for (String k : keys) { Object v = d.get(k); if (v != null) return v; }
        return null;
    }

    /** An encoded PCActn string from a {@code {pca | pcaProof}} bag; null when neither is a string. */
    public static String proofFromBag(Object bag) {
        Map<String, Object> d = asMap(bag);
        if (d == null) return null;
        Object v = first(d, "pca", "pcaProof");
        return v instanceof String ? (String) v : null;
    }

    /** Default proof source: {@code runContext.context.{pca|pcaProof}}, then {@code runContext.{pca|pcaProof}}. */
    public static Object proofFromRunContext(Map<String, Object> input, Map<String, Object> runContext) {
        String inner = proofFromBag(runContext.get("context"));
        return inner != null ? inner : proofFromBag(runContext);
    }

    /** Default provenance source: {@code {pcaProvenance | pca_provenance | PCA-Provenance}} on {@code runContext.context}, then on {@code runContext}. */
    public static Object provenanceFromRunContext(Map<String, Object> input, Map<String, Object> runContext) {
        for (Object bag : new Object[] {runContext.get("context"), runContext}) {
            Map<String, Object> d = asMap(bag);
            if (d == null) continue;
            Object v = first(d, "pcaProvenance", "pca_provenance", "PCA-Provenance");
            if (v != null) return v;
        }
        return null;
    }

    /** A proof source reading a base64url PCA-Action header from a headers-like bag on the tool input. */
    public static ProofSource proofFromInputHeaders(String field, String header) {
        return (input, runContext) -> {
            Map<String, Object> bag = asMap(input.get(field));
            return bag != null && bag.get(header) instanceof String ? bag.get(header) : null;
        };
    }

    public static ProofSource proofFromInputHeaders() { return proofFromInputHeaders("headers", "PCA-Action"); }

    /** The guardrail-side default: the proof from the run context the SDK passes as {@code args.context}. */
    public static Object guardrailProofFromContext(Map<String, Object> args) {
        Object outer = args.get("context");
        Map<String, Object> o = asMap(outer);
        String inner = proofFromBag(o == null ? null : o.get("context"));
        return inner != null ? inner : proofFromBag(outer);
    }

    // ---- the proof pipeline ----

    // a string is tried as raw encoded JSON, then as a PCA-Action header value
    static Map<String, Object> toPcActn(Object input) {
        Map<String, Object> d = asMap(input);
        if (d != null) return d;
        if (!(input instanceof String)) throw new IllegalArgumentException("a proof is a PCActn object or an encoded string");
        String s = (String) input;
        try {
            Map<String, Object> raw = asMap(Json.parse(s));
            if (raw != null) return raw;
        } catch (RuntimeException e) { /* fall through to the header form */ }
        String text = Pca.decodePcaHeader(s);
        if (text == null) throw new IllegalArgumentException("the proof is neither PCActn JSON nor a PCA-Action header value");
        Map<String, Object> out = asMap(Json.parse(text));
        if (out == null) throw new IllegalArgumentException("the proof is not a JSON object");
        return out;
    }

    static String verbOf(Map<String, Object> pcactn) {
        Map<String, Object> a = asMap(pcactn.get("action"));
        return a != null && a.get("verb") instanceof String ? (String) a.get("verb") : "";
    }

    private static VerifyOutcome runVerify(VerifyGrant verify, Function<Map<String, Object>, VerifyOutcome> fn, Map<String, Object> pcactn, String audience) {
        if (fn != null) return fn.apply(pcactn);
        PcaCore.Options o = new PcaCore.Options(verify.grant).audience(audience);
        LongSupplier nowFn = verify.now != null ? verify.now : System::currentTimeMillis;
        o.nowEpoch = nowFn.getAsLong();
        o.allowedSuites = verify.allowedSuites;
        o.planRoots = verify.planRoots;
        PcaCore.Result r = PcaCore.verify(pcactn, o);
        return new VerifyOutcome(r.allow, r.reason, new LinkedHashMap<>(r.checks));
    }

    // the kind of a refused full-policy decision, from the first failing check
    static String kindOf(Authorize.AuthorizeResult r) {
        if (r.missing != null && !r.missing.isEmpty()) return "config";
        String failed = "";
        for (Map.Entry<String, String> c : r.checks.entrySet()) if ("fail".equals(c.getValue())) { failed = c.getKey(); break; }
        switch (failed) {
            case "authorize_config": return "config";
            case "replay": return "replay";
            case "revocation": case "freshness": return "revoked";
            case "operation": case "params_digest": return "binding";
            case "policy": case "plan_state": case "plan_root_authorized": case "provenance_flow": return "policy";
            default: return "verify";
        }
    }

    private static void checkMode(String mode, boolean hasVerify, boolean hasAuthorize, String who) {
        String m = mode == null ? "full" : mode;
        if (!m.equals("full") && !m.equals("signature-only")) throw new IllegalArgumentException(who + ": unknown mode '" + m + "'");
        if (m.equals("signature-only")) {
            if (hasAuthorize) throw new IllegalArgumentException(who + ": `authorize` is the full mode; drop it, or drop mode 'signature-only'");
            if (!hasVerify) throw new IllegalArgumentException(who + ": mode 'signature-only' needs `verify` or `verifyFn`");
        } else {
            if (!hasAuthorize) throw new IllegalArgumentException(who + ": pass `authorize` (full policy, the default mode), or set mode 'signature-only' with `verify`");
            if (hasVerify) throw new IllegalArgumentException(who + ": `verify` checks the signature only: set mode 'signature-only' to use it, and drop `authorize`");
        }
    }

    /**
     * The bundle a framework carried: the bundle object itself, its JSON text, or a {@code PCA-Provenance} header value (base64url JSON). Null for anything
     * else (the gate then treats the call as unlabelled: fail closed).
     */
    static Object provenanceFrom(Object v) {
        if (v == null) return null;
        if (v instanceof Map || v instanceof List) return v;
        if (!(v instanceof String) || ((String) v).isEmpty()) return null;
        String s = (String) v;
        try { return Json.parse(s); } catch (RuntimeException e) { /* header form */ }
        try {
            String t = Pca.decodePcaHeader(s);
            return t == null ? null : Json.parse(t);
        } catch (RuntimeException e) { return null; }
    }

    /**
     * Wrap a tool's {@code execute(input, runContext)} so each call first REQUIRES + VERIFIES a proof-carrying action (fail closed:
     * {@link PcaToolDenied}), then runs the original. Throws {@link IllegalArgumentException} at construction on a missing or contradictory configuration.
     */
    public static Tool withPcaTool(String toolName, Tool execute, WithPcaToolOptions options) {
        checkMode(options.mode, options.verify != null || options.verifyFn != null, options.authorize != null, "with_pca_tool");
        if (options.verify != null && options.verifyFn != null) throw new IllegalArgumentException("with_pca_tool: give exactly one of `verify` and `verifyFn`");
        if (options.audience == null || options.audience.isEmpty()) throw new IllegalArgumentException("with_pca_tool: `audience` (this verifier's id) is required");
        final WithPcaToolOptions o = options.copy();
        final ProofSource source = o.require != null ? o.require : OpenAiAgents::proofFromRunContext;
        final ProofSource prov = o.provenance != null ? o.provenance : OpenAiAgents::provenanceFromRunContext;
        final String label = o.verb != null ? o.verb : toolName != null ? toolName : "(tool)";
        final String audience = o.audience;
        return (input, runContextOrNull) -> {
            Map<String, Object> runContext = runContextOrNull != null ? runContextOrNull : new LinkedHashMap<>();
            Map<String, Object> pcactn;
            try {
                Object raw = source.find(input, runContext);
                if (raw == null) throw new PcaToolDenied("no proof-carrying action present on the call", label, "missing");
                try { pcactn = toPcActn(raw); }
                catch (RuntimeException cause) { throw new PcaToolDenied("proof could not be decoded: " + cause.getMessage(), label, "malformed"); }
                String verb = verbOf(pcactn);
                if (o.verb != null && !verb.equals(o.verb))
                    throw new PcaToolDenied("proof is for '" + verb + "', not this tool's '" + o.verb + "'", verb, "binding");
                if (o.authorize != null) {
                    Authorize.AuthorizeResult d;
                    try {
                        Authorize.Input ai = o.authorize.apply(input, runContext);
                        ai.audience(audience);
                        if (ai.provenance() == null) {
                            Object bundle = provenanceFrom(prov.find(input, runContext));
                            if (bundle != null) ai.provenance(ArgProvenance.Presented.bundle(bundle));
                        }
                        d = Authorize.authorize(pcactn, ai);
                    } catch (RuntimeException e) { throw new PcaToolDenied("the authorize configuration failed: " + e.getMessage(), verb.isEmpty() ? label : verb, "config"); }
                    if (!d.allow) throw new PcaToolDenied(d.reason == null ? "denied" : d.reason, verb.isEmpty() ? label : verb, kindOf(d), d.checks);
                } else {
                    VerifyOutcome r = runVerify(o.verify, o.verifyFn, pcactn, audience);
                    if (!r.allow) throw new PcaToolDenied(r.reason == null ? "verification failed" : r.reason, verb.isEmpty() ? label : verb, "verify", r.checks);
                }
            } catch (PcaToolDenied e) {
                if (o.onDeny != null) o.onDeny.accept(e, input);
                throw e;
            }
            if (o.onVerified != null) o.onVerified.accept(pcactn, input);
            Object output = execute.execute(input, runContextOrNull);
            if (o.recorder != null) { String v = verbOf(pcactn); o.recorder.tool(v.isEmpty() ? label : v, output); }
            return output;
        };
    }

    private static WithPcaToolOptions merge(WithPcaToolOptions b, WithPcaToolOptions over) {
        if (over == null) return b;
        // a per-tool verify or authorize replaces the shared mode (the two are exclusive)
        WithPcaToolOptions m = b.copy();
        if (over.authorize != null) { m.authorize = over.authorize; m.verify = null; m.verifyFn = null; m.mode = over.mode; }
        else if (over.verify != null || over.verifyFn != null) { m.authorize = null; m.verify = over.verify; m.verifyFn = over.verifyFn; m.mode = over.mode != null ? over.mode : b.mode; }
        else m.mode = over.mode != null ? over.mode : b.mode;
        if (over.require != null) m.require = over.require;
        if (over.audience != null) m.audience = over.audience;
        if (over.verb != null) m.verb = over.verb;
        if (over.onDeny != null) m.onDeny = over.onDeny;
        if (over.onVerified != null) m.onVerified = over.onVerified;
        if (over.provenance != null) m.provenance = over.provenance;
        if (over.recorder != null) m.recorder = over.recorder;
        return m;
    }

    /**
     * Guard a whole {@code {name: execute}} set in one call. Every tool is guarded with the shared options (override per tool via {@code per}, or limit the
     * set via {@code only}; the others pass through unchanged, the same instance).
     */
    public static Map<String, Tool> pcaTools(Map<String, Tool> tools, WithPcaToolOptions options, Map<String, WithPcaToolOptions> per, Collection<String> only) {
        Map<String, Tool> res = new LinkedHashMap<>();
        for (Map.Entry<String, Tool> e : tools.entrySet()) {
            String name = e.getKey();
            res.put(name, only != null && !only.contains(name) ? e.getValue() : withPcaTool(name, e.getValue(), merge(options, per == null ? null : per.get(name))));
        }
        return res;
    }

    // ---- guardrails: reject a run / tool call lacking a valid proof ----

    private static Function<Map<String, Object>, GuardrailOutput> guardrailExecute(PcaGuardrailOptions opts) {
        if ((opts.verify == null) == (opts.verifyFn == null)) throw new IllegalArgumentException("guardrail: give exactly one of `verify` and `verifyFn`");
        if (opts.audience == null || opts.audience.isEmpty()) throw new IllegalArgumentException("guardrail: `audience` (this verifier's id) is required");
        final Function<Map<String, Object>, Object> source = opts.require != null ? opts.require : OpenAiAgents::guardrailProofFromContext;
        final String label = opts.verb != null ? opts.verb : "(run)";
        return args -> {
            try {
                Object raw = source.apply(args);
                if (raw == null) throw new PcaToolDenied("no proof-carrying action present on the call", label, "missing");
                Map<String, Object> pcactn;
                try { pcactn = toPcActn(raw); }
                catch (RuntimeException cause) { throw new PcaToolDenied("proof could not be decoded: " + cause.getMessage(), label, "malformed"); }
                String verb = verbOf(pcactn);
                if (opts.verb != null && !verb.equals(opts.verb)) throw new PcaToolDenied("proof is for '" + verb + "', not this tool's '" + opts.verb + "'", verb, "binding");
                VerifyOutcome r = runVerify(opts.verify, opts.verifyFn, pcactn, opts.audience);
                if (!r.allow) throw new PcaToolDenied(r.reason == null ? "verification failed" : r.reason, verb.isEmpty() ? label : verb, "verify", r.checks);
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("verb", verb);
                return new GuardrailOutput(false, info);
            } catch (PcaToolDenied e) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("kind", e.kind);
                info.put("verb", e.verb);
                info.put("reason", e.getMessage());
                info.put("checks", e.checks == null ? null : new LinkedHashMap<String, Object>(e.checks));
                return new GuardrailOutput(true, info);
            }
        };
    }

    /**
     * An input guardrail: runs once at the top of a run and trips the tripwire (rejecting the run before any step executes) when the run context carries no
     * valid proof. Signature-only: a run-level guardrail sees no single tool call to bind; put the authority check on the tool.
     */
    public static AgentGuardrail pcaInputGuardrail(PcaGuardrailOptions options) { return new AgentGuardrail(options.name != null ? options.name : "pca-input-guardrail", guardrailExecute(options)); }

    /** A tool guardrail: the same proof gate scoped to a tool call (read the proof from the tool input with {@code require}). */
    public static AgentGuardrail pcaToolGuard(PcaGuardrailOptions options) { return new AgentGuardrail(options.name != null ? options.name : "pca-tool-guard", guardrailExecute(options)); }

    // ---- step-up: map a risky tool to needsApproval / the interruption flow ----

    /** Maps a tool name (and its input) to the PCA action to review ({verb, resource, params?}); null treats the tool as unguarded (auto). */
    @FunctionalInterface
    public interface ToolIntent { Map<String, Object> map(String tool, Map<String, Object> input); }

    /** Options of {@link #reviewToolCall}. */
    public static class StepUpOptions {
        /** Which PCA (verb, resource, params) a tool call maps to for risk review. */
        public ToolIntent intent;
        /** Standing "approve this class for N hours" grants that downgrade a matching step-up to auto. */
        public List<Object> standing;
        /** Plaintext goal to carry on any step-up request. */
        public String goal;
        /** Review clock (epoch ms); null: the wall clock. */
        public Long now;
        /** The canonical approval render of the action. A step-up without one is a deny. */
        public Approvals.Renderer renderer;
        /** The documented INSECURE opt-out: create step-up requests with no render. */
        public boolean insecureUnboundApproval;
    }

    /** Options of {@link #pcaNeedsApproval}. */
    public static final class NeedsApprovalOptions extends StepUpOptions {
        /** The tool name to review (default "(tool)"). */
        public String toolName;
        /** True when a step-up request has already been co-signed (your FROST / CIBA result): it is then let through. */
        public Predicate<Map<String, Object>> approved;
        /** Receives each step-up this call raised: push it to the approval inbox / open the co-sign round. */
        public Consumer<ToolStepUp> onStepUp;
        /** Whether a policy deny also routes to approval (so the run interrupts and the approver rejects it). Default true. */
        public boolean denyNeedsApproval = true;
    }

    /** The outcome of reviewing one intended tool call: review is {kind: auto} | {kind: deny, reason} | {kind: step_up, request}. */
    public static final class ToolReview {
        public final String tool;
        public final Map<String, Object> review;
        public ToolReview(String tool, Map<String, Object> review) { this.tool = tool; this.review = review; }
    }

    /** A step-up a tool call raised (what the approval inbox / co-sign round / SDK interruption receives). */
    public static final class ToolStepUp {
        public final String tool;
        public final Map<String, Object> request;
        public ToolStepUp(String tool, Map<String, Object> request) { this.tool = tool; this.request = request; }
    }

    /** Reviews one intended tool call against the agent's grant. {@code opts.intent} maps the tool to the PCA action to review; null treats the tool as unguarded (auto). */
    public static ToolReview reviewToolCall(Facade.Handle agent, String tool, Map<String, Object> input, StepUpOptions opts) {
        Map<String, Object> mapped = opts.intent.map(tool, input);
        if (mapped == null) {
            Map<String, Object> auto = new LinkedHashMap<>();
            auto.put("kind", "auto");
            return new ToolReview(tool, auto);
        }
        Approvals.ReviewOptions ro = new Approvals.ReviewOptions();
        ro.now = opts.now;
        ro.goal = opts.goal;
        ro.standing = opts.standing;
        ro.renderer = opts.renderer;
        ro.insecureUnboundApproval = opts.insecureUnboundApproval;
        Map<String, Object> params = asMap(mapped.get("params"));
        return new ToolReview(tool, Approvals.reviewAction(agent, (String) mapped.get("verb"), (String) mapped.get("resource"), params != null ? params : input, ro));
    }

    /** The step-up requests from a batch of reviews (auto and deny are filtered out). */
    public static List<ToolStepUp> pendingStepUps(Collection<ToolReview> reviews) {
        List<ToolStepUp> out = new ArrayList<>();
        for (ToolReview r : reviews) if ("step_up".equals(r.review.get("kind"))) out.add(new ToolStepUp(r.tool, asMap(r.review.get("request"))));
        return out;
    }

    /**
     * Builds a needsApproval callback (run context, tool input) from PCA risk review: auto returns false; a step-up not yet approved is routed to
     * {@code onStepUp} and returns true (the SDK interrupts for a tier-2/3 co-sign); an already approved step-up returns false; a deny returns
     * {@code denyNeedsApproval} (default true: interrupt so the approver can reject it, fail safe).
     */
    public static BiPredicate<Map<String, Object>, Map<String, Object>> pcaNeedsApproval(Facade.Handle agent, NeedsApprovalOptions opts) {
        final String toolName = opts.toolName != null ? opts.toolName : "(tool)";
        return (runContext, input) -> {
            Map<String, Object> review = reviewToolCall(agent, toolName, input, opts).review;
            Object kind = review.get("kind");
            if ("auto".equals(kind)) return false;
            if ("deny".equals(kind)) return opts.denyNeedsApproval;
            Map<String, Object> request = asMap(review.get("request"));
            if (opts.approved != null && opts.approved.test(request)) return false;
            if (opts.onStepUp != null) opts.onStepUp.accept(new ToolStepUp(toolName, request));
            return true;
        };
    }

    /** The needsApproval callback of a tool named {@code toolName} (the intent lookup is seeded with it unless {@code opts.toolName} is set; a nameless tool is "(tool)"). */
    public static BiPredicate<Map<String, Object>, Map<String, Object>> withApproval(String toolName, Facade.Handle agent, NeedsApprovalOptions opts) {
        if (opts.toolName == null) {
            NeedsApprovalOptions o = new NeedsApprovalOptions();
            o.intent = opts.intent; o.standing = opts.standing; o.goal = opts.goal; o.now = opts.now; o.renderer = opts.renderer; o.insecureUnboundApproval = opts.insecureUnboundApproval;
            o.approved = opts.approved; o.onStepUp = opts.onStepUp; o.denyNeedsApproval = opts.denyNeedsApproval;
            o.toolName = toolName != null ? toolName : "(tool)";
            return pcaNeedsApproval(agent, o);
        }
        return pcaNeedsApproval(agent, opts);
    }
}
