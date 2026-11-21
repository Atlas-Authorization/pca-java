package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import net.atlasauth.pca.openaiagents.OpenAiAgents;
import net.atlasauth.pca.openaiagents.OpenAiAgents.PcaGuardrailOptions;
import net.atlasauth.pca.openaiagents.OpenAiAgents.Tool;
import net.atlasauth.pca.openaiagents.OpenAiAgents.VerifyOutcome;
import net.atlasauth.pca.openaiagents.OpenAiAgents.WithPcaToolOptions;
import net.atlasauth.pca.openaiagents.PcaToolDenied;
import org.junit.jupiter.api.Test;

/**
 * Replay of the reference's OpenAI Agents adapter logic: proof sources, the guard pipeline, per-tool option merging, guardrails and the step-up helpers.
 * Tools, verifiers and hooks are rebuilt from the declarative descriptors of the corpus. Deliberate differences, not compared: a tool is a lambda (no
 * name / extra / needsApproval members), a build error is any IllegalArgumentException (the reference splits TypeError from Error and words the text
 * differently), the audience is required here (an absent one is replaced by a fixed id, which the stub verifiers ignore), and full-mode components are
 * checked per call here, not when the tool is wrapped.
 */
class OpenAiAgentsDiffTest {
    private static final String M = "ref-openai-agents";
    private static final String AUD = "rs";
    private static final Pattern DECODED = Pattern.compile("proof could not be decoded: [\\s\\S]*$");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> o(Object v) { return v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<>(); }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object v) { return (List<Object>) v; }

    private static String str(Object v) { return v instanceof String ? (String) v : null; }

    private static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    private static Object clean(Object v, boolean dropNames) {
        if (v instanceof String) return DECODED.matcher((String) v).replaceAll("proof could not be decoded: ");
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(clean(x, dropNames)); return out; }
        if (v instanceof Map) {
            Map<String, Object> d = o(v);
            if (Boolean.TRUE.equals(d.get("build"))) { Map<String, Object> b = new LinkedHashMap<>(); b.put("err", "Error"); b.put("calls", clean(d.get("calls"), dropNames)); b.put("build", true); return b; }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : d.entrySet()) {
                String k = e.getKey();
                if (k.equals("extra") || k.equals("hasNeedsApproval") || (dropNames && k.equals("name"))) continue;
                out.put(k, clean(e.getValue(), dropNames));
            }
            return out;
        }
        return v;
    }

    private void check(String fn, OracleCases.Fn f, Function<Map<String, Object>, Boolean> skip, boolean dropNames, Set<String> keep) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, fn)) {
            if (skip != null && skip.apply(c)) continue;
            Object want = clean(c.get("out"), dropNames);
            if (keep != null && want instanceof Map) { Map<String, Object> w = new LinkedHashMap<>(o(want)); w.keySet().retainAll(keep); want = w; }
            final Set<String> k = keep;
            String d = OracleCases.diff(c, want, a -> { Object got = clean(f.apply(a), dropNames); if (k != null && got instanceof Map) { Map<String, Object> g = new LinkedHashMap<>(o(got)); g.keySet().retainAll(k); return g; } return got; });
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    private void check(String fn, OracleCases.Fn f) throws Exception { check(fn, f, null, true, null); }

    // ---- proof sources ----
    @Test void proofFromRunContext() throws Exception {
        check("proofFromRunContext", a -> { Map<String, Object> x = o(a.get(0)); return OpenAiAgents.proofFromRunContext(o(x.get("input")), o(x.get("runContext"))); });
    }

    @Test void guardrailProof() throws Exception { check("guardrailProofFromContext", a -> OpenAiAgents.guardrailProofFromContext(o(o(a.get(0)).get("args")))); }

    @Test void provenance() throws Exception { check("provenanceFromRunContext", a -> OpenAiAgents.provenanceFromRunContext(new LinkedHashMap<>(), o(o(a.get(0)).get("runContext")))); }

    @Test void inputHeaders() throws Exception {
        check("proofFromInputHeaders", a -> {
            Map<String, Object> x = o(a.get(0));
            String field = str(x.get("field")), header = str(x.get("header"));
            return OpenAiAgents.proofFromInputHeaders(field != null ? field : "headers", header != null ? header : "PCA-Action").find(o(x.get("input")), new LinkedHashMap<>());
        });
    }

    // ---- descriptors -> native objects ----
    private static Function<Map<String, Object>, VerifyOutcome> stub(Map<String, Object> d, List<Object> calls) {
        return p -> {
            Map<String, Object> action = o(p.get("action"));
            calls.add(list("verify", d.get("stub"), action.get("verb")));
            if (d.get("throws") instanceof String) throw new IllegalStateException((String) d.get("throws"));
            boolean allow = Boolean.TRUE.equals(d.get("allow"));
            Map<String, String> checks = new LinkedHashMap<>();
            checks.put("sig", allow ? "pass" : "fail");
            return new VerifyOutcome(allow, d.containsKey("reason") ? str(d.get("reason")) : null, checks);
        };
    }

    private static OpenAiAgents.ProofSource require(Map<String, Object> d) {
        if (!(d.get("require") instanceof Map)) return null;
        Map<String, Object> r = o(d.get("require"));
        if (r.containsKey("headers")) {
            List<Object> h = l(r.get("headers"));
            return OpenAiAgents.proofFromInputHeaders(h.size() > 0 ? (String) h.get(0) : "headers", h.size() > 1 ? (String) h.get(1) : "PCA-Action");
        }
        Object c = r.get("const");
        return (input, rc) -> c;
    }

    private static boolean on(Object v) { return v != null && !Boolean.FALSE.equals(v); }

    private static WithPcaToolOptions opts(Map<String, Object> d, List<Object> calls, boolean shared) {
        WithPcaToolOptions w = new WithPcaToolOptions();
        w.mode = str(d.get("mode"));
        w.verb = str(d.get("verb"));
        w.require = require(d);
        w.audience = d.containsKey("audience") && str(d.get("audience")) != null ? str(d.get("audience")) : shared ? AUD : null;
        if (d.get("verify") instanceof Map) w.verifyFn = stub(o(d.get("verify")), calls);
        if (d.get("authorize") != null) w.authorize = (i, r) -> new Authorize.Input();
        if (on(d.get("onDeny"))) w.onDeny = (e, i) -> calls.add(list("onDeny", e.kind, i));
        if (on(d.get("onVerified"))) w.onVerified = (p, i) -> calls.add(list("onVerified", true, o(p.get("action")).get("verb"), i));
        if (on(d.get("recorder"))) w.recorder = (name, out) -> calls.add(list("recorded", name, out));
        return w;
    }

    private static Tool tool(Map<String, Object> td, List<Object> calls) {
        String name = str(td.get("name"));
        if (Boolean.TRUE.equals(td.get("noExecute"))) return (i, r) -> { throw new IllegalStateException("with_pca_tool: the wrapped tool has no execute()"); };
        return (input, rc) -> {
            calls.add(list("exec", name, input));
            if (td.get("throws") instanceof String) throw new IllegalStateException((String) td.get("throws"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("echo", input);
            out.put("tool", name);
            return out;
        };
    }

    private static Map<String, Object> errOf(Exception e, List<Object> calls) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("err", e instanceof PcaToolDenied ? "PcaToolDenied" : "Error");
        out.put("message", e.getMessage());
        out.put("calls", calls);
        if (e instanceof PcaToolDenied) {
            PcaToolDenied p = (PcaToolDenied) e;
            out.put("kind", p.kind);
            out.put("verb", p.verb);
            if (p.checks != null) out.put("checks", new LinkedHashMap<String, Object>(p.checks));
        }
        return out;
    }

    private static Map<String, Object> buildErr(List<Object> calls) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("err", "Error");
        out.put("calls", calls);
        out.put("build", true);
        return out;
    }

    private static Map<String, Object> outcome(Tool t, Object input, Map<String, Object> rc, List<Object> calls) {
        try {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("out", t.execute(o(input), rc));
            out.put("calls", calls);
            return out;
        } catch (Exception e) { return errOf(e, calls); }
    }

    private static final Function<Map<String, Object>, Boolean> SKIP_FULL_MODE = c ->
        c.get("out") instanceof Map && Boolean.TRUE.equals(o(c.get("out")).get("build")) && str(o(c.get("out")).get("message")) != null
            && str(o(c.get("out")).get("message")).contains("full policy mode is missing");

    @Test void withPcaTool() throws Exception {
        check("withPcaTool", a -> {
            Map<String, Object> x = o(a.get(0));
            List<Object> calls = new ArrayList<>();
            Tool t;
            try { t = OpenAiAgents.withPcaTool(str(o(x.get("tool")).get("name")), tool(o(x.get("tool")), calls), opts(o(x.get("options")), calls, true)); }
            catch (IllegalArgumentException e) { return buildErr(calls); }
            Map<String, Object> rc = Boolean.TRUE.equals(x.get("noRunContext")) ? null : o(x.get("runContext"));
            return outcome(t, x.get("input"), rc, calls);
        }, SKIP_FULL_MODE, true, null);
    }

    @Test void pcaTools() throws Exception {
        check("pcaTools", a -> {
            Map<String, Object> x = o(a.get(0));
            List<Object> calls = new ArrayList<>();
            Map<String, Tool> tools = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : o(x.get("tools")).entrySet()) tools.put(e.getKey(), tool(o(e.getValue()), calls));
            Map<String, Object> options = o(x.get("options"));
            Map<String, WithPcaToolOptions> per = null;
            if (options.get("per") instanceof Map) { per = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : o(options.get("per")).entrySet()) per.put(e.getKey(), opts(o(e.getValue()), calls, false)); }
            List<String> only = null;
            if (options.get("only") instanceof List) { only = new ArrayList<>(); for (Object v : l(options.get("only"))) only.add((String) v); }
            Map<String, Tool> g;
            try { g = OpenAiAgents.pcaTools(tools, opts(options, calls, true), per, only); }
            catch (IllegalArgumentException e) { return buildErr(calls); }
            Map<String, Object> res = new LinkedHashMap<>();
            for (Map.Entry<String, Tool> e : g.entrySet()) {
                Map<String, Object> r = outcome(e.getValue(), x.get("input"), o(x.get("runContext")), calls);
                r.put("same", e.getValue() == tools.get(e.getKey()));
                res.put(e.getKey(), r);
            }
            return res;
        }, SKIP_FULL_MODE, true, null);
    }

    @Test void guardrail() throws Exception {
        check("guardrail", a -> {
            Map<String, Object> x = o(a.get(0));
            List<Object> calls = new ArrayList<>();
            Map<String, Object> d = o(x.get("options"));
            WithPcaToolOptions wo = opts(d, calls, true);
            PcaGuardrailOptions go = new PcaGuardrailOptions();
            go.verifyFn = wo.verifyFn;
            go.audience = wo.audience;
            go.verb = wo.verb;
            go.name = str(d.get("name"));
            if (wo.require != null) go.require = args -> wo.require.find(args, new LinkedHashMap<>());
            OpenAiAgents.AgentGuardrail g = "input".equals(x.get("kind")) ? OpenAiAgents.pcaInputGuardrail(go) : OpenAiAgents.pcaToolGuard(go);
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                OpenAiAgents.GuardrailOutput r = g.execute.apply(o(x.get("args")));
                Map<String, Object> info = new LinkedHashMap<>(r.outputInfo);
                if (info.get("checks") == null) info.remove("checks");
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("tripwireTriggered", r.tripwireTriggered);
                result.put("outputInfo", info);
                out.put("name", g.name);
                out.put("result", result);
                out.put("calls", calls);
            } catch (Exception e) {
                out.clear();
                out.put("err", "Error");
                out.put("message", e.getMessage());
                out.put("calls", calls);
            }
            return out;
        }, null, false, null);
    }

    // ---- step-up (the corpus intent always answers "unguarded", so no agent is consulted) ----
    private static OpenAiAgents.ToolIntent recording(List<Object> calls) { return (t, i) -> { calls.add(list("intent", t, i)); return null; }; }

    @Test void reviewToolCall() throws Exception {
        check("reviewToolCall", a -> {
            Map<String, Object> x = o(a.get(0));
            List<Object> calls = new ArrayList<>();
            OpenAiAgents.StepUpOptions so = new OpenAiAgents.StepUpOptions();
            so.intent = recording(calls);
            OpenAiAgents.ToolReview r = OpenAiAgents.reviewToolCall(null, (String) x.get("tool"), x.get("input") instanceof Map ? o(x.get("input")) : null, so);
            Map<String, Object> rr = new LinkedHashMap<>();
            rr.put("tool", r.tool);
            rr.put("review", r.review);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("r", rr);
            out.put("calls", calls);
            return out;
        });
    }

    @Test void pendingStepUps() throws Exception {
        check("pendingStepUps", a -> {
            List<OpenAiAgents.ToolReview> reviews = new ArrayList<>();
            for (Object r : l(a.get(0))) { Map<String, Object> d = o(r); reviews.add(new OpenAiAgents.ToolReview((String) d.get("tool"), o(d.get("review")))); }
            List<Object> out = new ArrayList<>();
            for (OpenAiAgents.ToolStepUp p : OpenAiAgents.pendingStepUps(reviews)) { Map<String, Object> m = new LinkedHashMap<>(); m.put("tool", p.tool); m.put("request", p.request); out.add(m); }
            return out;
        });
    }

    @Test void needsApproval() throws Exception {
        check("needsApproval", a -> {
            Map<String, Object> x = o(a.get(0));
            List<Object> calls = new ArrayList<>();
            OpenAiAgents.NeedsApprovalOptions no = new OpenAiAgents.NeedsApprovalOptions();
            no.intent = recording(calls);
            no.toolName = str(x.get("toolName"));
            java.util.function.BiPredicate<Map<String, Object>, Map<String, Object>> f = "direct".equals(x.get("via"))
                ? OpenAiAgents.pcaNeedsApproval(null, no)
                : OpenAiAgents.withApproval(str(o(x.get("tool")).get("name")), null, no);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("value", f.test(new LinkedHashMap<>(), o(x.get("input"))));
            out.put("calls", calls);
            return out;
        }, null, true, Set.of("value", "calls"));
    }
}
