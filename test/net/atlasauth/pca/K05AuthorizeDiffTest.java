package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Authorize}: a differential test against the TS reference (k05 authorize oracle ->
 * test-data/k05-authorize.json.gz): the {@code tool_schema} firewall (validateArgSchema, evaluateToolSchema), the risk policy,
 * the envelope reader, and whole authorize() scenarios (provenance by default, fresh_at escalation, escalation answers, undo
 * admission, the pipeline around them). Every case compares exactly.
 *
 * <p>Documented differences (naming only): Java reports the cap-chain check as {@code chain} (TS {@code cap_chain}); a tool call's
 * {@code toolSignature} / {@code toolSignatureDigest} are the Java call members {@code tool_signature} /
 * {@code tool_signature_digest}; the K7 refusal names the Java setter ({@code escalationRender}) where TS names
 * {@code escalation.render}. The TS reference reports {@code attestation: not-enforced} on every verdict; Java reports the check
 * only when it fails, so the check maps are compared on the names both report (every failing check is compared in full).
 */
public class K05AuthorizeDiffTest {

    static List<Map<String, Object>> cases() throws Exception {
        return K05Oracle.all("k05-authorize");
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    static void report(List<String> bad, int n) { assertTrue(bad.isEmpty(), bad.size() + "/" + n + " divergent case(s):\n" + String.join("\n", bad)); }

    interface Validator { String apply(Object o); }
    void validators(String fn, Validator v) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of(fn);
        for (Map<String, Object> c : cs) {
            Object want = c.get("out");
            String got;
            try { got = v.apply(args(c).get(0)); } catch (Throwable t) { got = "THROWS " + t; }
            if (want == null ? got != null : !want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report(bad, cs.size());
    }

    @Test void validateArgSchema() throws Exception { validators("validateArgSchema", Authorize::validateArgSchema); }
    @Test void validateRiskPolicy() throws Exception { validators("validateRiskPolicy", Authorize::validateRiskPolicy); }

    @Test void evaluateToolSchema() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of("evaluateToolSchema");
        for (Map<String, Object> c : cs) {
            Object call = args(c).get(1);
            if (call instanceof Map) {
                Map<String, Object> j = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : m(call).entrySet()) {
                    String k = e.getKey().equals("toolSignature") ? "tool_signature" : e.getKey().equals("toolSignatureDigest") ? "tool_signature_digest" : e.getKey();
                    j.put(k, e.getValue());
                }
                call = j;
            }
            Map<String, Object> got = new LinkedHashMap<>();
            Authorize.ToolSchemaResult r = Authorize.evaluateToolSchema(args(c).get(0), call);
            got.put("ok", r.ok);
            if (r.reason != null) got.put("reason", r.reason);
            if (!IntentJs.jsonEquals(c.get("out"), got)) bad.add(c.get("name") + "\n  want: " + c.get("out") + "\n  got:  " + got);
        }
        report(bad, cs.size());
    }

    @Test void readEnvelope() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of("readEnvelope");
        for (Map<String, Object> c : cs) {
            Object got;
            try { got = Authorize.readEnvelope(args(c).get(0)); } catch (Throwable t) { got = "THROWS " + t; }
            if (!IntentJs.jsonEquals(c.get("out"), got)) bad.add(c.get("name") + "\n  want: " + c.get("out") + "\n  got:  " + got);
        }
        report(bad, cs.size());
    }

    /**
     * The generator calls a requiresAttestation the TS package index does not export, so every recorded case is a "not a function"
     * throw (a generator gap, reported). Those are skipped; any case that records a real result is compared.
     */
    @Test void requiresAttestation() throws Exception {
        List<String> bad = new ArrayList<>();
        int compared = 0;
        List<Map<String, Object>> cs = of("requiresAttestation");
        for (Map<String, Object> c : cs) {
            Object want = c.get("out");
            if (want instanceof Map && String.valueOf(m(want).get("$throws")).contains("is not a function")) continue;
            compared++;
            Object got;
            try { got = Authorize.requiresAttestation(args(c).get(0)); } catch (Throwable t) { got = "THROWS " + t; }
            if (!IntentJs.jsonEquals(want, got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report(bad, compared);
    }

    // ---- authorize() scenarios ------------------------------------------------------------------------------------------------

    static final List<String> KEY = List.of("wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion",
        "plan_root_authorized", "leaf_signature", "counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation",
        "params_digest", "delegated_caveats", "policy", "replay", "provenance_flow", "undo_window", "escalation");
    static final List<String> OWN = List.of("provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: ");
    static final String K7_JAVA = "(set escalationRender, or insecureUnboundApproval)";
    static final String K7_TS = "(set escalation.render, or insecureUnboundApproval)";

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> scenario(Map<String, Object> sc) { return scenario(sc, null); }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> scenario(Map<String, Object> sc, List<Authorize.AuthorizeResult> raw) {
        Map<String, Object> grant = m(sc.get("grant"));
        Map<String, Object> cfg = m(sc.get("config"));
        String audience = (String) cfg.get("audience");
        long now = IntentJs.lng(cfg.get("now"));
        MemoryStateStore store = new MemoryStateStore();
        boolean[] revoked = {false};
        ArgProvenance.Options gate = new ArgProvenance.Options().mediators((List<?>) cfg.get("mediators"));
        if (cfg.get("actions") != null) {
            Map<String, Object> facts = m(cfg.get("actions"));
            gate.actions(op -> facts.get(op.verb) == null ? null : m(facts.get(op.verb)));
        }
        if (cfg.get("observed") != null) {
            List<?> obs = (List<?>) cfg.get("observed");
            gate.observed((pc, op, session) -> obs);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object so : (List<?>) sc.get("steps")) {
            Map<String, Object> s = m(so);
            revoked[0] = Boolean.TRUE.equals(s.get("revoked"));
            Map<String, Object> op = m(s.get("operation"));
            Authorize.Input in = new Authorize.Input()
                .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
                .audience(audience)
                .resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
                .stateStore(store)
                .isRevoked((p, g) -> revoked[0])
                .plan(Authorize.SINGLE_STEP)
                .now(now)
                .provenanceGate(gate);
            if (s.containsKey("provenance")) in.provenance(ArgProvenance.Presented.bundle(s.get("provenance")));
            if (cfg.get("freshAt") != null) in.freshAt(K3.FreshAtPolicy.fromJson(cfg.get("freshAt")));
            if (cfg.get("undo") != null) {
                Map<String, Object> undo = m(cfg.get("undo"));
                in.undo((p, g, o) -> undo.get(o.verb) == null ? null : m(IntentJs.normalize(undo.get(o.verb))));
            }
            if (cfg.get("escalation") != null) {
                Map<String, Object> esc = m(cfg.get("escalation"));
                in.escalationPrincipals((List<?>) esc.get("principals"));
                if (esc.get("render_digest") != null) {
                    String rd = (String) esc.get("render_digest");
                    in.escalationRender(p -> rd);
                }
                if (Boolean.TRUE.equals(esc.get("insecureUnboundApproval"))) in.insecureUnboundApproval(true);
            }
            if (s.containsKey("escalationAnswer")) in.escalationAnswer(s.get("escalationAnswer"));
            Authorize.AuthorizeResult r = Authorize.authorize(s.get("pcactn"), in);
            if (raw != null) raw.add(r);

            Map<String, Object> o = new LinkedHashMap<>();
            o.put("allow", r.allow);
            o.put("decision", r.decision);
            o.put("status", (long) r.status);
            Map<String, Object> checks = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : r.checks.entrySet()) {
                String k = e.getKey().equals("chain") ? "cap_chain" : e.getKey();
                if (KEY.contains(k)) checks.put(k, e.getValue());
            }
            o.put("checks", checks);
            List<Object> failed = new ArrayList<>();
            for (String k : KEY) if ("fail".equals(checks.get(k))) failed.add(k);
            o.put("failed", failed);
            List<Object> reasons = new ArrayList<>();
            for (String x : r.reasons) if (OWN.stream().anyMatch(x::startsWith)) reasons.add(x.replace(K7_JAVA, K7_TS));
            o.put("reasons", reasons);
            o.put("escalation", r.escalation == null ? null : r.allow ? new LinkedHashMap<>(r.escalation) : Map.of("request", true));
            o.put("undo", r.undo == null ? null : new LinkedHashMap<>(r.undo));
            out.add(o);
        }
        return out;
    }

    /** The step projections agree: everything exactly; `checks` on the names Java reports, and every name the oracle reports enforced (pass or fail) must be reported. */
    static String diff(Map<String, Object> want, Map<String, Object> got) {
        for (String k : List.of("allow", "decision", "status", "failed", "reasons", "escalation", "undo"))
            if (!IntentJs.jsonEquals(want.get(k), got.get(k))) return k;
        Map<String, Object> wc = m(want.get("checks")), gc = m(got.get("checks"));
        for (Map.Entry<String, Object> e : gc.entrySet())
            if (wc.containsKey(e.getKey()) && !IntentJs.jsonEquals(wc.get(e.getKey()), e.getValue())) return "checks." + e.getKey();
        for (Map.Entry<String, Object> e : wc.entrySet())
            if (!gc.containsKey(e.getKey()) && !"not-enforced".equals(e.getValue()))
                return "checks." + e.getKey() + " (absent)";
        return null;
    }

    @Test void authorizeScenarios() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of("authorize");
        for (Map<String, Object> c : cs) {
            List<?> want = (List<?>) c.get("out");
            List<Map<String, Object>> got;
            try { got = scenario(m(args(c).get(0))); } catch (Throwable t) { bad.add(c.get("name") + "\n  THROWS " + t); continue; }
            if (got.size() != want.size()) { bad.add(c.get("name") + "\n  steps: want " + want.size() + ", got " + got.size()); continue; }
            for (int i = 0; i < got.size(); i++) {
                String d = diff(m(want.get(i)), got.get(i));
                if (d != null) {
                    bad.add(c.get("name") + " step " + i + " [" + d + "]\n  want: " + Json.canonicalize(want.get(i)) + "\n  got:  " + Json.canonicalize(got.get(i)));
                    break;
                }
            }
        }
        report(bad, cs.size());
    }
}
