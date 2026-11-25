package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for the Authorize helpers outside {@code run}: the result and option objects, the tool-schema firewall, the
 * agent-native caveat evaluator, the decisive reason, the params copy depth, the PCActn coercion bounds, the provenance gate's
 * pins, the assurance report, the K1 filter, the v2 env merge, {@code isAuthorizedFor}, and the proofs source of the staleness gate.
 */
public class AuthorizeRestK05bKillTest {

    // ---- AuthorizeResult ------------------------------------------------------------------------------------------------

    @Test void theShortConstructorDerivesTheDecisionFromAllow() {
        Authorize.AuthorizeResult allow = new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<>(), new ArrayList<>(), null, null, null, null, null);
        assertEquals(Decision.ALLOW, allow.decision);
        Authorize.AuthorizeResult deny = new Authorize.AuthorizeResult(false, 403, new LinkedHashMap<>(), new ArrayList<>(), null, null, null, null, null);
        assertEquals(Decision.DENY, deny.decision);
    }

    @Test void theResultCollectionsAreReadOnly() {
        Map<String, Object> undo = new LinkedHashMap<>();
        undo.put("id", "u");
        undo.put("window_end", 5L);
        Map<String, Object> esc = new LinkedHashMap<>(Map.of("x", 1L));
        Map<String, String> deg = new LinkedHashMap<>(Map.of("tighten", "w"));
        Map<String, String> checks = new LinkedHashMap<>(Map.of("a", "pass"));
        List<String> reasons = new ArrayList<>(List.of("r"));
        List<String> missing = new ArrayList<>(List.of("m"));
        Authorize.AuthorizeResult r = new Authorize.AuthorizeResult(false, 403, checks, reasons, "r", null, null, null, missing,
            Decision.ESCALATE, esc, deg, undo);
        assertThrows(UnsupportedOperationException.class, () -> r.undo.put("k", 1L));
        assertThrows(UnsupportedOperationException.class, () -> r.degraded.put("k", "v"));
        assertThrows(UnsupportedOperationException.class, () -> r.escalation.put("k", 1L));
        assertThrows(UnsupportedOperationException.class, () -> r.checks.put("k", "v"));
        assertThrows(UnsupportedOperationException.class, () -> r.reasons.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> r.missing.add("x"));
        assertEquals("u", r.undo.get("id"));
        assertEquals(List.of("m"), r.missing);
    }

    @Test void theAssuranceReportIsComputedOnceAndReadOnly() {
        Authorize.AuthorizeResult r = new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<>(Map.of("a", "pass")), new ArrayList<>(),
            null, null, null, null, null);
        Map<String, Object> a = r.assurance();
        assertSame(a, r.assurance());
        assertEquals(Map.of("a", Map.of("outcome", "pass")), a);
        assertThrows(UnsupportedOperationException.class, () -> a.put("k", "v"));
    }

    // ---- Input setters --------------------------------------------------------------------------------------------------

    @Test void inputSetters() {
        Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO);
        assertEquals(List.of(), in.escalationPrincipals);
        assertSame(in, in.escalationPrincipals(null));
        assertEquals(List.of(), in.escalationPrincipals);
        StateStore s = new MemoryStateStore();
        assertSame(in, in.usesStore(s));
        assertSame(s, in.usesStore);
        IntentV2.Context ctx = IntentV2.Context.fromJson(Map.of());
        assertSame(in, in.intentV2(ctx));
        assertSame(ctx, in.intentV2.apply(Map.of()));
        assertSame(in, in.intentV2((IntentV2.Context) null));
        assertNull(in.intentV2);
        Function<Map<String, Object>, IntentV2.Context> f = p -> ctx;
        assertSame(in, in.intentV2(f));
        assertSame(f, in.intentV2);
        List<String> suites = List.of("ed25519");
        assertSame(in, in.allowedSuites(suites));
        assertSame(suites, in.allowedSuites);
        assertSame(in, in.require((List<String>) null));
        assertEquals(List.of(), in.require);
        assertSame(in, in.require("a", "b"));
        assertEquals(List.of("a", "b"), in.require);
    }

    @Test void smallHelpers() {
        assertEquals("g:h", Authorize.stateKey("g", "h"));
        assertEquals("ToolSchemaResult{ok=false, reason=x}", new Authorize.ToolSchemaResult(false, "x").toString());
        assertNull(Authorize.renderDigestOf(null));
        assertEquals("d", Authorize.renderDigestOf(Map.of("render_digest", "d")));
        // an envelope caveat with a non-string member name throws inside: no envelope
        Map<Object, Object> cv = new LinkedHashMap<>();
        cv.put("type", Authorize.ENVELOPE_CAVEAT);
        cv.put(5L, "x");
        assertNull(Authorize.readEnvelope(Map.of("caveats", List.of(cv))));
    }

    // ---- the tool-schema firewall ---------------------------------------------------------------------------------------

    @Test void jsEqMatrix() {
        assertTrue(Authorize.jsEq(1L, new Json.Num("1.0")));
        assertFalse(Authorize.jsEq(1L, 2L));
        assertFalse(Authorize.jsEq(1L, "1"));
        assertFalse(Authorize.jsEq("1", 1L));
        assertFalse(Authorize.jsEq(1L, true));
        assertFalse(Authorize.jsEq(true, 1L));
        assertTrue(Authorize.jsEq(true, Boolean.TRUE));
        assertFalse(Authorize.jsEq(true, false));
        assertFalse(Authorize.jsEq(true, "true"));
        assertFalse(Authorize.jsEq("true", true));
        assertTrue(Authorize.jsEq("a", "a"));
        assertFalse(Authorize.jsEq("a", "b"));
        assertFalse(Authorize.jsEq(null, null));
        assertFalse(Authorize.jsEq("a", null));
        assertFalse(Authorize.jsEq(null, "a"));
        assertFalse(Authorize.jsEq(List.of(), List.of()));
    }

    static final char HI = (char) 0xD83D, LO = (char) 0xDE00;

    @Test void showEscapesControlsAndLoneSurrogatesOnly() {
        assertEquals("\" \"", Authorize.show(" "));
        assertEquals("\"!\"", Authorize.show("!"));
        assertEquals("\"\\u001f\"", Authorize.show(String.valueOf((char) 0x1f)));
        assertEquals("\"" + HI + LO + "\"", Authorize.show("" + HI + LO));
        assertEquals("\"\\ud83d\"", Authorize.show(String.valueOf(HI)));
        assertEquals("\"a\\ud83d\"", Authorize.show("a" + HI));
        assertEquals("\"\\ud83da\"", Authorize.show(HI + "a"));
        assertEquals("\"\\ude00\"", Authorize.show(String.valueOf(LO)));
        assertEquals("\"a\\ude00\"", Authorize.show("a" + LO));
        assertEquals("\"" + HI + LO + "\\ude00\"", Authorize.show("" + HI + LO + LO));
    }

    static Map<String, Object> spec(Object... kv) { return Issue.obj(kv); }

    static Map<String, Object> schema(Map<String, Object> props) { return Issue.obj("props", props); }

    @Test void argSchemaValidation() {
        Map<String, Object> str = spec("type", "string");
        assertNull(Authorize.validateArgSchema(Issue.obj("props", Issue.obj("a", str), "required", List.of("a"))));
        assertEquals("required names an undeclared property", Authorize.validateArgSchema(Issue.obj("props", Issue.obj("a", str), "required", List.of(5L))));
        assertEquals("required names an undeclared property", Authorize.validateArgSchema(Issue.obj("props", Issue.obj("a", str), "required", List.of("zz"))));
        assertEquals("a: unknown type", Authorize.validateArgSchema(schema(Issue.obj("a", 5L))));
        Map<String, Object> nul = new LinkedHashMap<>();
        nul.put("a", null);
        assertEquals("a: unknown type", Authorize.validateArgSchema(schema(nul)));
        assertEquals("a: bad min", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "number", "min", "x")))));
        assertEquals("a: bad min", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "integer", "min", "x")))));
        assertEquals("a: bad max", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "integer", "max", "x")))));
        assertEquals("a: min > max", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "number", "min", 5L, "max", 1L)))));
        assertEquals("a: min > max", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "integer", "min", 5L, "max", 1L)))));
        assertNull(Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "integer", "min", 1L, "max", 5L)))));
        assertNull(Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "boolean")))));
        assertEquals("a: unknown spec key", Authorize.validateArgSchema(schema(Issue.obj("a", spec("type", "boolean", "min", 1L)))));
    }

    /** The root counts one node, each object one, each scalar one: 256 nodes are accepted, the 257th refused. */
    @Test void argSchemaNodeBudgetCountsEveryObjectOnce() {
        Map<String, Object> props = new LinkedHashMap<>();
        for (int i = 0; i < 5; i++) {
            Map<String, Object> inner = new LinkedHashMap<>();
            for (int j = 0; j < 50; j++) inner.put("q" + j, spec("type", "string"));
            props.put("p" + i, spec("type", "object", "props", inner));
        }
        assertNull(Authorize.validateArgSchema(schema(props))); // 1 + 5 * (1 + 50) = 256
        props.put("p5", spec("type", "string"));
        assertEquals("p5: schema too large", Authorize.validateArgSchema(schema(props)));
    }

    static Map<String, Object> toolCaveat(String tool, Map<String, Object> schema) {
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("tool", tool);
        binding.put("signature_digest", "sig");
        binding.put("schema", schema);
        Map<String, Object> cv = new LinkedHashMap<>();
        cv.put("type", "tool_schema");
        cv.put("tool", tool);
        cv.put("signature_digest", "sig");
        cv.put("schema", schema);
        cv.put("schema_digest", Pca.hashCanonical(schema));
        cv.put("binding_digest", Pca.hashCanonical(binding));
        return cv;
    }

    static List<Object> bools(int n) { return new ArrayList<>(Collections.nCopies(n, Boolean.TRUE)); }

    /** A call walks at most MAX_VALUE_NODES (10,000) values: node 10,000 passes, node 10,001 is refused with its path. */
    @Test void theValueBudget() {
        Map<String, Object> sch = schema(Issue.obj("a", spec("type", "array", "maxItems", 3L,
            "items", spec("type", "array", "maxItems", 4096L, "items", spec("type", "boolean")))));
        Map<String, Object> cv = toolCaveat("t", sch);
        // a (1), a[0] (2) and its 4096 values, a[1] (4099) and its 4096, a[2] (8196) and its values from node 8197 on
        Authorize.ToolSchemaResult within = Authorize.evaluateToolSchema(cv, Authorize.toolCall("t", Map.of("a", List.of(bools(4096), bools(4096), bools(1804))), null));
        assertTrue(within.ok, within.reason);
        Authorize.ToolSchemaResult over = Authorize.evaluateToolSchema(cv, Authorize.toolCall("t", Map.of("a", List.of(bools(4096), bools(4096), bools(1805))), null));
        assertFalse(over.ok);
        assertEquals("args.a[2][1804]: too many values", over.reason);
    }

    @Test void toolSchemaRefusals() {
        Map<String, Object> cv = toolCaveat("t", schema(Issue.obj("b", spec("type", "boolean"))));
        assertTrue(Authorize.evaluateToolSchema(cv, Authorize.toolCall("t", Map.of("b", true), null)).ok);
        Authorize.ToolSchemaResult wrong = Authorize.evaluateToolSchema(cv, Authorize.toolCall("t", Map.of("b", "x"), null));
        assertFalse(wrong.ok);
        assertEquals("args.b: wrong type (expected boolean)", wrong.reason);
        // a non-string tool: malformed (not an evaluation error)
        Authorize.ToolSchemaResult tool = Authorize.evaluateToolSchema(Map.of("type", "tool_schema", "tool", 5L), Authorize.toolCall("t", Map.of(), null));
        assertFalse(tool.ok);
        assertEquals("malformed tool_schema caveat", tool.reason);
        // a property name that is not a string throws inside the schema check: fail closed
        Map<Object, Object> props = new LinkedHashMap<>();
        props.put(1L, spec("type", "string"));
        Authorize.ToolSchemaResult err = Authorize.evaluateToolSchema(Map.of("type", "tool_schema", "tool", "t", "schema", Map.of("props", props)),
            Authorize.toolCall("t", Map.of(), null));
        assertFalse(err.ok);
        assertEquals("evaluation error (fail closed)", err.reason);
    }

    // ---- the agent-native caveat evaluator ------------------------------------------------------------------------------

    @Test void agentCaveats() {
        Map<String, Object> ctx = new LinkedHashMap<>();
        Caveats.Result notList = Authorize.evaluateAgentCaveats("x", ctx, null, null);
        assertFalse(notList.ok);
        assertEquals(List.of("<malformed caveats>"), notList.failed);
        Caveats.Result malformed = Authorize.evaluateAgentCaveats(Arrays.asList(5L, null, Map.of("type", 5L)), ctx, null, null);
        assertFalse(malformed.ok);
        assertEquals(List.of("<malformed>", "<malformed>", "<malformed>"), malformed.failed);
        Caveats.Result badAllow = Authorize.evaluateAgentCaveats(List.of(Map.of("type", "predicates", "allow", "x"), Map.of("type", "predicates")),
            ctx, Issue.obj("action", Issue.obj("verb", "a", "resource", "r")), null);
        assertFalse(badAllow.ok);
        assertEquals(List.of("predicates", "predicates"), badAllow.failed);
        Map<String, Object> preds = Issue.obj("type", "predicates", "allow", List.of(Issue.obj("verb", "*")));
        assertTrue(Authorize.evaluateAgentCaveats(List.of(preds), ctx, Issue.obj("action", Issue.obj("verb", "a", "resource", "r")), null).ok);
        Caveats.Result noAction = Authorize.evaluateAgentCaveats(List.of(preds), ctx, null, null);
        assertEquals(List.of("predicates"), noAction.failed);
        Map<String, Object> ts = toolCaveat("t", schema(Issue.obj("b", spec("type", "boolean"))));
        assertTrue(Authorize.evaluateAgentCaveats(List.of(ts), ctx, null, Authorize.toolCall("t", Map.of("b", true), null)).ok);
        assertEquals(List.of("tool_schema"), Authorize.evaluateAgentCaveats(List.of(ts), ctx, null, null).failed);
        // no stock context: an evaluation error (an empty list never reads it)
        Caveats.Result noCtx = Authorize.evaluateAgentCaveats(List.of(5L), null, null, null);
        assertFalse(noCtx.ok);
        assertEquals(List.of("<evaluation error>"), noCtx.failed);
        assertTrue(Authorize.evaluateAgentCaveats(List.of(), null, null, null).ok);
    }

    // ---- reasons --------------------------------------------------------------------------------------------------------

    static Map<String, String> checks(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    @Test void theDecisiveReason() {
        List<String> r = List.of("plan_state: p", "operation: o");
        assertEquals("operation: o", Authorize.decisive(checks("operation", "fail", "plan_state", "fail"), r));
        assertEquals("operation: o", Authorize.decisive(checks("plan_state", "fail", "operation", "fail"), r));
        assertEquals("plan_state: y", Authorize.decisive(checks("a", "fail", "plan_state", "fail"), List.of("a: x", "plan_state: y")));
        assertEquals("a: x", Authorize.decisive(checks("operation", "pass", "a", "fail"), List.of("operation: stale", "a: x")));
        assertEquals("a: 2", Authorize.decisive(checks("a", "fail"), List.of("b: 1", "a: 2")));
        assertEquals("zzz", Authorize.decisive(checks("a", "fail"), List.of("zzz")));
        assertEquals("denied", Authorize.decisive(checks(), List.of()));
    }

    @Test void foldV2ReasonsAddsEachFailedReasonOnce() {
        List<String> reasons = new ArrayList<>(List.of("x: dup"));
        Authorize.foldV2Reasons(reasons, List.of(new IntentV2.Check("a", false, "r"), new IntentV2.Check("b", true, "s"),
            new IntentV2.Check("c", false, null), new IntentV2.Check("x", false, "dup"), new IntentV2.Check("d", false, "")));
        assertEquals(List.of("x: dup", "a: r", "d: "), reasons);
    }

    // ---- the operation --------------------------------------------------------------------------------------------------

    @Test void anIncompleteOperationIsRefusedBeforeAnyVerification() {
        String why = "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)";
        Map<String, Object> params = Map.of("amount", 50L);
        Authorize.Operation[] bad = {null, Authorize.Operation.of(null, "payments/acme", params), Authorize.Operation.of("", "payments/acme", params),
            Authorize.Operation.of("payments.send", null, params), Authorize.Operation.of("payments.send", "", params),
            Authorize.Operation.of("payments.send", "payments/acme", null)};
        for (Authorize.Operation op : bad)
            AuthorizeK05KillTest.refused(Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(params).operation(op)), 403, "operation", why);
    }

    @Test void copyParamsDepth() {
        // 511 lists under the root map: the leaf sits at depth 512, which the copy accepts (the strict re-parse then refuses it)
        Object deep = "x";
        for (int i = 0; i < 511; i++) deep = List.of(deep);
        Object d511 = deep;
        String m = assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", d511))).getMessage();
        assertTrue(m.startsWith("nesting too deep"), m);
        Object d512 = List.of(d511); // leaf at 513
        assertEquals("params nested too deep", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", d512))).getMessage());
        Object maps = "x";
        for (int i = 0; i < 513; i++) maps = Map.of("k", maps); // the outermost is the params (depth 0), the leaf at 513
        @SuppressWarnings("unchecked")
        Map<String, ?> nested = (Map<String, ?>) maps;
        assertEquals("params nested too deep", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(nested)).getMessage());
    }

    @Test void coercionBounds() {
        String[] err = new String[1];
        String atLimit = "{\"a\":\"" + "a".repeat(Pca.MAX_ARTIFACT_BYTES - 8) + "\"}";
        assertEquals(Pca.MAX_ARTIFACT_BYTES, atLimit.length());
        Map<String, Object> m = Authorize.coerce(atLimit.getBytes(StandardCharsets.UTF_8), err);
        assertNull(err[0]);
        assertEquals(Pca.MAX_ARTIFACT_BYTES - 8, ((String) m.get("a")).length());
        // fewer characters than the limit but more UTF-8 bytes: too large, though it would parse
        String wide = "{\"a\":\"" + "\u20ac".repeat(180_000) + "\"}";
        assertTrue(wide.length() < Pca.MAX_ARTIFACT_BYTES);
        String[] e = new String[1];
        assertNull(Authorize.coerce(wide, e));
        assertEquals("undecodable", e[0]);
    }

    // ---- isAuthorizedFor ------------------------------------------------------------------------------------------------

    static Authorize.AuthorizeResult result(boolean allow, String verb, String resource, Map<String, ?> params) {
        Authorize.AuthorizedOperation op = verb == null ? null
            : new Authorize.AuthorizedOperation(verb, resource, Pca.paramsDigest(Authorize.copyParams(params)), "id");
        return new Authorize.AuthorizeResult(allow, allow ? 200 : 403, new LinkedHashMap<>(), new ArrayList<>(), null, op, null, null, null);
    }

    @Test void isAuthorizedForExactlyTheBoundOperation() {
        Map<String, Object> p = Map.of("amount", 50L);
        Authorize.AuthorizeResult r = result(true, "v", "r", p);
        assertTrue(Authorize.isAuthorizedFor(r, Authorize.Operation.of("v", "r", p)));
        assertTrue(Authorize.isAuthorizedFor(r, Authorize.Operation.of("v", "r", Map.of("amount", (short) 50)))); // the copy normalises Java numbers
        assertFalse(Authorize.isAuthorizedFor(r, Authorize.Operation.of("w", "r", p)));
        assertFalse(Authorize.isAuthorizedFor(r, Authorize.Operation.of("v", "s", p)));
        assertFalse(Authorize.isAuthorizedFor(r, Authorize.Operation.of("v", "r", Map.of("amount", 51L))));
        assertFalse(Authorize.isAuthorizedFor(r, Authorize.Operation.of("v", "r", Map.of("amount", new Object())))); // the copy throws
        for (Authorize.Operation op : new Authorize.Operation[] {null, Authorize.Operation.of(null, "r", p), Authorize.Operation.of("", "r", p),
                Authorize.Operation.of("v", null, p), Authorize.Operation.of("v", "", p)})
            assertFalse(Authorize.isAuthorizedFor(r, op));
        // null params are not the empty object
        Authorize.AuthorizeResult empty = result(true, "v", "r", Map.of());
        assertTrue(Authorize.isAuthorizedFor(empty, Authorize.Operation.of("v", "r", Map.of())));
        assertFalse(Authorize.isAuthorizedFor(empty, Authorize.Operation.of("v", "r", null)));
        // a refusal never authorizes, even one carrying an operation; nor does an allow without one, nor no result
        assertFalse(Authorize.isAuthorizedFor(result(false, "v", "r", p), Authorize.Operation.of("v", "r", p)));
        assertFalse(Authorize.isAuthorizedFor(result(true, null, null, p), Authorize.Operation.of("v", "r", p)));
        assertFalse(Authorize.isAuthorizedFor(null, Authorize.Operation.of("v", "r", p)));
    }

    // ---- the provenance gate --------------------------------------------------------------------------------------------

    static Map<String, Object> envelopeGrant(Object provenance) {
        Map<String, Object> cv = Issue.obj("type", Authorize.ENVELOPE_CAVEAT, "goal_commit", "g", "predicates", new ArrayList<>(),
            "caveats", new ArrayList<>(), "agent_binding", new LinkedHashMap<>(), "risk_policy", Issue.defaultRiskPolicy(), "provenance", provenance);
        return Issue.obj("caveats", List.of(cv));
    }

    static String[] prov(Authorize.Input in, Map<String, Object> grant, Map<String, Object> params, boolean plan, boolean control) {
        String[] r = Authorize.provenanceCheck(in, grant, new LinkedHashMap<>(), "payments.send", "payments/acme", params, plan, control);
        assertEquals(2, r.length);
        return r;
    }

    @Test void provenanceOutcomes() {
        Map<String, Object> none = new LinkedHashMap<>();
        Map<String, Object> noParams = new LinkedHashMap<>();
        assertEquals(Arrays.asList("fail", "the grant's provenance member is malformed: provenance must be an object"),
            Arrays.asList(prov(new Authorize.Input().risk(RiskCtx.ZERO), envelopeGrant(5L), noParams, false, false)));
        assertEquals(Arrays.asList("not-enforced", null),
            Arrays.asList(prov(new Authorize.Input().risk(RiskCtx.ZERO), envelopeGrant(Issue.obj("mode", "insecure_off")), noParams, false, false)));
        Authorize.Input badBundle = new Authorize.Input().risk(RiskCtx.ZERO).provenanceGate(new ArgProvenance.Options().bundle((pc, op) -> { throw new IllegalStateException("x"); }));
        assertEquals(Arrays.asList("fail", "the provenance bundle is unreadable (fail closed)"), Arrays.asList(prov(badBundle, none, noParams, false, false)));
        Authorize.Input badActions = new Authorize.Input().risk(RiskCtx.ZERO).provenanceGate(new ArgProvenance.Options().actions(op -> { throw new IllegalStateException("x"); }));
        assertEquals(Arrays.asList("fail", "the action facts or observations could not be resolved (fail closed)"),
            Arrays.asList(prov(badActions, none, noParams, false, false)));
        // no bundle: the agent chose a sensitive action, so it escalates, unless the principal chose it (control) or the plan is the principal's
        assertEquals(Arrays.asList("fail", "escalate: the choice of payments.send derives from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)"),
            Arrays.asList(prov(new Authorize.Input().risk(RiskCtx.ZERO), none, noParams, false, false)));
        assertEquals(Arrays.asList("pass", null), Arrays.asList(prov(new Authorize.Input().risk(RiskCtx.ZERO), none, noParams, false, true)));
        assertEquals(Arrays.asList("pass", null), Arrays.asList(prov(new Authorize.Input().risk(RiskCtx.ZERO), none, Issue.obj("amount", 50L), true, false)));
    }

    // ---- the assurance report -------------------------------------------------------------------------------------------

    @Test void assuranceOfDegradedAndUnsupported() {
        // a degraded tighten that did not fail reports pass, degraded
        assertEquals(Map.of("tighten", Map.of("outcome", "pass", "degraded", true, "reason", "why"), "x", Map.of("outcome", "fail")),
            Authorize.assuranceOf(checks("tighten", "not-enforced", "x", "fail"), null, Map.of("tighten", "why")));
        // a failed one stays failed
        assertEquals(Map.of("tighten", Map.of("outcome", "fail")), Authorize.assuranceOf(checks("tighten", "fail"), null, Map.of("tighten", "why")));
        // a degraded report without tighten changes nothing
        assertEquals(Map.of("tighten", Map.of("outcome", "not-enforced"), "other", Map.of("outcome", "pass")),
            Authorize.assuranceOf(checks("tighten", "not-enforced", "other", "pass"), null, Map.of("other", "w")));
        assertEquals(Map.of("tighten", Map.of("outcome", "not-enforced")), Authorize.assuranceOf(checks("tighten", "not-enforced"), null, null));
        // a failed zk_compliance is unsupported only when the PCActn carries one
        Map<String, Object> zk = Map.of("zk_compliance", "z");
        assertEquals(Map.of("zk_compliance", Map.of("outcome", "unsupported", "reason", "zk_compliance is not implemented by this verifier")),
            Authorize.assuranceOf(checks("zk_compliance", "fail"), zk, null));
        assertEquals(Map.of("zk_compliance", Map.of("outcome", "fail")), Authorize.assuranceOf(checks("zk_compliance", "fail"), Map.of(), null));
        assertEquals(Map.of("zk_compliance", Map.of("outcome", "fail")), Authorize.assuranceOf(checks("zk_compliance", "fail"), null, null));
        assertEquals(Map.of("zk_compliance", Map.of("outcome", "pass", "level", "unknown")), Authorize.assuranceOf(checks("zk_compliance", "pass"), zk, null));
        assertEquals(Map.of("x", Map.of("outcome", "pass")), Authorize.assuranceOf(checks("x", "pass"), zk, null));
    }

    // ---- the K1 filter --------------------------------------------------------------------------------------------------

    @Test void withoutK1DropsTheK1TypesOnlyWhenTheK1EvaluatorRan() {
        CaveatLang.K1Result k1 = new CaveatLang.K1Result(List.of(), List.of(), List.of(), List.of());
        List<Object> cs = List.of(Map.of("type", CaveatLang.CAVEAT_MAX_USES), Map.of("type", "x"), "s");
        assertEquals(List.of(Map.of("type", "x"), "s"), Authorize.withoutK1(cs, k1));
        assertSame(cs, Authorize.withoutK1(cs, null));
        assertSame("str", Authorize.withoutK1("str", k1));
    }

    // ---- the v2 env -----------------------------------------------------------------------------------------------------

    @Test void v2EnvWithoutASessionIsTheHostEnv() {
        Map<String, Object> env = new LinkedHashMap<>(Map.of("acc", 1L));
        assertSame(env, Authorize.v2Env(new LinkedHashMap<>(), new LinkedHashMap<>(), null, 0L, env));
    }

    @Test void v2EnvDropsTheVerifierMembersOfTheHostEnv() {
        // a malformed v2 context: decide reports failures and computes no env member
        Map<String, Object> p = Issue.obj("intent_session", new LinkedHashMap<>());
        IntentV2.Context bad = IntentV2.Context.fromJson(5L);
        assertTrue(IntentV2.decide(p, new LinkedHashMap<>(), bad, 0L).env.isEmpty());
        Map<String, Object> host = new LinkedHashMap<>();
        for (String k : new String[] {"acc", "mon", "canon", "world", "prov", "class"}) host.put(k, "host");
        host.put("keep", 1L);
        host.put(null, "n");
        Map<String, Object> want = new LinkedHashMap<>();
        want.put("keep", 1L);
        want.put(null, "n");
        Object got = Authorize.v2Env(p, new LinkedHashMap<>(), bad, 0L, host);
        assertEquals(want, got);
        assertNotSame(host, got);
        assertEquals(8, host.size());
        assertEquals(Map.of(), Authorize.v2Env(p, new LinkedHashMap<>(), bad, 0L, "not a map"));
        assertEquals(Map.of(), Authorize.v2Env(p, new LinkedHashMap<>(), bad, 0L, null));
    }

    @Test void v2EnvCarriesTheVerifierComputedMembers() throws Exception {
        Map<String, Object> c = K042IntentV2UnitTest.caseNamed("vec/session-g0");
        Map<String, Object> p = K042IntentV2UnitTest.parse(c.get("p"));
        K042IntentV2UnitTest.obj(p.get("intent_session")).put("seq", "x"); // schema and accumulators still pass (K042IntentV2UnitTest)
        Map<String, Object> grant = K042IntentV2UnitTest.parse(c.get("grant"));
        IntentV2.Context ctx = IntentV2.Context.fromJsonText((String) c.get("ctx"));
        long now = Json.asLong(c.get("now"));
        IntentV2.Decision d = IntentV2.decide(p, grant, ctx, now);
        assertTrue(d.env.containsKey("canon") && d.env.containsKey("acc") && d.env.containsKey("mon"), d.env.toString());
        Map<String, Object> host = new LinkedHashMap<>();
        host.put("keep", 1L);
        host.put("acc", "host");
        host.put("world", "host");
        host.put("class", "host");
        // the members are fresh trees (a second decide), so compare the member names and that each verifier member replaced the host's
        Map<String, Object> want = new LinkedHashMap<>();
        want.put("keep", 1L);
        want.putAll(d.env);
        @SuppressWarnings("unchecked")
        Map<String, Object> got = (Map<String, Object>) Authorize.v2Env(p, grant, ctx, now, host);
        assertEquals(want.keySet(), got.keySet());
        assertEquals(1L, got.get("keep"));
        for (String k : d.env.keySet()) assertEquals(d.env.get(k).getClass(), got.get(k).getClass(), k);
        assertFalse("host".equals(got.get("acc")));
    }

    // ---- Options --------------------------------------------------------------------------------------------------------

    static final Authorize.RevocationCheck NEVER = (p, g) -> false;

    @Test void optionsRequire() {
        StateStore s = new MemoryStateStore();
        assertEquals(List.of(), new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).require);
        List<String> req = new ArrayList<>(List.of("x"));
        Authorize.Options o = new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, null, req).withRisk(RiskCtx.ZERO);
        req.add("y");
        assertEquals(List.of("x"), o.require);
        assertThrows(UnsupportedOperationException.class, () -> o.require.add("z"));
    }

    static void carries(Authorize.Options o, Map<String, Object> k1, StateStore uses, Function<Map<String, Object>, String> render) {
        assertSame(k1, o.k1);
        assertSame(uses, o.usesStore);
        assertSame(render, o.escalationRender);
        assertTrue(o.insecureUnboundApproval);
    }

    @Test void everyCopyKeepsTheConfiguredMembers() {
        StateStore s = new MemoryStateStore(), uses = new MemoryStateStore();
        Map<String, Object> k1 = new LinkedHashMap<>();
        Function<Map<String, Object>, String> render = p -> "d";
        Authorize.Options o = new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        assertSame(o, o.k1(k1));
        assertSame(o, o.usesStore(uses));
        assertSame(o, o.escalationRender(render));
        assertSame(o, o.insecureUnboundApproval(true));
        carries(o, k1, uses, render);

        ArgProvenance.Options gate = new ArgProvenance.Options();
        Authorize.Options pv = o.withProvenance(gate);
        assertNotSame(o, pv);
        assertNull(o.provenance);
        assertSame(gate, pv.provenance);
        carries(pv, k1, uses, render);

        Undo.Admit admit = (pc, g, op) -> null;
        Authorize.Options un = pv.withUndo(admit);
        assertNotSame(pv, un);
        assertNull(pv.undo);
        assertSame(admit, un.undo);
        assertSame(gate, un.provenance);
        carries(un, k1, uses, render);

        Authorize.WorkflowPin pin = new Authorize.WorkflowPin("p", "s", true);
        Authorize.Options wf = un.withWorkflow(pin);
        assertNotSame(un, wf);
        assertNull(un.workflow());
        assertSame(pin, wf.workflow());
        assertSame(admit, wf.undo);
        assertSame(gate, wf.provenance);
        carries(wf, k1, uses, render);

        for (Authorize.Options c : List.of(wf.withPlans(null), wf.withIntentPolicy(null), wf.withRevocationStaleness(null),
                wf.withRequireAssurance(null), wf.withRevocationState(pc -> null))) {
            assertNotSame(wf, c);
            carries(c, k1, uses, render);
            assertSame(pin, c.workflow());
            assertSame(admit, c.undo);
            assertSame(gate, c.provenance);
        }
    }

    @Test void withRevocationStateMergesIntoTheContext() {
        StateStore s = new MemoryStateStore();
        Map<String, Object> pc = Map.of("p", 2L);
        assertEquals(Map.of("revocation_state", "st"), new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withRevocationState(x -> "st").context.apply(pc));
        Authorize.Options withBase = new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, x -> new LinkedHashMap<>(Map.of("a", 1L)), null).withRisk(RiskCtx.ZERO)
            .withRevocationState(x -> "st");
        assertEquals(Map.of("a", 1L, "revocation_state", "st"), withBase.context.apply(pc));
        Authorize.Options baseWins = new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, x -> Map.of("revocation_state", "own"), null).withRisk(RiskCtx.ZERO)
            .withRevocationState(x -> { throw new AssertionError("the context's own state wins"); });
        assertEquals(Map.of("revocation_state", "own"), baseWins.context.apply(pc));
        Map<String, Object> noState = new Authorize.Options(s, NEVER, Authorize.SINGLE_STEP, x -> null, null).withRisk(RiskCtx.ZERO).withRevocationState(x -> null).context.apply(pc);
        assertEquals(Map.of(), noState);
    }

    // ---- the staleness proofs source ------------------------------------------------------------------------------------

    /** A guardian-signed epoch (epoch 0) over the revocation set {@code root} of {@code size}, issued {@code ageMs} before {@code now}. */
    static Map<String, Object> epoch(String grantRef, long now, long ageMs, long size, String root) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", "i");
        body.put("grant_ref", grantRef);
        body.put("epoch", IntentJs.ofLong(0));
        body.put("set_size", IntentJs.ofLong(size));
        body.put("root", root);
        body.put("issued_at", IntentJs.ofLong(now - ageMs));
        body.put("not_after", IntentJs.ofLong(now - ageMs + 600_000));
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(StalenessVectorsTest.seed("staleness/guardian"), 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", StalenessVectorsTest.pub());
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    /** The proofs source is asked for each chain capability and its proof (empty set: {size: 0}) is what is verified. */
    @Test void aValidProofFromTheProofsSourceAdmits() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> pcactn = AuthorizeFixtures.pcactn(c, 0);
        long now = AuthorizeFixtures.now();
        Object state = RevocationStaleness.State.epoch(epoch((String) pcactn.get("grant_ref"), now, 30_000, 0, Mesh.bindRevRoot(0, Ledger.EMPTY_TREE_ROOT)), null, null);
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("size", IntentJs.ofLong(0));
        List<String> asked = new ArrayList<>();
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(StalenessVectorsTest.pub())
            .proofs((id, pc) -> { asked.add(id); return proof; });
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn, AuthorizeFixtures.input(c, 0).revocationStaleness(policy)
            .context(pc -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("revocation_state", state);
                return m;
            }));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("freshness"));
        assertFalse(asked.isEmpty());
    }
}
