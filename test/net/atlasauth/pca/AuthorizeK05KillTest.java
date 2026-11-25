package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Authorize: the params copy, the PCActn coercion, the component report, and the reversibility ranks. */
public class AuthorizeK05KillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "https://rs.example";

    static Keys.SuiteKey key(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return Keys.ed25519(Keys.edFromSeed(x));
    }

    static final Keys.SuiteKey PRINCIPAL = key(31), AGENT = key(32);
    static final Map<String, Object> GRANT;
    static {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        GRANT = Issue.mintGrant(PRINCIPAL, AGENT.id(), null, env, "pay invoices", Pca.b64(new byte[16])).grant;
    }

    static Map<String, Object> pcactn() {
        return Agent.create(AGENT, AUD, GRANT, null).clock(() -> NOW).act("payments.send", "payments/acme", Issue.obj("amount", 50L));
    }

    static Authorize.Input input(Map<String, ?> params) {
        return new Authorize.Input().risk(RiskCtx.ZERO).operation(Authorize.Operation.of("payments.send", "payments/acme", params)).audience(AUD)
            .resolveGrant(ref -> ref.equals(GRANT.get("id")) ? GRANT : null).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false)
            .plan(Authorize.SINGLE_STEP).now(NOW).provenanceGate(ProvHarness.options());
    }

    static Authorize.AuthorizeResult run(Object pc, Authorize.Input in) { return Authorize.authorize(pc, in); }

    @Test void theBaselineAllows() {
        Authorize.AuthorizeResult r = run(pcactn(), input(Map.of("amount", 50L)));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("params_digest"));
        assertEquals("pass", r.checks.get("grant_ref"));
        assertFalse(r.checks.containsKey("reversibility"));
    }

    @Test void theVerifiedParamsAreAPrivateCopy() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("amount", 50L);
        Authorize.Input in = input(params).context(p -> { params.put("amount", 51L); return new LinkedHashMap<>(); });
        Authorize.AuthorizeResult r = run(pcactn(), in);
        assertEquals("pass", r.checks.get("params_digest"), r.reasons.toString());
    }

    @Test void copyParamsNormalisesJavaValues() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("b", "s"); m.put("c", true); m.put("d", new Json.Num("3")); m.put("e", 1); m.put("f", 2L); m.put("g", (short) 3);
        m.put("h", (byte) 4); m.put("i", BigInteger.valueOf(5)); m.put("j", new BigDecimal("1.25")); m.put("k", 1.5d); m.put("l", 0.5f);
        m.put("m", null); m.put("n", Arrays.asList(1, "x")); m.put("o", Map.of("p", 2));
        assertEquals("{\"b\":\"s\",\"c\":true,\"d\":3,\"e\":1,\"f\":2,\"g\":3,\"h\":4,\"i\":5,\"j\":1.25,\"k\":1.5,\"l\":0.5,\"m\":null,\"n\":[1,\"x\"],\"o\":{\"p\":2}}",
            Json.canonicalize(Authorize.copyParams(m)));
        assertEquals("params: non-finite number", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", Double.NaN))).getMessage());
        assertEquals("params: non-finite number", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", Float.POSITIVE_INFINITY))).getMessage());
        assertEquals("params: non-string key", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", Map.of(1, "y")))).getMessage());
        assertEquals("params: unsupported type Object", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", new Object()))).getMessage());
        Object deep = "x";
        for (int i = 0; i <= Json.MAX_LENIENT_DEPTH; i++) deep = List.of(deep);
        Object tooDeep = deep;
        assertEquals("params nested too deep", assertThrows(IllegalArgumentException.class, () -> Authorize.copyParams(Map.of("x", tooDeep))).getMessage());
    }

    @Test void anUncopyableOperationDeniesThroughTheOuterGuard() {
        Authorize.AuthorizeResult r = run(pcactn(), input(Map.of("amount", new Object())));
        assertFalse(r.allow);
        assertEquals(403, r.status);
        assertEquals(Map.of("authorize", "fail"), r.checks);
        assertEquals("authorize: error (fail closed): IllegalArgumentException", r.reason);
    }

    @Test void aNullInputReportsEveryMissingComponent() {
        Authorize.AuthorizeResult r = run(pcactn(), null);
        assertEquals(403, r.status);
        assertEquals(List.of("audience", "resolveGrant", "stateStore", "isRevoked"), r.missing);
        assertEquals("fail", r.checks.get("authorize_config"));
        assertEquals(List.of("audience", "resolveGrant", "stateStore", "isRevoked"), Authorize.missingAuthorizeComponents(null, null, null, null));
        assertEquals(List.of("audience"), Authorize.missingAuthorizeComponents("", 1, 1, 1));
        assertEquals(List.of(), Authorize.missingAuthorizeComponents("a", 1, 1, 1));
    }

    @Test void coercion() {
        String[] err = new String[1];
        Map<String, Object> m = new LinkedHashMap<>();
        assertSame(m, Authorize.coerce(m, err));
        assertNull(err[0]);
        assertEquals("{\"a\":1}", Json.canonicalize(Authorize.coerce("{\"a\":1}", err)));
        assertNull(err[0]);
        assertEquals(Map.of(), Authorize.coerce("{}".getBytes(StandardCharsets.UTF_8), err));
        assertNull(err[0]);
        for (Object bad : new Object[] {"[1]", "{", 5, new byte[] {(byte) 0xff}, new byte[Pca.MAX_ARTIFACT_BYTES + 1], "\"" + "a".repeat(Pca.MAX_ARTIFACT_BYTES) + "\""}) {
            String[] e = new String[1];
            assertNull(Authorize.coerce(bad, e));
            assertEquals("undecodable", e[0]);
        }
        String[] e = new String[1];
        assertNull(Authorize.coerce(null, e));
        assertEquals("absent", e[0]);
        Authorize.AuthorizeResult absent = run(null, input(Map.of("amount", 50L)));
        assertEquals(401, absent.status);
        assertEquals("wire: no PCActn presented", absent.reason);
        Authorize.AuthorizeResult junk = run("[1]", input(Map.of("amount", 50L)));
        assertEquals(401, junk.status);
        assertEquals("undecodable PCActn: could not be decoded", junk.reason);
    }

    @Test void toolCallShape() {
        Map<String, Object> plain = Authorize.toolCall("t", Map.of("a", 1), null);
        assertEquals(List.of("tool", "args"), new ArrayList<>(plain.keySet()));
        assertEquals("t", plain.get("tool"));
        assertEquals(Map.of("a", 1), plain.get("args"));
        Map<String, Object> bound = Authorize.toolCall("t", Map.of(), "d");
        assertEquals(List.of("tool", "args", "tool_signature_digest"), new ArrayList<>(bound.keySet()));
        assertEquals("d", bound.get("tool_signature_digest"));
    }

    /** The reversibility check, read alone: a tampered declared class still reports its own check. */
    @SuppressWarnings("unchecked")
    static Authorize.AuthorizeResult rev(Object declared, Object server) {
        Map<String, Object> pc = pcactn();
        if (declared != null) {
            Map<String, Object> action = new LinkedHashMap<>((Map<String, Object>) pc.get("action"));
            action.put("reversibility_class", declared); // null: keep the agent's own default ("reversible")
            pc = new LinkedHashMap<>(pc);
            pc.put("action", action);
        }
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("reversibility_class", server);
        return run(pc, input(Map.of("amount", 50L)).context(p -> ctx));
    }

    @Test void reversibilityRanks() {
        String[][] pass = {{null, "reversible"}, {"costly", "rate_limited"}, {"rate_limited", "costly"}, {"reversible", "reversible"},
            {"rate_limited", "reversible"}, {"weird", "irreversible"}, {"irreversible", "weird"}};
        for (String[] c : pass) assertEquals("pass", rev(c[0], c[1]).checks.get("reversibility"), Arrays.toString(c));
        Authorize.AuthorizeResult r = rev(null, "reversible");
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("fail", rev(null, "costly").checks.get("reversibility"));
        String[][] fail = {{"reversible", "costly"}, {"reversible", "rate_limited"}, {"costly", "irreversible"}, {"reversible", "weird"}};
        for (String[] c : fail) {
            Authorize.AuthorizeResult f = rev(c[0], c[1]);
            assertEquals("fail", f.checks.get("reversibility"), Arrays.toString(c));
            assertTrue(f.reasons.contains("reversibility: declared class '" + c[0] + "' is less restrictive than the authoritative '" + c[1] + "'"), f.reasons.toString());
        }
        // a non-string declared class never reaches the rank: the wire check refuses it first (Pca.validateWireV2)
        Authorize.AuthorizeResult nonStr = rev(5L, "irreversible");
        assertFalse(nonStr.allow);
        assertEquals("fail", nonStr.checks.get("wire"));
        assertNull(nonStr.checks.get("reversibility"));
        assertTrue(nonStr.reasons.stream().anyMatch(x -> x.contains("action.verb/resource/reversibility_class must be strings")), nonStr.reasons.toString());
        // a non-string server class ranks as irreversible
        assertEquals("fail", rev("costly", 5L).checks.get("reversibility"));
        assertTrue(rev("costly", 5L).reasons.contains("reversibility: declared class 'costly' is less restrictive than the authoritative '5'"));
    }

    static Map<String, Object> with(Map<String, Object> pc, String k, Object v) {
        Map<String, Object> out = new LinkedHashMap<>(pc);
        out.put(k, v);
        return out;
    }

    static void refused(Authorize.AuthorizeResult r, int status, String check, String reason) {
        assertFalse(r.allow);
        assertEquals(status, r.status, r.reasons.toString());
        assertEquals(Map.of(check, "fail"), r.checks);
        assertEquals(reason, r.reason);
        assertEquals(List.of(reason), r.reasons);
    }

    @Test void grantResolutionAndContextRefusals() {
        Map<String, Object> pc = pcactn();
        refused(run(with(pc, "grant_ref", 5L), input(Map.of("amount", 50L))), 401, "malformed", "malformed: grant_ref is not a string");
        refused(run(pc, input(Map.of("amount", 50L)).resolveGrant(ref -> { throw new IllegalStateException("x"); })), 403, "resolve_grant",
            "resolve_grant: grant resolution failed (fail closed)");
        refused(run(pc, input(Map.of("amount", 50L)).resolveGrant(ref -> null)), 401, "grant_ref", "grant_ref: does not resolve to a known grant");
        refused(run(pc, input(Map.of("amount", 50L)).context(p -> { throw new IllegalStateException("x"); })), 403, "context",
            "context: the context callback failed (fail closed)");
        Authorize.AuthorizeResult nullCtx = run(pc, input(Map.of("amount", 50L)).context(p -> null));
        assertTrue(nullCtx.allow, nullCtx.reasons.toString());
    }

    @Test void revocationOutcomes() {
        Map<String, Object> pc = pcactn();
        Authorize.AuthorizeResult revoked = run(pc, input(Map.of("amount", 50L)).isRevoked((p, g) -> true));
        assertEquals("fail", revoked.checks.get("revocation"));
        assertTrue(revoked.reasons.contains("revocation: the grant is revoked"), revoked.reasons.toString());
        for (Authorize.RevocationCheck rc : List.<Authorize.RevocationCheck>of((p, g) -> null, (p, g) -> { throw new IllegalStateException("x"); })) {
            Authorize.AuthorizeResult r = run(pc, input(Map.of("amount", 50L)).isRevoked(rc));
            assertFalse(r.allow);
            assertEquals("fail", r.checks.get("revocation"));
            assertTrue(r.reasons.contains("revocation: the revocation check failed (fail closed)"), r.reasons.toString());
        }
    }

    @Test void withoutAClockTheSystemClockJudges() {
        Map<String, Object> live = Agent.create(AGENT, AUD, GRANT, null).clock(System::currentTimeMillis)
            .act("payments.send", "payments/acme", Issue.obj("amount", 50L));
        Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO).operation(Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L)))
            .audience(AUD).resolveGrant(ref -> GRANT).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false)
            .plan(Authorize.SINGLE_STEP).provenanceGate(ProvHarness.options());
        Authorize.AuthorizeResult r = run(live, in);
        assertTrue(r.allow, r.reasons.toString());
    }
}
