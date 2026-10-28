package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * The K3 {@code fresh_at} policy reaches the core verifier through {@link Authorize} and {@link PcaCore} (the servlet filter and the
 * Spring interceptor call PcaCore with the same arguments), including the side-carried {@code pca-fresh-at} header.
 */
public class FreshAtForwardTest {
    static final Map<String, Object> DOC = Track3Vectors.load("fresh-at-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> vec(String name) {
        for (Object x : (List<Object>) DOC.get("vectors")) if (name.equals(((Map<String, Object>) x).get("name"))) return (Map<String, Object>) x;
        throw new AssertionError("no vector " + name);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> ctx(Map<String, Object> v) { return (Map<String, Object>) v.get("context"); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> grant(Map<String, Object> v) { return (Map<String, Object>) v.get("grant"); }

    /** The vector's policy with no side-carried token (it travels as a header in these tests). */
    static K3.FreshAtPolicy policy(Map<String, Object> v) {
        K3.FreshAtPolicy p = K3.FreshAtPolicy.fromJson(ctx(v).get("fresh_at"));
        return p == null ? null : new K3.FreshAtPolicy(p.signer, p.scope, p.local, p.maxTokenAgeMs, p.require, false, null);
    }

    @SuppressWarnings("unchecked")
    static String sideHeader(Map<String, Object> v) {
        return Json.canonicalize(((Map<String, Object>) ctx(v).get("fresh_at")).get("side_carried"));
    }

    static String actionHeader(Map<String, Object> v) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalize(v.get("pcactn")).getBytes(StandardCharsets.UTF_8));
    }

    static PcaResult core(Map<String, Object> v, K3.FreshAtPolicy policy, String freshAtHeader) {
        return PcaCore.authorizeSignatureOnly(actionHeader(v), null, (String) ctx(v).get("aud"), Json.asLong(ctx(v).get("now")),
            ref -> grant(v), policy, freshAtHeader);
    }

    static Authorize.AuthorizeResult authorize(Map<String, Object> v, K3.FreshAtPolicy policy) {
        return Authorize.authorize(v.get("pcactn"), new Authorize.Input().operation(Authorize.Operation.of("x", "y", Map.of()))
            .audience((String) ctx(v).get("aud")).resolveGrant(ref -> grant(v)).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false)
            .now(Json.asLong(ctx(v).get("now"))).freshAt(policy));
    }

    @Test void authorizeForwardsThePolicy() {
        Map<String, Object> ok = vec("member-equal-state");
        assertEquals("pass", authorize(ok, policy(ok)).checks.get("fresh_at"));

        Map<String, Object> stale = vec("member-stale-revocation_epoch");
        Authorize.AuthorizeResult r = authorize(stale, policy(stale));
        assertEquals("fail", r.checks.get("fresh_at"));
        assertTrue(r.reasons.stream().anyMatch(x -> x.contains("escalate: stale_state")), r.reasons.toString());
        assertFalse(r.allow);

        // default null policy: a PCActn carrying the member is refused
        r = authorize(ok, null);
        assertEquals("fail", r.checks.get("fresh_at"));
        assertTrue(r.reasons.stream().anyMatch(x -> x.contains("no fresh_at policy")), r.reasons.toString());
    }

    @Test void pcaCoreForwardsThePolicy() {
        Map<String, Object> ok = vec("member-equal-state");
        PcaResult r = core(ok, policy(ok), null);
        assertTrue(r.allowed(), r.detail());
        assertEquals(Boolean.TRUE, r.verdict().checks.get("fresh_at"));

        Map<String, Object> stale = vec("member-stale-revocation_epoch");
        r = core(stale, policy(stale), null);
        assertFalse(r.allowed());
        assertTrue(r.verdict().reason.startsWith("fresh_at: escalate: stale_state"), r.verdict().reason);

        r = core(ok, null, null);
        assertFalse(r.allowed());
        assertTrue(r.verdict().reason.startsWith("fresh_at:"), r.verdict().reason);
    }

    @Test void sideCarriedHeader() {
        Map<String, Object> ok = vec("side-carried-ok");
        assertTrue(core(ok, policy(ok), sideHeader(ok)).allowed());
        assertFalse(core(ok, policy(ok), null).verdict().checks.containsKey("fresh_at"));

        Map<String, Object> stale = vec("side-carried-stale");
        PcaResult r = core(stale, policy(stale), sideHeader(stale));
        assertFalse(r.allowed());
        assertTrue(r.verdict().reason.contains("escalate: stale_state"), r.verdict().reason);

        // an unparseable header is a bad token (denied, not an escalation), never a missing one
        r = core(ok, policy(ok), "{not json");
        assertFalse(r.allowed());
        assertEquals(Boolean.FALSE, r.verdict().checks.get("fresh_at"));
        assertFalse(r.verdict().reason.contains("escalate"), r.verdict().reason);

        // the member wins: the header is ignored when the PCActn carries fresh_at
        Map<String, Object> wins = vec("member-wins-over-side-carried");
        assertTrue(core(wins, policy(wins), "{not json").allowed());
    }
}
