package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;

/**
 * Provenance by default through {@code authorize} (check {@code provenance_flow}: on by default, the grant envelope's signed
 * opt-out, request reading, fail-closed resolution) and the undo admission hook (it lifts only an unanswered, non-provenance
 * escalation, and an exception admits nothing).
 */
public class ProvenanceFlowTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final long END = 1_800_000_900_000L;

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    static Map<String, Object> pcactn() { return AuthorizeFixtures.pcactn(C, 0); }
    static Authorize.Operation op() { return AuthorizeFixtures.operation(C, 0); }

    /** The fixture input with the gate unconfigured: no pins, no bundle. */
    static Authorize.Input bare() { return AuthorizeFixtures.input(C, 0).provenanceGate(null); }

    static ArgProvenance.Options pinned() { return new ArgProvenance.Options().mediators(List.of(ProvHarness.PIN)); }

    static String b64json(Object o) { return Pca.b64(Json.canonicalizeStrict(o).getBytes(StandardCharsets.UTF_8)); }

    static boolean hasReason(Authorize.AuthorizeResult r, String prefix) {
        for (String x : r.reasons) if (x.startsWith(prefix)) return true;
        return false;
    }

    // ---- the gate -------------------------------------------------------------------------------------------------------

    @Test void onByDefaultASensitiveActionWithoutABundleEscalates() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), bare());
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
        assertEquals("fail", r.checks.get("provenance_flow"));
        assertTrue(hasReason(r, "provenance_flow: escalate: "), r.reasons.toString());
        assertTrue(r.escalation != null && ((List<?>) r.escalation.get("reasons")).stream().anyMatch(x -> ((String) x).startsWith("provenance_flow: escalate: ")));
    }

    @Test void aPrincipalDirectBundleUnderAPinnedMediatorPasses() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("provenance_flow"));
        assertFalse(r.checks.containsKey("undo_window"));
        assertNull(r.undo);
        assertEquals(List.of(), r.obligations);
    }

    @Test void anExplicitBundleWinsAndAForgedOneDenies() {
        Authorize.AuthorizeResult ok = Authorize.authorize(pcactn(), bare().provenanceGate(pinned())
            .provenance(ArgProvenance.Presented.bundle(ProvHarness.bundle(op()))));
        assertTrue(ok.allow, ok.reasons.toString());
        // an explicit "none" wins over the gate's bundle function
        Authorize.AuthorizeResult none = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).provenance(ArgProvenance.Presented.bundle(null)));
        assertEquals("escalate", none.decision);
        // the agent signs its own chain under the pinned mediator name
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 2);
        ArgProvenance.Recorder forger = new ArgProvenance.Recorder("conformance-harness", "k1", Keys.ed25519(Keys.edFromSeed(seed)), null, null);
        Authorize.AuthorizeResult forged = Authorize.authorize(pcactn(), bare().provenanceGate(pinned())
            .provenance(ArgProvenance.Presented.bundle(ArgProvenance.principalDirect(forger, op()))));
        assertFalse(forged.allow);
        assertEquals("deny", forged.decision);
        assertTrue(hasReason(forged, "provenance_flow: bad_signature: "), forged.reasons.toString());
        assertNull(forged.escalation);
    }

    @Test void theRequestHeaderThenTheBodyMemberIsRead() {
        Map<String, Object> bundle = ProvHarness.bundle(op());
        Authorize.AuthorizeResult h = Authorize.authorize(pcactn(), bare().provenanceGate(pinned())
            .provenance(ArgProvenance.Presented.request(b64json(bundle), null)));
        assertTrue(h.allow, h.reasons.toString());
        byte[] body = Json.canonicalizeStrict(Map.of("amount", 50L, "pca_provenance", bundle)).getBytes(StandardCharsets.UTF_8);
        Authorize.AuthorizeResult b = Authorize.authorize(pcactn(), bare().provenanceGate(pinned()).provenance(ArgProvenance.Presented.request(null, body)));
        assertTrue(b.allow, b.reasons.toString());
        Authorize.AuthorizeResult bad = Authorize.authorize(pcactn(), bare().provenanceGate(pinned()).provenance(ArgProvenance.Presented.request("!!", body)));
        assertFalse(bad.allow);
        assertEquals("deny", bad.decision);
        assertTrue(bad.reasons.contains("provenance_flow: the provenance bundle is unreadable (fail closed)"), bad.reasons.toString());
    }

    @Test void aResolverThatThrowsFailsClosed() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0)
            .provenanceGate(ProvHarness.options().actions(o -> { throw new IllegalStateException("down"); })));
        assertFalse(r.allow);
        assertEquals("deny", r.decision);
        assertTrue(r.reasons.contains("provenance_flow: the action facts or observations could not be resolved (fail closed)"), r.reasons.toString());
        Authorize.AuthorizeResult b = Authorize.authorize(pcactn(), bare()
            .provenanceGate(pinned().bundle((p, o) -> { throw new IllegalStateException("down"); })));
        assertEquals("deny", b.decision);
        assertTrue(b.reasons.contains("provenance_flow: the provenance bundle is unreadable (fail closed)"), b.reasons.toString());
    }

    @Test void declaredActionFactsLowerWhatIsNeeded() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), bare()
            .provenanceGate(new ArgProvenance.Options().actions(o -> Map.of("effects", List.of("read")))));
        assertEquals("pass", r.checks.get("provenance_flow"), r.reasons.toString());
        Authorize.AuthorizeResult s = Authorize.authorize(pcactn(), bare()
            .provenanceGate(new ArgProvenance.Options().actions(o -> Map.of("effects", List.of("spend")))));
        assertEquals("fail", s.checks.get("provenance_flow"));
        Authorize.AuthorizeResult bad = Authorize.authorize(pcactn(), bare()
            .provenanceGate(new ArgProvenance.Options().actions(o -> Map.of("effects", "read"))));
        assertEquals("deny", bad.decision);
        assertTrue(hasReason(bad, "provenance_flow: malformed_action: "), bad.reasons.toString());
    }

    @Test void anObservedUntrustedSourceEscalates() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0)
            .provenanceGate(ProvHarness.options().observed((p, o, session) -> List.of(Map.of("origin", "web", "source", "https://evil.example")))));
        assertEquals("escalate", r.decision, r.reasons.toString());
        assertTrue(hasReason(r, "provenance_flow: escalate: "), r.reasons.toString());
    }

    // ---- the grant envelope -------------------------------------------------------------------------------------------

    static final String AUD = "payments-rs";
    static final long NOW = 1_800_000_000_000L;

    static Keys.SuiteKey key(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return Keys.ed25519(Keys.edFromSeed(x));
    }

    /** A grant whose signed envelope carries {@code provenance} (null: none), and a PCActn for {@code payments.send}. */
    static Object[] minted(Object provenance) {
        Keys.SuiteKey principal = key(10), me = key(11);
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        if (provenance != null) env.put("provenance", provenance);
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, env, "pay invoices", Pca.b64(new byte[16]));
        Map<String, Object> a = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).act("payments.send", "payments/acme", Issue.obj("amount", 50L));
        return new Object[] {g.grant, a};
    }

    @SuppressWarnings("unchecked")
    static Authorize.AuthorizeResult run(Object[] m, ArgProvenance.Presented bundle) {
        Map<String, Object> grant = (Map<String, Object>) m[0];
        Authorize.Input in = new Authorize.Input().operation(Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L)))
            .audience(AUD).resolveGrant(ref -> grant).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false).now(NOW)
            .plan(Authorize.SINGLE_STEP).provenance(bundle);
        return Authorize.authorize(m[1], in);
    }

    @Test void theEnvelopesSignedOptOutIsTheOnlyWayOff() {
        Authorize.AuthorizeResult off = run(minted(Issue.obj("mode", "insecure_off")), null);
        assertEquals("not-enforced", off.checks.get("provenance_flow"), off.reasons.toString());
        assertFalse(hasReason(off, "provenance_flow"), off.reasons.toString());
        Authorize.AuthorizeResult on = run(minted(null), null);
        assertEquals("fail", on.checks.get("provenance_flow"));
        Authorize.AuthorizeResult enforce = run(minted(Issue.obj("mode", "enforce")), null);
        assertEquals("fail", enforce.checks.get("provenance_flow"));
    }

    @Test void aMalformedEnvelopeMemberDenies() {
        Authorize.AuthorizeResult r = run(minted(Issue.obj("mode", "off")), null);
        assertEquals("fail", r.checks.get("provenance_flow"));
        assertEquals("deny", r.decision);
        assertTrue(r.reasons.contains("provenance_flow: the grant's provenance member is malformed: provenance.mode must be 'enforce' or 'insecure_off'"),
            r.reasons.toString());
    }

    @Test void theEnvelopeCanNameTheMediator() {
        ArgProvenance.Recorder rec = ArgProvenance.Recorder.create("assistant", "k1");
        Map<String, Object> bundle = ArgProvenance.principalDirect(rec, Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L)));
        List<Object> pins = new ArrayList<>();
        pins.add(new LinkedHashMap<>(rec.pin()));
        Authorize.AuthorizeResult named = run(minted(Issue.obj("mediators", pins)), ArgProvenance.Presented.bundle(bundle));
        assertEquals("pass", named.checks.get("provenance_flow"), named.reasons.toString());
        Authorize.AuthorizeResult unnamed = run(minted(null), ArgProvenance.Presented.bundle(bundle));
        assertEquals("fail", unnamed.checks.get("provenance_flow"), "an unpinned mediator earns no trust");
    }

    // ---- the carriers ---------------------------------------------------------------------------------------------------

    static MockHttpServletResponse post(PcaFilter f, String provenanceHeader, String body, AtomicInteger chain) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", b64json(pcactn()));
        if (provenanceHeader != null) req.addHeader("PCA-Provenance", provenanceHeader);
        req.setContent(body.getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(req, resp, (a, b) -> chain.incrementAndGet());
        return resp;
    }

    @Test void theFilterReadsTheHeaderAndTheBody() throws Exception {
        Clock clock = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);
        Map<String, Object> grant = AuthorizeFixtures.grant(C);
        java.util.function.Supplier<PcaFilter> filter = () -> new PcaFilter(AuthorizeFixtures.audience(), ref -> grant, clock,
            new Authorize.Options(new MemoryStateStore(), (p, g) -> false).withProvenance(pinned()), (req, body) -> op());
        AtomicInteger chain = new AtomicInteger();
        MockHttpServletResponse none = post(filter.get(), null, "{\"amount\":50}", chain);
        assertEquals(403, none.getStatus());
        assertTrue(none.getContentAsString().contains("\"decision\":\"escalate\""), none.getContentAsString());
        String bundle = b64json(ProvHarness.bundle(op()));
        assertEquals(200, post(filter.get(), bundle, "{\"amount\":50}", chain).getStatus());
        String body = Json.canonicalizeStrict(Map.of("amount", 50L, "pca_provenance", ProvHarness.bundle(op())));
        assertEquals(200, post(filter.get(), null, body, chain).getStatus());
        assertEquals(403, post(filter.get(), bundle + "=", "{\"amount\":50}", chain).getStatus(), "a header that does not decode refuses");
        assertEquals(2, chain.get());
        assertEquals(net.atlasauth.pca.servlet.PcaCore.PROVENANCE_HEADER, ArgProvenance.HEADER);
    }

    // ---- undo windows ---------------------------------------------------------------------------------------------------

    /** Make the core verdict fail {@code check} with {@code reason} (escalate-class when it carries {@code intent_required:}). */
    static void failCore(String check, String reason) {
        Authorize.coreHook = core -> {
            core.checks.put(check, false);
            core.allow = false;
            core.reason = reason;
        };
    }

    static Map<String, Object> admission() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "op_1");
        a.put("window_end", END);
        a.put("compensation", Map.of("verb", "payments.refund", "resource", "payments/acme"));
        return a;
    }

    static Undo.Admit admitting(AtomicInteger calls) {
        return (p, g, o) -> {
            calls.incrementAndGet();
            assertEquals("payments.send", o.verb);
            return admission();
        };
    }

    @Test void a_anUnansweredEscalationIsAdmittedUnderAVetoWindow() {
        failCore("intent", "intent: intent_required: a question is required");
        AtomicInteger calls = new AtomicInteger();
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo(admitting(calls)));
        assertEquals(1, calls.get());
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("allow", r.decision);
        assertEquals(200, r.status);
        assertEquals("pass", r.checks.get("intent"));
        assertEquals("pass", r.checks.get("undo_window"));
        assertFalse(r.checks.containsValue("fail"));
        assertTrue(r.reasons.contains("undo_window: runs now under a veto window until " + END + " (compensation payments.refund)"), r.reasons.toString());
        assertNull(r.escalation);
        assertTrue(IntentJs.jsonEquals(admission(), r.undo));
        assertEquals(1, r.obligations.size());
        assertTrue(IntentJs.jsonEquals(Map.of("kind", "undo_window", "params", Map.of("id", "op_1", "window_end", END), "due", END), r.obligations.get(0)));
        // the same through the options (the filter, the interceptor and the executor run these)
        Authorize.AuthorizeResult o = new Authorize.Options(new MemoryStateStore(), (p, g) -> false).withProvenance(ProvHarness.options())
            .withUndo(admitting(calls)).run(pcactn(), op(), AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), AuthorizeFixtures.now(), null);
        assertTrue(o.allow, o.reasons.toString());
        assertEquals("pass", o.checks.get("undo_window"));
    }

    @Test void b_aProvenanceFlowEscalationIsNeverAdmitted() {
        AtomicInteger calls = new AtomicInteger();
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), bare().undo(admitting(calls)));
        assertEquals(0, calls.get());
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
        assertFalse(r.checks.containsKey("undo_window"));
        assertNull(r.undo);
    }

    @Test void c_anIntentRule17ProvenanceFailureIsNeverAdmitted() {
        failCore("provenance", "provenance: intent_required: a question is required");
        AtomicInteger calls = new AtomicInteger();
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo(admitting(calls)));
        assertEquals(0, calls.get());
        assertEquals("escalate", r.decision);
        assertEquals("pass", r.checks.get("provenance_flow"));
    }

    @Test void d_anAnswerPresentedIsNotOfferedToTheHook() {
        failCore("intent", "intent: intent_required: a question is required");
        AtomicInteger calls = new AtomicInteger();
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).escalationAnswer(Map.of("kind", "x")).undo(admitting(calls)));
        assertEquals(0, calls.get());
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
    }

    @Test void e_aHookThatThrowsOrAdmitsMalformedLeavesTheEscalation() {
        failCore("intent", "intent: intent_required: a question is required");
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo((p, g, o) -> { throw new IllegalStateException("ledger down"); }));
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
        assertFalse(r.checks.containsKey("undo_window"));
        Map<String, Object> bad = admission();
        bad.put("id", "i".repeat(129));
        Authorize.AuthorizeResult m = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo((p, g, o) -> bad));
        assertEquals("escalate", m.decision);
        Authorize.AuthorizeResult n = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo((p, g, o) -> null));
        assertEquals("escalate", n.decision);
        assertNull(n.undo);
    }

    @Test void f_aDenyIsNeverOfferedToTheHook() {
        failCore("intent", "intent: the goal does not open the commitment");
        AtomicInteger calls = new AtomicInteger();
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), AuthorizeFixtures.input(C, 0).undo(admitting(calls)));
        assertEquals(0, calls.get());
        assertEquals("deny", r.decision);
        assertFalse(r.allow);
    }
}
