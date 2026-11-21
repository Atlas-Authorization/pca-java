package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * The undo-window coordinator: admission, the durable record, the one-click veto, the compensation at most once, finalization, the veto relay
 * and every fail-closed refusal. Hand-written scripted flows (the pure ledger replays the reference in the Undo corpus tests).
 */
public class UndoCoordinatorTest {
    static final Keys.SuiteKey P = Keys.ed25519(Keys.edFromSeed(ProducerTest.fill(1, 32)));
    static final Keys.EdKey H = Keys.edFromSeed(ProducerTest.fill(2, 32));
    static final String D43 = "A".repeat(43);

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> grant() {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "pay", "resource", "invoice:*"));
        preds.add(Issue.obj("verb", "pay.refund", "resource", "invoice:*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        return Issue.mintGrant(P, H.id(), null, env, "pay invoices", "s").grant;
    }

    static final Map<String, Object> GRANT = grant();

    static Map<String, Object> op() { return Issue.obj("verb", "pay", "resource", "invoice:1", "params", Issue.obj("amount", new Json.Num("5"))); }

    static Map<String, Object> plan(String verb, String target) {
        Map<String, Object> comp = Issue.obj("verb", verb, "params", new LinkedHashMap<String, Object>(), "def_digest", D43);
        if (target != null) comp.put("target_param", target);
        return Issue.obj("def_digest", D43, "compensation", comp);
    }

    static Map<String, Object> action(String cls) {
        Map<String, Object> a = m(IntentJs.normalize(Agent.create(Keys.ed25519(H), "rs", GRANT, null).clock(() -> 1_000L).act("pay", "invoice:1", Issue.obj("amount", new Json.Num("5")))));
        if (cls != null) m(a.get("action")).put("reversibility_class", cls);
        return a;
    }

    static final class Ctx {
        final long[] clock = {1_000};
        final List<Map<String, Object>> notices = new ArrayList<>();
        final List<UndoCoordinator.CompensationCall> calls = new ArrayList<>();
        final List<UndoCoordinator.Alert> alerts = new ArrayList<>();
        boolean deliver = true;
        UndoCoordinator coord;
    }

    static Ctx build(Consumer<UndoCoordinator.Options> tweak) {
        Ctx c = new Ctx();
        UndoCoordinator.Options o = new UndoCoordinator.Options();
        o.store = new MemoryUndoStore();
        o.engine = (op, id) -> plan("pay.refund", "payment");
        o.signerSecret = ProducerTest.fill(9, 32);
        o.audience = "rs";
        o.resolveGrant = (ref, pc) -> GRANT;
        o.compensate = call -> { c.calls.add(call); return Issue.obj("refund", "r1"); };
        o.operations = new MemoryOperationStore();
        o.notifier = n -> { c.notices.add(n); return c.deliver ? new UndoCoordinator.Notice(true, null) : new UndoCoordinator.Notice(false, "no channel"); };
        o.alert = c.alerts::add;
        o.now = () -> c.clock[0];
        o.insecureVolatileStore = true;
        if (tweak != null) tweak.accept(o);
        c.coord = UndoCoordinator.createUndoCoordinator(o);
        return c;
    }

    @Test void vetoWithTheTokenCompensatesOnce() {
        Ctx c = build(null);
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        assertFalse(adm.containsKey("refused"), String.valueOf(adm.get("refused")));
        String id = (String) adm.get("id");
        Map<String, Object> info = c.coord.open(adm);
        assertEquals("undo_window", m(info.get("obligation")).get("kind"));
        assertEquals("open", c.coord.get(id).get("state"));
        c.coord.recordEffect(id, Issue.obj("id", "pay_1"), true);
        c.clock[0] = 2_000;
        UndoCoordinator.VetoResult v = c.coord.vetoWithToken(id, info.get("token"), null);
        assertTrue(v.ok, v.reason);
        assertEquals("compensated", v.record.get("state"));
        assertFalse(v.replayed);
        assertEquals(1, c.calls.size());
        assertEquals("{\"payment\":\"pay_1\"}", Json.canonicalize(c.calls.get(0).operation.get("params")));
        UndoCoordinator.VetoResult again = c.coord.vetoWithToken(id, info.get("token"), null); // the same veto is a replay: the compensation never runs twice
        assertTrue(again.ok && again.replayed);
        assertEquals(1, c.calls.size());
        assertTrue(c.alerts.isEmpty());
        // the principal heard about it: opened, vetoed, compensated
        List<Object> kinds = new ArrayList<>();
        for (Map<String, Object> n : c.notices) kinds.add(n.get("kind"));
        assertEquals(Arrays.asList("opened", "vetoed", "compensated"), kinds);
    }

    @Test void aTokenAfterTheWindowOrOfAnotherShapeIsRefused() {
        Ctx c = build(null);
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        Map<String, Object> info = c.coord.open(adm);
        assertFalse(c.coord.vetoWithToken((String) adm.get("id"), "not a token", null).ok);
        c.clock[0] = IntentJs.lng(adm.get("window_end")) + 1;
        assertFalse(c.coord.vetoWithToken((String) adm.get("id"), info.get("token"), null).ok);
        assertTrue(c.calls.isEmpty());
    }

    @Test void finalizeClosesTheWindowAndAlertsAnUnreportedEffect() {
        Ctx c = build(null);
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        assertTrue(c.coord.finalizeDue().isEmpty()); // the window is still open
        c.clock[0] = IntentJs.lng(adm.get("window_end")) + 5;
        assertEquals(Arrays.asList(adm.get("id")), c.coord.finalizeDue());
        assertEquals("finalized", c.coord.get((String) adm.get("id")).get("state"));
        assertEquals(1, c.alerts.size());
        assertEquals("effect_unknown", c.alerts.get(0).code);
        assertTrue(c.calls.isEmpty());
    }

    @Test void aWindowNobodyWasToldAboutIsAborted() {
        Ctx c = build(null);
        c.deliver = false;
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        assertThrows(Undo.UndoError.class, () -> c.coord.open(adm));
        assertEquals("finalized", c.coord.get((String) adm.get("id")).get("state"));
        assertEquals("notify_failed", c.alerts.get(0).code);
        assertEquals("critical", c.alerts.get(0).level);
    }

    @Test void admissionRefusesWhatIsNotConfirmedReversible() {
        Ctx c = build(null);
        assertTrue(((String) c.coord.admit(action("irreversible"), op(), false, GRANT).get("refused")).startsWith("the signed class is irreversible"));
        Ctx none = build(o -> o.engine = (op, id) -> null);
        assertTrue(((String) none.coord.admit(action(null), op(), false, GRANT).get("refused")).contains("not confirmed reversible"));
        Ctx off = build(o -> o.policy = (op, g) -> { UndoCoordinator.Policy p = new UndoCoordinator.Policy(); p.mode = "off"; return p; });
        assertEquals("policy: undo windows are off", off.coord.admit(action(null), op(), false, GRANT).get("refused"));
        Ctx esc = build(o -> o.policy = (op, g) -> { UndoCoordinator.Policy p = new UndoCoordinator.Policy(); p.mode = "escalations"; return p; });
        assertTrue(((String) esc.coord.admit(action(null), op(), false, GRANT).get("refused")).contains("windows only replace approvals"));
        assertFalse(esc.coord.admit(action(null), op(), true, GRANT).containsKey("refused"));
    }

    @Test void aCompensationTheGrantDoesNotAllowIsRefused() {
        Ctx c = build(o -> o.engine = (op, id) -> plan("admin.delete", null));
        assertTrue(((String) c.coord.admit(action(null), op(), false, GRANT).get("refused")).contains("not authorized under the grant"));
    }

    @Test void aVolatileStoreAndMissingComponentsFailClosed() {
        UndoCoordinator.Options o = new UndoCoordinator.Options();
        o.store = new MemoryUndoStore();
        o.engine = (op, id) -> null;
        o.signerSecret = ProducerTest.fill(9, 32);
        o.audience = "rs";
        o.resolveGrant = (r, p) -> GRANT;
        o.compensate = call -> null;
        o.operations = new MemoryOperationStore();
        o.notifier = n -> new UndoCoordinator.Notice(true, null);
        o.alert = a -> { };
        assertEquals("not_durable", assertThrows(Undo.UndoError.class, () -> UndoCoordinator.createUndoCoordinator(o)).code);
        o.audience = "";
        assertEquals("config", assertThrows(Undo.UndoError.class, () -> UndoCoordinator.createUndoCoordinator(o)).code);
        assertEquals(Arrays.asList("audience"), UndoCoordinator.missingUndoComponents(o));
        assertEquals(9, UndoCoordinator.missingUndoComponents(null).size());
    }

    @Test void theKvStoreAndEffectReporting() {
        Ctx c = build(o -> o.store = new KvUndoStore(new MemoryAtomicKv(), false));
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        Map<String, Object> info = c.coord.open(adm);
        String id = (String) adm.get("id");
        assertEquals(0L, IntentJs.lng(c.coord.get(id).get("ver")));
        Map<String, Object> rec = UndoCoordinator.reportUndoEffect(c.coord, id, Issue.obj("status", "committed", "result", Issue.obj("id", "p9")));
        assertEquals("{\"id\":\"p9\"}", Json.canonicalize(m(rec.get("effect")).get("result")));
        UndoCoordinator.VetoResult v = c.coord.vetoAsOperator(id, "ops");
        assertEquals("compensated", v.record.get("state"));
        assertEquals("{\"payment\":\"p9\"}", Json.canonicalize(c.calls.get(0).operation.get("params")));
        assertEquals(id, info.get("id"));
    }

    @Test void aFailedOrNeverStartedEffectAbortsTheWindow() {
        Ctx c = build(null);
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        Map<String, Object> rec = UndoCoordinator.reportUndoEffect(c.coord, (String) adm.get("id"), Issue.obj("status", "failed"));
        assertEquals("finalized", rec.get("state"));
        assertEquals("aborted", m(rec.get("outcome")).get("status"));
        assertTrue(c.calls.isEmpty());
    }

    @Test void aFailingCompensatorLeavesCompensationFailedAndAnAlert() {
        Ctx c = build(o -> o.compensate = call -> { throw new IllegalStateException("downstream down"); });
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        String id = (String) adm.get("id");
        c.coord.recordEffect(id, Issue.obj("id", "pay_3"), true);
        UndoCoordinator.VetoResult v = c.coord.vetoAsOperator(id, "ops");
        assertTrue(v.ok);
        assertEquals("compensation_failed", v.record.get("state"));
        assertEquals("compensation_failed", c.alerts.get(0).code);
        assertTrue(c.alerts.get(0).reason.contains("downstream down"));
    }

    @Test void aRelayedVetoLandsEvenAfterTheWindowClosed() {
        List<UndoCoordinator.RelayedVeto> pending = new ArrayList<>();
        Ctx c = build(o -> o.relay = () -> new ArrayList<>(pending));
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        Map<String, Object> info = c.coord.open(adm);
        String id = (String) adm.get("id");
        c.coord.recordEffect(id, Issue.obj("id", "pay_2"), true);
        pending.add(new UndoCoordinator.RelayedVeto(id, info.get("token"), new Json.Num("1500")));
        c.clock[0] = IntentJs.lng(adm.get("window_end")) + 5;
        assertTrue(c.coord.finalizeDue().isEmpty()); // the veto is applied (as of 1500), nothing is finalized
        assertEquals("compensated", c.coord.get(id).get("state"));
        assertEquals(1, c.calls.size());
    }

    @Test void anUnreadableRelayFinalizesNothing() {
        Ctx c = build(o -> o.relay = () -> { throw new IllegalStateException("relay down"); });
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        c.clock[0] = IntentJs.lng(adm.get("window_end")) + UndoCoordinator.UNDO_RELAY_GRACE_MS + 5;
        assertTrue(c.coord.finalizeDue().isEmpty());
        assertEquals("open", c.coord.get((String) adm.get("id")).get("state"));
        assertEquals("veto_relay_failed", c.alerts.get(0).code);
    }

    @Test void hostedRelayReadsTheVetoListAndRefusesAMalformedAnswer() {
        List<String> seen = new ArrayList<>();
        UndoCoordinator.Relay ok = UndoCoordinator.hostedUndoVetoRelay("https://h.example//", "sk", (url, headers) -> {
            seen.add(url + " " + headers.get("authorization"));
            return new UndoCoordinator.RelayResponse(true, 200, Json.parseLenient("{\"data\":[{\"record_id\":\"r1\",\"veto\":{\"token\":\"t\",\"at\":1500}}]}"));
        }, 500);
        List<UndoCoordinator.RelayedVeto> got = ok.pending();
        assertEquals("https://h.example/v1/pca/undo/vetoes?limit=200 Bearer sk", seen.get(0));
        assertEquals("r1", got.get(0).id);
        UndoCoordinator.Relay bad = UndoCoordinator.hostedUndoVetoRelay("https://h.example", "sk", (url, headers) -> new UndoCoordinator.RelayResponse(true, 200, Json.parseLenient("{\"data\":[{\"record_id\":\"r1\"}]}")), null);
        assertThrows(Undo.UndoError.class, bad::pending);
        UndoCoordinator.Relay down = UndoCoordinator.hostedUndoVetoRelay("https://h.example", "sk", (url, headers) -> new UndoCoordinator.RelayResponse(false, 503, null), null);
        assertTrue(assertThrows(Undo.UndoError.class, down::pending).getMessage().contains("503"));
    }

    @Test void revocationVetoesOpenWindowsWhenThePolicySaysSo() {
        Ctx c = build(o -> o.policy = (op, g) -> { UndoCoordinator.Policy p = new UndoCoordinator.Policy(); p.onRevocation = "veto"; return p; });
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        String id = (String) adm.get("id");
        c.coord.recordEffect(id, Issue.obj("id", "pay_4"), true);
        assertEquals(Arrays.asList(id), c.coord.onRevocation((String) m(adm.get("pcactn")).get("grant_ref")));
        assertEquals("compensated", c.coord.get(id).get("state"));
    }

    @Test void theNotifierOverTheDispatcherDeliversThroughAnEnabledChannel() {
        Ctx c = build(null);
        Map<String, Object> adm = c.coord.admit(action(null), op(), false, GRANT);
        c.coord.open(adm);
        List<String> sent = new ArrayList<>();
        ApprovalChannels.Dispatcher d = ApprovalChannels.createApprovalDispatcher(List.of(ApprovalChannels.textApprovalChannel("email", (subject, text) -> { sent.add(text); return "m1"; })));
        UndoCoordinator.Notifier n = UndoCoordinator.undoNotifierFromDispatcher(d, (token, id) -> "https://u.example/undo/" + id + "?t=" + token, null);
        assertTrue(n.notify(c.notices.get(0)).delivered);
        assertTrue(sent.get(0).contains("https://u.example/undo/"));
        UndoCoordinator.Notice none = UndoCoordinator.undoNotifierFromDispatcher(ApprovalChannels.createApprovalDispatcher(new ArrayList<>()), (t, i) -> "x", null).notify(c.notices.get(0));
        assertFalse(none.delivered);
        assertEquals("no enabled channel", none.reason);
    }

    @Test void theSignerPublicIsTheServiceKey() {
        Ctx c = build(null);
        assertEquals(UndoCoordinator.undoSignerPublic(ProducerTest.fill(9, 32)), c.coord.signerPublic);
    }
}
