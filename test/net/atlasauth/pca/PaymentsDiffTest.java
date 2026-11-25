package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.payments.ChargeBudgetStore;
import net.atlasauth.pca.payments.ChargeStoreError;
import net.atlasauth.pca.payments.MandateGrantError;
import net.atlasauth.pca.payments.MemoryChargeBudgetStore;
import net.atlasauth.pca.payments.NetworkToken;
import net.atlasauth.pca.payments.Payments;
import net.atlasauth.pca.payments.Rails;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the payments package through the native port, plus plain tests of the stateful parts. */
public class PaymentsDiffTest {
    private static final String M = "ref-payments";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** A dereference the reference performs (a null here is a TypeError there). */
    private static Map<String, Object> req(Object o) {
        if (o == null) throw new NullPointerException();
        return m(o);
    }

    private static double n(Object o) { return OracleCases.num(o); }

    private static String s(Object o) { return o instanceof String ? (String) o : null; }

    @Test void isPlainId() throws Exception { OracleCases.each(M, "isPlainId", a -> Payments.isPlainId(a.get(0))); }
    @Test void isMinorUnits() throws Exception { OracleCases.each(M, "isMinorUnits", a -> Payments.isMinorUnits(a.get(0))); }
    @Test void mandatePredicates() throws Exception { OracleCases.each(M, "mandatePredicates", a -> Payments.mandatePredicates(m(a.get(0)))); }
    // a primitive or array root has no members: only the reversibility floor
    @Test void mandateCaveats() throws Exception { OracleCases.each(M, "mandateCaveats", a -> Payments.mandateCaveats(a.get(0) instanceof Map ? m(a.get(0)) : req(a.get(0) == null ? null : new LinkedHashMap<String, Object>()))); }
    @Test void mandateRiskPolicy() throws Exception { OracleCases.each(M, "mandateRiskPolicy", a -> Payments.mandateRiskPolicy(m(a.get(0)), a.get(1))); }
    @Test void autoSpendBound() throws Exception { OracleCases.each(M, "autoSpendBound", a -> Payments.autoSpendBound(m(a.get(0)))); }
    @Test void buildPaymentMandate() throws Exception { OracleCases.each(M, "buildPaymentMandate", a -> Payments.buildPaymentMandate(m(a.get(0)))); }
    @Test void chargeActionContext() throws Exception { OracleCases.each(M, "chargeActionContext", a -> Payments.chargeActionContext(m(a.get(0)), m(a.get(1)))); }
    @Test void chargeParams() throws Exception { OracleCases.each(M, "chargeParams", a -> Payments.chargeParams(m(a.get(0)), m(a.get(1)))); }
    @Test void chargePlanNode() throws Exception { OracleCases.each(M, "chargePlanNode", a -> Payments.chargePlanNode(m(a.get(0)), m(a.get(1)), (String) a.get(2))); }
    @Test void chargeToPCActn() throws Exception { OracleCases.each(M, "chargeToPCActn", a -> Payments.chargeToPCActn(m(a.get(0)), m(a.get(1)), m(a.get(2)))); }
    @Test void chargeDecideInput() throws Exception { OracleCases.each(M, "chargeDecideInput", a -> Payments.chargeDecideInput(m(a.get(0)), m(a.get(1)), n(a.get(2)), a.get(3))); }
    @Test void authorizeCharge() throws Exception { OracleCases.each(M, "authorizeCharge", a -> Payments.authorizeCharge(m(a.get(0)), m(a.get(1)), a.get(2), in -> m(a.get(3)))); }
    @Test void settleCharge() throws Exception { OracleCases.each(M, "settleCharge", a -> Payments.settleCharge(m(a.get(0)), m(a.get(1)))); }

    @Test void applyHumanCosign() throws Exception {
        OracleCases.each(M, "applyHumanCosign", a -> {
            Object full = req(a.get(2)).get("full");
            boolean f = full != null && !Boolean.FALSE.equals(full) && !"".equals(full) && !(OracleCases.num(full) != null && (OracleCases.num(full) == 0 || Double.isNaN(OracleCases.num(full))));
            return Payments.applyHumanCosign(m(a.get(0)), n(a.get(1)), f);
        });
    }

    @Test void sharedPaymentTokenLimits() throws Exception { OracleCases.each(M, "sharedPaymentTokenLimits", a -> Rails.sharedPaymentTokenLimits(m(a.get(0)), n(a.get(1)))); }
    @Test void railLimits() throws Exception { OracleCases.each(M, "railLimits", a -> Rails.railLimits(m(a.get(0)), n(a.get(1)), req(a.get(2)))); }
    @Test void categoriesFromTraits() throws Exception { OracleCases.each(M, "categoriesFromTraits", a -> Rails.categoriesFromTraits((List<?>) a.get(0))); }
    @Test void reconcileSettlement() throws Exception { OracleCases.each(M, "reconcileSettlement", a -> Rails.reconcileSettlement(m(a.get(0)), m(a.get(1)))); }

    @Test void verifyStripeSignature() throws Exception {
        OracleCases.each(M, "verifyStripeSignature", a -> a.size() < 5 || a.get(4) == null
            ? Rails.verifyStripeSignature(s(a.get(0)), s(a.get(1)), s(a.get(2)), n(a.get(3)))
            : Rails.verifyStripeSignature(s(a.get(0)), s(a.get(1)), s(a.get(2)), n(a.get(3)), n(a.get(4))));
    }

    @Test void signStripePayload() throws Exception { OracleCases.each(M, "signStripePayload", a -> Rails.signStripePayload((String) a.get(0), (String) a.get(1), (long) n(a.get(2)))); }

    @Test void stripeCardParams() throws Exception {
        OracleCases.each(M, "stripeCardParams", a -> {
            Map<String, String> names = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(a.get(1)).entrySet()) names.put(e.getKey(), (String) e.getValue());
            Map<String, String> meta = null;
            if (a.get(3) != null) {
                meta = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : m(a.get(3)).entrySet()) meta.put(e.getKey(), (String) e.getValue());
            }
            return Rails.stripeCardParams(m(a.get(0)), names, (String) a.get(2), meta);
        });
    }

    @Test void stripeAuthorizationFromEvent() throws Exception { OracleCases.each(M, "stripeAuthorizationFromEvent", a -> Rails.stripeAuthorizationFromEvent(a.get(0))); }
    @Test void stripeSettlementFromTransaction() throws Exception { OracleCases.each(M, "stripeSettlementFromTransaction", a -> Rails.stripeSettlementFromTransaction(a.get(0))); }

    @Test void stripeIssuingWebhook() throws Exception {
        OracleCases.each(M, "stripeIssuingWebhook", a -> {
            Rails.StripeWebhookOptions o = new Rails.StripeWebhookOptions();
            o.secret = (String) a.get(2);
            double now = n(a.get(3));
            o.nowSec = () -> now;
            Object approved = a.get(4);
            o.authorize = auth -> {
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("approved", approved);
                return v;
            };
            return Rails.stripeIssuingWebhook(o, (String) a.get(0), s(a.get(1)));
        });
    }

    @Test void looksLikePan() throws Exception { OracleCases.each(M, "looksLikePan", a -> NetworkToken.looksLikePan((String) a.get(0))); }
    @Test void tokenRefError() throws Exception { OracleCases.each(M, "tokenRefError", a -> NetworkToken.tokenRefError(a.get(0))); }
    @Test void bindingMessage() throws Exception { OracleCases.each(M, "bindingMessage", a -> NetworkToken.bindingMessage(m(a.get(0)))); }
    @Test void bindNetworkToken() throws Exception { OracleCases.each(M, "bindNetworkToken", a -> NetworkToken.bindNetworkToken(m(a.get(0)))); }
    @Test void verifyNetworkTokenBinding() throws Exception { OracleCases.each(M, "verifyNetworkTokenBinding", a -> NetworkToken.verifyNetworkTokenBinding(a.get(0), m(a.get(1)))); }
    @Test void controlsFromLimits() throws Exception { OracleCases.each(M, "controlsFromLimits", a -> NetworkToken.controlsFromLimits(m(a.get(0)), a.get(1))); }
    @Test void settlementMetadata() throws Exception { OracleCases.each(M, "settlementMetadata", a -> NetworkToken.settlementMetadata(m(a.get(0)), (String) a.get(1))); }
    @Test void reconcileNetworkSettlement() throws Exception { OracleCases.each(M, "reconcileNetworkSettlement", a -> NetworkToken.reconcileNetworkSettlement(m(a.get(0)), a.get(1) == null ? null : m(a.get(1)))); }
    @Test void chargeWithNetworkToken() throws Exception { OracleCases.each(M, "chargeWithNetworkToken", a -> NetworkToken.chargeWithNetworkToken(m(a.get(0)), m(a.get(1)), m(a.get(2)), m(a.get(3)))); }

    // ---- stateful parts the oracle does not cover ----------------------------------------------------------------------------

    private static Map<String, Object> mandate() {
        Map<String, Object> p = new LinkedHashMap<>();
        Map<String, Object> sec = new LinkedHashMap<>();
        byte[] seed = new byte[32];
        seed[0] = 7;
        sec.put("$bytes", Keys.b64u(seed));
        p.put("principalSecret", sec);
        p.put("principalPublic", Keys.edFromSeed(seed).id());
        byte[] aseed = new byte[32];
        aseed[0] = 9;
        p.put("agentPublic", Keys.edFromSeed(aseed).id());
        p.put("merchants", new ArrayList<Object>(List.of("m1")));
        p.put("currency", "USD");
        p.put("perTransactionCap", new Json.Num("500"));
        p.put("autoApproveThreshold", new Json.Num("200"));
        p.put("cumulativeCap", new Json.Num("1000"));
        p.put("goalSalt", "c2FsdA");
        p.put("now", new Json.Num("1800000000000"));
        return Payments.buildPaymentMandate(p);
    }

    private static Map<String, Object> decision(boolean admit, boolean release, Object budget) {
        Map<String, Object> rt = new LinkedHashMap<>();
        rt.put("t", new Json.Num("1"));
        rt.put("proof", "claim");
        rt.put("optimisticAllowed", true);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("releaseGuardianShare", release);
        d.put("requiredThreshold", rt);
        d.put("r", new Json.Num("0.1"));
        d.put("admit", admit);
        d.put("needStepUp", !admit);
        d.put("reasons", new ArrayList<Object>());
        d.put("budget", budget);
        return d;
    }

    private static Map<String, Object> charge(long amount) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("merchant", "m1");
        c.put("amount", new Json.Num(Long.toString(amount)));
        c.put("currency", "USD");
        c.put("now", new Json.Num("1800000001000"));
        return c;
    }

    @Test void atomicChargeDebitsTheDurableBudgetOnce() {
        Map<String, Object> mand = mandate();
        MemoryChargeBudgetStore store = new MemoryChargeBudgetStore();
        Payments.Decider decider = in -> decision(true, true, in.get("budget"));
        Map<String, Object> d1 = Payments.authorizeChargeAtomic(mand, charge(50), mand.get("grant"), store, null, decider);
        assertEquals("auto", d1.get("outcome"));
        Map<String, Object> d2 = Payments.authorizeChargeAtomic(mand, charge(50), mand.get("grant"), store, null, decider);
        assertEquals("auto", d2.get("outcome"));
        // the second decision started from the stored (debited) budget, not the mandate's initial one
        assertEquals(950.0, n(((Map<?, ?>) d2.get("budgetBefore")).get("B")));
        assertEquals(900.0, n(((Map<?, ?>) d2.get("budgetAfter")).get("B")));
    }

    @Test void atomicChargeConflictDenies() {
        Map<String, Object> mand = mandate();
        ChargeBudgetStore losing = new ChargeBudgetStore() {
            @Override public Record get(String key) { return null; }
            @Override public boolean compareAndSet(String key, Object expected, Map<String, Object> budget) { return false; }
        };
        Map<String, Object> d = Payments.authorizeChargeAtomic(mand, charge(50), mand.get("grant"), losing, null, in -> decision(true, true, in.get("budget")));
        assertEquals("deny", d.get("outcome"));
        assertEquals("budget_store_conflict", ((List<?>) d.get("reasons")).get(0));
    }

    @Test void malformedStoreRecordThrows() {
        Map<String, Object> mand = mandate();
        ChargeBudgetStore bad = new ChargeBudgetStore() {
            @Override public Record get(String key) { return new Record(new LinkedHashMap<String, Object>(), new Json.Num("1")); }
            @Override public boolean compareAndSet(String key, Object expected, Map<String, Object> budget) { return true; }
        };
        assertThrows(ChargeStoreError.class, () -> Payments.authorizeChargeAtomic(mand, charge(50), mand.get("grant"), bad, null, in -> decision(true, true, in.get("budget"))));
        assertThrows(ChargeStoreError.class, () -> Payments.authorizeChargeAtomic(mand, charge(50), mand.get("grant"), null, null, in -> decision(true, true, in.get("budget"))));
    }

    @Test void foreignGrantIsRefused() {
        Map<String, Object> mand = mandate();
        MandateGrantError e = assertThrows(MandateGrantError.class, () -> Payments.authorizeCharge(mand, charge(50), new LinkedHashMap<String, Object>(), in -> null));
        assertEquals("mandate_grant_mismatch", e.code);
        assertEquals("verified_grant_required", assertThrows(MandateGrantError.class, () -> Payments.authorizeCharge(mand, charge(50), null, in -> null)).code);
    }

    @Test void cosignIsCommittedWithCompareAndSet() {
        Map<String, Object> mand = mandate();
        MemoryChargeBudgetStore store = new MemoryChargeBudgetStore();
        Map<String, Object> next = Payments.applyHumanCosignAtomic(mand, mand.get("grant"), store, 1_800_000_002_000.0, true, null);
        assertEquals(1000.0, n(next.get("B")));
        assertNotNull(store.get(Pca.hashCanonical(mand.get("grant"))));
    }

    @Test void railAuthorizerDeclinesEverythingButAuto() {
        Map<String, Object> mand = mandate();
        Rails.RailAuthorizerOptions o = new Rails.RailAuthorizerOptions();
        o.store = new MemoryChargeBudgetStore();
        o.decider = in -> decision(true, true, in.get("budget"));
        o.now = () -> 1_800_000_001_000L;
        o.instruments = id -> id.equals("ic_1") ? new Rails.InstrumentBinding(mand, mand.get("grant"), null) : null;
        var authorize = Rails.createRailAuthorizer(o);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "auth_1");
        a.put("instrumentId", "ic_1");
        a.put("amount", new Json.Num("50"));
        a.put("currency", "usd");
        a.put("merchantId", "m1");
        assertEquals(true, authorize.apply(a).get("approved"));
        a.put("instrumentId", "nope");
        assertEquals(List.of("instrument_unknown"), authorize.apply(a).get("reasons"));
        a.put("instrumentId", "ic_1");
        a.put("amount", new Json.Num("0"));
        assertEquals(List.of("amount_not_positive_minor_units"), authorize.apply(a).get("reasons"));
        o.decider = in -> { throw new IllegalStateException("boom"); };
        a.put("amount", new Json.Num("50"));
        assertFalse((Boolean) authorize.apply(a).get("approved"));
        assertEquals(List.of("authorizer_error"), authorize.apply(a).get("reasons"));
    }

    @Test void railAuthorizerTimesOut() {
        Map<String, Object> mand = mandate();
        Rails.RailAuthorizerOptions o = new Rails.RailAuthorizerOptions();
        o.store = new MemoryChargeBudgetStore();
        o.latencyBudgetMs = 50;
        o.decider = in -> { try { Thread.sleep(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } return decision(true, true, in.get("budget")); };
        o.instruments = id -> new Rails.InstrumentBinding(mand, mand.get("grant"), null);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "auth_1");
        a.put("instrumentId", "ic_1");
        a.put("amount", new Json.Num("50"));
        a.put("currency", "USD");
        a.put("merchantId", "m1");
        Map<String, Object> v = Rails.createRailAuthorizer(o).apply(a);
        assertEquals(false, v.get("approved"));
        assertEquals(List.of("latency_budget_exceeded"), v.get("reasons"));
        assertThrows(IllegalArgumentException.class, () -> { o.latencyBudgetMs = 0; Rails.createRailAuthorizer(o); });
    }

    @Test void partnerAdapterIssuesAndSuspends() {
        List<String> paths = new ArrayList<>();
        NetworkToken.PartnerTransport t = (path, body) -> {
            paths.add(path);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("token_ref", "tok_abcdef123456");
            return r;
        };
        NetworkToken.NetworkTokenProvider p = NetworkToken.visaIntelligentCommerceAdapter(t);
        assertEquals("visa_ic", p.id());
        Map<String, Object> controls = new LinkedHashMap<>();
        controls.put("currency", "USD");
        controls.put("perAuthorizationMax", new Json.Num("5"));
        controls.put("totalMax", new Json.Num("9"));
        controls.put("categories", new ArrayList<Object>());
        controls.put("merchants", new ArrayList<Object>());
        controls.put("metadata", new LinkedHashMap<String, Object>());
        assertEquals("tok_abcdef123456", p.issue(controls, "agent").get("token_ref"));
        p.suspend("tok a/b", "grant_revoked");
        assertEquals(List.of("/tokens", "/tokens/tok%20a%2Fb/suspend"), paths);
        assertNull(NetworkToken.tokenRefError("tok_abcdef123456"));
        assertTrue(NetworkToken.looksLikePan("4111111111111111"));
    }
}
