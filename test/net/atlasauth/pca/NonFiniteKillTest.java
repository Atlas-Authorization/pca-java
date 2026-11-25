package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.acp.Acp;
import net.atlasauth.pca.ap2.Constraints;
import net.atlasauth.pca.dpop.Dpop;
import net.atlasauth.pca.mcp.Mcp;
import net.atlasauth.pca.oidc.Oidc;
import net.atlasauth.pca.oidc.OidcVerificationError;
import net.atlasauth.pca.payments.Rails;
import net.atlasauth.pca.research.Dlp;
import net.atlasauth.pca.sdjwt.Sdjwt;
import net.atlasauth.pca.signals.Signals;
import net.atlasauth.pca.signals.SsfStream;
import net.atlasauth.pca.spiffe.Spiffe;
import net.atlasauth.pca.spiffe.SpiffeError;
import net.atlasauth.pca.storeconformance.Reference;
import net.atlasauth.pca.storeconformance.StoreClient;
import net.atlasauth.pca.txntokens.TxnTokens;
import net.atlasauth.pca.wallet.WalletNoise;
import net.atlasauth.pca.webbotauth.WebBotAuth;
import org.junit.jupiter.api.Test;

/** A clock, budget, amount, window or tolerance that is NaN, +Infinity or -Infinity never admits: every site refuses, expires or depletes. */
public class NonFiniteKillTest {
    static final double[] BAD = {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY};

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    @Test void classApprovalRefusesANonFiniteClock() {
        Map<String, Object> a = Approvals.approveClass(List.of("x.read"), 1000, "by", 100, null);
        assertTrue(Approvals.classApprovalCovers(a, "x.read", "r", 500));
        // NaN compared false on both sides of the old window test, so it was in force
        for (double now : BAD) assertFalse(Approvals.classApprovalCovers(a, "x.read", "r", now));
        Map<String, Object> inf = new LinkedHashMap<>(a);
        inf.put("ttlMs", Double.POSITIVE_INFINITY); // an unbounded ttl is never a standing approval
        assertFalse(Approvals.classApprovalCovers(inf, "x.read", "r", 500));
    }

    @Test void subBudgetAndDebitsRefuseANonFiniteBalance() {
        assertEquals(Boolean.TRUE, RiskBudgets.subBudget(m("B", 10.0), 5).get("ok"));
        for (double b : BAD) {
            // NaN: 5 > NaN is false (admitted); +Infinity: 5 > Infinity is false (admitted)
            assertEquals(Boolean.FALSE, RiskBudgets.subBudget(m("B", b), 5).get("ok"));
            assertEquals(Boolean.FALSE, RiskBudgets.debitConsolidated(m("B", b), m("B", 10.0), 1).get("ok"));
            assertEquals(Boolean.FALSE, RiskBudgets.debitConsolidated(m("B", 10.0), m("B", b), 1).get("ok"));
            List<Object> path = new ArrayList<>();
            path.add(m("B", 10.0));
            path.add(m("B", b));
            assertEquals(Boolean.FALSE, RiskBudgets.debitConsolidatedPath(path, 1).get("ok"));
        }
    }

    @Test void leakDepletesOnANonFiniteClockOrStamp() {
        for (double bad : BAD) {
            // the old code read an unusable clock as "no time has passed" and kept the full budget
            assertEquals(0.0, Risk.leak(new Risk.Budget(10, 0, 0), bad, 1.0).b, 0.0);
            assertEquals(0.0, Risk.leak(new Risk.Budget(10, 0, bad), 100, 1.0).b, 0.0);
        }
    }

    @Test void admitNeedsAFiniteBudget() {
        assertEquals(Boolean.TRUE, InvariantsBridge.admit(0.0, 10.0, 0.3, 0.7, 1.0).get("admit"));
        assertEquals(Boolean.FALSE, InvariantsBridge.admit(0.0, Double.POSITIVE_INFINITY, 0.3, 0.7, 1.0).get("admit"));
        assertEquals(Boolean.FALSE, InvariantsBridge.admit(0.0, Double.NaN, 0.3, 0.7, 1.0).get("admit"));
    }

    @Test void revocationAgeRefusesAnInfiniteClock() {
        assertTrue(RevocationStaleness.checkRevocationAge(1000.0, 2000.0, 5000.0, "state").ok);
        // an infinite age limit is a legitimate cap, but an infinite clock is not: now - t = Infinity <= Infinity admitted it
        for (double now : BAD) assertFalse(RevocationStaleness.checkRevocationAge(1000.0, now, Double.POSITIVE_INFINITY, "state").ok);
    }

    @Test void challengeWindowPolicyRefusesNonFiniteBounds() {
        Map<String, Object> claim = m("pcactn_digest", "d", "claimed_r", 0.5, "issued_at", 1000.0, "challenge_window_ms", 5000.0, "sig", "s");
        // NaN bounds compared false, so the window check passed and the verdict moved on to the signature
        assertEquals("window", Optimistic.claimCheck(claim, "d", "pk", 1000, new Optimistic.ChallengeWindowPolicy(1000, 60000, Double.NaN)));
        assertEquals("window", Optimistic.claimCheck(claim, "d", "pk", 1000, new Optimistic.ChallengeWindowPolicy(Double.NaN, 60000, 1000)));
        assertEquals("window", Optimistic.claimCheck(claim, "d", "pk", 1000, new Optimistic.ChallengeWindowPolicy(1000, Double.NaN, 1000)));
    }

    @Test void envelopePermitsRefusesNonFiniteHints() {
        Map<String, Object> ok = m("ok", true, "unsatisfiable", new ArrayList<Object>(), "scopes", null, "remainingBudgetHints", m("delegationDepthRemaining", 2.0));
        assertTrue(AgentNative.envelopePermits(ok, "x", "y", null, null));
        assertFalse(AgentNative.envelopePermits(m("ok", true, "unsatisfiable", new ArrayList<Object>(), "scopes", null,
            "remainingBudgetHints", m("delegationDepthRemaining", Double.NaN)), "x", "y", null, null));
        assertFalse(AgentNative.envelopePermits(m("ok", true, "unsatisfiable", new ArrayList<Object>(), "scopes", null,
            "remainingBudgetHints", m("expiresAt", Double.NaN)), "x", "y", 5L, null));
        assertFalse(AgentNative.envelopePermits(m("ok", true, "unsatisfiable", new ArrayList<Object>(), "scopes", null,
            "remainingBudgetHints", m("notBefore", Double.NaN)), "x", "y", 5L, null));
    }

    @Test void priceCoverageDeclinesANonNumericFloor() {
        // score < NaN was false, so a NaN underwriting floor priced every score
        assertEquals(Boolean.TRUE, Reputation.priceCoverage(0.5, 100, m("minScore", Double.NaN)).get("declined"));
        assertEquals(Boolean.FALSE, Reputation.priceCoverage(0.5, 100, m("minScore", 0.25)).get("declined"));
    }

    @Test void paymentConstraintsRefuseNonFiniteAmounts() {
        Map<String, Object> range = m("type", "payment.amount_range", "currency", "USD", "min", 0.0, "max", 100.0);
        Map<String, Object> budget = m("type", "payment.budget", "currency", "USD", "max", 1.0);
        for (double amount : BAD) {
            Map<String, Object> open = m("constraints", new ArrayList<Object>(List.of(range)));
            Map<String, Object> closed = m("payment_amount", m("currency", "USD", "amount", amount));
            Constraints.PaymentCheckOptions o = new Constraints.PaymentCheckOptions();
            assertFalse(Constraints.checkPaymentConstraints(open, closed, o).isEmpty(), "range " + amount);
            Constraints.PaymentCheckOptions ob = new Constraints.PaymentCheckOptions();
            ob.context = Constraints.context(0, 0, null);
            Map<String, Object> openB = m("constraints", new ArrayList<Object>(List.of(budget)));
            // a spend of -Infinity is not above the budget, so the old comparison admitted it
            assertFalse(Constraints.checkPaymentConstraints(openB, closed, ob).isEmpty(), "budget " + amount);
        }
    }

    @Test void slidingWindowCounterIgnoresNonFiniteClocks() {
        WalletNoise.SlidingWindowCounter c = new WalletNoise.SlidingWindowCounter(1000);
        assertTrue(c.tryAdd(100, 5));
        // an infinite clock pruned every recorded event, resetting the hourly cap
        assertEquals(1, c.count(Double.POSITIVE_INFINITY));
        assertThrows(IllegalStateException.class, () -> c.tryAdd(Double.NaN, 5)); // not >= the last event: time went backwards
        assertFalse(c.tryAdd(Double.POSITIVE_INFINITY, 5)); // recorded nothing: the old code added Infinity as an event
        assertEquals(1, c.count(200));
    }

    @Test void replayStoresRefuseANonFiniteClock() {
        var dp = Dpop.createInMemoryDpopReplayStore(null);
        assertTrue(dp.addIfAbsent("k", 200, 100));
        for (double now : BAD) assertFalse(dp.addIfAbsent("k", 300, now)); // NaN < held was false: a held key was re-admitted
        var st = Signals.createInMemorySetReplayStore(null);
        assertTrue(st.addIfAbsent("j", 200, 100));
        for (double now : BAD) assertFalse(st.addIfAbsent("j", 300, now));
        var wb = WebBotAuth.memoryReplayCache();
        try {
            assertTrue(wb.claim("w", 200, 100));
            for (double now : BAD) assertFalse(wb.claim("w", 300, now)); // held >= NaN was false: a held claim was re-admitted
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void streamHealthRefusesANonFiniteClock() {
        SsfStream.StreamHealth h = new SsfStream.StreamHealth(m(), null);
        for (double now : BAD) assertNull(h.requestVerification(now));
        String state = h.requestVerification(100);
        assertNotNull(state);
        // expire(-Infinity) removes nothing, so the pending request was acknowledged under a clock before its expiry
        assertFalse(h.ackVerification(state, Double.NEGATIVE_INFINITY));
        assertFalse(h.ackVerification(state, Double.NaN));
        assertTrue(h.ackVerification(state, 101));
    }

    @Test void verificationRequestRefusesANonFiniteClock() {
        Map<String, Map<String, Object>> streams = new LinkedHashMap<>();
        streams.put("s1", m("config", m()));
        for (double now : BAD) assertEquals(429, SsfStream.handleVerificationRequest(streams, m("stream_id", "s1"), now, null).status);
    }

    @Test void sdJwtRefusesANonFiniteClockOrTolerance() {
        for (double bad : BAD) {
            for (String k : new String[] {"now", "clockToleranceSec", "kbMaxAgeSec"}) {
                Map<String, Object> r = Sdjwt.verifyPcaSdJwt("x", m(k, bad));
                assertEquals(Boolean.FALSE, r.get("ok"));
                assertTrue(String.valueOf(r.get("reason")).contains("must be finite"), k + " " + bad);
            }
        }
    }

    @Test void paymentPeriodEndMustBeFinite() {
        for (double end : BAD) {
            Map<String, Object> mandate = m("terms", m("autoApproveThreshold", 100.0, "currency", "USD", "periodEnd", end), "budget", m("B", 1000.0));
            // NaN never ended and +Infinity was emitted as expires_at null (no expiry)
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Rails.sharedPaymentTokenLimits(mandate, 5000));
            assertTrue(e.getMessage().contains("periodEnd must be an epoch-ms time"), String.valueOf(end));
        }
    }

    @Test void unknownRecurrenceFrequencyIsAlwaysAViolation() {
        for (String f : new String[] {"HOURLY", "", "daily"}) {
            Map<String, Object> open = m("constraints", new ArrayList<Object>(List.of(m("type", "payment.agent_recurrence", "frequency", f))));
            Map<String, Object> closed = m("payment_amount", m("currency", "USD", "amount", 10.0));
            Constraints.PaymentCheckOptions o = new Constraints.PaymentCheckOptions();
            // no last-used date: the violation used to fire only when one existed
            assertTrue(Constraints.checkPaymentConstraints(open, closed, o).contains("unknown recurrence frequency"), f);
        }
    }

    @Test void acpSpendCapMustBeANonNegativeInteger() {
        Object[] bad = {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1.0, -0.0, 1.5};
        Map<String, Object> req = m("amount", 1.0, "currency", "USD", "merchant", "m");
        for (Object cap : bad) {
            Map<String, Object> a = m("maxAmount", cap, "merchants", null, "categories", null, "humanPresentRequired", false);
            Map<String, Object> r = Acp.checkPaymentAuthority(a, req);
            assertEquals(Boolean.FALSE, r.get("ok"), String.valueOf(cap));
            assertEquals("authorized spend cap is not a non-negative integer (fail closed)", r.get("reason"));
        }
        assertEquals(Boolean.TRUE, Acp.checkPaymentAuthority(m("merchants", null, "categories", null, "humanPresentRequired", false), req).get("ok"));
    }

    @Test void bondChallengeStatusRefusesANonFiniteClock() {
        for (double bad : BAD) {
            StoreBondLedger.Options o = new StoreBondLedger.Options();
            o.store = new KvBondStore(new MemoryAtomicKv());
            o.guardianKey = Keys.edFromSeed(new byte[32]);
            o.clock = () -> bad;
            // a non-finite clock must refuse, never answer finalized (which opens settlement)
            BondStoreError e = assertThrows(BondStoreError.class, () -> new StoreBondLedger(o).challengeStatus("c1"));
            assertEquals("clock_invalid", e.code());
        }
    }

    @Test void bondDebitRefusesAnInfiniteBalance() {
        List<Object> moves = new ArrayList<>(List.of(m("account", "a", "op", "debit", "amount", 5.0)));
        // an infinite balance was never below the amount, so the debit used to pass
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> BondDoc.applyBondMoves(a -> Double.POSITIVE_INFINITY, moves));
        assertTrue(e.getMessage().contains("is not finite"));
        assertThrows(IllegalStateException.class, () -> BondDoc.applyBondMoves(a -> Double.NaN, moves));
    }

    @Test void maaJwksRefusesANonFiniteClockOrSkew() {
        Map<String, Object> jwks = m("keys", new ArrayList<Object>(List.of(m("kid", "k1", "x5c", new ArrayList<Object>(List.of("AA==")))))); 
        for (double bad : BAD) {
            Map<String, Object> r = AttestMaaKeys.evaluateMaaJwks(jwks, "https://i", m(), bad);
            assertTrue(((List<?>) r.get("accepted")).isEmpty());
            assertTrue(String.valueOf(r.get("rejected")).contains("clock and skew must be finite"));
            Map<String, Object> s = AttestMaaKeys.evaluateMaaJwks(jwks, "https://i", m("clockSkewMs", bad), 1.0);
            assertTrue(((List<?>) s.get("accepted")).isEmpty());
            assertTrue(String.valueOf(s.get("rejected")).contains("clock and skew must be finite"));
        }
    }

    // a non-finite clock used to read as finalized (opens settlement); an infinite window end does too
    @Test void claimStatusRefusesANonFiniteClockOrWindow() {
        for (double bad : BAD) {
            assertThrows(ArithmeticException.class, () -> net.atlasauth.pca.Optimistic.claimStatus(0, 10, bad));
            assertThrows(ArithmeticException.class, () -> net.atlasauth.pca.Optimistic.claimStatus(0, bad, 5));
        }
        assertEquals("open", net.atlasauth.pca.Optimistic.claimStatus(0, 10, 5));
    }

    @Test void stripeSignatureRefusesANonFiniteToleranceOrClock() {
        String sig = Rails.signStripePayload("{}", "sec", 1000);
        assertTrue(Rails.verifyStripeSignature("{}", sig, "sec", 1000, 300));
        // an infinite tolerance made every timestamp fresh; a NaN clock compared false against the tolerance
        for (double tol : BAD) assertFalse(Rails.verifyStripeSignature("{}", sig, "sec", 1000, tol), "tolerance " + tol);
        for (double now : BAD) assertFalse(Rails.verifyStripeSignature("{}", sig, "sec", now, 300), "clock " + now);
    }

    @Test void dlpTreatsANonFiniteTaintAsOverAnUnboundedCeiling() {
        Map<String, Object> policy = m("classes", new ArrayList<Object>(), "defaultMaxTaintForAuto", Double.POSITIVE_INFINITY);
        assertEquals("allow", Dlp.evaluateDlp(policy, m("verb", "x", "resource", "r", "taint", 5.0)).get("outcome"));
        // Infinity > Infinity is false, so the substituted worst-case taint used to pass an unbounded ceiling
        for (double taint : BAD) assertEquals("step_up", Dlp.evaluateDlp(policy, m("verb", "x", "resource", "r", "taint", taint)).get("outcome"), "taint " + taint);
    }

    @Test void stepUpGivesUpOnANonFiniteAttemptCount() {
        String www = "Bearer error=\"insufficient_scope\", scope=\"read\"";
        for (double attempts : BAD) {
            Map<String, Object> r = Mcp.planStepUp(403, www, m("requested", new ArrayList<Object>(List.of("x")), "attempts", attempts));
            // NaN and -Infinity were never at the limit, so the step-up used to retry forever
            assertEquals("give_up", r.get("action"), "attempts " + attempts);
            assertEquals("retry_limit", r.get("reason"));
        }
    }

    @Test void idTokenVerificationRefusesANonFiniteToleranceOrAgeLimit() {
        for (double bad : new double[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1.0}) {
            OidcVerificationError e = assertThrows(OidcVerificationError.class, () -> Oidc.verifyIdToken("a.b.c", m("issuer", "https://i", "audience", "a", "clockToleranceSec", bad)));
            assertEquals("config", e.code());
        }
        OidcVerificationError e = assertThrows(OidcVerificationError.class, () -> Oidc.verifyIdToken("a.b.c", m("issuer", "https://i", "audience", "a", "maxTokenAgeSec", Double.NaN)));
        assertEquals("config", e.code());
    }

    @Test void transactionTokenRefusesANonFiniteToleranceOrClock() {
        for (double bad : BAD) {
            IllegalArgumentException t = assertThrows(IllegalArgumentException.class, () -> TxnTokens.fromTransactionToken("x", new byte[32], m("clockToleranceSec", bad, "audience", "a", "replayCheck", "unchecked")));
            assertTrue(t.getMessage().contains("clockToleranceSec must be a finite number"), String.valueOf(bad));
            IllegalArgumentException n = assertThrows(IllegalArgumentException.class, () -> TxnTokens.fromTransactionToken("x", new byte[32], m("now", bad, "audience", "a", "replayCheck", "unchecked")));
            assertTrue(n.getMessage().contains("now must be a valid Date"), String.valueOf(bad));
        }
    }

    @Test void jwtSvidRefusesANonFiniteTolerance() {
        for (double bad : BAD) {
            Spiffe.VerifyJwtSvidOptions o = new Spiffe.VerifyJwtSvidOptions();
            o.audience = new ArrayList<>(List.of("a"));
            o.trustDomain = "example.org";
            o.clockTolerance = bad;
            SpiffeError e = assertThrows(SpiffeError.class, () -> Spiffe.verifyJwtSvid("x", o));
            assertTrue(e.getMessage().contains("clockTolerance must be a finite number"), String.valueOf(bad));
        }
    }

    @Test void referenceStoreAdaptersRefuseANonFiniteClockOrHorizon() throws Exception {
        StoreClient good = Reference.inMemoryAdapter().open();
        assertTrue(good.consumeOnce("k", 200, 100));
        for (double bad : BAD) {
            assertThrows(IllegalArgumentException.class, () -> good.consumeOnce("k2", 300, bad));
            assertThrows(IllegalArgumentException.class, () -> good.consumeOnce("k3", bad, 100));
        }
        // the read-then-write control: a held key was re-admitted when the clock was NaN
        StoreClient rw = Reference.readThenWriteAdapter().open();
        assertTrue(rw.consumeOnce("k", 200, 100));
        for (double now : BAD) assertFalse(rw.consumeOnce("k", 300, now), "clock " + now);
    }

    @Test void nvidiaOcspRefusesAnInfiniteSkewOrNanAge() {
        for (double v : BAD) {
            AttestNvidiaOcsp.Opts o = new AttestNvidiaOcsp.Opts();
            o.skewMs = v;
            AttestNvidiaOcsp.Result r = AttestNvidiaOcsp.verifyResponse(new byte[0], null, null, null, 0L, o);
            assertFalse(r.ok);
            assertTrue(r.reason.contains("must be finite"), "skew " + v);
        }
        AttestNvidiaOcsp.Opts n = new AttestNvidiaOcsp.Opts();
        n.maxAgeMs = Double.NaN;
        assertTrue(AttestNvidiaOcsp.verifyResponse(new byte[0], null, null, null, 0L, n).reason.contains("maxAgeMs a number"));
    }

    @Test void verifierRefusesANonFiniteClock() {
        for (double bad : BAD) {
            Map<String, Object> v = ServerVerify.verify(m(), m("now", bad));
            assertEquals(Boolean.FALSE, v.get("allow"));
            assertTrue(String.valueOf(v.get("reasons")).contains("the verifier clock is not a finite time"), String.valueOf(bad));
        }
    }
}
