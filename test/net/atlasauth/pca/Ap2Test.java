package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.ap2.Ap2;
import net.atlasauth.pca.ap2.Ap2Error;
import net.atlasauth.pca.ap2.Chain;
import net.atlasauth.pca.ap2.Constraints;
import net.atlasauth.pca.ap2.Ledger;
import net.atlasauth.pca.ap2.Sdjwt;
import org.junit.jupiter.api.Test;

/** Round trips the oracle cannot cover (ES256 signatures are randomized): sign here, verify here. */
public class Ap2Test {
    private static final double T0 = 1_800_000_000d;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> mk(Object... kv) {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    private static Function<Map<String, Object>, Map<String, Object>> keyed(String kid, Map<String, Object> jwk) {
        return h -> kid.equals(h.get("kid")) ? jwk : null;
    }

    @Test void es256RoundTrip() {
        Sdjwt.Ap2KeyPair k = Sdjwt.generateAp2KeyPair("k1");
        assertEquals("k1", k.publicJwk.get("kid"));
        assertFalse(k.publicJwk.containsKey("d"));
        Sdjwt.assertP256Jwk(k.publicJwk, "key");
        String jwt = Sdjwt.signJwtEs256(mk("kid", "k1"), mk("a", Json.parse("1")), k.privateKey);
        Sdjwt.ParsedJwt p = Sdjwt.parseJwt(jwt, "jwt");
        assertEquals(64, p.signature.length);
        assertTrue(Sdjwt.verifyJwtEs256(p, k.publicJwk));
        assertFalse(Sdjwt.verifyJwtEs256(p, Sdjwt.generateAp2KeyPair().publicJwk));
        String[] seg = jwt.split("\\.");
        String tampered = Sdjwt.b64uEncode("{\"a\":2}") + "." + seg[1] + "." + seg[2];
        assertFalse(Sdjwt.verifyJwtEs256(Sdjwt.parseJwt(tampered, "jwt"), k.publicJwk));
    }

    @Test void signatureOutOfRangeIsRefusedNotThrown() {
        Sdjwt.Ap2KeyPair k = Sdjwt.generateAp2KeyPair();
        String jwt = Sdjwt.signJwtEs256(mk(), mk("a", Json.parse("1")), k.privateKey);
        String[] seg = jwt.split("\\.");
        byte[] ff = new byte[64];
        Arrays.fill(ff, (byte) 0xff);
        assertFalse(Sdjwt.verifyJwtEs256(Sdjwt.parseJwt(seg[0] + "." + seg[1] + "." + Sdjwt.b64uEncode(ff), "jwt"), k.publicJwk));
        assertFalse(Sdjwt.verifyJwtEs256(Sdjwt.parseJwt(seg[0] + "." + seg[1] + "." + Sdjwt.b64uEncode(new byte[64]), "jwt"), k.publicJwk));
    }

    @Test void offCurvePointIsRefused() {
        Map<String, Object> jwk = new HashMap<>(Sdjwt.generateAp2KeyPair().publicJwk);
        jwk.put("y", jwk.get("x"));
        assertThrows(Ap2Error.class, () -> Sdjwt.assertP256Jwk(jwk, "key"));
    }

    @Test void thumbprintOfGeneratedKeyIsStable() {
        Sdjwt.Ap2KeyPair k = Sdjwt.generateAp2KeyPair();
        assertEquals(43, Sdjwt.jwkThumbprint(k.publicJwk).length());
        assertEquals(Sdjwt.jwkThumbprint(k.publicJwk), Sdjwt.jwkThumbprint(k.publicJwk));
    }

    private static final Map<String, Object> MERCH = mk("id", "m1", "name", "Shop");
    private static final Map<String, Object> INSTR = mk("id", "spt_1", "type", "shared_payment_token");

    /** A signed purchase built with the native issuer: open + closed checkout, open + closed payment. */
    private static String[] purchase(Sdjwt.Ap2KeyPair issuer, Sdjwt.Ap2KeyPair agent, Sdjwt.Ap2KeyPair merchant) {
        Chain.MandateIssuer iss = new Chain.MandateIssuer(issuer.privateKey, "issuer-1");
        Chain.OpenCheckoutMandateInput oc = new Chain.OpenCheckoutMandateInput();
        oc.issuer = iss;
        oc.agentJwk = agent.publicJwk;
        oc.iat = T0 - 100;
        oc.exp = T0 + 3600;
        oc.constraints = list(mk("type", "checkout.line_items", "items",
            list(mk("id", "line_1", "acceptable_items", list(mk("id", "sku-1", "title", "Widget")), "quantity", Json.parse("2")))));
        String openCheckout = Chain.issueOpenCheckoutMandate(oc);
        Map<String, Object> payload = mk("id", "chk_1", "merchant", MERCH, "currency", "USD",
            "line_items", list(mk("id", "li_1", "item", mk("id", "sku-1", "title", "Widget", "price", Json.parse("2000")), "quantity", Json.parse("2"))),
            "totals", list(mk("type", "total", "amount", Json.parse("4000"))));
        String checkoutJwt = Sdjwt.signJwtEs256(mk("kid", "merchant-1"), payload, merchant.privateKey);
        Chain.ClosedCheckoutInput cc = new Chain.ClosedCheckoutInput();
        cc.open = openCheckout;
        cc.agentKey = agent;
        cc.aud = "merchant";
        cc.nonce = "nc";
        cc.iat = T0;
        cc.checkoutJwt = checkoutJwt;
        String checkoutChain = Chain.presentClosedCheckout(cc);
        String openHash = Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(openCheckout));
        Chain.OpenPaymentMandateInput op = new Chain.OpenPaymentMandateInput();
        op.issuer = iss;
        op.agentJwk = agent.publicJwk;
        op.iat = T0 - 100;
        op.exp = T0 + 3600;
        op.constraints = list(
            mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("50000")),
            mk("type", "payment.allowed_payees", "allowed", list(MERCH)),
            mk("type", "payment.reference", "conditional_transaction_id", openHash),
            mk("type", "payment.budget", "currency", "USD", "max", Json.parse("100")),
            mk("type", "payment.agent_recurrence", "frequency", "ON_DEMAND", "max_occurrences", Json.parse("3")));
        String openPayment = Chain.issueOpenPaymentMandate(op);
        Chain.ClosedPaymentInput cp = new Chain.ClosedPaymentInput();
        cp.open = openPayment;
        cp.agentKey = agent;
        cp.aud = "cp";
        cp.nonce = "np";
        cp.iat = T0;
        cp.transactionId = Sdjwt.sdDigest(checkoutJwt);
        cp.payee = MERCH;
        cp.paymentAmount = mk("amount", Json.parse("4000"), "currency", "USD");
        cp.paymentInstrument = INSTR;
        return new String[] {checkoutChain, Chain.presentClosedPayment(cp)};
    }

    private static Chain.VerifyPurchaseOptions options(Sdjwt.Ap2KeyPair issuer, Sdjwt.Ap2KeyPair merchant) {
        Chain.VerifyPurchaseOptions o = new Chain.VerifyPurchaseOptions();
        o.resolveIssuerKey = keyed("issuer-1", issuer.publicJwk);
        o.resolveMerchantKey = keyed("merchant-1", merchant.publicJwk);
        o.checkout = new Chain.Expect("merchant", "nc");
        o.payment = new Chain.Expect("cp", "np");
        o.now = T0 + 10;
        o.context = Constraints.context(0, 0, null);
        return o;
    }

    @Test void issuedPurchaseVerifies() {
        Sdjwt.Ap2KeyPair issuer = Sdjwt.generateAp2KeyPair(), agent = Sdjwt.generateAp2KeyPair(), merchant = Sdjwt.generateAp2KeyPair();
        String[] t = purchase(issuer, agent, merchant);
        Chain.PurchaseResult r = Chain.verifyPurchase(t[0], t[1], options(issuer, merchant));
        assertTrue(r.ok, r.reason);
        assertEquals(2, r.checkout.hops.size());
        assertEquals("terminal", r.payment.hops.get(1).kind);
        // a wrong merchant key, a wrong audience and a spent budget each refuse
        Chain.VerifyPurchaseOptions bad = options(issuer, merchant);
        bad.resolveMerchantKey = keyed("merchant-1", Sdjwt.generateAp2KeyPair().publicJwk);
        assertFalse(Chain.verifyPurchase(t[0], t[1], bad).ok);
        bad = options(issuer, merchant);
        bad.payment = new Chain.Expect("other", "np");
        assertFalse(Chain.verifyPurchase(t[0], t[1], bad).ok);
        bad = options(issuer, merchant);
        bad.context = Constraints.context(10000, 0, null);
        assertEquals("payment: open payment constraints violated: cumulative spend 14000 exceeds budget 10000 (past spend 10000)", Chain.verifyPurchase(t[0], t[1], bad).reason);
    }

    @Test void redeemIsSingleUseAndLedgerOwned() {
        Sdjwt.Ap2KeyPair issuer = Sdjwt.generateAp2KeyPair(), agent = Sdjwt.generateAp2KeyPair(), merchant = Sdjwt.generateAp2KeyPair();
        String[] t = purchase(issuer, agent, merchant);
        List<String> seen = new ArrayList<>();
        Ledger.PurchaseLedger ledger = new Ledger.PurchaseLedger() {
            @Override public Object reserve(String h, String tx, double amt) {
                if (seen.contains(h + tx)) return Ledger.PurchaseLedger.REPLAYED;
                seen.add(h + tx);
                return Constraints.context(0, 0, null);
            }

            @Override public void release(String h, String tx) { seen.remove(h + tx); }
        };
        assertTrue(Ledger.redeemPurchase(t[0], t[1], options(issuer, merchant), ledger).ok);
        assertEquals("replayed", Ledger.redeemPurchase(t[0], t[1], options(issuer, merchant), ledger).reason);
        assertEquals("ledger_required", Ledger.redeemPurchase(t[0], t[1], options(issuer, merchant), null).reason);
        Ledger.PurchaseLedger down = new Ledger.PurchaseLedger() {
            @Override public Object reserve(String h, String tx, double amt) throws Exception { throw new Exception("down"); }

            @Override public void release(String h, String tx) {}
        };
        assertEquals("ledger_unavailable", Ledger.redeemPurchase(t[0], t[1], options(issuer, merchant), down).reason);
    }

    @Test void constraintsWithinTermsNarrowsOnly() {
        Map<String, Object> merch = mk("id", "m1", "name", "Shop");
        Map<String, Object> terms = mk("currency", "USD", "perTransactionCap", Json.parse("50000"), "cumulativeCap", Json.parse("100000"), "merchants", list("m1"));
        Map<String, Object> open = mk("exp", Json.parse("5"), "constraints", list(
            mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("50000")),
            mk("type", "payment.allowed_payees", "allowed", list(merch)),
            mk("type", "payment.budget", "currency", "USD", "max", Json.parse("1000"))));
        assertNull(Ap2.constraintsWithinTerms(open, terms));
        open.put("constraints", list(mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("50001")),
            mk("type", "payment.allowed_payees", "allowed", list(merch)), mk("type", "payment.budget", "currency", "USD", "max", Json.parse("1000"))));
        assertEquals("amount_range.max 50001 exceeds the PCA per-transaction cap 50000", Ap2.constraintsWithinTerms(open, terms));
        open.put("constraints", list(mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("5")),
            mk("type", "payment.allowed_payees", "allowed", list(merch)), mk("type", "payment.budget", "currency", "USD", "max", Json.parse("1001"))));
        assertEquals("budget exceeds the PCA cumulative cap", Ap2.constraintsWithinTerms(open, terms));
        open.put("constraints", list(mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("5"))));
        assertEquals("open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side", Ap2.constraintsWithinTerms(open, terms));
        terms.put("periodEnd", Json.parse("1000"));
        open.put("constraints", list(mk("type", "payment.amount_range", "currency", "USD", "max", Json.parse("5")),
            mk("type", "payment.allowed_payees", "allowed", list(merch)), mk("type", "payment.budget", "currency", "USD", "max", Json.parse("1000"))));
        assertEquals("open mandate outlives the PCA period", Ap2.constraintsWithinTerms(open, terms));
        open.put("exp", Json.parse("1"));
        assertNull(Ap2.constraintsWithinTerms(open, terms));
    }

    @Test void pcaBindingErrorCarriesItsCode() {
        Ap2.PcaBindingError e = new Ap2.PcaBindingError("mandate_required", "x");
        assertEquals("mandate_required", e.code);
        assertNotNull(Ap2.AP2_COMMIT);
        assertEquals(40, Ap2.AP2_COMMIT.length());
    }
}
