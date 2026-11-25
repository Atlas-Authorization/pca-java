package net.atlasauth.pca.ap2;

import java.util.Map;
import net.atlasauth.pca.ap2.Chain.PurchaseResult;
import net.atlasauth.pca.ap2.Chain.VerifyPurchaseOptions;

/**
 * Durable, serialised purchase state for open mandates, and {@link #redeemPurchase}: {@code verifyPurchase} plus single use and
 * server-owned cumulative state.
 */
public final class Ledger {
    private Ledger() {}

    /**
     * Durable, serialised purchase state for open mandates. {@code reserve} is ONE atomic step: it refuses a transaction id that
     * was already reserved under this open mandate ({@link #REPLAYED}), otherwise records it with its amount and returns the
     * usage context of every EARLIER reservation (so two concurrent purchases see each other and cannot share one budget).
     * Back it with a unique key on (openMandateHash, transactionId) and a serialised sum (a row lock or one conditional write).
     * {@code release} undoes a reservation whose purchase then failed verification.
     */
    public interface PurchaseLedger {
        /** The {@link #reserve} answer for a transaction id that was already reserved. */
        String REPLAYED = "replayed";

        /** A usage context map ({@link Constraints#context}) or {@link #REPLAYED}. */
        Object reserve(String openMandateHash, String transactionId, double amountMinor) throws Exception;

        void release(String openMandateHash, String transactionId) throws Exception;
    }

    private static VerifyPurchaseOptions withContext(VerifyPurchaseOptions o, Map<String, Object> ctx) {
        VerifyPurchaseOptions c = new VerifyPurchaseOptions();
        c.resolveIssuerKey = o.resolveIssuerKey;
        c.resolveMerchantKey = o.resolveMerchantKey;
        c.checkout = o.checkout;
        c.payment = o.payment;
        c.context = ctx;
        c.now = o.now;
        c.clockSkewSeconds = o.clockSkewSeconds;
        return c;
    }

    /**
     * {@code verifyPurchase} plus single use and server-owned cumulative state. The usage context comes from {@code ledger}, never
     * from the caller (the {@code context} of {@code o} is ignored), and the purchase's transaction id can be redeemed once. A
     * missing or failing ledger denies ({@code ledger_required}, {@code ledger_unavailable}, {@code replayed}).
     */
    @SuppressWarnings("unchecked")
    public static PurchaseResult redeemPurchase(String checkoutToken, String paymentToken, VerifyPurchaseOptions o, PurchaseLedger ledger) {
        if (ledger == null) return PurchaseResult.fail("ledger_required");
        // A zero context is the most permissive one for budget and recurrence, so a failure here is final.
        PurchaseResult first = Chain.verifyPurchase(checkoutToken, paymentToken, withContext(o, Constraints.context(0, 0, null)));
        if (!first.ok) return first;
        String openHash = first.payment.openHash;
        String txId = (String) first.payment.closed.get("transaction_id");
        double amount = Js.num(Js.get(first.payment.closed.get("payment_amount"), "amount"));
        Object ctx;
        try {
            ctx = ledger.reserve(openHash, txId, amount);
        } catch (Exception e) {
            return PurchaseResult.fail("ledger_unavailable");
        }
        if (PurchaseLedger.REPLAYED.equals(ctx)) return PurchaseResult.fail("replayed");
        PurchaseResult fin = Chain.verifyPurchase(checkoutToken, paymentToken, withContext(o, ctx instanceof Map ? (Map<String, Object>) ctx : null));
        if (!fin.ok) {
            try {
                ledger.release(openHash, txId);
            } catch (Exception e) {
                // the reservation stays: a failed release only ever over-counts spend
            }
        }
        return fin;
    }
}
