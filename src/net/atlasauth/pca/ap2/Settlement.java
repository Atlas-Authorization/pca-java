package net.atlasauth.pca.ap2;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

/**
 * Settlement backends: the rails PCA's governance feeds. STRUCTURAL ONLY, no network.
 *
 * <p>A backend turns a payment mandate that has ALREADY been verified into the rail's wire shape. Amounts are the mandate's
 * integer minor units; nothing here accepts a decimal. Mandates are parsed JSON (Map, List, String, Boolean, Json.Num, null).
 */
public final class Settlement {
    private Settlement() {}

    /** Context the caller supplies for building a rail-specific settlement payload (every field optional). */
    public static final class SettlementContext {
        /** Protected resource URL (x402). */
        public String resourceUrl;
        /** Payee address / account (x402 {@code payTo}, Stripe {@code on_behalf_of}). */
        public String payTo;
        /** Rail network, e.g. an x402 chain id like {@code base-sepolia}. */
        public String network;
        /** x402 {@code asset}: the token contract address. Defaults to the mandate's currency code (a placeholder; supply the address). */
        public String asset;
        /** x402: decimals of the asset (a number), used to convert the mandate amount to atomic units. Default 6 (USDC). */
        public Object decimals;
        /** x402 {@code maxTimeoutSeconds} (a number): how long the payer has to complete payment. Default 60. */
        public Object maxTimeoutSeconds;

        /** A context from its JSON object form (members named as in the TypeScript option bag). */
        public static SettlementContext fromMap(Map<String, Object> m) {
            if (m == null) return null;
            SettlementContext c = new SettlementContext();
            c.resourceUrl = (String) m.get("resourceUrl");
            c.payTo = (String) m.get("payTo");
            c.network = (String) m.get("network");
            c.asset = (String) m.get("asset");
            c.decimals = m.get("decimals");
            c.maxTimeoutSeconds = m.get("maxTimeoutSeconds");
            return c;
        }
    }

    /**
     * Convert integer minor units to an integer string of atomic units. Scales by {@code 10^(decimals - exponent)} exactly, so no
     * float is involved; when the asset has fewer decimals than the currency the division must be exact. Throws otherwise
     * (fail closed). {@code amount} is {@code {amount, currency}}; {@code decimals} a number.
     */
    public static String toAtomicUnits(Map<String, Object> amount, Object decimals) {
        if (!Js.isFinite(decimals) || Js.num(decimals) != Math.rint(Js.num(decimals)) || Js.num(decimals) < 0 || Js.num(decimals) > 18) {
            throw new IllegalArgumentException("x402: decimals must be an integer in 0..18, got " + Js.str(decimals));
        }
        int dec = (int) (double) Js.num(decimals);
        Object a = amount.get("amount");
        if (!Js.isSafeInteger(a) || Js.num(a) < 0 || Js.isNegZero(Js.num(a))) {
            throw new IllegalArgumentException("x402: amount " + Js.str(a) + " cannot be expressed in atomic units with " + dec + " decimals");
        }
        int exp = Mandates.currencyExponent(amount.get("currency"));
        BigInteger minor = BigInteger.valueOf((long) (double) Js.num(a));
        if (dec >= exp) return minor.multiply(BigInteger.TEN.pow(dec - exp)).toString();
        BigInteger div = BigInteger.TEN.pow(exp - dec);
        if (minor.mod(div).signum() != 0) throw new IllegalArgumentException("x402: amount " + Js.str(a) + " cannot be expressed in atomic units with " + dec + " decimals");
        return minor.divide(div).toString();
    }

    /** A settlement rail: turns a (presumed-verified) closed Payment Mandate into the rail's wire shape. Pure; no network. */
    public interface SettlementBackend {
        String rail();

        /** The instruction {@code {rail, amount, merchant?, payload}}. */
        Map<String, Object> settle(Map<String, Object> payment, SettlementContext ctx);
    }

    private static Object or(Object v, Object dflt) { return v != null ? v : dflt; }

    /**
     * Coinbase x402 adapter: the HTTP 402 {@code Payment Required} challenge ({@code accepts}) plus the {@code X-PAYMENT} request
     * header (standard base64 of the JSON payment payload). The payload is a placeholder envelope, not a signed authorization:
     * the real rail settles on-chain.
     */
    public static final SettlementBackend x402Settlement = new SettlementBackend() {
        @Override public String rail() { return "x402"; }

        @Override public Map<String, Object> settle(Map<String, Object> payment, SettlementContext ctx) {
            Object network = or(ctx == null ? null : ctx.network, "base-sepolia");
            Object amt = payment.get("payment_amount");
            Object payeeId = Js.get(payment.get("payee"), "id");
            Map<String, Object> requirement = Js.m(
                "scheme", "exact",
                "network", network,
                // x402 v1: maxAmountRequired is a string in ATOMIC token units, not a decimal amount.
                "maxAmountRequired", toAtomicUnits(Js.obj(amt), or(ctx == null ? null : ctx.decimals, Js.n(6))),
                "resource", or(ctx == null ? null : ctx.resourceUrl, ""),
                "description", "AP2 payment mandate " + Js.str(Js.getU(payment, "transaction_id")),
                "payTo", or(ctx == null ? null : ctx.payTo, payeeId),
                "asset", or(ctx == null ? null : ctx.asset, Js.get(amt, "currency")),
                "mimeType", "application/json",
                "maxTimeoutSeconds", or(ctx == null ? null : ctx.maxTimeoutSeconds, Js.n(60)));
            String xPayment = Base64.getEncoder().encodeToString(Js.utf8(Js.stringify(Js.m(
                "x402Version", Js.n(1),
                "scheme", "exact",
                "network", network,
                "payload", Js.m("transactionId", payment.get("transaction_id"), "amount", Js.get(amt, "amount"), "currency", Js.get(amt, "currency"))))));
            return Js.m(
                "rail", "x402",
                "amount", amt,
                "merchant", payeeId,
                "payload", Js.m("httpStatus", Js.n(402), "x402Version", Js.n(1), "error", "X-PAYMENT header is required", "accepts", Js.l(requirement), "header", Js.m("X-PAYMENT", xPayment)));
        }
    };

    /**
     * Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The
     * mandate amount is already in minor units, which is what Stripe takes. The token is the mandate's payment instrument id,
     * never a raw PAN.
     */
    public static final SettlementBackend stripeSptSettlement = new SettlementBackend() {
        @Override public String rail() { return "stripe-spt"; }

        @Override public Map<String, Object> settle(Map<String, Object> payment, SettlementContext ctx) {
            Object inst = payment.get("payment_instrument");
            if (!"shared_payment_token".equals(Js.get(inst, "type"))) {
                throw new Ap2Error("stripe-spt: the payment instrument must be of type shared_payment_token, got " + Js.str(Js.getU(inst, "type")));
            }
            Object amt = payment.get("payment_amount");
            Map<String, Object> payload = Js.m(
                "shared_payment_token", Js.get(inst, "id"),
                "amount", Js.get(amt, "amount"),
                "currency", Js.str(Js.get(amt, "currency")).toLowerCase(Locale.ROOT));
            if (ctx != null && ctx.payTo != null && !ctx.payTo.isEmpty()) payload.put("on_behalf_of", ctx.payTo);
            return Js.m("rail", "stripe-spt", "amount", amt, "merchant", Js.get(payment.get("payee"), "id"), "payload", payload);
        }
    };
}
