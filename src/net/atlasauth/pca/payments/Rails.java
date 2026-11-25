package net.atlasauth.pca.payments;

import static net.atlasauth.pca.payments.PayJs.copy;
import static net.atlasauth.pca.payments.PayJs.get;
import static net.atlasauth.pca.payments.PayJs.has;
import static net.atlasauth.pca.payments.PayJs.jn;
import static net.atlasauth.pca.payments.PayJs.map;
import static net.atlasauth.pca.payments.PayJs.num;
import static net.atlasauth.pca.payments.PayJs.str;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.atlasauth.pca.Json;

/**
 * Spend rails: a virtual card (or any instrument) whose limits mirror the grant, the real-time authorization callback that answers
 * from {@link Payments#authorizeCharge}, settlement reconciliation, the Shared Payment Token limits and the Stripe Issuing adapter
 * (the reference's rails, spt-limits and rails-stripe modules). A rail answer is only ever "approve" when the PCA decision is
 * {@code auto}; a step-up, a deny, an unknown card, a timeout or an exception all decline.
 */
public final class Rails {
    private Rails() {}

    public static final int STRIPE_WEBHOOK_TOLERANCE_SEC = 300;
    public static final String STRIPE_API_VERSION = "2025-03-31.basil";
    /** Action-kit convention: a custom trait {@code mcc.c5734} on the verb says the verb may spend in MCC 5734. */
    public static final Pattern MCC_TRAIT_RE = Pattern.compile("^mcc\\.c(\\d{4})$");

    // ---- Shared Payment Token limits -------------------------------------------------------------------------------------

    /**
     * The {@code usage_limits} of a Stripe Shared Payment Token that fit what the mandate lets an agent spend WITHOUT a human co-sign:
     * at most the auto-approve threshold, at most the remaining autonomous budget, in the mandate currency, expiring with the mandate
     * period. Throws when no autonomous capacity is left or the mandate has ended at {@code now}.
     */
    public static Map<String, Object> sharedPaymentTokenLimits(Map<String, Object> mandate, double now) {
        if (Double.isNaN(now) || Double.isInfinite(now)) throw new IllegalArgumentException("sharedPaymentTokenLimits: now must be an epoch-ms time");
        Object t = mandate.get("terms");
        Double bd = num(get(get(mandate, "budget"), "B"));
        double budget = Math.floor(bd == null ? Double.NaN : bd);
        Double thr = num(get(t, "autoApproveThreshold"));
        double max = thr == null ? Double.NaN : Math.min(thr, budget);
        if (!PayJs.isSafeInteger(max) || max <= 0) throw new IllegalArgumentException("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed");
        if (has(t, "periodEnd") && !Double.isFinite(num(get(t, "periodEnd")) == null ? Double.NaN : num(get(t, "periodEnd")))) throw new IllegalArgumentException("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time");
        if (has(t, "periodEnd") && !(now < num(get(t, "periodEnd")))) throw new IllegalArgumentException("sharedPaymentTokenLimits: the mandate period has ended");
        Map<String, Object> out = map("currency", ((String) get(t, "currency")).toLowerCase(Locale.ROOT), "max_amount", jn(max));
        if (has(t, "periodEnd")) out.put("expires_at", jn(Math.floor(num(get(t, "periodEnd")) / 1000)));
        return out;
    }

    // ---- rail limits -----------------------------------------------------------------------------------------------------

    /** The MCC codes named by {@code mcc.cNNNN} traits, sorted and de-duplicated. */
    public static List<Object> categoriesFromTraits(List<?> traits) {
        TreeSet<String> out = new TreeSet<>();
        for (Object t : traits) {
            if (!(t instanceof String)) continue;
            Matcher m = MCC_TRAIT_RE.matcher((String) t);
            if (m.matches()) out.add(m.group(1));
        }
        return new ArrayList<Object>(out);
    }

    /**
     * The limits an instrument for this mandate may carry. {@code opts}: actionTraits (list of strings) and allowAnyCategory (boolean).
     * No autonomous capacity left throws; an empty category intersection throws; with no category control the call is refused unless allowAnyCategory.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> railLimits(Map<String, Object> mandate, double now, Map<String, Object> opts) {
        Map<String, Object> spt = sharedPaymentTokenLimits(mandate, now);
        double total = Math.floor(num(get(get(mandate, "budget"), "B")));
        List<Object> fromMandate = new ArrayList<>((List<Object>) get(mandate.get("terms"), "categories"));
        Object at = opts == null ? null : opts.get("actionTraits");
        List<Object> fromTraits = categoriesFromTraits(at == null ? new ArrayList<Object>() : (List<?>) at);
        List<Object> categories;
        if (!fromMandate.isEmpty() && !fromTraits.isEmpty()) {
            categories = new ArrayList<>();
            for (Object c : fromMandate) if (fromTraits.contains(c)) categories.add(c);
            sortStrings(categories);
            if (categories.isEmpty()) throw new IllegalArgumentException("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent");
        } else {
            categories = new ArrayList<>(!fromMandate.isEmpty() ? fromMandate : fromTraits);
            sortStrings(categories);
        }
        if (categories.isEmpty() && !Boolean.TRUE.equals(opts == null ? null : opts.get("allowAnyCategory")))
            throw new IllegalArgumentException("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category");
        Map<String, Object> out = map("currency", ((String) get(mandate.get("terms"), "currency")).toUpperCase(Locale.ROOT), "perAuthorizationMax", spt.get("max_amount"),
            "totalMax", jn(total), "categories", categories, "merchants", new ArrayList<>((List<Object>) get(mandate.get("terms"), "merchants")));
        if (spt.containsKey("expires_at")) out.put("expiresAt", jn(num(spt.get("expires_at")) * 1000));
        return out;
    }

    private static void sortStrings(List<Object> l) { Collections.sort(l, (a, b) -> ((String) a).compareTo((String) b)); }

    // ---- the real-time authorization callback ----------------------------------------------------------------------------

    /** The instrument a rail request is for. */
    public static final class InstrumentBinding {
        public final Map<String, Object> mandate;
        /** The grant the caller verified or loaded from its own store. */
        public final Object grant;
        /** Budget store key; null = the grant hash. */
        public final String budgetKey;

        public InstrumentBinding(Map<String, Object> mandate, Object grant, String budgetKey) {
            this.mandate = mandate;
            this.grant = grant;
            this.budgetKey = budgetKey;
        }
    }

    /** A step-up cannot wait at a card terminal: it is declined, and this hook may notify the principal. */
    @FunctionalInterface
    public interface StepUpHook {
        void onStepUp(Map<String, Object> authorization, Map<String, Object> decision) throws Exception;
    }

    /** Options of {@link #createRailAuthorizer}. */
    public static final class RailAuthorizerOptions {
        public Function<String, InstrumentBinding> instruments;
        public ChargeBudgetStore store;
        public Payments.Decider decider;
        /** Answer by this many ms or decline (default 1500). */
        public double latencyBudgetMs = 1500;
        public LongSupplier now = System::currentTimeMillis;
        public StepUpHook onStepUp;
    }

    private static Map<String, Object> decline(String... reasons) {
        List<Object> r = new ArrayList<>();
        for (String s : reasons) r.add(s);
        return map("approved", false, "reasons", r);
    }

    private static Map<String, Object> decideRail(RailAuthorizerOptions opts, Map<String, Object> a) {
        if (a == null || !(a.get("id") instanceof String) || !(a.get("instrumentId") instanceof String) || ((String) a.get("id")).isEmpty()) return decline("malformed_authorization");
        if (!PayJs.isSafeInteger(a.get("amount")) || num(a.get("amount")) <= 0) return decline("amount_not_positive_minor_units");
        if (!(a.get("currency") instanceof String) || ((String) a.get("currency")).isEmpty()) return decline("currency_missing");
        if (!(a.get("merchantId") instanceof String) || ((String) a.get("merchantId")).isEmpty()) return decline("merchant_unknown");
        InstrumentBinding inst = opts.instruments.apply((String) a.get("instrumentId"));
        if (inst == null) return decline("instrument_unknown");
        Map<String, Object> charge = map("merchant", a.get("merchantId"), "amount", a.get("amount"), "currency", ((String) a.get("currency")).toUpperCase(Locale.ROOT));
        if (has(a, "mcc")) charge.put("category", a.get("mcc"));
        charge.put("now", jn(opts.now.getAsLong()));
        Map<String, Object> d = Payments.authorizeChargeAtomic(inst.mandate, charge, inst.grant, opts.store, inst.budgetKey, opts.decider);
        Object outcome = d.get("outcome");
        if ("auto".equals(outcome)) return map("approved", true, "reasons", new ArrayList<Object>(), "decision", d);
        List<Object> dr = d.get("reasons") instanceof List ? (List<Object>) d.get("reasons") : new ArrayList<Object>();
        if ("step_up".equals(outcome)) {
            try { if (opts.onStepUp != null) opts.onStepUp.onStepUp(a, d); } catch (Exception e) { /* a failing notifier must not change the answer */ }
            List<Object> r = new ArrayList<>();
            r.add("step_up_required");
            r.addAll(dr);
            return map("approved", false, "reasons", r, "decision", d);
        }
        List<Object> r = new ArrayList<>(dr);
        if (r.isEmpty()) r.add("denied");
        return map("approved", false, "reasons", r, "decision", d);
    }

    /** The single code path from a rail request to a PCA decision. Total: every failure (including a timeout) is a decline. */
    public static Function<Map<String, Object>, Map<String, Object>> createRailAuthorizer(RailAuthorizerOptions opts) {
        double budgetMs = opts.latencyBudgetMs;
        if (Double.isNaN(budgetMs) || Double.isInfinite(budgetMs) || budgetMs <= 0) throw new IllegalArgumentException("createRailAuthorizer: latencyBudgetMs must be positive");
        return a -> {
            CompletableFuture<Map<String, Object>> f = CompletableFuture.supplyAsync(() -> {
                try { return decideRail(opts, a); } catch (Throwable t) { return decline("authorizer_error"); }
            });
            try {
                // shortcut: a decision that finishes after the timeout may still have debited the budget with no approval sent (under-spend, the safe direction)
                return f.get((long) Math.ceil(budgetMs), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                f.cancel(true);
                return decline("latency_budget_exceeded");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return decline("authorizer_error");
            } catch (ExecutionException e) {
                return decline("authorizer_error");
            }
        };
    }

    // ---- settlement ------------------------------------------------------------------------------------------------------

    /**
     * Compare what settled with what PCA approved. {@code {ok: true}} only on an exact fit; any excess, a different merchant or currency, or a second
     * capture is {@code {ok: false, reasons, action: "freeze_grant"}}. No classifier; the caller applies the action.
     */
    public static Map<String, Object> reconcileSettlement(Map<String, Object> approved, Map<String, Object> s) {
        List<Object> reasons = new ArrayList<>();
        if (!java.util.Objects.equals(s.get("authorizationId"), approved.get("id"))) reasons.add("authorization_id_mismatch");
        if (gt(s.get("amount"), approved.get("amount"))) reasons.add("settled_more_than_approved");
        if (!((String) s.get("currency")).toUpperCase(Locale.ROOT).equals(((String) approved.get("currency")).toUpperCase(Locale.ROOT))) reasons.add("currency_mismatch");
        if (!java.util.Objects.equals(s.get("merchantId"), approved.get("merchantId"))) reasons.add("merchant_mismatch");
        if (gt(s.get("captures"), new Json.Num("1"))) reasons.add("second_capture");
        return reasons.isEmpty() ? map("ok", true) : map("ok", false, "reasons", reasons, "action", "freeze_grant");
    }

    private static boolean gt(Object a, Object b) { return PayJs.toNumber(a) > PayJs.toNumber(b); }

    // ---- Stripe Issuing --------------------------------------------------------------------------------------------------

    /**
     * The form parameters for {@code POST /v1/issuing/cards} (virtual, active) that carry the rail limits. Throws if an MCC has no Stripe category
     * name. {@code categoryNames} maps MCC to the Stripe name; {@code metadata} may be null.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> stripeCardParams(Map<String, Object> limits, Map<String, String> categoryNames, String cardholder, Map<String, String> metadata) {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("cardholder", cardholder);
        p.put("type", "virtual");
        p.put("status", "active");
        p.put("currency", ((String) limits.get("currency")).toLowerCase(Locale.ROOT));
        p.put("spending_controls[spending_limits][0][amount]", str(limits.get("perAuthorizationMax")));
        p.put("spending_controls[spending_limits][0][interval]", "per_authorization");
        p.put("spending_controls[spending_limits][1][amount]", str(limits.get("totalMax")));
        p.put("spending_controls[spending_limits][1][interval]", "all_time");
        List<Object> cats = (List<Object>) limits.get("categories");
        for (int i = 0; i < cats.size(); i++) {
            String mcc = (String) cats.get(i);
            String name = categoryNames.get(mcc);
            if (name == null) throw new IllegalArgumentException("stripeCardParams: no Stripe category name for MCC " + mcc);
            p.put("spending_controls[allowed_categories][" + i + "]", name);
        }
        if (metadata != null) for (Map.Entry<String, String> e : metadata.entrySet()) p.put("metadata[" + e.getKey() + "]", e.getValue());
        return p;
    }

    private static final Pattern T_RE = Pattern.compile("[0-9]{1,12}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");

    private static byte[] hmac(String secret, String payload) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Json.utf8(secret), "HmacSHA256"));
        return mac.doFinal(Json.utf8(payload));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    private static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** Verify a {@code Stripe-Signature} header over the RAW body. Total; false on anything malformed, stale (beyond tolerance) or mismatched. */
    public static boolean verifyStripeSignature(String rawBody, String header, String secret, double nowSec, double toleranceSec) {
        try {
            if (rawBody == null || header == null || secret == null || secret.isEmpty() || !(Double.isFinite(toleranceSec) && toleranceSec > 0)) return false;
            String t = null;
            List<String> v1 = new ArrayList<>();
            for (String part : header.split(",", -1)) {
                int i = part.indexOf('=');
                if (i < 0) continue;
                String k = PayJs.jsTrim(part.substring(0, i));
                String v = PayJs.jsTrim(part.substring(i + 1));
                if (k.equals("t")) t = v;
                else if (k.equals("v1")) v1.add(v);
            }
            if (t == null || !T_RE.matcher(t).matches() || v1.isEmpty()) return false;
            if (!(Math.abs(nowSec - Double.parseDouble(t)) <= toleranceSec)) return false;
            byte[] want = hmac(secret, t + "." + rawBody);
            boolean ok = false;
            for (String sig : v1) if (HEX64.matcher(sig).matches() && MessageDigest.isEqual(unhex(sig), want)) ok = true;
            return ok;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyStripeSignature(String rawBody, String header, String secret, double nowSec) {
        return verifyStripeSignature(rawBody, header, secret, nowSec, STRIPE_WEBHOOK_TOLERANCE_SEC);
    }

    /** The header Stripe would send (tests and local tooling): {@code t=<tSec>,v1=<hex hmac>}. */
    public static String signStripePayload(String rawBody, String secret, long tSec) {
        try {
            return "t=" + tSec + ",v1=" + hex(hmac(secret, tSec + "." + rawBody));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> obj(Object v) { return v instanceof Map ? copy(v) : null; }

    /** Normalise an {@code issuing_authorization.request} event; null when it is not a well-formed request with a pending amount. */
    public static Map<String, Object> stripeAuthorizationFromEvent(Object event) {
        Map<String, Object> e = obj(event);
        if (e == null || !"issuing_authorization.request".equals(e.get("type"))) return null;
        Map<String, Object> a = obj(get(obj(e.get("data")), "object"));
        Map<String, Object> pending = obj(get(a, "pending_request"));
        Map<String, Object> card = obj(get(a, "card"));
        Map<String, Object> merchant = obj(get(a, "merchant_data"));
        if (a == null || pending == null || !(a.get("id") instanceof String) || card == null || !(card.get("id") instanceof String)) return null;
        Object amount = pending.get("amount");
        Object currency = pending.get("currency");
        if (num(amount) == null || !(currency instanceof String)) return null;
        Map<String, Object> out = map("id", a.get("id"), "instrumentId", card.get("id"), "amount", amount, "currency", currency);
        Object nid = get(merchant, "network_id");
        if (nid instanceof String && !((String) nid).isEmpty()) out.put("merchantId", nid);
        Object cc = get(merchant, "category_code");
        if (cc instanceof String) out.put("mcc", cc);
        return out;
    }

    /** Normalise an {@code issuing_transaction.created} capture into a settlement (a capture amount is negative in Stripe's ledger); null otherwise. */
    public static Map<String, Object> stripeSettlementFromTransaction(Object txn) {
        Map<String, Object> t = obj(txn);
        Map<String, Object> m = obj(get(t, "merchant_data"));
        if (t == null || !"capture".equals(t.get("type")) || !(t.get("authorization") instanceof String) || num(t.get("amount")) == null || !(t.get("currency") instanceof String)) return null;
        Map<String, Object> out = map("authorizationId", t.get("authorization"), "amount", jn(-num(t.get("amount"))), "currency", t.get("currency"));
        if (get(m, "network_id") instanceof String) out.put("merchantId", get(m, "network_id"));
        out.put("captures", new Json.Num("1"));
        return out;
    }

    /** Options of {@link #stripeIssuingWebhook}. */
    public static final class StripeWebhookOptions {
        /** The endpoint's signing secret. */
        public String secret;
        /** Normally the function {@link #createRailAuthorizer} returned. */
        public Function<Map<String, Object>, Map<String, Object>> authorize;
        public String stripeVersion = STRIPE_API_VERSION;
        public java.util.function.DoubleSupplier nowSec = () -> Math.floor(System.currentTimeMillis() / 1000.0);
        public double toleranceSec = STRIPE_WEBHOOK_TOLERANCE_SEC;
    }

    private static Map<String, Object> reply(int status, String body, String version) {
        return map("status", jn(status), "headers", map("Stripe-Version", version, "Content-Type", "application/json"), "body", body);
    }

    /**
     * The handler body for the {@code issuing_authorization.request} endpoint: a bad signature is 400 (nothing is decided), a request event gets 200
     * {@code {approved}} from the PCA decision, any other event type gets 200 {@code {}}. {@code amount} is never sent. Returns {@code {status, headers, body}}.
     */
    public static Map<String, Object> stripeIssuingWebhook(StripeWebhookOptions opts, String rawBody, String signature) {
        String version = opts.stripeVersion;
        if (!verifyStripeSignature(rawBody, signature, opts.secret, opts.nowSec.getAsDouble(), opts.toleranceSec)) return reply(400, "{\"error\":\"bad_signature\"}", version);
        Object event;
        try { event = Json.parseNoDuplicates(rawBody); } catch (RuntimeException e) { return reply(400, "{\"error\":\"bad_json\"}", version); }
        Map<String, Object> ev = obj(event);
        if (ev == null || !"issuing_authorization.request".equals(ev.get("type"))) return reply(200, "{}", version);
        Map<String, Object> auth = stripeAuthorizationFromEvent(event);
        if (auth == null) return reply(200, "{\"approved\":false}", version);
        Map<String, Object> v = opts.authorize.apply(auth);
        return reply(200, Boolean.TRUE.equals(v.get("approved")) ? "{\"approved\":true}" : "{\"approved\":false}", version);
    }
}
