package net.atlasauth.pca.acp;

import static net.atlasauth.pca.acp.AcpJs.def;
import static net.atlasauth.pca.acp.AcpJs.get;
import static net.atlasauth.pca.acp.AcpJs.isInt;
import static net.atlasauth.pca.acp.AcpJs.isObj;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Stripe Shared Payment Granted Tokens: reads and checks the {@code shared_payment.granted_token} object and relates it to a PCA delegated
 * payment token. No I/O; whether Stripe accepts a token is Stripe's decision, these checks only refuse what PCA authority forbids.
 */
public final class StripeSpt {
    private StripeSpt() {}

    public static final String STRIPE_SPT_OBJECT = "shared_payment.granted_token";
    private static final List<String> REASONS = List.of("consumed", "expired", "resolved", "revoked");
    private static final Pattern SPT_ID = Pattern.compile("spt_[A-Za-z0-9_]+");
    private static final Pattern CURRENCY = Pattern.compile("[a-z]{3}");

    private static boolean isCurrency(Object v) { return AcpJs.matches(CURRENCY, v); }

    /** Problems with a Shared Payment Granted Token object (empty = well formed). */
    public static List<String> stripeSptProblems(Object t) {
        List<String> p = new ArrayList<>();
        if (!isObj(t)) { p.add("the token must be an object"); return p; }
        if (!STRIPE_SPT_OBJECT.equals(get(t, "object"))) p.add("object must be \"" + STRIPE_SPT_OBJECT + "\"");
        if (!AcpJs.matches(SPT_ID, get(t, "id"))) p.add("id must be an spt_ identifier");
        if (!isInt(get(t, "created"))) p.add("created must be an integer timestamp");
        if (!(get(t, "livemode") instanceof Boolean)) p.add("livemode must be a boolean");
        Object da = get(t, "deactivated_at");
        if (!(def(t, "deactivated_at") && da == null) && !isInt(da)) p.add("deactivated_at must be null or an integer timestamp");
        Object dr = get(t, "deactivated_reason");
        if (!(def(t, "deactivated_reason") && dr == null) && !(dr instanceof String && REASONS.contains(dr))) p.add("deactivated_reason must be null or one of consumed, expired, resolved, revoked");
        Object u = get(t, "usage_limits");
        if (!isObj(u)) p.add("usage_limits is required");
        else {
            if (!isCurrency(get(u, "currency"))) p.add("usage_limits.currency must be a lowercase three-letter code");
            Object max = get(u, "max_amount");
            if (!isInt(max) || JsVal.num(max) < 0) p.add("usage_limits.max_amount must be a non-negative integer in minor units");
            if (get(u, "expires_at") != null && !isInt(get(u, "expires_at"))) p.add("usage_limits.expires_at must be an integer timestamp");
        }
        Object ud = get(t, "usage_details");
        if (ud != null) {
            Object c = isObj(ud) ? get(ud, "amount_captured") : null;
            if (!isObj(c) || !isInt(get(c, "value")) || JsVal.num(get(c, "value")) < 0 || !isCurrency(get(c, "currency"))) p.add("usage_details.amount_captured needs a non-negative integer value and a lowercase currency");
        }
        for (String k : new String[] {"payment_method_details", "agent_details", "shared_metadata"}) {
            if (get(t, k) != null && !isObj(get(t, k))) p.add(k + " must be null or an object");
        }
        Object pm = get(t, "payment_method_details");
        if (isObj(pm) && !(get(pm, "type") instanceof String)) p.add("payment_method_details.type must be a string");
        return p;
    }

    /** Parse a Shared Payment Granted Token; throws IllegalArgumentException listing every problem. */
    public static Map<String, Object> parseStripeSpt(Object t) {
        List<String> problems = stripeSptProblems(t);
        if (!problems.isEmpty()) throw new IllegalArgumentException("stripe spt: " + String.join("; ", problems));
        return JsVal.map(t);
    }

    private static Map<String, Object> ok() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.TRUE);
        return m;
    }

    private static Map<String, Object> no(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }

    /**
     * Can this token still be used for this capture? {@code use} = {now (epoch seconds), amount (minor units), currency, livemode? (default true)}.
     * Refuses a malformed or deactivated or expired token, the wrong mode, another currency, a non-integer amount and one above
     * max_amount minus what was already captured. Returns {ok} or {ok:false, reason}.
     */
    public static Map<String, Object> stripeSptUsable(Object t, Map<String, Object> use) {
        List<String> problems = stripeSptProblems(t);
        if (!problems.isEmpty()) return no("malformed token: " + problems.get(0));
        Map<String, Object> spt = JsVal.map(t);
        Object now = use.get("now"), amount = use.get("amount");
        if (!isInt(now) || !isInt(amount) || JsVal.num(amount) <= 0) return no("now and amount must be integers and the amount positive");
        Object live = use.get("livemode") != null ? use.get("livemode") : Boolean.TRUE;
        if (!live.equals(spt.get("livemode"))) return no("the token is in the wrong mode");
        if (spt.get("deactivated_reason") != null) return no("the token is deactivated (" + spt.get("deactivated_reason") + ")");
        if (spt.get("deactivated_at") != null && !(JsVal.num(spt.get("deactivated_at")) > JsVal.num(now))) return no("the token is deactivated");
        Map<String, Object> lim = JsVal.map(spt.get("usage_limits"));
        Object exp = lim.get("expires_at");
        if (JsVal.isNumber(exp) && !(JsVal.num(now) < JsVal.num(exp))) return no("the token has expired");
        if (!(use.get("currency") instanceof String)) throw new IllegalArgumentException("use.currency must be a string");
        if (!lim.get("currency").equals(((String) use.get("currency")).toLowerCase(Locale.ROOT))) return no("the capture currency differs from the token currency");
        Map<String, Object> captured = spt.get("usage_details") == null ? null : JsVal.map(JsVal.map(spt.get("usage_details")).get("amount_captured"));
        if (captured != null && !captured.get("currency").equals(lim.get("currency"))) return no("the captured amount is in another currency");
        long remaining = AcpJs.lng(lim.get("max_amount")) - (captured != null ? AcpJs.lng(captured.get("value")) : 0L);
        if (JsVal.num(amount) > remaining) return no("the amount " + AcpJs.str(amount) + " exceeds the remaining " + remaining);
        return ok();
    }

    /**
     * The {@code usage_limits} to request for a PCA authority {maxAmount, currency, expiresAtMs?}: lowercase currency, integer minor units,
     * expiry in whole seconds (rounded down). Throws IllegalArgumentException for an invalid authority.
     */
    public static Map<String, Object> stripeUsageLimitsFor(Map<String, Object> authority) {
        Object max = authority.get("maxAmount");
        if (!(AcpJs.isSafeInteger(max) && JsVal.num(max) > 0)) throw new IllegalArgumentException("stripe spt: maxAmount must be a positive integer in minor units");
        if (!(authority.get("currency") instanceof String) || !((String) authority.get("currency")).matches("[A-Za-z]{3}")) throw new IllegalArgumentException("stripe spt: currency must be a three-letter code");
        boolean hasExp = def(authority, "expiresAtMs");
        Double e = JsVal.num(authority.get("expiresAtMs"));
        if (hasExp && !(e != null && !Double.isNaN(e) && !Double.isInfinite(e) && e > 0)) throw new IllegalArgumentException("stripe spt: expiresAtMs must be a positive epoch-ms time");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("currency", ((String) authority.get("currency")).toLowerCase(Locale.ROOT));
        out.put("max_amount", max);
        if (hasExp) out.put("expires_at", AcpJs.num((long) Math.floor(e / 1000)));
        return out;
    }

    /** {@code claims[k]} when it is a finite JavaScript number, else null. */
    private static Double finiteClaim(Map<String, Object> claims, String k) {
        Object v = claims.get(k);
        Double d = JsVal.isNumber(v) ? JsVal.num(v) : null;
        return d != null && Double.isFinite(d) ? d : null;
    }

    /**
     * A Shared Payment Token may be no wider than the delegated payment token it serves: same currency, max_amount not above the delegated
     * amount, and an expiry present and not after the delegated token's. {@code claims} = {amount, currency, exp (epoch ms)}.
     */
    public static Map<String, Object> stripeSptWithinClaims(Object t, Map<String, Object> claims) {
        List<String> problems = stripeSptProblems(t);
        if (!problems.isEmpty()) return no("malformed token: " + problems.get(0));
        Map<String, Object> lim = JsVal.map(JsVal.map(t).get("usage_limits"));
        if (!(claims.get("currency") instanceof String)) throw new IllegalArgumentException("claims.currency must be a string");
        if (!lim.get("currency").equals(((String) claims.get("currency")).toLowerCase(Locale.ROOT))) return no("the token currency differs from the delegated currency");
        // Number.isFinite is strict: a string, array or missing claim is not a finite number (no coercion), and a missing one prints as undefined
        Double amount = finiteClaim(claims, "amount"), exp = finiteClaim(claims, "exp");
        if (!(amount != null && AcpJs.dbl(lim.get("max_amount")) <= amount)) return no("max_amount " + AcpJs.str(lim.get("max_amount")) + " exceeds the delegated amount " + (AcpJs.def(claims, "amount") ? AcpJs.str(claims.get("amount")) : "undefined"));
        if (!JsVal.isNumber(lim.get("expires_at"))) return no("the token has no expiry");
        if (!(exp != null && AcpJs.dbl(lim.get("expires_at")) * 1000 <= exp)) return no("the token outlives the delegated payment token");
        return ok();
    }
}
