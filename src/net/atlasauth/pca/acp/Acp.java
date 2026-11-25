package net.atlasauth.pca.acp;

import static net.atlasauth.pca.acp.AcpJs.def;
import static net.atlasauth.pca.acp.AcpJs.dbl;
import static net.atlasauth.pca.acp.AcpJs.isAmount;
import static net.atlasauth.pca.acp.AcpJs.num;
import static net.atlasauth.pca.acp.AcpJs.str;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Agentic Commerce Protocol (ACP) and x402 for PCA. PCA governs; ACP mints the delegated one-time payment token; x402 (HTTP 402) is the pay
 * rail. A delegated payment token is a JWS minted FROM a PCActn and carries that proof's authority by reference (its digest); the proof's
 * capability caveats (spend cap, merchant / category allowlist, human-present) gate issuance. At settlement the token's
 * session / merchant / amount / expiry binding is re-checked and the bound PCActn can be re-verified, failing closed.
 *
 * <p>Values are parsed JSON (Map, List, String, Boolean, Json.Num, null) and option bags are Maps keyed by the reference's option names, so a
 * reader can map every call one to one. Keys are public JWK maps ({@code signingKey} private, {@code verifyKey} public). The reference's async
 * calls are plain blocking calls here. See {@link X402V2}, {@link X402Http} and {@link StripeSpt} for the rest of the package surface.
 */
public final class Acp {
    private Acp() {}

    public static final int ACP_DELEGATED_TOKEN_VERSION = 1;
    public static final String ACP_DELEGATED_TOKEN_TYPE = "acp-delegated-payment";
    public static final String SPEND_CAP_CAVEAT = "max_amount";
    public static final String MERCHANT_ALLOW_CAVEAT = "merchant_allow";
    public static final String MERCHANT_CATEGORY_CAVEAT = "merchant_category";
    public static final String HUMAN_PRESENT_CAVEAT = "human_present";

    /** Thrown when a delegated payment token cannot be minted because the request exceeds the proof's authority. */
    public static final class AcpAuthorityException extends RuntimeException {
        public AcpAuthorityException(String message) { super(message); }
    }

    /** Atomic first-use claim: true exactly once per jti (a conditional insert). A throw fails closed. */
    @FunctionalInterface
    public interface SingleUseStore { boolean claim(String jti, double expiresAtMs) throws Exception; }

    /** An injectable function that verifies an x402 payment payload: {ok, reason?, claims?}. */
    @FunctionalInterface
    public interface X402Verify { Map<String, Object> verify(Object payload) throws Exception; }

    /** An injectable settlement step run once payment is verified; its return value becomes the receipt (null = none). */
    @FunctionalInterface
    public interface X402Settler { Object settle(Object payload, Map<String, Object> claims) throws Exception; }

    // ---- caveat builders ----

    public static Map<String, Object> spendCapCaveat(long max) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", SPEND_CAP_CAVEAT);
        m.put("max", num(max));
        return m;
    }

    public static Map<String, Object> spendCapCaveat(long max, String currency) {
        Map<String, Object> m = spendCapCaveat(max);
        m.put("currency", currency);
        return m;
    }

    public static Map<String, Object> merchantAllowCaveat(List<String> merchants) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", MERCHANT_ALLOW_CAVEAT);
        m.put("merchants", new ArrayList<Object>(merchants));
        return m;
    }

    public static Map<String, Object> merchantCategoryCaveat(List<String> categories) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", MERCHANT_CATEGORY_CAVEAT);
        m.put("categories", new ArrayList<Object>(categories));
        return m;
    }

    public static Map<String, Object> humanPresentCaveat(boolean required) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", HUMAN_PRESENT_CAVEAT);
        m.put("required", required);
        return m;
    }

    public static Map<String, Object> humanPresentCaveat() { return humanPresentCaveat(true); }

    // ---- payment authority ----

    private static List<Object> asStringArray(Object v, String label) {
        if (!JsVal.allStrings(v)) throw new AcpAuthorityException("malformed " + label + " caveat: expected a string[] (fail closed)");
        return JsVal.list(v);
    }

    /**
     * Collapse a leaf capability's cumulative caveat list into its effective payment authority {maxAmount?, currency?, merchants (list or null),
     * categories (list or null), humanPresentRequired}. Payment caveats combine conjunctively (tightest cap, intersected allowlists, sticky
     * human-present); a malformed PAYMENT caveat throws AcpAuthorityException (fail closed); any other caveat type is ignored.
     */
    public static Map<String, Object> extractPaymentAuthority(Object caveats) {
        if (caveats instanceof String) caveats = List.of(); // a string iterates as one-character strings, none of which is a caveat object
        if (!(caveats instanceof List)) throw new IllegalArgumentException("caveats must be an array"); // not iterable: the reference throws a TypeError
        Long maxAmount = null;
        String currency = null;
        List<Object> merchants = null, categories = null;
        boolean humanPresentRequired = false;
        for (Object c : (List<?>) caveats) {
            if (c == null) throw new IllegalArgumentException("caveat is null");
            Object type = AcpJs.get(c, "type");
            if (!(type instanceof String)) continue;
            switch ((String) type) {
                case SPEND_CAP_CAVEAT: {
                    Object max = AcpJs.get(c, "max");
                    if (!AcpJs.isSafeInteger(max) || JsVal.num(max) < 0 || JsVal.isNegZero(max)) {
                        throw new AcpAuthorityException("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)");
                    }
                    long m = AcpJs.lng(max);
                    maxAmount = maxAmount == null ? m : Math.min(maxAmount, m);
                    if (def(c, "currency")) {
                        Object cur = AcpJs.get(c, "currency");
                        if (!AcpJs.nonEmpty(cur)) throw new AcpAuthorityException("malformed max_amount caveat: currency must be a non-empty string (fail closed)");
                        if (currency != null && !currency.equals(cur)) throw new AcpAuthorityException("conflicting spend-cap currencies \"" + currency + "\" vs \"" + cur + "\" (fail closed)");
                        currency = (String) cur;
                    }
                    break;
                }
                case MERCHANT_ALLOW_CAVEAT: {
                    List<Object> list = asStringArray(AcpJs.get(c, "merchants"), "merchant_allow");
                    merchants = merchants == null ? new ArrayList<>(new LinkedHashSet<>(list)) : intersect(merchants, list);
                    break;
                }
                case MERCHANT_CATEGORY_CAVEAT: {
                    List<Object> list = asStringArray(AcpJs.get(c, "categories"), "merchant_category");
                    categories = categories == null ? new ArrayList<>(new LinkedHashSet<>(list)) : intersect(categories, list);
                    break;
                }
                case HUMAN_PRESENT_CAVEAT: {
                    Object req = AcpJs.get(c, "required");
                    if (!(req instanceof Boolean)) throw new AcpAuthorityException("malformed human_present caveat: required must be a boolean (fail closed)");
                    humanPresentRequired = humanPresentRequired || (Boolean) req;
                    break;
                }
                default:
                    break; // non-payment caveat (ttl, scope, resource, ...): not this adapter's concern
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (maxAmount != null) out.put("maxAmount", num(maxAmount));
        if (currency != null) out.put("currency", currency);
        out.put("merchants", merchants);
        out.put("categories", categories);
        out.put("humanPresentRequired", humanPresentRequired);
        return out;
    }

    private static List<Object> intersect(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>();
        for (Object x : a) if (b.contains(x)) out.add(x);
        return out;
    }

    private static Map<String, Object> check(boolean ok, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /**
     * Check a purchase request {amount, currency, merchant, category?, humanPresent?} against a payment authority (the output of
     * {@link #extractPaymentAuthority}). Pure and fail-closed. Returns {ok} or {ok:false, reason}.
     */
    public static Map<String, Object> checkPaymentAuthority(Map<String, Object> authority, Map<String, Object> request) {
        Object amount = request.get("amount");
        if (!isAmount(amount)) return check(false, "amount must be a positive integer in minor units");
        if (!AcpJs.nonEmpty(request.get("currency"))) return check(false, "currency must be a non-empty string");
        if (!AcpJs.nonEmpty(request.get("merchant"))) return check(false, "merchant must be a non-empty string");
        Object currency = request.get("currency"), merchant = request.get("merchant");
        if (def(authority, "currency") && !Objects.equals(authority.get("currency"), currency)) {
            return check(false, "currency \"" + currency + "\" is not the authorized currency \"" + str(authority.get("currency")) + "\"");
        }
        if (def(authority, "maxAmount") && !(AcpJs.isInt(authority.get("maxAmount")) && dbl(authority.get("maxAmount")) >= 0)) return check(false, "authorized spend cap is not a non-negative integer (fail closed)");
        if (def(authority, "maxAmount") && !(dbl(amount) <= dbl(authority.get("maxAmount")))) {
            return check(false, "amount " + str(amount) + " exceeds the authorized spend cap " + str(authority.get("maxAmount")));
        }
        Object merchants = authority.get("merchants");
        if (merchants != null && !((List<?>) merchants).contains(merchant)) return check(false, "merchant \"" + merchant + "\" is not in the authorized allowlist");
        Object categories = authority.get("categories");
        if (categories != null) {
            if (!def(request, "category")) return check(false, "the proof constrains merchant categories but no category was supplied");
            Object cat = request.get("category");
            if (!((List<?>) categories).contains(cat)) return check(false, "category \"" + str(cat) + "\" is not in the authorized allowlist");
        }
        if (Boolean.TRUE.equals(authority.get("humanPresentRequired")) && !Boolean.TRUE.equals(request.get("humanPresent"))) {
            return check(false, "the proof requires a human-present charge but humanPresent was not asserted");
        }
        return check(true, null);
    }

    // ---- authority reference ----

    private static Map<String, Object> leafCapability(Object pcActn) {
        Object chain = AcpJs.get(pcActn, "cap_chain");
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) throw new AcpAuthorityException("PCActn carries no capability chain (fail closed)");
        List<?> l = (List<?>) chain;
        Object leaf = l.get(l.size() - 1);
        if (!(leaf instanceof Map)) throw new IllegalArgumentException("capability chain leaf is not an object");
        return JsVal.map(leaf);
    }

    private static void copy(Map<String, Object> to, String key, Object from, String fromKey) {
        if (def(from, fromKey)) to.put(key, AcpJs.get(from, fromKey));
    }

    private static Map<String, Object> authorityRef(Object pcActn) {
        Map<String, Object> leaf = leafCapability(pcActn);
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("digest", Pca.hashCanonical(pcActn));
        copy(ref, "aud", pcActn, "aud");
        copy(ref, "grant_ref", pcActn, "grant_ref");
        copy(ref, "leaf_holder", leaf, "holder");
        Object action = AcpJs.get(pcActn, "action");
        if (action == null) throw new IllegalStateException("TypeError: Cannot read properties of " + (def(pcActn, "action") ? "null" : "undefined") + " (reading 'verb')");
        copy(ref, "verb", action, "verb");
        copy(ref, "resource", action, "resource");
        copy(ref, "params_digest", action, "params_digest");
        return ref;
    }

    private static double nowOf(Map<String, Object> opts) {
        Double n = JsVal.num(opts.get("now"));
        return n != null && !Double.isNaN(n) && !Double.isInfinite(n) ? n : (double) System.currentTimeMillis();
    }

    private static Object nowValue(Map<String, Object> opts) {
        Double n = JsVal.num(opts.get("now"));
        return n != null && !Double.isNaN(n) && !Double.isInfinite(n) ? opts.get("now") : (Object) num(System.currentTimeMillis());
    }

    // ---- mint ----

    /**
     * Mint a one-time ACP delegated payment token (a JWS) FROM a PCActn. {@code opts}: amount, currency, merchant, session, expiresAt (epoch ms),
     * paymentMethod {type, display?, token?}, signingKey (private JWK), alg (default EdDSA), category?, humanPresent?, issuer?, kid?, jti?, now?.
     * The PCActn's caveats gate issuance: throws AcpAuthorityException when the request exceeds the proof's authority or the expiry is in the past
     * or outlives the proof. The token carries the proof only by digest.
     */
    public static String mintDelegatedPaymentToken(Object pcActn, Map<String, Object> opts) {
        Object nowV = nowValue(opts);
        double now = nowOf(opts);

        Map<String, Object> authority = extractPaymentAuthority(leafCapability(pcActn).get("caveats"));
        Map<String, Object> request = new LinkedHashMap<>();
        for (String k : new String[] {"amount", "currency", "merchant", "category", "humanPresent"}) if (def(opts, k)) request.put(k, opts.get(k));
        Map<String, Object> chk = checkPaymentAuthority(authority, request);
        if (!Boolean.TRUE.equals(chk.get("ok"))) throw new AcpAuthorityException("refused: " + (chk.get("reason") != null ? chk.get("reason") : "request exceeds the proof authority"));

        Double exp = JsVal.num(opts.get("expiresAt"));
        if (exp == null || Double.isNaN(exp) || Double.isInfinite(exp)) throw new AcpAuthorityException("refused: expiresAt must be a finite epoch-ms timestamp");
        if (!(exp > now)) throw new AcpAuthorityException("refused: expiresAt is not in the future");
        if (!(Double.isFinite(AcpJs.dblField(pcActn, "exp")) && exp <= AcpJs.dblField(pcActn, "exp"))) throw new AcpAuthorityException("refused: token expiry " + str(opts.get("expiresAt")) + " would outlive the proof's exp " + str(AcpJs.get(pcActn, "exp")));
        if (!JsVal.truthy(opts.get("session"))) throw new AcpAuthorityException("refused: a session id is required");

        Map<String, Object> pca = authorityRef(pcActn);
        Object jti = opts.get("jti");
        if (jti == null) {
            Map<String, Object> seed = new LinkedHashMap<>(JsVal.map(pcActn));
            seed.put("nonce", "acp:" + str(opts.get("session")) + ":" + str(opts.get("merchant")) + ":" + str(opts.get("amount")) + ":" + str(opts.get("currency")) + ":" + str(opts.get("expiresAt")) + ":" + pca.get("digest"));
            jti = Pca.hashCanonical(seed);
        }

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("typ", ACP_DELEGATED_TOKEN_TYPE);
        claims.put("ver", num(ACP_DELEGATED_TOKEN_VERSION));
        claims.put("jti", jti);
        claims.put("session", opts.get("session"));
        claims.put("merchant", opts.get("merchant"));
        claims.put("amount", opts.get("amount"));
        claims.put("currency", opts.get("currency"));
        claims.put("iat", nowV);
        claims.put("exp", opts.get("expiresAt"));
        claims.put("paymentMethod", AcpJs.spread(opts.get("paymentMethod")));
        claims.put("humanPresent", Boolean.TRUE.equals(opts.get("humanPresent")));
        if (def(opts, "category")) claims.put("category", opts.get("category"));
        if (def(opts, "issuer")) claims.put("iss", opts.get("issuer"));
        claims.put("pca", pca);

        String alg = opts.get("alg") != null ? (String) opts.get("alg") : "EdDSA";
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", ACP_DELEGATED_TOKEN_TYPE);
        if (def(opts, "kid")) header.put("kid", opts.get("kid"));
        if (!(opts.get("signingKey") instanceof Map)) throw new IllegalArgumentException("signingKey must be a private JWK");
        return Jose.signJwt(header, claims, JsVal.map(opts.get("signingKey")));
    }

    // ---- verify ----

    private static Map<String, Object> parseClaims(Map<String, Object> c) {
        if (!ACP_DELEGATED_TOKEN_TYPE.equals(c.get("typ")) || !(JsVal.num(c.get("ver")) != null && JsVal.num(c.get("ver")) == ACP_DELEGATED_TOKEN_VERSION)) return null;
        for (String k : new String[] {"jti", "session", "merchant", "currency"}) if (!AcpJs.nonEmpty(c.get(k))) return null;
        if (!isAmount(c.get("amount"))) return null;
        if (!JsVal.isNumber(c.get("iat")) || !JsVal.isNumber(c.get("exp"))) return null;
        if (!(c.get("humanPresent") instanceof Boolean)) return null;
        Object pm = c.get("paymentMethod");
        if (!(pm instanceof Map) || !(((Map<?, ?>) pm).get("type") instanceof String)) return null;
        Object p = c.get("pca");
        if (!(p instanceof Map)) return null;
        for (String k : new String[] {"digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest"}) if (!(((Map<?, ?>) p).get(k) instanceof String)) return null;
        return c;
    }

    private static Map<String, Object> verdict(boolean ok, String reason, Map<String, Object> claims, Map<String, Object> pcaResult) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        if (claims != null) m.put("claims", claims);
        if (pcaResult != null) m.put("pcaResult", pcaResult);
        return m;
    }

    /**
     * Verify a delegated payment token at settlement. {@code opts}: expectedMerchant, amount, verifyKey (public JWK), alg, now, expectedSession,
     * expectedCurrency, pcActn, grant, audience, authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse ({@link SingleUseStore}), strict
     * (default true: requires singleUse and expectedCurrency). Returns {ok, reason?, claims?, pcaResult?}; fails CLOSED on every mismatch.
     */
    public static Map<String, Object> verifyDelegatedPaymentToken(Object token, Map<String, Object> opts) {
        if (!Boolean.FALSE.equals(opts.get("strict"))) {
            if (!(opts.get("singleUse") instanceof SingleUseStore)) return verdict(false, "strict settlement requires a singleUse store (fail closed)", null, null);
            if (!AcpJs.nonEmpty(opts.get("expectedCurrency"))) return verdict(false, "strict settlement requires expectedCurrency (fail closed)", null, null);
        }
        Map<String, Object> res = verifyBinding(token, opts);
        if (!Boolean.TRUE.equals(res.get("ok")) || !def(opts, "singleUse")) return res;
        Map<String, Object> claims = JsVal.map(res.get("claims"));
        boolean first;
        try {
            first = ((SingleUseStore) opts.get("singleUse")).claim((String) claims.get("jti"), dbl(claims.get("exp")));
        } catch (Exception e) {
            return verdict(false, "single-use store unavailable (fail closed)", claims, null);
        }
        return first ? res : verdict(false, "the delegated payment token was already redeemed", claims, null);
    }

    private static Map<String, Object> verifyBinding(Object token, Map<String, Object> opts) {
        Object algO = opts.get("alg") != null ? opts.get("alg") : "EdDSA";
        double now = nowOf(opts);

        Map<String, Object> claims;
        try {
            if (!(algO instanceof String)) throw new Jose.JoseException("\"alg\" (Algorithm) Header Parameter value not allowed");
            String alg = (String) algO;
            Jose.CanonicalJws gate = Jose.assertCanonicalCompactJws(token); // canonical-spelling gate BEFORE signature work
            if (!(opts.get("verifyKey") instanceof Map)) throw new Jose.JoseException("Invalid key input");
            Map<String, Object> verifyKey = new LinkedHashMap<>(JsVal.map(opts.get("verifyKey")));
            verifyKey.remove("d"); // the reference imports a private JWK as a key object, which verifies as its public half
            Jose.compactVerify((String) token, verifyKey, List.of(alg));
            claims = parseClaims(gate.payload);
        } catch (RuntimeException e) {
            return verdict(false, "token signature did not verify: " + e.getMessage(), null, null);
        }
        if (claims == null) return verdict(false, "token payload is not a well-formed delegated payment token", null, null);

        if (!Objects.equals(claims.get("merchant"), opts.get("expectedMerchant"))) {
            return verdict(false, "token merchant \"" + claims.get("merchant") + "\" does not match expected \"" + (def(opts, "expectedMerchant") ? str(opts.get("expectedMerchant")) : "undefined") + "\"", claims, null);
        }
        if (!isAmount(opts.get("amount"))) return verdict(false, "settlement amount must be a positive integer in minor units", claims, null);
        if (!(dbl(opts.get("amount")) <= dbl(claims.get("amount")))) {
            return verdict(false, "settlement amount " + str(opts.get("amount")) + " exceeds the token's authorized amount " + str(claims.get("amount")), claims, null);
        }
        if (!(now <= dbl(claims.get("exp")))) return verdict(false, "the delegated payment token has expired", claims, null);
        if (def(opts, "expectedSession") && !Objects.equals(claims.get("session"), opts.get("expectedSession"))) {
            return verdict(false, "token session \"" + claims.get("session") + "\" does not match expected \"" + str(opts.get("expectedSession")) + "\"", claims, null);
        }
        if (def(opts, "expectedCurrency") && !Objects.equals(claims.get("currency"), opts.get("expectedCurrency"))) {
            return verdict(false, "token currency \"" + claims.get("currency") + "\" does not match expected \"" + str(opts.get("expectedCurrency")) + "\"", claims, null);
        }

        if (def(opts, "grant") && !def(opts, "pcActn")) return verdict(false, "a grant was supplied without the pcActn to re-verify (fail closed)", claims, null);
        if (def(opts, "pcActn")) {
            Object pcActn = opts.get("pcActn");
            if (!Pca.hashCanonical(pcActn).equals(JsVal.map(claims.get("pca")).get("digest"))) {
                return verdict(false, "pcactn_digest mismatch: the supplied proof is not the one that minted this token", claims, null);
            }
            if (def(opts, "grant")) {
                Object roots = opts.get("authorizedPlanRoots");
                List<String> rootList = null;
                if (roots instanceof List) { rootList = new ArrayList<>(); for (Object r : (List<?>) roots) rootList.add(String.valueOf(r)); }
                net.atlasauth.pca.PcaCore.Options co = new net.atlasauth.pca.PcaCore.Options(JsVal.map(opts.get("grant")));
                // an explicit null audience is the opt-out; an omitted one fails closed when the PCActn carries an aud
                if (def(opts, "audience")) { Object aud = opts.get("audience"); if (aud == null) co.audienceAny(); else if (aud instanceof String) co.audience((String) aud); }
                co.nowEpoch = (long) now;
                co.planRoots = Pca.PlanRoots.of(rootList, Boolean.TRUE.equals(opts.get("insecureSkipPlanRootCheck")));
                net.atlasauth.pca.PcaCore.Result v = net.atlasauth.pca.PcaCore.verify(pcActn, co);
                Map<String, Object> pr = new LinkedHashMap<>();
                pr.put("allow", v.allow);
                pr.put("checks", new LinkedHashMap<String, Object>(v.checks));
                if (v.reason != null && !v.reason.isEmpty()) pr.put("reason", v.reason);
                if (!v.allow) return verdict(false, "bound proof failed to verify: " + (v.reason == null || v.reason.isEmpty() ? "denied" : v.reason), claims, pr);
                return verdict(true, null, claims, pr);
            }
        }
        return verdict(true, null, claims, null);
    }

    // ---- x402 v1 ----

    /**
     * Build the HTTP 402 challenge ({status, headers, body}) for a protected resource: the server's {@code accepts} requirement plus the 402 status.
     * {@code opts}: amount, currency (the x402 asset), payTo (both required), network (default base-sepolia), description, scheme (default exact),
     * mimeType, error, maxTimeoutSeconds (default 60). Structural only; no network.
     */
    public static Map<String, Object> x402Challenge(String resource, Map<String, Object> opts) {
        if (!isAmount(opts.get("amount"))) throw new IllegalArgumentException("x402Challenge: amount must be a positive integer in atomic/minor units");
        if (!AcpJs.nonEmpty(opts.get("payTo"))) throw new IllegalArgumentException("x402Challenge: payTo is required");
        if (!AcpJs.nonEmpty(opts.get("currency"))) throw new IllegalArgumentException("x402Challenge: currency (the x402 asset) is required");
        Object timeout = opts.get("maxTimeoutSeconds") != null ? opts.get("maxTimeoutSeconds") : num(60);
        if (!AcpJs.isSafeInteger(timeout) || JsVal.num(timeout) <= 0) throw new IllegalArgumentException("x402Challenge: maxTimeoutSeconds must be a positive integer");
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("maxTimeoutSeconds", timeout);
        req.put("scheme", opts.get("scheme") != null ? opts.get("scheme") : "exact");
        req.put("network", opts.get("network") != null ? opts.get("network") : "base-sepolia");
        req.put("maxAmountRequired", str(opts.get("amount")));
        req.put("resource", resource);
        req.put("description", opts.get("description") != null ? opts.get("description") : "Payment required for " + resource);
        req.put("payTo", opts.get("payTo"));
        req.put("asset", opts.get("currency"));
        req.put("mimeType", opts.get("mimeType") != null ? opts.get("mimeType") : "application/json");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("x402Version", num(1));
        body.put("error", opts.get("error") != null ? opts.get("error") : "X-PAYMENT header is required");
        body.put("accepts", new ArrayList<Object>(List.of(req)));
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", num(402));
        out.put("headers", headers);
        out.put("body", body);
        return out;
    }

    private static Map<String, Object> settleResult(boolean settled, int status, String reason, Map<String, Object> claims) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("settled", settled);
        m.put("status", num(status));
        if (reason != null) m.put("reason", reason);
        if (claims != null) m.put("claims", claims);
        return m;
    }

    /**
     * Gate an x402 settlement on a verified, PCActn-bound payment: runs {@code verify} over the client's payload; on failure REFUSES with 402
     * (fail closed); on success runs the optional {@code settle} step and returns the receipt. Returns {settled, status, reason?, claims?, receipt?}.
     */
    public static Map<String, Object> x402Settle(Object payload, X402Verify verify, X402Settler settle) throws Exception {
        Map<String, Object> norm = X402V2.normalizeX402Payload(payload);
        if (!Boolean.TRUE.equals(norm.get("ok"))) return settleResult(false, 402, (String) norm.get("reason"), null);
        Map<String, Object> v = verify.verify(payload);
        if (!JsVal.truthy(v.get("ok"))) {
            Object reason = v.get("reason");
            Map<String, Object> out = settleResult(false, 402, null, null);
            out.put("reason", reason != null ? reason : "payment verification failed");
            if (JsVal.truthy(v.get("claims"))) out.put("claims", v.get("claims"));
            return out;
        }
        if (!def(v, "claims")) return settleResult(false, 402, "verifier admitted the payment but returned no claims (fail closed)", null);
        Map<String, Object> claims = JsVal.map(v.get("claims"));
        Object receipt = settle != null ? settle.settle(payload, claims) : null;
        Map<String, Object> out = settleResult(true, 200, null, claims);
        if (receipt != null) out.put("receipt", receipt);
        return out;
    }

    /**
     * Adapt {@link #verifyDelegatedPaymentToken} into an {@link X402Verify} for {@link #x402Settle}. {@code opts}: verifyKey, alg, now,
     * expectedMerchant, amount, offered (v2 requirements the server offered), expectedSession, expectedCurrency, pcActn, grant, audience,
     * authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse, strict (default true: expectedMerchant, amount, expectedCurrency and singleUse
     * are all required and the payload's own merchant / amount are never read).
     */
    public static X402Verify acpX402Verifier(Map<String, Object> opts) {
        return payload -> {
            Map<String, Object> norm = X402V2.normalizeX402Payload(payload);
            if (!Boolean.TRUE.equals(norm.get("ok"))) return verdict(false, (String) norm.get("reason"), null, null);
            if (JsVal.num(norm.get("version")) == 2.0 && opts.get("offered") != null && !X402V2.x402AcceptedMatches(JsVal.list(opts.get("offered")), norm.get("accepted"))) {
                return verdict(false, "x402 v2 payload.accepted is not one of the requirements this server offered", null, null);
            }
            if (!Boolean.FALSE.equals(opts.get("strict")) && (opts.get("expectedMerchant") == null || opts.get("amount") == null)) {
                return verdict(false, "strict settlement requires the server to supply expectedMerchant and amount (fail closed)", null, null);
            }
            Object merchant = opts.get("expectedMerchant") != null ? opts.get("expectedMerchant") : norm.get("merchant");
            if (!AcpJs.nonEmpty(merchant)) return verdict(false, "x402 payload has no merchant to check the token against", null, null);
            Object amount = opts.get("amount") != null ? opts.get("amount") : norm.get("amount");
            if (!JsVal.isNumber(amount) || !isAmount(amount)) return verdict(false, "x402 payload has no amount to check the token against", null, null);
            Map<String, Object> vo = new LinkedHashMap<>();
            vo.put("expectedMerchant", merchant);
            vo.put("amount", amount);
            vo.put("verifyKey", opts.get("verifyKey"));
            for (String k : new String[] {"alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots",
                "insecureSkipPlanRootCheck", "singleUse", "strict"}) if (def(opts, k)) vo.put(k, opts.get(k));
            Map<String, Object> res = verifyDelegatedPaymentToken(norm.get("token"), vo);
            return verdict(Boolean.TRUE.equals(res.get("ok")), (String) res.get("reason"), res.get("claims") == null ? null : JsVal.map(res.get("claims")), null);
        };
    }

    // ---- ACP delegate_payment allowance ----

    /**
     * Map VERIFIED token claims to the ACP delegate_payment {@code allowance} {reason, max_amount, currency, checkout_session_id, merchant_id,
     * expires_at}. Throws AcpAuthorityException when a claim cannot be expressed in the ACP shape (currency not three letters, merchant over 256
     * characters, expiry not a date).
     */
    public static Map<String, Object> toAcpAllowance(Map<String, Object> claims) {
        if (!isAmount(claims.get("amount"))) throw new AcpAuthorityException("allowance: amount must be a positive integer in minor units");
        String currency = claims.get("currency") instanceof String ? ((String) claims.get("currency")).toLowerCase(Locale.ROOT) : "";
        if (!currency.matches("[a-z]{3}")) throw new AcpAuthorityException("allowance: currency must be a three-letter ISO-4217 code");
        Object merchant = claims.get("merchant");
        if (!(merchant instanceof String) || ((String) merchant).isEmpty() || ((String) merchant).length() > 256) throw new AcpAuthorityException("allowance: merchant_id must be 1 to 256 characters");
        if (!AcpJs.nonEmpty(claims.get("session"))) throw new AcpAuthorityException("allowance: checkout_session_id is required");
        Double exp = JsVal.num(claims.get("exp"));
        if (exp == null || Double.isNaN(exp) || Double.isInfinite(exp) || Math.abs(exp) > 8.64e15) throw new AcpAuthorityException("allowance: expiry is not a valid time");
        long ms = (long) (double) exp; // Date truncates toward zero
        ZonedDateTime z = Instant.ofEpochMilli(ms).atZone(ZoneOffset.UTC);
        int y = z.getYear();
        String year = y >= 0 && y <= 9999 ? String.format("%04d", y) : (y < 0 ? "-" : "+") + String.format("%06d", Math.abs(y));
        String iso = year + String.format("-%02d-%02dT%02d:%02d:%02d.%03dZ", z.getMonthValue(), z.getDayOfMonth(), z.getHour(), z.getMinute(), z.getSecond(), z.getNano() / 1_000_000);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("reason", "one_time");
        out.put("max_amount", claims.get("amount"));
        out.put("currency", currency);
        out.put("checkout_session_id", claims.get("session"));
        out.put("merchant_id", merchant);
        out.put("expires_at", iso);
        return out;
    }
}
