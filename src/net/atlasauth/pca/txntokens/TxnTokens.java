package net.atlasauth.pca.txntokens;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;

/**
 * The OAuth chain-of-custody PROFILE of a PCA capability chain: the RFC 8693 nested {@code act} projection ({@link #subActChain},
 * {@link #actDepth}, {@link #toRfc8693Act}) and the EdDSA-signed Transaction Token of draft-ietf-oauth-transaction-tokens
 * ({@link #toTransactionToken}, {@link #fromTransactionToken}). The token is an interop envelope, not a bearer credential: the PCActn's
 * signed capability chain stays the credential. Maps use the reference's member names; a refusal throws IllegalArgumentException
 * (or {@link TxnTokenError} for a verifier configured without a replay store).
 */
public final class TxnTokens {
    private TxnTokens() {}

    /** draft-ietf-oauth-transaction-tokens-11 header typ. */
    public static final String TXN_TOKEN_TYP_DRAFT_11 = "txntoken+jwt";
    /** Upper bound on an accepted token string (adversarial-size guard, checked before any parsing). */
    public static final int MAX_TOKEN_CHARS = 16384;
    private static final String TXN_TOKEN_TYP = "txn_token+jwt";
    private static final long DEFAULT_TTL_SEC = 120;
    private static final String EDDSA = "EdDSA";

    private static boolean nonEmptyString(Object s) { return s instanceof String && !((String) s).isEmpty(); }

    // ---- RFC 8693 section 4.1 nested actor claim ----

    /** {sub: root issuer, act: {sub: holder0, act: {sub: holder1 ...}}}: one nested act per delegation hop, root to leaf. */
    public static Map<String, Object> subActChain(Object chain) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) throw new IllegalArgumentException("subActChain: chain must be a non-empty CapabilityChain");
        List<?> c = (List<?>) chain;
        Map<String, Object> act = null;
        for (int i = c.size() - 1; i >= 0; i--) {
            Object holder = JsVal.get(c.get(i), "holder");
            if (!nonEmptyString(holder)) throw new IllegalArgumentException("subActChain: hop " + i + " has no holder");
            Map<String, Object> n = new LinkedHashMap<>();
            n.put("sub", holder);
            if (act != null) n.put("act", act);
            act = n;
        }
        Object issuer = JsVal.get(c.get(0), "issuer");
        if (!nonEmptyString(issuer)) throw new IllegalArgumentException("subActChain: root hop has no issuer (principal)");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", issuer);
        out.put("act", act);
        return out;
    }

    /** The number of nested act levels (the top-level sub does not count). */
    public static long actDepth(Object claim) {
        if (!JsVal.isObjectLike(claim)) throw new IllegalArgumentException("actDepth: expected a sub/act claim object");
        long depth = 0;
        Object cur = JsVal.get(claim, "act");
        while (JsVal.truthy(cur)) {
            depth++;
            cur = JsVal.get(cur, "act");
        }
        return depth;
    }

    /** RFC 8693 ordering of an act chain: the MOST RECENT actor outermost. The sub is unchanged. */
    public static Map<String, Object> toRfc8693Act(Object claim) {
        if (claim == null) throw new IllegalArgumentException("toRfc8693Act: claim is required");
        List<Object[]> actors = new ArrayList<>(); // {present, sub}
        for (Object c = JsVal.get(claim, "act"); JsVal.truthy(c); c = JsVal.get(c, "act")) {
            boolean has = c instanceof Map && ((Map<?, ?>) c).containsKey("sub");
            actors.add(new Object[] {has, JsVal.get(c, "sub")});
        }
        Map<String, Object> act = null;
        for (Object[] a : actors) {
            Map<String, Object> n = new LinkedHashMap<>();
            if ((Boolean) a[0]) n.put("sub", a[1]);
            if (act != null) n.put("act", act);
            act = n;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (claim instanceof Map && ((Map<?, ?>) claim).containsKey("sub")) out.put("sub", ((Map<?, ?>) claim).get("sub"));
        if (act != null) out.put("act", act);
        return out;
    }

    // ---- Transaction Token ----

    private static Keys.EdKey signingKey(Object key) {
        if (key instanceof byte[]) {
            if (((byte[]) key).length != 32) throw new IllegalArgumentException("toTransactionToken: a raw Ed25519 secret key must be 32 bytes");
            return Keys.edFromSeed((byte[]) key);
        }
        if (key instanceof Keys.EdKey) return (Keys.EdKey) key;
        throw new IllegalArgumentException("toTransactionToken: issuerKey must be a 32-byte Ed25519 seed");
    }

    private static Object jsNum(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e15) return JsVal.n((long) d);
        return new Json.Num(BigDecimal.valueOf(d).toPlainString()); // shortcut: Double.toString digits, which are not always the shortest JavaScript form
    }

    public static String toTransactionToken(Map<String, Object> args) { return toTransactionToken(args, System::currentTimeMillis); }

    /**
     * Mint a signed Transaction Token carrying the chain's custody (sub / act) and the action as its transaction context (tctx). Args (reference
     * names): chain, action {verb, resource, aud}, issuerKey (32-byte Ed25519 seed as byte[], or a Keys.EdKey), issuer, ttlSec (120), profile
     * (draft-11 default, or legacy), and for draft-11 scope, reqWl, txn (random UUID), trustDomain (action.aud). {@code clock}: epoch ms.
     */
    public static String toTransactionToken(Map<String, Object> args, LongSupplier clock) {
        Object issuer = args.get("issuer");
        if (!nonEmptyString(issuer)) throw new IllegalArgumentException("toTransactionToken: `issuer` is required");
        Object action = args.get("action");
        if (!(action instanceof Map) || !(JsVal.get(action, "verb") instanceof String) || !(JsVal.get(action, "resource") instanceof String) || !(JsVal.get(action, "aud") instanceof String)) {
            throw new IllegalArgumentException("toTransactionToken: `action` must have string verb, resource and aud");
        }
        Map<String, Object> custody = subActChain(args.get("chain"));
        Object ttlO = args.get("ttlSec");
        double ttl = ttlO == null ? DEFAULT_TTL_SEC : (JsVal.isNumber(ttlO) ? JsVal.num(ttlO) : Double.NaN);
        if (Double.isNaN(ttl) || Double.isInfinite(ttl) || ttl <= 0) throw new IllegalArgumentException("toTransactionToken: ttlSec must be > 0");
        long nowSec = Math.floorDiv(clock.getAsLong(), 1000L);
        Keys.EdKey key = signingKey(args.get("issuerKey"));
        Object profile = args.get("profile");
        boolean draft = profile == null || "draft-11".equals(profile);
        if (profile != null && !"legacy".equals(profile) && !draft) throw new IllegalArgumentException("toTransactionToken: profile must be legacy or draft-11");

        Map<String, Object> tctx = new LinkedHashMap<>();
        tctx.put("verb", JsVal.get(action, "verb"));
        tctx.put("resource", JsVal.get(action, "resource"));
        tctx.put("aud", JsVal.get(action, "aud"));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", EDDSA);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tctx", tctx);
        if (custody.get("act") != null) claims.put("act", custody.get("act"));
        if (draft) {
            if (!nonEmptyString(args.get("scope"))) throw new IllegalArgumentException("toTransactionToken: draft-11 requires `scope`");
            if (!nonEmptyString(args.get("reqWl"))) throw new IllegalArgumentException("toTransactionToken: draft-11 requires `reqWl`");
            Object td = args.get("trustDomain") != null ? args.get("trustDomain") : JsVal.get(action, "aud");
            if (!nonEmptyString(td)) throw new IllegalArgumentException("toTransactionToken: draft-11 requires a non-empty trust domain (aud)");
            claims.put("txn", args.get("txn") != null ? args.get("txn") : UUID.randomUUID().toString());
            claims.put("scope", args.get("scope"));
            claims.put("req_wl", args.get("reqWl"));
            header.put("typ", TXN_TOKEN_TYP_DRAFT_11);
            claims.put("iat", JsVal.n(nowSec));
            claims.put("iss", issuer);
            claims.put("sub", custody.get("sub"));
            claims.put("aud", td);
            claims.put("exp", jsNum(nowSec + ttl));
        } else {
            header.put("typ", TXN_TOKEN_TYP);
            claims.put("iat", JsVal.n(nowSec));
            claims.put("iss", issuer);
            claims.put("sub", custody.get("sub"));
            claims.put("aud", JsVal.get(action, "aud"));
            claims.put("exp", jsNum(nowSec + ttl));
            claims.put("jti", UUID.randomUUID().toString());
        }
        return Jws.signEd25519(header, claims, key);
    }

    /** The result of {@link #fromTransactionToken}: the custody chain, the PCA action (null for a free-form draft tctx), the tctx and the verified claims. */
    public static Map<String, Object> fromTransactionToken(String jwt, Object verifyKey, Map<String, Object> opts) { return fromTransactionToken(jwt, verifyKey, opts, System::currentTimeMillis); }

    /**
     * Verify a Transaction Token's EdDSA signature and parse out the custody chain and the transaction context. {@code verifyKey}: the raw
     * 32-byte Ed25519 public key (byte[]) or a public key. Options (reference names): profile, audience (required for draft-11), clockToleranceSec,
     * now (epoch ms, Number or Date), seenTxn ({@link SeenTxn}), replayCheck ('unchecked'). Returns {chain, action?, tctx, claims}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> fromTransactionToken(String jwt, Object verifyKey, Map<String, Object> opts, LongSupplier clock) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        Object profile = o.get("profile");
        boolean draft = profile == null || "draft-11".equals(profile);
        if (profile != null && !"legacy".equals(profile) && !draft) throw new IllegalArgumentException("fromTransactionToken: profile must be legacy or draft-11");
        if (draft && !nonEmptyString(o.get("audience"))) throw new IllegalArgumentException("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)");
        SeenTxn seen = o.get("seenTxn") instanceof SeenTxn ? (SeenTxn) o.get("seenTxn") : null;
        if (seen == null && !"unchecked".equals(o.get("replayCheck"))) {
            throw new TxnTokenError("replay_store_required", "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'");
        }
        if (jwt != null && jwt.length() > MAX_TOKEN_CHARS) throw new IllegalArgumentException("transaction token: token exceeds the size limit");
        // a non-finite tolerance or clock makes every exp/nbf comparison pass
        if (o.get("clockToleranceSec") != null) {
            Double ct = JsVal.num(o.get("clockToleranceSec"));
            if (ct == null || !(Double.isFinite(ct) && ct >= 0)) throw new IllegalArgumentException("fromTransactionToken: clockToleranceSec must be a finite number >= 0");
        }
        // shortcut: a finite Number is still accepted as epoch ms (the reference takes a Date only); only a non-finite one is refused
        if (o.get("now") != null && !(o.get("now") instanceof Date)) {
            Double nv = JsVal.num(o.get("now"));
            if (nv == null || !Double.isFinite(nv)) throw new IllegalArgumentException("fromTransactionToken: now must be a valid Date");
        }
        Jws.Canonical canon = Jws.assertCanonicalCompactJws(jwt); // canonical-spelling gate BEFORE the JOSE layer
        Object key = verifyKey;
        if (verifyKey instanceof byte[]) {
            if (((byte[]) verifyKey).length != 32) throw new IllegalArgumentException("fromTransactionToken: a raw Ed25519 public key must be 32 bytes");
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", Jws.b64u((byte[]) verifyKey));
            key = jwk;
        }
        Map<String, Object> vo = new LinkedHashMap<>();
        vo.put("typ", draft ? TXN_TOKEN_TYP_DRAFT_11 : TXN_TOKEN_TYP);
        vo.put("algorithms", new ArrayList<Object>(List.of(EDDSA)));
        vo.put("requiredClaims", new ArrayList<Object>(draft ? Arrays.<Object>asList("iat", "exp", "aud", "sub", "txn", "scope", "req_wl") : Arrays.<Object>asList("exp")));
        if (o.get("audience") != null) vo.put("audience", o.get("audience"));
        if (o.get("clockToleranceSec") != null) vo.put("clockTolerance", o.get("clockToleranceSec"));
        long nowMs = clock.getAsLong();
        Object now = o.get("now");
        if (now instanceof Date) nowMs = ((Date) now).getTime();
        else if (now != null) nowMs = (long) (double) JsVal.num(now);
        Map<String, Object> payload = Jws.jwtVerify(jwt, canon, key, vo, nowMs).payload;
        if (draft) {
            for (String k : new String[] {"txn", "scope", "req_wl"}) {
                if (!nonEmptyString(payload.get(k))) throw new IllegalArgumentException("transaction token: `" + k + "` must be a non-empty string");
            }
        }
        if (!nonEmptyString(payload.get("sub"))) throw new IllegalArgumentException("transaction token: missing `sub` (root principal)");
        Map<String, Object> read = readTctx(payload.get("tctx"), draft);
        if (draft && payload.containsKey("rctx") && !(payload.get("rctx") instanceof Map)) throw new IllegalArgumentException("transaction token: malformed `rctx`");
        Map<String, Object> act = normalizeAct(payload.containsKey("act") ? payload.get("act") : UNDEFINED);
        // Consume the identifier last: a token refused for any other reason never burns its transaction id.
        if (seen != null) {
            Object id = draft ? payload.get("txn") : payload.get("jti");
            if (!nonEmptyString(id)) throw new IllegalArgumentException("transaction token: no transaction identifier to check for replay");
            boolean replayed;
            try {
                Double exp = JsVal.num(payload.get("exp"));
                replayed = JsVal.truthy(seen.seen((String) id, exp == null ? Double.NaN : exp));
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            if (replayed) throw new IllegalArgumentException("transaction token: replayed (transaction identifier already seen)");
        }
        Map<String, Object> chain = new LinkedHashMap<>();
        chain.put("sub", payload.get("sub"));
        if (act != null) chain.put("act", act);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("chain", chain);
        if (read.get("action") != null) out.put("action", read.get("action"));
        out.put("tctx", read.get("tctx"));
        out.put("claims", payload);
        return out;
    }

    private static final Object UNDEFINED = new Object();

    /** Validate and normalize an untrusted nested act claim (the signature is verified, the shape is not). */
    private static Map<String, Object> normalizeAct(Object node) {
        if (node == UNDEFINED) return null;
        if (!(node instanceof Map)) throw new IllegalArgumentException("transaction token: malformed `act` claim");
        Map<?, ?> obj = (Map<?, ?>) node;
        if (!nonEmptyString(obj.get("sub"))) throw new IllegalArgumentException("transaction token: `act.sub` must be a non-empty string");
        Map<String, Object> inner = normalizeAct(obj.containsKey("act") ? obj.get("act") : UNDEFINED);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", obj.get("sub"));
        if (inner != null) out.put("act", inner);
        return out;
    }

    /**
     * The transaction context. The draft's tctx is a free-form JSON object, so the draft profile accepts any object; when it uses any of the PCA
     * action keys (verb, resource, aud) it must use all three as strings. The legacy profile requires the PCA action. {@code action} is absent only
     * for a free-form draft tctx.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> readTctx(Object raw, boolean draft) {
        if (!(raw instanceof Map)) throw new IllegalArgumentException("transaction token: missing or malformed `tctx`");
        Map<String, Object> r = (Map<String, Object>) raw;
        boolean usesPca = r.containsKey("verb") || r.containsKey("resource") || r.containsKey("aud");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tctx", r);
        if (!draft || usesPca) {
            if (!(r.get("verb") instanceof String) || !(r.get("resource") instanceof String) || !(r.get("aud") instanceof String)) {
                throw new IllegalArgumentException("transaction token: missing or malformed `tctx`");
            }
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("verb", r.get("verb"));
            a.put("resource", r.get("resource"));
            a.put("aud", r.get("aud"));
            out.put("action", a);
        }
        return out;
    }
}
