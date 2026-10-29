package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
 * binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
 * Signatures are Ed25519 (strict) over the UTF-8 bytes of hashCanonical({"kind": kind, "body": body}) (the digest string); body is the
 * signed object without its {@code sig}. Escalation is integer-only (BigInteger). Total: never throws.
 */
public final class K4 {
    private K4() {}

    public static final long PPM = 1_000_000L;
    public static final long MAX_MULTIPLIER_PPM = 100 * PPM;
    public static final String BINDING_KIND = "pca.network_token_binding";
    private static final Pattern REF = Pattern.compile("[A-Za-z0-9_.:\\-]{8,128}");
    private static final Pattern ADDR = Pattern.compile("0x[0-9a-fA-F]{40}");
    private static final Pattern QTY = Pattern.compile("0x(0|[1-9a-fA-F][0-9a-fA-F]*)");
    private static final Pattern CTX = Pattern.compile("0x[0-9a-fA-F]+");

    private static boolean isInt(Object o) { return Json.isSafeInt(o); }
    private static boolean isMinor(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }
    private static long l(Object o) { return Json.isSafeInt(o) ? Json.asLong(o) : 0; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** null when the key or signature does not decode; else the strict verification result. */
    private static Boolean sigOk(Object pub, String kind, Map<String, Object> o) {
        Object sig = o.get("sig");
        if (!(pub instanceof String) || !(sig instanceof String) || Pca.decodeB64uStrict(pub, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return null;
        Map<String, Object> body = new LinkedHashMap<>(o);
        body.remove("sig");
        String digest = Pca.hashCanonical(mapOf("kind", kind, "body", body));
        return Pca.verifyB64u((String) pub, digest.getBytes(StandardCharsets.UTF_8), (String) sig);
    }

    // ---- network-token binding ----

    private static boolean luhn(String d) {
        int sum = 0;
        boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int n = d.charAt(i) - '0';
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    public static boolean looksLikePan(String s) {
        for (String r : s.replaceAll("[\\s\\-]", "").split("[^0-9]+")) if (r.length() >= 13 && r.length() <= 19 && luhn(r)) return true;
        return false;
    }

    public static String tokenRefError(Object ref) {
        if (!(ref instanceof String) || !REF.matcher((String) ref).matches()) return "token_ref_malformed";
        return looksLikePan((String) ref) ? "token_ref_looks_like_pan" : null;
    }

    /** null = valid, else the reason. provider null = any. */
    public static String verifyBinding(Object bo, Object grant, String holder, String issuerNonce, String provider) {
        try {
            Map<String, Object> b = obj(bo);
            if (b == null || !BINDING_KIND.equals(b.get("kind"))) return "binding_malformed";
            String e = tokenRefError(b.get("token_ref"));
            if (e != null) return e;
            Object p = b.get("provider");
            if (!(p instanceof String) || ((String) p).isEmpty() || (provider != null && !p.equals(provider))) return "provider_mismatch";
            if (!Pca.hashCanonical(grant).equals(b.get("grant_digest"))) return "grant_digest_mismatch";
            if (!holder.equals(b.get("holder"))) return "holder_mismatch";
            if (!issuerNonce.equals(b.get("issuer_nonce"))) return "issuer_nonce_mismatch";
            Object proof = b.get("binding_proof");
            if (Pca.decodeB64uStrict(holder, -1) == null || Pca.decodeB64uStrict(proof, -1) == null) return "binding_malformed";
            Map<String, Object> body = mapOf("kind", BINDING_KIND, "v", 1, "provider", p, "token_ref", b.get("token_ref"),
                "grant_digest", b.get("grant_digest"), "issuer_nonce", b.get("issuer_nonce"), "holder", b.get("holder"));
            return Pca.verifyB64u(holder, Pca.hashCanonical(body).getBytes(StandardCharsets.UTF_8), (String) proof) ? null : "binding_proof_invalid";
        } catch (RuntimeException ex) {
            return "binding_malformed";
        }
    }

    // ---- risk-priced escalation ----

    public static String pricingConfigError(Object co) {
        try {
            Map<String, Object> c = obj(co);
            if (c == null || !isInt(c.get("v")) || l(c.get("v")) != 1 || !(c.get("principal") instanceof String) || !(c.get("currency") instanceof String) || !(c.get("sig") instanceof String)) return "config_malformed";
            for (String k : new String[] {"interruptionCost", "maxInterruptionCost", "hardCeilingLoss", "epoch"}) if (!isMinor(c.get(k))) return "config_amounts_invalid";
            if (l(c.get("interruptionCost")) > l(c.get("maxInterruptionCost"))) return "config_cost_above_max";
            Object st = c.get("tightenStepPpm");
            if (!isInt(st) || l(st) < 0 || l(st) > MAX_MULTIPLIER_PPM) return "config_step_invalid";
            Boolean r = sigOk(c.get("principal"), "pca.escalation_pricing", c);
            return r == null ? "config_malformed" : (r ? null : "config_signature_invalid");
        } catch (RuntimeException ex) {
            return "config_malformed";
        }
    }

    /** {ask, reason}: reason is never null. */
    public static final class Verdict {
        public final boolean ask;
        public final String reason;
        Verdict(boolean ask, String reason) { this.ask = ask; this.reason = reason; }
        @Override public String toString() { return "Verdict{" + ask + "," + reason + "}"; }
    }

    private static Verdict ask(String r) { return new Verdict(true, r); }

    /** Ask a person iff min(p * multiplier, 1e12) * loss > interruptionCost * 1e12; anything unexpected asks. */
    public static Verdict decide(Object config, Object cal, Object ao) {
        String e = pricingConfigError(config);
        if (e != null) return ask(e);
        Map<String, Object> cfg = obj(config);
        Map<String, Object> a = obj(ao);
        if (a == null || !cfg.get("currency").equals(a.get("currency"))) return ask("currency_mismatch");
        if (!isMinor(a.get("loss")) || !isInt(a.get("pBadUpperPpm")) || l(a.get("pBadUpperPpm")) < 0 || l(a.get("pBadUpperPpm")) > PPM) return ask("risk_input_invalid");
        Map<String, Object> cm = obj(cal);
        Object mo = cm == null ? null : cm.get("multiplierPpm");
        if (!isInt(mo) || l(mo) < PPM || l(mo) > MAX_MULTIPLIER_PPM) return ask("calibration_invalid");
        long loss = l(a.get("loss"));
        if (loss > l(cfg.get("hardCeilingLoss"))) return ask("above_hard_ceiling");
        BigInteger one = BigInteger.valueOf(PPM).multiply(BigInteger.valueOf(PPM));
        BigInteger capped = BigInteger.valueOf(l(a.get("pBadUpperPpm"))).multiply(BigInteger.valueOf(l(mo))).min(one);
        if (capped.multiply(BigInteger.valueOf(loss)).compareTo(BigInteger.valueOf(l(cfg.get("interruptionCost"))).multiply(one)) > 0) return ask("expected_loss_exceeds_interruption_cost");
        return new Verdict(false, "expected_loss_within_interruption_cost");
    }

    private static boolean answerOk(Object ao, String principal) {
        try {
            Map<String, Object> a = obj(ao);
            if (a == null || !isInt(a.get("v")) || l(a.get("v")) != 1 || !principal.equals(a.get("principal"))) return false;
            if (!(a.get("nonce") instanceof String) || ((String) a.get("nonce")).length() < 8 || !(a.get("action_digest") instanceof String)) return false;
            if (!"approve".equals(a.get("answer")) && !"deny".equals(a.get("answer"))) return false;
            return Boolean.TRUE.equals(sigOk(principal, "pca.escalation_answer", a));
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** Result of {@link #updateCalibration}. */
    public static final class Calibration {
        public final long multiplierPpm;
        public final List<String> seen;
        Calibration(long m, List<String> s) { multiplierPpm = m; seen = s; }
    }

    /** Fold principal-signed answers into the calibration; the multiplier can only rise. risks: action digest to risk object. */
    public static Calibration updateCalibration(Object config, long startMult, List<String> startSeen, List<Object> answers, Map<String, Object> risks) {
        List<String> order = new ArrayList<>(startSeen);
        if (pricingConfigError(config) != null) return new Calibration(startMult, order);
        Map<String, Object> cfg = obj(config);
        String principal = (String) cfg.get("principal");
        long step = l(cfg.get("tightenStepPpm"));
        long mult = startMult;
        for (Object ao : answers) {
            if (!answerOk(ao, principal)) continue;
            Map<String, Object> a = obj(ao);
            String nonce = (String) a.get("nonce");
            if (order.contains(nonce)) continue;
            order.add(nonce);
            Object risk = risks.get((String) a.get("action_digest"));
            if (!"deny".equals(a.get("answer")) || risk == null) continue;
            if (!decide(config, mapOf("multiplierPpm", mult), risk).ask) mult = Math.min(MAX_MULTIPLIER_PPM, mult + step);
        }
        return new Calibration(Math.max(mult, startMult), order);
    }

    // ---- ERC-7715 granted-permission check ----

    private static String lower(Object o) { return o instanceof String ? ((String) o).toLowerCase(Locale.ROOT) : "\0"; }

    /** null when what the wallet granted is within the request and the grant. g = {grantDigest, expiresAtSec}. contextOwner may be null. */
    public static String verifyGranted(Object go, Object sentO, Object gotO, List<String> allowedManagers, Function<String, String> contextOwner) {
        try {
            Map<String, Object> g = obj(go), sent = obj(sentO), r = obj(gotO);
            if (r == null || obj(r.get("permission")) == null) return "response_malformed";
            Object ctx = r.get("context");
            if (!(ctx instanceof String) || !CTX.matcher((String) ctx).matches()) return "context_malformed";
            String owner = contextOwner == null ? null : contextOwner.apply((String) ctx);
            if (owner != null && !owner.equals(g.get("grantDigest"))) return "context_bound_to_other_grant";
            Object m = r.get("delegationManager");
            boolean allowed = false;
            for (String x : allowedManagers) if (m instanceof String && x.equalsIgnoreCase((String) m)) allowed = true;
            if (!(m instanceof String) || !ADDR.matcher((String) m).matches() || !allowed) return "delegation_manager_not_allowed";
            if (!lower(r.get("chainId")).equals(lower(sent.get("chainId")))) return "chain_mismatch";
            if (!lower(r.get("to")).equals(lower(sent.get("to")))) return "recipient_mismatch";
            if (sent.get("from") != null && !lower(r.get("from")).equals(lower(sent.get("from")))) return "from_mismatch";
            Map<String, Object> perm = obj(r.get("permission")), sperm = obj(sent.get("permission"));
            Object pt = perm.get("type");
            if (pt == null || !pt.equals(sperm.get("type")) || !("native-token-allowance".equals(pt) || "erc20-token-allowance".equals(pt))) return "permission_type_mismatch";
            Map<String, Object> d = obj(perm.get("data")), sd = obj(sperm.get("data"));
            if (d == null) return "response_malformed";
            String t1 = d.get("tokenAddress") instanceof String ? ((String) d.get("tokenAddress")).toLowerCase(Locale.ROOT) : "";
            String t2 = sd.get("tokenAddress") instanceof String ? ((String) sd.get("tokenAddress")).toLowerCase(Locale.ROOT) : "";
            if (!t1.equals(t2)) return "token_mismatch";
            Object al = d.get("allowance");
            if (!(al instanceof String) || !QTY.matcher((String) al).matches()) return "amount_malformed";
            if (new BigInteger(((String) al).substring(2), 16).compareTo(new BigInteger(((String) sd.get("allowance")).substring(2), 16)) > 0) return "amount_widened";
            Object ra = perm.get("isAdjustmentAllowed");
            if (!java.util.Objects.equals(ra, sperm.get("isAdjustmentAllowed")) && Boolean.TRUE.equals(ra)) return "adjustment_widened";
            if (!(r.get("rules") instanceof List)) return "expiry_missing";
            Long expiry = null;
            for (Object ru : (List<?>) r.get("rules")) {
                Map<String, Object> rule = obj(ru);
                if (rule == null || !"expiry".equals(rule.get("type"))) return "unknown_rule_type";
                if (expiry != null) return "duplicate_expiry";
                Map<String, Object> rd = obj(rule.get("data"));
                Object ts = rd == null ? null : rd.get("timestamp");
                if (!isInt(ts)) return "expiry_malformed";
                expiry = Json.asLong(ts);
            }
            if (expiry == null) return "expiry_missing";
            return expiry > l(g.get("expiresAtSec")) ? "expiry_extended" : null;
        } catch (RuntimeException ex) {
            return "response_malformed";
        }
    }
}
