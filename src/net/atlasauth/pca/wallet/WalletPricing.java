package net.atlasauth.pca.wallet;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.WalletBridge;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Risk-priced escalation (the reference's escalation-pricing.ts). Rule: ask a human iff {@code pBadUpper * loss >
 * interruptionCost}, in integer arithmetic (probabilities in ppm, money in minor units, big-integer products; no floats, no
 * randomness, no clock). The loss and the interruption cost come from a principal-signed configuration; anything missing,
 * out of range or unsigned means ask. The only learned component is a per-principal multiplier of at least 1_000_000 that scales
 * the probability UP, so it can only add asks; the way to ask less is a principal-signed autonomy raise.
 */
public final class WalletPricing {
    private WalletPricing() {}

    public static final long PPM = 1_000_000L;
    public static final long MAX_MULTIPLIER_PPM = 100 * PPM;

    private static boolean isMinor(Object n) { return Wallet.isSafeInteger(n) && Wallet.nv(n) >= 0; }

    private static byte[] msg(String kind, Object body) { return Wallet.utf8(Pca.hashCanonical(Wallet.obj("kind", kind, "body", body))); }

    private static String sigOf(String kind, Object body, byte[] seed) { return Keys.b64u(Keys.edFromSeed(seed).sign(msg(kind, body))); }

    private static Map<String, Object> withSig(Map<String, Object> body, String sig) {
        Map<String, Object> m = new LinkedHashMap<>(body);
        m.put("sig", sig);
        return m;
    }

    private static Map<String, Object> without(Map<?, ?> o, String k) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : o.entrySet()) if (!k.equals(e.getKey())) m.put((String) e.getKey(), e.getValue());
        return m;
    }

    /** The principal-signed configuration {...body, sig}; {@code principalSeed} is the Ed25519 seed. */
    public static Map<String, Object> signPricingConfig(Map<String, Object> body, byte[] principalSeed) {
        return withSig(body, sigOf("pca.escalation_pricing", body, principalSeed));
    }

    /** Null when the configuration is well formed and verifies; else the reason code. */
    public static String pricingConfigError(Object c) {
        try {
            if (!(c instanceof Map)) return "config_malformed";
            Map<?, ?> x = (Map<?, ?>) c;
            Object principal = x.get("principal"), sig = x.get("sig");
            if (!Wallet.isSafeInteger(x.get("v")) || Wallet.nv(x.get("v")) != 1 || !(principal instanceof String) || !(x.get("currency") instanceof String) || !(sig instanceof String)) return "config_malformed";
            if (!isMinor(x.get("interruptionCost")) || !isMinor(x.get("maxInterruptionCost")) || !isMinor(x.get("hardCeilingLoss")) || !isMinor(x.get("epoch"))) return "config_amounts_invalid";
            if (Wallet.nv(x.get("interruptionCost")) > Wallet.nv(x.get("maxInterruptionCost"))) return "config_cost_above_max";
            Object step = x.get("tightenStepPpm");
            if (!Wallet.isSafeInteger(step) || Wallet.nv(step) < 0 || Wallet.nv(step) > MAX_MULTIPLIER_PPM) return "config_step_invalid";
            if (Pca.decodeB64uStrict(principal, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return "config_malformed";
            Map<String, Object> body = without(x, "sig");
            return WalletBridge.verifyEd((String) principal, msg("pca.escalation_pricing", body), (String) sig) ? null : "config_signature_invalid";
        } catch (RuntimeException e) {
            return "config_malformed";
        }
    }

    public static Map<String, Object> freshCalibration() { return Wallet.obj("multiplierPpm", JsVal.n(PPM), "seen", new ArrayList<Object>()); }

    private static BigInteger big(Object n) { return BigInteger.valueOf((long) Wallet.nv(n)); }

    /** Pure and total: {ask, reason}. {@code a} is {currency, loss, pBadUpperPpm}; {@code cal} is {multiplierPpm, seen}. */
    public static Map<String, Object> decideEscalation(Map<String, Object> config, Object cal, Object a) {
        String e = pricingConfigError(config);
        if (e != null) return ask(true, e);
        if (!(a instanceof Map) || !config.get("currency").equals(((Map<?, ?>) a).get("currency"))) return ask(true, "currency_mismatch");
        Object loss = ((Map<?, ?>) a).get("loss"), p = ((Map<?, ?>) a).get("pBadUpperPpm");
        if (!isMinor(loss) || JsVal.isNegZero(loss) || !Wallet.isSafeInteger(p) || Wallet.nv(p) < 0 || JsVal.isNegZero(p) || Wallet.nv(p) > PPM) return ask(true, "risk_input_invalid");
        Object mult = Wallet.get(cal, "multiplierPpm");
        if (!(Wallet.isSafeInteger(mult) && Wallet.nv(mult) >= PPM && Wallet.nv(mult) <= MAX_MULTIPLIER_PPM)) return ask(true, "calibration_invalid");
        if (Wallet.nv(loss) > Wallet.nv(config.get("hardCeilingLoss"))) return ask(true, "above_hard_ceiling");
        BigInteger ppm2 = BigInteger.valueOf(PPM).multiply(BigInteger.valueOf(PPM));
        BigInteger pe = big(p).multiply(big(mult));
        BigInteger capped = pe.compareTo(ppm2) > 0 ? ppm2 : pe;
        BigInteger lhs = capped.multiply(big(loss));
        BigInteger rhs = big(config.get("interruptionCost")).multiply(ppm2);
        return lhs.compareTo(rhs) > 0 ? ask(true, "expected_loss_exceeds_interruption_cost") : ask(false, "expected_loss_within_interruption_cost");
    }

    private static Map<String, Object> ask(boolean ask, String reason) { return Wallet.obj("ask", ask, "reason", reason); }

    /** Sign an answer {v, principal, nonce, action_digest, answer}. */
    public static Map<String, Object> signAnswer(Map<String, Object> body, byte[] principalSeed) {
        return withSig(body, sigOf("pca.escalation_answer", body, principalSeed));
    }

    private static boolean answerOk(Object aO, String principal) {
        try {
            if (!(aO instanceof Map)) return false;
            Map<?, ?> a = (Map<?, ?>) aO;
            Object nonce = a.get("nonce"), digest = a.get("action_digest"), ans = a.get("answer"), sig = a.get("sig");
            if (!Wallet.isSafeInteger(a.get("v")) || Wallet.nv(a.get("v")) != 1 || !principal.equals(a.get("principal")) || !(nonce instanceof String) || ((String) nonce).length() < 8
                || !(digest instanceof String) || (!"approve".equals(ans) && !"deny".equals(ans))) return false;
            if (!(sig instanceof String) || Pca.decodeB64uStrict(principal, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return false;
            return WalletBridge.verifyEd(principal, msg("pca.escalation_answer", without(a, "sig")), (String) sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Fold signed answers into the calibration {multiplierPpm, seen}. A deny the principal gave to an action that the current
     * pricing would have auto-approved is a miss and adds tightenStepPpm (capped). Everything else changes nothing; the result's
     * multiplier is at least the input's for every input. {@code risks} maps an action digest to its risk.
     */
    public static Map<String, Object> updateCalibration(Map<String, Object> config, Map<String, Object> cal, List<?> answers, Map<String, Object> risks) {
        if (pricingConfigError(config) != null) return cal;
        double mult = Wallet.nv(cal.get("multiplierPpm"));
        Set<Object> seen = new HashSet<>((List<?>) cal.get("seen"));
        List<Object> order = new ArrayList<>((List<?>) cal.get("seen"));
        for (Object a : answers) {
            if (!answerOk(a, (String) config.get("principal")) || seen.contains(((Map<?, ?>) a).get("nonce"))) continue;
            seen.add(((Map<?, ?>) a).get("nonce"));
            order.add(((Map<?, ?>) a).get("nonce"));
            String digest = (String) ((Map<?, ?>) a).get("action_digest");
            if (!"deny".equals(((Map<?, ?>) a).get("answer")) || !risks.containsKey(digest)) continue;
            Map<String, Object> c = Wallet.obj("multiplierPpm", mult, "seen", new ArrayList<Object>());
            if (!Boolean.TRUE.equals(decideEscalation(config, c, risks.get(digest)).get("ask"))) {
                mult = Math.min((double) MAX_MULTIPLIER_PPM, mult + Wallet.nv(config.get("tightenStepPpm")));
            }
        }
        return Wallet.obj("multiplierPpm", Math.max(mult, Wallet.nv(cal.get("multiplierPpm"))), "seen", order);
    }

    /** Sign an autonomy raise {v, principal, epoch, newInterruptionCost}. */
    public static Map<String, Object> signAutonomyRaise(Map<String, Object> b, byte[] seed) { return withSig(b, sigOf("pca.autonomy_raise", b, seed)); }

    /**
     * A higher interruption cost means fewer asks. Requires the principal's signature, a strictly newer epoch and a cost no
     * higher than maxInterruptionCost; throws otherwise. Returns the re-signed configuration.
     */
    public static Map<String, Object> applyAutonomyRaise(Map<String, Object> config, Map<String, Object> raise, byte[] principalSeed) {
        boolean ok = false;
        try {
            Object sig = raise.get("sig");
            Object cp = config.get("principal");
            ok = Wallet.isSafeInteger(raise.get("v")) && Wallet.nv(raise.get("v")) == 1 && raise.get("principal") != null && raise.get("principal").equals(cp) && cp instanceof String
                && sig instanceof String && Pca.decodeB64uStrict(cp, -1) != null && Pca.decodeB64uStrict(sig, -1) != null
                && WalletBridge.verifyEd((String) cp, msg("pca.autonomy_raise", without(raise, "sig")), (String) sig);
        } catch (RuntimeException e) {
            ok = false;
        }
        if (!ok) throw new IllegalArgumentException("applyAutonomyRaise: signature or principal invalid");
        if (!(Wallet.nv(raise.get("epoch")) > Wallet.nv(config.get("epoch")))) throw new IllegalArgumentException("applyAutonomyRaise: epoch must advance");
        Object nc = raise.get("newInterruptionCost");
        if (!isMinor(nc) || Wallet.nv(nc) > Wallet.nv(config.get("maxInterruptionCost"))) throw new IllegalArgumentException("applyAutonomyRaise: above the configured maximum");
        Map<String, Object> body = without(config, "sig");
        body.put("interruptionCost", nc);
        body.put("epoch", raise.get("epoch"));
        return signPricingConfig(body, principalSeed);
    }
}
