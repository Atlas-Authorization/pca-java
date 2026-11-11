package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link K4}: self-signed escalation configs / answers and network-token bindings (keys from fixed
 * seeds), the Luhn PAN screen at its length and doubling boundaries, and the ERC-7715 check member by member. Every
 * assertion pins the exact reason (or null / the exact calibration).
 */
public class K4K05KillTest {
    static byte[] fill(int b) { byte[] s = new byte[32]; Arrays.fill(s, (byte) b); return s; }

    static final Keys.EdKey KEY = Keys.edFromSeed(fill(7));
    static final Keys.EdKey OTHER = Keys.edFromSeed(fill(8));
    static final Keys.EdKey HOLDER = Keys.edFromSeed(fill(9));
    static final String P = KEY.id();

    @SuppressWarnings("unchecked")
    static Map<String, Object> j(String json) { return (Map<String, Object>) Json.parseLenient(json); }

    static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Signs o (without its sig) the way K4 verifies it: Ed25519 over the UTF-8 of hashCanonical({kind, body}). */
    static Map<String, Object> sign(Keys.EdKey k, String kind, Map<String, Object> o) {
        Map<String, Object> body = new LinkedHashMap<>(o);
        body.remove("sig");
        String digest = Pca.hashCanonical(mapOf("kind", kind, "body", body));
        o.put("sig", Keys.b64u(k.sign(digest.getBytes(StandardCharsets.UTF_8))));
        return o;
    }

    // ---- pricing config ----

    static final String BASE = "{\"v\":1,\"principal\":\"" + P + "\",\"currency\":\"USD\",\"interruptionCost\":100,\"maxInterruptionCost\":500,"
        + "\"hardCeilingLoss\":100000,\"tightenStepPpm\":500000,\"epoch\":1}";

    /** The base config with members overridden (a null JSON text removes the member), signed by KEY. */
    static Map<String, Object> cfg(String... kv) {
        Map<String, Object> c = j(BASE);
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) c.remove(kv[i]);
            else c.put(kv[i], Json.parseLenient(kv[i + 1]));
        }
        return sign(KEY, "pca.escalation_pricing", c);
    }

    static Map<String, Object> with(Map<String, Object> m, String k, Object v) { m.put(k, v); return m; }

    @Test void pricingConfig() {
        assertNull(K4.pricingConfigError(cfg()));
        assertEquals("config_malformed", K4.pricingConfigError(null));
        assertEquals("config_malformed", K4.pricingConfigError("x"));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("v", null)));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("v", "2")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("v", "\"1\"")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("v", "1.5")));
        // a type fault is reported before the amounts
        assertEquals("config_amounts_invalid", K4.pricingConfigError(cfg("interruptionCost", "-1")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("v", "2", "interruptionCost", "-1")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("principal", "5", "interruptionCost", "-1")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("currency", "5", "interruptionCost", "-1")));
        assertEquals("config_malformed", K4.pricingConfigError(with(cfg("interruptionCost", "-1"), "sig", 5L)));
        assertEquals("config_malformed", K4.pricingConfigError(with(cfg(), "sig", 5L)));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("principal", "5")));
        assertEquals("config_malformed", K4.pricingConfigError(cfg("currency", null)));
        // amounts
        assertEquals("config_amounts_invalid", K4.pricingConfigError(cfg("interruptionCost", "\"100\"")));
        assertEquals("config_amounts_invalid", K4.pricingConfigError(cfg("epoch", "1.5")));
        assertEquals("config_amounts_invalid", K4.pricingConfigError(cfg("hardCeilingLoss", null)));
        assertNull(K4.pricingConfigError(cfg("interruptionCost", "500")));
        assertEquals("config_cost_above_max", K4.pricingConfigError(cfg("interruptionCost", "501")));
        // step
        assertNull(K4.pricingConfigError(cfg("tightenStepPpm", "0")));
        assertNull(K4.pricingConfigError(cfg("tightenStepPpm", "100000000")));
        assertEquals("config_step_invalid", K4.pricingConfigError(cfg("tightenStepPpm", "100000001")));
        assertEquals("config_step_invalid", K4.pricingConfigError(cfg("tightenStepPpm", "-1")));
        assertEquals("config_step_invalid", K4.pricingConfigError(cfg("tightenStepPpm", "1.5")));
        assertEquals("config_step_invalid", K4.pricingConfigError(cfg("tightenStepPpm", "\"5\"")));
        assertEquals("config_step_invalid", K4.pricingConfigError(cfg("tightenStepPpm", null)));
        // keys and signatures: undecodable = malformed, decodable but wrong = signature invalid
        assertEquals("config_malformed", K4.pricingConfigError(cfg("principal", "\"not+b64\"")));
        assertEquals("config_malformed", K4.pricingConfigError(with(cfg(), "sig", "not+b64")));
        assertEquals("config_signature_invalid", K4.pricingConfigError(cfg("principal", "\"" + OTHER.id() + "\"")));
        assertEquals("config_signature_invalid", K4.pricingConfigError(sign(OTHER, "pca.escalation_pricing", j(BASE))));
        assertEquals("config_signature_invalid", K4.pricingConfigError(with(cfg(), "epoch", 2L)));
    }

    // ---- decide ----

    static Map<String, Object> risk(String loss, String p) { return j("{\"currency\":\"USD\",\"loss\":" + loss + ",\"pBadUpperPpm\":" + p + "}"); }
    static Map<String, Object> cal(String m) { return j("{\"multiplierPpm\":" + m + "}"); }
    static String d(Object config, Object c, Object r) { K4.Verdict v = K4.decide(config, c, r); return v.ask + " " + v.reason; }

    @Test void decide() {
        Map<String, Object> c = cfg();
        assertEquals("false expected_loss_within_interruption_cost", d(c, cal("1000000"), risk("1000", "100000")));
        // the config is checked first
        assertEquals("true config_malformed", d(null, cal("1000000"), risk("1000", "100000")));
        assertEquals("true config_signature_invalid", d(sign(OTHER, "pca.escalation_pricing", j(BASE)), cal("1000000"), risk("1000", "100000")));
        assertEquals("Verdict{true,config_malformed}", K4.decide(null, null, null).toString());
        // the risk
        assertEquals("true currency_mismatch", d(c, cal("1000000"), null));
        assertEquals("true currency_mismatch", d(c, cal("1000000"), "x"));
        assertEquals("true currency_mismatch", d(c, cal("1000000"), j("{\"currency\":\"EUR\",\"loss\":1,\"pBadUpperPpm\":1}")));
        for (String[] bad : new String[][] {{"-1", "1"}, {"\"5\"", "1"}, {"1.5", "1"}, {"1", "-1"}, {"1", "\"5\""}, {"1", "1.5"}, {"1", "1000001"}}) {
            assertEquals("true risk_input_invalid", d(c, cal("1000000"), risk(bad[0], bad[1])), bad[0] + "/" + bad[1]);
        }
        assertEquals("false expected_loss_within_interruption_cost", d(c, cal("1000000"), risk("100", "1000000")));
        // the calibration
        assertEquals("true calibration_invalid", d(c, null, risk("1", "1")));
        assertEquals("true calibration_invalid", d(c, "x", risk("1", "1")));
        assertEquals("true calibration_invalid", d(c, cal("\"x\""), risk("1", "1")));
        assertEquals("true calibration_invalid", d(c, cal("1.5"), risk("1", "1")));
        assertEquals("true calibration_invalid", d(c, cal("999999"), risk("1", "1")));
        assertEquals("true calibration_invalid", d(c, cal("100000001"), risk("1", "1")));
        assertEquals("false expected_loss_within_interruption_cost", d(c, cal("100000000"), risk("1", "1")));
        assertEquals("true above_hard_ceiling", d(c, cal("1000000"), risk("100001", "0")));
        // 1e5 * 1000001 * 1000 = 1e14 + 1e8: above 100 * 1e12, exactly 100 * (1e12 + 1e6)
        assertEquals("true expected_loss_exceeds_interruption_cost", d(c, cal("1000001"), risk("1000", "100000")));
        // p * multiplier is capped at 1e12: 1e6 * 2e6 -> 1e12, times 100 = the cost exactly (not above)
        assertEquals("false expected_loss_within_interruption_cost", d(c, cal("2000000"), risk("100", "1000000")));
        assertEquals("true expected_loss_exceeds_interruption_cost", d(c, cal("2000000"), risk("101", "1000000")));
    }

    // ---- calibration ----

    static Map<String, Object> ans(String nonce, String digest, String answer, String... kv) {
        Map<String, Object> a = j("{\"v\":1,\"principal\":\"" + P + "\",\"nonce\":\"" + nonce + "\",\"action_digest\":\"" + digest + "\",\"answer\":\"" + answer + "\"}");
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) a.remove(kv[i]);
            else a.put(kv[i], Json.parseLenient(kv[i + 1]));
        }
        return sign(KEY, "pca.escalation_answer", a);
    }

    static final Map<String, Object> RISKS = j("{\"d1\":{\"currency\":\"USD\",\"loss\":1000,\"pBadUpperPpm\":100000}}");

    static String fold(Object config, Object... answers) {
        K4.Calibration c = K4.updateCalibration(config, 1_000_000L, List.of("start-nonce"), new ArrayList<>(Arrays.asList(answers)), RISKS);
        return c.multiplierPpm + " " + c.seen;
    }

    @Test void calibration() {
        Map<String, Object> c = cfg();
        assertEquals("1500000 [start-nonce, nonce-001]", fold(c, ans("nonce-001", "d1", "deny")));
        // an invalid config folds nothing (not even the nonce)
        assertEquals("1000000 [start-nonce]", fold(sign(OTHER, "pca.escalation_pricing", j(BASE)), ans("nonce-001", "d1", "deny")));
        assertEquals("1000000 [start-nonce]", fold(null, ans("nonce-001", "d1", "deny")));
        // refused answers are skipped entirely
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "d1", "deny", "v", "2")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "d1", "deny", "v", null)));
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "d1", "deny", "v", "\"1\"")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "d1", "deny", "principal", "\"" + OTHER.id() + "\"")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("1234567", "d1", "deny")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("x", "d1", "deny", "nonce", "12345678")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("x", "d1", "deny", "nonce", null)));
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "x", "deny", "action_digest", "5")));
        assertEquals("1000000 [start-nonce]", fold(c, ans("nonce-001", "d1", "maybe")));
        assertEquals("1000000 [start-nonce]", fold(c, with(ans("nonce-001", "d1", "deny"), "sig", 5L)));
        assertEquals("1000000 [start-nonce]", fold(c, with(ans("nonce-001", "d1", "deny"), "answer", "approve")));
        assertEquals("1000000 [start-nonce]", fold(c, (Object) null));
        // the nonce is exactly 8 characters at least
        assertEquals("1500000 [start-nonce, 12345678]", fold(c, ans("12345678", "d1", "deny")));
        // an approval or an unknown digest records the nonce without tightening
        assertEquals("1000000 [start-nonce, nonce-001]", fold(c, ans("nonce-001", "d1", "approve")));
        assertEquals("1000000 [start-nonce, nonce-001]", fold(c, ans("nonce-001", "zz", "deny")));
        // a null answer is skipped, the next one still counts; a repeated nonce counts once
        assertEquals("1500000 [start-nonce, nonce-001]", fold(c, null, ans("nonce-001", "d1", "deny"), ans("nonce-001", "d1", "deny")));
    }

    // ---- network-token binding ----

    static final Map<String, Object> GRANT = j("{\"kind\":\"g\",\"n\":1}");

    static Map<String, Object> binding(String provider, String holder) {
        Map<String, Object> body = mapOf("kind", K4.BINDING_KIND, "v", 1, "provider", provider, "token_ref", "tok_abcdef123456",
            "grant_digest", Pca.hashCanonical(GRANT), "issuer_nonce", "nonce-0123456789", "holder", holder);
        Map<String, Object> b = new LinkedHashMap<>(body);
        b.remove("v");
        b.put("binding_proof", Keys.b64u(HOLDER.sign(Pca.hashCanonical(body).getBytes(StandardCharsets.UTF_8))));
        return b;
    }

    static String vb(Object b, String holder, String provider) { return K4.verifyBinding(b, GRANT, holder, "nonce-0123456789", provider); }

    @Test void networkBinding() {
        String h = HOLDER.id();
        assertNull(vb(binding("visa", h), h, null));
        assertNull(vb(binding("visa", h), h, "visa"));
        assertEquals("provider_mismatch", vb(binding("visa", h), h, "mc"));
        assertEquals("provider_mismatch", vb(binding("", h), h, null));
        assertEquals("provider_mismatch", vb(with(binding("visa", h), "provider", 5L), h, null));
        assertEquals("provider_mismatch", vb(with(binding("visa", h), "provider", null), h, null));
        assertEquals("token_ref_malformed", vb(with(binding("visa", h), "token_ref", 5L), h, null));
        assertEquals("binding_malformed", vb(null, h, null));
        assertEquals("binding_malformed", vb("x", h, null));
        assertEquals("binding_malformed", vb(with(binding("visa", h), "kind", "other"), h, null));
        assertEquals("binding_malformed", vb(binding("visa", "not+b64"), "not+b64", null));
        assertEquals("binding_malformed", vb(with(binding("visa", h), "binding_proof", "not+b64"), h, null));
        assertEquals("binding_malformed", vb(with(binding("visa", h), "binding_proof", 5L), h, null));
        assertEquals("binding_proof_invalid", vb(with(binding("visa", h), "binding_proof", Keys.b64u(OTHER.sign(new byte[] {1}))), h, null));
        assertEquals("token_ref_malformed", K4.tokenRefError(5L));
        assertEquals("token_ref_malformed", K4.tokenRefError(null));
        assertEquals("token_ref_malformed", K4.tokenRefError("short"));
        assertNull(K4.tokenRefError("tok_abcdef123456"));
        assertEquals("token_ref_looks_like_pan", K4.tokenRefError("tok-4111111111111111"));
    }

    @Test void panScreen() {
        // Luhn-valid runs at the length bounds: 13 and 19 digits are PANs, 12 and 20 are not
        assertFalse(K4.looksLikePan("411111111117"));
        assertTrue(K4.looksLikePan("4111111111119"));
        assertTrue(K4.looksLikePan("4111111111111111110"));
        assertFalse(K4.looksLikePan("41111111111111111115"));
        assertTrue(K4.looksLikePan("x4111 1111-1111 1111y"));
        // the doubling step (doubled digits 0..9 each matter)
        for (String pan : new String[] {"4111111111111111", "4012888888881881", "5555555555554444", "378282246310005", "6011111111111117",
                "4444444444444448", "9999999999999995"}) assertTrue(K4.looksLikePan(pan), pan);
        for (String no : new String[] {"4111111111111112", "1234567812345678", "4444444444444444", "5000000000000001"}) assertFalse(K4.looksLikePan(no), no);
    }

    // ---- ERC-7715 ----

    static final String MGR = "0xabababababababababababababababababababab";
    static final String ENV = "{\"grantDigest\":\"gd1\",\"expiresAtSec\":1800086400}";
    static final String SENT = "{\"chainId\":\"0x2105\",\"to\":\"0x1111111111111111111111111111111111111111\",\"permission\":{\"type\":\"erc20-token-allowance\","
        + "\"isAdjustmentAllowed\":true,\"data\":{\"tokenAddress\":\"0x2222222222222222222222222222222222222222\",\"allowance\":\"0x989680\"}},"
        + "\"rules\":[{\"type\":\"expiry\",\"data\":{\"timestamp\":1800086400}}]}";
    static final String GOT = "{\"chainId\":\"0x2105\",\"to\":\"0x1111111111111111111111111111111111111111\",\"permission\":{\"type\":\"erc20-token-allowance\","
        + "\"isAdjustmentAllowed\":true,\"data\":{\"tokenAddress\":\"0x2222222222222222222222222222222222222222\",\"allowance\":\"0x989680\"}},"
        + "\"rules\":[{\"type\":\"expiry\",\"data\":{\"timestamp\":1800086400}}],\"context\":\"0xabc123\",\"delegationManager\":\"" + MGR + "\"}";
    static final Function<String, String> CTX = k -> "0xabc123".equals(k) ? "gd1" : null;

    static String vg(String env, String sent, String got, List<String> mgrs, Function<String, String> ctx) {
        return K4.verifyGranted(Json.parseLenient(env), Json.parseLenient(sent), Json.parseLenient(got), mgrs, ctx);
    }
    static String vg(String sent, String got) { return vg(ENV, sent, got, List.of(MGR), CTX); }
    static String got(String from, String to) { return GOT.replace(from, to); }

    @Test void erc7715() {
        assertNull(vg(SENT, GOT));
        assertNull(vg(ENV, SENT, GOT, List.of(MGR), null));
        assertNull(vg(ENV, SENT, GOT, List.of(MGR), k -> null));
        assertEquals("context_bound_to_other_grant", vg(ENV, SENT, GOT, List.of(MGR), k -> "other"));
        assertEquals("response_malformed", vg(ENV, SENT, "null", List.of(MGR), CTX));
        assertEquals("response_malformed", vg(ENV, SENT, "[]", List.of(MGR), CTX));
        assertEquals("response_malformed", vg(SENT, got("\"permission\":{", "\"permission\":5,\"x\":{")));
        // context
        assertEquals("context_malformed", vg(SENT, got("\"context\":\"0xabc123\"", "\"context\":5")));
        assertEquals("context_malformed", vg(SENT, got("\"context\":\"0xabc123\",", "")));
        assertEquals("context_malformed", vg(SENT, got("\"context\":\"0xabc123\"", "\"context\":\"abc123\"")));
        // delegation manager
        assertEquals("delegation_manager_not_allowed", vg(SENT, got("\"delegationManager\":\"" + MGR + "\"", "\"delegationManager\":5")));
        assertEquals("delegation_manager_not_allowed", vg(SENT, got(",\"delegationManager\":\"" + MGR + "\"", "")));
        assertEquals("delegation_manager_not_allowed", vg(ENV, SENT, got(MGR, "0xabc"), List.of("0xabc"), CTX));
        assertNull(vg(ENV, SENT, got(MGR, MGR.toUpperCase().replace("0X", "0x")), List.of(MGR), CTX));
        // chain / recipient compare case-insensitively; absent on both sides is equal
        assertNull(vg(SENT.replace("0x2105", "0xAB"), got("0x2105", "0xab")));
        assertNull(vg(SENT.replace("\"chainId\":\"0x2105\",", ""), got("\"chainId\":\"0x2105\",", "")));
        assertEquals("chain_mismatch", vg(SENT, got("\"chainId\":\"0x2105\",", "")));
        assertNull(vg(SENT.replace("0x1111111111111111111111111111111111111111", "0xAAAA"), got("0x1111111111111111111111111111111111111111", "0xaaaa")));
        // from: checked only when the request names one
        String sentFrom = SENT.replace("{\"chainId\"", "{\"from\":\"0xAA\",\"chainId\"");
        assertNull(vg(sentFrom, got("{\"chainId\"", "{\"from\":\"0xaa\",\"chainId\"")));
        assertEquals("from_mismatch", vg(sentFrom, got("{\"chainId\"", "{\"from\":\"0xbb\",\"chainId\"")));
        assertEquals("from_mismatch", vg(sentFrom, GOT));
        assertNull(vg(SENT, got("{\"chainId\"", "{\"from\":\"0xbb\",\"chainId\"")));
        assertNull(vg(SENT.replace("{\"chainId\"", "{\"from\":null,\"chainId\""), got("{\"chainId\"", "{\"from\":\"0xbb\",\"chainId\"")));
        // permission type
        assertEquals("permission_type_mismatch", vg(SENT, got("\"type\":\"erc20-token-allowance\",", "")));
        // data / token / amount
        assertEquals("response_malformed", vg(SENT, got(",\"data\":{\"tokenAddress\":\"0x2222222222222222222222222222222222222222\",\"allowance\":\"0x989680\"}", "")));
        assertNull(vg(SENT.replace("0x2222222222222222222222222222222222222222", "0xABCD"), got("0x2222222222222222222222222222222222222222", "0xabcd")));
        assertNull(vg(SENT.replace("0x2222222222222222222222222222222222222222", "0xabcd"), got("0x2222222222222222222222222222222222222222", "0xABCD")));
        assertEquals("token_mismatch", vg(SENT, got("0x2222222222222222222222222222222222222222", "0xabcd")));
        assertEquals("amount_malformed", vg(SENT, got("\"allowance\":\"0x989680\"", "\"allowance\":5")));
        assertEquals("amount_malformed", vg(SENT, got("\"allowance\":\"0x989680\"", "\"allowance\":\"989680\"")));
        // adjustment: only switching it ON widens
        assertNull(vg(SENT, got("\"isAdjustmentAllowed\":true", "\"isAdjustmentAllowed\":false")));
        assertNull(vg(SENT, got("\"isAdjustmentAllowed\":true,", "")));
        assertEquals("adjustment_widened", vg(SENT.replace("\"isAdjustmentAllowed\":true", "\"isAdjustmentAllowed\":false"), GOT));
        // rules
        String rules = "\"rules\":[{\"type\":\"expiry\",\"data\":{\"timestamp\":1800086400}}]";
        assertEquals("unknown_rule_type", vg(SENT, got(rules, "\"rules\":[null]")));
        assertEquals("expiry_malformed", vg(SENT, got(rules, "\"rules\":[{\"type\":\"expiry\"}]")));
        assertEquals("expiry_malformed", vg(SENT, got(rules, "\"rules\":[{\"type\":\"expiry\",\"data\":5}]")));
        assertEquals("expiry_malformed", vg(SENT, got(rules, "\"rules\":[{\"type\":\"expiry\",\"data\":{\"timestamp\":\"5\"}}]")));
        assertEquals("duplicate_expiry", vg(SENT, got(rules, "\"rules\":[{\"type\":\"expiry\",\"data\":{\"timestamp\":1}},{\"type\":\"expiry\",\"data\":{\"timestamp\":1}}]")));
        assertNull(vg(SENT, got("1800086400}}]", "1800086399}}]")));
        assertEquals("expiry_extended", vg(SENT, got("1800086400}}]", "1800086401}}]")));
        // a grant without expiresAtSec reads as 0: any positive expiry extends it, 0 does not
        assertEquals("expiry_extended", vg("{\"grantDigest\":\"gd1\"}", SENT, got("1800086400}}]", "1}}]"), List.of(MGR), CTX));
        assertNull(vg("{\"grantDigest\":\"gd1\"}", SENT, got("1800086400}}]", "0}}]"), List.of(MGR), CTX));
    }
}
