package net.atlasauth.pca.payments;

import net.atlasauth.pca.Json;

import static net.atlasauth.pca.payments.PayJs.copy;
import static net.atlasauth.pca.payments.PayJs.get;
import static net.atlasauth.pca.payments.PayJs.has;
import static net.atlasauth.pca.payments.PayJs.map;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Agent payment network tokens: a {@code NetworkTokenBinding} ties a PCA grant holder to an OPAQUE network-token reference (never a PAN)
 * and carries the PCActn digest onto the charge so the card-network record joins the PCA ledger entry (the reference's network-token
 * module). The Visa and Mastercard adapters are GENERIC mappings of PCA controls onto a neutral shape, mock-tested in the reference and
 * making no network call themselves: the caller supplies the {@link PartnerTransport}. Every check is exact; malformed input is a refusal.
 */
public final class NetworkToken {
    private NetworkToken() {}

    public static final String NETWORK_TOKEN_BINDING_KIND = "pca.network_token_binding";

    /** {@code token_ref} is an opaque handle: 8..128 chars of [A-Za-z0-9_.:-]. */
    private static final Pattern REF_RE = Pattern.compile("[A-Za-z0-9_.:-]{8,128}");

    private static boolean luhn(String d) {
        int sum = 0;
        boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int n = d.charAt(i) - 48;
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    /** True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only: no sliding windows. */
    public static boolean looksLikePan(String s) {
        StringBuilder run = new StringBuilder();
        // JavaScript's \s: whitespace and line terminators (the Unicode set), plus the hyphen
        String t = s.chars().filter(c -> !isJsSpace((char) c) && c != '-').collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        for (int i = 0; i <= t.length(); i++) {
            char c = i < t.length() ? t.charAt(i) : 'x';
            if (c >= '0' && c <= '9') { run.append(c); continue; }
            if (run.length() >= 13 && run.length() <= 19 && luhn(run.toString())) return true;
            run.setLength(0);
        }
        return false;
    }

    private static boolean isJsSpace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }

    /** null when the reference is acceptable, else token_ref_malformed or token_ref_looks_like_pan. */
    public static String tokenRefError(Object ref) {
        if (!(ref instanceof String) || !REF_RE.matcher((String) ref).matches()) return "token_ref_malformed";
        if (looksLikePan((String) ref)) return "token_ref_looks_like_pan";
        return null;
    }

    private static Map<String, Object> bodyOf(Object provider, Object tokenRef, Object grantDigest, Object issuerNonce, Object holder) {
        return map("kind", NETWORK_TOKEN_BINDING_KIND, "v", new net.atlasauth.pca.Json.Num("1"), "provider", provider, "token_ref", tokenRef,
            "grant_digest", grantDigest, "issuer_nonce", issuerNonce, "holder", holder);
    }

    /** The exact bytes the holder signs: utf8 of the canonical-JSON digest of the body (domain-separated by {@code kind}). */
    public static byte[] bindingMessage(Map<String, Object> b) {
        return Pca.hashCanonical(bodyOf(b.get("provider"), b.get("token_ref"), b.get("grant_digest"), b.get("issuer_nonce"), b.get("holder"))).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Bind a token reference to the grant and its holder. {@code opts}: provider, tokenRef, grant, issuerNonce (at least 16 chars),
     * holderSecret (32-byte seed) and holderPublic (32 bytes), bytes as byte[] or {@code {"$bytes": b64url}}.
     */
    public static Map<String, Object> bindNetworkToken(Map<String, Object> opts) {
        String e = tokenRefError(opts.get("tokenRef"));
        if (e != null) throw new IllegalArgumentException("bindNetworkToken: " + e);
        if (((String) opts.get("issuerNonce")).length() < 16) throw new IllegalArgumentException("bindNetworkToken: issuer nonce must be at least 16 chars");
        byte[] seed = PayJs.bytes(opts.get("holderSecret"));
        byte[] pub = PayJs.bytes(opts.get("holderPublic"));
        if (seed == null || pub == null) throw new IllegalArgumentException("bindNetworkToken: holderSecret and holderPublic are required");
        Map<String, Object> core = map("provider", opts.get("provider"), "token_ref", opts.get("tokenRef"), "grant_digest", Pca.hashCanonical(opts.get("grant")),
            "issuer_nonce", opts.get("issuerNonce"), "holder", Keys.b64u(pub));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", NETWORK_TOKEN_BINDING_KIND);
        out.putAll(core);
        out.put("binding_proof", Keys.b64u(Keys.edFromSeed(seed).sign(bindingMessage(core))));
        return out;
    }

    /**
     * Total. null = valid, else the refusal code. {@code expect}: grant (the one the caller verified), holder (the key the caller expects: the
     * grant's leaf holder), issuerNonce, and optionally provider.
     */
    public static String verifyNetworkTokenBinding(Object b, Map<String, Object> expect) {
        try {
            if (!(b instanceof Map) || !NETWORK_TOKEN_BINDING_KIND.equals(get(b, "kind"))) return "binding_malformed";
            Map<String, Object> x = copy(b);
            String e = tokenRefError(x.get("token_ref"));
            if (e != null) return e;
            Object prov = x.get("provider");
            if (!(prov instanceof String) || ((String) prov).isEmpty() || (has(expect, "provider") && !prov.equals(expect.get("provider")))) return "provider_mismatch";
            if (!has(expect, "grant")) return "binding_malformed";
            if (!java.util.Objects.equals(x.get("grant_digest"), Pca.hashCanonical(expect.get("grant")))) return "grant_digest_mismatch";
            if (!java.util.Objects.equals(x.get("holder"), expect.get("holder"))) return "holder_mismatch";
            if (!java.util.Objects.equals(x.get("issuer_nonce"), expect.get("issuerNonce"))) return "issuer_nonce_mismatch";
            byte[] pk = Keys.unb64u((String) x.get("holder"));
            byte[] msg = bindingMessage(x);
            byte[] sig = Keys.unb64u((String) x.get("binding_proof"));
            return EdStrict.verify(pk, msg, sig) ? null : "binding_proof_invalid";
        } catch (RuntimeException ex) {
            return "binding_malformed";
        }
    }

    // ---- controls + provider interface -----------------------------------------------------------------------------------

    /** The network-side controls: always an upper-bounded copy of the rail limits, echoing the grant digest as metadata. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> controlsFromLimits(Map<String, Object> limits, Object grant) {
        Map<String, Object> out = map("currency", limits.get("currency"), "perAuthorizationMax", limits.get("perAuthorizationMax"), "totalMax", limits.get("totalMax"),
            "categories", new ArrayList<>((List<Object>) limits.get("categories")), "merchants", new ArrayList<>((List<Object>) limits.get("merchants")));
        if (has(limits, "expiresAt")) out.put("expiresAt", limits.get("expiresAt"));
        out.put("metadata", map("grant_digest", Pca.hashCanonical(grant)));
        return out;
    }

    /** A token provider (Visa, Mastercard, generic). */
    public interface NetworkTokenProvider {
        String id();

        /** Issue/activate a token whose own controls equal {@code controls}; returns {@code {token_ref}}. */
        Map<String, Object> issue(Map<String, Object> controls, String agentId);

        /** Suspend the token (grant revoked). Must be idempotent. */
        void suspend(String tokenRef, String reason);
    }

    /**
     * Issuance gate: builds the controls from the rail limits, asks the provider to issue, then binds the returned reference to the grant and
     * holder. A provider response whose token_ref is malformed or PAN-shaped is refused. {@code opts}: limits, grant, agentId, holderSecret,
     * holderPublic, issuerNonce. Returns {@code {binding, controls}}.
     */
    public static Map<String, Object> issueBoundNetworkToken(NetworkTokenProvider provider, Map<String, Object> opts) {
        @SuppressWarnings("unchecked")
        Map<String, Object> controls = controlsFromLimits((Map<String, Object>) opts.get("limits"), opts.get("grant"));
        Map<String, Object> r = provider.issue(controls, (String) opts.get("agentId"));
        Map<String, Object> bo = new LinkedHashMap<>();
        bo.put("provider", provider.id());
        bo.put("tokenRef", r.get("token_ref"));
        bo.put("grant", opts.get("grant"));
        bo.put("issuerNonce", opts.get("issuerNonce"));
        bo.put("holderSecret", opts.get("holderSecret"));
        bo.put("holderPublic", opts.get("holderPublic"));
        return map("binding", bindNetworkToken(bo), "controls", controls);
    }

    /** Grant revoked: suspend. Provider errors propagate (a failed suspend is not a success). */
    public static void suspendOnRevoke(NetworkTokenProvider provider, Map<String, Object> binding) {
        provider.suspend((String) binding.get("token_ref"), "grant_revoked");
    }

    // ---- the charge carries the PCActn digest ----------------------------------------------------------------------------

    /** The metadata a charge/authorization carries: fixed keys, digest values (no PII, no PAN). */
    public static Map<String, Object> settlementMetadata(Map<String, Object> binding, String pcactnDigest) {
        return map("pca_grant", binding.get("grant_digest"), "pca_pcactn", pcactnDigest, "pca_token_ref", binding.get("token_ref"));
    }

    /**
     * The one way to start a network-token charge: builds the signed PCActn for the charge and returns the metadata for the network request,
     * derived from THAT PCActn's digest. Returns {@code {pcactn, node, metadata, pcactnDigest}}; {@code opts} are those of {@link Payments#chargeToPCActn}.
     */
    public static Map<String, Object> chargeWithNetworkToken(Map<String, Object> binding, Map<String, Object> mandate, Map<String, Object> charge, Map<String, Object> opts) {
        if (tokenRefError(binding.get("token_ref")) != null) throw new IllegalArgumentException("chargeWithNetworkToken: bad binding");
        if (!java.util.Objects.equals(binding.get("grant_digest"), Pca.hashCanonical(mandate.get("grant")))) throw new IllegalArgumentException("chargeWithNetworkToken: binding is for another grant");
        Map<String, Object> r = Payments.chargeToPCActn(mandate, charge, opts);
        String digest = Pca.hashCanonical(r.get("pcactn"));
        return map("pcactn", r.get("pcactn"), "node", r.get("node"), "metadata", settlementMetadata(binding, digest), "pcactnDigest", digest);
    }

    /** A network settlement record joins the ledger entry only if all three echoed values match exactly: {@code {ok: true}} or {@code {ok: false, reasons}}. */
    public static Map<String, Object> reconcileNetworkSettlement(Map<String, Object> expected, Map<String, Object> record) {
        Object m0 = get(record, "metadata");
        Object m = m0 == null ? map() : m0;
        List<Object> reasons = new ArrayList<>();
        Object pc = get(m, "pca_pcactn");
        // a settlement without the PCActn digest never joins, even if the expectation is empty too
        if (!(pc instanceof String) || ((String) pc).isEmpty() || emptyLength(expected.get("pcactnDigest"))) reasons.add("pcactn_digest_missing");
        if (!java.util.Objects.equals(get(m, "pca_grant"), expected.get("grantDigest"))) reasons.add("grant_digest_mismatch");
        if (!java.util.Objects.equals(pc, expected.get("pcactnDigest"))) reasons.add("pcactn_digest_mismatch");
        if (!java.util.Objects.equals(get(m, "pca_token_ref"), expected.get("tokenRef"))) reasons.add("token_ref_mismatch");
        return reasons.isEmpty() ? map("ok", true) : map("ok", false, "reasons", reasons);
    }

    /** {@code x.length === 0}: undefined/null has no length (TypeError), a number has none (false). */
    private static boolean emptyLength(Object x) {
        if (x == null) throw new NullPointerException("expected.pcactnDigest is required");
        return PayJs.jsLength(x) == 0;
    }

    // ---- generic partner-gated adapters ----------------------------------------------------------------------------------

    /** The partner's HTTP surface; the caller supplies it (these adapters make no network call themselves). */
    public interface PartnerTransport {
        Map<String, Object> post(String path, Map<String, Object> body);
    }

    static String encodeUriComponent(String s) {
        if (Json.hasLoneSurrogate(s)) throw new IllegalArgumentException("URI malformed"); // the JavaScript URIError
        StringBuilder sb = new StringBuilder();
        for (byte b : Json.utf8(s)) {
            char c = (char) (b & 0xff);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".indexOf(c) >= 0) sb.append(c);
            else sb.append('%').append(Character.toUpperCase(Character.forDigit((b >> 4) & 15, 16))).append(Character.toUpperCase(Character.forDigit(b & 15, 16)));
        }
        return sb.toString();
    }

    /**
     * LABEL: GENERIC MAPPING, NOT THE PARTNER WIRE FORMAT. The path and body names are placeholders; replace them with the partner's documented
     * ones once access exists. The control VALUES are exact copies of PCA's limits.
     */
    private static NetworkTokenProvider partnerAdapter(String id, String scopeKey, PartnerTransport t) {
        return new NetworkTokenProvider() {
            @Override public String id() { return id; }

            @Override public Map<String, Object> issue(Map<String, Object> controls, String agentId) {
                Map<String, Object> scope = map("currency", controls.get("currency"), "per_authorization_max", controls.get("perAuthorizationMax"), "total_max", controls.get("totalMax"),
                    "merchant_categories", controls.get("categories"), "merchants", controls.get("merchants"));
                if (has(controls, "expiresAt")) scope.put("expires_at", controls.get("expiresAt"));
                Map<String, Object> r = t.post("/tokens", map("agent_id", agentId, scopeKey, scope, "metadata", controls.get("metadata")));
                Object ref = r.get("token_ref");
                String e = tokenRefError(ref);
                if (e != null) throw new IllegalStateException(id + ": provider returned " + e);
                return map("token_ref", ref);
            }

            @Override public void suspend(String tokenRef, String reason) {
                t.post("/tokens/" + encodeUriComponent(tokenRef) + "/suspend", map("reason", reason));
            }
        };
    }

    /** Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names). */
    public static NetworkTokenProvider visaIntelligentCommerceAdapter(PartnerTransport t) { return partnerAdapter("visa_ic", "instructions", t); }

    /** Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names). */
    public static NetworkTokenProvider mastercardAgentPayAdapter(PartnerTransport t) { return partnerAdapter("mastercard_agent_pay", "session_scope", t); }
}
