package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Signed agent passport verification (wire level), the native counterpart of verifyPassport in @atlasauth/pca.
 * Same reason codes and check order; the reason text is not part of the contract. Every signature suite this verifier
 * implements for PCActns ({@link Pq#supportedSuites()}) is accepted, the post-quantum ones only under a PQ key pinned for
 * the issuer ({@link Options#pqPins}); a suite it does not implement is refused with {@code unsupported_suite}.
 *
 * <p>Hardware evidence: the age rule, the binding handed to the verifier and the identity comparison are enforced here.
 * The verifier is the integrator's {@link Options#attest}, or, when none is given, {@link Options#defaultHardware}
 * (the built-in vendor verifiers); an integrator {@code attest} always wins. With neither, a hardware_rooted passport that
 * passes every other check is refused with {@code hardware_verifier_missing} (fail closed, never a software pass).
 */
public final class Passport {
    private Passport() {}

    static final byte[] SIG_DOMAIN = "atlas-pca/passport-sig/v1\0".getBytes(StandardCharsets.UTF_8);
    public static final long DEFAULT_EVIDENCE_AGE_MS = 24L * 3600_000L;
    public static final long MAX_SKEW_MS = 60_000L;
    private static final long MAX_SAFE = 9007199254740991L;

    /** What the quote's bound value must equal: holder = the subject key, grant = "passport:&lt;id&gt;", epoch 0. */
    public static final class Binding {
        public final String holderPub, grantRef, nonce;
        public final long epoch;
        public Binding(String holderPub, String grantRef, long epoch, String nonce) {
            this.holderPub = holderPub; this.grantRef = grantRef; this.epoch = epoch; this.nonce = nonce;
        }
    }

    /**
     * A hardware verifier's answer. {@code measured} holds model_id, operator, weights_digest, weights_measured,
     * runtime_measurement, system_prompt_digest and tool_manifest_digest as the hardware measured them.
     */
    public static final class Attestation {
        public final boolean ok, bound;
        public final Map<String, Object> measured;
        public Attestation(boolean ok, boolean bound, Map<String, Object> measured) { this.ok = ok; this.bound = bound; this.measured = measured; }
    }

    /** Verifies hardware evidence (a vendor verifier). May throw: a throw is {@code hardware_attestation_failed}. */
    @FunctionalInterface
    public interface Attest { Attestation verify(Map<String, Object> doc, Binding expected) throws Exception; }

    /**
     * The built-in vendor verifier seam, used when no integrator {@link Attest} is given. The adapter point for the vendor
     * verifiers: given the verification clock, return the {@link Attest} that checks one evidence document.
     */
    @FunctionalInterface
    public interface DefaultHardware { Attest attest(long nowMs); }

    /** Reports whether the passport is revoked; may throw (then {@code revocation_unavailable}). */
    @FunctionalInterface
    public interface Revoked { boolean isRevoked(String id, String iss, String sub) throws Exception; }

    /** Configuration of {@link #verify}. */
    public static final class Options {
        public List<String> trustedIssuers = List.of();
        public long nowMs;
        /** null = 0; clamped to [0, 60000]. */
        public Long clockSkewMs;
        /** null = 24 h. */
        public Long maxEvidenceAgeMs;
        /** When non-null, must equal the passport's sub. */
        public String subject;
        /** Issuer key to the PQ public key pinned for it (required for every non-Ed25519 suite). */
        public Map<String, Object> pqPins;
        public Attest attest;
        public DefaultHardware defaultHardware;
        /** null = no revocation source (revocation_unavailable). */
        public Revoked revoked;
    }

    private static boolean nonEmpty(Object v) { return v instanceof String && !((String) v).isEmpty(); }

    private static Map<String, Object> map(Object v) {
        if (!(v instanceof Map)) return null;
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    /** Returns "" when the passport verifies, else the reason code. Never throws. */
    public static String verify(Object sp, Options o) {
        try {
            return verifyUnchecked(sp, o);
        } catch (RuntimeException e) {
            return "malformed";
        }
    }

    private static String verifyUnchecked(Object sp, Options o) {
        Map<String, Object> s = map(sp);
        if (s == null) return "malformed";
        Map<String, Object> p = map(s.get("passport"));
        if (!"atlas-pca/passport".equals(s.get("typ")) || p == null) return "malformed";
        Object ver = s.get("ver");
        if (!Json.isSafeInt(ver) || Json.asLong(ver) != 1) return "unsupported_version";
        boolean algPresent = s.containsKey("alg");
        Object alg = s.get("alg");
        if (algPresent && Pq.resolveSigAlg(alg, true) == null) return "unsupported_suite";
        if (!(nonEmpty(s.get("iss")) && nonEmpty(s.get("sub")) && nonEmpty(s.get("sig")) && nonEmpty(p.get("id"))
            && nonEmpty(p.get("model_id")) && nonEmpty(p.get("operator")) && p.get("hardware_rooted") instanceof Boolean))
            return "malformed";
        String iss = (String) s.get("iss"), sub = (String) s.get("sub"), id = (String) p.get("id");
        boolean hw = (Boolean) p.get("hardware_rooted");
        if (!(Json.isSafeInt(s.get("nbf")) && Json.isSafeInt(s.get("exp")) && Json.isSafeInt(s.get("iat")))) return "malformed";
        long nbf = Json.asLong(s.get("nbf")), exp = Json.asLong(s.get("exp"));
        if (exp <= nbf || o.nowMs > MAX_SAFE || o.nowMs < -MAX_SAFE) return "malformed";
        if (!o.trustedIssuers.contains(iss)) return "unknown_issuer";
        Map<String, Object> body = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : s.entrySet())
            if (!e.getKey().equals("sig") && !e.getKey().equals("pq_sig")) body.put(e.getKey(), e.getValue());
        String canon;
        try { canon = Json.canonicalizeStrict(body); } catch (IllegalArgumentException e) { return "malformed"; }
        byte[] msg = Pca.concat(SIG_DOMAIN, canon.getBytes(StandardCharsets.UTF_8));
        if (!IntentJs.verifyPinnedSuite(alg, algPresent, iss, s.get("pq_pk"), msg, s.get("sig"), s.get("pq_sig"), o.pqPins))
            return "bad_signature";
        Map<String, Object> fp = new LinkedHashMap<>();
        fp.put("d", "atlas-pca/passport/v1");
        fp.put("operator", p.get("operator"));
        fp.put("hardware_rooted", hw);
        for (String k : new String[] {"model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"})
            fp.put(k, p.containsKey(k) ? p.get(k) : null);
        String want;
        try { want = Pca.hashCanonical(fp); } catch (RuntimeException e) { return "id_mismatch"; }
        if (!want.equals(id)) return "id_mismatch";
        long skew = o.clockSkewMs == null ? 0 : Math.min(Math.max(o.clockSkewMs, 0), MAX_SKEW_MS);
        if (o.nowMs + skew < nbf) return "not_yet_valid";
        if (o.nowMs - skew >= exp) return "expired";
        if (o.subject != null && !o.subject.equals(sub)) return "subject_mismatch";
        if (o.revoked == null) return "revocation_unavailable";
        try {
            if (o.revoked.isRevoked(id, iss, sub)) return "revoked";
        } catch (Exception e) {
            return "revocation_unavailable";
        }
        if (hw) {
            Map<String, Object> ev = map(s.get("evidence"));
            Map<String, Object> doc = ev == null ? null : map(ev.get("document"));
            if (doc == null || !nonEmpty(doc.get("nonce"))) return "hardware_evidence_missing";
            if (!Json.isSafeInt(ev.get("at"))) return "hardware_evidence_missing";
            long at = Json.asLong(ev.get("at"));
            long maxAge = o.maxEvidenceAgeMs == null ? DEFAULT_EVIDENCE_AGE_MS : o.maxEvidenceAgeMs;
            if (maxAge < 0 || o.nowMs - at > maxAge || at - o.nowMs > skew) return "hardware_evidence_stale";
            Attest attest = o.attest;
            if (attest == null && o.defaultHardware == null) return "hardware_verifier_missing";
            Attestation r;
            try {
                if (attest == null) attest = o.defaultHardware.attest(o.nowMs);
                r = attest.verify(doc, new Binding(sub, "passport:" + id, 0, (String) doc.get("nonce")));
            } catch (Exception e) {
                return "hardware_attestation_failed";
            }
            if (r == null || !r.ok || !r.bound) return "hardware_attestation_failed";
            if (!identityMatches(p, r.measured)) return "hardware_identity_mismatch";
        }
        return "";
    }

    /**
     * The hardware-measured identity equals the claims: model and operator always; the optional digests and the runtime
     * measurement when the passport states them; measured weights when it claims them.
     */
    static boolean identityMatches(Map<String, Object> p, Map<String, Object> m) {
        if (m == null) return false;
        if (!eq(p, m, "model_id") || !eq(p, m, "operator")) return false;
        for (String k : new String[] {"weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"})
            if (p.containsKey(k) && !eq(p, m, k)) return false;
        return !Boolean.TRUE.equals(p.get("weights_measured")) || Boolean.TRUE.equals(m.get("weights_measured"));
    }

    private static boolean eq(Map<String, Object> p, Map<String, Object> m, String k) {
        return p.get(k) instanceof String && m.get(k) instanceof String && p.get(k).equals(m.get(k));
    }
}
