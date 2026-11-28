package net.atlasauth.pca.attesteat;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.jose.Jose;

/**
 * POST-QUANTUM co-signature of a verified attestation verdict (port of {@code pqcosign.ts}). After the classical AMD hardware root has been
 * verified, the verdict's security-relevant fields are bound under a post-quantum signature (ML-DSA-65 by default, or a hybrid / nested /
 * category-5 suite), so PCA's propagation of the verdict no longer rests on classical crypto. This does NOT make AMD's root post-quantum; it
 * makes the recorded verdict forward-secure. A classical-only suite is refused (fail closed).
 *
 * <p>A verdict is the JSON-shaped map {tier, trustworthy, measured?, measurement?, nonce?, iat?, issuer?}; a co-signed attestation is
 * {verdict, cosig: {cosignedAt, sig, pq_sig?}, suite, signer_pub: {pq, ed?}}.
 */
public final class AttestEatPq {
    private AttestEatPq() {}

    public static final String PQCOSIGN_DOMAIN = "atlas-pca/attest-cosign/v1";
    public static final String DEFAULT_PQ_COSIGN_SUITE = "ml-dsa-65";
    public static final List<String> PQ_COSIGN_SUITES = List.of(
        "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
        "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s");

    /** Type guard: {@code x} is one of the accepted PQ co-sign suites (rejects ed25519, unknown names, non-strings). */
    public static boolean isPqCoSignSuite(Object x) { return x instanceof String && PQ_COSIGN_SUITES.contains(x); }

    private static boolean has(Map<String, Object> m, String k) { return m.containsKey(k); }

    private static Object canonicalMeasured(Map<String, Object> verdict) {
        if (!has(verdict, "measured")) return null;
        Object mo = verdict.get("measured");
        if (mo == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'model_id')");
        Map<String, Object> m = AttestEat.rec(mo);
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : new String[] {"model_id", "weights_digest"}) if (m != null && m.containsKey(k)) out.put(k, m.get(k));
        out.put("weights_measured", m != null && m.get("weights_measured") instanceof Boolean ? m.get("weights_measured") : null);
        for (String k : new String[] {"runtime_measurement", "operator"}) if (m != null && m.containsKey(k)) out.put(k, m.get(k));
        out.put("system_prompt_digest", m != null && m.get("system_prompt_digest") instanceof String ? m.get("system_prompt_digest") : null);
        out.put("tool_manifest_digest", m != null && m.get("tool_manifest_digest") instanceof String ? m.get("tool_manifest_digest") : null);
        return out;
    }

    /**
     * The CANONICAL, DETERMINISTIC bytes the co-signature is computed over: {@code utf8(JSON.stringify(obj))} with {@code obj} in the fixed
     * order typ, tier, trustworthy, measurement, measured, nonce, iat, issuer, cosignedAt, every optional emitted as its value or null.
     */
    public static byte[] canonicalVerdictBytes(Map<String, Object> verdict, Object cosignedAt) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("typ", PQCOSIGN_DOMAIN);
        if (has(verdict, "tier")) c.put("tier", verdict.get("tier"));
        c.put("trustworthy", Boolean.TRUE.equals(verdict.get("trustworthy")));
        c.put("measurement", verdict.get("measurement") instanceof String ? verdict.get("measurement") : null);
        c.put("measured", canonicalMeasured(verdict));
        c.put("nonce", verdict.get("nonce") instanceof String ? verdict.get("nonce") : null);
        Double iat = Jose.num(verdict.get("iat"));
        c.put("iat", iat != null && !iat.isNaN() && !iat.isInfinite() ? verdict.get("iat") : null);
        c.put("issuer", verdict.get("issuer") instanceof String ? verdict.get("issuer") : null);
        if (cosignedAt != null) c.put("cosignedAt", cosignedAt);
        return Jose.stringify(c).getBytes(StandardCharsets.UTF_8);
    }

    /** Build a verdict from an {@link AttestEat#appraise} result plus the EAT claims (tier, trustworthy, measured, measurement, nonce, iat, issuer). */
    public static Map<String, Object> verdictFromAppraisal(Map<String, Object> result, Map<String, Object> claims) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("tier", result.get("tier"));
        v.put("trustworthy", result.get("trustworthy"));
        if (claims.containsKey("measured")) v.put("measured", claims.get("measured"));
        Object rm = claims.get("measured") instanceof Map ? ((Map<?, ?>) claims.get("measured")).get("runtime_measurement") : null;
        Object measurement = rm instanceof String && !((String) rm).isEmpty() ? rm : (claims.get("sevsnp") instanceof Map ? ((Map<?, ?>) claims.get("sevsnp")).get("measurement") : null);
        if (measurement instanceof String && !((String) measurement).isEmpty()) v.put("measurement", measurement);
        if (claims.get("eat_nonce") instanceof String) v.put("nonce", claims.get("eat_nonce"));
        Double iat = Jose.num(claims.get("iat"));
        if (iat != null && !iat.isNaN() && !iat.isInfinite()) v.put("iat", claims.get("iat"));
        if (claims.get("iss") instanceof String) v.put("issuer", claims.get("iss"));
        return v;
    }

    /** Options of {@link #coSignAttestation}. */
    public static final class CoSignOptions {
        /** The suite name (default {@link #DEFAULT_PQ_COSIGN_SUITE}); a classical-only or unknown suite is refused. */
        public String suite;
        /** The co-signer's key material for that suite ({@link Keys#suite}). */
        public Keys.SuiteKey secretKey;
        /** Pin the co-sign timestamp (epoch ms, a JSON-shaped number) for a deterministic signature; null = now. */
        public Object now;

        public CoSignOptions(Keys.SuiteKey secretKey) { this.secretKey = secretKey; }
    }

    /**
     * Co-sign a verified attestation verdict under a post-quantum suite. Call AFTER the classical hardware verification has passed.
     * FAIL-CLOSED on misconfiguration: a classical-only or unknown suite, or key material for a different suite, THROWS.
     */
    public static Map<String, Object> coSignAttestation(Map<String, Object> verdict, CoSignOptions opts) {
        String suiteName = opts.suite != null ? opts.suite : DEFAULT_PQ_COSIGN_SUITE;
        if (!isPqCoSignSuite(suiteName)) throw new IllegalArgumentException("coSignAttestation: '" + suiteName + "' is not an accepted post-quantum co-sign suite");
        if (opts.secretKey == null) throw new IllegalArgumentException("coSignAttestation: secretKey material is required");
        if (!suiteName.equals(opts.secretKey.alg)) throw new IllegalArgumentException("coSignAttestation: suite '" + suiteName + "' requires key material for that suite");
        Double nowD = Jose.num(opts.now);
        Object cosignedAt = nowD != null && !nowD.isNaN() && !nowD.isInfinite() ? opts.now : (Object) System.currentTimeMillis();
        byte[] msg = canonicalVerdictBytes(verdict, cosignedAt);
        Map<String, Object> signerPub = new LinkedHashMap<>();
        signerPub.put("pq", opts.secretKey.pq.pkB64u());
        if (opts.secretKey.ed != null) signerPub.put("ed", opts.secretKey.ed.id());
        String[] parts = opts.secretKey.sign(msg);
        Map<String, Object> cosig = new LinkedHashMap<>();
        cosig.put("cosignedAt", cosignedAt);
        cosig.put("sig", parts[0]);
        if (parts[1] != null) cosig.put("pq_sig", parts[1]);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verdict", verdict);
        out.put("cosig", cosig);
        out.put("suite", suiteName);
        out.put("signer_pub", signerPub);
        return out;
    }

    private static Map<String, Object> parseSignerPub(Object v) {
        Map<String, Object> r = AttestEat.rec(v);
        if (r == null || !(r.get("pq") instanceof String) || ((String) r.get("pq")).isEmpty()) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("pq", r.get("pq"));
        if (r.get("ed") instanceof String && !((String) r.get("ed")).isEmpty()) out.put("ed", r.get("ed"));
        return out;
    }

    private static boolean signerMatches(Object expected, Map<String, Object> got) {
        Object expPq;
        if (expected instanceof String) expPq = expected;
        else if (expected == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'pq')");
        else expPq = expected instanceof Map ? ((Map<?, ?>) expected).get("pq") : null;
        if (!(expPq instanceof String) || !AttestEat.strEq((String) expPq, (String) got.get("pq"))) return false;
        Map<String, Object> e = AttestEat.rec(expected);
        if (e != null && e.get("ed") instanceof String) {
            if (!(got.get("ed") instanceof String) || !AttestEat.strEq((String) e.get("ed"), (String) got.get("ed"))) return false;
        }
        return true;
    }

    private static Object numOut(double d) { return d == Math.rint(d) && Math.abs(d) < 9007199254740992.0 ? (Object) (long) d : (Object) d; }

    private static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String || v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num) return Json.canonicalize(v);
        if (v instanceof List) return "";
        return "[object Object]";
    }

    private static Map<String, Object> fail(Map<String, Object> partial, String reason) {
        Map<String, Object> m = new LinkedHashMap<>(partial);
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    /**
     * Verify a co-signed attestation: recompute the canonical verdict bytes from the artifact's OWN verdict and co-sign time and check the
     * post-quantum signature under the embedded signer key. FAIL CLOSED on a malformed artifact, a classical-only or unknown suite, a tampered
     * verdict, a wrong key, an {@code expectedSigner} mismatch (a b64u PQ key string or {pq, ed?}), or a co-signature older than {@code maxAgeMs}.
     * {@code opts}: expectedSigner?, maxAgeMs?, now?. Never throws. Result {ok, reason?, suite?, verdict?, signer_pub?, cosignedAt?, ageMs?}.
     */
    public static Map<String, Object> verifyCoSignedAttestation(Object cosigned, Map<String, Object> opts) { return verifyCoSignedAttestation(cosigned, opts, System::currentTimeMillis); }

    /** As above with the clock used when {@code opts.now} is not a finite number (epoch ms). */
    public static Map<String, Object> verifyCoSignedAttestation(Object cosigned, Map<String, Object> opts, java.util.function.LongSupplier clock) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<String, Object>() : opts;
        try {
            Map<String, Object> c = AttestEat.rec(cosigned);
            if (c == null) return fail(new LinkedHashMap<>(), "co-signed attestation is not an object");
            Map<String, Object> verdict = AttestEat.rec(c.get("verdict"));
            if (verdict == null || !(verdict.get("tier") instanceof String) || !(verdict.get("trustworthy") instanceof Boolean)) {
                return fail(new LinkedHashMap<>(), "verdict is missing or has a non-string tier / non-boolean trustworthy");
            }
            Map<String, Object> cosig = AttestEat.rec(c.get("cosig"));
            Double cat = cosig == null ? null : Jose.num(cosig.get("cosignedAt"));
            if (cosig == null || cat == null || cat.isNaN() || cat.isInfinite() || !(cosig.get("sig") instanceof String)) {
                return fail(new LinkedHashMap<>(), "cosig is missing or has a non-numeric cosignedAt / non-string sig");
            }
            if (!isPqCoSignSuite(c.get("suite"))) {
                return fail(new LinkedHashMap<>(), "suite '" + (c.containsKey("suite") ? jsString(c.get("suite")) : "undefined") + "' is not an accepted post-quantum co-sign suite");
            }
            String suite = (String) c.get("suite");
            Map<String, Object> signerPub = parseSignerPub(c.get("signer_pub"));
            if (signerPub == null) return fail(new LinkedHashMap<>(), "signer_pub is missing or has no post-quantum public key");

            Double nowD = Jose.num(o.get("now"));
            double now = nowD != null && !nowD.isNaN() && !nowD.isInfinite() ? nowD : (double) clock.getAsLong();
            double ageMs = now - cat;
            Map<String, Object> partial = new LinkedHashMap<>();
            partial.put("ok", false);
            partial.put("suite", suite);
            partial.put("verdict", c.get("verdict"));
            partial.put("signer_pub", signerPub);
            partial.put("cosignedAt", cosig.get("cosignedAt"));
            partial.put("ageMs", numOut(ageMs));

            if (o.containsKey("expectedSigner") && !signerMatches(o.get("expectedSigner"), signerPub)) return fail(partial, "co-signer public key does not match the expected signer");
            if (o.containsKey("maxAgeMs")) {
                Double max = Jose.num(o.get("maxAgeMs"));
                if (max == null || max.isNaN() || max.isInfinite() || max <= 0) return fail(partial, "invalid maxAgeMs");
                if (!(cat <= now)) return fail(partial, "co-sign timestamp is in the future");
                if (!(ageMs <= max)) return fail(partial, "co-signature is stale (older than maxAgeMs)");
            }
            byte[] msg = canonicalVerdictBytes(verdict, cosig.get("cosignedAt"));
            boolean hybrid = suite.startsWith("hybrid-");
            boolean good = Pq.verifyArtifactSignature(suite, hybrid ? (String) signerPub.get("ed") : null, signerPub.get("pq"), msg, cosig.get("sig"), cosig.get("pq_sig"));
            if (!good) return fail(partial, "post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)");
            Map<String, Object> ok = new LinkedHashMap<>(partial);
            ok.put("ok", true);
            return ok;
        } catch (RuntimeException e) {
            return fail(new LinkedHashMap<>(), "co-signature verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }

    public static Map<String, Object> verifyCoSignedAttestation(Object cosigned) { return verifyCoSignedAttestation(cosigned, null); }
}
