package net.atlasauth.pca.sandbox;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;
import net.atlasauth.pca.revoke.JsVal;

/**
 * A signed statement that a sandbox instance runs at a class, bound to the signed passport (by digest) of the agent it contains.
 * The signer is an attestor the verifier pins (a platform or attestation key); an operator saying so is not enough. Anything that
 * does not verify is treated as {@code none}.
 */
public final class RuntimeClaims {
    private RuntimeClaims() {}

    /** Signed bytes: {@code domain || canonical(claim without sig)}, the construction of the other signed records. */
    public static final String RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\u0000";

    private static final Set<String> KEYS = new HashSet<>(Arrays.asList("v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"));

    private static byte[] body(Object claimWithoutSig) {
        byte[] d = RUNTIME_CLAIM_DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] b = W3Bridge.canonBytes(claimWithoutSig);
        byte[] out = new byte[d.length + b.length];
        System.arraycopy(d, 0, out, 0, d.length);
        System.arraycopy(b, 0, out, d.length, b.length);
        return out;
    }

    /**
     * Sign a claim ({@code class, passport_digest, evidence_digest, iat, exp}) with the attestor's Ed25519 key (a 32-byte seed).
     * Returns the claim with {@code v}, {@code attestor} and {@code sig}.
     */
    public static Map<String, Object> signRuntimeClaim(byte[] secretKey, byte[] publicKey, Map<String, Object> c) {
        Map<String, Object> unsigned = new LinkedHashMap<>();
        unsigned.put("v", 1L);
        unsigned.putAll(c);
        unsigned.put("attestor", Keys.b64u(publicKey));
        byte[] sig = Keys.edFromSeed(secretKey).sign(body(unsigned));
        Map<String, Object> out = new LinkedHashMap<>(unsigned);
        out.put("sig", Keys.b64u(sig));
        return out;
    }

    private static boolean isInteger(Object o) {
        Double d = JsVal.num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d);
    }

    /** A safe integer >= 0, never -0: a negative time is never valid. */
    private static boolean nat(Object o) {
        return isInteger(o) && !negZero(o) && JsVal.num(o) >= 0 && JsVal.num(o) <= 9007199254740991.0;
    }

    /** A non-empty string of at most 128 UTF-16 code units. */
    private static boolean str(Object o) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= 128; }

    private static boolean negZero(Object o) {
        Double d = JsVal.num(o);
        return d != null && d == 0.0 && 1.0 / d < 0;
    }

    private static boolean includes(Object list, Object x) { return list instanceof List && ((List<?>) list).contains(x); }

    /**
     * The class the claim proves, or {@code "none"} for anything missing, unsigned, unpinned, expired, for another passport or
     * malformed. {@code trust} carries {@code pinnedAttestors}, {@code passportDigest}, {@code verifiedEvidenceDigests} and {@code now}.
     */
    @SuppressWarnings("unchecked")
    public static String verifiedRuntimeClass(Object claim, Object trust) {
        try {
            if (!(claim instanceof Map) || !(trust instanceof Map)) return "none";
            Map<String, Object> c = (Map<String, Object>) claim;
            Map<String, Object> t = (Map<String, Object>) trust;
            if (!c.keySet().equals(KEYS)) return "none";
            Double v = JsVal.num(c.get("v"));
            if (v == null || v != 1.0 || !(c.get("class") instanceof String) || !Receipts.RUNTIME_CLASSES.contains(c.get("class"))) return "none";
            if (!(c.get("sig") instanceof String) || !str(c.get("attestor")) || !str(c.get("passport_digest")) || !str(c.get("evidence_digest"))
                || !includes(t.get("pinnedAttestors"), c.get("attestor"))) return "none";
            Object now = t.get("now");
            if (c.get("passport_digest") == null || !c.get("passport_digest").equals(t.get("passportDigest"))
                || !nat(c.get("iat")) || !nat(c.get("exp")) || !nat(now)
                || JsVal.num(now) < JsVal.num(c.get("iat")) || JsVal.num(now) >= JsVal.num(c.get("exp"))) return "none";
            if (!(c.get("evidence_digest") instanceof String) || !includes(t.get("verifiedEvidenceDigests"), c.get("evidence_digest")) || !(c.get("passport_digest") instanceof String)) return "none";
            Map<String, Object> rest = new LinkedHashMap<>(c);
            rest.remove("sig");
            return W3Bridge.verifyB64u((String) c.get("attestor"), body(rest), (String) c.get("sig")) ? (String) c.get("class") : "none";
        } catch (RuntimeException e) {
            return "none";
        }
    }

    /** hashCanonical of the signed passport a claim is about. */
    public static String passportDigest(Object signedPassport) { return Pca.hashCanonical(signedPassport); }

    /** The digest a claim's {@code evidence_digest} must equal for this attestation document. */
    public static String evidenceDigest(Object document) { return Pca.hashCanonical(document); }

    /**
     * Run an attestation verifier over the evidence; only if it answers {@code {ok: true, bound: true}} is the evidence's digest admitted
     * into the trust. Anything else (a throw, a malformed answer, not bound) leaves the list empty, so every claim is {@code none}.
     */
    public static Map<String, Object> trustFromAttestation(Object document, Callable<Object> verify, long nowMs, List<String> pinnedAttestors, String passportDigest) {
        boolean ok = false;
        try {
            Object h = verify.call();
            ok = h instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) h).get("ok")) && Boolean.TRUE.equals(((Map<?, ?>) h).get("bound"));
        } catch (Exception e) {
            ok = false;
        }
        List<Object> digests = new ArrayList<>();
        if (ok) digests.add(evidenceDigest(document));
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("pinnedAttestors", new ArrayList<Object>(pinnedAttestors));
        t.put("passportDigest", passportDigest);
        t.put("verifiedEvidenceDigests", digests);
        t.put("now", nowMs);
        return t;
    }

}
