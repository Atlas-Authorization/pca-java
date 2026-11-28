package net.atlasauth.pca.fhe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to
 * one action, the gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the
 * policy and a replay guard BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate
 * output it opened. A claim and an attestation are parsed JSON objects (maps); the BFV evaluation that sits between them is not
 * part of this class (see {@link Fhe}).
 */
public final class Origin {
    private Origin() {}

    private static final String CLAIM_DOMAIN = "atlas-pca-fhe/signed-claim/v1\0";
    private static final String VERDICT_DOMAIN = "atlas-pca-fhe/verdict-attestation/v1\0";
    private static final int NONCE_BYTES = 16;
    private static final int MAX_CONTEXT_LEN = 512;

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String bytesDigest(String s) { return Keys.b64u(sha256(utf8(s))); }

    private static byte[] prefixed(String domain, Object body) {
        byte[] p = utf8(domain);
        byte[] b = utf8(Json.canonicalizeStrict(body));
        byte[] m = new byte[p.length + b.length];
        System.arraycopy(p, 0, m, 0, p.length);
        System.arraycopy(b, 0, m, p.length, b.length);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    private static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }

    /** The exact bytes the encryptor signs. */
    private static byte[] claimStatement(Map<String, Object> claim, String context, String nonce, String signer) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", Long.valueOf(1));
        body.put("context", context);
        body.put("nonce", nonce);
        body.put("signer", signer);
        body.put("binding", claim.get("binding"));
        body.put("policy", Pca.hashCanonical(claim.get("policy")));
        body.put("enc_inputs", bytesDigest((String) claim.get("encInputs")));
        return prefixed(CLAIM_DOMAIN, body);
    }

    /** The content digest of a signed claim (what the key holder's attestation commits to). */
    public static String signedClaimDigest(Object signed) { return Pca.hashCanonical(signed); }

    private static byte[] signerPublicKey(byte[] secretKey) {
        if (secretKey == null || secretKey.length != 32) throw new IllegalArgumentException("signing key must be a 32-byte Ed25519 secret key");
        return Keys.edFromSeed(secretKey).pub;
    }

    /** Signs an encrypted risk claim with a fresh random one-time nonce. */
    public static Map<String, Object> signRiskClaim(Map<String, Object> claim, byte[] signerSecretKey, String context) {
        byte[] nonce = new byte[NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        return signRiskClaim(claim, signerSecretKey, context, nonce);
    }

    /** Signs with a caller-supplied nonce (tests and replay of recorded vectors); an all-zero nonce is refused as an RNG failure. */
    public static Map<String, Object> signRiskClaim(Map<String, Object> claim, byte[] signerSecretKey, String context, byte[] nonce) {
        if (context == null || context.isEmpty() || context.length() > MAX_CONTEXT_LEN) {
            throw new IllegalArgumentException("context must be a non-empty string of at most " + MAX_CONTEXT_LEN + " characters");
        }
        boolean allZero = true;
        for (byte b : nonce) if (b != 0) allZero = false;
        if (allZero) throw new IllegalStateException("signRiskClaim: random source returned all zeros (RNG failure)");
        String signer = Keys.b64u(signerPublicKey(signerSecretKey));
        String n = Keys.b64u(nonce);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("claim", claim);
        out.put("context", context);
        out.put("nonce", n);
        out.put("signer", signer);
        out.put("sig", Keys.b64u(Keys.edFromSeed(signerSecretKey).sign(claimStatement(claim, context, n, signer))));
        return out;
    }

    /** A bounded set of nonces already seen; claim(key) is false when the key was seen or the window is full. */
    public interface NonceGuard { boolean claim(String key); }

    public static NonceGuard memoryNonceGuard(int maxEntries) {
        Set<String> seen = new HashSet<>();
        return key -> {
            if (seen.contains(key) || seen.size() >= maxEntries) return false;
            seen.add(key);
            return true;
        };
    }

    public static NonceGuard memoryNonceGuard() { return memoryNonceGuard(100_000); }

    /** What the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate policy and the replay guard. */
    public static final class ClaimExpectations {
        public List<String> trustedSigners;
        public String context;
        public Object binding;
        public Object policy;
        public NonceGuard nonces;
    }

    /** ok with the claim and its digest, or not ok with a reason. */
    public record ClaimCheck(boolean ok, Map<String, Object> claim, String digest, String reason) {}

    private static ClaimCheck fail(String reason) { return new ClaimCheck(false, null, null, reason); }

    /** Verifies a signed claim; never throws (a malformed or hostile input is a not-ok result). */
    public static ClaimCheck verifySignedRiskClaim(Object s, ClaimExpectations exp) {
        try {
            if (!(s instanceof Map)) return fail("claim is not signed: malformed envelope");
            Map<String, Object> c = obj(s);
            Object claimO = c.get("claim");
            if (!(c.get("context") instanceof String) || !(c.get("nonce") instanceof String) || !(c.get("signer") instanceof String) || !(c.get("sig") instanceof String)
                || !(claimO instanceof Map) || !(obj(claimO).get("encInputs") instanceof String) || !isObject(obj(claimO).get("binding")) || !isObject(obj(claimO).get("policy"))) {
                return fail("claim is not signed: malformed envelope");
            }
            Map<String, Object> claim = obj(claimO);
            String context = (String) c.get("context"), nonce = (String) c.get("nonce"), signer = (String) c.get("signer"), sig = (String) c.get("sig");
            if (Pca.decodeB64uStrict(nonce, NONCE_BYTES) == null) return fail("malformed nonce");
            byte[] signerBytes = Pca.decodeB64uStrict(signer, 32);
            byte[] sigBytes = Pca.decodeB64uStrict(sig, 64);
            if (signerBytes == null || sigBytes == null) return fail("malformed signer key or signature");
            if (!exp.trustedSigners.contains(signer)) return fail("signer is not a trusted encryptor");
            if (!EdStrict.verify(signerBytes, claimStatement(claim, context, nonce, signer), sigBytes)) {
                return fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)");
            }
            if (!context.equals(exp.context)) return fail("context mismatch: claim was signed for a different grant/policy");
            if (!Pca.hashCanonical(claim.get("binding")).equals(Pca.hashCanonical(exp.binding))) return fail("binding mismatch: claim is bound to a different action");
            if (!Pca.hashCanonical(claim.get("policy")).equals(Pca.hashCanonical(exp.policy))) return fail("policy mismatch: claim was signed for a different gate policy");
            if (!exp.nonces.claim(signer + ":" + nonce)) return fail("replay: nonce already used (or the replay window is full)");
            return new ClaimCheck(true, claim, signedClaimDigest(s), null);
        } catch (RuntimeException e) {
            return fail("claim could not be verified (malformed)");
        }
    }

    private static byte[] verdictStatement(String claimDigest, Object gateDigest, boolean admit, String holder) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", Long.valueOf(1));
        body.put("claim", claimDigest);
        body.put("gate", gateDigest);
        body.put("admit", admit);
        body.put("holder", holder);
        return prefixed(VERDICT_DOMAIN, body);
    }

    /** The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output. */
    public static Map<String, Object> attestVerdict(byte[] holderSecretKey, Map<String, Object> signed, Map<String, Object> gate, boolean admit) {
        Map<String, Object> gateDigest = new LinkedHashMap<>();
        gateDigest.put("encRiskRaw", bytesDigest((String) gate.get("encRiskRaw")));
        gateDigest.put("encSlack", bytesDigest((String) gate.get("encSlack")));
        String claimDigest = signedClaimDigest(signed);
        String holder = Keys.b64u(signerPublicKey(holderSecretKey));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("claimDigest", claimDigest);
        out.put("gateDigest", gateDigest);
        out.put("admit", admit);
        out.put("holder", holder);
        out.put("sig", Keys.b64u(Keys.edFromSeed(holderSecretKey).sign(verdictStatement(claimDigest, gateDigest, admit, holder))));
        return out;
    }

    /** ok with the attested admit bit, or not ok with a reason. */
    public record AttestationCheck(boolean ok, boolean admit, String reason) {}

    private static AttestationCheck afail(String reason) { return new AttestationCheck(false, false, reason); }

    /** Verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output. */
    public static AttestationCheck verifyVerdictAttestation(Object a, List<String> trustedHolders, String claimDigest, Map<String, Object> gate) {
        try {
            if (!(a instanceof Map)) return afail("malformed attestation");
            Map<String, Object> x = obj(a);
            Object gd = x.get("gateDigest");
            if (!(x.get("claimDigest") instanceof String) || !(x.get("holder") instanceof String) || !(x.get("sig") instanceof String) || !(x.get("admit") instanceof Boolean)
                || !(gd instanceof Map) || !(obj(gd).get("encRiskRaw") instanceof String) || !(obj(gd).get("encSlack") instanceof String)) {
                return afail("malformed attestation");
            }
            String holderS = (String) x.get("holder");
            if (!trustedHolders.contains(holderS)) return afail("attestation holder is not trusted");
            byte[] holder = Pca.decodeB64uStrict(holderS, 32);
            byte[] sig = Pca.decodeB64uStrict((String) x.get("sig"), 64);
            if (holder == null || sig == null) return afail("malformed holder key or signature");
            if (!EdStrict.verify(holder, verdictStatement((String) x.get("claimDigest"), gd, (Boolean) x.get("admit"), holderS), sig)) return afail("attestation signature does not verify");
            if (!x.get("claimDigest").equals(claimDigest)) return afail("attestation is for a different claim");
            if (gate != null) {
                if (!obj(gd).get("encRiskRaw").equals(bytesDigest((String) gate.get("encRiskRaw"))) || !obj(gd).get("encSlack").equals(bytesDigest((String) gate.get("encSlack")))) {
                    return afail("attestation is for a different gate output");
                }
            }
            return new AttestationCheck(true, (Boolean) x.get("admit"), null);
        } catch (RuntimeException e) {
            return afail("attestation could not be verified (malformed)");
        }
    }
}
