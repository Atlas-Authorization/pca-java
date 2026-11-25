package net.atlasauth.pca.oprf;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The PCA layer over the RFC 9497 OPRF core: private revocation checks (the service learns nothing about which capability id is
 * queried) and private rate-limiting (a POPRF token keyed by a public window, the identifier stays hidden).
 */
public final class OprfPca {
    private OprfPca() {}

    /** UTF-8 encode STRICTLY: an unpaired surrogate is refused instead of silently collapsing to U+FFFD (two ids must never share a counter). */
    static byte[] encodeStrict(String s, String what) {
        if (s == null) throw new IllegalArgumentException(what + " must be a string");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
                else throw new IllegalArgumentException(what + " contains an unpaired surrogate (ill-formed UTF-16)");
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException(what + " contains an unpaired surrogate (ill-formed UTF-16)");
            }
        }
        return Json.utf8(s);
    }

    private static void revocationMode(String mode) {
        if (!"oprf".equals(mode) && !"voprf".equals(mode)) throw new IllegalArgumentException("revocation mode must be oprf or voprf");
    }

    /** The published revocation set: lowercase-hex OPRF outputs, the mode, and (voprf) the service public key. */
    public static final class RevocationSet {
        public final Set<String> outputs;
        public final String mode;
        public final byte[] publicKey;
        public RevocationSet(Set<String> outputs, String mode, byte[] publicKey) { this.outputs = Collections.unmodifiableSet(outputs); this.mode = mode; this.publicKey = publicKey; }
    }

    /** The only thing that crosses client to service: a blinded element in, an evaluation (plus proof for voprf) out. */
    @FunctionalInterface public interface BlindEvaluator { Oprf.EvaluateResult evaluate(byte[] blindedElement); }

    public static RevocationSet buildRevocationSet(byte[] secretKey, Collection<String> revokedCapIds, String mode) {
        revocationMode(mode);
        Set<String> outputs = new LinkedHashSet<>();
        for (String id : revokedCapIds) outputs.add(Oprf.toHex(Oprf.evaluate(secretKey, encodeStrict(id, "capability id"), mode)));
        return new RevocationSet(outputs, mode, "voprf".equals(mode) ? Oprf.publicKeyFor(secretKey) : null);
    }

    public static BlindEvaluator makeRevocationEvaluator(byte[] secretKey, String mode) {
        revocationMode(mode);
        byte[] publicKey = "voprf".equals(mode) ? Oprf.publicKeyFor(secretKey) : null;
        return blinded -> Oprf.blindEvaluate(secretKey, blinded, mode, publicKey, null);
    }

    /** Is {@code capId} in the published set, learned obliviously? A voprf set verifies the service's DLEQ proof (a lying service is refused). */
    public static boolean isRevokedPrivate(String capId, BlindEvaluator blindEval, RevocationSet revokedSet) {
        byte[] input = encodeStrict(capId, "capability id");
        String mode = revokedSet.mode;
        Oprf.BlindResult b = Oprf.blind(input, mode);
        Oprf.EvaluateResult res = blindEval.evaluate(b.blindedElement);
        byte[] output;
        if ("voprf".equals(mode)) {
            if (res.proof == null || revokedSet.publicKey == null) throw new IllegalStateException("isRevokedPrivate(voprf): missing DLEQ proof or service public key");
            output = Oprf.finalizeOprf(input, b.blind, res.evaluatedElement, "voprf", res.proof, revokedSet.publicKey, b.blindedElement);
        } else {
            output = Oprf.finalizeOprf(input, b.blind, res.evaluatedElement, "oprf", null, null, null);
        }
        return revokedSet.outputs.contains(Oprf.toHex(output));
    }

    /** A POPRF blind-evaluation oracle: the window is the public info tag. */
    @FunctionalInterface public interface RateBlindEvaluator { Oprf.EvaluateResult evaluate(byte[] blindedElement, String window); }

    public static byte[] rateToken(byte[] secretKey, String identifier, String window) {
        return Oprf.evaluatePoprf(secretKey, encodeStrict(identifier, "identifier"), encodeStrict(window, "window"));
    }

    public static String rateTokenHex(byte[] secretKey, String identifier, String window) { return Oprf.toHex(rateToken(secretKey, identifier, window)); }

    public static RateBlindEvaluator makeRateEvaluator(byte[] secretKey) {
        return (blinded, window) -> Oprf.blindEvaluatePoprf(secretKey, blinded, encodeStrict(window, "window"), null);
    }

    /** The rate token for (identifier, window) without revealing the identifier; equals {@link #rateToken} for the same key. */
    public static byte[] privateRateToken(String identifier, String window, RateBlindEvaluator blindEval, byte[] publicKey) {
        byte[] input = encodeStrict(identifier, "identifier");
        byte[] info = encodeStrict(window, "window");
        Oprf.PoprfBlindResult b = Oprf.blindPoprf(input, info, publicKey, null);
        Oprf.EvaluateResult res = blindEval.evaluate(b.blindedElement, window);
        if (res.proof == null) throw new IllegalStateException("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof");
        return Oprf.finalizePoprf(input, b.blind, res.evaluatedElement, info, res.proof, b.blindedElement, b.tweakedKey);
    }

    /** A tiny in-memory counter over rate tokens (the identifier is never stored). */
    public static final class RateWindowCounter {
        private final Map<String, Integer> counts = new HashMap<>();
        private final int limit;

        public RateWindowCounter(int limit) {
            if (limit < 1) throw new IllegalArgumentException("RateWindowCounter: limit must be a positive integer");
            this.limit = limit;
        }

        /** Record one use of {@code token}: returns {count, allowed ? 1 : 0}. */
        public synchronized int[] hit(byte[] token) {
            String key = Oprf.toHex(token);
            int count = counts.getOrDefault(key, 0) + 1;
            counts.put(key, count);
            return new int[] {count, count <= limit ? 1 : 0};
        }

        public synchronized int count(byte[] token) { return counts.getOrDefault(Oprf.toHex(token), 0); }

        public synchronized void reset() { counts.clear(); }
    }
}
