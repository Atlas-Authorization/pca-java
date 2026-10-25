package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;

/**
 * B4 — post-quantum crypto-agility, mirroring {@code packages/pca/src/pq.ts} (and the Go/Swift/.NET SDKs).
 *
 * <p>An ADDITIVE, backward-compatible algorithm-agility slot for the PCActn leaf signature. An absent {@code alg}
 * (or {@code alg == "ed25519"}) is BYTE-IDENTICAL to the pre-B4 wire — the signed bytes, the {@code sig} field and
 * every verdict are unchanged — so every existing conformance vector and all other SDK verifiers remain valid.
 * B4 only adds OPTIONAL post-quantum suites alongside it:
 * <ul>
 *   <li>{@code ed25519}                    classical 64-byte Ed25519 {@code sig} (unchanged).</li>
 *   <li>{@code ml-dsa-65}                  pure PQ: {@code sig} carries an ML-DSA-65 (FIPS-204) signature, verified
 *                                          under the ML-DSA public key in {@code pq_pk}.</li>
 *   <li>{@code hybrid-ed25519-ml-dsa-65}   BOTH: {@code sig} is the Ed25519 signature (under the leaf holder key,
 *                                          exactly as today) AND {@code pq_sig} is an ML-DSA-65 signature (under
 *                                          {@code pq_pk}), over the SAME canonical message; BOTH must verify.</li>
 * </ul>
 *
 * <p>{@code alg} and {@code pq_pk} are SIGNED (part of the canonical body hashed by {@code thresholdMessage}), so a
 * downgrade of the suite or a swap of the ML-DSA key invalidates every signature. {@code sig} and {@code pq_sig} are
 * the signatures themselves and are EXCLUDED from the signed body (like {@code sig} / {@code threshold}).
 *
 * <p>The ML-DSA primitive is BouncyCastle's {@code MLDSASigner} with {@code MLDSAParameters.ml_dsa_65}
 * (CRYSTALS-Dilithium / FIPS-204, 192-bit category-3 parameter set), pure variant with an EMPTY context —
 * byte-compatible with {@code @noble/post-quantum}'s {@code ml_dsa65} and circl's {@code mldsa65}. ML-DSA-65 sizes:
 * public key 1952 bytes, signature 3309 bytes.
 *
 * <p>Suite capability ({@code packages/pca/conformance/SUITES.md}): every registered suite BouncyCastle provides is
 * implemented, pure mode, EMPTY context: ML-DSA-65 / ML-DSA-87 (FIPS 204, {@code MLDSASigner}), SLH-DSA-SHA2-128f /
 * SLH-DSA-SHA2-256s (FIPS 205, {@code SLHDSASigner}), their {@code hybrid-ed25519-*} forms (the Ed25519 half is checked
 * first) and the SUF-CMA {@code hybrid-nested-ed25519-ml-dsa-65} (the PQ half signs msg || the Ed25519 signature bytes).
 * FN-DSA (BouncyCastle ships round-3 Falcon, not the FIPS 206 encoding) is refused with the distinct reason
 * {@code unsupported_suite: <alg>}; so is LESS unless {@link LessNative} has a runtime and {@code libatlas_less} (its
 * signature is variable-length, see {@link Prim#sigLenOk}).
 */
public final class Pq {
    private Pq() {}

    /** ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes. */
    public static final int ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
    public static final int ML_DSA_65_SIGNATURE_BYTES = 3309;
    /** Ed25519 signature length, in bytes (unchanged classical suite). */
    public static final int ED25519_SIGNATURE_BYTES = 64;

    /** The reason token of a registered suite this verifier does not implement (full reason {@code unsupported_suite: <alg>}). */
    public static final String UNSUPPORTED_SUITE = "unsupported_suite";

    /** The closed TS suite registry ({@code SIG_SUITES} in pq.ts), in registry order. */
    public static final List<String> REGISTERED_SUITES = List.of(
        "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
        "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1");

    /** The post-quantum primitive of a suite, with its (public key, signature) byte lengths. */
    public enum Prim {
        ML_DSA_65(ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES),
        ML_DSA_87(2592, 4627),
        SLH_DSA_SHA2_128F(32, 17088),
        SLH_DSA_SHA2_256S(64, 29792),
        /** LESS (less-252-45) through {@link LessNative}; {@code sigBytes} is the MAXIMUM signature length. */
        LESS_CAT1(LessNative.PUBLIC_KEY_BYTES, LessNative.SIGNATURE_MAX_BYTES);
        public final int pkBytes;
        public final int sigBytes;
        Prim(int pkBytes, int sigBytes) { this.pkBytes = pkBytes; this.sigBytes = sigBytes; }
        /** {@code n} is a signature length of this primitive: its fixed length, or (LESS) any length the parameter set produces. */
        public boolean sigLenOk(int n) { return this == LESS_CAT1 ? LessNative.sigLenOk(n) : n == sigBytes; }
    }

    /** A signature suite: the decoded {@code sig} byte length and which components / fields it requires. */
    public static final class Suite {
        public final String alg;
        public final int sigBytes;
        public final boolean hasEd25519;
        /** The PQ primitive (null for ed25519). */
        public final Prim pq;
        public final boolean needsPqPk;
        public final boolean needsPqSig;
        /** SUF-CMA nested hybrid: the PQ half signs msg || the Ed25519 signature bytes. */
        public final boolean nested;
        Suite(String alg, int sigBytes, boolean hasEd25519, Prim pq, boolean needsPqPk, boolean needsPqSig, boolean nested) {
            this.alg = alg;
            this.sigBytes = sigBytes;
            this.hasEd25519 = hasEd25519;
            this.pq = pq;
            this.needsPqPk = needsPqPk;
            this.needsPqSig = needsPqSig;
            this.nested = nested;
        }
    }

    private static void pure(String alg, Prim p) { SUITES.put(alg, new Suite(alg, p.sigBytes, false, p, true, false, false)); }

    private static void hybrid(String alg, Prim p, boolean nested) {
        SUITES.put(alg, new Suite(alg, ED25519_SIGNATURE_BYTES, true, p, true, true, nested));
    }

    /** The default suite used when {@code alg} is absent — the pre-B4 default. MUST stay "ed25519" forever. */
    public static final String DEFAULT_SIG_ALG = "ed25519";

    /** The suites this verifier implements (a subset of {@link #REGISTERED_SUITES}). */
    static final Map<String, Suite> SUITES = new LinkedHashMap<>();
    static {
        SUITES.put("ed25519", new Suite("ed25519", ED25519_SIGNATURE_BYTES, true, null, false, false, false));
        pure("ml-dsa-65", Prim.ML_DSA_65);
        hybrid("hybrid-ed25519-ml-dsa-65", Prim.ML_DSA_65, false);
        hybrid("hybrid-nested-ed25519-ml-dsa-65", Prim.ML_DSA_65, true);
        pure("slh-dsa-sha2-128f", Prim.SLH_DSA_SHA2_128F);
        hybrid("hybrid-ed25519-slh-dsa-sha2-128f", Prim.SLH_DSA_SHA2_128F, false);
        pure("ml-dsa-87", Prim.ML_DSA_87);
        hybrid("hybrid-ed25519-ml-dsa-87", Prim.ML_DSA_87, false);
        pure("slh-dsa-sha2-256s", Prim.SLH_DSA_SHA2_256S);
        hybrid("hybrid-ed25519-slh-dsa-sha2-256s", Prim.SLH_DSA_SHA2_256S, false);
        if (LessNative.available()) {
            pure("less-cat1", Prim.LESS_CAT1);
            hybrid("hybrid-ed25519-less-cat1", Prim.LESS_CAT1, false);
        }
    }

    /** The capability manifest: the registered suites this verifier implements, in registry order. */
    public static List<String> supportedSuites() {
        List<String> out = new ArrayList<>();
        for (String a : REGISTERED_SUITES) if (SUITES.containsKey(a)) out.add(a);
        return Collections.unmodifiableList(out);
    }

    /** The refusal of an {@code alg} this verifier does not resolve: {@code unsupported_suite: <alg>} for a registered
     *  suite, else {@code unknown signature alg '<alg>'}. */
    static String refusal(Object alg) {
        return alg instanceof String && REGISTERED_SUITES.contains(alg)
            ? UNSUPPORTED_SUITE + ": " + alg : "unknown signature alg '" + String.valueOf(alg) + "'";
    }

    /**
     * Resolve the suite for a PCActn {@code alg} value. {@code algPresent} is false when the field is absent
     * (=> default {@code ed25519}). Returns the default or a known suite, else null (FAIL-CLOSED: caller rejects).
     */
    static Suite resolveSigAlg(Object alg, boolean algPresent) {
        if (!algPresent) return SUITES.get(DEFAULT_SIG_ALG);
        if (!(alg instanceof String)) return null;
        return SUITES.get(alg);
    }

    // ---- ML-DSA-65 verification -------------------------------------------------------------

    /** PQ verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    public static boolean pqVerify(Prim p, byte[] pk, byte[] msg, byte[] sig) {
        if (p == null || pk == null || sig == null || msg == null || pk.length != p.pkBytes || !p.sigLenOk(sig.length))
            return false;
        if (p == Prim.LESS_CAT1) return LessNative.verify(pk, msg, sig);
        try {
            switch (p) {
                case ML_DSA_65:
                case ML_DSA_87: {
                    MLDSAParameters ps = p == Prim.ML_DSA_65 ? MLDSAParameters.ml_dsa_65 : MLDSAParameters.ml_dsa_87;
                    MLDSASigner v = new MLDSASigner(); // pure ML-DSA, empty context (matches @noble / circl)
                    v.init(false, new MLDSAPublicKeyParameters(ps, pk));
                    v.update(msg, 0, msg.length);
                    return v.verifySignature(sig);
                }
                default: {
                    SLHDSAParameters ps = p == Prim.SLH_DSA_SHA2_128F ? SLHDSAParameters.sha2_128f : SLHDSAParameters.sha2_256s;
                    SLHDSASigner v = new SLHDSASigner(); // pure SLH-DSA, empty context
                    v.init(false, new SLHDSAPublicKeyParameters(ps, pk));
                    return v.verifySignature(msg, sig);
                }
            }
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** ML-DSA-65 verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    public static boolean mlDsa65Verify(byte[] pk, byte[] msg, byte[] sig) {
        return pqVerify(Prim.ML_DSA_65, pk, msg, sig);
    }

    /** {@link #mlDsa65Verify} over base64url-encoded key and signature; false on any decoding error. */
    static boolean mlDsa65VerifyB64u(Object pkB64u, byte[] msg, Object sigB64u) {
        return pqVerifyB64u(Prim.ML_DSA_65, pkB64u, msg, sigB64u);
    }

    /** {@link #pqVerify} over base64url-encoded key and signature; false on any decoding error. */
    static boolean pqVerifyB64u(Prim p, Object pkB64u, byte[] msg, Object sigB64u) {
        byte[] pk = Pca.decodeB64uStrict(pkB64u, p.pkBytes);
        byte[] sg = Pca.decodeB64uStrict(sigB64u, -1);
        if (pk == null || sg == null || !p.sigLenOk(sg.length)) return false;
        return pqVerify(p, pk, msg, sg);
    }

    /** Canonical base64url whose decoded length is a signature length of {@code p}. */
    static boolean pqSigOk(Prim p, Object v) {
        byte[] b = Pca.decodeB64uStrict(v, -1);
        return b != null && p.sigLenOk(b.length);
    }

    /** The primary {@code sig}: the PQ signature for a pure suite (its length rule), else the 64-byte Ed25519 one. */
    static boolean sigFieldOk(Suite suite, Object v) {
        return suite.pq != null && !suite.needsPqSig ? pqSigOk(suite.pq, v) : Pca.decodeB64uStrict(v, suite.sigBytes) != null;
    }

    // ---- wire-shape validation of the signature fields --------------------------------------

    /**
     * Validate the signature-carrying fields ({@code alg}, {@code sig}, {@code pq_pk}, {@code pq_sig}) per suite.
     * Returns null when well-formed, else a short reason. Strict + fail-closed:
     * unknown alg, wrong sizes, or a field not used by the suite being present, all fail.
     */
    static String validateSignatureWire(Map<String, Object> p) {
        boolean algPresent = p.containsKey("alg");
        Object algV = p.get("alg");
        if (algPresent && !(algV instanceof String)) return "'alg' must be a string";
        Suite suite = resolveSigAlg(algV, algPresent);
        if (suite == null) return refusal(algV);

        if (!sigFieldOk(suite, p.get("sig")))
            return "'sig' is not canonical base64url (" + suite.sigBytes + " bytes) for alg '" + suite.alg + "'";

        if (suite.needsPqPk) {
            if (Pca.decodeB64uStrict(p.get("pq_pk"), suite.pq.pkBytes) == null)
                return "'pq_pk' is not canonical base64url (" + suite.pq.pkBytes + " bytes)";
        } else if (p.containsKey("pq_pk")) {
            return "'pq_pk' must be absent for alg '" + suite.alg + "'";
        }
        if (suite.needsPqSig) {
            if (!pqSigOk(suite.pq, p.get("pq_sig")))
                return "'pq_sig' is not canonical base64url (" + suite.pq.sigBytes + " bytes)";
        } else if (p.containsKey("pq_sig")) {
            return "'pq_sig' must be absent for alg '" + suite.alg + "'";
        }
        return null;
    }

    /**
     * 0.4.1: wire-shape validation of ONE threshold share's signature fields, per suite (it used to be a fixed 64-byte
     * {@code sig}, so a pure post-quantum share could never be carried). Mirrors {@code validateShareSignatureWire} in
     * packages/pca/src/pq.ts: {@code alg} absent == ed25519; present and not a string (JSON null included) or unknown
     * fails; {@code sig} must be canonical base64url of the suite's signature length; {@code pq_sig} is required (3309
     * bytes) for the hybrid and must be absent otherwise. A share's {@code pq_pk} is NOT judged here: it is an optional
     * echo that {@link Threshold} checks against the signer set. Returns null when well-formed, else a short reason.
     */
    static String validateShareSignatureWire(Map<String, Object> s) {
        boolean algPresent = s.containsKey("alg");
        Object algV = s.get("alg");
        if (algPresent && !(algV instanceof String)) return "'alg' must be a string";
        Suite suite = resolveSigAlg(algV, algPresent);
        if (suite == null) return refusal(algV);
        if (!sigFieldOk(suite, s.get("sig")))
            return "'sig' is not canonical base64url (" + suite.sigBytes + " bytes) for alg '" + suite.alg + "'";
        if (suite.needsPqSig) {
            if (!pqSigOk(suite.pq, s.get("pq_sig")))
                return "'pq_sig' is not canonical base64url (" + suite.pq.sigBytes + " bytes) for alg '" + suite.alg + "'";
        } else if (s.containsKey("pq_sig")) {
            return "'pq_sig' must be absent for alg '" + suite.alg + "'";
        }
        return null;
    }

    // ---- the leaf signature SEAM ------------------------------------------------------------

    /**
     * Verify the leaf signature under the PCActn's suite. The single agility seam; everything above it (the full
     * verifier) is unchanged. FAIL-CLOSED: an unknown {@code alg}, a missing component, or any invalid component
     * returns false. Never throws.
     * <ul>
     *   <li>ed25519:   Ed25519 {@code sig} under {@code holder} — byte-identical to the pre-B4 path.</li>
     *   <li>ml-dsa-65: ML-DSA-65 {@code sig} under {@code pq_pk}.</li>
     *   <li>hybrid:    Ed25519 {@code sig} under {@code holder} AND ML-DSA-65 {@code pq_sig} under {@code pq_pk},
     *                  both over {@code message}; BOTH must verify.</li>
     * </ul>
     */
    /**
     * Verify a NON-LEAF transparency/authority artifact signature (STH, revocation, beacon, bond-settlement,
     * safety-certificate, judge-verdict, software-attestation) over {@code msg} under suite {@code alg} — the
     * SAME agility seam as the leaf. {@code edPub} is the Ed25519 key, {@code pqPk} the ML-DSA key. Fail-closed.
     */
    public static boolean verifyArtifactSignature(String alg, String edPub, Object pqPk, byte[] msg, Object sig, Object pqSig) {
        return verifyLeafSuiteCallerVouched(alg, true, edPub, pqPk, msg, sig, pqSig);
    }

    /**
     * An opaque PQ verification key (R3-01 choke point). Its constructor is private to {@link Pq} and the only caller is
     * {@link #resolvePqKey}, so {@link #verifyLeafSuite} cannot be reached with a {@code pq_pk} read straight off the
     * artifact being verified.
     */
    static final class PinnedPq {
        private final String key;
        private PinnedPq(String key) { this.key = key; }
    }

    /**
     * THE choke point (R3-01), mirroring {@code resolvePqVerifyKey} in packages/pca/src/pq.ts. Returns the key to verify
     * under, or null (REFUSE) when no verifier-side authority vouches for the artifact's {@code pq_pk}:
     * <ol>
     *   <li>{@code trustedPk}: a key the verifier itself holds (the stored grant). Used as is.</li>
     *   <li>{@code pqPins[identity]} (own entry only): the artifact's pq_pk MUST equal the pin; a differing pin refuses.</li>
     *   <li>{@code holderPq}: the artifact's pq_pk must hash to the signer's committed holder_pq (F-2).</li>
     * </ol>
     * Natives have no allowUnboundPq: an artifact's own key is never enough.
     */
    static PinnedPq resolvePqKey(String identity, Object artifactPk, Object holderPq, Map<String, Object> pqPins, String trustedPk) {
        if (trustedPk != null && !trustedPk.isEmpty()) return new PinnedPq(trustedPk);
        if (!(artifactPk instanceof String) || ((String) artifactPk).isEmpty()) return null;
        String pk = (String) artifactPk;
        if (pqPins != null && identity != null && pqPins.containsKey(identity))
            return pk.equals(pqPins.get(identity)) ? new PinnedPq(pk) : null;
        if (holderPq instanceof String && Pca.holderPqCommitment(pk).equals(holderPq)) return new PinnedPq(pk);
        return null;
    }

    /**
     * CALLER-VOUCHED wrapper: verifies under the artifact's OWN {@code pq_pk}. ONLY for surfaces whose key is authorised
     * elsewhere (threshold shares, the pq_artifact conformance primitives); it proves nothing about who issued the
     * artifact. The chain and the PCActn leaf never call it; they resolve through {@link #resolvePqKey}.
     */
    static boolean verifyLeafSuiteCallerVouched(Object alg, boolean algPresent, String holder, Object pqPk, byte[] msg,
                                                Object sig, Object pqSig) {
        return verifyLeafSuite(alg, algPresent, holder,
            pqPk instanceof String ? resolvePqKey(null, pqPk, null, null, (String) pqPk) : null, msg, sig, pqSig);
    }

    /** Verify under suite {@code alg}. The PQ half verifies ONLY under {@code pq} (never an artifact-supplied key). */
    static boolean verifyLeafSuite(Object alg, boolean algPresent, String holder, PinnedPq pq, byte[] msg,
                                   Object sig, Object pqSig) {
        Suite suite = resolveSigAlg(alg, algPresent);
        if (suite == null) return false;
        if (!(sig instanceof String)) return false;
        String sigStr = (String) sig;
        if (suite.pq == null) return Pca.verifyB64u(holder, msg, sigStr);
        if (pq == null) return false;
        if (!suite.needsPqSig) return pqVerifyB64u(suite.pq, pq.key, msg, sigStr); // pure PQ: `sig` is the PQ signature
        // hybrid: the cheap Ed25519 half first (R6-API-04), then the PQ `pq_sig` (nested: over msg || Ed25519 sig bytes)
        if (!(pqSig instanceof String) || !Pca.verifyB64u(holder, msg, sigStr)) return false;
        byte[] pqMsg = msg;
        if (suite.nested) {
            byte[] edSig = Pca.decodeB64uStrict(sigStr, ED25519_SIGNATURE_BYTES);
            if (edSig == null) return false;
            pqMsg = new byte[msg.length + edSig.length];
            System.arraycopy(msg, 0, pqMsg, 0, msg.length);
            System.arraycopy(edSig, 0, pqMsg, msg.length, edSig.length);
        }
        return pqVerifyB64u(suite.pq, pq.key, pqMsg, pqSig);
    }
}
