package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import net.atlasauth.pca.fndsa.FnDsa;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
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
 * FN-DSA (BouncyCastle ships round-3 Falcon, not the FIPS 206 encoding) verifies through the {@link FnDsa} backend seam, raw and
 * pure; with no backend registered it is refused with the distinct reason {@code unsupported_suite: <alg>} (never accepted); so is LESS unless {@link LessNative} has a runtime and {@code libatlas_less} (its
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
    public static final List<String> REGISTERED_SUITES = NullSafe.list(List.of(
        "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
        "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024"));

    /** The post-quantum primitive of a suite, with its (public key, signature) byte lengths. */
    public enum Prim {
        ML_DSA_65(ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES),
        ML_DSA_87(2592, 4627),
        SLH_DSA_SHA2_128F(32, 17088),
        SLH_DSA_SHA2_256S(64, 29792),
        /** FN-DSA (raw, no domain) through the {@link FnDsa} seam; implemented only while a backend is registered. */
        FN_DSA_512(FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES, FnDsa.FN_DSA_512_SIGNATURE_BYTES),
        FN_DSA_1024(FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES, FnDsa.FN_DSA_1024_SIGNATURE_BYTES),
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

    /** Pure FN-DSA verify suites. Kept out of {@link #SUITES} (the producer table): they resolve only while a backend is registered. */
    private static final Map<String, Suite> FN_DSA_VERIFY = new LinkedHashMap<>();
    static {
        FN_DSA_VERIFY.put("fn-dsa-512", new Suite("fn-dsa-512", Prim.FN_DSA_512.sigBytes, false, Prim.FN_DSA_512, true, false, false));
        FN_DSA_VERIFY.put("fn-dsa-1024", new Suite("fn-dsa-1024", Prim.FN_DSA_1024.sigBytes, false, Prim.FN_DSA_1024, true, false, false));
    }

    /** The suite a PRODUCER may sign under: the closed table, plus fn-dsa-* only while a signing-capable backend is registered. */
    static Suite signerSuite(String alg) {
        Suite s = SUITES.get(alg);
        return s != null ? s : FnDsa.hasBackend() && FnDsa.getFalconBackend().canSign() ? FN_DSA_VERIFY.get(alg) : null;
    }

    private static Suite lookup(String alg) {
        Suite s = SUITES.get(alg);
        return s != null ? s : FnDsa.hasBackend() ? FN_DSA_VERIFY.get(alg) : null;
    }

    /** The shape (components and byte lengths) of a suite this SDK knows, whether or not its optional backend is loaded; null for anything else. */
    static Suite suiteShape(Object alg) {
        if (!(alg instanceof String)) return null;
        Suite s = SUITES.get(alg);
        if (s == null) s = FN_DSA_VERIFY.get(alg);
        if (s != null) return s;
        // the LESS shapes are fixed by the parameter set, so they are known without libatlas_less
        if ("less-cat1".equals(alg)) return new Suite("less-cat1", Prim.LESS_CAT1.sigBytes, false, Prim.LESS_CAT1, true, false, false);
        return "hybrid-ed25519-less-cat1".equals(alg) ? new Suite("hybrid-ed25519-less-cat1", ED25519_SIGNATURE_BYTES, true, Prim.LESS_CAT1, true, true, false) : null;
    }

    /** The capability manifest: the registered suites this verifier implements, in registry order. */
    public static List<String> supportedSuites() {
        List<String> out = new ArrayList<>();
        for (String a : REGISTERED_SUITES) if (lookup(a) != null) out.add(a);
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
        return lookup((String) alg);
    }

    /** True when {@code alg} (absent = the ed25519 default) names a suite this verifier implements. */
    public static boolean sigAlgKnown(Object alg, boolean algPresent) { return resolveSigAlg(alg, algPresent) != null; }

    // ---- ML-DSA-65 verification -------------------------------------------------------------

    /** PQ verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    public static boolean pqVerify(Prim p, byte[] pk, byte[] msg, byte[] sig) {
        if (p == null || pk == null || sig == null || msg == null || pk.length != p.pkBytes || !p.sigLenOk(sig.length))
            return false;
        if (p == Prim.LESS_CAT1) return LessNative.verify(pk, msg, sig);
        if (p == Prim.FN_DSA_512 || p == Prim.FN_DSA_1024) {
            if (!FnDsa.hasBackend()) return false;
            try { return FnDsa.fndsaVerify(p == Prim.FN_DSA_512 ? "fn-dsa-512" : "fn-dsa-1024", pk, msg, sig); }
            catch (RuntimeException e) { return false; } // a throwing backend denies
        }
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
    public static boolean mlDsa65VerifyB64u(Object pkB64u, byte[] msg, Object sigB64u) {
        return pqVerifyB64u(Prim.ML_DSA_65, pkB64u, msg, sigB64u);
    }

    /** {@link #pqVerify} over base64url-encoded key and signature; false on any decoding error. */
    public static boolean pqVerifyB64u(Prim p, Object pkB64u, byte[] msg, Object sigB64u) {
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
    public static final class PinnedPq {
        private final String key;
        /** The b64u PQ public key this pin vouches for. */
        public String b64u() { return key; }
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
    public static PinnedPq resolvePqKey(String identity, Object artifactPk, Object holderPq, Map<String, Object> pqPins, String trustedPk) {
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

    // ---- the public PQ surface of packages/pca/src/pq.ts: sizes, keygen / sign / verify per primitive, suite helpers, composite ----

    public static final int ML_DSA_65_SEED_BYTES = 32;
    public static final int ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
    public static final int ML_DSA_87_SIGNATURE_BYTES = 4627;
    public static final int ML_DSA_87_SEED_BYTES = 32;
    public static final int SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32;
    public static final int SLH_DSA_SHA2_128F_SECRET_KEY_BYTES = 64;
    public static final int SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17088;
    public static final int SLH_DSA_SHA2_128F_SEED_BYTES = 48;
    public static final int SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64;
    public static final int SLH_DSA_SHA2_256S_SECRET_KEY_BYTES = 128;
    public static final int SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29792;
    public static final int SLH_DSA_SHA2_256S_SEED_BYTES = 96;
    public static final int FN_DSA_512_SECRET_KEY_BYTES = 1345;
    public static final int FN_DSA_1024_SECRET_KEY_BYTES = 2369;
    public static final int FN_DSA_SEED_BYTES = 32;
    public static final int LESS_CAT1_PUBLIC_KEY_BYTES = 97484;
    public static final int LESS_CAT1_SECRET_KEY_BYTES = 32;
    public static final int LESS_CAT1_SIGNATURE_MAX_BYTES = 1329;
    public static final int LESS_CAT1_SIGNATURE_MIN_BYTES = 1153;
    public static final int LESS_CAT1_SIGNATURE_STEP_BYTES = 16;
    public static final int LESS_SEED_BYTES = 32;

    /** A key pair in the encodings the wire uses (FIPS 204 / 205 / FN-DSA / LESS). */
    public static final class KeyPair {
        public final byte[] publicKey;
        public final byte[] secretKey;
        public KeyPair(byte[] publicKey, byte[] secretKey) { this.publicKey = publicKey; this.secretKey = secretKey; }
    }

    /** FN-DSA signing material for the suite seam: the key pair plus the 32-byte signing RNG seed (a fixed seed signs reproducibly). */
    public static final class FnDsaSuiteKey {
        public final byte[] verifyingKey, signingKey, signSeed;
        public FnDsaSuiteKey(byte[] verifyingKey, byte[] signingKey, byte[] signSeed) { this.verifyingKey = verifyingKey; this.signingKey = signingKey; this.signSeed = signSeed; }
    }

    /** LESS signing material for the suite seam (like {@link FnDsaSuiteKey}). */
    public static final class LessSuiteKey {
        public final byte[] publicKey, secretKey, signSeed;
        public LessSuiteKey(byte[] publicKey, byte[] secretKey, byte[] signSeed) { this.publicKey = publicKey; this.secretKey = secretKey; this.signSeed = signSeed; }
    }

    /** Secret key material for signing under a suite; a caller fills only the slots its suite needs. */
    public static class SuiteSecretKeys {
        public byte[] edSecret;
        public KeyPair mlDsa, slhDsa, mlDsa87, slhDsa256s;
        public FnDsaSuiteKey fnDsa512, fnDsa1024;
        public LessSuiteKey lessCat1;
    }

    /** The signer-options type of every PQ-capable signing surface: {@code alg} plus the suite key material (no Ed25519 secret; a null alg is ed25519). */
    public static final class SignerSuiteOpts extends SuiteSecretKeys {
        public String alg;
    }

    /** The signature components a suite produces: {@code sig}, and {@code pqSig} for a hybrid (else null). */
    public static final class SuiteSignatureParts {
        public final String sig, pqSig;
        SuiteSignatureParts(String sig, String pqSig) { this.sig = sig; this.pqSig = pqSig; }
    }

    /** Every wire field a signed artifact carries for its suite; {@code alg}, {@code pqPk} and {@code pqSig} are null for the default suite (and pqSig for a pure suite). */
    public static final class SuiteArtifactFields {
        public final String sig, alg, pqPk, pqSig;
        SuiteArtifactFields(String sig, String alg, String pqPk, String pqSig) { this.sig = sig; this.alg = alg; this.pqPk = pqPk; this.pqSig = pqSig; }
    }

    /** Availability of the optional LESS backend; {@code reason} says why a LESS suite is unsupported. */
    public static final class LessBackendStatus {
        public final boolean available;
        public final String reason;
        LessBackendStatus(boolean available, String reason) { this.available = available; this.reason = reason; }
    }

    public static boolean isLessBackendActive() { return LessNative.available(); }

    public static LessBackendStatus lessBackendStatus() {
        return LessNative.available() ? new LessBackendStatus(true, null)
            : new LessBackendStatus(false, "libatlas_less is not loaded (needs a Java 22+ runtime with native access and the library; set ATLAS_PCA_LIBLESS)");
    }

    /** True when {@code x} is a registered suite name (a verifier may still not implement it; see {@link #supportedSuites()}). */
    public static boolean isKnownSigAlg(Object x) { return x instanceof String && REGISTERED_SUITES.contains(x); }

    private static MLDSAParameters mlParams(Prim p) { return p == Prim.ML_DSA_65 ? MLDSAParameters.ml_dsa_65 : MLDSAParameters.ml_dsa_87; }

    private static KeyPair keygenSeeded(Prim p, byte[] seed) {
        Keys.PqKey k = Keys.pqFromSeed(p, seed); // checks the seed length per primitive
        return new KeyPair(k.pk.clone(), k.sk.clone());
    }

    private static byte[] signRaw(Prim p, byte[] sk, byte[] msg) {
        if (sk == null || msg == null) throw new IllegalArgumentException("secret key and message must be byte arrays");
        switch (p) {
            case ML_DSA_65:
            case ML_DSA_87: {
                MLDSASigner s = new MLDSASigner(); // pure ML-DSA, empty context, deterministic
                s.init(true, new MLDSAPrivateKeyParameters(mlParams(p), sk));
                s.update(msg, 0, msg.length);
                return Keys.bc(s::generateSignature);
            }
            case SLH_DSA_SHA2_128F:
            case SLH_DSA_SHA2_256S: {
                SLHDSASigner s = new SLHDSASigner();
                s.init(true, new SLHDSAPrivateKeyParameters(p == Prim.SLH_DSA_SHA2_128F ? SLHDSAParameters.sha2_128f : SLHDSAParameters.sha2_256s, sk));
                return s.generateSignature(msg);
            }
            default:
                throw new IllegalArgumentException("cannot sign with " + p + " here");
        }
    }

    /** Deterministic ML-DSA-65 keygen from a 32-byte seed (FIPS 204). */
    public static KeyPair mlDsa65Keygen(byte[] seed) { return keygenSeeded(Prim.ML_DSA_65, seed); }
    /** ML-DSA-65 sign (deterministic, pure, empty context). */
    public static byte[] mlDsa65Sign(byte[] secretKey, byte[] msg) { return signRaw(Prim.ML_DSA_65, secretKey, msg); }
    public static String encodeMlDsaPublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    public static KeyPair mlDsa87Keygen(byte[] seed) { return keygenSeeded(Prim.ML_DSA_87, seed); }
    public static byte[] mlDsa87Sign(byte[] secretKey, byte[] msg) { return signRaw(Prim.ML_DSA_87, secretKey, msg); }
    public static boolean mlDsa87Verify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.ML_DSA_87, publicKey, msg, sig); }
    public static boolean mlDsa87VerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.ML_DSA_87, publicKeyB64u, msg, sigB64u); }
    public static String encodeMlDsa87PublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    /** SLH-DSA-SHA2-128f keygen from a 48-byte seed (sk_seed, sk_prf, pk_seed). */
    public static KeyPair slhDsa128fKeygen(byte[] seed) { return keygenSeeded(Prim.SLH_DSA_SHA2_128F, seed); }
    public static byte[] slhDsa128fSign(byte[] secretKey, byte[] msg) { return signRaw(Prim.SLH_DSA_SHA2_128F, secretKey, msg); }
    public static boolean slhDsa128fVerify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.SLH_DSA_SHA2_128F, publicKey, msg, sig); }
    public static boolean slhDsa128fVerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.SLH_DSA_SHA2_128F, publicKeyB64u, msg, sigB64u); }
    public static String encodeSlhDsaPublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    /** SLH-DSA-SHA2-256s keygen from a 96-byte seed. */
    public static KeyPair slhDsa256sKeygen(byte[] seed) { return keygenSeeded(Prim.SLH_DSA_SHA2_256S, seed); }
    public static byte[] slhDsa256sSign(byte[] secretKey, byte[] msg) { return signRaw(Prim.SLH_DSA_SHA2_256S, secretKey, msg); }
    public static boolean slhDsa256sVerify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.SLH_DSA_SHA2_256S, publicKey, msg, sig); }
    public static boolean slhDsa256sVerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.SLH_DSA_SHA2_256S, publicKeyB64u, msg, sigB64u); }
    public static String encodeSlhDsa256sPublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    /** FN-DSA-512 keygen from a 32-byte seed; needs a registered FN-DSA backend (else {@code unsupported_suite: fn-dsa-512}). */
    public static KeyPair fnDsa512Keygen(byte[] seed) { return keygenSeeded(Prim.FN_DSA_512, seed); }
    public static KeyPair fnDsa1024Keygen(byte[] seed) { return keygenSeeded(Prim.FN_DSA_1024, seed); }
    /** FN-DSA-512 sign with an explicit 32-byte signing seed; needs a signing-capable backend. */
    public static byte[] fnDsa512Sign(byte[] signingKey, byte[] msg, byte[] seed) { return FnDsa.fndsaSignSeeded("fn-dsa-512", signingKey, msg, seed); }
    public static byte[] fnDsa1024Sign(byte[] signingKey, byte[] msg, byte[] seed) { return FnDsa.fndsaSignSeeded("fn-dsa-1024", signingKey, msg, seed); }
    /** False without a backend, on a wrong length and on any failure. */
    public static boolean fnDsa512Verify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.FN_DSA_512, publicKey, msg, sig); }
    public static boolean fnDsa1024Verify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.FN_DSA_1024, publicKey, msg, sig); }
    public static boolean fnDsa512VerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.FN_DSA_512, publicKeyB64u, msg, sigB64u); }
    public static boolean fnDsa1024VerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.FN_DSA_1024, publicKeyB64u, msg, sigB64u); }
    public static String encodeFnDsaPublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    /** LESS keygen from a 32-byte seed; needs libatlas_less (else IllegalStateException). */
    public static KeyPair lessCat1Keygen(byte[] seed) {
        if (seed == null || seed.length != LESS_SEED_BYTES) throw new IllegalArgumentException("lessCat1Keygen: seed must be " + LESS_SEED_BYTES + " bytes");
        byte[][] kp = LessNative.keygen(seed);
        return new KeyPair(kp[0], kp[1]);
    }

    /** LESS detached signature (1153..1329 bytes) with an explicit 32-byte signing seed. */
    public static byte[] lessCat1Sign(byte[] secretKey, byte[] msg, byte[] seed) {
        if (seed == null || seed.length != LESS_SEED_BYTES) throw new IllegalArgumentException("lessCat1Sign: seed must be " + LESS_SEED_BYTES + " bytes");
        return LessNative.sign(secretKey, msg, seed);
    }

    public static boolean lessCat1Verify(byte[] publicKey, byte[] msg, byte[] sig) { return pqVerify(Prim.LESS_CAT1, publicKey, msg, sig); }
    public static boolean lessCat1VerifyB64u(Object publicKeyB64u, byte[] msg, Object sigB64u) { return pqVerifyB64u(Prim.LESS_CAT1, publicKeyB64u, msg, sigB64u); }
    public static String encodeLessPublicKey(byte[] publicKey) { return Pca.b64(publicKey); }

    // ---- the suite seam ----

    /** The suite of a signer: registered and implemented here (FN-DSA / LESS only with their backend), else the typed refusal. */
    private static Suite signingSuite(String fn, Object alg) {
        if (alg == null) return SUITES.get(DEFAULT_SIG_ALG);
        if (!isKnownSigAlg(alg)) throw new IllegalArgumentException(fn + ": unknown signature alg '" + alg + "'");
        Suite s = SUITES.get(alg);
        if (s == null) s = FN_DSA_VERIFY.get(alg);
        if (s == null) throw new IllegalArgumentException(refusal(alg));
        return s;
    }

    /** {@code {secret, public, signSeed}} of the primitive's slot, or IllegalArgumentException when it is absent. */
    private static byte[][] material(Suite suite, SuiteSecretKeys k) {
        String name;
        byte[][] m = null;
        switch (suite.pq) {
            case ML_DSA_65: name = "mlDsa"; if (k.mlDsa != null) m = new byte[][] {k.mlDsa.secretKey, k.mlDsa.publicKey, null}; break;
            case ML_DSA_87: name = "mlDsa87"; if (k.mlDsa87 != null) m = new byte[][] {k.mlDsa87.secretKey, k.mlDsa87.publicKey, null}; break;
            case SLH_DSA_SHA2_128F: name = "slhDsa"; if (k.slhDsa != null) m = new byte[][] {k.slhDsa.secretKey, k.slhDsa.publicKey, null}; break;
            case SLH_DSA_SHA2_256S: name = "slhDsa256s"; if (k.slhDsa256s != null) m = new byte[][] {k.slhDsa256s.secretKey, k.slhDsa256s.publicKey, null}; break;
            case FN_DSA_512: name = "fnDsa512 (signingKey + signSeed)"; if (k.fnDsa512 != null && k.fnDsa512.signSeed != null) m = new byte[][] {k.fnDsa512.signingKey, k.fnDsa512.verifyingKey, k.fnDsa512.signSeed}; break;
            case FN_DSA_1024: name = "fnDsa1024 (signingKey + signSeed)"; if (k.fnDsa1024 != null && k.fnDsa1024.signSeed != null) m = new byte[][] {k.fnDsa1024.signingKey, k.fnDsa1024.verifyingKey, k.fnDsa1024.signSeed}; break;
            default: name = "lessCat1 (secretKey + signSeed)"; if (k.lessCat1 != null && k.lessCat1.signSeed != null) m = new byte[][] {k.lessCat1.secretKey, k.lessCat1.publicKey, k.lessCat1.signSeed}; break;
        }
        if (m == null || m[0] == null) throw new IllegalArgumentException("signWithSuite: '" + suite.alg + "' requires " + name + " key material");
        return m;
    }

    private static byte[] pqSignWith(Suite suite, byte[][] m, byte[] msg) {
        switch (suite.pq) {
            case FN_DSA_512: return FnDsa.fndsaSignSeeded("fn-dsa-512", m[0], msg, m[2]);
            case FN_DSA_1024: return FnDsa.fndsaSignSeeded("fn-dsa-1024", m[0], msg, m[2]);
            case LESS_CAT1: return LessNative.sign(m[0], msg, m[2]);
            default: return signRaw(suite.pq, m[0], msg);
        }
    }

    /**
     * Sign {@code msg} under {@code alg} (null = ed25519). Fail closed: an unknown alg, a suite this SDK cannot sign, or a
     * missing secret throws IllegalArgumentException (a signer never silently emits a weaker signature). The ed25519 path is
     * byte-identical to a plain Ed25519 signature; the nested hybrid signs {@code msg || ed25519 signature} with the PQ key.
     */
    public static SuiteSignatureParts signWithSuite(Object alg, SuiteSecretKeys keys, byte[] msg) {
        Suite suite = signingSuite("signWithSuite", alg);
        if (keys == null || msg == null) throw new IllegalArgumentException("signWithSuite: keys and message are required");
        if (suite.hasEd25519 && keys.edSecret == null) throw new IllegalArgumentException("signWithSuite: '" + suite.alg + "' requires edSecret");
        byte[][] m = suite.pq == null ? null : material(suite, keys);
        if (suite.pq == null) return new SuiteSignatureParts(Pca.b64(Keys.edFromSeed(keys.edSecret).sign(msg)), null);
        if (!suite.hasEd25519) return new SuiteSignatureParts(Pca.b64(pqSignWith(suite, m, msg)), null);
        byte[] edSig = Keys.edFromSeed(keys.edSecret).sign(msg);
        byte[] pqSig = pqSignWith(suite, m, suite.nested ? Pca.concat(msg, edSig) : msg);
        return new SuiteSignatureParts(Pca.b64(edSig), Pca.b64(pqSig));
    }

    /**
     * Verify a suite signature over {@code msg}. {@code pq} is the opaque pinned key only {@link #resolvePqVerifyKey} mints
     * (null for ed25519). Fail closed; a hybrid checks its Ed25519 half first and needs both. Never throws.
     */
    public static boolean verifyWithSuite(Object alg, String edPub, PinnedPq pq, byte[] msg, Object sig, Object pqSig) {
        return verifyLeafSuite(alg, alg != null, edPub, pq, msg, sig, pqSig);
    }

    /** The choke point of {@link #resolvePqKey}, under the reference's name. */
    public static PinnedPq resolvePqVerifyKey(String identity, Object artifactPk, Object holderPq, Map<String, Object> pqPins, String trustedPk) {
        return resolvePqKey(identity, artifactPk, holderPq, pqPins, trustedPk);
    }

    /** True when {@code x} was minted by {@link #resolvePqVerifyKey}. */
    public static boolean isPinnedPqKey(Object x) { return x instanceof PinnedPq; }

    /** The b64u {@code pq_pk} that {@code alg} selects from {@code keys}, or null for ed25519, an unknown alg or absent key material. */
    public static String suitePqPublicKey(Object alg, SuiteSecretKeys keys) {
        if (keys == null || (alg != null && !isKnownSigAlg(alg))) return null;
        Suite s = alg == null ? SUITES.get(DEFAULT_SIG_ALG) : SUITES.containsKey(alg) ? SUITES.get(alg) : FN_DSA_VERIFY.get(alg);
        if (s == null || !s.needsPqPk) return null;
        try {
            return Pca.b64(material(s, keys)[1]);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Sign {@code msg} and return every wire field the suite carries; the default suite yields only {@code sig}. */
    public static SuiteArtifactFields signSuiteArtifact(Object alg, SuiteSecretKeys keys, byte[] msg) {
        SuiteSignatureParts parts = signWithSuite(alg, keys, msg);
        Suite suite = signingSuite("signSuiteArtifact", alg);
        if (DEFAULT_SIG_ALG.equals(suite.alg)) return new SuiteArtifactFields(parts.sig, null, null, null);
        return new SuiteArtifactFields(parts.sig, suite.alg, suitePqPublicKey(suite.alg, keys), parts.pqSig);
    }

    /** The full signing keys for a surface artifact: the identity's Ed25519 secret plus the PQ material of {@code suite}. */
    public static SuiteSecretKeys suiteKeysOf(byte[] edSecret, SignerSuiteOpts suite) {
        SuiteSecretKeys k = new SuiteSecretKeys();
        if (suite != null) {
            k.mlDsa = suite.mlDsa; k.slhDsa = suite.slhDsa; k.mlDsa87 = suite.mlDsa87; k.slhDsa256s = suite.slhDsa256s;
            k.fnDsa512 = suite.fnDsa512; k.fnDsa1024 = suite.fnDsa1024; k.lessCat1 = suite.lessCat1;
        }
        k.edSecret = edSecret;
        return k;
    }

    /** Decoded lengths of every registered PQ public-key family. */
    private static final int[] PQ_PUBLIC_KEY_LENGTHS = {ML_DSA_65_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES,
        SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES, FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES, LESS_CAT1_PUBLIC_KEY_BYTES};

    /** True when {@code pq} is canonical b64u of a byte string with the public-key length of a registered PQ suite. */
    public static boolean isWellFormedPqPublicKey(Object pq) {
        if (!(pq instanceof String)) return false;
        byte[] b = Pca.decodeB64uStrict(pq, -1);
        if (b == null) return false;
        for (int n : PQ_PUBLIC_KEY_LENGTHS) if (b.length == n) return true;
        return false;
    }

    // ---- composite ML-DSA-65 + Ed25519 (draft-ietf-lamps-pq-composite-sigs), for the X.509 / PKI boundary ----

    public static final String COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025";
    public static final String COMPOSITE_LABEL = "COMPSIG-MLDSA65-Ed25519-SHA512";
    public static final int COMPOSITE_SIGNATURE_BYTES = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;

    /** {@code M' = Prefix || Label || len(ctx) || ctx || SHA-512(message)}; a ctx over 255 bytes is an IllegalArgumentException. */
    public static byte[] compositeRepresentative(byte[] message, byte[] ctx) {
        byte[] c = ctx == null ? new byte[0] : ctx;
        if (c.length > 255) throw new IllegalArgumentException("compositeRepresentative: ctx exceeds 255 bytes");
        byte[] h;
        try {
            h = MessageDigest.getInstance("SHA-512").digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return Pca.concat(COMPOSITE_PREFIX.getBytes(StandardCharsets.UTF_8), COMPOSITE_LABEL.getBytes(StandardCharsets.UTF_8), new byte[] {(byte) c.length}, c, h);
    }

    public static byte[] compositeRepresentative(byte[] message, String ctx) {
        return compositeRepresentative(message, ctx == null ? null : ctx.getBytes(StandardCharsets.UTF_8));
    }

    /** Composite signature {@code mldsaSig || ed25519Sig} (3373 bytes), both over {@code M'}. */
    public static byte[] compositeSign(byte[] ed25519Secret, KeyPair mlDsa, byte[] message, byte[] ctx) {
        if (ed25519Secret == null) throw new IllegalArgumentException("compositeSign: ed25519Secret required");
        if (mlDsa == null || mlDsa.secretKey == null) throw new IllegalArgumentException("compositeSign: mlDsa key material required");
        byte[] mPrime = compositeRepresentative(message, ctx);
        return Pca.concat(mlDsa65Sign(mlDsa.secretKey, mPrime), Keys.edFromSeed(ed25519Secret).sign(mPrime));
    }

    /** Fail closed: a wrong total length, an over-long ctx or either half failing returns false; both halves must verify over {@code M'}. Never throws. */
    public static boolean compositeVerify(byte[] ed25519Pub, byte[] mlDsaPub, byte[] message, byte[] signature, byte[] ctx) {
        try {
            if (ed25519Pub == null || mlDsaPub == null || message == null || signature == null || signature.length != COMPOSITE_SIGNATURE_BYTES) return false;
            byte[] mPrime = compositeRepresentative(message, ctx);
            byte[] mldsaSig = java.util.Arrays.copyOfRange(signature, 0, ML_DSA_65_SIGNATURE_BYTES);
            byte[] tradSig = java.util.Arrays.copyOfRange(signature, ML_DSA_65_SIGNATURE_BYTES, signature.length);
            return mlDsa65Verify(mlDsaPub, mPrime, mldsaSig) && Pca.verifyB64u(Pca.b64(ed25519Pub), mPrime, Pca.b64(tradSig));
        } catch (RuntimeException e) {
            return false;
        }
    }
}
