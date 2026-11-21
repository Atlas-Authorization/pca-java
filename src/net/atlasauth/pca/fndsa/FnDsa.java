package net.atlasauth.pca.fndsa;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;

/**
 * FN-DSA / Falcon (FIPS 206 draft) for PCA's crypto-agility seam: suite ids, exact byte-length enforcement, the PCA leaf framing and the
 * Ed25519 + FN-DSA hybrid, with the lattice math behind a pluggable {@link FalconBackend}.
 *
 * <p>No Falcon primitive is bundled in the core, so the core has no native dependency. The real primitive is the separate {@code pca-fndsa}
 * adapter (JNA over libfndsa, Thomas Pornin's fn-dsa 0.4.0), which registers itself with {@link #setFalconBackend}. FIPS 206 is not yet
 * published: fn-dsa 0.4.0 is a draft best guess, pinned in lockstep with the TypeScript reference. liboqs, BouncyCastle (org.bouncycastle.pqc.crypto.falcon)
 * and circl implement the ROUND-3 Falcon, whose hash-to-point is H(nonce || message); FN-DSA hashes the nonce, the hashed verifying key, a
 * domain/context prefix and the message, so the two do not verify each other's signatures (same key encodings, different signatures). Never
 * register round-3 code under the {@code fn-dsa-*} suite ids. Everything else here (the wire, framing, hybrid rule) is real.
 */
public final class FnDsa {
    private FnDsa() {}

    public static final int FN_DSA_512_PUBLIC_KEY_BYTES = 897, FN_DSA_512_SIGNATURE_BYTES = 666;
    public static final int FN_DSA_1024_PUBLIC_KEY_BYTES = 1793, FN_DSA_1024_SIGNATURE_BYTES = 1280;
    private static final int ED25519_SIGNATURE_BYTES = 64;
    public static final String FN_DSA_LEAF_DOMAIN = "atlas-pca/fn-dsa/leaf/v1\0";
    public static final String NO_FN_DSA_BACKEND_MESSAGE =
        "no FN-DSA backend registered — install @atlasauth/pca-fndsa-wasm or supply a backend via setFalconBackend()";

    /** One suite's wire contract. */
    public static final class Suite {
        public final String alg, variant;
        public final boolean hasEd25519, needsPqPk, needsPqSig;
        public final int sigBytes, pqPkBytes, pqSigBytes, fnSigBytes;
        Suite(String alg, String variant, boolean ed, int sigBytes, int pqPkBytes, boolean needsPqSig, int pqSigBytes, int fnSigBytes) {
            this.alg = alg; this.variant = variant; this.hasEd25519 = ed; this.sigBytes = sigBytes; this.needsPqPk = true;
            this.pqPkBytes = pqPkBytes; this.needsPqSig = needsPqSig; this.pqSigBytes = pqSigBytes; this.fnSigBytes = fnSigBytes;
        }

        /** The suite as the reference prints it (JSON value). */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("alg", alg); m.put("variant", variant); m.put("hasEd25519", hasEd25519); m.put("sigBytes", sigBytes); m.put("needsPqPk", needsPqPk);
            m.put("pqPkBytes", pqPkBytes); m.put("needsPqSig", needsPqSig); m.put("pqSigBytes", pqSigBytes); m.put("fnSigBytes", fnSigBytes);
            return m;
        }
    }

    public static final Map<String, Suite> FN_DSA_SUITES;
    static {
        Map<String, Suite> s = new LinkedHashMap<>();
        s.put("fn-dsa-512", new Suite("fn-dsa-512", "fn-dsa-512", false, FN_DSA_512_SIGNATURE_BYTES, FN_DSA_512_PUBLIC_KEY_BYTES, false, 0, FN_DSA_512_SIGNATURE_BYTES));
        s.put("fn-dsa-1024", new Suite("fn-dsa-1024", "fn-dsa-1024", false, FN_DSA_1024_SIGNATURE_BYTES, FN_DSA_1024_PUBLIC_KEY_BYTES, false, 0, FN_DSA_1024_SIGNATURE_BYTES));
        s.put("hybrid-ed25519-fn-dsa-512", new Suite("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", true, ED25519_SIGNATURE_BYTES, FN_DSA_512_PUBLIC_KEY_BYTES, true, FN_DSA_512_SIGNATURE_BYTES, FN_DSA_512_SIGNATURE_BYTES));
        s.put("hybrid-ed25519-fn-dsa-1024", new Suite("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", true, ED25519_SIGNATURE_BYTES, FN_DSA_1024_PUBLIC_KEY_BYTES, true, FN_DSA_1024_SIGNATURE_BYTES, FN_DSA_1024_SIGNATURE_BYTES));
        FN_DSA_SUITES = Collections.unmodifiableMap(s);
    }

    private static int variantPk(String v) { return "fn-dsa-512".equals(v) ? FN_DSA_512_PUBLIC_KEY_BYTES : FN_DSA_1024_PUBLIC_KEY_BYTES; }
    private static int variantSig(String v) { return "fn-dsa-512".equals(v) ? FN_DSA_512_SIGNATURE_BYTES : FN_DSA_1024_SIGNATURE_BYTES; }

    public static boolean isKnownFnDsaAlg(Object x) { return x instanceof String && FN_DSA_SUITES.containsKey(x); }

    /** The suite for an id, or null (fail closed) for an unknown name or a non-string. */
    public static Suite resolveFnDsaAlg(Object alg) { return isKnownFnDsaAlg(alg) ? FN_DSA_SUITES.get(alg) : null; }

    public static boolean isFnDsaVariant(Object v) { return "fn-dsa-512".equals(v) || "fn-dsa-1024".equals(v); }

    // ---- backend seam ------------------------------------------------------------------------------------------------

    public static final class FalconKeyPair {
        public final byte[] pk, sk;
        public FalconKeyPair(byte[] pk, byte[] sk) { this.pk = pk; this.sk = sk; }
    }

    /**
     * The vetted FN-DSA primitive. {@code verify} is mandatory and MUST return false on a bad signature; {@code sign} and {@code keygen} are
     * optional ({@link #canSign()} false means verify-only). All byte arguments are the padded FIPS 206 encodings.
     */
    public interface FalconBackend {
        boolean verify(byte[] pubkey, byte[] message, byte[] signature);
        default boolean canSign() { return false; }
        default byte[] sign(byte[] secretkey, byte[] message) { throw new UnsupportedOperationException("backend is verify-only"); }
        default FalconKeyPair keygen() { throw new UnsupportedOperationException("backend cannot generate keys"); }
        /** Deterministic signature from a caller-supplied 32-byte signing seed (the producer vectors); optional. */
        default byte[] sign(byte[] secretkey, byte[] message, byte[] signSeed) { throw new UnsupportedOperationException("backend cannot sign from a seed"); }
        /** Deterministic key generation of {@code variant} from a 32-byte seed; optional. */
        default FalconKeyPair keygen(String variant, byte[] seed) { throw new UnsupportedOperationException("backend cannot generate keys from a seed"); }
    }

    private static final FalconBackend DEFAULT_BACKEND = new FalconBackend() {
        @Override public boolean verify(byte[] p, byte[] m, byte[] s) { throw new IllegalStateException(NO_FN_DSA_BACKEND_MESSAGE); }
        @Override public boolean canSign() { return true; }
        @Override public byte[] sign(byte[] k, byte[] m) { throw new IllegalStateException(NO_FN_DSA_BACKEND_MESSAGE); }
        @Override public FalconKeyPair keygen() { throw new IllegalStateException(NO_FN_DSA_BACKEND_MESSAGE); }
    };

    private static final AtomicReference<FalconBackend> CURRENT = new AtomicReference<>(DEFAULT_BACKEND);

    public static void setFalconBackend(FalconBackend backend) { CURRENT.set(backend); }
    public static FalconBackend getFalconBackend() { return CURRENT.get(); }
    /** True once a backend (real or test double) is registered; the core verifies fn-dsa-* suites only then. */
    public static boolean hasBackend() { return CURRENT.get() != DEFAULT_BACKEND; }
    public static void resetFalconBackend() { CURRENT.set(DEFAULT_BACKEND); }

    // ---- primitive wrappers ------------------------------------------------------------------------------------------

    /** Sign through the backend after enforcing framing; throws when no backend, a verify-only backend, or a wrong-length signature. */
    public static byte[] fndsaSign(String variant, byte[] sk, byte[] msg) {
        if (!isFnDsaVariant(variant)) throw new IllegalArgumentException("fndsaSign: unknown FN-DSA variant '" + variant + "'");
        if (sk == null || sk.length == 0) throw new IllegalArgumentException("fndsaSign: secret key must be a non-empty byte array");
        if (msg == null) throw new IllegalArgumentException("fndsaSign: message must be a byte array");
        FalconBackend backend = CURRENT.get();
        if (!backend.canSign()) throw new IllegalStateException("fndsaSign: FN-DSA backend is verify-only (no sign())");
        byte[] sig = backend.sign(sk, msg);
        int expected = variantSig(variant);
        if (sig == null || sig.length != expected) {
            throw new IllegalStateException("fndsaSign: FN-DSA backend returned a " + (sig == null ? "non-byte" : String.valueOf(sig.length)) + " signature; expected padded " + expected + " bytes for '" + variant + "'");
        }
        return sig;
    }

    /** Like {@link #fndsaSign(String, byte[], byte[])} with an explicit 32-byte signing seed (deterministic). */
    public static byte[] fndsaSignSeeded(String variant, byte[] sk, byte[] msg, byte[] signSeed) {
        if (!isFnDsaVariant(variant)) throw new IllegalArgumentException("fndsaSignSeeded: unknown FN-DSA variant '" + variant + "'");
        if (sk == null || sk.length == 0) throw new IllegalArgumentException("fndsaSignSeeded: secret key must be a non-empty byte array");
        if (msg == null) throw new IllegalArgumentException("fndsaSignSeeded: message must be a byte array");
        if (signSeed == null || signSeed.length != 32) throw new IllegalArgumentException("fndsaSignSeeded: signing seed must be 32 bytes");
        FalconBackend backend = CURRENT.get();
        if (!backend.canSign()) throw new IllegalStateException("fndsaSignSeeded: FN-DSA backend is verify-only (no sign())");
        byte[] sig = backend.sign(sk, msg, signSeed);
        int expected = variantSig(variant);
        if (sig == null || sig.length != expected) throw new IllegalStateException("fndsaSignSeeded: FN-DSA backend returned a wrong-length signature; expected " + expected + " bytes for '" + variant + "'");
        return sig;
    }

    /** Seed-based key generation through the registered backend (32-byte seed); throws without one. */
    public static FalconKeyPair fndsaKeygen(String variant, byte[] seed) {
        if (!isFnDsaVariant(variant)) throw new IllegalArgumentException("fndsaKeygen: unknown FN-DSA variant '" + variant + "'");
        if (seed == null || seed.length != 32) throw new IllegalArgumentException("fndsaKeygen: seed must be 32 bytes");
        FalconKeyPair kp = CURRENT.get().keygen(variant, seed);
        if (kp == null || kp.pk == null || kp.pk.length != variantPk(variant)) throw new IllegalStateException("fndsaKeygen: FN-DSA backend returned a wrong-length public key");
        return kp;
    }

    /** Verify; key and signature lengths are enforced BEFORE the backend runs (wrong length gives false). A throwing backend is not swallowed. */
    public static boolean fndsaVerify(String variant, byte[] pk, byte[] msg, byte[] sig) {
        if (!isFnDsaVariant(variant)) return false;
        if (pk == null || pk.length != variantPk(variant)) return false;
        if (sig == null || sig.length != variantSig(variant)) return false;
        if (msg == null) return false;
        return CURRENT.get().verify(pk, msg, sig);
    }

    // ---- PCA leaf framing --------------------------------------------------------------------------------------------

    private static byte[] utf8(String s) { return Json.utf8(s); }

    /** {@code thresholdMessage(leaf) || domain || alg || 0x00 || pq_pk}: binds the suite and the key into the signed bytes. */
    public static byte[] fndsaLeafMessage(Map<String, Object> leaf, String alg, String pqPkB64u) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(Pca.thresholdMessage(leaf));
        o.writeBytes(utf8(FN_DSA_LEAF_DOMAIN));
        o.writeBytes(utf8(alg));
        o.write(0);
        o.writeBytes(utf8(pqPkB64u));
        return o.toByteArray();
    }

    /**
     * Sign a PCActn leaf; returns the wire fields {sig, alg, pq_pk[, pq_sig]}. Pure: sig = FN-DSA signature. Hybrid: sig = Ed25519, pq_sig = FN-DSA,
     * both over the same bytes. Throws on an unknown suite, a wrong-length key, a missing edSecret for a hybrid, or a missing/limited backend.
     */
    public static Map<String, Object> signPcaWithFndsa(Object alg, Map<String, Object> leaf, byte[] fnPk, byte[] fnSk, byte[] edSecret) {
        Suite suite = resolveFnDsaAlg(alg);
        if (suite == null) throw new IllegalArgumentException("signPcaWithFndsa: unknown FN-DSA alg '" + alg + "'");
        if (fnPk == null || fnPk.length != suite.pqPkBytes) throw new IllegalArgumentException("signPcaWithFndsa: '" + suite.alg + "' requires a " + suite.pqPkBytes + "-byte FN-DSA public key");
        if (fnSk == null || fnSk.length == 0) throw new IllegalArgumentException("signPcaWithFndsa: '" + suite.alg + "' requires FN-DSA secret-key material");
        String pqPk = Keys.b64u(fnPk);
        byte[] msg = fndsaLeafMessage(leaf, suite.alg, pqPk);
        byte[] fnSig = fndsaSign(suite.variant, fnSk, msg);
        Map<String, Object> out = new LinkedHashMap<>();
        if (!suite.hasEd25519) {
            out.put("sig", Keys.b64u(fnSig)); out.put("alg", suite.alg); out.put("pq_pk", pqPk);
            return out;
        }
        if (edSecret == null) throw new IllegalArgumentException("signPcaWithFndsa: '" + suite.alg + "' requires edSecret (Ed25519 leaf-holder secret key)");
        out.put("sig", Keys.b64u(Keys.edFromSeed(edSecret).sign(msg))); out.put("alg", suite.alg); out.put("pq_pk", pqPk); out.put("pq_sig", Keys.b64u(fnSig));
        return out;
    }

    /**
     * Verify an FN-DSA leaf signature. Fail closed and never throws for wire faults: unknown alg, wrong-length or absent key/signature, a tampered
     * leaf or a suite/key swap give false. A hybrid needs BOTH halves. (A backend that throws is not caught.) All wire fields are untrusted Objects.
     */
    public static boolean verifyPcaFndsa(Object alg, Map<String, Object> leaf, Object holder, Object pqPk, Object sig, Object pqSig) {
        Suite suite = resolveFnDsaAlg(alg);
        if (suite == null) return false;
        if (!(pqPk instanceof String)) return false;
        byte[] pk = Pca.decodeB64uStrict(pqPk, suite.pqPkBytes);
        if (pk == null) return false;
        byte[] msg = fndsaLeafMessage(leaf, suite.alg, (String) pqPk);
        if (!suite.hasEd25519) {
            if (!(sig instanceof String)) return false;
            byte[] fnSig = Pca.decodeB64uStrict(sig, suite.sigBytes);
            if (fnSig == null) return false;
            return fndsaVerify(suite.variant, pk, msg, fnSig);
        }
        if (!(holder instanceof String) || !(sig instanceof String)) return false;
        if (Pca.decodeB64uStrict(sig, suite.sigBytes) == null) return false;
        boolean edOk = W3Bridge.verifyB64u((String) holder, msg, (String) sig);
        if (!(pqSig instanceof String)) return false;
        byte[] fnSig = Pca.decodeB64uStrict(pqSig, suite.pqSigBytes);
        if (fnSig == null) return false;
        boolean pqOk = fndsaVerify(suite.variant, pk, msg, fnSig);
        return edOk && pqOk;
    }

    // ---- KAT / mock backend (a TEST double: hash-derived bytes, NOT Falcon) -----------------------------------------------

    /** A known-answer vector: the backend must map (pk, msg) to sig. */
    public static final class FalconKat {
        public final byte[] pk, msg, sig;
        public FalconKat(byte[] pk, byte[] msg, byte[] sig) { this.pk = pk; this.msg = msg; this.sig = sig; }
    }

    private static final byte[] MOCK_SK_TAG = utf8("atlas-pca/fn-dsa/mock-sk/v1\0");

    private static byte[] sha256(byte[] b) {
        try { return MessageDigest.getInstance("SHA-256").digest(b); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }

    /** Deterministic SHA-256 counter-mode stretch of {@code seed} to exactly {@code outLen} bytes (mock/KAT derivation, not Falcon). */
    public static byte[] hashKat(byte[] seed, int outLen) {
        if (outLen < 0) throw new IllegalArgumentException("hashKat: negative length");
        byte[] out = new byte[outLen];
        int off = 0;
        for (int counter = 0; off < outLen; counter++) {
            byte[] block = sha256(concat(seed, new byte[] {(byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter}));
            int take = Math.min(block.length, outLen - off);
            System.arraycopy(block, 0, out, off, take);
            off += take;
        }
        return out;
    }

    public static FalconKeyPair mockKeypair(String variant) { return mockKeypair(variant, "default"); }

    /** Deterministic MOCK key pair (NOT Falcon keys) from a String or byte[] seed. */
    public static FalconKeyPair mockKeypair(String variant, Object seed) {
        if (!isFnDsaVariant(variant)) throw new IllegalArgumentException("mockKeypair: unknown FN-DSA variant '" + variant + "'");
        byte[] seedBytes;
        if (seed instanceof String) seedBytes = utf8(variant + "/" + seed);
        else if (seed instanceof byte[]) seedBytes = concat(utf8(variant + "/"), (byte[]) seed);
        else throw new IllegalArgumentException("mockKeypair: seed must be a String or byte[]");
        byte[] pk = hashKat(seedBytes, variantPk(variant));
        return new FalconKeyPair(pk, concat(MOCK_SK_TAG, pk));
    }

    private static byte[] deriveMockSig(byte[] pk, byte[] msg) {
        int len = pk.length == FN_DSA_512_PUBLIC_KEY_BYTES ? FN_DSA_512_SIGNATURE_BYTES : pk.length == FN_DSA_1024_PUBLIC_KEY_BYTES ? FN_DSA_1024_SIGNATURE_BYTES : -1;
        if (len < 0) return null;
        return hashKat(concat(utf8("fn-dsa/mock-sig/v1\0"), pk, msg), len);
    }

    private static String katKey(byte[] pk, byte[] msg) { return Keys.b64u(pk) + "|" + Keys.b64u(msg); }

    /** Install (and return) the deterministic mock backend; explicit {@code vectors} take precedence over the derived signature. */
    public static FalconBackend registerTestBackend(List<FalconKat> vectors) {
        Map<String, byte[]> table = new HashMap<>();
        if (vectors != null) for (FalconKat v : vectors) table.put(katKey(v.pk, v.msg), v.sig);
        FalconBackend backend = new FalconBackend() {
            @Override public boolean verify(byte[] pk, byte[] msg, byte[] sig) {
                byte[] expected = table.get(katKey(pk, msg));
                if (expected == null) expected = deriveMockSig(pk, msg);
                return expected != null && MessageDigest.isEqual(sig, expected);
            }
            @Override public boolean canSign() { return true; }
            @Override public byte[] sign(byte[] sk, byte[] msg) {
                if (sk.length <= MOCK_SK_TAG.length || !MessageDigest.isEqual(java.util.Arrays.copyOfRange(sk, 0, MOCK_SK_TAG.length), MOCK_SK_TAG)) {
                    throw new IllegalArgumentException("mock FN-DSA backend: secret key was not minted by mockKeypair()");
                }
                byte[] pk = java.util.Arrays.copyOfRange(sk, MOCK_SK_TAG.length, sk.length);
                byte[] fromTable = table.get(katKey(pk, msg));
                if (fromTable != null) return fromTable;
                byte[] derived = deriveMockSig(pk, msg);
                if (derived == null) throw new IllegalArgumentException("mock FN-DSA backend: public key length matches no FN-DSA variant");
                return derived;
            }
            @Override public FalconKeyPair keygen() { return mockKeypair("fn-dsa-512"); }
        };
        setFalconBackend(backend);
        return backend;
    }
}
