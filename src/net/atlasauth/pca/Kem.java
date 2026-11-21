package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * Post-quantum key encapsulation that establishes a 32-byte shared secret (no cipher is shipped): the custom HKDF hybrid X25519 +
 * ML-KEM-768 (and its own-domain ML-KEM-1024 variant), the X-Wing hybrid of draft-connolly-cfrg-xwing-kem-09 (SHA3-256 combiner, byte
 * interoperable), and the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM keys. All primitives come from BouncyCastle; every input
 * is length-checked and every refusal throws IllegalArgumentException.
 */
public final class Kem {
    private Kem() {}

    private static final int X_LEN = 32;
    private static final int SS_LEN = 32;

    public static final int HYBRID_PUBLIC_KEY_LEN = 1216;
    public static final int HYBRID_CIPHERTEXT_LEN = 1120;
    public static final int HYBRID_SHARED_SECRET_LEN = 32;
    public static final String HYBRID_KEM_SUITE = "x25519-ml-kem-768";
    public static final String XWING_SUITE = "xwing";
    public static final int XWING_SEED_LEN = 32;
    public static final int XWING_SECRET_KEY_LEN = 32;
    public static final int XWING_PUBLIC_KEY_LEN = 1216;
    public static final int XWING_CIPHERTEXT_LEN = 1120;
    public static final int XWING_SHARED_SECRET_LEN = 32;
    public static final int XWING_ESEED_LEN = 64;
    public static final int HYBRID1024_PUBLIC_KEY_LEN = 1600;
    public static final int HYBRID1024_CIPHERTEXT_LEN = 1600;
    public static final int HYBRID1024_SHARED_SECRET_LEN = 32;
    public static final String HYBRID1024_KEM_SUITE = "x25519-ml-kem-1024";

    private static final byte[] XWING_LABEL = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

    /** The 6-byte X-Wing domain label, ASCII {@code \.//^\}. */
    public static byte[] xwingLabel() { return XWING_LABEL.clone(); }

    /** A recipient key pair. Hybrid: pub = X25519 pub (32) || ML-KEM ek, secret = X25519 secret (32) || expanded ML-KEM dk. X-Wing: secret = the 32-byte seed. */
    public record KeyPair(byte[] publicKey, byte[] secretKey) {}

    /** The ciphertext to send and the 32-byte shared secret to keep. */
    public record Encapsulation(byte[] ciphertext, byte[] sharedSecret) {}

    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] random(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    private static byte[] slice(byte[] b, int from, int to) { return Arrays.copyOfRange(b, from, to); }

    /** A SecureRandom that replays fixed bytes in order (the engines draw d, z / the message in FIPS 203 order). */
    private static final class Replay extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] data;
        private int at = 0;

        Replay(byte[] data) { this.data = data.clone(); }

        @Override public synchronized void nextBytes(byte[] out) {
            if (at + out.length > data.length) throw new IllegalStateException("Kem: randomness exhausted");
            System.arraycopy(data, at, out, 0, out.length);
            at += out.length;
        }
    }

    /** One ML-KEM parameter set and the hybrid transcript domain built on it. */
    private static final class Level {
        final MLKEMParameters params;
        final int k, ekLen, ctLen, dkLen;
        final byte[] domain;

        Level(MLKEMParameters params, int k, int ctLen, String suite) {
            this.params = params;
            this.k = k;
            this.ekLen = 384 * k + 32;
            this.ctLen = ctLen;
            this.dkLen = 768 * k + 96;
            this.domain = ("atlas-pca/kem/" + suite + "/v1\0").getBytes(StandardCharsets.UTF_8);
        }
    }

    private static final Level L768 = new Level(MLKEMParameters.ml_kem_768, 3, 1088, "x25519-ml-kem-768");
    private static final Level L1024 = new Level(MLKEMParameters.ml_kem_1024, 4, 1568, "x25519-ml-kem-1024");

    private static Level level(int level) {
        if (level == 768) return L768;
        if (level == 1024) return L1024;
        throw new IllegalArgumentException("ML-KEM level must be 768 or 1024");
    }

    // ---- primitives ----

    private static byte[] xPublic(byte[] secret) { return new X25519PrivateKeyParameters(secret, 0).generatePublicKey().getEncoded(); }

    /** X25519 ECDH; an all-zero result (a low-order peer point) is refused. */
    private static byte[] xAgree(byte[] secret, byte[] peerPublic) {
        X25519Agreement a = new X25519Agreement();
        a.init(new X25519PrivateKeyParameters(secret, 0));
        byte[] out = new byte[X_LEN];
        a.calculateAgreement(new X25519PublicKeyParameters(peerPublic, 0), out, 0);
        int acc = 0;
        for (byte b : out) acc |= b;
        if (acc == 0) throw new IllegalArgumentException("Kem: X25519 produced an all-zero shared secret (low-order point)");
        return out;
    }

    private static byte[] sha3(byte[] in) {
        SHA3Digest d = new SHA3Digest(256);
        d.update(in, 0, in.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    /** ML-KEM key generation from the 64-byte seed d || z. */
    private static AsymmetricCipherKeyPair mlKeygen(Level lv, byte[] dz) {
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(new Replay(dz), lv.params));
        return g.generateKeyPair();
    }

    private static byte[] mlEk(AsymmetricCipherKeyPair kp) { return ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded(); }

    private static byte[] mlDk(Level lv, AsymmetricCipherKeyPair kp) {
        byte[] dk = ((MLKEMPrivateKeyParameters) kp.getPrivate()).getEncoded();
        if (dk.length != lv.dkLen) throw new IllegalStateException("Kem: unexpected ML-KEM decapsulation key length " + dk.length);
        return dk;
    }

    private static SecretWithEncapsulation mlEncaps(Level lv, byte[] ek, byte[] m) {
        return new MLKEMGenerator(new Replay(m)).generateEncapsulated(new MLKEMPublicKeyParameters(lv.params, ek));
    }

    /** ML-KEM decapsulation from an EXPANDED dk. BouncyCastle does not validate the encoding length, so it is checked here. */
    private static byte[] mlDecaps(Level lv, byte[] ct, byte[] dk) {
        if (ct.length != lv.ctLen) throw new IllegalArgumentException("Kem: ML-KEM ciphertext must be " + lv.ctLen + " bytes (got " + ct.length + ")");
        if (dk.length != lv.dkLen) throw new IllegalArgumentException("Kem: ML-KEM decapsulation key must be " + lv.dkLen + " bytes (got " + dk.length + ")");
        return new MLKEMExtractor(new MLKEMPrivateKeyParameters(lv.params, dk)).extractSecret(ct);
    }

    /** FIPS 203 section 7.2: every 12-bit coefficient of the 384*k-byte t part is strictly below q = 3329. */
    private static boolean coefficientsReduced(byte[] ek, int k) {
        for (int i = 0; i < 384 * k; i += 3) {
            if (((ek[i] & 0xff) | ((ek[i + 1] & 0x0f) << 8)) >= 3329) return false;
            if ((((ek[i + 1] & 0xff) >> 4) | ((ek[i + 2] & 0xff) << 4)) >= 3329) return false;
        }
        return true;
    }

    private static void requireReduced(byte[] ek, int k, String who) {
        if (!coefficientsReduced(ek, k)) throw new IllegalArgumentException(who + ": ML-KEM encapsulation key fails the FIPS 203 modulus check");
    }

    private static byte[] combine(Level lv, byte[] ssMl, byte[] ssX, byte[] ephPub, byte[] recipX) {
        return Entropy.hkdfSha256(cat(ssMl, ssX, ephPub, recipX), null, lv.domain, SS_LEN);
    }

    // ---- the custom HKDF hybrid (768 and 1024 share one body) ----

    private static KeyPair hybridKeygen(Level lv, byte[] rng) {
        if (rng.length != 96) throw new IllegalArgumentException("Kem: keygen randomness must be x(32) || d(32) || z(32)");
        byte[] x = slice(rng, 0, 32);
        AsymmetricCipherKeyPair kp = mlKeygen(lv, slice(rng, 32, 96));
        return new KeyPair(cat(xPublic(x), mlEk(kp)), cat(x, mlDk(lv, kp)));
    }

    private static Encapsulation hybridEncaps(Level lv, byte[] pk, byte[] rng, String who) {
        if (pk.length != X_LEN + lv.ekLen) throw new IllegalArgumentException(who + ": public key must be " + (X_LEN + lv.ekLen) + " bytes (got " + pk.length + ")");
        if (rng.length != 64) throw new IllegalArgumentException("Kem: encapsulation randomness must be ephemeral(32) || m(32)");
        byte[] recipX = slice(pk, 0, X_LEN), recipMl = slice(pk, X_LEN, pk.length);
        byte[] eph = slice(rng, 0, 32);
        byte[] ephPub = xPublic(eph);
        byte[] ssX = xAgree(eph, recipX);
        requireReduced(recipMl, lv.k, who);
        SecretWithEncapsulation s = mlEncaps(lv, recipMl, slice(rng, 32, 64));
        return new Encapsulation(cat(ephPub, s.getEncapsulation()), combine(lv, s.getSecret(), ssX, ephPub, recipX));
    }

    private static byte[] hybridDecaps(Level lv, byte[] ct, byte[] sk, String who) {
        if (ct.length != X_LEN + lv.ctLen) throw new IllegalArgumentException(who + ": ciphertext must be " + (X_LEN + lv.ctLen) + " bytes (got " + ct.length + ")");
        if (sk.length <= X_LEN) throw new IllegalArgumentException(who + ": malformed secret key");
        byte[] ephPub = slice(ct, 0, X_LEN);
        byte[] xPriv = slice(sk, 0, X_LEN);
        byte[] ssX = xAgree(xPriv, ephPub);
        byte[] ssMl = mlDecaps(lv, slice(ct, X_LEN, ct.length), slice(sk, X_LEN, sk.length));
        return combine(lv, ssMl, ssX, ephPub, xPublic(xPriv));
    }

    /** Generate a hybrid X25519 + ML-KEM-768 recipient key pair (public 1216 bytes, secret 2432 bytes). */
    public static KeyPair hybridKemKeygen() { return hybridKeygen(L768, random(96)); }
    /** Test entry point: the randomness is {@code x(32) || d(32) || z(32)}. */
    static KeyPair hybridKemKeygenDerand(byte[] rng) { return hybridKeygen(L768, rng); }

    /** Encapsulate to a hybrid recipient public key. */
    public static Encapsulation hybridEncapsulate(byte[] recipientPublicKey) { return hybridEncaps(L768, recipientPublicKey, random(64), "hybridEncapsulate"); }
    /** Test entry point: the randomness is {@code ephemeralX25519Secret(32) || m(32)}. */
    static Encapsulation hybridEncapsulateDerand(byte[] recipientPublicKey, byte[] rng) { return hybridEncaps(L768, recipientPublicKey, rng, "hybridEncapsulate"); }

    /** Decapsulate with the recipient secret key: recovers the same shared secret. */
    public static byte[] hybridDecapsulate(byte[] ciphertext, byte[] secretKey) { return hybridDecaps(L768, ciphertext, secretKey, "hybridDecapsulate"); }

    /** Generate a hybrid X25519 + ML-KEM-1024 recipient key pair (public 1600 bytes, secret 3200 bytes). */
    public static KeyPair hybridKem1024Keygen() { return hybridKeygen(L1024, random(96)); }
    static KeyPair hybridKem1024KeygenDerand(byte[] rng) { return hybridKeygen(L1024, rng); }

    public static Encapsulation hybridEncapsulate1024(byte[] recipientPublicKey) { return hybridEncaps(L1024, recipientPublicKey, random(64), "hybridEncapsulate1024"); }
    static Encapsulation hybridEncapsulate1024Derand(byte[] recipientPublicKey, byte[] rng) { return hybridEncaps(L1024, recipientPublicKey, rng, "hybridEncapsulate1024"); }

    public static byte[] hybridDecapsulate1024(byte[] ciphertext, byte[] secretKey) { return hybridDecaps(L1024, ciphertext, secretKey, "hybridDecapsulate1024"); }

    // ---- X-Wing (draft-connolly-cfrg-xwing-kem-09) ----

    private record XWingKey(AsymmetricCipherKeyPair ml, byte[] xSecret, byte[] xPublic) {}

    /** Draft-09 5.2: SHAKE-256(seed, 96) = d(32) || z(32) || skX(32). */
    private static XWingKey xwingExpand(byte[] seed) {
        if (seed.length != XWING_SEED_LEN) throw new IllegalArgumentException("xwing: seed must be " + XWING_SEED_LEN + " bytes (got " + seed.length + ")");
        SHAKEDigest sh = new SHAKEDigest(256);
        sh.update(seed, 0, seed.length);
        byte[] ex = new byte[96];
        sh.doFinal(ex, 0, 96);
        byte[] xs = slice(ex, 64, 96);
        return new XWingKey(mlKeygen(L768, slice(ex, 0, 64)), xs, xPublic(xs));
    }

    /** Draft-09 5.3: SHA3-256(ssM || ssX || ctX || pkX || label); ct_M is deliberately not hashed in. */
    private static byte[] xwingCombine(byte[] ssM, byte[] ssX, byte[] ctX, byte[] pkX) { return sha3(cat(ssM, ssX, ctX, pkX, XWING_LABEL)); }

    /** Generate an X-Wing key pair from a fresh seed; the secret key IS the 32-byte seed. */
    public static KeyPair xwingKeygen() { return xwingKeygen(random(XWING_SEED_LEN)); }

    /** Deterministic X-Wing key generation from a 32-byte seed (copied into the result). */
    public static KeyPair xwingKeygen(byte[] seed) {
        byte[] sk = seed.clone();
        XWingKey ex = xwingExpand(sk);
        return new KeyPair(cat(mlEk(ex.ml()), ex.xPublic()), sk);
    }

    /** Derandomized X-Wing encapsulation: {@code eseed} (64 bytes) = ML-KEM message m (32) || X25519 ephemeral secret (32). */
    public static Encapsulation xwingEncapsulateDerand(byte[] recipientPublicKey, byte[] eseed) {
        if (recipientPublicKey.length != XWING_PUBLIC_KEY_LEN) throw new IllegalArgumentException("xwingEncapsulateDerand: public key must be " + XWING_PUBLIC_KEY_LEN + " bytes (got " + recipientPublicKey.length + ")");
        if (eseed.length != XWING_ESEED_LEN) throw new IllegalArgumentException("xwingEncapsulateDerand: eseed must be " + XWING_ESEED_LEN + " bytes (got " + eseed.length + ")");
        byte[] pkM = slice(recipientPublicKey, 0, 1184), pkX = slice(recipientPublicKey, 1184, XWING_PUBLIC_KEY_LEN);
        byte[] ekX = slice(eseed, 32, 64);
        requireReduced(pkM, 3, "xwingEncapsulateDerand");
        SecretWithEncapsulation s = mlEncaps(L768, pkM, slice(eseed, 0, 32));
        byte[] ctX = xPublic(ekX);
        byte[] ssX = xAgree(ekX, pkX);
        return new Encapsulation(cat(s.getEncapsulation(), ctX), xwingCombine(s.getSecret(), ssX, ctX, pkX));
    }

    /** Encapsulate to an X-Wing public key with fresh randomness. */
    public static Encapsulation xwingEncapsulate(byte[] recipientPublicKey) { return xwingEncapsulateDerand(recipientPublicKey, random(XWING_ESEED_LEN)); }

    /** Decapsulate an X-Wing ciphertext with the 32-byte seed secret key. */
    public static byte[] xwingDecapsulate(byte[] ciphertext, byte[] secretKey) {
        if (ciphertext.length != XWING_CIPHERTEXT_LEN) throw new IllegalArgumentException("xwingDecapsulate: ciphertext must be " + XWING_CIPHERTEXT_LEN + " bytes (got " + ciphertext.length + ")");
        XWingKey ex = xwingExpand(secretKey);
        byte[] ctM = slice(ciphertext, 0, 1088), ctX = slice(ciphertext, 1088, XWING_CIPHERTEXT_LEN);
        byte[] ssM = new MLKEMExtractor((MLKEMPrivateKeyParameters) ex.ml().getPrivate()).extractSecret(ctM);
        byte[] ssX = xAgree(ex.xSecret(), ctX);
        return xwingCombine(ssM, ssX, ctX, ex.xPublic());
    }

    // ---- b64url wire forms (unpadded; decode is strict: canonical alphabet and trailing bits) ----

    public static String encodeHybridPublicKey(byte[] k) { return Keys.b64u(k); }
    public static byte[] decodeHybridPublicKey(String s) { return Keys.unb64u(s); }
    public static String encodeHybridCiphertext(byte[] c) { return Keys.b64u(c); }
    public static byte[] decodeHybridCiphertext(String s) { return Keys.unb64u(s); }
    public static String encodeXWingPublicKey(byte[] k) { return Keys.b64u(k); }
    public static byte[] decodeXWingPublicKey(String s) { return Keys.unb64u(s); }
    public static String encodeXWingCiphertext(byte[] c) { return Keys.b64u(c); }
    public static byte[] decodeXWingCiphertext(String s) { return Keys.unb64u(s); }

    // ---- FIPS 203 7.2 / 7.3 input checks for keys that did not come from this process's own keygen ----

    /** FIPS 203 7.2 type and modulus check of an encapsulation key; false for any wrong length or non-reduced coefficient. An unknown level throws. */
    public static boolean mlKemEncapsulationKeyCheck(int level, byte[] ek) {
        Level lv = level(level);
        return ek != null && ek.length == lv.ekLen && coefficientsReduced(ek, lv.k);
    }

    /** FIPS 203 7.3 check of a decapsulation key: length, the embedded H(ek) and the embedded key's modulus check. An unknown level throws. */
    public static boolean mlKemDecapsulationKeyCheck(int level, byte[] dk) {
        Level lv = level(level);
        if (dk == null || dk.length != lv.dkLen) return false;
        byte[] ek = slice(dk, 384 * lv.k, 768 * lv.k + 32);
        byte[] h = slice(dk, 768 * lv.k + 32, 768 * lv.k + 64);
        return java.security.MessageDigest.isEqual(sha3(ek), h) && mlKemEncapsulationKeyCheck(level, ek);
    }
}
