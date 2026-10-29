package net.atlasauth.pca;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;

/**
 * Agent-side keys: Ed25519 and every post-quantum / hybrid suite this SDK verifies (ML-DSA-65/87, SLH-DSA-SHA2-128f/256s
 * and their hybrids, plus the SUF-CMA nested hybrid), through BouncyCastle. FN-DSA and LESS cannot be signed here (the
 * verifier does not implement FN-DSA either; LESS needs a native runtime) and are refused.
 *
 * <p>Ed25519 and ML-DSA signing are deterministic, so a fixed seed and fixed message give fixed bytes. SLH-DSA is signed in its
 * deterministic variant too.
 */
public final class Keys {
    private Keys() {}

    public static String b64u(byte[] b) { return Pca.b64(b); }

    public static byte[] unb64u(String s) {
        byte[] b = Pca.decodeB64uStrict(s, -1);
        if (b == null) throw new IllegalArgumentException("not canonical base64url");
        return b;
    }

    /** An Ed25519 key: the 32-byte seed (RFC 8032 private key) and the 32-byte public key. */
    public static final class EdKey {
        public final byte[] seed;
        public final byte[] pub;
        private EdKey(byte[] seed, byte[] pub) { this.seed = seed; this.pub = pub; }
        /** The b64u public key: the key id used as {@code issuer} / {@code holder} on the wire. */
        public String id() { return b64u(pub); }
        public byte[] sign(byte[] msg) {
            Ed25519Signer s = new Ed25519Signer();
            s.init(true, new Ed25519PrivateKeyParameters(seed, 0));
            s.update(msg, 0, msg.length);
            return s.generateSignature();
        }
    }

    public static EdKey edFromSeed(byte[] seed) {
        if (seed == null || seed.length != 32) throw new IllegalArgumentException("an Ed25519 seed is 32 bytes");
        byte[] s = seed.clone();
        return new EdKey(s, new Ed25519PrivateKeyParameters(s, 0).generatePublicKey().getEncoded());
    }

    public static EdKey edGenerate() {
        byte[] s = new byte[32];
        new SecureRandom().nextBytes(s);
        return edFromSeed(s);
    }

    /** A post-quantum key pair of one primitive, in the byte encodings the wire uses (FIPS 204 / FIPS 205). */
    public static final class PqKey {
        public final Pq.Prim prim;
        public final byte[] pk;
        public final byte[] sk;
        private PqKey(Pq.Prim prim, byte[] pk, byte[] sk) { this.prim = prim; this.pk = pk; this.sk = sk; }
        /** The b64u public key carried as {@code pq_pk}. */
        public String pkB64u() { return b64u(pk); }
        byte[] sign(byte[] msg) {
            switch (prim) {
                case ML_DSA_65:
                case ML_DSA_87: {
                    MLDSAParameters ps = mlParams(prim);
                    MLDSASigner s = new MLDSASigner(); // pure ML-DSA, empty context, deterministic
                    s.init(true, new MLDSAPrivateKeyParameters(ps, sk));
                    s.update(msg, 0, msg.length);
                    try { return s.generateSignature(); } catch (org.bouncycastle.crypto.CryptoException e) { throw new IllegalStateException(e); }
                }
                case SLH_DSA_SHA2_128F:
                case SLH_DSA_SHA2_256S: {
                    SLHDSASigner s = new SLHDSASigner();
                    s.init(true, new SLHDSAPrivateKeyParameters(slhParams(prim), sk));
                    return s.generateSignature(msg);
                }
                default:
                    throw new IllegalArgumentException("cannot sign with " + prim + " in this SDK");
            }
        }
    }

    private static MLDSAParameters mlParams(Pq.Prim p) { return p == Pq.Prim.ML_DSA_65 ? MLDSAParameters.ml_dsa_65 : MLDSAParameters.ml_dsa_87; }
    private static SLHDSAParameters slhParams(Pq.Prim p) { return p == Pq.Prim.SLH_DSA_SHA2_128F ? SLHDSAParameters.sha2_128f : SLHDSAParameters.sha2_256s; }

    /** A SecureRandom that replays a fixed seed, so key generation is reproducible. Never use it for anything else. */
    private static final class SeedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;
        private int pos;
        SeedRandom(byte[] seed) { this.seed = seed.clone(); }
        @Override public synchronized void nextBytes(byte[] out) {
            for (int i = 0; i < out.length; i++) {
                if (pos >= seed.length) throw new IllegalStateException("seed exhausted");
                out[i] = seed[pos++];
            }
        }
    }

    private static PqKey pqGen(Pq.Prim p, SecureRandom rng) {
        switch (p) {
            case ML_DSA_65:
            case ML_DSA_87: {
                MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
                g.init(new MLDSAKeyGenerationParameters(rng, mlParams(p)));
                AsymmetricCipherKeyPair kp = g.generateKeyPair();
                return new PqKey(p, ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded(), ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded());
            }
            case SLH_DSA_SHA2_128F:
            case SLH_DSA_SHA2_256S: {
                SLHDSAKeyPairGenerator g = new SLHDSAKeyPairGenerator();
                g.init(new SLHDSAKeyGenerationParameters(rng, slhParams(p)));
                AsymmetricCipherKeyPair kp = g.generateKeyPair();
                return new PqKey(p, ((SLHDSAPublicKeyParameters) kp.getPublic()).getEncoded(), ((SLHDSAPrivateKeyParameters) kp.getPrivate()).getEncoded());
            }
            default:
                throw new IllegalArgumentException("cannot generate " + p + " keys in this SDK");
        }
    }

    public static PqKey pqGenerate(Pq.Prim p) { return pqGen(p, new SecureRandom()); }

    /** Reproducible key from a seed: 32 bytes for ML-DSA (FIPS 204 xi), 3n bytes for SLH-DSA (sk_seed, sk_prf, pk_seed). */
    public static PqKey pqFromSeed(Pq.Prim p, byte[] seed) {
        int need = p == Pq.Prim.SLH_DSA_SHA2_128F ? 48 : p == Pq.Prim.SLH_DSA_SHA2_256S ? 96 : 32;
        if (seed == null || seed.length != need) throw new IllegalArgumentException(p + " needs a " + need + "-byte seed");
        return pqGen(p, new SeedRandom(seed));
    }

    /** Load a key pair from its encoded public and secret key (as produced by another implementation of the same suite). */
    public static PqKey pqLoad(Pq.Prim p, byte[] pk, byte[] sk) {
        if (pk == null || pk.length != p.pkBytes) throw new IllegalArgumentException("wrong public key length for " + p);
        return new PqKey(p, pk.clone(), sk.clone());
    }

    /**
     * The key material one signature suite needs: the suite name, the Ed25519 key (every hybrid, and ed25519 itself) and the
     * post-quantum key (every non-ed25519 suite). The constructor fails closed on a missing or mismatched key.
     */
    public static final class SuiteKey {
        public final String alg;
        public final EdKey ed;
        public final PqKey pq;
        final Pq.Suite suite;
        private SuiteKey(String alg, EdKey ed, PqKey pq, Pq.Suite suite) { this.alg = alg; this.ed = ed; this.pq = pq; this.suite = suite; }

        /** The PQ public key bound into the signed body ({@code pq_pk}); null for ed25519. */
        public String pqPk() { return suite.needsPqPk ? pq.pkB64u() : null; }

        /** The Ed25519 identity (key id) this signer is known by. For a pure PQ suite there is none: use {@link #ed}. */
        public String id() { return ed == null ? null : ed.id(); }

        /** Sign: index 0 is {@code sig}, index 1 is {@code pq_sig} (hybrids only, else null). */
        public String[] sign(byte[] msg) {
            if (suite.pq == null) return new String[] {b64u(ed.sign(msg)), null};
            if (!suite.hasEd25519) return new String[] {b64u(pq.sign(msg)), null};
            byte[] edSig = ed.sign(msg);
            byte[] pqSig = pq.sign(suite.nested ? Pca.concat(msg, edSig) : msg);
            return new String[] {b64u(edSig), b64u(pqSig)};
        }
    }

    /** Ed25519 only (the default suite). */
    public static SuiteKey ed25519(EdKey ed) { return suite("ed25519", ed, null); }

    public static SuiteKey suite(String alg, EdKey ed, PqKey pq) {
        Pq.Suite s = Pq.SUITES.get(alg);
        if (s == null) throw new IllegalArgumentException(Pq.refusal(alg));
        if (s.hasEd25519 && ed == null) throw new IllegalArgumentException("'" + alg + "' requires an Ed25519 key");
        if (s.pq != null) {
            if (pq == null) throw new IllegalArgumentException("'" + alg + "' requires a " + s.pq + " key");
            if (pq.prim != s.pq) throw new IllegalArgumentException("'" + alg + "' needs a " + s.pq + " key, got " + pq.prim);
            if (s.pq == Pq.Prim.LESS_CAT1) throw new IllegalArgumentException("LESS cannot be signed in this SDK");
        }
        return new SuiteKey(alg, ed, pq, s);
    }

    /** The verifier-side PQ pin for an identity: {@code { ed25519 b64u: pq_pk }} (what {@code policy.pqPins} holds). */
    public static Map<String, Object> pqPin(SuiteKey k) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (k.ed != null && k.pq != null) m.put(k.ed.id(), k.pq.pkB64u());
        return m;
    }
}
