package net.atlasauth.pca.mpc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * ML-KEM-768 (FIPS 203) on the audited BouncyCastle implementation with caller-supplied randomness: key generation from a
 * 64-byte seed (d || z) and encapsulation from a 32-byte message, so the OT transcripts are reproducible from a seeded stream.
 */
final class MlKem768 {
    private MlKem768() {}

    static final int MSG_BYTES = 32;
    static final int KEYGEN_SEED_BYTES = 64;

    /** A SecureRandom that replays fixed bytes in order (the engines draw d, z / the message in FIPS 203 order). */
    private static final class Replay extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] data;
        private int at = 0;

        Replay(byte[] data) { this.data = data.clone(); }

        @Override public synchronized void nextBytes(byte[] out) {
            if (at + out.length > data.length) throw new IllegalStateException("MlKem768: randomness exhausted");
            System.arraycopy(data, at, out, 0, out.length);
            at += out.length;
        }
    }

    /** A key pair; {@code publicKey} is the 1184-byte encapsulation key. */
    record KeyPair(byte[] publicKey, MLKEMPrivateKeyParameters secretKey) {}

    /** Encapsulation result. */
    record Encapsulation(byte[] cipherText, byte[] sharedSecret) {}

    static KeyPair keygen(byte[] seed64) {
        if (seed64.length != KEYGEN_SEED_BYTES) throw new IllegalArgumentException("ml-kem keygen: seed must be exactly 64 bytes");
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(new Replay(seed64), MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        return new KeyPair(((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded(), (MLKEMPrivateKeyParameters) kp.getPrivate());
    }

    static Encapsulation encapsulate(byte[] publicKey, byte[] msg32) {
        if (msg32.length != MSG_BYTES) throw new IllegalArgumentException("ml-kem encapsulate: message must be exactly 32 bytes");
        MLKEMPublicKeyParameters pk = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, publicKey);
        SecretWithEncapsulation s = new MLKEMGenerator(new Replay(msg32)).generateEncapsulated(pk);
        return new Encapsulation(s.getEncapsulation(), s.getSecret());
    }

    static byte[] decapsulate(byte[] cipherText, MLKEMPrivateKeyParameters sk) {
        return new MLKEMExtractor(sk).extractSecret(cipherText);
    }
}
