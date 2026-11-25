package net.atlasauth.pca;

import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.utils.LibraryLoader;
import java.util.List;

/**
 * The one libsodium binding behind every ristretto255 / Ed25519 group operation in this library (vetted, constant-time; no group or
 * field arithmetic is written here). {@link #S} exposes the ristretto255 and scalar natives (lazysodium-java 5.2.0); lazysodium has no
 * binding for the plain Ed25519 core / scalarmult calls, so {@link Ed} registers those few over the same libsodium (system library
 * preferred, the lazysodium-bundled one as fallback).
 */
public final class Libsodium {
    private Libsodium() {}

    public static final SodiumJava S = new SodiumJava();

    /** crypto_core_ed25519_* and crypto_scalarmult_ed25519_*; 0 means success except is_valid_point (1 = valid). */
    public static final class Ed {
        private Ed() {}
        public static native int crypto_core_ed25519_add(byte[] r, byte[] p, byte[] q);
        public static native int crypto_core_ed25519_sub(byte[] r, byte[] p, byte[] q);
        public static native int crypto_core_ed25519_is_valid_point(byte[] p);
        public static native int crypto_scalarmult_ed25519_noclamp(byte[] q, byte[] n, byte[] p);
        public static native int crypto_scalarmult_ed25519_base_noclamp(byte[] q, byte[] n);

        // a nested class does not trigger the outer class's initialiser: touch S (loads and sodium_init()s libsodium), then register
        static {
            if (S == null) throw new IllegalStateException("libsodium not loaded");
            new LibraryLoader(List.<Class>of(Ed.class)).loadLibrary(LibraryLoader.Mode.PREFER_SYSTEM, "sodium");
        }
    }

    /** Little-endian 32 bytes of a non-negative integer below 2^256. */
    public static byte[] le32(java.math.BigInteger n) {
        if (n.signum() < 0 || n.bitLength() > 256) throw new IllegalArgumentException("scalar out of range");
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) n.shiftRight(8 * i).intValue();
        return out;
    }

    public static java.math.BigInteger fromLe(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[b.length - 1 - i] = b[i];
        return new java.math.BigInteger(1, be);
    }
}
