package net.atlasauth.pca.aggsig;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * BLS12-381 signature aggregation for Proof-Carrying Authority (port of the TypeScript aggsig package), on blst.
 *
 * <p>Rogue-key safety by construction: the aggregate verifiers take {@link RegisteredKey}s only, and a RegisteredKey can only
 * come from {@link #registerKey} / {@link KeyRegistry#register}, which verify KeyValidate and a proof of possession first.
 * The raw verifiers live in the package-private {@code AggsigCore}.
 */
public final class Aggsig {
    private Aggsig() {}

    public static final String SIG_DST = AggsigCore.SIG_DST;
    public static final String POP_DST = AggsigCore.POP_DST;
    public static final int PUBLIC_KEY_LENGTH = AggsigCore.PUBLIC_KEY_LENGTH;
    public static final int SIGNATURE_LENGTH = AggsigCore.SIGNATURE_LENGTH;

    /** 32-byte big-endian scalar and its 48-byte compressed G1 public key. */
    public static final class KeyPair {
        public final byte[] secretKey;
        public final byte[] publicKey;
        KeyPair(byte[] secretKey, byte[] publicKey) { this.secretKey = secretKey; this.publicKey = publicKey; }
    }

    /** Either a registered key or the reason it was refused. */
    public static final class RegisterResult {
        public final boolean ok;
        public final RegisteredKey key;
        public final String reason;
        private RegisterResult(boolean ok, RegisteredKey key, String reason) { this.ok = ok; this.key = key; this.reason = reason; }
        static RegisterResult ok(RegisteredKey k) { return new RegisterResult(true, k, null); }
        static RegisterResult fail(String why) { return new RegisterResult(false, null, why); }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    public static KeyPair keyGen() { return AggsigCore.keyGen(new SecureRandom()); }

    public static byte[] publicKeyOf(byte[] secretKey) { return AggsigCore.publicKeyOf(secretKey); }

    public static boolean keyValidate(byte[] publicKey) { return AggsigCore.keyValidate(publicKey); }

    public static byte[] sign(byte[] secretKey, byte[] msg) { return AggsigCore.sign(secretKey, msg); }

    /** CoreVerify of one signature. Never throws. */
    public static boolean verify(byte[] publicKey, byte[] msg, byte[] sig) { return AggsigCore.verify(publicKey, msg, sig); }

    /** Sum the G2 signature points into one 96-byte aggregate; throws on an empty list or a non-canonical signature. */
    public static byte[] aggregate(List<byte[]> sigs) { return AggsigCore.aggregate(sigs); }

    /** Sign one's OWN public key under the PoP DST. */
    public static byte[] popProve(byte[] secretKey) { return AggsigCore.popProve(secretKey); }

    /** Admit a public key: KeyValidate plus a valid proof of possession. The only way to obtain a RegisteredKey. Never throws. */
    public static RegisterResult registerKey(byte[] publicKey, byte[] pop) {
        if (publicKey == null || pop == null) return RegisterResult.fail("public key and proof of possession must be Uint8Arrays");
        if (!AggsigCore.keyValidate(publicKey)) return RegisterResult.fail("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)");
        if (pop.length != AggsigCore.SIGNATURE_LENGTH) return RegisterResult.fail("proof of possession is not a 96-byte compressed G2 signature");
        if (!AggsigCore.popVerify(publicKey, pop)) return RegisterResult.fail("proof of possession does not verify for this key");
        return RegisterResult.ok(new RegisteredKey(publicKey));
    }

    /** Why the keys cannot be used for aggregate verification, or null when every element is a genuine RegisteredKey. */
    public static String checkRegistered(List<RegisteredKey> keys) {
        if (keys == null) return "keys must be an array of RegisteredKey";
        if (keys.isEmpty()) return "no keys";
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i) == null) return "key " + i + " is not a registered key: it was not admitted through registerKey (proof of possession)";
        }
        return null;
    }

    private static List<byte[]> rawOf(List<RegisteredKey> keys) {
        List<byte[]> out = new ArrayList<>();
        for (RegisteredKey k : keys) out.add(k.bytes());
        return out;
    }

    /** AggregateVerify over distinct messages, registered keys only. Never throws. */
    public static boolean aggregateVerify(List<RegisteredKey> keys, List<byte[]> msgs, byte[] aggSig) {
        if (checkRegistered(keys) != null) return false;
        return AggsigCore.aggregateVerify(rawOf(keys), msgs, aggSig);
    }

    /** FastAggregateVerify: one message, registered keys only; one signer may not be counted twice. Never throws. */
    public static boolean fastAggregateVerify(List<RegisteredKey> keys, byte[] msg, byte[] aggSig) {
        if (checkRegistered(keys) != null) return false;
        Set<String> seen = new HashSet<>();
        for (RegisteredKey k : keys) if (!seen.add(hex(k.bytes()))) return false;
        return AggsigCore.fastAggregateVerify(rawOf(keys), msg, aggSig);
    }
}
