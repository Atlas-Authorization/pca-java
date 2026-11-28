package net.atlasauth.pca.aggsig;

import net.atlasauth.pca.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.atlasauth.pca.pairing.Bls12;
import supranational.blst.BLST_ERROR;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.Pairing;

/**
 * BLS signatures on BLS12-381, aggregation-ready (draft-irtf-cfrg-bls-signature, proof-of-possession ciphersuite,
 * minimal-pubkey-size: 48-byte G1 public keys, 96-byte G2 signatures). Every curve operation is blst's (via jblst); nothing
 * here implements a pairing or a field. INTERNAL: the raw aggregate verifiers take unvetted public keys and are only
 * sound after a proof-of-possession check; the public surface is {@link Aggsig}, which takes only {@link RegisteredKey}s.
 * Verification is total: any malformed input is a {@code false}, never an exception.
 */
final class AggsigCore {
    private AggsigCore() {}

    static final String SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    static final String POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    static final int PUBLIC_KEY_LENGTH = 48;
    static final int SIGNATURE_LENGTH = 96;
    /** The prime order r of the BLS12-381 groups. */
    static final BigInteger R = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /** blst failures surface as runtime exceptions; a missing native library must not be mistaken for a bad input. */
    static void fatal(Throwable t) {
        if (t instanceof LinkageError || t instanceof VirtualMachineError) {
            if (t instanceof Error) throw (Error) t;
        }
    }

    static boolean isCompressed(byte[] b, int len) { return b != null && b.length == len && (b[0] & 0x80) != 0; }

    /** A 96-byte compressed G2 point that is exactly the re-encoding of the point it decodes to (no second encoding per signature). */
    static boolean isCanonicalSignature(byte[] sig) {
        if (!isCompressed(sig, SIGNATURE_LENGTH)) return false;
        try {
            P2_Affine p = new P2_Affine(sig);
            return Arrays.equals(p.compress(), sig) && p.in_group(); // the reference's point parse also rejects an off-subgroup point
        } catch (Throwable t) {
            fatal(t);
            return false;
        }
    }

    /** KeyValidate (draft 2.5): canonical compressed G1 point, not the identity, in the prime-order subgroup. */
    static boolean keyValidate(byte[] pk) {
        if (!isCompressed(pk, PUBLIC_KEY_LENGTH)) return false;
        try {
            P1_Affine p = new P1_Affine(pk);
            if (p.is_inf() || !p.on_curve() || !Arrays.equals(p.compress(), pk)) return false;
            return p.in_group();
        } catch (Throwable t) {
            fatal(t);
            return false;
        }
    }

    static BigInteger scalar(byte[] sk) {
        if (sk == null || sk.length != 32) throw new IllegalArgumentException("secret key must be 32 bytes");
        BigInteger s = new BigInteger(1, sk);
        if (s.signum() == 0 || s.compareTo(R) >= 0) throw new IllegalArgumentException("secret key must be a scalar in [1, r-1]");
        return s;
    }

    static byte[] publicKeyOf(byte[] sk) { return Bls12.mul(P1.generator(), scalar(sk)).compress(); }

    /** A fresh key pair; refuses the degenerate key 1 (a stuck entropy source). */
    static Aggsig.KeyPair keyGen(SecureRandom rng) {
        byte[] wide = new byte[64];
        rng.nextBytes(wide);
        BigInteger s = new BigInteger(1, wide).mod(R.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        if (s.equals(BigInteger.ONE)) throw new IllegalStateException("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue");
        byte[] sk = new byte[32];
        byte[] be = s.toByteArray();
        System.arraycopy(be, Math.max(0, be.length - 32), sk, 32 - Math.min(32, be.length), Math.min(32, be.length));
        return new Aggsig.KeyPair(sk, publicKeyOf(sk));
    }

    static byte[] signWith(String dst, byte[] sk, byte[] msg) {
        BigInteger s = scalar(sk);
        if (msg == null) throw new IllegalArgumentException("msg is required");
        return Bls12.mul(new P2().hash_to(msg, dst), s).compress();
    }

    static byte[] sign(byte[] sk, byte[] msg) { return signWith(SIG_DST, sk, msg); }

    static boolean verifyWith(String dst, byte[] pk, byte[] msg, byte[] sig) {
        try {
            if (!isCanonicalSignature(sig)) return false;
            if (!keyValidate(pk)) return false;
            if (msg == null) return false;
            return new P2_Affine(sig).core_verify(new P1_Affine(pk), true, msg, dst) == BLST_ERROR.BLST_SUCCESS;
        } catch (Throwable t) {
            fatal(t);
            return false;
        }
    }

    static boolean verify(byte[] pk, byte[] msg, byte[] sig) { return verifyWith(SIG_DST, pk, msg, sig); }

    static byte[] aggregate(List<byte[]> sigs) {
        if (sigs.isEmpty()) throw new IllegalArgumentException("aggregate: need at least one signature");
        for (byte[] s : sigs) if (!isCanonicalSignature(s)) throw new IllegalArgumentException("aggregate: every signature must be a 96-byte compressed G2 point");
        P2 sum = new P2();
        for (byte[] s : sigs) sum.add(new P2_Affine(s));
        return sum.compress();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    private static boolean distinct(List<byte[]> msgs) {
        Set<String> seen = new HashSet<>();
        for (byte[] m : msgs) if (!seen.add(hex(m))) return false;
        return true;
    }

    /** AggregateVerify (draft 3.1.1) over pairwise-distinct messages: one pairing-product check. */
    static boolean aggregateVerify(List<byte[]> pks, List<byte[]> msgs, byte[] aggSig) {
        try {
            if (!isCanonicalSignature(aggSig)) return false;
            if (pks.isEmpty() || pks.size() != msgs.size()) return false;
            if (!distinct(msgs)) return false;
            for (byte[] pk : pks) if (!keyValidate(pk)) return false;
            Pairing ctx = new Pairing(true, SIG_DST);
            P2_Affine sig = new P2_Affine(aggSig);
            for (int i = 0; i < pks.size(); i++) {
                BLST_ERROR e = ctx.aggregate(new P1_Affine(pks.get(i)), i == 0 ? sig : null, msgs.get(i));
                if (e != BLST_ERROR.BLST_SUCCESS) return false;
            }
            ctx.commit();
            return ctx.finalverify();
        } catch (Throwable t) {
            fatal(t);
            return false;
        }
    }

    /** FastAggregateVerify (draft 3.3.4): one message, many signers; the aggregate key is KeyValidate'd too ({P,-P} sums to the identity). */
    static boolean fastAggregateVerify(List<byte[]> pks, byte[] msg, byte[] aggSig) {
        try {
            if (!isCanonicalSignature(aggSig)) return false;
            if (pks.isEmpty() || msg == null) return false;
            P1 agg = new P1();
            for (byte[] pk : pks) {
                if (!keyValidate(pk)) return false;
                agg.add(new P1_Affine(pk));
            }
            if (agg.is_inf()) return false;
            byte[] aggPk = agg.compress();
            if (!keyValidate(aggPk)) return false;
            return new P2_Affine(aggSig).core_verify(new P1_Affine(aggPk), true, msg, SIG_DST) == BLST_ERROR.BLST_SUCCESS;
        } catch (Throwable t) {
            fatal(t);
            return false;
        }
    }

    static byte[] popProve(byte[] sk) { return signWith(POP_DST, sk, publicKeyOf(sk)); }

    static boolean popVerify(byte[] pk, byte[] pop) { return verifyWith(POP_DST, pk, pk, pop); }

    static byte[] utf8(String s) { return Json.utf8(s); }
}
