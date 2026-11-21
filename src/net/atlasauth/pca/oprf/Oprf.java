package net.atlasauth.pca.oprf;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.atlasauth.pca.ratchet.RistrettoElement;

/**
 * RFC 9497 Oblivious Pseudorandom Functions on the {@code ristretto255-SHA512} ciphersuite (OPRF 0x00, VOPRF 0x01, POPRF 0x02).
 * The group is the shared ristretto255 implementation (RFC 9496) the ratchet package already carries; BouncyCastle has no
 * ristretto255 and no RFC 9380 expand_message_xmd, so the XMD expander is written here from RFC 9380 section 5.3.1 and checked
 * against the RFC 9497 Appendix A.1 vectors. Only this ciphersuite exists in the reference (no P-256 / P-384 / P-521 / decaf448).
 */
public final class Oprf {
    private Oprf() {}

    public static final int ELEMENT_BYTES = 32, SCALAR_BYTES = 32, OUTPUT_BYTES = 64;
    public static final String SUITE_ID = "ristretto255-SHA512";
    private static final BigInteger ORDER = RistrettoElement.ORDER;
    private static final int MAX_FRAMED_BYTES = 0xffff;
    private static final SecureRandom RNG = new SecureRandom();

    /** The mode byte folded into every domain-separation tag. */
    static int modeByte(String mode) {
        if ("oprf".equals(mode)) return 0x00;
        if ("voprf".equals(mode)) return 0x01;
        if ("poprf".equals(mode)) return 0x02;
        throw new IllegalArgumentException("unknown OPRF mode: " + mode);
    }

    // ---- byte helpers -----------------------------------------------------------------------------------------------

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }

    private static byte[] sha512(byte[] m) {
        try { return MessageDigest.getInstance("SHA-512").digest(m); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** I2OSP: non-negative integer to a fixed-length big-endian byte string; refuses a value that does not fit. */
    static byte[] i2osp(long n, int len) {
        if (n < 0 || (len < 8 && n >= (1L << (8 * len)))) throw new IllegalArgumentException("I2OSP: value does not fit in " + len + " bytes");
        byte[] out = new byte[len];
        for (int i = len - 1; i >= 0; i--) { out[i] = (byte) n; n >>>= 8; }
        return out;
    }

    private static byte[] lenPrefixed2(byte[] b) { return cat(i2osp(b.length, 2), b); }

    private static void assertBytes(byte[] v, String what, int maxLen) {
        if (v == null) throw new IllegalArgumentException(what + ": expected a byte array");
        if (v.length > maxLen) throw new IllegalArgumentException(what + ": " + v.length + " bytes exceeds the " + maxLen + "-byte limit (RFC 9497 2-byte length framing)");
    }

    private static byte[] contextString(String mode) { return cat(utf8("OPRFV1-"), i2osp(modeByte(mode), 1), utf8("-" + SUITE_ID)); }

    private static byte[] littleEndian(BigInteger n, int len) {
        byte[] out = new byte[len];
        byte[] be = n.toByteArray();
        for (int i = 0; i < len && i < be.length; i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    private static BigInteger fromLittleEndian(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[le.length - 1 - i] = le[i];
        return new BigInteger(1, be);
    }

    // ---- element / scalar encodings ----------------------------------------------------------------------------------

    public static byte[] serializeElement(RistrettoElement p) { return p.toRawBytes(); }

    /** Canonical 32-byte ristretto255 decoding; rejects the identity element and every non-canonical encoding. */
    public static RistrettoElement deserializeElement(byte[] bytes) {
        assertBytes(bytes, "DeserializeElement", Integer.MAX_VALUE);
        RistrettoElement p = RistrettoElement.fromBytes(bytes);
        if (p.isIdentity()) throw new IllegalArgumentException("DeserializeElement: identity element is not a valid input");
        return p;
    }

    public static byte[] serializeScalar(BigInteger s) { return littleEndian(s.mod(ORDER), SCALAR_BYTES); }

    /** 32-byte little-endian scalar; rejects any value >= the group order (one valid encoding per scalar). */
    public static BigInteger deserializeScalar(byte[] bytes) {
        assertBytes(bytes, "DeserializeScalar", Integer.MAX_VALUE);
        if (bytes.length != SCALAR_BYTES) throw new IllegalArgumentException("DeserializeScalar: expected " + SCALAR_BYTES + " bytes, got " + bytes.length);
        BigInteger n = fromLittleEndian(bytes);
        if (n.compareTo(ORDER) >= 0) throw new IllegalArgumentException("DeserializeScalar: non-canonical scalar (value >= group order)");
        return n;
    }

    // ---- hashing to the group / scalar field -------------------------------------------------------------------------

    /** RFC 9380 section 5.3.1 expand_message_xmd with SHA-512 (block size 128, output 64). */
    static byte[] expandMessageXmd(byte[] msg, byte[] dst, int lenInBytes) {
        final int bInBytes = 64, sInBytes = 128;
        int ell = (lenInBytes + bInBytes - 1) / bInBytes;
        if (ell > 255 || lenInBytes > 65535 || dst.length > 255) throw new IllegalArgumentException("expand_message_xmd: parameters out of range");
        byte[] dstPrime = cat(dst, i2osp(dst.length, 1));
        byte[] b0 = sha512(cat(new byte[sInBytes], msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstPrime));
        byte[] bi = sha512(cat(b0, i2osp(1, 1), dstPrime));
        ByteArrayOutputStream uniform = new ByteArrayOutputStream();
        uniform.writeBytes(bi);
        for (int i = 2; i <= ell; i++) {
            byte[] x = new byte[bInBytes];
            for (int j = 0; j < bInBytes; j++) x[j] = (byte) (b0[j] ^ bi[j]);
            bi = sha512(cat(x, i2osp(i, 1), dstPrime));
            uniform.writeBytes(bi);
        }
        byte[] all = uniform.toByteArray();
        byte[] out = new byte[lenInBytes];
        System.arraycopy(all, 0, out, 0, lenInBytes);
        return out;
    }

    /** {@code HashToGroup(input)} with the mode's DST. */
    public static RistrettoElement hashToGroup(byte[] input, String mode) {
        byte[] dst = cat(utf8("HashToGroup-"), contextString(mode));
        return RistrettoElement.fromUniformBytes(expandMessageXmd(input, dst, 64));
    }

    private static BigInteger hashToScalarWithDst(byte[] input, byte[] dst) { return fromLittleEndian(expandMessageXmd(input, dst, 64)).mod(ORDER); }

    private static BigInteger hashToScalar(byte[] input, String mode) { return hashToScalarWithDst(input, cat(utf8("HashToScalar-"), contextString(mode))); }

    private static RistrettoElement scalarBaseMult(BigInteger k) { return RistrettoElement.BASE.multiply(k.mod(ORDER)); }

    /** A uniformly random non-zero scalar; fails closed if the entropy source keeps returning zero. */
    public static BigInteger randomScalar() {
        for (int attempt = 0; attempt < 8; attempt++) {
            byte[] b = new byte[64];
            RNG.nextBytes(b);
            BigInteger s = fromLittleEndian(b).mod(ORDER);
            if (s.signum() != 0) return s;
        }
        throw new IllegalStateException("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue");
    }

    private static BigInteger scalarInvert(BigInteger s) {
        return RistrettoElement.scalarInvert(s);
    }

    // ---- keys -------------------------------------------------------------------------------------------------------

    /** A server key pair, both halves serialized. */
    public static final class KeyPair {
        public final byte[] secretKey, publicKey;
        KeyPair(byte[] sk, byte[] pk) { this.secretKey = sk; this.publicKey = pk; }
    }

    /** {@code DeriveKeyPair(seed, info)} (RFC 9497 section 3.2): the seed is exactly 32 bytes. */
    public static KeyPair deriveKeyPair(byte[] seed, byte[] info, String mode) {
        if (seed == null || seed.length != SCALAR_BYTES) throw new IllegalArgumentException("DeriveKeyPair: seed must be exactly " + SCALAR_BYTES + " bytes");
        assertBytes(info, "DeriveKeyPair(info)", MAX_FRAMED_BYTES);
        byte[] dst = cat(utf8("DeriveKeyPair"), contextString(mode));
        byte[] deriveInput = cat(seed, i2osp(info.length, 2), info);
        for (int counter = 0; counter <= 255; counter++) {
            BigInteger skS = hashToScalarWithDst(cat(deriveInput, i2osp(counter, 1)), dst);
            if (skS.signum() != 0) return new KeyPair(serializeScalar(skS), serializeElement(scalarBaseMult(skS)));
        }
        throw new IllegalStateException("DeriveKeyPair: failed to derive a non-zero key after 256 attempts");
    }

    public static KeyPair randomKeyPair() {
        BigInteger skS = randomScalar();
        return new KeyPair(serializeScalar(skS), serializeElement(scalarBaseMult(skS)));
    }

    public static byte[] publicKeyFor(byte[] secretKey) { return serializeElement(scalarBaseMult(deserializeScalar(secretKey))); }

    // ---- DLEQ proof (RFC 9497 section 2.2) --------------------------------------------------------------------------

    private static byte[] compositesSeed(byte[] bSer, String mode) {
        byte[] seedDst = cat(utf8("Seed-"), contextString(mode));
        return sha512(cat(i2osp(bSer.length, 2), bSer, i2osp(seedDst.length, 2), seedDst));
    }

    private static BigInteger compositeCoefficient(byte[] seed, int index, byte[] cSer, byte[] dSer, String mode) {
        return hashToScalar(cat(i2osp(seed.length, 2), seed, i2osp(index, 2), i2osp(cSer.length, 2), cSer, i2osp(dSer.length, 2), dSer, utf8("Composite")), mode);
    }

    /** Single-element {@code ComputeComposites}: returns {M, Z}; when {@code k} is non-null this is the prover path (Z = k * M). */
    private static RistrettoElement[] composites(BigInteger k, RistrettoElement b, RistrettoElement c, RistrettoElement d, String mode) {
        byte[] seed = compositesSeed(serializeElement(b), mode);
        BigInteger coeff = compositeCoefficient(seed, 0, serializeElement(c), serializeElement(d), mode);
        RistrettoElement m = c.multiplyPublic(coeff).add(RistrettoElement.ZERO);
        RistrettoElement z = k != null ? m.multiply(k.mod(ORDER)) : d.multiplyPublic(coeff).add(RistrettoElement.ZERO);
        return new RistrettoElement[] {m, z};
    }

    private static BigInteger challenge(RistrettoElement b, RistrettoElement m, RistrettoElement z, RistrettoElement t2, RistrettoElement t3, String mode) {
        byte[] transcript = cat(lenPrefixed2(serializeElement(b)), lenPrefixed2(serializeElement(m)), lenPrefixed2(serializeElement(z)),
            lenPrefixed2(serializeElement(t2)), lenPrefixed2(serializeElement(t3)), utf8("Challenge"));
        return hashToScalar(transcript, mode);
    }

    private static byte[] generateProof(BigInteger k, RistrettoElement a, RistrettoElement b, RistrettoElement c, RistrettoElement d, String mode, byte[] fixedRandomness) {
        RistrettoElement[] mz = composites(k, b, c, d, mode);
        BigInteger r = fixedRandomness == null ? randomScalar() : deserializeScalar(fixedRandomness);
        RistrettoElement t2 = a.multiply(r);
        RistrettoElement t3 = mz[0].multiply(r);
        BigInteger cc = challenge(b, mz[0], mz[1], t2, t3, mode);
        BigInteger s = r.subtract(cc.multiply(k)).mod(ORDER);
        return cat(serializeScalar(cc), serializeScalar(s));
    }

    private static boolean verifyProof(RistrettoElement a, RistrettoElement b, RistrettoElement c, RistrettoElement d, byte[] proof, String mode) {
        if (proof.length != 2 * SCALAR_BYTES) return false;
        BigInteger cc = deserializeScalar(java.util.Arrays.copyOfRange(proof, 0, SCALAR_BYTES));
        BigInteger s = deserializeScalar(java.util.Arrays.copyOfRange(proof, SCALAR_BYTES, 2 * SCALAR_BYTES));
        RistrettoElement[] mz = composites(null, b, c, d, mode);
        RistrettoElement t2 = a.multiplyPublic(s).add(b.multiplyPublic(cc));
        RistrettoElement t3 = mz[0].multiplyPublic(s).add(mz[1].multiplyPublic(cc));
        BigInteger expected = challenge(b, mz[0], mz[1], t2, t3, mode);
        return expected.subtract(cc).mod(ORDER).signum() == 0;
    }

    // ---- finalize hashes ---------------------------------------------------------------------------------------------

    private static byte[] finalizeHash(byte[] input, byte[] issued) {
        return sha512(cat(i2osp(input.length, 2), input, i2osp(issued.length, 2), issued, utf8("Finalize")));
    }

    private static byte[] finalizeHashPoprf(byte[] input, byte[] info, byte[] issued) {
        return sha512(cat(i2osp(input.length, 2), input, i2osp(info.length, 2), info, i2osp(issued.length, 2), issued, utf8("Finalize")));
    }

    // ---- OPRF + VOPRF ------------------------------------------------------------------------------------------------

    /** The client's retained blind plus the element to send. */
    public static class BlindResult {
        public final byte[] blind, blindedElement;
        BlindResult(byte[] blind, byte[] blindedElement) { this.blind = blind; this.blindedElement = blindedElement; }
    }

    /** A server blind-evaluation; {@code proof} is null for plain OPRF. */
    public static final class EvaluateResult {
        public final byte[] evaluatedElement, proof;
        public EvaluateResult(byte[] evaluatedElement, byte[] proof) { this.evaluatedElement = evaluatedElement; this.proof = proof; }
    }

    /** {@code Blind(input)}; {@code fixedBlind} (null normally) pins the blind for test vectors. */
    public static BlindResult blind(byte[] input, String mode, byte[] fixedBlind) {
        assertBytes(input, "Blind(input)", MAX_FRAMED_BYTES);
        BigInteger r = fixedBlind == null ? randomScalar() : deserializeScalar(fixedBlind);
        RistrettoElement inputElement = hashToGroup(input, mode);
        if (inputElement.isIdentity()) throw new IllegalStateException("Blind: input maps to identity");
        return new BlindResult(serializeScalar(r), serializeElement(inputElement.multiply(r)));
    }

    public static BlindResult blind(byte[] input, String mode) { return blind(input, mode, null); }

    /**
     * Server {@code BlindEvaluate} for mode "oprf" or "voprf" (anything else is refused). For VOPRF a DLEQ proof against
     * {@code publicKey} (derived from the secret key when null) is attached; {@code fixedProofRandomness} is for test vectors only.
     */
    public static EvaluateResult blindEvaluate(byte[] secretKey, byte[] blindedElement, String mode, byte[] publicKey, byte[] fixedProofRandomness) {
        if (!"oprf".equals(mode) && !"voprf".equals(mode)) throw new IllegalArgumentException("blindEvaluate: mode must be oprf or voprf");
        BigInteger skS = deserializeScalar(secretKey);
        RistrettoElement r = deserializeElement(blindedElement);
        RistrettoElement evaluated = r.multiply(skS);
        if ("oprf".equals(mode)) return new EvaluateResult(serializeElement(evaluated), null);
        RistrettoElement pk = publicKey == null ? scalarBaseMult(skS) : deserializeElement(publicKey);
        byte[] proof = generateProof(skS, RistrettoElement.BASE, pk, r, evaluated, "voprf", fixedProofRandomness);
        return new EvaluateResult(serializeElement(evaluated), proof);
    }

    public static EvaluateResult blindEvaluate(byte[] secretKey, byte[] blindedElement, String mode) { return blindEvaluate(secretKey, blindedElement, mode, null, null); }

    /**
     * Client {@code Finalize} for "oprf" / "voprf". For VOPRF the DLEQ proof is verified first (proof, publicKey and blindedElement are
     * required) and a bad proof throws.
     */
    public static byte[] finalizeOprf(byte[] input, byte[] blindScalar, byte[] evaluatedElement, String mode, byte[] proof, byte[] publicKey, byte[] blindedElement) {
        if (!"oprf".equals(mode) && !"voprf".equals(mode)) throw new IllegalArgumentException("finalize: mode must be oprf or voprf");
        assertBytes(input, "Finalize(input)", MAX_FRAMED_BYTES);
        BigInteger r = deserializeScalar(blindScalar);
        RistrettoElement evaluated = deserializeElement(evaluatedElement);
        if ("voprf".equals(mode)) {
            if (proof == null || publicKey == null || blindedElement == null) throw new IllegalArgumentException("Finalize(voprf): proof, publicKey and blindedElement are required");
            RistrettoElement pk = deserializeElement(publicKey);
            RistrettoElement blinded = deserializeElement(blindedElement);
            if (!verifyProof(RistrettoElement.BASE, pk, blinded, evaluated, proof, "voprf")) throw new SecurityException("Finalize(voprf): DLEQ proof verification failed");
        }
        return finalizeHash(input, serializeElement(evaluated.multiply(scalarInvert(r))));
    }

    /** The server's non-blinded reference output for "oprf" / "voprf". */
    public static byte[] evaluate(byte[] secretKey, byte[] input, String mode) {
        if (!"oprf".equals(mode) && !"voprf".equals(mode)) throw new IllegalArgumentException("evaluate: mode must be oprf or voprf");
        assertBytes(input, "Evaluate(input)", MAX_FRAMED_BYTES);
        BigInteger skS = deserializeScalar(secretKey);
        RistrettoElement inputElement = hashToGroup(input, mode);
        if (inputElement.isIdentity()) throw new IllegalStateException("Evaluate: input maps to identity");
        return finalizeHash(input, serializeElement(inputElement.multiply(skS)));
    }

    // ---- POPRF -------------------------------------------------------------------------------------------------------

    private static BigInteger poprfInfoScalar(byte[] info) {
        assertBytes(info, "info", MAX_FRAMED_BYTES);
        return hashToScalar(cat(utf8("Info"), i2osp(info.length, 2), info), "poprf");
    }

    /** The POPRF client state: blind, blinded element and the tweaked key (m*G + pkS) it must verify against. */
    public static final class PoprfBlindResult extends BlindResult {
        public final byte[] tweakedKey;
        PoprfBlindResult(BlindResult b, byte[] tweakedKey) { super(b.blind, b.blindedElement); this.tweakedKey = tweakedKey; }
    }

    public static PoprfBlindResult blindPoprf(byte[] input, byte[] info, byte[] publicKey, byte[] fixedBlind) {
        assertBytes(input, "Blind(input)", MAX_FRAMED_BYTES);
        BigInteger m = poprfInfoScalar(info);
        RistrettoElement tweaked = scalarBaseMult(m).add(deserializeElement(publicKey));
        if (tweaked.isIdentity()) throw new IllegalStateException("Blind(poprf): tweaked key is identity");
        BlindResult base = blind(input, "poprf", fixedBlind);
        return new PoprfBlindResult(base, serializeElement(tweaked));
    }

    public static EvaluateResult blindEvaluatePoprf(byte[] secretKey, byte[] blindedElement, byte[] info, byte[] fixedProofRandomness) {
        BigInteger skS = deserializeScalar(secretKey);
        BigInteger m = poprfInfoScalar(info);
        BigInteger t = skS.add(m).mod(ORDER);
        if (t.signum() == 0) throw new IllegalStateException("BlindEvaluate(poprf): inverse of zero (bad info/key)");
        RistrettoElement blinded = deserializeElement(blindedElement);
        RistrettoElement evaluated = blinded.multiply(scalarInvert(t));
        RistrettoElement tweakedKey = scalarBaseMult(t);
        byte[] proof = generateProof(t, RistrettoElement.BASE, tweakedKey, evaluated, blinded, "poprf", fixedProofRandomness);
        return new EvaluateResult(serializeElement(evaluated), proof);
    }

    public static byte[] finalizePoprf(byte[] input, byte[] blindScalar, byte[] evaluatedElement, byte[] info, byte[] proof, byte[] blindedElement, byte[] tweakedKey) {
        assertBytes(input, "Finalize(input)", MAX_FRAMED_BYTES);
        assertBytes(info, "info", MAX_FRAMED_BYTES);
        BigInteger r = deserializeScalar(blindScalar);
        RistrettoElement evaluated = deserializeElement(evaluatedElement);
        RistrettoElement blinded = deserializeElement(blindedElement);
        RistrettoElement tweaked = deserializeElement(tweakedKey);
        if (proof == null || !verifyProof(RistrettoElement.BASE, tweaked, evaluated, blinded, proof, "poprf")) throw new SecurityException("Finalize(poprf): DLEQ proof verification failed");
        return finalizeHashPoprf(input, info, serializeElement(evaluated.multiply(scalarInvert(r))));
    }

    public static byte[] evaluatePoprf(byte[] secretKey, byte[] input, byte[] info) {
        assertBytes(input, "Evaluate(input)", MAX_FRAMED_BYTES);
        BigInteger skS = deserializeScalar(secretKey);
        BigInteger m = poprfInfoScalar(info);
        BigInteger t = skS.add(m).mod(ORDER);
        if (t.signum() == 0) throw new IllegalStateException("Evaluate(poprf): inverse of zero (bad info/key)");
        RistrettoElement inputElement = hashToGroup(input, "poprf");
        if (inputElement.isIdentity()) throw new IllegalStateException("Evaluate(poprf): input maps to identity");
        return finalizeHashPoprf(input, info, serializeElement(inputElement.multiply(scalarInvert(t))));
    }

    // ---- utilities -----------------------------------------------------------------------------------------------------

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) { sb.append(Character.forDigit((b >> 4) & 15, 16)).append(Character.forDigit(b & 15, 16)); }
        return sb.toString();
    }

    /** Length check first, then a full-width constant-time compare. */
    public static boolean bytesEqual(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }
}
