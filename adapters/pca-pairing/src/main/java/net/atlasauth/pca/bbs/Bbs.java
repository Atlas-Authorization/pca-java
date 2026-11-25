package net.atlasauth.pca.bbs;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.pairing.Bls12;
import supranational.blst.P1;
import supranational.blst.P2;

/**
 * BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
 * draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings; validated against the draft's official fixtures).
 * Signatures and generators live in G1 (48 bytes compressed), public keys in G2 (96 bytes), scalars are 32 bytes big-endian.
 * All curve work is blst's (via jblst); scalar-field arithmetic is BigInteger (see {@link Bls12}).
 */
public final class Bbs {
    private Bbs() {}

    /** Implementation limit on the number of messages in one credential (a verifier derives the count from attacker-supplied lengths). */
    public static final int MAX_MESSAGES = 1024;
    public static final BigInteger R = Bls12.R;
    public static final String CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    public static final String API_ID = CIPHERSUITE_ID + "H2G_HM2S_";

    private static final int SCALAR_LEN = 32;
    private static final int POINT_LEN = 48;
    private static final int EXPAND_LEN = 48;
    private static final String H2S_DST = API_ID + "H2S_";
    private static final String MAP_DST = API_ID + "MAP_MSG_TO_SCALAR_AS_HASH_";
    private static final String SEED_DST = API_ID + "SIG_GENERATOR_SEED_";
    private static final String GEN_DST = API_ID + "SIG_GENERATOR_DST_";
    private static final String GEN_SEED = API_ID + "MESSAGE_GENERATOR_SEED";
    private static final String KEYGEN_DST = API_ID + "KEYGEN_DST_";
    /** P1: the fixed G1 generator of the ciphersuite (draft 7.2.2). */
    private static final String P1_HEX = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

    private static final P1 P1_GEN = Bls12.decodeG1(hex(P1_HEX));
    private static final P2 BP2 = P2.generator();

    // ---- helpers ----

    static byte[] hex(String s) { return java.util.HexFormat.of().parseHex(s); }

    private static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }

    private static byte[] i2osp(BigInteger n, int len) { return Bls12.i2osp(n, len); }

    private static byte[] i2osp(long n, int len) { return Bls12.i2osp(BigInteger.valueOf(n), len); }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    private static byte[] expand(byte[] msg, String dst, int len) { return Bls12.expandMessageXmd(msg, ascii(dst), len); }

    /** hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2). */
    public static BigInteger hashToScalar(byte[] msg, String dst) { return Bls12.mod(Bls12.os2ip(expand(msg, dst, EXPAND_LEN))); }

    /** MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2). */
    public static BigInteger mapMessageToScalarAsHash(byte[] message) { return hashToScalar(message, MAP_DST); }

    public static List<BigInteger> messagesToScalars(List<byte[]> messages) {
        List<BigInteger> out = new ArrayList<>();
        for (byte[] m : messages) out.add(mapMessageToScalarAsHash(m));
        return out;
    }

    private static List<P1> gens(int count) {
        if (count < 0) throw new IllegalArgumentException("bbs: generator count must be a non-negative integer");
        if (count > MAX_MESSAGES + 1) throw new IllegalArgumentException("bbs: at most " + MAX_MESSAGES + " messages are supported");
        List<P1> out = new ArrayList<>();
        byte[] v = expand(ascii(GEN_SEED), SEED_DST, EXPAND_LEN);
        for (int i = 1; i <= count; i++) {
            v = expand(concat(v, i2osp(i, 8)), SEED_DST, EXPAND_LEN);
            out.add(new P1().hash_to(v, GEN_DST));
        }
        return out;
    }

    /** create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1). */
    public static List<byte[]> createGenerators(int count) {
        List<byte[]> out = new ArrayList<>();
        for (P1 g : gens(count)) out.add(g.compress());
        return out;
    }

    // ---- key generation ----

    /** KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0. */
    public static BigInteger keyGen(byte[] keyMaterial, byte[] keyInfo) {
        if (keyMaterial.length < 32) throw new IllegalArgumentException("bbs: key material must be at least 32 octets");
        if (keyInfo.length > 65535) throw new IllegalArgumentException("bbs: key info must be at most 65535 octets");
        BigInteger sk = hashToScalar(concat(keyMaterial, i2osp(keyInfo.length, 2), keyInfo), KEYGEN_DST);
        if (sk.signum() == 0) throw new IllegalStateException("bbs: derived SK is zero (retry with different key material)");
        return sk;
    }

    public static BigInteger keyGen(byte[] keyMaterial) { return keyGen(keyMaterial, new byte[0]); }

    /** SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2). */
    public static byte[] skToPk(BigInteger sk) { return Bls12.mul(BP2, sk).compress(); }

    /** A fresh (SK, PK) pair from the system CSPRNG; refuses an all-zero entropy source. */
    public static KeyPair generateKeyPair() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        boolean zero = true;
        for (byte b : ikm) if (b != 0) zero = false;
        if (zero) throw new IllegalStateException("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key");
        BigInteger sk = keyGen(ikm);
        return new KeyPair(sk, skToPk(sk));
    }

    public record KeyPair(BigInteger sk, byte[] pk) {}

    public static byte[] skToBytes(BigInteger sk) { return i2osp(sk, SCALAR_LEN); }

    public static BigInteger skFromBytes(byte[] bytes) {
        if (bytes.length != SCALAR_LEN) throw new IllegalArgumentException("bbs: SK must be 32 octets");
        BigInteger sk = Bls12.os2ip(bytes);
        if (sk.signum() == 0 || sk.compareTo(R) >= 0) throw new IllegalArgumentException("bbs: SK out of range");
        return sk;
    }

    // ---- serialization (draft 4.2.4) ----

    /** serialize(): points compressed, scalars 32 octets, integers 8 octets. Elements are P1, P2, BigInteger (scalar) or Integer (count/index). */
    private static byte[] serialize(List<Object> els) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (Object el : els) {
            byte[] b;
            if (el instanceof P1) b = ((P1) el).compress();
            else if (el instanceof P2) b = ((P2) el).compress();
            else if (el instanceof BigInteger) b = i2osp((BigInteger) el, SCALAR_LEN);
            else b = i2osp(((Integer) el).longValue(), 8);
            o.write(b, 0, b.length);
        }
        return o.toByteArray();
    }

    // ---- signature octets ----

    private record ParsedSignature(P1 a, BigInteger e) {}

    private static byte[] signatureToOctets(P1 a, BigInteger e) { return concat(a.compress(), i2osp(e, SCALAR_LEN)); }

    private static ParsedSignature octetsToSignature(byte[] sig) {
        if (sig.length != POINT_LEN + SCALAR_LEN) throw new IllegalArgumentException("bbs: signature must be 80 octets");
        P1 a = Bls12.decodeG1(java.util.Arrays.copyOfRange(sig, 0, POINT_LEN));
        if (a.is_inf()) throw new IllegalArgumentException("bbs: signature point A is the identity");
        BigInteger e = Bls12.os2ip(java.util.Arrays.copyOfRange(sig, POINT_LEN, sig.length));
        if (e.signum() <= 0 || e.compareTo(R) >= 0) throw new IllegalArgumentException("bbs: signature scalar e out of range");
        return new ParsedSignature(a, e);
    }

    // ---- domain (draft 4.2.3) ----

    private static BigInteger calculateDomain(byte[] pk, P1 q1, List<P1> h, byte[] header) {
        List<Object> els = new ArrayList<>();
        els.add(h.size());
        els.add(q1);
        els.addAll(h);
        byte[] domOcts = concat(serialize(els), ascii(API_ID));
        byte[] domInput = concat(pk, domOcts, i2osp(header.length, 8), header);
        return hashToScalar(domInput, H2S_DST);
    }

    /** B = P1 + Q_1*domain + sum H_i*msg_i. */
    private static P1 computeB(P1 q1, List<P1> h, BigInteger domain, List<BigInteger> msgScalars) {
        P1 b = Bls12.add(P1_GEN, Bls12.mul(q1, domain));
        for (int i = 0; i < msgScalars.size(); i++) b = Bls12.add(b, Bls12.mul(h.get(i), msgScalars.get(i)));
        return b;
    }

    // ---- Sign / Verify ----

    /** Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector. */
    public static byte[] sign(BigInteger sk, byte[] pk, byte[] header, List<byte[]> messages) {
        List<BigInteger> ms = messagesToScalars(messages);
        List<P1> g = gens(ms.size() + 1);
        P1 q1 = g.get(0);
        List<P1> h = g.subList(1, g.size());
        BigInteger domain = calculateDomain(pk, q1, h, header);
        List<Object> eEls = new ArrayList<>();
        eEls.add(sk);
        eEls.addAll(ms);
        eEls.add(domain);
        BigInteger e = hashToScalar(serialize(eEls), H2S_DST);
        P1 b = computeB(q1, h, domain, ms);
        P1 a = Bls12.mul(b, Bls12.inv(Bls12.add(sk, e)));
        return signatureToOctets(a, e);
    }

    /** Result of a verification: ok, or the stable machine-readable reason. */
    public record Result(boolean ok, String reason) {
        static final Result OK = new Result(true, null);
        static Result fail(String reason) { return new Result(false, reason); }
    }

    public static final String MALFORMED_SIGNATURE = "malformed-signature";
    public static final String MALFORMED_PUBLIC_KEY = "malformed-public-key";
    public static final String MALFORMED_PROOF = "malformed-proof";
    public static final String DISCLOSED_LENGTH_MISMATCH = "disclosed-length-mismatch";
    public static final String INVALID_DISCLOSED_INDEXES = "invalid-disclosed-indexes";
    public static final String PAIRING_MISMATCH = "pairing-mismatch";
    public static final String CHALLENGE_MISMATCH = "challenge-mismatch";

    /** Decode a public key: strict G2, not the identity; null when malformed. */
    private static P2 decodePk(byte[] pk) {
        try {
            P2 w = Bls12.decodeG2(pk);
            return w.is_inf() ? null : w;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input. */
    public static Result verifyDetailed(byte[] pk, byte[] signature, byte[] header, List<byte[]> messages) {
        ParsedSignature parsed;
        try {
            parsed = octetsToSignature(signature);
        } catch (IllegalArgumentException e) {
            return Result.fail(MALFORMED_SIGNATURE);
        }
        P2 w = decodePk(pk);
        if (w == null) return Result.fail(MALFORMED_PUBLIC_KEY);
        if (messages.size() > MAX_MESSAGES) return Result.fail(DISCLOSED_LENGTH_MISMATCH);
        List<BigInteger> ms = messagesToScalars(messages);
        List<P1> g = gens(ms.size() + 1);
        P1 q1 = g.get(0);
        List<P1> h = g.subList(1, g.size());
        BigInteger domain = calculateDomain(pk, q1, h, header);
        P1 b = computeB(q1, h, domain, ms);
        // e(A, W + BP2*e) == e(B, BP2)
        boolean ok = Bls12.pairingEq(parsed.a(), Bls12.add(w, Bls12.mul(BP2, parsed.e())), b, BP2);
        return ok ? Result.OK : Result.fail(PAIRING_MISMATCH);
    }

    public static boolean verify(byte[] pk, byte[] signature, byte[] header, List<byte[]> messages) {
        return verifyDetailed(pk, signature, header, messages).ok();
    }

    // ---- challenge (draft 3.7.4) ----

    private static BigInteger calculateChallenge(P1 abar, P1 bbar, P1 d, P1 t1, P1 t2, List<Integer> idx, List<BigInteger> msgs, BigInteger domain, byte[] ph) {
        List<Object> els = new ArrayList<>();
        els.add(idx.size());
        for (int k = 0; k < idx.size(); k++) {
            els.add(idx.get(k));
            els.add(msgs.get(k));
        }
        els.add(abar);
        els.add(bbar);
        els.add(d);
        els.add(t1);
        els.add(t2);
        els.add(domain);
        return hashToScalar(concat(serialize(els), i2osp(ph.length, 8), ph), H2S_DST);
    }

    // ---- proof octets ----

    private record ParsedProof(P1 abar, P1 bbar, P1 d, BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat, List<BigInteger> mHat, BigInteger c) {}

    private static byte[] proofToOctets(ParsedProof p) {
        List<byte[]> parts = new ArrayList<>();
        parts.add(p.abar().compress());
        parts.add(p.bbar().compress());
        parts.add(p.d().compress());
        parts.add(i2osp(p.eHat(), SCALAR_LEN));
        parts.add(i2osp(p.r1Hat(), SCALAR_LEN));
        parts.add(i2osp(p.r3Hat(), SCALAR_LEN));
        for (BigInteger m : p.mHat()) parts.add(i2osp(m, SCALAR_LEN));
        parts.add(i2osp(p.c(), SCALAR_LEN));
        return concat(parts.toArray(new byte[0][]));
    }

    private static BigInteger readScalar(byte[] proof, int offset) {
        BigInteger v = Bls12.os2ip(java.util.Arrays.copyOfRange(proof, offset, offset + SCALAR_LEN));
        if (v.compareTo(R) >= 0) throw new IllegalArgumentException("bbs: proof scalar out of range");
        return v;
    }

    private static ParsedProof octetsToProof(byte[] proof) {
        int fixed = 3 * POINT_LEN + 4 * SCALAR_LEN;
        if (proof.length < fixed || (proof.length - fixed) % SCALAR_LEN != 0) throw new IllegalArgumentException("bbs: malformed proof length");
        int o = 0;
        P1 abar = Bls12.decodeG1(java.util.Arrays.copyOfRange(proof, o, o += POINT_LEN));
        P1 bbar = Bls12.decodeG1(java.util.Arrays.copyOfRange(proof, o, o += POINT_LEN));
        P1 d = Bls12.decodeG1(java.util.Arrays.copyOfRange(proof, o, o += POINT_LEN));
        BigInteger eHat = readScalar(proof, o);
        o += SCALAR_LEN;
        BigInteger r1Hat = readScalar(proof, o);
        o += SCALAR_LEN;
        BigInteger r3Hat = readScalar(proof, o);
        o += SCALAR_LEN;
        int u = (proof.length - fixed) / SCALAR_LEN;
        List<BigInteger> mHat = new ArrayList<>();
        for (int i = 0; i < u; i++) {
            mHat.add(readScalar(proof, o));
            o += SCALAR_LEN;
        }
        BigInteger c = readScalar(proof, o);
        if (abar.is_inf() || bbar.is_inf() || d.is_inf()) throw new IllegalArgumentException("bbs: proof contains the identity point");
        return new ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c);
    }

    // ---- index-set helpers ----

    private static void validateIndexes(List<Integer> indexes, int l) {
        Set<Integer> seen = new TreeSet<>();
        for (int i : indexes) {
            if (i < 0 || i >= l) throw new IllegalArgumentException("bbs: disclosed index " + i + " out of range [0, " + l + ")");
            if (!seen.add(i)) throw new IllegalArgumentException("bbs: duplicate disclosed index " + i);
        }
    }

    private static List<Integer> undisclosedAscending(Set<Integer> disclosed, int l) {
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < l; i++) if (!disclosed.contains(i)) out.add(i);
        return out;
    }

    // ---- ProofGen ----

    /** ProofGen with fresh randomness from the system CSPRNG. */
    public static byte[] proofGen(byte[] pk, byte[] signature, byte[] header, byte[] ph, List<byte[]> messages, List<Integer> disclosedIndexes) {
        return proofGen(pk, signature, header, ph, messages, disclosedIndexes, null);
    }

    /**
     * ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
     * discloses the messages at the given indexes. {@code fixedRandomScalars} (5 + undisclosed count scalars) pins the randomness
     * for test vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability.
     */
    public static byte[] proofGen(byte[] pk, byte[] signature, byte[] header, byte[] ph, List<byte[]> messages, List<Integer> disclosedIndexes, List<BigInteger> fixedRandomScalars) {
        ParsedSignature sig = octetsToSignature(signature);
        P1 a = sig.a();
        BigInteger e = sig.e();
        List<BigInteger> ms = messagesToScalars(messages);
        int l = ms.size();
        validateIndexes(disclosedIndexes, l);
        Set<Integer> disclosedSet = new TreeSet<>(disclosedIndexes);
        List<Integer> disclosed = new ArrayList<>(disclosedSet);
        List<Integer> undisclosed = undisclosedAscending(disclosedSet, l);
        int u = undisclosed.size();

        List<P1> g = gens(l + 1);
        P1 q1 = g.get(0);
        List<P1> h = g.subList(1, g.size());
        BigInteger domain = calculateDomain(pk, q1, h, header);
        P1 b = computeB(q1, h, domain, ms);

        List<BigInteger> rs;
        if (fixedRandomScalars == null) {
            rs = new ArrayList<>();
            SecureRandom rng = new SecureRandom();
            for (int i = 0; i < 5 + u; i++) {
                byte[] wide = new byte[EXPAND_LEN];
                rng.nextBytes(wide);
                rs.add(Bls12.mod(Bls12.os2ip(wide)));
            }
        } else {
            rs = new ArrayList<>(fixedRandomScalars);
        }
        if (rs.size() != 5 + u) throw new IllegalArgumentException("bbs: expected " + (5 + u) + " random scalars, got " + rs.size());
        if (rs.get(0).signum() == 0 || rs.get(1).signum() == 0) throw new IllegalArgumentException("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)");
        BigInteger r1 = rs.get(0);
        BigInteger r2 = rs.get(1);
        BigInteger eTilde = rs.get(2);
        BigInteger r1Tilde = rs.get(3);
        BigInteger r3Tilde = rs.get(4);
        List<BigInteger> mTilde = rs.subList(5, rs.size());

        P1 d = Bls12.mul(b, r2);
        P1 abar = Bls12.mul(a, Bls12.mul(r1, r2));
        P1 bbar = Bls12.sub(Bls12.mul(d, r1), Bls12.mul(abar, e));
        P1 t1 = Bls12.add(Bls12.mul(abar, eTilde), Bls12.mul(d, r1Tilde));
        P1 t2 = Bls12.mul(d, r3Tilde);
        for (int k = 0; k < u; k++) t2 = Bls12.add(t2, Bls12.mul(h.get(undisclosed.get(k)), mTilde.get(k)));

        List<BigInteger> disclosedMsgs = new ArrayList<>();
        for (int i : disclosed) disclosedMsgs.add(ms.get(i));
        BigInteger c = calculateChallenge(abar, bbar, d, t1, t2, disclosed, disclosedMsgs, domain, ph);

        BigInteger r3 = Bls12.inv(r2);
        BigInteger eHat = Bls12.add(eTilde, Bls12.mul(e, c));
        BigInteger r1Hat = Bls12.sub(r1Tilde, Bls12.mul(r1, c));
        BigInteger r3Hat = Bls12.sub(r3Tilde, Bls12.mul(r3, c));
        List<BigInteger> mHat = new ArrayList<>();
        for (int k = 0; k < u; k++) mHat.add(Bls12.add(mTilde.get(k), Bls12.mul(ms.get(undisclosed.get(k)), c)));
        return proofToOctets(new ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c));
    }

    // ---- ProofVerify ----

    /** ProofVerify with a rejection reason. {@code disclosedMessages[k]} corresponds to {@code disclosedIndexes[k]}. */
    public static Result proofVerifyDetailed(byte[] pk, byte[] proof, byte[] header, byte[] ph, List<byte[]> disclosedMessages, List<Integer> disclosedIndexes) {
        ParsedProof p;
        try {
            p = octetsToProof(proof);
        } catch (IllegalArgumentException e) {
            return Result.fail(MALFORMED_PROOF);
        }
        P2 w = decodePk(pk);
        if (w == null) return Result.fail(MALFORMED_PUBLIC_KEY);
        if (disclosedMessages.size() != disclosedIndexes.size()) return Result.fail(DISCLOSED_LENGTH_MISMATCH);
        int u = p.mHat().size();
        int l = disclosedIndexes.size() + u;
        if (l > MAX_MESSAGES) return Result.fail(MALFORMED_PROOF);

        List<int[]> order = new ArrayList<>(); // {index, position in the caller's lists}
        List<BigInteger> scalars;
        try {
            validateIndexes(disclosedIndexes, l);
            scalars = messagesToScalars(disclosedMessages);
        } catch (IllegalArgumentException e) {
            return Result.fail(INVALID_DISCLOSED_INDEXES);
        }
        for (int k = 0; k < disclosedIndexes.size(); k++) order.add(new int[] {disclosedIndexes.get(k), k});
        Collections.sort(order, (x, y) -> Integer.compare(x[0], y[0]));
        Set<Integer> disclosedSet = new TreeSet<>(disclosedIndexes);
        List<Integer> undisclosed = undisclosedAscending(disclosedSet, l);

        List<P1> g = gens(l + 1);
        P1 q1 = g.get(0);
        List<P1> h = g.subList(1, g.size());
        BigInteger domain = calculateDomain(pk, q1, h, header);

        P1 t1 = Bls12.add(Bls12.add(Bls12.mul(p.bbar(), p.c()), Bls12.mul(p.abar(), p.eHat())), Bls12.mul(p.d(), p.r1Hat()));
        P1 bv = Bls12.add(P1_GEN, Bls12.mul(q1, domain));
        List<Integer> sortedIdx = new ArrayList<>();
        List<BigInteger> sortedMsgs = new ArrayList<>();
        for (int[] o : order) {
            sortedIdx.add(o[0]);
            sortedMsgs.add(scalars.get(o[1]));
            bv = Bls12.add(bv, Bls12.mul(h.get(o[0]), scalars.get(o[1])));
        }
        P1 t2 = Bls12.add(Bls12.mul(bv, p.c()), Bls12.mul(p.d(), p.r3Hat()));
        for (int k = 0; k < u; k++) t2 = Bls12.add(t2, Bls12.mul(h.get(undisclosed.get(k)), p.mHat().get(k)));

        BigInteger cv = calculateChallenge(p.abar(), p.bbar(), p.d(), t1, t2, sortedIdx, sortedMsgs, domain, ph);
        if (!cv.equals(p.c())) return Result.fail(CHALLENGE_MISMATCH);
        return Bls12.pairingEq(p.abar(), w, p.bbar(), BP2) ? Result.OK : Result.fail(PAIRING_MISMATCH);
    }

    public static boolean proofVerify(byte[] pk, byte[] proof, byte[] header, byte[] ph, List<byte[]> disclosedMessages, List<Integer> disclosedIndexes) {
        return proofVerifyDetailed(pk, proof, header, ph, disclosedMessages, disclosedIndexes).ok();
    }
}
