package net.atlasauth.pca.ratchet;

import static net.atlasauth.pca.ratchet.Group.G;
import static net.atlasauth.pca.ratchet.Group.H;
import static net.atlasauth.pca.ratchet.Group.add;
import static net.atlasauth.pca.ratchet.Group.decodePoint;
import static net.atlasauth.pca.ratchet.Group.decodeScalar;
import static net.atlasauth.pca.ratchet.Group.encodePoint;
import static net.atlasauth.pca.ratchet.Group.encodeScalar;
import static net.atlasauth.pca.ratchet.Group.hashToScalar;
import static net.atlasauth.pca.ratchet.Group.mod;
import static net.atlasauth.pca.ratchet.Group.mul;
import static net.atlasauth.pca.ratchet.Group.numberToBytesLE;
import static net.atlasauth.pca.ratchet.Group.randScalar;
import static net.atlasauth.pca.ratchet.Group.scalarAdd;
import static net.atlasauth.pca.ratchet.Group.scalarMul;
import static net.atlasauth.pca.ratchet.Group.scalarSub;
import static net.atlasauth.pca.ratchet.Group.sub;
import static net.atlasauth.pca.ratchet.Group.utf8;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.ratchet.Ristretto.Point;

/**
 * Homomorphic risk accumulator with a zero-knowledge spend ceiling. Risk is a Pedersen commitment on ristretto255,
 * {@code C = risk*G + blinding*H}; commitments add, and a bit-decomposition range proof (a Fiat-Shamir OR proof per bit plus a Schnorr proof
 * that the bits aggregate to the slack commitment) shows the aggregate satisfies {@code sum(risk) <= bMax} without revealing the individual risks.
 * Proofs are JSON-shaped maps ({@code n}, {@code bitCommitments}, {@code or}, {@code agg}); risk units are non-negative integers (a Java number or a
 * {@link BigInteger}); blindings are {@link BigInteger}.
 */
public final class Accumulator {
    private Accumulator() {}

    /** Range-proof bit length: the slack (bMax - sum(risk)) must lie in [0, 2^32). */
    public static final int N_BITS = 32;
    /** Largest ceiling the range proof can express: 2^N_BITS - 1. */
    public static final BigInteger MAX_PROVABLE_CEILING = BigInteger.ONE.shiftLeft(N_BITS).subtract(BigInteger.ONE);

    private static final byte[] CTX_DOMAIN = utf8("atlas-pca-ratchet/budget/ctx/v1");
    private static final byte[] RISK_CTX_DOMAIN = utf8("atlas-pca-ratchet/risk-range/ctx/v1");
    private static final byte[] OR_DOMAIN = utf8("atlas-pca-ratchet/budget/bit-or/v1");
    private static final byte[] AGG_DOMAIN = utf8("atlas-pca-ratchet/budget/agg/v1");

    /** A risk commitment and its blinding scalar. */
    public static final class RiskCommitment {
        /** b64u ristretto255 point. */
        public final String commitment;
        public final BigInteger blinding;

        public RiskCommitment(String commitment, BigInteger blinding) {
            this.commitment = commitment;
            this.blinding = blinding;
        }
    }

    /** Non-negative integer units from a Java number / {@link Json.Num} (integer valued) or a {@link BigInteger}; anything else is refused. */
    static BigInteger asUnits(Object x) {
        if (x instanceof BigInteger) {
            if (((BigInteger) x).signum() < 0) throw new AccumulatorError("invalid_value", "risk/budget must be >= 0");
            return (BigInteger) x;
        }
        Double d = null;
        if (x instanceof Json.Num) {
            try { d = Double.parseDouble(((Json.Num) x).raw); } catch (NumberFormatException e) { d = null; }
        } else if (x instanceof Number) {
            d = ((Number) x).doubleValue();
        }
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || d < 0) {
            throw new AccumulatorError("invalid_value", "risk/budget must be a non-negative integer");
        }
        return new BigDecimal(d).toBigInteger();
    }

    /** Commit to a non-negative integer risk with the given blinding (a fresh random one when {@code blinding} is null). */
    public static RiskCommitment commitRisk(Object risk, BigInteger blinding) {
        BigInteger v = asUnits(risk);
        BigInteger b = blinding == null ? randScalar() : mod(blinding);
        return new RiskCommitment(encodePoint(add(mul(G, v), mul(H, b))), b);
    }

    /** Homomorphic sum: a commitment to (sum risk, sum blinding). Empty input is the identity. */
    public static String addCommitments(List<?> commitments) {
        Point acc = mul(G, BigInteger.ZERO);
        for (Object c : commitments) acc = add(acc, decodePoint(c));
        return encodePoint(acc);
    }

    /** True when {@code commitment} opens to ({@code risk}, {@code blinding}). Never throws; malformed input is false. */
    public static boolean openCommitment(Object commitment, Object risk, BigInteger blinding) {
        try {
            BigInteger v = asUnits(risk);
            Point expected = add(mul(G, v), mul(H, mod(blinding)));
            return decodePoint(commitment).equalsPoint(expected);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- range proof -----------------------------------------------------------------------------------------------------

    /** A ceiling above 2^N_BITS - 1 is clamped to it: a strictly stronger statement, so a verifier is never weakened. */
    private static BigInteger effectiveCeiling(BigInteger bMaxUnits) {
        return bMaxUnits.compareTo(MAX_PROVABLE_CEILING) > 0 ? MAX_PROVABLE_CEILING : bMaxUnits;
    }

    private static byte[] ctxBytes(byte[][] parts) { return numberToBytesLE(hashToScalar(parts), 32); }

    private static byte[] contextHash(int n, BigInteger bMaxUnits, Point commitmentSum, List<Point> bits) {
        List<byte[]> parts = new ArrayList<>();
        parts.add(CTX_DOMAIN);
        parts.add(new byte[] {(byte) (n & 0xff)});
        parts.add(numberToBytesLE(mod(bMaxUnits), 32));
        parts.add(commitmentSum.toRawBytes());
        for (Point b : bits) parts.add(b.toRawBytes());
        return ctxBytes(parts.toArray(new byte[0][]));
    }

    private static byte[] riskContextHash(int n, Point commitment, List<Point> bits) {
        List<byte[]> parts = new ArrayList<>();
        parts.add(RISK_CTX_DOMAIN);
        parts.add(new byte[] {(byte) (n & 0xff)});
        parts.add(commitment.toRawBytes());
        for (Point b : bits) parts.add(b.toRawBytes());
        return ctxBytes(parts.toArray(new byte[0][]));
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Prove bit commitment B (= b*G + s*H) opens to 0 or 1, knowing the bit and its blinding. */
    private static Map<String, Object> proveBit(byte[] ctx, int index, Point b, BigInteger bit, BigInteger s) {
        Point p0 = b;
        Point p1 = sub(b, G);
        int real = bit.equals(BigInteger.ONE) ? 1 : 0;
        BigInteger eFake = randScalar();
        BigInteger zFake = randScalar();
        Point pFake = real == 1 ? p0 : p1;
        Point aFake = sub(mul(H, zFake), mul(pFake, eFake));
        BigInteger k = randScalar();
        Point aReal = mul(H, k);
        Point a0 = real == 0 ? aReal : aFake;
        Point a1 = real == 1 ? aReal : aFake;
        BigInteger e = hashToScalar(OR_DOMAIN, ctx, new byte[] {(byte) (index & 0xff)}, a0.toRawBytes(), a1.toRawBytes());
        BigInteger eReal = scalarSub(e, eFake);
        BigInteger zReal = scalarAdd(k, scalarMul(eReal, s));
        BigInteger e0 = real == 0 ? eReal : eFake, e1 = real == 1 ? eReal : eFake;
        BigInteger z0 = real == 0 ? zReal : zFake, z1 = real == 1 ? zReal : zFake;
        return obj("e0", encodeScalar(e0), "e1", encodeScalar(e1), "z0", encodeScalar(z0), "z1", encodeScalar(z1));
    }

    private static boolean verifyBit(byte[] ctx, int index, Point b, Object proof) {
        BigInteger e0 = decodeScalar(member(proof, "e0"));
        BigInteger e1 = decodeScalar(member(proof, "e1"));
        BigInteger z0 = decodeScalar(member(proof, "z0"));
        BigInteger z1 = decodeScalar(member(proof, "z1"));
        Point p0 = b;
        Point p1 = sub(b, G);
        Point a0 = sub(mul(H, z0), mul(p0, e0));
        Point a1 = sub(mul(H, z1), mul(p1, e1));
        BigInteger e = hashToScalar(OR_DOMAIN, ctx, new byte[] {(byte) (index & 0xff)}, a0.toRawBytes(), a1.toRawBytes());
        return scalarAdd(e0, e1).equals(e);
    }

    /** {@code o[k]} of a proof node: a missing node is a TypeError in the reference, so it throws here. */
    private static Object member(Object o, String k) {
        if (o == null) throw new NullPointerException("proof member of null");
        return o instanceof Map ? ((Map<?, ?>) o).get(k) : null;
    }

    private static Map<String, Object> proveSchnorr(byte[] ctx, Point d, BigInteger w) {
        BigInteger k = randScalar();
        Point a = mul(H, k);
        BigInteger e = hashToScalar(AGG_DOMAIN, ctx, d.toRawBytes(), a.toRawBytes());
        BigInteger z = scalarAdd(k, scalarMul(e, w));
        return obj("a", encodePoint(a), "z", encodeScalar(z));
    }

    private static boolean verifySchnorr(byte[] ctx, Point d, Object proof) {
        Point a = decodePoint(member(proof, "a"));
        BigInteger z = decodeScalar(member(proof, "z"));
        BigInteger e = hashToScalar(AGG_DOMAIN, ctx, d.toRawBytes(), a.toRawBytes());
        return mul(H, z).equalsPoint(add(a, mul(d, e)));
    }

    /** The shared range-proof core: V = value*G + gamma*H is known to both sides; the value is taken modulo 2^N_BITS. */
    private static Map<String, Object> rangeProve(Function<List<Point>, byte[]> makeCtx, Point v, BigInteger value, BigInteger gamma) {
        BigInteger mask = BigInteger.ONE.shiftLeft(N_BITS).subtract(BigInteger.ONE);
        BigInteger vMasked = value.and(mask);
        List<Point> bitCommitments = new ArrayList<>();
        List<BigInteger> bitBlindings = new ArrayList<>();
        List<BigInteger> bits = new ArrayList<>();
        for (int i = 0; i < N_BITS; i++) {
            BigInteger bit = vMasked.shiftRight(i).and(BigInteger.ONE);
            BigInteger s = randScalar();
            bits.add(bit);
            bitBlindings.add(s);
            bitCommitments.add(add(mul(G, bit), mul(H, s)));
        }
        byte[] ctx = makeCtx.apply(bitCommitments);
        List<Object> or = new ArrayList<>();
        for (int i = 0; i < N_BITS; i++) or.add(proveBit(ctx, i, bitCommitments.get(i), bits.get(i), bitBlindings.get(i)));
        BigInteger sStar = BigInteger.ZERO;
        Point aggPoint = mul(G, BigInteger.ZERO);
        for (int i = 0; i < N_BITS; i++) {
            BigInteger w = BigInteger.ONE.shiftLeft(i);
            sStar = scalarAdd(sStar, scalarMul(w, bitBlindings.get(i)));
            aggPoint = add(aggPoint, mul(bitCommitments.get(i), w));
        }
        Point d = sub(aggPoint, v);
        Map<String, Object> agg = proveSchnorr(ctx, d, scalarSub(sStar, gamma));
        List<Object> bc = new ArrayList<>();
        for (Point p : bitCommitments) bc.add(encodePoint(p));
        return obj("n", Long.valueOf(N_BITS), "bitCommitments", bc, "or", or, "agg", agg);
    }

    private static boolean rangeVerify(Function<List<Point>, byte[]> makeCtx, Point v, Object proof) {
        if (!(proof instanceof Map)) return false;
        Map<?, ?> p = (Map<?, ?>) proof;
        Object n = p.get("n");
        Object bitCommitments = p.get("bitCommitments");
        Object or = p.get("or");
        Object agg = p.get("agg");
        Double nd = n instanceof Json.Num ? parse(((Json.Num) n).raw) : n instanceof Number ? Double.valueOf(((Number) n).doubleValue()) : null;
        if (nd == null || nd != N_BITS || !(bitCommitments instanceof List) || !(or instanceof List)) return false;
        List<?> bcl = (List<?>) bitCommitments;
        List<?> orl = (List<?>) or;
        if (bcl.size() != N_BITS || orl.size() != N_BITS) return false;
        if (!(agg instanceof Map || agg instanceof List)) return false;
        List<Point> b = new ArrayList<>();
        for (Object c : bcl) b.add(decodePoint(c));
        byte[] ctx = makeCtx.apply(b);
        for (int i = 0; i < N_BITS; i++) if (!verifyBit(ctx, i, b.get(i), orl.get(i))) return false;
        Point aggPoint = mul(G, BigInteger.ZERO);
        for (int i = 0; i < N_BITS; i++) aggPoint = add(aggPoint, mul(b.get(i), BigInteger.ONE.shiftLeft(i)));
        return verifySchnorr(ctx, sub(aggPoint, v), agg);
    }

    private static Double parse(String s) {
        try { return Double.parseDouble(s); } catch (NumberFormatException e) { return null; }
    }

    /**
     * Prove that the committed aggregate satisfies sum(risk) <= bMax, in zero knowledge over the individual risks. {@code risks} and
     * {@code blindings} are the per-action values behind the commitments whose sum goes to {@link #verifyBudget}. An over-budget aggregate (or a
     * slack that does not fit N_BITS) yields a well-formed proof that the verifier REJECTS: soundness lives in verification.
     *
     * <p>SCOPE: the proof is about the committed VALUE of the sum; pair it with {@link #proveRiskRange} / {@link #verifyBoundedBudget} so no
     * addend can be a "negative" value near the group order.
     */
    public static Map<String, Object> proveBudget(List<?> risks, List<BigInteger> blindings, Object bMax) {
        if (risks.size() != blindings.size()) throw new AccumulatorError("length_mismatch", "risks and blindings must have equal length");
        BigInteger ceiling = effectiveCeiling(asUnits(bMax));
        BigInteger sumRisk = BigInteger.ZERO;
        BigInteger sumBlind = BigInteger.ZERO;
        for (int i = 0; i < risks.size(); i++) {
            sumRisk = sumRisk.add(asUnits(risks.get(i) == null ? BigInteger.ZERO : risks.get(i)));
            sumBlind = scalarAdd(sumBlind, blindings.get(i) == null ? BigInteger.ZERO : blindings.get(i));
        }
        Point cSum = add(mul(G, mod(sumRisk)), mul(H, sumBlind));
        Point v = sub(mul(G, mod(ceiling)), cSum);
        BigInteger slack = ceiling.subtract(sumRisk);
        final Point fc = cSum;
        return rangeProve(bits -> contextHash(N_BITS, ceiling, fc, bits), v, slack, mod(sumBlind.negate()));
    }

    /**
     * Verify a budget proof against the commitment sum and ceiling: true only if every bit commitment opens to 0/1 and they aggregate to
     * {@code bMax*G - commitmentSum}, i.e. sum(risk) <= bMax. Never throws; malformed input is false. Scalars and points must be canonical.
     */
    public static boolean verifyBudget(Object commitmentSum, Object bMax, Object proof) {
        try {
            BigInteger ceiling = effectiveCeiling(asUnits(bMax));
            Point cSum = decodePoint(commitmentSum);
            Point v = sub(mul(G, mod(ceiling)), cSum);
            return rangeVerify(bits -> contextHash(N_BITS, ceiling, cSum, bits), v, proof);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Prove that {@code commitRisk(risk, blinding)} holds a value in [0, 2^N_BITS): each action's commitment needs one. */
    public static Map<String, Object> proveRiskRange(Object risk, BigInteger blinding) {
        BigInteger v = asUnits(risk);
        BigInteger b = mod(blinding);
        Point c = add(mul(G, mod(v)), mul(H, b));
        return rangeProve(bits -> riskContextHash(N_BITS, c, bits), c, v, b);
    }

    /** Verify {@link #proveRiskRange} for {@code commitment}. Never throws; malformed input is false. */
    public static boolean verifyRiskRange(Object commitment, Object proof) {
        try {
            Point c = decodePoint(commitment);
            return rangeVerify(bits -> riskContextHash(N_BITS, c, bits), c, proof);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The sound end-to-end budget check over per-action commitments: every commitment carries a valid range proof and the budget proof verifies for
     * their homomorphic sum. Accepting implies sum(committed risks), as integers, <= min(bMax, 2^N_BITS - 1). Never throws.
     */
    public static boolean verifyBoundedBudget(Object commitments, Object rangeProofs, Object bMax, Object budgetProof) {
        try {
            if (!(commitments instanceof List) || !(rangeProofs instanceof List) || ((List<?>) commitments).size() != ((List<?>) rangeProofs).size()) return false;
            List<?> cs = (List<?>) commitments;
            List<?> rps = (List<?>) rangeProofs;
            for (int i = 0; i < cs.size(); i++) if (!verifyRiskRange(cs.get(i), rps.get(i))) return false;
            return verifyBudget(addCommitments(cs), bMax, budgetProof);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
