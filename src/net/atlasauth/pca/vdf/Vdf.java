package net.atlasauth.pca.vdf;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wesolowski Verifiable Delay Function over an RSA group (port of the reference vdf module).
 * BigInteger (JDK) is the big-number primitive; the Fiat-Shamir challenge prime derivation, the fixed-base
 * Miller-Rabin and the strong Lucas test are ported 1:1 so prover and verifier derive the SAME prime as the reference.
 *
 * TRUSTED SETUP: an RSA-group VDF only delays anybody if the modulus has unknown factorisation. {@link #insecureDevSetup}
 * knows its trapdoor and is refused by the timelock layer unless the caller opts in by name.
 */
public final class Vdf {
    private Vdf() {}

    public static final int CHALLENGE_PRIME_BITS = 256;
    public static final int INSECURE_DEV_SETUP_DEFAULT_BITS = 2048;
    public static final int MIN_PRODUCTION_MODULUS_BITS = 2048;
    /** 2^53 - 1: JavaScript's largest safe integer (the reference's step-count domain). */
    static final double MAX_SAFE = 9007199254740991d;

    /** The RSA Factoring Challenge RSA-2048 modulus (factorisation never published). */
    public static final BigInteger RSA_2048_CHALLENGE_MODULUS = new BigInteger(
        "2519590847565789349402718324004839857142928212620403202777713783604366202070"
            + "7595556264018525880784406918290641249515082189298559149176184502808489120072"
            + "8449926873928072877767359714183472702618963750149718246911650776133798590957"
            + "0009733045974880842840179742910064245869181719511874612151517265463228221686"
            + "9987549182422433637259085141865462043576798423387184774447920739934236584823"
            + "8242811981638150106748104516603773060562016196762561338441436038339044149526"
            + "3443219011465754445417842402092461651572335077870774981712577246796292638635"
            + "6373289912154831438167899885040445364023527381951378636564391212010397122822"
            + "120720357");
    public static final BigInteger DEFAULT_MODULUS = RSA_2048_CHALLENGE_MODULUS;

    private static final BigInteger ZERO = BigInteger.ZERO, ONE = BigInteger.ONE, TWO = BigInteger.TWO;
    private static final BigInteger THREE = BigInteger.valueOf(3), FOUR = BigInteger.valueOf(4);

    /** A VDF proof: {@code y = x^(2^T) mod N} and {@code pi = x^floor(2^T / l) mod N}. */
    public static final class VdfProof {
        public final BigInteger y, pi;
        public VdfProof(BigInteger y, BigInteger pi) { this.y = y; this.pi = pi; }
    }

    /** The development modulus plus its trapdoor factors. */
    public static final class InsecureDevVdfSetup {
        public final boolean insecureDevOnly = true;
        public final BigInteger N, p, q;
        public final int bits;
        InsecureDevVdfSetup(BigInteger N, BigInteger p, BigInteger q) { this.N = N; this.p = p; this.q = q; this.bits = N.bitLength(); }
    }

    /** Verification result with the machine-readable refusal reason (malformed-input, bad-modulus, bad-steps, non-canonical-y, non-canonical-pi, bad-input-x, equation-mismatch). */
    public static final class VdfVerdict {
        public final boolean ok;
        public final String reason;
        VdfVerdict(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
        static final VdfVerdict OK = new VdfVerdict(true, null);
        static VdfVerdict no(String r) { return new VdfVerdict(false, r); }
    }

    /** Outcome of {@link #checkProductionModulus}. */
    public static final class ModulusCheck {
        public final boolean ok;
        public final String reason;
        ModulusCheck(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
    }

    // ---- bigint / byte helpers -------------------------------------------------------------------------------------

    /** Big-endian bytes -> non-negative integer (empty -> 0). */
    public static BigInteger bytesToBigInt(byte[] bytes) { return bytes.length == 0 ? ZERO : new BigInteger(1, bytes); }

    /** Non-negative integer -> minimal big-endian bytes (0 -> a single 0x00). */
    public static byte[] bigIntToBytes(BigInteger value) {
        if (value.signum() < 0) throw new IllegalArgumentException("bigIntToBytes: negative value");
        if (value.signum() == 0) return new byte[] {0};
        byte[] b = value.toByteArray();
        if (b[0] == 0 && b.length > 1) { byte[] c = new byte[b.length - 1]; System.arraycopy(b, 1, c, 0, c.length); return c; }
        return b;
    }

    private static byte[] u32be(long n) { return new byte[] {(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n}; }

    private static byte[] u64be(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte) v; v >>>= 8; }
        return b;
    }

    private static void lp(ByteArrayOutputStream out, byte[] b) { out.writeBytes(u32be(b.length)); out.writeBytes(b); }

    private static byte[] sha256(byte[] m) {
        try { return MessageDigest.getInstance("SHA-256").digest(m); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** True for a JavaScript safe integer >= 0. */
    static boolean isSafeSteps(double t) { return t >= 0 && t <= MAX_SAFE && t == Math.floor(t); }

    private static BigInteger normalizeSteps(long T) {
        if (T < 0 || T > (long) MAX_SAFE) throw new IllegalArgumentException("VDF: steps T must be a non-negative safe integer, got " + T);
        return BigInteger.valueOf(T);
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) { return a.abs().gcd(b.abs()); }

    private static boolean isUnit(BigInteger v, BigInteger N) {
        return v.signum() > 0 && v.compareTo(N) < 0 && v.gcd(N).equals(ONE);
    }

    private static BigInteger red(BigInteger v, BigInteger N) { return v.mod(N); }

    /** {@code base^exp mod mod}; exp >= 0, mod > 0. */
    public static BigInteger modpow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (mod.signum() <= 0) throw new IllegalArgumentException("modpow: modulus must be positive");
        if (mod.equals(ONE)) return ZERO;
        if (exp.signum() < 0) throw new IllegalArgumentException("modpow: negative exponent (no inverse in a group of unknown order)");
        return base.mod(mod).modPow(exp, mod);
    }

    // ---- primality --------------------------------------------------------------------------------------------------

    private static final long[] SMALL = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};

    private static int jacobi(BigInteger a, BigInteger n) {
        int r = 1;
        a = a.mod(n);
        while (a.signum() != 0) {
            while (!a.testBit(0)) {
                a = a.shiftRight(1);
                int m = n.intValue() & 7;
                if (m == 3 || m == 5) r = -r;
            }
            BigInteger t = a; a = n; n = t;
            if ((a.intValue() & 3) == 3 && (n.intValue() & 3) == 3) r = -r;
            a = a.mod(n);
        }
        return n.equals(ONE) ? r : 0;
    }

    static boolean isPerfectSquare(BigInteger n) {
        if (n.signum() < 0) return false;
        if (n.compareTo(TWO) < 0) return true;
        BigInteger s = n.sqrt();
        return s.multiply(s).equals(n);
    }

    /** Strong Lucas probable-prime test, Selfridge method A (P = 1, Q = (1 - D) / 4). Expects odd n > 2. */
    public static boolean isStrongLucasProbablePrime(BigInteger n) {
        if (n.compareTo(THREE) < 0 || !n.testBit(0) || isPerfectSquare(n)) return false;
        BigInteger D = BigInteger.valueOf(5);
        for (;;) {
            int j = jacobi(D, n);
            if (j == -1) break;
            if (j == 0 && !D.abs().equals(n)) return false;
            D = D.signum() > 0 ? D.add(TWO).negate() : D.negate().add(TWO);
        }
        BigInteger P = ONE;
        BigInteger Q = ONE.subtract(D).divide(FOUR);
        BigInteger d = n.add(ONE);
        int s = 0;
        while (!d.testBit(0)) { d = d.shiftRight(1); s++; }
        BigInteger U = ONE, V = P, Qk = Q.mod(n);
        String bits = d.toString(2);
        for (int i = 1; i < bits.length(); i++) {
            U = U.multiply(V).mod(n);
            V = V.multiply(V).subtract(TWO.multiply(Qk)).mod(n);
            Qk = Qk.multiply(Qk).mod(n);
            if (bits.charAt(i) == '1') {
                BigInteger U1 = half(P.multiply(U).add(V).mod(n), n);
                BigInteger V1 = half(D.multiply(U).add(P.multiply(V)).mod(n), n);
                U = U1; V = V1;
                Qk = Qk.multiply(Q).mod(n);
            }
        }
        if (U.signum() == 0 || V.signum() == 0) return true;
        for (int r = 1; r < s; r++) {
            V = V.multiply(V).subtract(TWO.multiply(Qk)).mod(n);
            if (V.signum() == 0) return true;
            Qk = Qk.multiply(Qk).mod(n);
        }
        return false;
    }

    private static BigInteger half(BigInteger x, BigInteger n) { return (x.testBit(0) ? x.add(n) : x).shiftRight(1); }

    /** Strong (Miller-Rabin) probable-prime test of odd n > 2 against the fixed bases 2..97; refuses even n and n < 3. */
    public static boolean isMillerRabinProbablePrime(BigInteger n) {
        if (n.compareTo(THREE) < 0 || !n.testBit(0)) return false;
        BigInteger nm1 = n.subtract(ONE);
        int s = nm1.getLowestSetBit();
        BigInteger d = nm1.shiftRight(s);
        witness:
        for (long a : SMALL) {
            BigInteger base = BigInteger.valueOf(a).mod(n);
            if (base.signum() == 0) continue;
            BigInteger x = base.modPow(d, n);
            if (x.equals(ONE) || x.equals(nm1)) continue;
            for (int i = 1; i < s; i++) {
                x = x.multiply(x).mod(n);
                if (x.equals(nm1)) continue witness;
            }
            return false;
        }
        return true;
    }

    /** Trial division, Miller-Rabin over the fixed bases, then strong Lucas (deterministic: prover and verifier agree). */
    public static boolean isProbablePrime(BigInteger n) {
        if (n.compareTo(TWO) < 0) return false;
        for (long p : SMALL) {
            BigInteger bp = BigInteger.valueOf(p);
            if (n.equals(bp)) return true;
            if (n.mod(bp).signum() == 0) return false;
        }
        return isMillerRabinProbablePrime(n) && isStrongLucasProbablePrime(n);
    }

    // ---- hash-to-prime -----------------------------------------------------------------------------------------------

    private static final byte[] H2P_DOMAIN = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\0".getBytes(StandardCharsets.UTF_8);

    public static BigInteger hashToPrime(BigInteger x, BigInteger y, long T, BigInteger N) { return hashToPrime(x, y, T, N, CHALLENGE_PRIME_BITS); }

    /** Fiat-Shamir challenge prime from the transcript (x, y, T, N); byte-identical to the reference. */
    public static BigInteger hashToPrime(BigInteger x, BigInteger y, long T, BigInteger N, int bits) {
        if (bits < 8 || bits > 8192) throw new IllegalArgumentException("hashToPrime: bits must be an integer in [8, 8192]");
        BigInteger steps = normalizeSteps(T);
        BigInteger xr = red(x, N), yr = red(y, N);
        ByteArrayOutputStream t = new ByteArrayOutputStream();
        t.writeBytes(H2P_DOMAIN);
        lp(t, bigIntToBytes(xr));
        lp(t, bigIntToBytes(yr));
        lp(t, bigIntToBytes(steps));
        lp(t, bigIntToBytes(N));
        lp(t, u32be(bits));
        byte[] seed = sha256(t.toByteArray());
        int bytesNeeded = (bits + 7) / 8;
        BigInteger topBit = ONE.shiftLeft(bits - 1);
        BigInteger mask = ONE.shiftLeft(bits).subtract(ONE);
        for (long counter = 0; ; counter++) {
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            for (int blockIndex = 0; raw.size() < bytesNeeded; blockIndex++) {
                ByteArrayOutputStream in = new ByteArrayOutputStream();
                in.writeBytes(seed);
                in.writeBytes(u64be(counter));
                in.writeBytes(u32be(blockIndex));
                raw.writeBytes(sha256(in.toByteArray()));
            }
            byte[] all = raw.toByteArray();
            byte[] cut = new byte[bytesNeeded];
            System.arraycopy(all, 0, cut, 0, bytesNeeded);
            BigInteger candidate = bytesToBigInt(cut).and(mask).or(topBit).or(ONE);
            if (isProbablePrime(candidate)) return candidate;
        }
    }

    // ---- the VDF ---------------------------------------------------------------------------------------------------

    /** {@code x^(2^T) mod N} by T real sequential squarings. */
    public static BigInteger sequentialSquare(BigInteger x, long T, BigInteger N) {
        if (N.compareTo(ONE) <= 0) throw new IllegalArgumentException("VDF: modulus N must be > 1");
        BigInteger steps = normalizeSteps(T);
        BigInteger y = red(x, N);
        for (long i = 0, n = steps.longValueExact(); i < n; i++) y = y.multiply(y).mod(N);
        return y;
    }

    private static BigInteger wesolowskiProof(BigInteger x, long T, BigInteger l, BigInteger N) {
        BigInteger xr = red(x, N);
        BigInteger pi = ONE.mod(N);
        BigInteger r = ONE.mod(l);
        for (long i = 0; i < T; i++) {
            BigInteger twoR = r.shiftLeft(1);
            boolean b = twoR.compareTo(l) >= 0;
            r = b ? twoR.subtract(l) : twoR;
            pi = pi.multiply(pi).mod(N);
            if (b) pi = pi.multiply(xr).mod(N);
        }
        return pi;
    }

    private static void requireModulus(BigInteger N) {
        if (N.compareTo(THREE) <= 0 || !N.testBit(0)) throw new IllegalArgumentException("VDF: modulus N must be odd and > 3");
    }

    private static BigInteger requireInput(BigInteger x, BigInteger N) {
        BigInteger xr = red(x, N);
        if (!isUnit(xr, N) || xr.equals(ONE) || xr.equals(N.subtract(ONE))) {
            throw new IllegalArgumentException("VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)");
        }
        return xr;
    }

    /** y = x^(2^T) mod N by T sequential squarings, plus the Wesolowski proof. */
    public static VdfProof vdfEval(BigInteger x, long T, BigInteger N) {
        requireModulus(N);
        normalizeSteps(T);
        requireInput(x, N);
        BigInteger y = sequentialSquare(x, T, N);
        BigInteger l = hashToPrime(x, y, T, N);
        return new VdfProof(y, wesolowskiProof(x, T, l, N));
    }

    public static BigInteger canonicalVdfOutput(BigInteger y, BigInteger N) { return y.compareTo(N.subtract(y)) > 0 ? N.subtract(y) : y; }

    /** Evaluate with a unique (canonical, y and pi both <= N/2) output. */
    public static VdfProof vdfEvalCanonical(BigInteger x, long T, BigInteger N) {
        requireModulus(N);
        normalizeSteps(T);
        requireInput(x, N);
        BigInteger y = canonicalVdfOutput(sequentialSquare(x, T, N), N);
        BigInteger l = hashToPrime(x, y, T, N);
        return new VdfProof(y, canonicalVdfOutput(wesolowskiProof(x, T, l, N), N));
    }

    public static VdfVerdict vdfVerifyDetailed(BigInteger x, BigInteger y, BigInteger pi, long T, BigInteger N) { return vdfVerifyDetailed(x, y, pi, (double) T, N); }

    /** Verify in O(log) work; fails closed (never throws), returning why on refusal. */
    public static VdfVerdict vdfVerifyDetailed(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N) { return verify(x, y, pi, T, N, false); }

    public static VdfVerdict vdfVerifyCanonicalDetailed(BigInteger x, BigInteger y, BigInteger pi, long T, BigInteger N) { return vdfVerifyCanonicalDetailed(x, y, pi, (double) T, N); }

    /** Verify a canonical-output proof: y and pi must be <= N/2; the relation holds up to sign. */
    public static VdfVerdict vdfVerifyCanonicalDetailed(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N) { return verify(x, y, pi, T, N, true); }

    private static VdfVerdict verify(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N, boolean canonical) {
        try {
            if (x == null || y == null || pi == null || N == null) return VdfVerdict.no("malformed-input");
            if (N.compareTo(THREE) <= 0 || !N.testBit(0)) return VdfVerdict.no("bad-modulus");
            if (!isSafeSteps(T)) return VdfVerdict.no("bad-steps");
            long steps = (long) T;
            if (!isUnit(y, N) || (canonical && y.compareTo(N.subtract(y)) > 0)) return VdfVerdict.no("non-canonical-y");
            if (!isUnit(pi, N) || (canonical && pi.compareTo(N.subtract(pi)) > 0)) return VdfVerdict.no("non-canonical-pi");
            BigInteger xr = red(x, N);
            if (!isUnit(xr, N) || xr.equals(ONE) || xr.equals(N.subtract(ONE))) return VdfVerdict.no("bad-input-x");
            BigInteger l = hashToPrime(x, y, steps, N);
            BigInteger r = modpow(TWO, BigInteger.valueOf(steps), l);
            BigInteger lhs = modpow(pi, l, N).multiply(modpow(xr, r, N)).mod(N);
            boolean ok = lhs.equals(y) || (canonical && lhs.equals(N.subtract(y)));
            return ok ? VdfVerdict.OK : VdfVerdict.no("equation-mismatch");
        } catch (RuntimeException e) {
            return VdfVerdict.no("malformed-input");
        }
    }

    public static boolean vdfVerify(BigInteger x, BigInteger y, BigInteger pi, long T, BigInteger N) { return vdfVerifyDetailed(x, y, pi, T, N).ok; }

    public static boolean vdfVerifyCanonical(BigInteger x, BigInteger y, BigInteger pi, long T, BigInteger N) { return vdfVerifyCanonicalDetailed(x, y, pi, T, N).ok; }

    // ---- DEV / TEST-ONLY modulus generation ------------------------------------------------------------------------

    private static final Set<BigInteger> INSECURE_DEV_MODULI = ConcurrentHashMap.newKeySet();

    private static BigInteger randomPrime(int bits, SecureRandom rnd) {
        if (bits < 16) throw new IllegalArgumentException("randomPrime: bits too small");
        int nb = (bits + 7) / 8;
        BigInteger topBit = ONE.shiftLeft(bits - 1), mask = ONE.shiftLeft(bits).subtract(ONE);
        for (int attempt = 0; attempt < 50_000; attempt++) {
            byte[] b = new byte[nb];
            rnd.nextBytes(b);
            BigInteger c = bytesToBigInt(b).and(mask).or(topBit).or(ONE);
            if (isProbablePrime(c)) return c;
        }
        throw new IllegalStateException("insecureDevSetup: randomness source failed to yield a prime");
    }

    public static InsecureDevVdfSetup insecureDevSetup() { return insecureDevSetup(INSECURE_DEV_SETUP_DEFAULT_BITS, new SecureRandom()); }

    /** DEVELOPMENT / TESTS ONLY: generates N = p*q and therefore KNOWS the trapdoor; the timelock layer refuses it unless opted in by name. */
    public static InsecureDevVdfSetup insecureDevSetup(int bits, SecureRandom rnd) {
        if (bits < 32) throw new IllegalArgumentException("insecureDevSetup: bits must be an integer >= 32");
        int half = bits / 2;
        BigInteger p = randomPrime(half, rnd);
        BigInteger q = randomPrime(bits - half, rnd);
        for (int i = 0; p.equals(q); i++) {
            if (i >= 8) throw new IllegalStateException("insecureDevSetup: randomness source returned the same prime repeatedly");
            q = randomPrime(bits - half, rnd);
        }
        BigInteger N = p.multiply(q);
        INSECURE_DEV_MODULI.add(N);
        return new InsecureDevVdfSetup(N, p, q);
    }

    private static final List<Integer> SCREEN_PRIMES = screenPrimes();

    private static List<Integer> screenPrimes() {
        int limit = 1 << 16;
        boolean[] sieve = new boolean[limit];
        java.util.ArrayList<Integer> out = new java.util.ArrayList<>();
        for (int i = 2; i < limit; i++) {
            if (sieve[i]) continue;
            out.add(i);
            for (long j = (long) i * i; j < limit; j += i) sieve[(int) j] = true;
        }
        return out;
    }

    /** Screen a modulus for the production timelock path (a screen, not a proof of unknown factorisation). */
    public static ModulusCheck checkProductionModulus(BigInteger N) {
        if (N == null) return new ModulusCheck(false, "modulus is not a bigint");
        if (INSECURE_DEV_MODULI.contains(N)) return new ModulusCheck(false, "modulus came from insecureDevSetup(): its factors are known, so it provides no delay");
        if (N.compareTo(THREE) <= 0) return new ModulusCheck(false, "modulus is too small");
        if (N.bitLength() < MIN_PRODUCTION_MODULUS_BITS) return new ModulusCheck(false, "modulus is below " + MIN_PRODUCTION_MODULUS_BITS + " bits");
        if (!N.testBit(0)) return new ModulusCheck(false, "modulus is even");
        if (isPerfectSquare(N)) return new ModulusCheck(false, "modulus is a perfect square");
        if (isProbablePrime(N)) return new ModulusCheck(false, "modulus is prime (group order N-1 is public)");
        for (int p : SCREEN_PRIMES) {
            if (N.mod(BigInteger.valueOf(p)).signum() == 0) return new ModulusCheck(false, "modulus has the small prime factor " + p);
        }
        return new ModulusCheck(true, null);
    }
}
