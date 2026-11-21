package net.atlasauth.pca.vdf;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.atlasauth.pca.Pca;

/**
 * PCA timelock: a mandatory, offline-verifiable cooling-off on an irreversible action, enforced by a canonical Wesolowski VDF.
 * The VDF input is bound to the action AND to a beacon (an unpredictable, time-ordered value the caller validates):
 * {@code x = H(domain || len||actionDigest || len||beacon) mod N}. Limits are those of the reference: a work proof, not a clock.
 */
public final class Timelock {
    private Timelock() {}

    private static final byte[] X_DOMAIN = "atlas-pca/vdf/timelock/input/v2\0".getBytes(StandardCharsets.UTF_8);

    /** The derived requirement: input x, step count, modulus, and the digest x came from. */
    public static final class TimelockRequirement {
        public final String kind = "vdf-timelock";
        public final BigInteger x, N;
        public final long steps;
        public final String actionDigest;
        TimelockRequirement(BigInteger x, long steps, BigInteger N, String actionDigest) { this.x = x; this.steps = steps; this.N = N; this.actionDigest = actionDigest; }
    }

    /** A timelock proof: canonical y, pi, and the step count it attests to (a JavaScript number, so any double). */
    public static final class TimelockProof {
        public final String kind;
        public final BigInteger y, pi;
        public final double steps;
        public TimelockProof(String kind, BigInteger y, BigInteger pi, double steps) { this.kind = kind; this.y = y; this.pi = pi; this.steps = steps; }
    }

    /** The digest a timelock binds to: a String is an opaque digest; a PCActn (JSON object) uses the canonical hash. */
    public static String actionDigest(Object action) {
        return action instanceof String ? (String) action : Pca.hashCanonical(action);
    }

    private static byte[] beaconBytes(Object beacon) {
        byte[] b = beacon instanceof String ? Json.utf8(((String) beacon)) : beacon instanceof byte[] ? (byte[]) beacon : null;
        if (b == null || b.length == 0) throw new IllegalArgumentException("timelock: a non-empty beacon (unpredictable, post-action value) is required");
        return b;
    }

    private static void lp(ByteArrayOutputStream out, byte[] b) {
        out.writeBytes(new byte[] {(byte) (b.length >>> 24), (byte) (b.length >>> 16), (byte) (b.length >>> 8), (byte) b.length});
        out.writeBytes(b);
    }

    /** {@code x in [2, N)} bound to the action and beacon; deterministic. */
    public static BigInteger deriveTimelockInput(Object action, BigInteger N, Object beacon) {
        if (N == null || N.compareTo(BigInteger.valueOf(3)) <= 0) throw new IllegalArgumentException("deriveTimelockInput: modulus N must be a bigint > 3");
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(X_DOMAIN);
        lp(m, Json.utf8(actionDigest(action)));
        lp(m, beaconBytes(beacon));
        byte[] h;
        try { h = MessageDigest.getInstance("SHA-256").digest(m.toByteArray()); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        BigInteger raw = Vdf.bytesToBigInt(h).mod(N);
        return raw.compareTo(BigInteger.ONE) <= 0 ? raw.add(BigInteger.TWO) : raw;
    }

    private static void requireProductionModulus(BigInteger N, boolean allowInsecureDevModulus) {
        if (allowInsecureDevModulus) return;
        Vdf.ModulusCheck c = Vdf.checkProductionModulus(N);
        if (!c.ok) {
            throw new IllegalArgumentException("timelock: refusing this modulus: " + c.reason
                + ". Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.");
        }
    }

    private static long requireSteps(double steps) {
        if (!Vdf.isSafeSteps(steps) || steps < 1) throw new IllegalArgumentException("timelock: steps must be a safe integer >= 1, got " + steps);
        return (long) steps;
    }

    /** The requirement for an action: derives the VDF input and carries steps and modulus. */
    public static TimelockRequirement requireTimelock(Object action, long steps, BigInteger N, Object beacon, boolean allowInsecureDevModulus) {
        long s = requireSteps(steps);
        requireProductionModulus(N, allowInsecureDevModulus);
        BigInteger x = deriveTimelockInput(action, N, beacon);
        return new TimelockRequirement(x, s, N, actionDigest(action));
    }

    /** Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow. */
    public static TimelockProof proveTimelockElapsed(Object action, long steps, BigInteger N, Object beacon, boolean allowInsecureDevModulus) {
        long s = requireSteps(steps);
        requireProductionModulus(N, allowInsecureDevModulus);
        BigInteger x = deriveTimelockInput(action, N, beacon);
        Vdf.VdfProof p = Vdf.vdfEvalCanonical(x, s, N);
        return new TimelockProof("vdf-timelock-proof", p.y, p.pi, s);
    }

    /** Gate release on a valid proof for THIS action, beacon, step count and modulus. Fails closed (false, never throws). */
    public static boolean verifyTimelock(Object action, TimelockProof proof, double steps, BigInteger N, Object beacon, boolean allowInsecureDevModulus) {
        try {
            long required = requireSteps(steps);
            requireProductionModulus(N, allowInsecureDevModulus);
            if (proof == null || !"vdf-timelock-proof".equals(proof.kind)) return false;
            if (!Vdf.isSafeSteps(proof.steps) || proof.steps != required) return false;
            if (proof.y == null || proof.pi == null) return false;
            BigInteger x = deriveTimelockInput(action, N, beacon);
            return Vdf.vdfVerifyCanonical(x, proof.y, proof.pi, required, N);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** What {@link #calibrateSteps} measured: the step count and the assumed rates. */
    public static final class Calibration {
        public final long steps;
        public final double measuredSquaringsPerSecond, assumedAdversarySquaringsPerSecond;
        Calibration(long steps, double measured, double assumed) { this.steps = steps; this.measuredSquaringsPerSecond = measured; this.assumedAdversarySquaringsPerSecond = assumed; }
    }

    /**
     * Time a sample of squarings mod {@code n} on this machine and size a timelock for {@code desiredSeconds} against a conservative adversary
     * ({@code adversaryAdvantage} times faster than the measured rate). Treat the resulting wall clock as a FLOOR (the honest party may be slower).
     * {@code nowNanos} null is {@link System#nanoTime}; {@code sampleSquarings} null is 50000, {@code adversaryAdvantage} null is 10.
     */
    public static Calibration calibrateSteps(BigInteger n, double desiredSeconds, Integer sampleSquarings, Double adversaryAdvantage, java.util.function.LongSupplier nowNanos) {
        if (n == null || n.compareTo(BigInteger.valueOf(3)) <= 0) throw new IllegalArgumentException("calibrateSteps: modulus N must be > 3");
        if (Double.isNaN(desiredSeconds) || Double.isInfinite(desiredSeconds) || desiredSeconds <= 0) throw new IllegalArgumentException("calibrateSteps: desiredSeconds must be > 0");
        int sample = sampleSquarings != null ? sampleSquarings : 50_000;
        double advantage = adversaryAdvantage != null ? adversaryAdvantage : 10;
        if (sample < 1) throw new IllegalArgumentException("calibrateSteps: sampleSquarings must be an integer >= 1");
        if (Double.isNaN(advantage) || Double.isInfinite(advantage) || advantage < 1) throw new IllegalArgumentException("calibrateSteps: adversaryAdvantage must be >= 1");
        java.util.function.LongSupplier clock = nowNanos != null ? nowNanos : System::nanoTime;
        BigInteger y = BigInteger.TWO.mod(n);
        long t0 = clock.getAsLong();
        for (int i = 0; i < sample; i++) y = y.multiply(y).mod(n);
        double elapsedMs = Math.max((clock.getAsLong() - t0) / 1e6, Double.MIN_VALUE);
        if (y.signum() < 0) throw new IllegalStateException("unreachable"); // keeps the loop live
        double measured = sample / elapsedMs * 1000;
        double assumed = measured * advantage;
        return new Calibration(Math.max(1L, (long) Math.ceil(assumed * desiredSeconds)), measured, assumed);
    }
}
