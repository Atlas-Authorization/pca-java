package net.atlasauth.pca;

/**
 * Public doors onto package-private core helpers, for the sandbox, harness and control-evals ports that live in their own
 * subpackages. Each method is a one-line delegate; no logic is added here.
 */
public final class W3Bridge {
    private W3Bridge() {}

    /** True iff {@code sig} is a canonical 64-byte base64url Ed25519 signature by the canonical 32-byte base64url key {@code pub} over {@code msg}. */
    public static boolean verifyB64u(String pub, byte[] msg, String sig) { return Pca.verifyB64u(pub, msg, sig); }

    /** The strict canonical JSON bytes of a value. */
    public static byte[] canonBytes(Object v) { return Pca.canonBytes(v); }

    /** Risk score of the six inputs (semanticDistance, reversibility, blastRadius, taint, confidence, age) under the weights map. */
    public static double riskScore(double[] inputs, java.util.Map<String, Object> weights) { return Risk.riskScore(inputs, weights); }

    /** The required threshold (1..3) of a risk, optimistic acceptance ignored. */
    public static int requiredThreshold(double r, double theta1, double theta2, boolean irreversible) { return Risk.requiredThreshold(r, theta1, theta2, irreversible).t; }

    /** c(A) = kappa r(A). */
    public static double cost(double r, double kappa) { return Risk.cost(r, kappa); }

    /** Passive leak of a trust budget {B, tau, asOf}: returns {B, tau, asOf}. */
    public static double[] leak(double b, double tau, double asOf, double now, double lambda) {
        Risk.Budget l = Risk.leak(new Risk.Budget(b, tau, asOf), now, lambda);
        return new double[] {l.b, l.tau, l.asOf};
    }

    /** B = max(0, B - cost): returns {B, tau, asOf}. */
    public static double[] debit(double b, double tau, double asOf, double c) {
        Risk.Budget d = Risk.debit(new Risk.Budget(b, tau, asOf), c);
        return new double[] {d.b, d.tau, d.asOf};
    }
}
