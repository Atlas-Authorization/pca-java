package net.atlasauth.pca.mpc;

import java.util.Map;
import net.atlasauth.pca.Decide;

/** Per-stakeholder local evaluation: each party distills its own Policy VM result to a small decision vector. */
public final class Party {
    private Party() {}

    public static final int DEFAULT_Q = 100;

    /** The decision a party contributes to the MPC: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}. */
    public record DecisionVector(int allow, int t, int rQuant) {}

    /** Quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q). */
    public static int quantizeR(double r, int Q) {
        if (Double.isNaN(r) || Double.isInfinite(r)) return Q;
        long q = Math.round(Math.max(0, Math.min(1, r)) * Q);
        // Math.round (floor(x+0.5)) matches JS Math.round for the non-negative values reached here
        return (int) Math.max(0, Math.min(Q, q));
    }

    public static int quantizeR(double r) { return quantizeR(r, DEFAULT_Q); }

    /** Evaluates a party's own decide input through the Policy VM to its decision vector. */
    public static DecisionVector evaluateParty(Map<String, Object> decideInput, int Q) {
        Map<String, Object> d = Decide.decide(decideInput);
        @SuppressWarnings("unchecked") Map<String, Object> thr = (Map<String, Object>) d.get("requiredThreshold");
        Object r = d.get("r");
        return new DecisionVector(
            Boolean.TRUE.equals(d.get("releaseGuardianShare")) ? 1 : 0,
            ((Number) thr.get("t")).intValue(),
            quantizeR(r instanceof Number ? ((Number) r).doubleValue() : Double.NaN, Q));
    }

    public static DecisionVector evaluateParty(Map<String, Object> decideInput) { return evaluateParty(decideInput, DEFAULT_Q); }
}
