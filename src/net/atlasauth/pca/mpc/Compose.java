package net.atlasauth.pca.mpc;

import java.util.List;
import net.atlasauth.pca.mpc.Party.DecisionVector;

/**
 * Composition semantics (the "meet" of stakeholder authorities) and the cleartext reference: allow = AND, t = MAX,
 * rQuant = MAX. Composition can only tighten, never loosen.
 */
public final class Compose {
    private Compose() {}

    public record ComposedDecision(int allow, int t, int rQuant) {}

    /** Rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer rQuant in [0,Q]). */
    public static void assertDecisionVectors(List<DecisionVector> vectors, int Q) {
        if (vectors == null) throw new IllegalArgumentException("decision vectors must be an array");
        for (int i = 0; i < vectors.size(); i++) {
            DecisionVector v = vectors.get(i);
            if (v == null) throw new IllegalArgumentException("party " + i + ": decision vector must be an object");
            if (v.allow() != 0 && v.allow() != 1) throw new IllegalArgumentException("party " + i + ": allow must be 0 or 1");
            if (v.t() < 1 || v.t() > 3) throw new IllegalArgumentException("party " + i + ": t must be 1, 2 or 3");
            if (v.rQuant() < 0 || v.rQuant() > Q) throw new IllegalArgumentException("party " + i + ": rQuant must be an integer in [0, " + Q + "]");
        }
    }

    public static ComposedDecision composeClear(List<DecisionVector> vectors, int Q) {
        if (vectors.isEmpty()) throw new IllegalArgumentException("composeClear: no parties (fail closed)");
        assertDecisionVectors(vectors, Q);
        int allow = 1, t = 1, r = 0;
        for (DecisionVector v : vectors) {
            if (v.allow() == 0) allow = 0;
            if (v.t() > t) t = v.t();
            if (v.rQuant() > r) r = v.rQuant();
        }
        return new ComposedDecision(allow, t, r);
    }

    public static ComposedDecision composeClear(List<DecisionVector> vectors) { return composeClear(vectors, Party.DEFAULT_Q); }
}
