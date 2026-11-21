package net.atlasauth.pca.goal;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import net.atlasauth.pca.Decision;
import net.atlasauth.pca.Pca;

/** The decision-to-effect binding and the claimed-fidelity gate of goal-to-decision. */
public final class GoalBinding {
    private GoalBinding() {}

    /** Digest of exactly the action that was decided: verb, resource and every parameter. */
    public static String actionDigest(Map<String, Object> act) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-action/v1", "act", act)); }

    /** Bind a decision to the action it was made for: {decision, action_digest}. */
    public static Map<String, Object> bindDecision(Map<String, Object> act, String decision) {
        return G.map("decision", decision, "action_digest", actionDigest(act));
    }

    private static boolean ctEq(String x, String y) {
        return MessageDigest.isEqual(Json.utf8(x), Json.utf8(y));
    }

    /** Run guard: true only for an {@code allow} bound to exactly this action. Total. */
    public static boolean guardExecute(Map<String, Object> bound, Map<String, Object> executed) {
        try {
            if (!"allow".equals(bound.get("decision"))) return false;
            Object d = bound.get("action_digest");
            return d instanceof String && ctEq((String) d, actionDigest(executed));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, and only downward.
     * {@code replayedPpm} null = not replayed; a NaN replay is unconfirmed and tightens.
     */
    public static String claimGate(String base, double minPpm, Double replayedPpm) {
        return replayedPpm != null && !(replayedPpm >= minPpm) ? Decision.tighten(base, "escalate") : base;
    }

    /** Hiding goal commitment (goal binding v3). */
    public static String goalCommit(String goalDigest, String policyDigest, String salt) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.utf8(("pca-goal:v3:commit:" + goalDigest + ":" + policyDigest + ":" + salt)));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Constant-time check that {@code commit} opens to (goal, policy, salt). */
    public static boolean openCommit(String commit, String goalDigest, String policyDigest, String salt) {
        return ctEq(commit, goalCommit(goalDigest, policyDigest, salt));
    }
}
