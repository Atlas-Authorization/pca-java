package net.atlasauth.pca.goal;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The pure parts of the typed compiler front door. The compiler itself (typecheck, compile, the Dafny-extracted decision
 * functions) is the proved reference and is not re-implemented here: the native decision semantics live in
 * {@code net.atlasauth.pca.GoalSemantics} and {@link GoalRefsem}; this class holds the policy canonical form and digest
 * and the tape codec entry points.
 */
public final class GoalCompiler {
    private GoalCompiler() {}

    /** Canonical bytes of a policy (sorted-key JSON, no floats): the input of the policy digest. */
    public static String canonicalPolicy(Map<String, Object> p) { return G.stable(p); }

    public static String policyDigest(Map<String, Object> p) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.utf8(canonicalPolicy(p)));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The goal as a token tape: the proved kernel's rendering ({@link GoalKernel#renderTape}); {@code decodeGoal(renderTape(g))} equals g. */
    public static List<Object> renderTape(Map<String, Object> goal) { return GoalKernel.renderTape(goal); }
}
