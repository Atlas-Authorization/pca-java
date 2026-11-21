package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.Pca;

/** The content digests of the goal-to-decision flow (strict canonical JSON: safe integers only; a float or cycle throws). */
public final class GoalDigests {
    private GoalDigests() {}

    /** Digest of the whole signed Goal. */
    public static String goalDigest(Object goal) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-ir/v1", "goal", goal)); }

    /** Digest of the instruction text a goal was interpreted from. */
    public static String nlDigest(String instruction) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-nl/v1", "text", instruction)); }

    /** Digest of the model set: sorted (code-unit order), de-duplicated ids. */
    public static String modelSetDigest(List<String> models) {
        return Pca.hashCanonical(G.map("d", "atlas-pca/goal-model-set/v1", "models", new ArrayList<Object>(new TreeSet<>(models))));
    }

    /** Digest of an approval's covered fields (the digests it pins plus its expiry). */
    public static String approvalDigest(Map<String, Object> body) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-approval-body/v1", "body", body)); }
}
