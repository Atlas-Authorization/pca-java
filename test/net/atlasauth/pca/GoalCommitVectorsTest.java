package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Goal binding v3 (approved_goal): the shared goal-commit vectors (commit, invalid, binding) plus the unit checks that fail
 * without the validation. A missing vector file or an empty table FAILS.
 */
public class GoalCommitVectorsTest {
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> table(Map<String, Object> doc, String name, int size) {
        Object t = doc.get(name);
        assertTrue(t instanceof List, name + ": missing table");
        assertEquals(size, ((List<?>) t).size(), name + ": vector count");
        return (List<Map<String, Object>>) (List<?>) t;
    }

    private static Map<String, Object> grantWith(Object commit) {
        Map<String, Object> grant = new LinkedHashMap<>();
        List<Object> caveats = new ArrayList<>();
        if (commit != null) {
            Map<String, Object> env = new LinkedHashMap<>();
            env.put("type", "envelope");
            env.put("goal_commit", commit);
            caveats.add(env);
        }
        grant.put("caveats", caveats);
        return grant;
    }

    @Test void commitVectors() {
        Map<String, Object> doc = Track3Vectors.load("goal-commit-vectors.json");
        for (Map<String, Object> v : table(doc, "commit", 7)) {
            Map<String, Object> ref = Pca.approvedGoal((String) v.get("goal_digest"), (String) v.get("policy_digest"));
            assertTrue(Pca.isApprovedGoalRef(ref), (String) v.get("name"));
            assertEquals(v.get("goal"), Pca.intentGoalV3(ref), (String) v.get("name"));
            assertEquals(v.get("commit"), Pca.intentGoalCommitV3(ref, (String) v.get("salt")), (String) v.get("name"));
        }
    }

    @Test void invalidDigestsAreRefused() {
        Map<String, Object> doc = Track3Vectors.load("goal-commit-vectors.json");
        for (Map<String, Object> v : table(doc, "invalid", 4)) {
            Map<String, Object> ref = Pca.approvedGoal((String) v.get("goal_digest"), (String) v.get("policy_digest"));
            assertFalse(Pca.isApprovedGoalRef(ref), (String) v.get("name"));
            assertThrows(IllegalArgumentException.class, () -> Pca.intentGoalV3(ref), (String) v.get("name"));
            assertThrows(IllegalArgumentException.class, () -> Pca.intentGoalCommitV3(ref, "s"), (String) v.get("name"));
        }
    }

    @Test void bindingVectors() {
        Map<String, Object> doc = Track3Vectors.load("goal-commit-vectors.json");
        for (Map<String, Object> v : table(doc, "binding", 16)) {
            String name = (String) v.get("name");
            Object intent = v.get("intent");
            Pca.IntentPolicy policy = Pca.IntentPolicy.fromJson(v.get("policy"));
            assertNotNull(policy, name);
            String session = v.get("session") instanceof String ? (String) v.get("session") : null;
            String got = Pca.decideIntent(intent, intent != null, grantWith(v.get("grant_commit")), policy, session, null);
            assertEquals("pass".equals(v.get("expect")), "".equals(got), name + ": " + got);
        }
    }

    @Test void policyIsClosedAndImpliesRequire() {
        String good = Pca.b64(new byte[32]); // a canonical 32-byte digest, built at run time
        Pca.IntentPolicy p = Pca.IntentPolicy.approvedGoalPolicy(good, good);
        assertTrue(p.isActive());
        // an active policy and a PCActn without an intent: fails closed
        assertEquals("this verifier requires an intent binding but the PCActn carries none", Pca.decideIntent(null, false, grantWith("x"), p, null, null));
        // an explicit JSON null (or any non-object) approved_goal is a misconfiguration, not "unset"
        Pca.IntentPolicy bad = Pca.IntentPolicy.fromJson(Json.parseLenient("{\"approved_goal\":null}"));
        assertTrue(bad.isActive());
        assertTrue(Pca.decideIntent(null, false, grantWith("x"), bad, null, null).startsWith("intent policy misconfigured: approved_goal"));
        Pca.IntentPolicy extra = Pca.IntentPolicy.fromJson(Json.parseLenient(
            "{\"approved_goal\":{\"goal_digest\":\"" + good + "\",\"policy_digest\":\"" + good + "\",\"x\":1}}"));
        assertTrue(Pca.decideIntent(null, false, grantWith("x"), extra, null, null).startsWith("intent policy misconfigured: approved_goal"));
        // a v3 grant commits to the digests it was minted for, whichever salt: the same digests with another salt do not open
        String commit = Pca.intentGoalCommitV3(Pca.approvedGoal(good, good), "s");
        Map<String, Object> intent = new LinkedHashMap<>();
        intent.put("ref", good);
        intent.put("map_digest", good);
        intent.put("goal_salt", "s");
        intent.put("fidelity_ppm", IntentJs.ofLong(900_000));
        intent.put("residual_risk_ppm", IntentJs.ofLong(1));
        assertEquals("", Pca.decideIntent(intent, true, grantWith(commit), p, null, null));
        intent.put("goal_salt", "t");
        assertTrue(Pca.decideIntent(intent, true, grantWith(commit), p, null, null).contains("does not open to the approved goal and compiled policy (v3)"));
    }
}
