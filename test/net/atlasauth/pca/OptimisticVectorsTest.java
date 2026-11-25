package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** The optimistic-path corpus (optimistic-vectors.json): bonded claims, challenge windows, fraud proofs and settlement records. */
public class OptimisticVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("optimistic-vectors.json");

    private static double d(Object o) { return IntentJs.num(o); }

    private static String check(Map<String, Object> v) { return (String) Track3Vectors.mapOrNull(v.get("expect")).get("check"); }

    @Test void claims() {
        Map<String, Object> wp = Track3Vectors.mapOrNull(DOC.get("window_policy"));
        Optimistic.ChallengeWindowPolicy pol = new Optimistic.ChallengeWindowPolicy(d(wp.get("minWindowMs")), d(wp.get("maxWindowMs")), d(wp.get("maxSkewMs")));
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "optimistic_claim")) {
            String got = Optimistic.claimCheck(v.get("claim"), (String) v.get("pcactn_digest"), (String) v.get("signer_public"), d(v.get("server_now")), pol);
            assertEquals(check(v), got, "claim/" + v.get("name"));
            assertEquals(Track3Vectors.expectOk(v), got.equals("ok"), "claim ok/" + v.get("name"));
        }
    }

    @Test void windows() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "optimistic_window")) {
            double i = d(v.get("issued_at")), w = d(v.get("challenge_window_ms")), now = d(v.get("now"));
            Map<String, Object> exp = Track3Vectors.mapOrNull(v.get("expect"));
            String name = "window/" + v.get("name");
            assertEquals(d(exp.get("end")), Optimistic.challengeWindowEnd(i, w), name);
            assertEquals(exp.get("within"), Optimistic.withinChallengeWindow(i, w, now), name);
            assertEquals(exp.get("phase"), Optimistic.claimStatus(i, w, now), name);
        }
    }

    @Test void fraudProofs() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "optimistic_fraud_proof")) {
            assertEquals(check(v), Optimistic.fraudProofWireCheck(v.get("claim"), v.get("proof")), "fraud/" + v.get("name"));
        }
    }

    @Test void settlements() {
        for (Map<String, Object> v : Track3Vectors.rows(DOC, "optimistic_settlement")) {
            assertEquals(Track3Vectors.lacks(v) ? "suite" : check(v), Optimistic.settlementWireCheck(v.get("record"), (String) v.get("guardian_public"), Track3Vectors.pins(v)), "settlement/" + v.get("name"));
        }
    }
}
