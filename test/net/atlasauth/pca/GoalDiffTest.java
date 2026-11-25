package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalBinding;
import net.atlasauth.pca.goal.GoalCard;
import net.atlasauth.pca.goal.GoalCodec;
import net.atlasauth.pca.goal.GoalCompiler;
import net.atlasauth.pca.goal.GoalDigests;
import net.atlasauth.pca.goal.GoalFmt;
import net.atlasauth.pca.goal.GoalNormalize;
import net.atlasauth.pca.goal.GoalRefsem;
import net.atlasauth.pca.goal.GoalSign;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal core: tape codec, digests, normalize, fmt, card, reference semantics, binding, signing. */
class GoalDiffTest {
    private static final String M = "ref-goal";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void encodeGoal() throws Exception { OracleCases.each(M, "encodeGoal", a -> GoalCodec.encodeGoal(m(a.get(0)))); }
    @Test void decodeGoal() throws Exception { OracleCases.each(M, "decodeGoal", a -> GoalCodec.decodeGoal(l(a.get(0)))); }
    @Test void encodeOntology() throws Exception { OracleCases.each(M, "encodeOntology", a -> GoalCodec.encodeOntology(m(a.get(0)))); }
    @Test void encodeAct() throws Exception { OracleCases.each(M, "encodeAct", a -> GoalCodec.encodeAct(m(a.get(0)))); }
    @Test void encodeHist() throws Exception { OracleCases.each(M, "encodeHist", a -> GoalCodec.encodeHist(m(a.get(0)))); }
    @Test void decodePolicy() throws Exception { OracleCases.each(M, "decodePolicy", a -> GoalCodec.decodePolicy(l(a.get(0)))); }

    @Test void goalDigest() throws Exception { OracleCases.each(M, "goalDigest", a -> GoalDigests.goalDigest(a.get(0))); }
    @Test void nlDigest() throws Exception { OracleCases.each(M, "nlDigest", a -> GoalDigests.nlDigest((String) a.get(0))); }
    @Test void modelSetDigest() throws Exception {
        OracleCases.each(M, "modelSetDigest", a -> { List<String> ms = new ArrayList<>(); for (Object x : l(a.get(0))) ms.add((String) x); return GoalDigests.modelSetDigest(ms); });
    }
    @Test void approvalDigest() throws Exception { OracleCases.each(M, "approvalDigest", a -> GoalDigests.approvalDigest(m(a.get(0)))); }
    @Test void canonicalizeGoal() throws Exception { OracleCases.each(M, "canonicalizeGoal", a -> GoalNormalize.canonicalizeGoal(m(a.get(0)))); }
    @Test void stable() throws Exception { OracleCases.each(M, "stable", a -> GoalNormalize.stable(a.get(0))); }

    @Test void fmtMoney() throws Exception { OracleCases.each(M, "fmtMoney", a -> GoalFmt.fmtMoney((String) a.get(0), a.get(1))); }
    @Test void fmtQuantity() throws Exception { OracleCases.each(M, "fmtQuantity", a -> GoalFmt.fmtQuantity(m(a.get(0)))); }
    @Test void fmtValue() throws Exception { OracleCases.each(M, "fmtValue", a -> GoalFmt.fmtValue(m(a.get(0)))); }
    @Test void fmtAct() throws Exception { OracleCases.each(M, "fmtAct", a -> GoalFmt.fmtAct(m(a.get(0)))); }
    @Test void renderCard() throws Exception { OracleCases.each(M, "renderCard", a -> GoalCard.renderCard(m(a.get(0)))); }
    @Test void renderCond() throws Exception { OracleCases.each(M, "renderCond", a -> GoalCard.cond(m(a.get(0)))); }

    @Test void refExplain() throws Exception { OracleCases.each(M, "refExplain", a -> GoalRefsem.refExplain(m(a.get(0)), m(a.get(1)), m(a.get(2)), m(a.get(3)))); }
    @Test void refDecide() throws Exception { OracleCases.each(M, "refDecide", a -> GoalRefsem.refDecide(m(a.get(0)), m(a.get(1)), m(a.get(2)), m(a.get(3)))); }
    @Test void canonicalPolicy() throws Exception { OracleCases.each(M, "canonicalPolicy", a -> GoalCompiler.canonicalPolicy(m(a.get(0)))); }
    @Test void policyDigest() throws Exception { OracleCases.each(M, "policyDigest", a -> GoalCompiler.policyDigest(m(a.get(0)))); }

    @Test void actionDigest() throws Exception { OracleCases.each(M, "actionDigest", a -> GoalBinding.actionDigest(m(a.get(0)))); }
    @Test void bindDecision() throws Exception { OracleCases.each(M, "bindDecision", a -> GoalBinding.bindDecision(m(a.get(0)), (String) a.get(1))); }
    @Test void guardExecute() throws Exception { OracleCases.each(M, "guardExecute", a -> GoalBinding.guardExecute(m(a.get(0)), m(a.get(1)))); }
    @Test void claimGate() throws Exception {
        OracleCases.each(M, "claimGate", a -> GoalBinding.claimGate((String) a.get(0), Double.parseDouble(a.get(1).toString()),
            a.get(2) == null ? null : Double.valueOf(a.get(2).toString())));
    }
    @Test void goalCommit() throws Exception { OracleCases.each(M, "goalCommit", a -> GoalBinding.goalCommit((String) a.get(0), (String) a.get(1), (String) a.get(2))); }
    @Test void openCommit() throws Exception { OracleCases.each(M, "openCommit", a -> GoalBinding.openCommit((String) a.get(0), (String) a.get(1), (String) a.get(2), (String) a.get(3))); }

    @Test void signPayload() throws Exception { OracleCases.each(M, "signPayloadSeed", a -> GoalSign.signPayload((String) a.get(0), a.get(1), Keys.unb64u((String) a.get(2)))); }
    @Test void signGoalArtifact() throws Exception { OracleCases.each(M, "signGoalArtifactSeed", a -> GoalSign.signGoalArtifact((String) a.get(0), m(a.get(1)), Keys.unb64u((String) a.get(2)))); }
    @Test void signerId() throws Exception { OracleCases.each(M, "signerId", a -> GoalSign.signerId(Keys.unb64u((String) a.get(0)))); }
    @Test void goalDomain() throws Exception { OracleCases.each(M, "goalDomain", a -> GoalSign.goalDomain((String) a.get(0))); }
    @Test void verifyPayload() throws Exception { OracleCases.each(M, "verifyPayload", a -> GoalSign.verifyPayload(m(a.get(0)), (String) a.get(1), l(a.get(2)))); }
    @Test void verifyGoalArtifact() throws Exception { OracleCases.each(M, "verifyGoalArtifact", a -> GoalSign.verifyGoalArtifact((String) a.get(0), a.get(1), (String) a.get(2), l(a.get(3)))); }
}
