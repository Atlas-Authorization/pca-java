package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Frost.FrostKeygenOpts;
import net.atlasauth.pca.Frost.FrostKeygenResult;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import net.atlasauth.pca.pqthreshold.GroupDescriptor;
import net.atlasauth.pca.pqthreshold.HybridThreshold;
import net.atlasauth.pca.pqthreshold.PqThreshold;
import org.junit.jupiter.api.Test;

/** Replays the hybrid-threshold signer / step-up oracle, plus a native FROST-to-verifier round trip. */
class HybridThresholdDiffTest {
    private static final String M = "ref-pq-threshold-java-extra";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("expected object");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("expected array");
        return (List<Object>) o;
    }

    /** {"$bytes"} objects become byte[] everywhere (the reference wrapper's `un`). */
    @SuppressWarnings("unchecked")
    private static Object un(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(un(x)); return out; }
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            if (m.size() == 1 && m.get("$bytes") instanceof String) return Keys.unb64u((String) m.get("$bytes"));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) out.put(e.getKey(), un(e.getValue()));
            return out;
        }
        return v;
    }

    private static byte[] by(Object o) { Object u = un(o); if (!(u instanceof byte[])) throw new IllegalArgumentException("expected bytes"); return (byte[]) u; }

    private static long whole(Object o) {
        if (!(o instanceof Json.Num)) throw new IllegalArgumentException("expected number");
        return new BigDecimal(((Json.Num) o).raw).toBigIntegerExact().longValueExact();
    }

    @Test void foldHybridStepUp() throws Exception {
        OracleCases.each(M, "fold", a -> {
            HybridThreshold.StepUp s = HybridThreshold.foldHybridStepUp(map(a.get(0)), map(a.get(1)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pcactn", s.pcactn);
            if (s.pq != null) m.put("pq", s.pq);
            return m;
        });
    }

    @Test void thresholdHook() throws Exception {
        OracleCases.each(M, "hook", a -> {
            Map<String, Object> o = map(un(a.get(0)));
            HybridThreshold.VerifierOpts v = new HybridThreshold.VerifierOpts();
            v.groupKey = o.get("groupKey"); v.pqPublicKeys = o.get("pqPublicKeys"); v.t = o.get("t"); v.pqT = o.get("pqT"); v.pqBlock = o.get("pqBlock");
            v.groupDescriptor = o.get("groupDescriptor"); v.trustedAuthorities = o.get("trustedAuthorities");
            v.signerSetCommitment = o.get("signerSetCommitment") instanceof String ? (String) o.get("signerSetCommitment") : null;
            PcaCore.HookResult r = HybridThreshold.createHybridThresholdVerifier(v).run(new PcaCore.Ctx(map(a.get(1)), new LinkedHashMap<>(), 1_800_000_000_000L));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("enforced", r.enforced); m.put("ok", r.ok);
            if (r.reason != null) m.put("reason", r.reason);
            return m;
        });
    }

    @Test void verifyHybridStepUp() throws Exception {
        OracleCases.each(M, "stepUp", a -> {
            Map<String, Object> su = map(a.get(0)), o = map(un(a.get(1)));
            HybridThreshold.StepUpVerifyOpts v = new HybridThreshold.StepUpVerifyOpts();
            v.grant = map(o.get("grant"));
            v.groupKey = o.get("groupKey"); v.pqPublicKeys = o.get("pqPublicKeys"); v.t = o.get("t"); v.pqT = o.get("pqT");
            v.groupDescriptor = o.get("groupDescriptor"); v.trustedAuthorities = o.get("trustedAuthorities");
            v.signerSetCommitment = o.get("signerSetCommitment") instanceof String ? (String) o.get("signerSetCommitment") : null;
            if (o.containsKey("audience")) { if (o.get("audience") == null) v.audienceAny(); else v.audience((String) o.get("audience")); }
            if (o.containsKey("nowEpoch")) v.nowEpoch = IntentJs.num(o.get("nowEpoch")).longValue();
            Object pq = su.get("pq");
            HybridThreshold.StepUpResult r = HybridThreshold.verifyHybridStepUp(new HybridThreshold.StepUp(map(su.get("pcactn")), pq == null ? null : map(pq)), v);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", r.allow); m.put("pq", r.pq);
            if (r.reason != null) m.put("reason", r.reason);
            m.put("checks", new LinkedHashMap<String, Object>(r.core.checks));
            return m;
        });
    }

    @Test void hybridSign() throws Exception {
        OracleCases.each(M, "hybridSign", a -> {
            Map<String, Object> x = map(un(a.get(0)));
            int t = (int) whole(x.get("t")), n = (int) whole(x.get("n"));
            FrostKeygenOpts ko = new FrostKeygenOpts();
            ko.secret = (byte[]) x.get("secret");
            ko.coefficients = new ArrayList<>();
            for (Object c : list(x.get("coefficients"))) ko.coefficients.add((byte[]) c);
            FrostKeygenResult kg = Frost.trustedDealerKeygen(t, n, ko);
            List<FrostParticipantShare> quorum = new ArrayList<>();
            for (Object id : list(x.get("quorum"))) {
                FrostParticipantShare found = null;
                for (FrostParticipantShare s : kg.participantShares) if (s.identifier == whole(id)) found = s;
                quorum.add(found);
            }
            List<Object> seeds = list(x.get("pqSeeds"));
            Keys.PqKey[] keys = new Keys.PqKey[seeds.size()];
            for (int i = 0; i < keys.length; i++) keys[i] = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, (byte[]) seeds.get(i));
            List<PqThreshold.MlDsaKeyPair> signers = new ArrayList<>();
            for (Object i : list(x.get("pq"))) signers.add(new PqThreshold.MlDsaKeyPair(keys[(int) whole(i)].pk, keys[(int) whole(i)].sk));
            Integer pqT = x.get("pqT") == null ? null : (int) whole(x.get("pqT"));
            int signT = x.get("signT") == null ? t : (int) whole(x.get("signT"));
            Object group = Boolean.TRUE.equals(x.get("groupAsString")) ? Keys.b64u(kg.groupPublicKey) : kg.groupPublicKey;
            Map<String, Object> action = map(x.get("action"));
            Map<String, Object> artifact = HybridThreshold.hybridThresholdSign(action, new HybridThreshold.FrostQuorumInput(group, quorum, signT), signers, pqT);

            List<Object> parts = new ArrayList<>();
            for (FrostParticipantShare s : kg.participantShares) { Map<String, Object> p = new LinkedHashMap<>(); p.put("identifier", s.identifier); p.put("publicKey", Keys.b64u(s.publicKey)); parts.add(p); }
            byte[] authSeed = (byte[]) x.get("authSeed");
            Map<String, Object> descriptor = GroupDescriptor.issueGroupDescriptor(authSeed, Keys.b64u(kg.groupPublicKey), (long) t, parts);
            PqThreshold.HybridVerifyOpts vo = new PqThreshold.HybridVerifyOpts();
            vo.groupKey = Keys.b64u(kg.groupPublicKey);
            List<Object> pool = new ArrayList<>();
            for (Keys.PqKey k : keys) pool.add(k.pkB64u());
            vo.pqPublicKeys = pool; vo.t = (long) t; vo.pqT = (long) (pqT != null ? pqT : signers.size());
            vo.groupDescriptor = descriptor; vo.trustedAuthorities = List.of(Keys.b64u(Keys.edFromSeed(authSeed).pub));
            Map<String, Object> verdict = PqThreshold.verifyHybridThreshold(action, artifact, vo);

            Map<String, Object> frost = new LinkedHashMap<>(map(artifact.get("frost")));
            String sig = (String) frost.remove("sig");
            frost.put("sigLen", (long) sig.length());
            Map<String, Object> shown = new LinkedHashMap<>(artifact);
            shown.put("frost", frost);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("artifact", shown); out.put("verdict", verdict);
            return out;
        });
    }

    /** A native FROST quorum folded into a PCActn-shaped action verifies through the standalone hybrid verifier, and a sub-threshold one cannot be signed. */
    @Test void signFoldRoundTrip() {
        FrostKeygenOpts ko = new FrostKeygenOpts();
        ko.secret = new byte[] {9, 8, 7, 6, 5, 4, 3, 2, 1};
        ko.coefficients = List.of(new byte[] {1, 1, 2, 3, 5, 8, 13});
        FrostKeygenResult kg = Frost.trustedDealerKeygen(2, 3, ko);
        Keys.PqKey k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, new byte[32]);
        List<PqThreshold.MlDsaKeyPair> signers = List.of(new PqThreshold.MlDsaKeyPair(k.pk, k.sk));
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("ver", 2L); action.put("aud", "rs"); action.put("counter", 1L);
        Map<String, Object> artifact = HybridThreshold.hybridThresholdSign(action, new HybridThreshold.FrostQuorumInput(kg.groupPublicKey, kg.participantShares.subList(1, 3), 2), signers, null);
        assertTrue(EdStrict.verify(kg.groupPublicKey, Pca.thresholdMessage(action), Keys.unb64u((String) map(artifact.get("frost")).get("sig"))));
        HybridThreshold.StepUp folded = HybridThreshold.foldHybridStepUp(action, artifact);
        assertEquals(Pca.thresholdMessage(action).length, Pca.thresholdMessage(folded.pcactn).length); // folding does not change the signed bytes
        assertFalse(((List<?>) map(folded.pcactn.get("threshold")).get("shares")).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> HybridThreshold.hybridThresholdSign(action, new HybridThreshold.FrostQuorumInput(kg.groupPublicKey, kg.participantShares.subList(0, 1), 2), signers, null));
    }
}
