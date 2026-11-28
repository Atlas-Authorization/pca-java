package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.pqthreshold.GroupDescriptor;
import net.atlasauth.pca.pqthreshold.PqThreshold;
import org.junit.jupiter.api.Test;

class PqThresholdDiffTest {
    private static final String M = "ref-pq-threshold";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

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

    private static byte[] by(Object o) {
        Object u = un(o);
        if (!(u instanceof byte[])) throw new IllegalArgumentException("expected bytes");
        return (byte[]) u;
    }

    @Test void signerSetCommitment() throws Exception {
        OracleCases.each(M, "signerSetCommitment", a -> {
            if (!(a.get(0) instanceof List)) throw new IllegalArgumentException("participants must be an array");
            return GroupDescriptor.signerSetCommitment((List<?>) un(a.get(0)));
        });
    }

    @Test void issueGroupDescriptor() throws Exception {
        OracleCases.each(M, "issueGroupDescriptor", a -> {
            Map<String, Object> in = map(a.get(0));
            Object seed = un(in.get("authoritySeed"));
            if (!(in.get("participants") instanceof List)) throw new IllegalArgumentException("participants must be an array");
            return GroupDescriptor.issueGroupDescriptor(seed instanceof byte[] ? (byte[]) seed : null, in.get("groupPublicKey"), in.get("t"), (List<?>) un(in.get("participants")));
        });
    }

    @Test void verifyGroupDescriptor() throws Exception {
        OracleCases.each(M, "verifyGroupDescriptor", a -> {
            Map<String, Object> e = map(a.get(1));
            Object ssc = e.get("signerSetCommitment");
            return GroupDescriptor.verifyGroupDescriptor(a.get(0), e.get("trustedAuthorities"), e.get("groupKey"), e.get("t"), ssc instanceof String ? (String) ssc : null);
        });
    }

    @Test void normalizePqQuorumPool() throws Exception {
        OracleCases.each(M, "normalizePqQuorumPool", a -> {
            List<String> out = new ArrayList<>(PqThreshold.normalizePqQuorumPool((List<?>) un(a.get(0))));
            Collections.sort(out);
            return out;
        });
    }

    @Test void pqQuorumRepresentative() throws Exception { OracleCases.each(M, "pqQuorumRepresentative", a -> PqThreshold.pqQuorumRepresentative(by(a.get(0)))); }

    @Test void verifyPqQuorum() throws Exception {
        OracleCases.each(M, "verifyPqQuorum", a -> PqThreshold.verifyPqQuorum(a.get(0), by(a.get(1)), PqThreshold.normalizePqQuorumPool((List<?>) un(a.get(2))), a.get(3)));
    }

    @Test void verifyHybridThreshold() throws Exception {
        OracleCases.each(M, "verifyHybridThreshold", a -> {
            Map<String, Object> o = map(un(a.get(2)));
            PqThreshold.HybridVerifyOpts opts = new PqThreshold.HybridVerifyOpts();
            opts.groupKey = o.get("groupKey"); opts.pqPublicKeys = o.get("pqPublicKeys"); opts.t = o.get("t"); opts.pqT = o.get("pqT");
            opts.groupDescriptor = o.get("groupDescriptor"); opts.trustedAuthorities = o.get("trustedAuthorities");
            opts.signerSetCommitment = o.get("signerSetCommitment") instanceof String ? (String) o.get("signerSetCommitment") : null;
            return PqThreshold.verifyHybridThreshold(map(a.get(0)), un(a.get(1)), opts);
        });
    }

    // ---- signing round trip (the co-signers and the assembled artifact) ----

    private static byte[] seed(String l) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/ref-pqt-java/" + l).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    @Test void signAssembleAndVerifyRoundTrip() {
        Keys.PqKey k1 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq1")), k2 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq2")), k3 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq3"));
        List<PqThreshold.MlDsaKeyPair> signers = List.of(new PqThreshold.MlDsaKeyPair(k1.pk, k1.sk), new PqThreshold.MlDsaKeyPair(k2.pk, k2.sk));
        Keys.EdKey group = Keys.edFromSeed(seed("group")), authority = Keys.edFromSeed(seed("authority"));
        List<Object> parts = new ArrayList<>();
        for (int i = 1; i <= 3; i++) { Map<String, Object> p = new LinkedHashMap<>(); p.put("identifier", (long) i); p.put("publicKey", Keys.edFromSeed(seed("share" + i)).id()); parts.add(p); }
        Map<String, Object> descriptor = GroupDescriptor.issueGroupDescriptor(seed("authority"), group.id(), 2L, parts);

        Map<String, Object> action = new LinkedHashMap<>();
        action.put("ver", 2L); action.put("aud", "rs"); action.put("counter", 7L);
        byte[] msg = Pca.thresholdMessage(action);
        byte[] aggregate = group.sign(msg);
        Map<String, Object> artifact = PqThreshold.hybridThresholdAssemble(action, group.pub, aggregate, 2, 3, signers, null);

        PqThreshold.HybridVerifyOpts opts = new PqThreshold.HybridVerifyOpts();
        opts.groupKey = group.id(); opts.pqPublicKeys = List.of(k1.pkB64u(), k2.pkB64u(), k3.pkB64u()); opts.t = 2L; opts.pqT = 2L;
        opts.groupDescriptor = descriptor; opts.trustedAuthorities = List.of(authority.id());
        Map<String, Object> ok = PqThreshold.verifyHybridThreshold(action, artifact, opts);
        assertEquals(true, ok.get("ok"), String.valueOf(ok));
        opts.pqT = 3L;
        assertEquals(false, PqThreshold.verifyHybridThreshold(action, artifact, opts).get("ok"));
        opts.pqT = 2L;
        Map<String, Object> other = new LinkedHashMap<>(action);
        other.put("counter", 8L);
        assertEquals(false, PqThreshold.verifyHybridThreshold(other, artifact, opts).get("ok"));
        assertThrows(IllegalArgumentException.class, () -> PqThreshold.hybridThresholdAssemble(other, group.pub, aggregate, 2, 3, signers, null));
        assertThrows(IllegalArgumentException.class, () -> PqThreshold.hybridThresholdAssemble(action, group.pub, aggregate, 3, 2, signers, null));
        assertTrue(GroupDescriptor.signerSetCommitment(parts).length() > 0);
        assertFalse(PqThreshold.normalizePqQuorumPool(List.of("x")).iterator().hasNext());
    }
}
