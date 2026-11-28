package net.atlasauth.pca.aggsig;

import static net.atlasauth.pca.aggsig.Oracle.bytes;
import static net.atlasauth.pca.aggsig.Oracle.bytesList;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference corpus (test-data/ref-aggsig.json.gz) through the native port. */
class AggsigDiffTest {
    private static final String M = "ref-aggsig";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** Register every {pk, pop}; null when any refuses (the reference reports {registerFailed: true}). */
    private static List<RegisteredKey> reg(Object keys) {
        List<RegisteredKey> out = new ArrayList<>();
        for (Object k : (List<?>) keys) {
            Aggsig.RegisterResult r = Aggsig.registerKey(bytes(m(k).get("pk")), bytes(m(k).get("pop")));
            if (!r.ok) return null;
            out.add(r.key);
        }
        return out;
    }

    private static KeyRegistry registry(Object keys) {
        KeyRegistry r = new KeyRegistry();
        for (Object k : (List<?>) keys) if (!r.register(bytes(m(k).get("pk")), bytes(m(k).get("pop"))).ok) return r;
        return r;
    }

    private static Object failed() { Map<String, Object> o = new LinkedHashMap<>(); o.put("registerFailed", Boolean.TRUE); return o; }

    @Test void publicKeyOf() throws Exception { Oracle.each(M, "publicKeyOf", a -> Aggsig.publicKeyOf(bytes(a.get(0)))); }
    @Test void sign() throws Exception { Oracle.each(M, "sign", a -> Aggsig.sign(bytes(a.get(0)), bytes(a.get(1)))); }
    @Test void popProve() throws Exception { Oracle.each(M, "popProve", a -> Aggsig.popProve(bytes(a.get(0)))); }
    @Test void verify() throws Exception { Oracle.each(M, "verify", a -> Aggsig.verify(bytes(a.get(0)), bytes(a.get(1)), bytes(a.get(2)))); }
    @Test void keyValidate() throws Exception { Oracle.each(M, "keyValidate", a -> Aggsig.keyValidate(bytes(a.get(0)))); }

    @Test void registerKey() throws Exception {
        Oracle.each(M, "registerKey", a -> {
            Aggsig.RegisterResult r = Aggsig.registerKey(bytes(a.get(0)), bytes(a.get(1)));
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("ok", r.ok);
            if (!r.ok) o.put("reason", r.reason);
            return o;
        });
    }

    @Test void aggregate() throws Exception { Oracle.each(M, "aggregate", a -> Aggsig.aggregate(bytesList(a.get(0)))); }

    @Test void aggregateVerify() throws Exception {
        Oracle.each(M, "aggregateVerify", a -> {
            List<RegisteredKey> ks = reg(a.get(0));
            return ks == null ? failed() : Aggsig.aggregateVerify(ks, bytesList(a.get(1)), bytes(a.get(2)));
        });
    }

    @Test void fastAggregateVerify() throws Exception {
        Oracle.each(M, "fastAggregateVerify", a -> {
            List<RegisteredKey> ks = reg(a.get(0));
            return ks == null ? failed() : Aggsig.fastAggregateVerify(ks, bytes(a.get(1)), bytes(a.get(2)));
        });
    }

    @Test void mintBlsRoot() throws Exception {
        Oracle.each(M, "mintBlsRoot", a -> AggsigChain.mintBlsRoot(bytes(a.get(0)), (String) a.get(1), (String) a.get(2), (List<?>) a.get(3)));
    }

    @Test void chainDelegate() throws Exception {
        Oracle.each(M, "chainDelegate", a -> AggsigChain.blsDelegate(m(a.get(0)), (String) a.get(1), (List<?>) a.get(2), bytes(a.get(3))));
    }

    @Test void chainAttenuate() throws Exception {
        Oracle.each(M, "chainAttenuate", a -> AggsigChain.blsAttenuate(m(a.get(0)), (List<?>) a.get(1), bytes(a.get(2))));
    }

    @Test void capHash() throws Exception { Oracle.each(M, "capHash", a -> AggsigChain.capHash(m(a.get(0)))); }

    @SuppressWarnings("unchecked")
    @Test void aggregateChainSignatures() throws Exception {
        Oracle.each(M, "aggregateChainSignatures", a -> AggsigChain.aggregateChainSignatures((List<Object>) a.get(0)));
    }

    @SuppressWarnings("unchecked")
    @Test void verifyAggregatedChain() throws Exception {
        Oracle.each(M, "verifyAggregatedChain", a -> AggsigChain.verifyAggregatedChain((List<Object>) a.get(0), bytes(a.get(1)), registry(a.get(2)), (String) a.get(3)));
    }

    @Test void cosignTreeHead() throws Exception { Oracle.each(M, "cosignTreeHead", a -> AggsigWitness.cosignTreeHead(m(a.get(0)), bytes(a.get(1)))); }
    @Test void verifyWitnessCosignature() throws Exception { Oracle.each(M, "verifyWitnessCosignature", a -> AggsigWitness.verifyWitnessCosignature(m(a.get(0)), m(a.get(1)))); }

    @SuppressWarnings("unchecked")
    @Test void aggregateWitnessCosignatures() throws Exception {
        Oracle.each(M, "aggregateWitnessCosignatures", a -> {
            List<Map<String, Object>> cs = new ArrayList<>();
            for (Object c : (List<?>) a.get(0)) cs.add(m(c));
            return AggsigWitness.aggregateWitnessCosignatures(cs);
        });
    }

    @Test void verifyAggregatedWitnessCosignatures() throws Exception {
        Oracle.each(M, "verifyAggregatedWitnessCosignatures", a -> {
            List<RegisteredKey> ks = reg(a.get(1));
            return ks == null ? failed() : AggsigWitness.verifyAggregatedWitnessCosignatures(m(a.get(0)), ks, bytes(a.get(2)));
        });
    }
}
