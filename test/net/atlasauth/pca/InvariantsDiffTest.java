package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.invariants.Invariants;
import org.junit.jupiter.api.Test;

class InvariantsDiffTest {
    private static final String M = "ref-invariants";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    /** {"$bytes": b64u} members become byte[] (the JSON args of a case carry bytes that way). */
    @SuppressWarnings("unchecked")
    private static Object rev(Object v) {
        if (v instanceof List) { List<Object> out = new java.util.ArrayList<>(); for (Object x : (List<Object>) v) out.add(rev(x)); return out; }
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            if (m.size() == 1 && m.get("$bytes") instanceof String) return Keys.unb64u((String) m.get("$bytes"));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) out.put(e.getKey(), rev(e.getValue()));
            return out;
        }
        return v;
    }

    @Test void keyPairFromSeed() throws Exception { OracleCases.each(M, "keyPairFromSeed", a -> Invariants.keyPairFromSeed((byte[]) rev(a.get(0))).toMap()); }

    @Test void buildChain() throws Exception { OracleCases.each(M, "buildChain", a -> Invariants.buildChain(map(rev(a.get(0))))); }

    @Test void worsen() throws Exception { OracleCases.each(M, "worsen", a -> Invariants.worsen(map(a.get(0)), map(a.get(1)))); }

    @Test void consts() throws Exception {
        OracleCases.each(M, "consts", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("DEFAULT_SEED", Invariants.DEFAULT_SEED);
            m.put("DEFAULT_NUM_RUNS", Invariants.DEFAULT_NUM_RUNS);
            m.put("INVARIANT_NAMES", Invariants.INVARIANT_NAMES);
            return m;
        });
    }
}
