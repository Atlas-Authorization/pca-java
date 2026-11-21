package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Proof assembly (compaction) and action signing of the mesh against the reference, over scripted multi-domain sequences. */
public class CoreMeshProofDiffTest {
    static final String MODULE = "ref-core-mesh-proof-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Keys.EdKey key(Object label) { return Keys.edFromSeed(CoreStoresDiffTest.seed("mesh-proof/" + label)); }

    static List<Map<String, Object>> chainOf(Object labels) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object l : (List<?>) labels) out.add(CoreMeshDomainDiffTest.cap((String) l));
        return out;
    }

    @Test void meshProof() throws Exception {
        OracleCases.each(MODULE, "meshProof", a -> {
            Map<String, MeshDomain> doms = new HashMap<>();
            Map<String, MeshWitness> ws = new HashMap<>();
            Map<String, Map<String, Object>> store = new HashMap<>();
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "domain": { MeshDomain d = new MeshDomain((String) op.get(1), key(op.get(2))); doms.put((String) op.get(1), d); v = d.id; break; }
                        case "witness": { MeshWitness w = new MeshWitness(key(op.get(2))); ws.put((String) op.get(1), w); v = w.id; break; }
                        case "record": v = doms.get((String) op.get(1)).record(CoreMeshDomainDiffTest.cap((String) op.get(2))); break;
                        case "revoke": doms.get((String) op.get(1)).revoke((String) op.get(2)); break;
                        case "publish": {
                            List<MeshWitness> list = new ArrayList<>();
                            for (Object w : (List<?>) op.get(4)) list.add(ws.get((String) w));
                            Map<String, Object> h = doms.get((String) op.get(1)).publishHead(list, StoreJs.dbl(op.get(3)), op.get(5) == null ? null : (int) (double) StoreJs.dbl(op.get(5)));
                            store.put((String) op.get(2), h);
                            v = h;
                            break;
                        }
                        case "subcos": {
                            Map<String, Object> h = new LinkedHashMap<>(need(store, op.get(2)));
                            List<Object> keep = new ArrayList<>();
                            List<?> all = (List<?>) h.get("cosigs");
                            for (Object i : (List<?>) op.get(3)) keep.add(all.get((int) (double) StoreJs.dbl(i)));
                            h.put("cosigs", keep);
                            store.put((String) op.get(1), h);
                            break;
                        }
                        case "fork": { Map<String, Object> h = new LinkedHashMap<>(need(store, op.get(2))); h.put((String) op.get(3), op.get(4)); store.put((String) op.get(1), h); break; }
                        case "forkHead": {
                            Map<String, Object> h = new LinkedHashMap<>(need(store, op.get(2)));
                            Map<String, Object> inner = new LinkedHashMap<>(m(h.get("head")));
                            inner.put((String) op.get(3), op.get(4));
                            h.put("head", inner);
                            store.put((String) op.get(1), h);
                            break;
                        }
                        case "enroll": { Map<String, Object> b = doms.get((String) op.get(1)).enroll((String) op.get(3), (String) op.get(4)); store.put((String) op.get(2), b); v = b; break; }
                        case "ev": {
                            Map<String, Object> e = doms.get((String) op.get(1)).evidence(CoreMeshDomainDiffTest.cap((String) op.get(3)), need(store, op.get(4)), op.get(5) == null ? null : need(store, op.get(5)));
                            store.put((String) op.get(2), e);
                            v = e;
                            break;
                        }
                        case "setEv": {
                            Map<String, Object> e = new LinkedHashMap<>(need(store, op.get(2)));
                            Object val = op.get(4);
                            // a head name stands for the stored head (as in the reference, where the value is looked up by name only for "head")
                            if (val instanceof Map && ((Map<?, ?>) val).containsKey("$del")) e.remove((String) op.get(3));
                            else if ("head".equals(op.get(3)) && val instanceof String && store.containsKey(val)) e.put("head", store.get(val));
                            else e.put((String) op.get(3), val);
                            store.put((String) op.get(1), e);
                            break;
                        }
                        case "pinProofAs": {
                            Object pin = op.get(3);
                            Map<String, Object> p = doms.get((String) op.get(1)).pinProof(pin instanceof String ? m(need(store, pin).get("head")) : m(pin), need(store, op.get(4)));
                            store.put((String) op.get(2), p);
                            v = p;
                            break;
                        }
                        case "assemble": {
                            List<Map<String, Object>> hops = new ArrayList<>();
                            for (Object n : (List<?>) op.get(2)) hops.add(need(store, n));
                            List<Object> pins = null;
                            if (op.get(5) != null) { pins = new ArrayList<>(); for (Object n : (List<?>) op.get(5)) pins.add(need(store, n)); }
                            v = Mesh.assembleMeshProof(chainOf(op.get(1)), hops, m(op.get(3)), key(op.get(4)), pins);
                            break;
                        }
                        case "sign": v = Mesh.signMeshAction(chainOf(op.get(1)), m(op.get(2)), key(op.get(3))); break;
                        default: throw new IllegalStateException("op");
                    }
                    out.add(v);
                } catch (Throwable t) {
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("$err", "Error");
                    out.add(e);
                }
            }
            return out;
        });
    }

    static Map<String, Object> need(Map<String, Map<String, Object>> store, Object name) {
        Map<String, Object> v = store.get((String) name);
        if (v == null) throw new IllegalStateException("unknown " + name);
        return v;
    }

    @Test void assembledProofVerifies() {
        Keys.EdKey leaf = key("leaf");
        List<Map<String, Object>> chain = new ArrayList<>();
        chain.add(CoreMeshDomainDiffTest.cap("c0"));
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "pay");
        String sig = Mesh.signMeshAction(chain, action, leaf);
        assertEquals(Mesh.signMeshAction(chain, action, leaf), sig);
        assertTrue(Pca.verifyB64u(leaf.id(), Pca.concat(Mesh.ACTION_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            Pca.canonBytes(tipBody(chain, action))), sig));
    }

    private static Map<String, Object> tipBody(List<Map<String, Object>> chain, Map<String, Object> action) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("action", action);
        b.put("tip", Pca.capHash(chain.get(chain.size() - 1)));
        return b;
    }
}
