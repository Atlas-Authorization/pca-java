package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The issuing side of the mesh (enroll, evidence, pinProof, non-membership proofs) against the reference, plus a proof that the evidence verifies. */
public class CoreMeshDomainDiffTest {
    static final String MODULE = "ref-core-mesh-domain-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> cap(String label) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", label);
        c.put("issuer", "iss-" + label);
        c.put("holder", "h");
        Map<String, Object> cav = new LinkedHashMap<>();
        cav.put("type", "scope");
        List<Object> acts = new ArrayList<>();
        acts.add(label);
        cav.put("actions", acts);
        List<Object> cavs = new ArrayList<>();
        cavs.add(cav);
        c.put("caveats", cavs);
        return c;
    }

    @Test void meshDomain() throws Exception {
        OracleCases.each(MODULE, "meshDomain", a -> {
            Map<String, MeshDomain> doms = new HashMap<>();
            Map<String, MeshWitness> ws = new HashMap<>();
            Map<String, Map<String, Object>> heads = new HashMap<>(), binds = new HashMap<>();
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "domain": { MeshDomain d = new MeshDomain((String) op.get(1), Keys.edFromSeed(CoreStoresDiffTest.seed("mesh-domain/" + op.get(2)))); doms.put((String) op.get(1), d); v = d.id; break; }
                        case "witness": { MeshWitness w = new MeshWitness(Keys.edFromSeed(CoreStoresDiffTest.seed("mesh-domain/" + op.get(2)))); ws.put((String) op.get(1), w); v = w.id; break; }
                        case "record": v = doms.get((String) op.get(1)).record(cap((String) op.get(2))); break;
                        case "revoke": doms.get((String) op.get(1)).revoke((String) op.get(2)); break;
                        case "publish": {
                            List<MeshWitness> list = new ArrayList<>();
                            for (Object w : (List<?>) op.get(4)) list.add(ws.get((String) w));
                            Map<String, Object> h = doms.get((String) op.get(1)).publishHead(list, StoreJs.dbl(op.get(3)), op.get(5) == null ? null : (int) (double) StoreJs.dbl(op.get(5)));
                            heads.put((String) op.get(2), h);
                            v = h;
                            break;
                        }
                        case "fork": { Map<String, Object> h = new LinkedHashMap<>(heads.get((String) op.get(2))); h.put((String) op.get(3), op.get(4)); heads.put((String) op.get(1), h); break; }
                        case "enroll": { Map<String, Object> b = doms.get((String) op.get(1)).enroll((String) op.get(3), (String) op.get(4)); binds.put((String) op.get(2), b); v = b; break; }
                        case "evidence": v = doms.get((String) op.get(1)).evidence(cap((String) op.get(2)), heads.get((String) op.get(3)), op.get(4) == null ? null : binds.get((String) op.get(4))); break;
                        case "pinProof": v = doms.get((String) op.get(1)).pinProof(op.get(2) instanceof String ? m(heads.get((String) op.get(2)).get("head")) : m(op.get(2)), heads.get((String) op.get(3))); break;
                        case "nonMembership": v = nonMembership(doms.get((String) op.get(1)), op.get(2)); break;
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

    /** The domain's revocation set is private; rebuild the same set from the revoke calls made through a recording domain. */
    static Map<String, Object> nonMembership(MeshDomain d, Object id) {
        if (!(id instanceof String)) throw new IllegalArgumentException("not a string");
        return d.revocationSetCopy().nonMembershipProof((String) id);
    }

    @Test void nonMembershipProofsVerify() {
        RevocationSet set = new RevocationSet(List.of("b", "d", "f", "h", "j"));
        for (String id : new String[] {"a", "c", "e", "g", "i", "k", "", "key:x"}) {
            Map<String, Object> p = set.nonMembershipProof(id);
            assertTrue(Mesh.nonMembership(set.root(), p, id), id);
        }
        for (String id : new String[] {"b", "d", "j"}) {
            final String x = id;
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> set.nonMembershipProof(x));
        }
        assertEquals("0", ((Json.Num) new RevocationSet().nonMembershipProof("a").get("size")).raw);
    }
}
