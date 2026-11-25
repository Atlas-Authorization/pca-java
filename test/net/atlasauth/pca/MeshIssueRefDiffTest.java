package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The issuing side of the mesh and the federation primitives against the reference corpus (ref-mesh-issue, 787 cases): every function,
 * every case. The domain and witness lifecycle is replayed as scripts, one result per step; a step the reference refuses must be
 * refused, and a witness's own refusal must carry the reference's text.
 */
class MeshIssueRefDiffTest {
    static final String MODULE = "ref-mesh-issue";
    static final int TOTAL = 787;
    static final int STEPS = 271;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** The loader has replaced each {"$seed": label} by the base64url seed; anything else is not a key and the reference refuses it. */
    private static Keys.EdKey key(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, 32);
        if (b == null) throw new IllegalArgumentException("not a signing key");
        return Keys.edFromSeed(b);
    }

    private static Keys.EdKey labelKey(String label) { return Keys.edFromSeed(CoreStoresDiffTest.seed("mesh-issue/" + label)); }

    /** A number as the corpus spells it: a non-finite one is {"$num": text}. */
    private static Object n(double d) {
        if (Double.isNaN(d)) return Issue.obj("$num", "NaN");
        if (Double.isInfinite(d)) return Issue.obj("$num", d > 0 ? "Infinity" : "-Infinity");
        return d;
    }

    private static Object example(Mesh.Example ex) {
        List<Object> ws = new ArrayList<>();
        for (MeshWitness w : ex.witnesses) ws.add(w.id);
        return Issue.obj("trust", ex.trust, "proof", ex.proof, "evidence", ex.evidence, "chain", ex.chain, "heads", ex.heads, "bindings", ex.bindings,
            "domains", Issue.obj("A", ex.domains.get("A").id, "B", ex.domains.get("B").id, "C", ex.domains.get("C").id), "witnesses", ws);
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", a -> Issue.obj("DEFAULT_MAX_HEAD_AGE_MS", Mesh.DEFAULT_MAX_HEAD_AGE_MS, "DEFAULT_MAX_CLOCK_SKEW_MS", Mesh.DEFAULT_MAX_CLOCK_SKEW_MS,
            "DEFAULT_MAX_CHAIN_LENGTH", Mesh.DEFAULT_MAX_CHAIN_LENGTH));
        f.put("keyRevocationId", a -> Mesh.keyRevocationId(arg(a, 0)));
        f.put("effectiveAuthority", a -> Mesh.effectiveAuthority(arg(a, 0)));
        f.put("buildMeshExample", a -> example(arg(a, 0) == null ? Mesh.buildMeshExample() : Mesh.buildMeshExample(OracleCases.num(arg(a, 0)))));
        f.put("demonstrateForkRejection", a -> Mesh.demonstrateForkRejection());
        f.put("meshProofSize", a -> Mesh.meshProofSize(arg(a, 0)));
        f.put("revocationLatencyBound", a -> {
            Mesh.LatencyBound b = Mesh.revocationLatencyBound(arg(a, 0));
            return Issue.obj("published_ms", n(b.publishedMs), "unpinned_ms", n(b.unpinnedMs), "pinned_ms", n(b.pinnedMs), "honest_provers_viable", b.honestProversViable);
        });
        f.put("translateCapability", a -> {
            Map<String, Object> args = m(arg(a, 1));
            return MeshFederation.translateCapability(arg(a, 0), args, key(args.get("bridgeSecret")));
        });
        f.put("verifyTranslatedCapability", a -> a.size() < 2 ? MeshFederation.verifyTranslatedCapability(a.get(0)) : MeshFederation.verifyTranslatedCapability(a.get(0), a.get(1)));
        f.put("translatedEffectiveAuthority", a -> MeshFederation.translatedEffectiveAuthority(arg(a, 0)));
        f.put("createFederatedBudget", a -> MeshFederation.createFederatedBudget(arg(a, 0)));
        f.put("allocateSub", a -> MeshFederation.allocateSub(arg(a, 0), arg(a, 1)));
        f.put("spendFederated", a -> MeshFederation.spendFederated(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("federatedSafetyBound", a -> n(MeshFederation.federatedSafetyBound(arg(a, 0))));
        f.put("meshActionDigest", a -> MeshFederation.meshActionDigest(arg(a, 0)));
        f.put("crossReferenceCommit", a -> MeshFederation.crossReferenceCommit(arg(a, 0)));
        f.put("anchorCrossReference", a -> MeshFederation.anchorCrossReference(key(arg(a, 0)), arg(a, 1), arg(a, 2)));
        f.put("verifyCrossReference", a -> MeshFederation.verifyCrossReference(arg(a, 0), arg(a, 1)));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>(), handled = new TreeSet<>(f.keySet());
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        handled.add("meshIssue"); // the scripts, replayed step by step below
        assertEquals(handled, fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    // ---- the domain / witness scripts ----

    private static <T> T get(Map<String, T> map, Object k) {
        if (!map.containsKey(k)) throw new IllegalStateException("unknown name " + k);
        return map.get(k);
    }

    private static final class World {
        final Map<String, MeshDomain> doms = new LinkedHashMap<>(); // in creation order: a head's domain is the first one with its id
        final Map<String, MeshWitness> ws = new HashMap<>();
        final Map<String, Map<String, Object>> heads = new HashMap<>(), binds = new HashMap<>();
        final Map<String, MeshWitnessStore> stores = new HashMap<>();
    }

    private static Object step(World s, List<?> op) {
        String name = op.size() > 1 && op.get(1) instanceof String ? (String) op.get(1) : null;
        switch ((String) op.get(0)) {
            case "domain": {
                MeshDomain d = new MeshDomain(name, labelKey("d/" + op.get(2)));
                s.doms.put(name, d);
                return d.id;
            }
            case "witness": {
                MeshWitness w = new MeshWitness(labelKey("w/" + op.get(2)));
                s.ws.put(name, w);
                return w.id;
            }
            case "witnessOpts": {
                Map<String, Object> x = m(op.get(3));
                MeshWitness.Options o = new MeshWitness.Options();
                if (x.get("store") != null) o.store = get(s.stores, x.get("store"));
                if (x.get("clock") != null) {
                    double now = StoreJs.dbl(x.get("clock"));
                    o.clock = () -> now;
                }
                if (x.get("skew") != null) o.maxClockSkewMs = StoreJs.dbl(x.get("skew"));
                MeshWitness w = new MeshWitness(labelKey("w/" + op.get(2)), o);
                s.ws.put(name, w);
                return w.id;
            }
            case "store":
                s.stores.put(name, new MemoryMeshWitnessStore());
                return true;
            case "failStore": { // a store whose save throws once that many saves happened
                MemoryMeshWitnessStore inner = new MemoryMeshWitnessStore();
                long failAfter = Json.asLong(op.get(2));
                long[] saves = {0};
                s.stores.put(name, new MeshWitnessStore() {
                    @Override public Map<String, Object> load() { return inner.load(); }
                    @Override public void save(Map<String, Object> state) {
                        if (saves[0]++ >= failAfter) throw new IllegalStateException("disk");
                        inner.save(state);
                    }
                });
                return true;
            }
            case "storeLoad": return get(s.stores, name).load();
            case "record": return get(s.doms, name).record(CoreMeshDomainDiffTest.cap((String) op.get(2)));
            case "revoke":
                get(s.doms, name).revoke((String) op.get(2));
                return null;
            case "publish": {
                MeshDomain d = get(s.doms, name);
                List<MeshWitness> list = new ArrayList<>();
                for (Object w : (List<?>) op.get(4)) list.add(get(s.ws, w));
                Integer threshold = op.get(5) == null ? null : Integer.valueOf((int) Json.asLong(op.get(5)));
                Map<String, Object> h = d.publishHead(list, StoreJs.dbl(op.get(3)), threshold);
                s.heads.put((String) op.get(2), h);
                return h;
            }
            case "fork": { // a copy of a head with one top-level member replaced
                Map<String, Object> h = new LinkedHashMap<>(get(s.heads, op.get(2)));
                h.put((String) op.get(3), op.get(4));
                s.heads.put(name, h);
                return null;
            }
            case "forkHead": { // the same inside its head
                Map<String, Object> h = new LinkedHashMap<>(get(s.heads, op.get(2)));
                Map<String, Object> inner = new LinkedHashMap<>(m(h.get("head")));
                inner.put((String) op.get(3), op.get(4));
                h.put("head", inner);
                s.heads.put(name, h);
                return null;
            }
            case "cosign": {
                MeshWitness w = get(s.ws, name);
                Map<String, Object> h = get(s.heads, op.get(2));
                Map<String, Object> inner = m(h.get("head"));
                MeshDomain d = null;
                if (inner != null) for (MeshDomain x : s.doms.values()) if (d == null && x.id.equals(inner.get("domain"))) d = x;
                if (d == null) throw new IllegalStateException("no such domain");
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("head", h);
                if ("domain".equals(op.get(3))) { // the domain's own proof from the witness's last-seen head
                    Map<String, Object> prev = w.lastSeen((String) inner.get("domain"));
                    if (prev != null) req.put("consistency", d.consistencyProof(Json.asLong(prev.get("size")), Json.asLong(inner.get("size"))));
                } else if (op.get(3) != null) {
                    req.put("consistency", op.get(3));
                }
                req.put("rev_ids", "domain".equals(op.get(4)) ? new ArrayList<Object>(d.revocationSetCopy().list()) : op.get(4));
                return w.cosign(req);
            }
            case "lastSeen": {
                MeshWitness w = get(s.ws, name);
                Object k = op.get(2);
                return w.lastSeen(s.doms.containsKey(k) ? s.doms.get(k).id : (String) k);
            }
            case "export": return get(s.ws, name).exportState();
            case "import": {
                MeshWitness w = get(s.ws, name);
                Map<String, Object> st = m(op.get(2));
                w.importState(st != null && st.containsKey("$export") ? get(s.ws, st.get("$export")).exportState() : st);
                return null;
            }
            case "restart": {
                MeshWitness.Options o = new MeshWitness.Options();
                o.store = get(s.stores, op.get(2));
                MeshWitness w = new MeshWitness(labelKey("w/" + op.get(3)), o);
                s.ws.put(name, w);
                return w.exportState();
            }
            case "consistency": {
                MeshDomain d = get(s.doms, name);
                return op.get(3) == null ? d.consistencyProof(Json.asLong(op.get(2))) : d.consistencyProof(Json.asLong(op.get(2)), Json.asLong(op.get(3)));
            }
            case "enroll": {
                Map<String, Object> b = get(s.doms, name).enroll((String) op.get(3), (String) op.get(4));
                s.binds.put((String) op.get(2), b);
                return b;
            }
            case "evidence":
                return get(s.doms, name).evidence(CoreMeshDomainDiffTest.cap((String) op.get(2)), get(s.heads, op.get(3)), op.get(4) == null ? null : get(s.binds, op.get(4)));
            default: throw new IllegalStateException("op");
        }
    }

    @Test void domainAndWitnessScripts() throws Exception {
        List<String> bad = new ArrayList<>();
        int steps = 0;
        for (Map<String, Object> c : OracleCases.of(MODULE, "meshIssue")) {
            List<?> ops = (List<?>) ((List<?>) c.get("args")).get(0), want = (List<?>) c.get("out");
            assertEquals(ops.size(), want.size(), String.valueOf(c.get("name")));
            World s = new World();
            for (int i = 0; i < ops.size(); i++, steps++) {
                Object got;
                String refused = null;
                try {
                    got = IntentJs.normalize(OracleCases.toJson(step(s, (List<?>) ops.get(i))));
                } catch (RuntimeException e) {
                    got = null;
                    refused = String.valueOf(e.getMessage());
                }
                Map<String, Object> w = m(want.get(i));
                String wantRefusal = w != null && w.containsKey("$err") ? String.valueOf(w.get("$err")) : null;
                boolean same;
                if (wantRefusal == null || refused == null) same = wantRefusal == null && refused == null && IntentJs.jsonEquals(want.get(i), got);
                else same = !wantRefusal.startsWith("witness: ") || wantRefusal.equals(refused);
                if (!same) bad.add(c.get("name") + " step " + i + " " + Json.canonicalize(ops.get(i)) + "\n  want: " + Json.canonicalize(want.get(i)) + "\n  got:  " + (refused != null ? "REFUSED " + refused : Json.canonicalize(got)));
            }
        }
        assertEquals(STEPS, steps);
        assertTrue(bad.isEmpty(), bad.size() + " divergent step(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
