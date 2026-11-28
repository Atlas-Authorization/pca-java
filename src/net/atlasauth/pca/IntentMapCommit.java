package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The builder side of the committed Intent Map (Merkle form, per-leaf salts derived from one session secret): the leaf layout,
 * salts, tree and Z0 disclosure that {@link IntentMap} verifies. Inputs and outputs are plain JSON trees.
 */
public final class IntentMapCommit {
    private IntentMapCommit() {}

    /** Informative per-leaf salt derivation tag (wallet side). */
    public static final String MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\0";

    /** One committed leaf: its kind, its (normalised) JSON and its salt. */
    public static final class Leaf {
        public final String kind;
        public final Object leaf;
        public final byte[] salt;
        Leaf(String kind, Object leaf, byte[] salt) { this.kind = kind; this.leaf = leaf; this.salt = salt; }
    }

    public static final class CommittedMap {
        public final String mapCommit;
        public final int size;
        public final List<Leaf> leaves;
        private final List<byte[]> hashes;
        private final List<Map<String, Object>> full;

        CommittedMap(String mapCommit, int size, List<Leaf> leaves, List<byte[]> hashes, List<Map<String, Object>> full) {
            this.mapCommit = mapCommit; this.size = size; this.leaves = leaves; this.hashes = hashes; this.full = full;
        }

        /** The leaves as JSON: [{kind, leaf, salt}]. */
        public List<Object> leavesJson() {
            List<Object> out = new ArrayList<>();
            for (Leaf l : leaves) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("kind", l.kind);
                m.put("leaf", l.leaf);
                m.put("salt", Pca.b64(l.salt));
                out.add(m);
            }
            return out;
        }

        private Map<String, Object> entry(int i) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", (long) i);
            m.put("salt", Pca.b64(leaves.get(i).salt));
            m.put("leaf", leaves.get(i).leaf);
            List<Object> path = new ArrayList<>();
            List<byte[]> out = new ArrayList<>();
            auditPath(hashes, i, out);
            for (byte[] p : out) path.add(Pca.b64(p));
            m.put("path", path);
            return m;
        }

        /** Z0 disclosure for an action; throws when the action lies outside the map. */
        public Map<String, Object> disclose(String verb, Object resource, Object params) {
            int hi = -1;
            for (int i = 0; i < full.size(); i++) if (full.get(i).get("verb").equals(verb)) { hi = i; break; }
            if (hi < 0) throw new IllegalArgumentException("commitMap.disclose: verb " + verb + " is not in the map");
            long[][] w = IntentMap.cellOf(full.get(hi), resource, params);
            if (w == null) throw new IllegalArgumentException("commitMap.disclose: the action lies outside the committed map's dimension");
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("size", (long) size);
            d.put("header", entry(hi));
            d.put("cell", entry((int) (IntentJs.lng(full.get(hi).get("first")) + w[1][0])));
            d.put("metrics", entry(size - 2));
            return d;
        }
    }

    private static long split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }

    private static byte[] treeRoot(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = (int) split(hs.size());
        return IntentMap.nodeHash(treeRoot(hs.subList(0, k)), treeRoot(hs.subList(k, hs.size())));
    }

    private static void auditPath(List<byte[]> hs, int idx, List<byte[]> out) {
        if (hs.size() == 1) return;
        int k = (int) split(hs.size());
        if (idx < k) {
            auditPath(hs.subList(0, k), idx, out);
            out.add(treeRoot(hs.subList(k, hs.size())));
        } else {
            auditPath(hs.subList(k, hs.size()), idx - k, out);
            out.add(treeRoot(hs.subList(0, k)));
        }
    }

    /** Per-leaf salt: SHA-256(TAG_SALT || secret || u64be(index)). */
    public static byte[] mapLeafSalt(byte[] secret, long index) {
        return Pca.sha(IntentJs.utf8(MAP_TAG_SALT), secret, IntentMap.u64be(index));
    }

    private static long dimCells(Map<String, Object> d) {
        return "num".equals(d.get("kind")) ? IntentMap.numCells(d).size() : ((List<?>) d.get("values")).size();
    }

    /**
     * Build the committed form. {@code headers}: [{verb, dims}], {@code cells}: verb -> [{cell, p_ppm, in_grant}] in flat order,
     * {@code metrics}: the metrics leaf, {@code learnerDigest}: the learner settings' content address. Throws on a malformed input.
     */
    @SuppressWarnings("unchecked")
    public static CommittedMap commitMap(List<Map<String, Object>> headers, Map<String, List<Map<String, Object>>> cells, Map<String, Object> metrics, String learnerDigest, byte[] secret) {
        if (secret == null || secret.length != 32) throw new IllegalArgumentException("commitMap: the secret is 32 bytes");
        List<Map<String, Object>> heads = new ArrayList<>(headers);
        heads.sort((a, b) -> Json.compareUtf8((String) a.get("verb"), (String) b.get("verb")));
        for (int i = 1; i < heads.size(); i++) if (heads.get(i).get("verb").equals(heads.get(i - 1).get("verb"))) throw new IllegalArgumentException("commitMap: duplicate verb");
        long[] counts = new long[heads.size()];
        for (int i = 0; i < counts.length; i++) {
            long n = 1;
            for (Object d : (List<Object>) heads.get(i).get("dims")) n *= dimCells((Map<String, Object>) d);
            counts[i] = n;
        }
        long next = heads.size();
        List<Map<String, Object>> full = new ArrayList<>();
        for (int i = 0; i < heads.size(); i++) {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("verb", heads.get(i).get("verb"));
            h.put("first", next);
            h.put("cells", counts[i]);
            h.put("dims", heads.get(i).get("dims"));
            full.add(h);
            next += counts[i];
        }
        List<String> kinds = new ArrayList<>();
        List<Object> leaves = new ArrayList<>();
        for (Map<String, Object> h : full) { kinds.add("header"); leaves.add(h); }
        for (Map<String, Object> h : full) {
            List<Map<String, Object>> cs = cells.get(h.get("verb"));
            if (cs == null || cs.size() != (long) h.get("cells")) throw new IllegalArgumentException("commitMap: verb " + h.get("verb") + " needs " + h.get("cells") + " cell leaves");
            for (Map<String, Object> c : cs) {
                Map<String, Object> l = new LinkedHashMap<>();
                l.put("verb", h.get("verb"));
                l.put("cell", c.get("cell"));
                l.put("p_ppm", c.get("p_ppm"));
                l.put("in_grant", c.get("in_grant"));
                kinds.add("cell");
                leaves.add(l);
            }
        }
        kinds.add("metrics");
        leaves.add(metrics);
        Map<String, Object> lf = new LinkedHashMap<>();
        lf.put("learner_digest", learnerDigest);
        kinds.add("learner");
        leaves.add(lf);
        for (int i = 0; i < leaves.size(); i++) {
            Object leaf = leaves.get(i);
            String k = kinds.get(i);
            String e = k.equals("header") ? IntentMap.headerError(leaf) : k.equals("cell") ? IntentMap.cellError(leaf) : k.equals("metrics") ? IntentMap.metricsError(leaf) : IntentMap.learnerError(leaf);
            if (e != null) throw new IllegalArgumentException("commitMap: " + e);
        }
        if (leaves.size() < 4 || leaves.size() > IntentMap.MAX_MAP_LEAVES) throw new IllegalArgumentException("commitMap: the map has too few or too many leaves");
        List<Leaf> out = new ArrayList<>();
        List<byte[]> hashes = new ArrayList<>();
        for (int i = 0; i < leaves.size(); i++) {
            byte[] salt = mapLeafSalt(secret, i);
            Object norm = IntentJs.normalize(leaves.get(i));
            out.add(new Leaf(kinds.get(i), norm, salt));
            hashes.add(IntentMap.leafHash(kinds.get(i), salt, norm));
        }
        return new CommittedMap(IntentMap.commitOf(hashes.size(), treeRoot(hashes)), hashes.size(), out, hashes, (List<Map<String, Object>>) (List<?>) IntentJs.normalize(full));
    }
}
