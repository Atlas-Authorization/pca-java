package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A sorted, size-bound revocation set: the ids a mesh domain commits to with {@code rev_root} (the issuing side of {@link Mesh}). */
public final class RevocationSet {
    private final List<String> ids = new ArrayList<>();

    public RevocationSet() {}

    public RevocationSet(Iterable<String> initial) { for (String id : initial) revoke(id); }

    public int size() { return ids.size(); }

    private int lowerBound(String id) {
        int lo = 0, hi = ids.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (Json.compareUtf8(ids.get(mid), id) < 0) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    /** Idempotent. Returns true when newly revoked. */
    public boolean revoke(String id) {
        if (id == null) throw new IllegalArgumentException("revoke: id must be a string");
        int lo = lowerBound(id);
        if (lo < ids.size() && ids.get(lo).equals(id)) return false;
        ids.add(lo, id);
        return true;
    }

    public boolean has(String id) {
        int lo = lowerBound(id);
        return lo < ids.size() && ids.get(lo).equals(id);
    }

    /** Sorted revoked ids (copy). */
    public List<String> list() { return new ArrayList<>(ids); }

    /**
     * Proof that {@code id} is NOT in the set: {@code {size, lo?, hi?}}, the bracketing leaves {@code {id, proof}} (lo = the greatest id below, hi = the
     * least id above). Throws when the id IS revoked (no such proof can exist).
     */
    public Map<String, Object> nonMembershipProof(String id) {
        if (has(id)) throw new IllegalStateException("nonMembershipProof: id is revoked");
        int n = ids.size();
        int lo = lowerBound(id); // first index whose leaf is > id
        List<byte[]> hs = new ArrayList<>();
        for (String x : ids) hs.add(Pca.leafHash(x));
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("size", StoreJs.num((long) n));
        if (lo > 0) p.put("lo", leaf(hs, lo - 1));
        if (lo < n) p.put("hi", leaf(hs, lo));
        return p;
    }

    private Map<String, Object> leaf(List<byte[]> hs, int i) {
        List<Object> path = new ArrayList<>();
        prove(hs, i, path);
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("index", StoreJs.num((long) i));
        proof.put("size", StoreJs.num((long) hs.size()));
        proof.put("path", path);
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("id", ids.get(i));
        l.put("proof", proof);
        return l;
    }

    private static void prove(List<byte[]> hs, int idx, List<Object> out) {
        if (hs.size() == 1) return;
        int k = Pca.split(hs.size());
        Map<String, Object> step = new LinkedHashMap<>();
        if (idx < k) {
            prove(hs.subList(0, k), idx, out);
            step.put("side", "R");
            step.put("hash", Pca.b64(Pca.build(hs.subList(k, hs.size()))));
        } else {
            prove(hs.subList(k, hs.size()), idx - k, out);
            step.put("side", "L");
            step.put("hash", Pca.b64(Pca.build(hs.subList(0, k))));
        }
        out.add(step);
    }

    /** The size-bound root. */
    public String root() { return IntentRevocation.revsetRoot(ids); }
}
