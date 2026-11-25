package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An append-only RFC 9162 Merkle log over opaque commitment strings: head, root at an earlier size, inclusion and consistency
 * proofs, in the wire shapes the verifiers in {@link Ledger} and {@link Mesh} read. It holds only commitments (no openings).
 */
public final class MerkleLog {
    private final List<String> commits = new ArrayList<>();
    private final List<byte[]> hashes = new ArrayList<>();

    public MerkleLog() {}

    /** Rebuild from stored commitments. */
    public static MerkleLog of(List<String> commits) {
        MerkleLog l = new MerkleLog();
        for (String c : commits) l.appendCommitment(c);
        return l;
    }

    public int size() { return commits.size(); }

    public List<String> commits() { return new ArrayList<>(commits); }

    /** Append an opaque commitment leaf; refuses an empty one. Returns its index. */
    public int appendCommitment(String commit) {
        if (commit == null || commit.isEmpty()) throw new IllegalArgumentException("appendCommitment: commit must be a non-empty string");
        commits.add(commit);
        hashes.add(Pca.leafHash(commit));
        return commits.size() - 1;
    }

    private static byte[] mth(List<byte[]> hs) { return hs.isEmpty() ? Pca.sha(new byte[0]) : Pca.build(hs); }

    /** {size, root}. */
    public Map<String, Object> head() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("size", StoreJs.num(size()));
        m.put("root", Pca.b64(mth(hashes)));
        return m;
    }

    public String root() { return Pca.b64(mth(hashes)); }

    /** The root the log had when it held only the first {@code size} entries. */
    public String rootAt(long size) {
        if (size < 0 || size > size()) throw new IllegalArgumentException("rootAt: size out of range");
        return Pca.b64(mth(hashes.subList(0, (int) size)));
    }

    /** {index, size, path: [{side, hash}]}. */
    public Map<String, Object> inclusionProof(long index) {
        if (index < 0 || index >= size()) throw new IllegalArgumentException("merkleProof: index out of range");
        List<Object> path = new ArrayList<>();
        prove(hashes, (int) index, path);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", StoreJs.num(index));
        m.put("size", StoreJs.num(size()));
        m.put("path", path);
        return m;
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

    /** RFC 9162 SUBPROOF: {oldSize, newSize, path: [b64u]}. */
    public Map<String, Object> consistencyProof(long oldSize, long newSize) {
        if (oldSize < 0 || oldSize > newSize || newSize > size()) throw new IllegalArgumentException("consistencyProof: invalid sizes");
        List<Object> out = new ArrayList<>();
        if (oldSize > 0 && oldSize < newSize) sub((int) oldSize, hashes.subList(0, (int) newSize), true, out);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("oldSize", StoreJs.num(oldSize));
        m.put("newSize", StoreJs.num(newSize));
        m.put("path", out);
        return m;
    }

    /** RFC 9162 SUBPROOF(m, D[n], b). */
    public Map<String, Object> consistencyProof(long oldSize) { return consistencyProof(oldSize, size()); }

    private static void sub(int m, List<byte[]> hs, boolean b, List<Object> out) {
        int n = hs.size();
        if (m == n) {
            if (!b) out.add(Pca.b64(mth(hs)));
            return;
        }
        int k = Pca.split(n);
        if (m <= k) {
            sub(m, hs.subList(0, k), b, out);
            out.add(Pca.b64(mth(hs.subList(k, n))));
        } else {
            sub(m - k, hs.subList(k, n), false, out);
            out.add(Pca.b64(mth(hs.subList(0, k))));
        }
    }
}
