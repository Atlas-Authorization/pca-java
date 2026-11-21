package net.atlasauth.pca.scitt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 9162 section 2.1 Merkle tree (SHA-256): tree hash, inclusion paths and consistency proofs, with the verification algorithms of
 * sections 2.1.3.2 and 2.1.4.2. Leaf inputs are the raw entry bytes ({@code SHA-256(0x00 || entry)}), so any independent RFC 9162 /
 * RFC 6962 verifier can check a proof given the same entry bytes.
 */
public final class Rfc9162 {
    private Rfc9162() {}

    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Root hash of the empty tree: SHA-256 of the empty string. */
    public static byte[] emptyRoot() { return sha256(); }

    /** {@code SHA-256(0x00 || entry)}. */
    public static byte[] leafHash(byte[] entry) { return sha256(new byte[] {0x00}, entry); }

    /** {@code SHA-256(0x01 || left || right)}. */
    public static byte[] nodeHash(byte[] left, byte[] right) { return sha256(new byte[] {0x01}, left, right); }

    /** Largest power of two strictly less than n (n &gt;= 2). */
    private static int splitPoint(int n) {
        int k = 1;
        while (k * 2L < n) k *= 2;
        return k;
    }

    /** MTH over already-hashed leaves (RFC 9162 section 2.1.1). */
    public static byte[] treeHash(List<byte[]> leafHashes) {
        int n = leafHashes.size();
        if (n == 0) return emptyRoot();
        if (n == 1) return leafHashes.get(0);
        int k = splitPoint(n);
        return nodeHash(treeHash(leafHashes.subList(0, k)), treeHash(leafHashes.subList(k, n)));
    }

    /** Inclusion path for leaf {@code index} (RFC 9162 section 2.1.3.1), bottom-up. */
    public static List<byte[]> inclusionPath(List<byte[]> leafHashes, long index) {
        int n = leafHashes.size();
        if (index < 0 || index >= n) throw new IndexOutOfBoundsException("rfc9162: leaf index out of range");
        if (n == 1) return new ArrayList<>();
        int k = splitPoint(n);
        List<byte[]> out;
        if (index < k) {
            out = inclusionPath(leafHashes.subList(0, k), index);
            out.add(treeHash(leafHashes.subList(k, n)));
        } else {
            out = inclusionPath(leafHashes.subList(k, n), index - k);
            out.add(treeHash(leafHashes.subList(0, k)));
        }
        return out;
    }

    private static boolean equal(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }

    private static boolean allHashes(List<byte[]> path) {
        for (byte[] p : path) if (p == null || p.length != 32) return false;
        return true;
    }

    /**
     * Recompute the tree root from a leaf hash and its inclusion path (RFC 9162 section 2.1.3.2). Returns null when the
     * (index, size, path length) combination is invalid.
     */
    public static byte[] rootFromInclusionPath(byte[] leaf, long index, long size, List<byte[]> path) {
        if (index < 0 || size < 1 || index >= size) return null;
        if (leaf == null || leaf.length != 32 || !allHashes(path)) return null;
        BigInteger fn = BigInteger.valueOf(index);
        BigInteger sn = BigInteger.valueOf(size - 1);
        byte[] r = leaf;
        for (byte[] p : path) {
            if (sn.signum() == 0) return null;
            if (fn.testBit(0) || fn.equals(sn)) {
                r = nodeHash(p, r);
                if (!fn.testBit(0)) {
                    while (!fn.testBit(0) && fn.signum() != 0) {
                        fn = fn.shiftRight(1);
                        sn = sn.shiftRight(1);
                    }
                }
            } else {
                r = nodeHash(r, p);
            }
            fn = fn.shiftRight(1);
            sn = sn.shiftRight(1);
        }
        return sn.signum() == 0 ? r : null;
    }

    /** Verify an inclusion proof: the recomputed root must equal {@code root}. */
    public static boolean verifyInclusionPath(byte[] leaf, long index, long size, List<byte[]> path, byte[] root) {
        byte[] computed = rootFromInclusionPath(leaf, index, size, path);
        return computed != null && root != null && equal(computed, root);
    }

    private static List<byte[]> subproof(int m, List<byte[]> d, boolean complete) {
        int n = d.size();
        List<byte[]> out = new ArrayList<>();
        if (m == n) {
            if (!complete) out.add(treeHash(d));
            return out;
        }
        int k = splitPoint(n);
        if (m <= k) {
            out = subproof(m, d.subList(0, k), complete);
            out.add(treeHash(d.subList(k, n)));
        } else {
            out = subproof(m - k, d.subList(k, n), false);
            out.add(treeHash(d.subList(0, k)));
        }
        return out;
    }

    /** Consistency proof between the first {@code m} leaves and all of {@code leafHashes} (RFC 9162 section 2.1.4.1). */
    public static List<byte[]> consistencyPath(List<byte[]> leafHashes, long m) {
        if (m < 1 || m > leafHashes.size()) throw new IndexOutOfBoundsException("rfc9162: consistency size out of range");
        return subproof((int) m, leafHashes, true);
    }

    /**
     * Verify a consistency proof between a tree of {@code first} leaves (root {@code firstRoot}) and one of {@code second} leaves
     * (root {@code secondRoot}) per RFC 9162 section 2.1.4.2. A proof from an empty tree is rejected.
     */
    public static boolean verifyConsistencyPath(long first, long second, byte[] firstRoot, byte[] secondRoot, List<byte[]> path) {
        if (first < 1 || second < first) return false;
        if (firstRoot == null || secondRoot == null || firstRoot.length != 32 || secondRoot.length != 32 || !allHashes(path)) return false;
        if (first == second) return path.isEmpty() && equal(firstRoot, secondRoot);
        if (path.isEmpty()) return false;
        List<byte[]> nodes = new ArrayList<>(path);
        if ((first & (first - 1)) == 0) nodes.add(0, firstRoot); // first is an exact power of two
        BigInteger fn = BigInteger.valueOf(first - 1);
        BigInteger sn = BigInteger.valueOf(second - 1);
        while (fn.testBit(0)) {
            fn = fn.shiftRight(1);
            sn = sn.shiftRight(1);
        }
        byte[] fr = nodes.get(0);
        byte[] sr = nodes.get(0);
        for (byte[] c : nodes.subList(1, nodes.size())) {
            if (sn.signum() == 0) return false;
            if (fn.testBit(0) || fn.equals(sn)) {
                fr = nodeHash(c, fr);
                sr = nodeHash(c, sr);
                if (!fn.testBit(0)) {
                    while (!fn.testBit(0) && fn.signum() != 0) {
                        fn = fn.shiftRight(1);
                        sn = sn.shiftRight(1);
                    }
                }
            } else {
                sr = nodeHash(sr, c);
            }
            fn = fn.shiftRight(1);
            sn = sn.shiftRight(1);
        }
        return sn.signum() == 0 && equal(fr, firstRoot) && equal(sr, secondRoot);
    }
}
