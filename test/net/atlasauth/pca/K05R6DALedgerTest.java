package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Round 2 (tag DA) kills for {@link Ledger#verifyLedgerConsistency}: genuine RFC 9162 consistency proofs, built here, for the three
 * (old, new) sizes below, checked in this order. Each mutant of the proof walk that does not hang changes the verdict of at least
 * one of them, and none of the mutants killed here hangs on a size that precedes the one that kills it, so the mutant fails by
 * assertion rather than by timeout. The tests run in microseconds.
 */
public class K05R6DALedgerTest {
    static byte[] leaf(int i) { return Pca.leafHash(Long.valueOf(i)); }

    static byte[] mth(List<byte[]> ls) {
        if (ls.size() == 1) return ls.get(0);
        int k = 1;
        while (k * 2 < ls.size()) k *= 2;
        return Pca.nodeHash(mth(ls.subList(0, k)), mth(ls.subList(k, ls.size())));
    }

    /** RFC 9162 section 2.1.4.1 SUBPROOF(m, D[n], b). */
    static List<byte[]> sub(int m, List<byte[]> ls, boolean b) {
        int n = ls.size();
        List<byte[]> out = new ArrayList<>();
        if (m == n) {
            if (!b) out.add(mth(ls));
            return out;
        }
        int k = 1;
        while (k * 2 < n) k *= 2;
        if (m <= k) {
            out.addAll(sub(m, ls.subList(0, k), b));
            out.add(mth(ls.subList(k, n)));
        } else {
            out.addAll(sub(m - k, ls.subList(k, n), false));
            out.add(mth(ls.subList(0, k)));
        }
        return out;
    }

    static boolean verify(int m, int n) {
        List<byte[]> ls = new ArrayList<>();
        for (int i = 0; i < n; i++) ls.add(leaf(i));
        List<Object> path = new ArrayList<>();
        for (byte[] h : sub(m, ls, true)) path.add(Pca.b64(h));
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("oldSize", Long.valueOf(m));
        proof.put("newSize", Long.valueOf(n));
        proof.put("path", path);
        return Ledger.verifyLedgerConsistency(Pca.b64(mth(ls.subList(0, m))), Pca.b64(mth(ls)), proof);
    }

    @Test void genuineProofsVerifyInThisOrder() {
        assertTrue(verify(13, 14), "13 -> 14");
        assertTrue(verify(6, 7), "6 -> 7");
        assertTrue(verify(11, 13), "11 -> 13");
    }

    static Map<String, Object> sizes(long oldSize, long newSize) {
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("oldSize", oldSize);
        proof.put("newSize", newSize);
        proof.put("path", new ArrayList<Object>());
        return proof;
    }

    @Test void equalSizesNeedEqualRootsAndAnEmptyTreeHasTheEmptyRoot() {
        assertTrue(Ledger.verifyLedgerConsistency("x", "x", sizes(1, 1)));
        assertFalse(Ledger.verifyLedgerConsistency("x", "y", sizes(1, 1)));
        // an old size of 0 is the empty tree: its root is the empty-tree root, whatever else is claimed
        assertFalse(Ledger.verifyLedgerConsistency("X", "X", sizes(0, 0)));
        assertFalse(Ledger.verifyLedgerConsistency("X", "X", sizes(0, 0)), "again");
        assertEquals(true, Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, Ledger.EMPTY_TREE_ROOT, sizes(0, 0)));
    }
}
