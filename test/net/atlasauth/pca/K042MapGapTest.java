package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** RFC 9162 audit-path folding checked against an independent reference tree for every size up to 70 and every leaf. */
class K042MapGapTest {
    static byte[] leaf(int i) {
        try { return MessageDigest.getInstance("SHA-256").digest(("leaf-" + i).getBytes()); } catch (Exception e) { throw new IllegalStateException(e); }
    }
    static byte[] mth(List<byte[]> d) {
        if (d.size() == 1) return d.get(0);
        int k = 1;
        while (k * 2 < d.size()) k *= 2;
        return IntentMap.nodeHash(mth(d.subList(0, k)), mth(d.subList(k, d.size())));
    }
    /** RFC 9162 2.1.3.1 PATH(m, D[n]). */
    static List<byte[]> path(int m, List<byte[]> d) {
        if (d.size() == 1) return new ArrayList<>();
        int k = 1;
        while (k * 2 < d.size()) k *= 2;
        List<byte[]> out;
        if (m < k) { out = path(m, d.subList(0, k)); out.add(mth(d.subList(k, d.size()))); }
        else { out = path(m - k, d.subList(k, d.size())); out.add(mth(d.subList(0, k))); }
        return out;
    }

    @Test void auditPathsFoldToTheTreeRootForEverySizeAndLeaf() {
        for (int n = 1; n <= 70; n++) {
            List<byte[]> d = new ArrayList<>();
            for (int i = 0; i < n; i++) d.add(leaf(i));
            byte[] root = mth(d);
            for (int m = 0; m < n; m++) {
                List<byte[]> p = path(m, d);
                byte[] got = IntentMap.rootFromPath(m, n, d.get(m), p);
                assertNotNull(got, "n=" + n + " m=" + m);
                assertArrayEquals(root, got, "n=" + n + " m=" + m);
                // a path that is too long or too short does not fit
                List<byte[]> longer = new ArrayList<>(p); longer.add(leaf(999));
                assertNull(IntentMap.rootFromPath(m, n, d.get(m), longer), "long n=" + n + " m=" + m);
                if (!p.isEmpty()) assertNull(IntentMap.rootFromPath(m, n, d.get(m), p.subList(0, p.size() - 1)), "short n=" + n + " m=" + m);
                // another leaf hash / another index does not fold to the root
                byte[] other = IntentMap.rootFromPath(m, n, leaf(1000), p);
                assertFalse(other != null && Arrays.equals(root, other), "wrong leaf n=" + n + " m=" + m);
                if (n > 1) {
                    int m2 = (m + 1) % n;
                    byte[] w = IntentMap.rootFromPath(m2, n, d.get(m), p);
                    assertFalse(w != null && Arrays.equals(root, w), "wrong index n=" + n + " m=" + m);
                }
            }
            assertNull(IntentMap.rootFromPath(n, n, leaf(0), new ArrayList<>()), "index=size n=" + n);
            assertNull(IntentMap.rootFromPath(-1, n, leaf(0), new ArrayList<>()), "index<0 n=" + n);
        }
        assertArrayEquals(leaf(0), IntentMap.rootFromPath(0, 1, leaf(0), new ArrayList<>()));
        assertNull(IntentMap.rootFromPath(0, 0, leaf(0), new ArrayList<>()));
    }
}
