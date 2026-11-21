package net.atlasauth.pca.ratchet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import net.atlasauth.pca.Frost;
import org.junit.jupiter.api.Test;

/** Point validation is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order and must be refused. */
public class EdwardsMixedOrderTest {
    private static byte[] filled(int first, int mid, int last) {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) mid);
        b[0] = (byte) first;
        b[31] = (byte) last;
        return b;
    }

    private static final byte[] BASE = filled(0x58, 0x66, 0x66);
    private static final byte[] T2 = filled(0xEC, 0xFF, 0x7F); // (0, -1), order 2
    private static final byte[] NONCANON = filled(0xEE, 0xFF, 0x7F); // y = p + 1

    private static byte[] identity() { byte[] b = new byte[32]; b[0] = 1; return b; }

    @Test
    public void decodeSafePointRefusesTorsion() {
        byte[] mixed = EdwardsPoint.fromBytes(BASE).add(EdwardsPoint.fromBytes(T2)).toBytes();
        assertArrayEquals(BASE, Frost.decodeSafePoint(BASE).toBytes());
        byte[] neg = BASE.clone();
        neg[31] |= (byte) 0x80;
        assertArrayEquals(neg, Frost.decodeSafePoint(neg).toBytes());
        for (byte[] bad : new byte[][] {mixed, T2, identity(), new byte[32], NONCANON}) {
            assertThrows(IllegalArgumentException.class, () -> Frost.decodeSafePoint(bad));
        }
    }
}
