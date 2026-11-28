package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The ledger-entry comparator of the monitor state: {@code a.t - b.t || a.amount - b.amount} as a three-way sign. */
class LedgerEntryOrderTest {
    static Map<String, Object> e(double t, double amount) { return Prohibitions.map("t", Prohibitions.jn(t), "amount", Prohibitions.jn(amount)); }

    static int cmp(Map<String, Object> a, Map<String, Object> b) throws Exception {
        Method m = Prohibitions.class.getDeclaredMethod("cmpEntry", Map.class, Map.class);
        m.setAccessible(true);
        return (Integer) m.invoke(null, a, b);
    }

    @Test void theTimeDecidesFirstThenTheAmountAndEqualEntriesTie() throws Exception {
        assertEquals(-1, cmp(e(1, 9), e(2, 0)));
        assertEquals(1, cmp(e(2, 0), e(1, 9)));
        assertEquals(-1, cmp(e(5, 3), e(5, 5)));
        assertEquals(1, cmp(e(5, 5), e(5, 3)));
        assertEquals(0, cmp(e(5, 3), e(5, 3)));
        assertEquals(0, cmp(e(0, 0), e(0, 0)));
        assertEquals(1, cmp(e(5, 0.5), e(5, 0.25)));
        assertEquals(-1, cmp(e(5, 0.25), e(5, 0.5)));
    }
}
