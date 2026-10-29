package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The "hop widens authority" branch of verifyMeshProof cannot be reached through a validly chained proof (each hop's caveats
 * start with its parent's, and effective authority is a conjunction), so it is pinned here on the narrowing relation itself.
 */
public class MeshNarrowsTest {
    private static Map<String, Object> cv(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static Object scope(String... a) { return cv("type", "scope", "actions", List.of(a)); }
    private static Object amount(long n) { return cv("type", "max_amount", "max", IntentJs.ofLong(n)); }
    private static Object hops(long n) { return cv("type", "max_hops", "n", IntentJs.ofLong(n)); }

    @Test void equalAndNarrowerPass() {
        assertTrue(Mesh.narrowsCaveats(List.of(scope("pay"), amount(5)), List.of(scope("pay", "read"), amount(10))));
        assertTrue(Mesh.narrowsCaveats(List.of(scope("pay"), amount(10)), List.of(scope("pay"), amount(10))));
    }

    @Test void widerOrDroppedBoundsAreRefused() {
        assertFalse(Mesh.narrowsCaveats(List.of(scope("pay", "refund")), List.of(scope("pay"))));
        assertFalse(Mesh.narrowsCaveats(List.of(amount(11)), List.of(amount(10))));
        assertFalse(Mesh.narrowsCaveats(List.of(scope("pay")), List.of(scope("pay"), amount(10))));
        assertFalse(Mesh.narrowsCaveats(List.of(hops(3)), List.of(hops(2))));
        assertFalse(Mesh.narrowsCaveats(List.of(cv("type", "resource", "prefix", "a/")), List.of(cv("type", "resource", "prefix", "a/b/"))));
    }

    @Test void malformedCaveatsNeverNarrow() {
        assertFalse(Mesh.narrowsCaveats(List.of(cv("type", "nope")), List.of(scope("pay"))));
    }
}
