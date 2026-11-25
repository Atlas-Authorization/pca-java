package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    /** a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused. */
    @SuppressWarnings("unchecked")
    @Test void emptyHeadAdvances() {
        Map<String, Object> j = (Map<String, Object>) IntentJs.normalize(Json.parseLenient("{\"e\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":0,\"root\":\"\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"n\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":3,\"root\":\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"ok\":{\"oldSize\":0,\"newSize\":3,\"path\":[]},\"path\":{\"oldSize\":0,\"newSize\":3,\"path\":[\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\"]},\"old1\":{\"oldSize\":1,\"newSize\":3,\"path\":[]}}"));
        assertEquals("", Mesh.checkHeadAdvance(j.get("e"), j.get("n"), j.get("ok")));
        assertEquals("consistency proof required for a larger head", Mesh.checkHeadAdvance(j.get("e"), j.get("n"), null));
        assertEquals("head is not consistent with the previous head (fork or rewrite)", Mesh.checkHeadAdvance(j.get("e"), j.get("n"), j.get("path")));
        assertEquals("consistency proof required for a larger head", Mesh.checkHeadAdvance(j.get("e"), j.get("n"), j.get("old1")));
    }
}
