package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** identity_overrides merge only into a successful result that measured something, and only when there are overrides. */
public class VendorVerifierK05bKillTest {
    static HardwareResult through(HardwareResult r, Map<String, Object> overrides) {
        return new VendorVerifier("test", (ev, b, now) -> r, overrides).verify(null, null, 0L);
    }

    @Test
    void overridesMergeOnlyIntoMeasuredSuccess() {
        Map<String, Object> measured = new LinkedHashMap<>();
        measured.put("a", "1");
        Map<String, Object> ov = new LinkedHashMap<>();
        ov.put("b", "2");

        HardwareResult ok = HardwareResult.ok(true, measured, null);
        assertSame(ok, through(ok, null));
        assertSame(ok, through(ok, new LinkedHashMap<>()));
        HardwareResult merged = through(ok, ov);
        assertTrue(merged.ok);
        Map<String, Object> want = new LinkedHashMap<>(measured);
        want.put("b", "2");
        assertEquals(want, merged.measured);

        // a refusal is returned as is, even one that carries a measured map
        HardwareResult refused = new HardwareResult(false, false, "no", measured, null);
        assertSame(refused, through(refused, ov));
        // a success that measured nothing: nothing to merge into
        HardwareResult bare = HardwareResult.ok(true, null, null);
        assertSame(bare, through(bare, ov));
    }
}
