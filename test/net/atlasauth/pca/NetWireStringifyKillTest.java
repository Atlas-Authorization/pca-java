package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.NetWire;
import org.junit.jupiter.api.Test;

/** A party's final report carries measured times as doubles; the wire JSON writer must spell them like JSON.stringify (it once threw, aborting every mesh that had a Java party). */
public class NetWireStringifyKillTest {
    @Test void doublesAreSpelledLikeJsonStringify() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("whole", 12.0);
        m.put("fraction", 0.25);
        m.put("big", 1e21);
        m.put("small", 1e-7);
        m.put("nan", Double.NaN);
        m.put("inf", Double.POSITIVE_INFINITY);
        m.put("float", 1.5f);
        m.put("list", List.of(3.0, 4L, "x"));
        assertEquals("{\"whole\":12,\"fraction\":0.25,\"big\":1e+21,\"small\":1e-7,\"nan\":null,\"inf\":null,\"float\":1.5,\"list\":[3,4,\"x\"]}", NetWire.stringify(m));
    }
}
