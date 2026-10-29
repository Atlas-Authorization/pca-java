package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The K4 corpus (k4-vectors.json): escalation pricing, network-token binding, ERC-7715 check. A missing file FAILS. */
public class K4VectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("k4-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) { return (List<Object>) o; }

    @Test void escalation() {
        Map<String, Object> esc = m(DOC.get("escalation"));
        assertTrue(list(esc.get("config_cases")).size() >= 6);
        for (Object x : list(esc.get("config_cases"))) assertEquals(m(x).get("expect"), K4.pricingConfigError(m(x).get("config")), String.valueOf(m(x).get("name")));
        assertTrue(list(esc.get("decisions")).size() >= 14);
        for (Object x : list(esc.get("decisions"))) {
            K4.Verdict g = K4.decide(esc.get("config"), m(x).get("calibration"), m(x).get("risk"));
            assertEquals(m(m(x).get("expect")).get("ask"), g.ask, String.valueOf(m(x).get("risk")));
            assertEquals(m(m(x).get("expect")).get("reason"), g.reason, String.valueOf(m(x).get("risk")));
        }
        for (Object x : list(esc.get("calibration"))) {
            Map<String, Object> c = m(x);
            List<String> seen = new ArrayList<>();
            for (Object s : list(m(c.get("start")).get("seen"))) seen.add((String) s);
            K4.Calibration g = K4.updateCalibration(c.get("config"), Json.asLong(m(c.get("start")).get("multiplierPpm")), seen, list(c.get("answers")), m(c.get("risks")));
            assertEquals(Json.asLong(m(c.get("expect")).get("multiplierPpm")), g.multiplierPpm, String.valueOf(c.get("name")));
            assertEquals(m(c.get("expect")).get("seen"), g.seen, String.valueOf(c.get("name")));
        }
    }

    @Test void binding() {
        List<Object> cs = list(m(DOC.get("network_binding")).get("cases"));
        assertTrue(cs.size() >= 15);
        for (Object x : cs) {
            Map<String, Object> c = m(x), e = m(c.get("expect_in"));
            assertEquals(c.get("expect"), K4.verifyBinding(c.get("binding"), e.get("grant"), (String) e.get("holder"), (String) e.get("issuer_nonce"), (String) e.get("provider")), String.valueOf(c.get("name")));
        }
    }

    @Test void erc7715() {
        List<Object> cs = list(m(DOC.get("erc7715")).get("cases"));
        assertTrue(cs.size() >= 24);
        for (Object x : cs) {
            Map<String, Object> c = m(x), o = m(c.get("opts"));
            List<String> mgrs = new ArrayList<>();
            for (Object s : list(o.get("allowedManagers"))) mgrs.add((String) s);
            Map<String, Object> ctx = o.containsKey("contexts") ? m(o.get("contexts")) : Map.of();
            assertEquals(c.get("expect"), K4.verifyGranted(c.get("envelope"), c.get("sent"), c.get("got"), mgrs, k -> (String) ctx.get(k)), String.valueOf(c.get("name")));
        }
    }
}
