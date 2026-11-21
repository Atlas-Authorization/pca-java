package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** How a verifier assembles the Policy VM input from a PCActn and its own context, and the decision on it, against the reference corpus (240 cases). */
class DecideDeriveDiffTest {
    private static final String MOD = "ref-decide-derive";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ctx(List<?> a) { return a.size() > 1 && a.get(1) instanceof Map ? (Map<String, Object>) DecideDiffTest.revive(a.get(1)) : null; }

    @Test void everyCaseIsReplayed() throws Exception {
        assertEquals(240, BaseOracle.of(MOD, null).size());
        assertEquals(240, OracleCases.of(MOD, "deriveDecideInput").size() + OracleCases.of(MOD, "deriveThenDecide").size());
    }

    @Test void derive() throws Exception {
        OracleCases.each(MOD, "deriveDecideInput", a -> Decide.deriveDecideInput(DecideDiffTest.revive(a.get(0)), ctx(a)));
    }

    @Test void deriveThenDecide() throws Exception {
        OracleCases.each(MOD, "deriveThenDecide", a -> {
            Map<String, Object> input = Decide.deriveDecideInput(DecideDiffTest.revive(a.get(0)), ctx(a));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("input", input);
            out.put("decision", Decide.decide(input));
            return out;
        });
    }
}
