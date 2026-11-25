package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.controlevals.ControlEvals;
import net.atlasauth.pca.controlevals.ControlEvalsExample;
import org.junit.jupiter.api.Test;

/**
 * The example blue control protocol (with data-flow governance and the behavioral immune system) against the reference's own recorded episodes and
 * evaluations: the native protocol decides every action of every recorded run exactly as the TypeScript stack did (outcome, control, risk, threat
 * level, reason, budget), so the whole transcript and the aggregated report compare equal.
 */
class ControlEvalsExampleDiffTest {
    private static final String M = "ref-control-evals";

    @Test void episodesAreDecidedLikeTheReference() throws Exception {
        Facade.Handle agent = ControlEvalsExample.buildExampleAgent();
        OracleCases.each(M, "runEpisode", a -> {
            Map<String, Object> spec = ControlEvalsDiffTest.m(a.get(0));
            return ControlEvals.runEpisode(ControlEvalsDiffTest.red((String) spec.get("red")), ControlEvalsExample.exampleBlue(agent), ControlEvalsDiffTest.env((String) spec.get("env")), ControlEvalsDiffTest.d(spec.get("seed")));
        });
    }

    @Test void evaluationsAreScoredLikeTheReference() throws Exception {
        Facade.Handle agent = ControlEvalsExample.buildExampleAgent();
        OracleCases.each(M, "controlEval", a -> {
            Map<String, Object> spec = ControlEvalsDiffTest.m(a.get(0));
            List<ControlEvals.RedPolicy> reds = null;
            if (spec.get("reds") instanceof List) {
                reds = new ArrayList<>();
                for (Object n : ControlEvalsDiffTest.l(spec.get("reds"))) reds.add(ControlEvalsDiffTest.red((String) n));
            }
            return ControlEvals.controlEval(reds, ControlEvalsExample.exampleBlue(agent), ControlEvals.exampleEnv.name().equals(spec.get("env")) ? ControlEvals.exampleEnv : ControlEvalsDiffTest.env((String) spec.get("env")), spec.get("episodes"), spec.get("seed"));
        });
    }

    @SuppressWarnings("unchecked")
    @Test void exampleControlEvalIsDeterministicAndScoresEveryStrategy() {
        Map<String, Object> r = ControlEvalsExample.exampleControlEval();
        assertEquals(8L * ControlEvals.EXAMPLE_RED_POLICIES.size(), ((Number) r.get("episodes")).longValue());
        assertEquals(ControlEvals.EXAMPLE_RED_POLICIES.size(), ((Map<String, Object>) r.get("byStrategy")).size());
        assertEquals(Json.canonicalize(r), Json.canonicalize(ControlEvalsExample.exampleControlEval()));
        assertThrows(IllegalArgumentException.class, () -> ControlEvalsExample.exampleControlEval(0L, 1L, null));
    }
}
