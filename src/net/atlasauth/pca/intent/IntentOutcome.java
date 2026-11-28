package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/** Checking an executed action's effect against its postconditions and feeding a violation back, and the Monte Carlo form of the residual-risk estimate. */
public final class IntentOutcome {
    private IntentOutcome() {}

    /**
     * Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the action's cell; ok and
     * pending change nothing. {@code pcs} null = the default postconditions. Returns {report, divergence?}.
     */
    public static Map<String, Object> verifyOutcome(IntentLearner l, Outcome o, Map<String, Object> effect, List<?> pcs) {
        VerbSpace vs = null;
        for (VerbSpace v : l.omega.verbs) if (v.verb.equals(o.verb())) { vs = v; break; }
        if (vs == null) throw new IllegalArgumentException("verifyOutcome: no verb " + o.verb() + " in Ω");
        Map<String, Object> report = pcs == null ? IntentEffects.checkPostconditions(vs, o, effect) : IntentEffects.checkPostconditions(vs, o, effect, pcs);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("report", report);
        if ("violated".equals(report.get("status"))) r.put("divergence", IntentMapKit.applyDivergence(l, o, 0));
        return r;
    }

    /** The Monte Carlo residual-risk estimate of the learner's grant over {@code samples} draws (default 20000) with the seeded generator (default 7). */
    public static double estimateResidualRiskMC(IntentLearner l, Integer samples, Double seed) {
        int m = samples != null ? samples : 20_000;
        DoubleSupplier rand = IntentOmega.rng(seed != null ? seed : 7);
        IntentLearner.Synthesis syn = l.synthesize();
        Map<String, Object> grant = new LinkedHashMap<>();
        grant.put("predicates", syn.predicates);
        grant.put("caveats", syn.caveats);
        IntentPolicy.Admitter g = IntentPolicy.admitter(grant);
        double r = 0;
        for (int i = 0; i < m; i++) {
            IntentOmega.Sample s = IntentOmega.sampleOutcome(l.omega, rand);
            if (g.admits(s.vs(), s.o())) r += (1 - l.acceptance(s.o())) * IntentOmega.harmOf(s.vs(), s.o(), l.harm);
        }
        return r / m;
    }
}
