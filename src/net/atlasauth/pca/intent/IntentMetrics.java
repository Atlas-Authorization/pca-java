package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.intent.IntentOmega.HarmModel;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Measuring a grant against an intent over the outcome space: risk R(G) = E[1_G (1 - a) h], burden B(G) = E[1_notG a],
 * R_max = E[(1 - a) h], fidelity F = 1 - R / R_max, by Monte Carlo with the real evaluator on both sides or exactly by summing
 * over cells.
 */
public final class IntentMetrics {
    private IntentMetrics() {}

    /** The acceptability of an outcome in [0, 1]. */
    public interface Acceptability { double of(VerbSpace vs, Outcome o); }

    public static Acceptability acceptabilityOf(Object policy) {
        IntentPolicy.Admitter a = IntentPolicy.admitter(policy);
        return (vs, o) -> a.admits(vs, o) ? 1 : 0;
    }

    public record GrantMetrics(double risk, double burden, double riskMax, double fidelity, double samples, double riskHalfWidth, Double meanHarm) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("risk", risk);
            m.put("burden", burden);
            m.put("riskMax", riskMax);
            m.put("fidelity", fidelity);
            if (meanHarm == null) {
                m.put("samples", samples);
                m.put("riskHalfWidth", riskHalfWidth);
            } else m.put("meanHarm", meanHarm);
            return m;
        }
    }

    public static GrantMetrics measureGrant(Omega omega, Object grant, Acceptability acceptability) {
        return measureGrant(omega, grant, acceptability, 20000, 1, IntentOmega.DEFAULT_HARM, null);
    }

    /** Monte Carlo over the workload; {@code hMax} null = the largest harm drawn. */
    public static GrantMetrics measureGrant(Omega omega, Object grant, Acceptability acceptability, double samples, double seed, HarmModel harm, Double hMax) {
        double M = samples;
        DoubleSupplier rand = IntentOmega.rng(seed);
        IntentPolicy.Admitter g = IntentPolicy.admitter(grant);
        double R = 0, B = 0, Rm = 0, hm = 0;
        for (double i = 0; i < M; i++) {
            IntentOmega.Sample s = IntentOmega.sampleOutcome(omega, rand);
            double a = acceptability.of(s.vs(), s.o());
            double h = IntentOmega.harmOf(s.vs(), s.o(), harm);
            hm = Math.max(hm, h);
            if (g.admits(s.vs(), s.o())) R += (1 - a) * h;
            else B += a;
            Rm += (1 - a) * h;
        }
        R /= M;
        B /= M;
        Rm /= M;
        return new GrantMetrics(R, B, Rm, Rm > 0 ? 1 - R / Rm : 1, M, IntentStats.hoeffdingHalfWidth(hMax != null ? hMax : hm, M), null);
    }

    public static GrantMetrics measureGrantExact(Omega omega, Object grant, Acceptability acceptability) {
        return measureGrantExact(omega, grant, acceptability, IntentOmega.DEFAULT_HARM);
    }

    /** Exact R, B, R_max, F by summing over the cells; valid when grant and acceptability are constant on each cell. */
    public static GrantMetrics measureGrantExact(Omega omega, Object grant, Acceptability acceptability, HarmModel harm) {
        IntentPolicy.Admitter g = IntentPolicy.admitter(grant);
        double R = 0, B = 0, Rm = 0, Eh = 0;
        for (VerbSpace vs : omega.verbs) {
            double n = IntentOmega.verbCellCount(vs);
            for (double c = 0; c < n; c++) {
                int[] idx = IntentOmega.decodeCell(vs, c);
                Outcome o = IntentOmega.cellRep(vs, idx);
                IntentOmega.Stats st = IntentOmega.cellStats(vs, idx, harm);
                double a = acceptability.of(vs, o);
                Eh += st.mass() * st.harm();
                Rm += st.mass() * (1 - a) * st.harm();
                if (g.admits(vs, o)) R += st.mass() * (1 - a) * st.harm();
                else B += st.mass() * a;
            }
        }
        return new GrantMetrics(R, B, Rm, Rm > 0 ? 1 - R / Rm : 1, 0, 0, Eh);
    }

}
