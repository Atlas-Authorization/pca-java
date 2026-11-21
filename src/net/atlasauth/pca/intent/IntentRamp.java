package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The trust ramp's pure parts: runtime signal labels, the narrow starting configuration, and the drift detector, a one-sided
 * Bernoulli CUSUM on divergences (negative signals about actions the grant admitted). S_t = max(0, S_{t-1} + log LR_t); an
 * alarm at S_t &gt;= h is sticky until reset.
 */
public final class IntentRamp {
    private IntentRamp() {}

    /** y = 1 for jit-approve and principal-confirm; every other signal is y = 0 (a veto). */
    public static int signalLabel(String signal) { return "jit-approve".equals(signal) || "principal-confirm".equals(signal) ? 1 : 0; }

    /** The narrow start: tau 1, eta 0, a high empty-set prior for every verb (very high for verbs the slots do not name). */
    public static Map<String, Object> narrowStart(Omega omega, Object slots, Double slotNullMass, Double otherNullMass) {
        Map<String, Object> nullMass = new LinkedHashMap<>();
        Object verbs = slots instanceof Map ? ((Map<?, ?>) slots).get("verbs") : null;
        for (VerbSpace vs : omega.verbs) {
            boolean named = false;
            if (verbs instanceof List) for (Object v : (List<?>) verbs) if (vs.verb.equals(v)) named = true;
            nullMass.put(vs.verb, named ? (slotNullMass != null ? slotNullMass : 0.5) : (otherNullMass != null ? otherNullMass : 0.95));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("eta", 0.0);
        out.put("tau", 1.0);
        out.put("nullMass", nullMass);
        return out;
    }

    /** The detector's state. */
    public record DriftState(double statistic, boolean alarm, double informative, double divergences) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("statistic", statistic);
            m.put("alarm", alarm);
            m.put("informative", informative);
            m.put("divergences", divergences);
            return m;
        }
    }

    public static final class DriftDetector {
        public final double rho0, rho1, h;
        private DriftState s = new DriftState(0, false, 0, 0);

        /** Defaults: rho0 0.02, rho1 0.25, h ln(100); a null member takes its default. */
        public DriftDetector(Double rho0, Double rho1, Double h) {
            this.rho0 = rho0 != null ? rho0 : 0.02;
            this.rho1 = rho1 != null ? rho1 : 0.25;
            this.h = h != null ? h : StrictMath.log(100);
            if (!(this.rho0 > 0 && this.rho0 < this.rho1 && this.rho1 < 1)) throw new IllegalArgumentException("DriftDetector: need 0 < rho0 < rho1 < 1");
            if (!(this.h > 0)) throw new IllegalArgumentException("DriftDetector: h must be positive");
        }

        /** Feed one signal about an action inside the grant: {@code diverged} = a negative signal. */
        public DriftState update(boolean diverged) {
            double inc = diverged ? StrictMath.log(rho1 / rho0) : StrictMath.log((1 - rho1) / (1 - rho0));
            double statistic = Math.max(0, s.statistic() + inc);
            s = new DriftState(statistic, s.alarm() || statistic >= h, s.informative() + 1, s.divergences() + (diverged ? 1 : 0));
            return s;
        }

        public DriftState state() { return s; }

        public void reset() { s = new DriftState(0, false, 0, 0); }
    }
}
