package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;

/** A vendor verifier's answer (the reference HardwareAttestationResult). */
public final class HardwareResult {
    public final boolean ok;
    public final boolean bound;
    public final String reason;
    /** model_id, weights_digest, weights_measured, runtime_measurement, operator (and vendor extras); null when not ok. */
    public final Map<String, Object> measured;
    public final Map<String, String> hostAsserted;

    public HardwareResult(boolean ok, boolean bound, String reason, Map<String, Object> measured, Map<String, String> hostAsserted) {
        this.ok = ok;
        this.bound = bound;
        this.reason = reason == null ? "" : reason;
        this.measured = measured;
        this.hostAsserted = hostAsserted;
    }

    public static HardwareResult fail(String reason) { return new HardwareResult(false, false, reason, null, null); }

    public static HardwareResult ok(boolean bound, Map<String, Object> measured, Map<String, String> hostAsserted) {
        return new HardwareResult(true, bound, "", measured, hostAsserted);
    }

    /** The language-neutral form of the result (what the conformance vectors record in {@code expect}). */
    public Map<String, Object> wire() {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!ok) {
            out.put("ok", false);
            out.put("reason", reason);
            return out;
        }
        out.put("ok", true);
        out.put("bound", bound);
        if (measured != null) out.put("measured", measured);
        if (hostAsserted != null) out.put("hostAsserted", new LinkedHashMap<String, Object>(hostAsserted));
        return out;
    }

    /** The measured identity the passport seam compares: model_id "", weights_digest "", weights_measured false, plus the two given. */
    public static Map<String, Object> newMeasured(String runtimeMeasurement, String operator) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("model_id", "");
        m.put("weights_digest", "");
        m.put("weights_measured", false);
        m.put("runtime_measurement", runtimeMeasurement);
        m.put("operator", operator);
        return m;
    }
}
