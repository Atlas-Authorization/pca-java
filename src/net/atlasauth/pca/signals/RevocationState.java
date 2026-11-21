package net.atlasauth.pca.signals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Subscriber-side revocation state. A resource server holds one and consults {@link Signals#isRevoked} on every request, next to
 * the core verifier. Every map stores the event_timestamp (seconds) of the revoking event; revocation is monotone: a key, once
 * present, is never removed.
 */
public final class RevocationState {
    /** grant_ref to event_timestamp of the revoking event. */
    public final Map<String, Double> revokedGrants = new LinkedHashMap<>();
    /** agent id to event_timestamp of the kill-switch that revoked all of its grants. */
    public final Map<String, Double> killedAgents = new LinkedHashMap<>();
    /** intent revocation id to event_timestamp of the intent-revoked event that named it; null until first used. */
    public Map<String, Double> revokedIntentIds;

    static void recordMax(Map<String, Double> m, String key, double ts) {
        Double prev = m.get(key);
        if (prev == null || ts > prev) m.put(key, ts);
    }

    private static List<Object> pairs(Map<String, Double> m) {
        List<Object> out = new ArrayList<>();
        for (Map.Entry<String, Double> e : m.entrySet()) {
            List<Object> p = new ArrayList<>();
            p.add(e.getKey());
            p.add(JsVal.numOf(e.getValue()));
            out.add(p);
        }
        return out;
    }

    /** The JSON form: {grants, agents, intents} as [key, timestamp] pairs (intents null while the map has never been used). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("grants", pairs(revokedGrants));
        m.put("agents", pairs(killedAgents));
        m.put("intents", revokedIntentIds == null ? null : pairs(revokedIntentIds));
        return m;
    }
}
