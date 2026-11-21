package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentRamp.DriftDetector;
import net.atlasauth.pca.intent.IntentRamp.DriftState;

/**
 * Trust ramp: start narrow, widen only through confirmed behaviour, and every negative runtime signal vetoes its cell for good. A one-sided
 * Bernoulli CUSUM on divergences (negative signals about actions the grant admitted) freezes widening on alarm: positive signals are queued
 * until a rebase on a new signed statement; negative signals are always applied.
 */
public final class IntentTrustRamp {
    private IntentLearner l;
    public final DriftDetector drift;
    private List<Object[]> queued = new ArrayList<>(); // {Outcome, String signal}
    public final List<RampRecord> log = new ArrayList<>();

    public IntentTrustRamp(IntentLearner learner, Double rho0, Double rho1, Double h) {
        this.l = learner;
        this.drift = new DriftDetector(rho0, rho1, h);
    }

    /** One recorded signal. */
    public record RampRecord(String signal, int y, boolean wasInGrant, int before, int after, boolean applied, DriftState drift) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("signal", signal);
            m.put("y", (double) y);
            m.put("wasInGrant", wasInGrant);
            m.put("before", (double) before);
            m.put("after", (double) after);
            m.put("applied", applied);
            m.put("drift", drift.toJson());
            return m;
        }
    }

    public IntentLearner learner() { return l; }

    /** Widening is frozen while a drift alarm stands. */
    public boolean frozen() { return drift.state().alarm(); }

    /** Positive signals held back by a freeze (released only by a rebase, which discards them). */
    public List<Map<String, Object>> pending() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object[] q : queued) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("o", IntentOmega.outcomeToJson((Outcome) q[0]));
            m.put("signal", q[1]);
            out.add(m);
        }
        return out;
    }

    /** A live read-only view of the queue as it is now: later queued signals show in it until a rebase replaces the queue. */
    public List<Map<String, Object>> pendingView() {
        final List<Object[]> q = queued;
        return new java.util.AbstractList<Map<String, Object>>() {
            @Override public int size() { return q.size(); }
            @Override public Map<String, Object> get(int i) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("o", IntentOmega.outcomeToJson((Outcome) q.get(i)[0]));
                m.put("signal", q.get(i)[1]);
                return m;
            }
        };
    }

    private int grantSize() {
        int n = 0;
        for (IntentLearner.CellView c : l.cells()) if (c.inGrant) n++;
        return n;
    }

    public RampRecord record(Outcome o, String signal) {
        int y = IntentRamp.signalLabel(signal);
        boolean wasInGrant = l.admitsOutcome(o);
        int before = grantSize();
        DriftState d = drift.state();
        if (wasInGrant) d = drift.update(y == 0);
        boolean applied = true;
        if (y == 1 && frozen()) {
            queued.add(new Object[] {o, signal});
            applied = false;
        } else l.observe(o, y, "runtime", null);
        RampRecord rec = new RampRecord(signal, y, wasInGrant, before, grantSize(), applied, d);
        log.add(rec);
        return rec;
    }

    /**
     * Record a SIGNED runtime observation: the signature must verify, the signer must be trusted, and the observation must be about this map
     * and a runtime one. Returns {ok: true, record} or {ok: false, reason}.
     */
    public Map<String, Object> recordObservation(Object obs, String mapDigest, List<String> trustedSigners, String expectedSigner, Map<String, Object> pqPins) {
        Map<String, Object> v = IntentObservation.verifyIntentObservation(obs, expectedSigner, pqPins);
        Map<String, Object> r = new LinkedHashMap<>();
        if (!Boolean.TRUE.equals(v.get("ok"))) { r.put("ok", false); r.put("reason", v.get("reason")); return r; }
        Map<?, ?> o = (Map<?, ?>) obs;
        if (!trustedSigners.contains(o.get("signer"))) { r.put("ok", false); r.put("reason", "untrusted observation signer"); return r; }
        if (!mapDigest.equals(o.get("map_digest"))) { r.put("ok", false); r.put("reason", "observation is about a different map"); return r; }
        if (!"runtime".equals(o.get("source"))) { r.put("ok", false); r.put("reason", "only runtime observations feed the ramp"); return r; }
        Map<String, Object> vals = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : ((Map<?, ?>) o.get("values")).entrySet()) vals.put((String) e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
        boolean yes = IntentOmega.dbl(o.get("y")) == 1;
        RampRecord rec = record(new Outcome((String) o.get("verb"), vals), yes ? "principal-confirm" : "postcondition-violation");
        r.put("ok", true);
        r.put("record", rec.toJson());
        return r;
    }

    /** Re-base on a new learner (the only way to clear an alarm): the old vetoes are not carried over and queued positives are discarded. */
    public void rebase(IntentLearner next) {
        this.l = next;
        this.queued = new ArrayList<>(); // a new list: a view taken before the rebase keeps the signals it saw
        this.drift.reset();
    }
}
