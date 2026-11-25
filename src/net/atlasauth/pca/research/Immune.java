package net.atlasauth.pca.research;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import net.atlasauth.pca.AtomicKv;
import net.atlasauth.pca.InvariantsBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.StoreJs;
import net.atlasauth.pca.W3Bridge;

/**
 * The read side of the behavioural immune system the console uses: the per-principal risk baseline, the observation fold
 * ({@link #observe}), the state validation and the threat read ({@link #assess}). A heuristic (EWMA and z-score over one principal's
 * history): it can be gamed by a slow attacker who drifts the baseline and is no proof that an agent is compromised or benign.
 *
 * <p>An immune state is {@code {baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}}; an observation is {@code {r, at, stepUp?, denied?}}.
 */
public final class Immune {
    private Immune() {}

    private static final double MAX_COUNT = 1e9;
    private static final double ALPHA = 0.3, HALF_LIFE_MS = 3_600_000, DRIFT_Z_SAT = 3, STEP_UP_SAT = 5, DENY_SAT = 3;

    /** The default immune tuning {@code {alpha, halfLifeMs, driftZSat, stepUpSat, denySat}} (the constants {@link #observe} and {@link #assess} use). */
    public static final Map<String, Object> DEFAULT_IMMUNE_CONFIG;
    /** The default adaptation caps {@code {maxKappaMult, minThetaMult}} (the ones {@link #adapt} defaults to). */
    public static final Map<String, Object> DEFAULT_ADAPT_CONFIG;
    static {
        Map<String, Object> i = new LinkedHashMap<>();
        i.put("alpha", StoreJs.num(ALPHA));
        i.put("halfLifeMs", StoreJs.num(HALF_LIFE_MS));
        i.put("driftZSat", StoreJs.num(DRIFT_Z_SAT));
        i.put("stepUpSat", StoreJs.num(STEP_UP_SAT));
        i.put("denySat", StoreJs.num(DENY_SAT));
        DEFAULT_IMMUNE_CONFIG = java.util.Collections.unmodifiableMap(i);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("maxKappaMult", StoreJs.num(3.0));
        a.put("minThetaMult", StoreJs.num(0.4));
        DEFAULT_ADAPT_CONFIG = java.util.Collections.unmodifiableMap(a);
    }

    /** The empty baseline {@code {n: 0, mean: 0, m2: 0}}. */
    public static Map<String, Object> emptyBaseline() {
        Map<String, Object> b = Js.obj();
        b.put("n", Js.n(0L));
        b.put("mean", Js.n(0L));
        b.put("m2", Js.n(0L));
        return b;
    }

    /** The state of a principal with no history. */
    public static Map<String, Object> initialState() {
        Map<String, Object> s = Js.obj();
        s.put("baseline", emptyBaseline());
        s.put("ewma", Js.n(0L));
        s.put("stepUps", Js.n(0L));
        s.put("denies", Js.n(0L));
        s.put("lastAt", Js.n(0L));
        s.put("seeded", false);
        return s;
    }

    private static double fin(Object x) { return Js.isFinite(x) ? Js.d(x) : 0; }

    /** Welford update of a baseline with one risk sample (a non-finite sample counts as 0). */
    public static Map<String, Object> updateBaseline(Map<String, Object> b, double r) {
        double x = Double.isNaN(r) || Double.isInfinite(r) ? 0 : r;
        double n = Js.d(b.get("n")) + 1;
        double delta = x - Js.d(b.get("mean"));
        double mean = Js.d(b.get("mean")) + delta / n;
        double m2 = Js.d(b.get("m2")) + delta * (x - mean);
        Map<String, Object> out = Js.obj();
        out.put("n", Js.n(n));
        out.put("mean", Js.n(mean));
        out.put("m2", Js.n(m2));
        return out;
    }

    /** Population standard deviation of the baseline (0 until at least 2 samples). */
    public static double baselineStd(Map<String, Object> b) {
        double n = Js.d(b.get("n"));
        return n >= 2 ? Math.sqrt(Js.d(b.get("m2")) / n) : 0;
    }

    private static final double DECAY_STEPS_PER_HALF_LIFE = 1024;
    /** 2^(-1/1024) rounded to the nearest double (the same literal in every language). */
    private static final double DECAY_STEP = 0.9993233275026507;

    /**
     * Exponential decay by a half-life from exactly rounded operations only (no pow, exp or log): the elapsed time is quantized down to
     * whole 1/1024ths of a half-life, and the factor is 0.5 multiplied floor(u / 1024) times, then DECAY_STEP multiplied (u mod 1024)
     * times, one multiplication at a time in IEEE double (Java never fuses a plain multiply-add).
     */
    private static double decay(double count, double dtMs, double halfLifeMs) {
        if (dtMs <= 0 || count == 0) return count;
        double u = Math.floor((dtMs * DECAY_STEPS_PER_HALF_LIFE) / halfLifeMs);
        if (Double.isNaN(u)) return Double.NaN;
        if (u >= DECAY_STEPS_PER_HALF_LIFE * 1100) return count * 0; // 0.5^1100 underflows
        double k = Math.floor(u / DECAY_STEPS_PER_HALF_LIFE);
        double m = u - k * DECAY_STEPS_PER_HALF_LIFE;
        double f = 1;
        for (long i = 0; i < (long) k; i++) f *= 0.5;
        for (long i = 0; i < (long) m; i++) f *= DECAY_STEP;
        return count * f;
    }

    private static double cfg(Map<String, Object> cfg, String key) {
        Double d = StoreJs.dbl(cfg.get(key));
        return d == null ? Double.NaN : d;
    }

    /** Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters). */
    public static Map<String, Object> observe(Map<String, Object> state, Map<String, Object> obs) { return observe(state, obs, DEFAULT_IMMUNE_CONFIG); }

    /** {@link #observe(Map, Map)} under the given tuning ({@code alpha, halfLifeMs} are read). */
    public static Map<String, Object> observe(Map<String, Object> state, Map<String, Object> obs, Map<String, Object> config) {
        double alpha = cfg(config, "alpha"), halfLifeMs = cfg(config, "halfLifeMs");
        double r = Math.max(0, Math.min(1, Js.isFinite(obs.get("r")) ? Js.d(obs.get("r")) : 0));
        double lastAt = Js.d(state.get("lastAt"));
        double at = Js.isFinite(obs.get("at")) ? Js.d(obs.get("at")) : lastAt;
        boolean seeded = Boolean.TRUE.equals(state.get("seeded"));
        double dt = seeded ? Math.max(0, at - lastAt) : 0;
        Map<String, Object> baseline = updateBaseline(Js.map(state.get("baseline")), r);
        double ewma = seeded ? alpha * r + (1 - alpha) * Js.d(state.get("ewma")) : r;
        double stepUps = decay(Js.d(state.get("stepUps")), dt, halfLifeMs) + (Js.truthy(obs.get("stepUp")) ? 1 : 0);
        double denies = decay(Js.d(state.get("denies")), dt, halfLifeMs) + (Js.truthy(obs.get("denied")) ? 1 : 0);
        Map<String, Object> s = Js.obj();
        s.put("baseline", baseline);
        s.put("ewma", Js.n(ewma));
        s.put("stepUps", Js.n(stepUps));
        s.put("denies", Js.n(denies));
        s.put("lastAt", Js.n(at));
        s.put("seeded", true);
        return s;
    }

    private static boolean inRange(Object x, double lo, double hi) { return Js.isFinite(x) && Js.d(x) >= lo && Js.d(x) <= hi; }

    private static boolean isInteger(Object x) { double d = Js.d(x); return d == Math.floor(d); }

    private static boolean negZero(Object x) { double d = Js.d(x); return d == 0 && 1 / d < 0; }

    /** The reason a state is malformed (non-finite, negative, out of bound), or null. */
    public static String validateImmuneState(Object s) {
        Map<String, Object> x = s instanceof List ? Js.obj() : Js.map(s); // an array is an object with no members
        if (x == null) return "state must be an object";
        Object bo = x.get("baseline");
        Map<String, Object> b = bo instanceof List ? Js.obj() : Js.map(bo);
        if (b == null) return "baseline missing";
        if (!inRange(b.get("n"), 0, MAX_COUNT) || !isInteger(b.get("n")) || negZero(b.get("n"))) return "baseline.n must be an integer in [0, 1e9]";
        if (!inRange(b.get("mean"), 0, 1)) return "baseline.mean must be in [0, 1]";
        if (!inRange(b.get("m2"), 0, MAX_COUNT)) return "baseline.m2 must be finite and >= 0";
        if (!inRange(x.get("ewma"), 0, 1)) return "ewma must be in [0, 1]";
        if (!inRange(x.get("stepUps"), 0, MAX_COUNT)) return "stepUps must be finite and >= 0";
        if (!inRange(x.get("denies"), 0, MAX_COUNT)) return "denies must be finite and >= 0";
        if (!inRange(x.get("lastAt"), 0, 9007199254740991.0)) return "lastAt must be a finite non-negative time";
        if (!(x.get("seeded") instanceof Boolean)) return "seeded must be a boolean";
        return null;
    }

    private static double clamp01(double x) { return Math.max(0, Math.min(1, x)); }

    /**
     * The current threat from the immune state: {@code {level: calm|elevated|high, score, signals, components: {drift, volatility, violation}}}.
     * The score is the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66. A malformed state is
     * the maximal threat.
     */
    public static Map<String, Object> assess(Object state) { return assess(state, DEFAULT_IMMUNE_CONFIG); }

    /** {@link #assess(Object)} under the given tuning ({@code driftZSat, stepUpSat, denySat} are read). */
    public static Map<String, Object> assess(Object state, Map<String, Object> config) {
        double driftZSat = cfg(config, "driftZSat"), stepUpSat = cfg(config, "stepUpSat"), denySat = cfg(config, "denySat");
        String bad = validateImmuneState(state);
        if (bad != null) return threat("high", 1, List.of("invalid immune state: " + bad), 1, 1, 1);
        Map<String, Object> st = Js.map(state);
        Map<String, Object> base = Js.map(st.get("baseline"));
        double std = baselineStd(base);
        List<String> signals = new ArrayList<>();
        double drift = 0;
        if (Js.d(base.get("n")) >= 5 && std > 1e-9) {
            double z = (Js.d(st.get("ewma")) - Js.d(base.get("mean"))) / std;
            drift = clamp01(z / driftZSat);
            if (drift > 0.33) signals.add("risk drifted " + Js.toFixed(z, 1) + "σ above baseline");
        }
        double stepUps = Js.d(st.get("stepUps")), denies = Js.d(st.get("denies"));
        double volatility = clamp01(stepUps / stepUpSat);
        if (volatility > 0.33) signals.add("elevated step-up rate (" + Js.toFixed(stepUps, 1) + ")");
        double violation = clamp01(denies / denySat);
        if (violation > 0.33) signals.add("repeated policy violations (" + Js.toFixed(denies, 1) + ")");
        double score = Math.max(drift, Math.max(volatility, violation));
        return threat(score >= 0.66 ? "high" : score >= 0.33 ? "elevated" : "calm", score, signals, drift, volatility, violation);
    }

    private static Map<String, Object> threat(String level, double score, List<String> signals, double drift, double volatility, double violation) {
        Map<String, Object> t = Js.obj();
        t.put("level", level);
        t.put("score", Js.n(score));
        t.put("signals", new ArrayList<Object>(signals));
        Map<String, Object> c = Js.obj();
        c.put("drift", Js.n(drift));
        c.put("volatility", Js.n(volatility));
        c.put("violation", Js.n(violation));
        t.put("components", c);
        return t;
    }

    // ---- adaptation ------------------------------------------------------------------------------------------------

    /** A relational operand as JavaScript converts it (an absent member is NaN, null is 0, a numeric string its value). */
    private static double operand(Map<String, Object> o, String k) { return o.containsKey(k) ? net.atlasauth.pca.doctor.Js.toNumber(o.get(k)) : Double.NaN; }

    private static double num(Object x) { Double d = StoreJs.dbl(x); return d == null ? Double.NaN : d; }

    /** The adapted policy for a threat assessment, derived from the BASE policy (never compounded): {@code {policy, changed, rationale}}. Default caps: kappa x3, theta x0.4. */
    public static Map<String, Object> adapt(Object base, Map<String, Object> assessment) { return adapt(base, assessment, 3, 0.4); }

    public static Map<String, Object> adapt(Object baseIn, Map<String, Object> assessment, double maxKappaMult, double minThetaMult) {
        Map<String, Object> base = baseIn instanceof Map ? Js.map(baseIn) : Js.obj(); // a non-object spreads to nothing
        double s = Js.isFinite(assessment.get("score")) ? clamp01(Js.d(assessment.get("score"))) : 1; // a non-finite score is the worst case, never calm
        if (s == 0) return adaptation(baseIn, false, "calm \u2014 baseline policy");
        if (baseIn == null) throw new IllegalArgumentException("base policy missing");
        double kappaMult = 1 + (maxKappaMult - 1) * s;
        double thetaMult = 1 - (1 - minThetaMult) * s;
        Map<String, Object> policy = new LinkedHashMap<>(base);
        Map<String, Object> w = Js.map(base.get("weights"));
        policy.put("weights", w == null ? Js.obj() : new LinkedHashMap<>(w));
        policy.put("kappa", Js.n(num(base.get("kappa")) * kappaMult));
        policy.put("theta1", Js.n(clamp01(num(base.get("theta1")) * thetaMult)));
        policy.put("theta2", Js.n(clamp01(num(base.get("theta2")) * thetaMult)));
        String bad = InvariantsBridge.validateRiskPolicy(policy);
        if (bad == null) bad = noWidenViolation(base, policy);
        if (bad != null) return adaptation(baseIn, false, "adaptation rejected (" + bad + ") \u2014 kept baseline");
        List<?> sig = (List<?>) assessment.get("signals");
        String why = !sig.isEmpty() ? String.join("; ", sig.stream().map(Js::str).toList()) : "threat score " + Js.toFixed(s, 2);
        return adaptation(policy, true, Js.str(assessment.get("level")) + ": " + why + " \u2192 \u03ba \u00d7" + Js.toFixed(kappaMult, 2) + ", \u03b8 \u00d7" + Js.toFixed(thetaMult, 2));
    }

    private static Map<String, Object> adaptation(Object policy, boolean changed, String rationale) {
        Map<String, Object> a = Js.obj();
        a.put("policy", policy);
        a.put("changed", changed);
        a.put("rationale", rationale);
        return a;
    }

    private static boolean same(Object a, Object b) {
        Double x = StoreJs.dbl(a), y = StoreJs.dbl(b);
        return x != null && y != null ? x.doubleValue() == y.doubleValue() : Objects.equals(a, b);
    }

    /** Why {@code adapted} is looser than {@code base}, or null when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as looser. */
    public static String noWidenViolation(Map<String, Object> base, Map<String, Object> adapted) {
        // null and booleans coerce to numbers in a relational comparison: a value that is not a number is a violation before any comparison
        for (String k : new String[] {"kappa", "theta1", "theta2"}) if (StoreJs.dbl(adapted.get(k)) == null) return "kappa and theta must be numbers";
        if (!(operand(adapted, "kappa") >= operand(base, "kappa"))) return "kappa decreased";
        if (!(operand(adapted, "theta1") <= operand(base, "theta1"))) return "theta1 increased";
        if (!(operand(adapted, "theta2") <= operand(base, "theta2"))) return "theta2 increased";
        for (String k : new String[] {"lambda", "rho", "bMax"}) if (!same(adapted.get(k), base.get(k))) return k + " changed";
        Map<String, Object> bw = Js.map(base.get("weights")), aw = Js.map(adapted.get("weights"));
        if (bw == null) throw new IllegalArgumentException("base.weights missing");
        if (aw == null) throw new IllegalArgumentException("adapted.weights missing");
        for (String k : bw.keySet()) if (!same(aw.get(k), bw.get(k))) return "weights." + k + " changed";
        return null;
    }

    /** Throws unless {@code adapted} only tightens {@code base}. */
    public static void assertNoWiden(Map<String, Object> base, Map<String, Object> adapted) {
        String v = noWidenViolation(base, adapted);
        if (v != null) throw new IllegalStateException("immune: adaptation widens the policy (" + v + ")");
    }

    // ---- signed tightening proposals -------------------------------------------------------------------------------

    public static final String TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\0";

    private static byte[] tighteningMessage(Map<String, Object> claim) {
        byte[] pre = TIGHTENING_DOMAIN.getBytes(StandardCharsets.UTF_8), body = Json.canonicalize(claim).getBytes(StandardCharsets.UTF_8);
        byte[] m = new byte[pre.length + body.length];
        System.arraycopy(pre, 0, m, 0, pre.length);
        System.arraycopy(body, 0, m, pre.length, body.length);
        return m;
    }

    public static String policyDigest(Map<String, Object> policy) { return StoreJs.hashLenient(policy); }

    public static String immuneStateDigest(Map<String, Object> state) { return StoreJs.hashLenient(state); }

    /**
     * Derive and sign the tightening for {@code state}; throws on a malformed base, an epoch that is not an integer &gt;= 1, a non-finite
     * {@code now} or a malformed state (never an unsigned loosening). {@code guardianSecret} is the 32-byte Ed25519 seed.
     */
    public static Map<String, Object> issueTighteningProposal(Map<String, Object> base, Map<String, Object> state, Object epoch, Object now, byte[] guardianSecret) {
        String bad = InvariantsBridge.validateRiskPolicy(base);
        if (bad != null) throw new IllegalArgumentException("issueTighteningProposal: " + bad);
        if (!StoreJs.isInt(epoch) || StoreJs.lng(epoch) < 1) throw new IllegalArgumentException("issueTighteningProposal: epoch must be an integer >= 1");
        if (!Js.isFinite(now)) throw new IllegalArgumentException("issueTighteningProposal: now must be finite");
        Keys.EdKey key = Keys.edFromSeed(guardianSecret);
        Map<String, Object> ad = adapt(base, assess(state));
        Map<String, Object> claim = Js.obj();
        claim.put("v", Js.n(1L));
        claim.put("base_digest", policyDigest(base));
        claim.put("state_digest", StoreJs.hashLenient(state));
        claim.put("epoch", epoch);
        claim.put("issued_at", now);
        claim.put("policy", ad.get("policy"));
        claim.put("rationale", ad.get("rationale"));
        claim.put("guardian", key.id());
        Map<String, Object> p = new LinkedHashMap<>(claim);
        p.put("sig", Keys.b64u(key.sign(tighteningMessage(claim))));
        return p;
    }

    private static Map<String, Object> refused(String reason) {
        Map<String, Object> o = Js.obj();
        o.put("ok", false);
        o.put("reason", reason);
        return o;
    }

    /**
     * Verify a proposal and return {@code {ok: true, policy, epoch}} or {@code {ok: false, reason}}; never throws. {@code o} holds the pinned
     * {@code guardian} (b64u, required), {@code lastEpoch}, {@code now}, {@code maxAgeMs} and optionally {@code state} (a recompute check).
     */
    public static Map<String, Object> applyTightening(Map<String, Object> base, Map<String, Object> p, Map<String, Object> o) {
        try {
            if (p == null || !same(p.get("v"), Js.n(1L)) || !(p.get("sig") instanceof String) || !(p.get("guardian") instanceof String)) return refused("malformed");
            if (!(o.get("guardian") instanceof String) || !o.get("guardian").equals(p.get("guardian"))) return refused("guardian");
            Map<String, Object> claim = new LinkedHashMap<>(p);
            claim.remove("sig");
            if (!W3Bridge.verifyB64u((String) p.get("guardian"), tighteningMessage(claim), (String) p.get("sig"))) return refused("signature");
            Map<String, Object> pol = Js.map(p.get("policy"));
            if (InvariantsBridge.validateRiskPolicy(base) != null || InvariantsBridge.validateRiskPolicy(p.get("policy")) != null) return refused("invalid-policy");
            if (!Objects.equals(p.get("base_digest"), policyDigest(base))) return refused("base");
            double now = num(o.get("now")), at = num(p.get("issued_at"));
            if (Double.isNaN(now) || Double.isInfinite(now) || Double.isNaN(at) || Double.isInfinite(at) || !(at <= now) || !(now - at <= operand(o, "maxAgeMs"))) return refused("stale");
            Object epoch = p.get("epoch");
            if (!StoreJs.isInt(epoch) || !(num(epoch) > operand(o, "lastEpoch"))) return refused("replayed-epoch");
            if (noWidenViolation(base, pol) != null) return refused("widens");
            Object st = o.get("state");
            if (Js.truthy(st) && (!Objects.equals(p.get("state_digest"), StoreJs.hashLenient(st))
                    || !policyDigest(Js.map(adapt(base, assess(st)).get("policy"))).equals(policyDigest(pol)))) return refused("state-mismatch");
            Map<String, Object> ok = Js.obj();
            ok.put("ok", true);
            ok.put("policy", pol);
            ok.put("epoch", epoch);
            return ok;
        } catch (RuntimeException e) {
            return refused("malformed");
        }
    }

    // ---- durable state ---------------------------------------------------------------------------------------------

    /** Immune state and applied epoch for one subject over an atomic kv, so a restart keeps the history and the replay floor. */
    public static ImmuneStore createImmuneStore(AtomicKv kv, String subject) { return new ImmuneStore(kv, subject); }

    public static final class ImmuneStore {
        private final AtomicKv kv;
        private final String sKey, eKey;

        ImmuneStore(AtomicKv kv, String subject) {
            this.kv = Objects.requireNonNull(kv);
            this.sKey = "immune/state/" + subject;
            this.eKey = "immune/epoch/" + subject;
        }

        /** The stored state, or the initial one. */
        public Map<String, Object> get() {
            Object v = kv.get(sKey);
            if (v == AtomicKv.JSON_NULL) return null; // a stored JSON null is returned as it is, never read as absent
            return v == null ? initialState() : Js.map(v);
        }

        /** Folds one observation atomically; throws when the stored state is malformed (it is never silently reset to calm). */
        public Map<String, Object> observe(Map<String, Object> obs) {
            return Js.map(kv.update(sKey, prev -> {
                if (prev == AtomicKv.JSON_NULL) throw new IllegalStateException("immune store: stored state invalid (null)");
                Object cur = prev == null ? initialState() : prev;
                String bad = validateImmuneState(cur);
                if (bad != null) throw new IllegalStateException("immune store: stored state invalid (" + bad + ")");
                return Immune.observe(Js.map(cur), obs);
            }));
        }

        public long lastEpoch() {
            Object v = kv.get(eKey);
            return Js.isNum(v) ? (long) Js.d(v) : 0;
        }

        /** Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. {@code o} is as for {@link #applyTightening} without lastEpoch. */
        public Map<String, Object> apply(Map<String, Object> base, Map<String, Object> p, Map<String, Object> o) {
            @SuppressWarnings("unchecked") Map<String, Object>[] out = new Map[] {refused("malformed")};
            kv.update(eKey, prev -> {
                Map<String, Object> oo = new LinkedHashMap<>(o);
                oo.put("lastEpoch", Js.isNum(prev) ? prev : Js.n(0L));
                out[0] = applyTightening(base, p, oo);
                return Boolean.TRUE.equals(out[0].get("ok")) ? out[0].get("epoch") : null;
            });
            return out[0];
        }
    }
}
