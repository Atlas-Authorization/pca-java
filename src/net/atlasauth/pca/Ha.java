package net.atlasauth.pca;

import java.text.Collator;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;

/**
 * Guardian high-availability control logic (the reference's ha module): which guardians are live, whether a co-sign quorum is available,
 * the degrade mode when it is lost, signer selection and failover order, and a durable, FENCED leader lease (at most one holder, a strictly
 * increasing fencing epoch, store-side expiry, "no leader" whenever the store errs). It never fails OPEN: losing quorum or the lease restricts
 * authority, never widens it.
 *
 * <p>Guardian sets, lease records and results are JSON trees (maps and lists), the members of the reference's objects:
 * a guardian set is {@code {guardians: [{id, healthy, lastSeen, weight?}], quorum}}, a lease record {@code {holder, epoch, expiresAt}}.
 * Every function is total over hostile input as the reference is (a malformed set counts as no live guardian). Lease safety holds if the store's
 * compare-and-swap is linearizable and the holder's clock error stays under {@code skewMs}.
 *
 * <p>Shortcut: signer ties on the id use {@link Collator} (root locale, tertiary) as the reference uses {@code localeCompare}; they agree on
 * Latin text, a rarer script may order differently.
 */
public final class Ha {
    private Ha() {}

    public static final long MAX_LEASE_TTL_MS = 3_600_000L;
    public static final long DEFAULT_LEASE_SKEW_MS = 1_000L;
    private static final int MAX_HOLDER_LEN = 256;
    private static final double MAX_SAFE = 9007199254740991d;
    public static final String DEFAULT_LEASE_KEY = "ha/lease";

    private static Double fin(Object o) { return Caveats.fin(o); }

    private static boolean isInteger(Object o) { Double d = fin(o); return d != null && d == Math.rint(d); }

    private static boolean isSafeInteger(Object o) { Double d = fin(o); return d != null && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE; }

    private static Object num(double d) { return d == Math.rint(d) && Math.abs(d) <= MAX_SAFE ? (Object) (long) d : (Object) d; }

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    private static Object member(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }

    // ---- pure decisions ----------------------------------------------------------------------------------------------------

    /**
     * Guardians that are flagged healthy (the boolean true) AND have a fresh heartbeat at {@code now}. Fails closed: a malformed set, a
     * non-finite clock or stale window, a non-finite or FUTURE-dated heartbeat counts as down. {@code opts}: {@code {staleMs}}, default 30000.
     */
    public static List<Object> liveGuardians(Object set, Object now, Object opts) {
        List<Object> out = new ArrayList<>();
        Object st = member(opts, "staleMs");
        Double staleMs = st == null ? Double.valueOf(30_000) : fin(st);
        Double n = fin(now);
        Object gs = member(set, "guardians");
        if (n == null || staleMs == null || staleMs < 0 || !(gs instanceof List)) return out;
        for (Object g : (List<?>) gs) if (!isObject(g)) return out;
        for (Object g : (List<?>) gs) {
            Double seen = fin(member(g, "lastSeen"));
            if (Boolean.TRUE.equals(member(g, "healthy")) && seen != null && seen <= n && n - seen <= staleMs) out.add(g);
        }
        return out;
    }

    public static List<Object> liveGuardians(Object set, double now) { return liveGuardians(set, now, null); }

    /** {@code {total, live, quorum, available, degraded}}; {@code quorum} is echoed as given (absent when the set has none). */
    public static Map<String, Object> quorumStatus(Object set, Object now, Object opts) {
        int live = liveGuardians(set, now, opts).size();
        Object gs = member(set, "guardians");
        Object q = member(set, "quorum");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", gs instanceof List ? ((List<?>) gs).size() : 0);
        out.put("live", live);
        if (has(set, "quorum")) out.put("quorum", q);
        out.put("available", isInteger(q) && fin(q) >= 1 && live >= fin(q));
        out.put("degraded", live > 0 && live < Actions.jsNumber(q, has(set, "quorum")));
        return out;
    }

    /** {@code 'normal'} with quorum, {@code 'read-only'} below quorum with some guardian live (unless {@code allowReadOnly} is false), else {@code 'halt'}. */
    public static String degradeMode(Object status, Object policy) {
        if (Zk.truthy(member(status, "available"))) return "normal";
        if (Actions.jsNumber(member(status, "live"), has(status, "live")) > 0 && !Boolean.FALSE.equals(member(policy, "allowReadOnly"))) return "read-only";
        return "halt";
    }

    private static double weightOf(Object g) { Double w = fin(member(g, "weight")); return w == null ? 0 : w; }

    private static int compareGuardians(Object a, Object b) {
        double dw = weightOf(b) - weightOf(a);
        if (dw != 0) return dw < 0 ? -1 : 1;
        double dl = fin(member(b, "lastSeen")) - fin(member(a, "lastSeen"));
        if (dl != 0) return dl < 0 ? -1 : 1;
        Object ia = member(a, "id"), ib = member(b, "id");
        if (!(ia instanceof String)) throw new IllegalArgumentException("a.id.localeCompare is not a function");
        Collator c = Collator.getInstance(Locale.ROOT);
        c.setStrength(Collator.TERTIARY);
        return c.compare((String) ia, IntentRevocation.jsText(ib, has(b, "id")));
    }

    private static List<Object> byPreference(List<Object> live) {
        List<Object> s = new ArrayList<>(live);
        s.sort(Ha::compareGuardians);
        return s;
    }

    /** The {@code quorum} freshest, highest-weight live guardians' ids; empty when no quorum is available. A null set throws, as the reference does. */
    public static List<Object> selectSigners(Object set, Object now, Object opts) {
        if (set == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'quorum')");
        List<Object> live = liveGuardians(set, now, opts);
        Object q = member(set, "quorum");
        List<Object> out = new ArrayList<>();
        if (!isInteger(q) || fin(q) < 1 || live.size() < fin(q)) return out;
        List<Object> sorted = byPreference(live);
        for (int i = 0; i < (int) (double) fin(q); i++) out.add(member(sorted.get(i), "id"));
        return out;
    }

    /** {@code {primary, standbys}}: the preferred live guardian (null when none) and the other live ones in preference order. */
    public static Map<String, Object> failoverPlan(Object set, Object now, Object opts) {
        List<Object> live = byPreference(liveGuardians(set, now, opts));
        List<Object> standbys = new ArrayList<>();
        for (int i = 1; i < live.size(); i++) standbys.add(member(live.get(i), "id"));
        return obj("primary", live.isEmpty() ? null : member(live.get(0), "id"), "standbys", standbys);
    }

    /** An error text when the set is malformed (quorum in range, unique non-empty string ids), else null. */
    public static String validateGuardianSet(Object set) {
        if (!isObject(set)) return "guardian set is not an object";
        Object gs = member(set, "guardians");
        if (!(gs instanceof List) || ((List<?>) gs).isEmpty()) return "guardian set is empty";
        Object q = member(set, "quorum");
        if (!isInteger(q) || fin(q) < 1) return "quorum must be an integer ≥ 1";
        List<?> l = (List<?>) gs;
        if (fin(q) > l.size()) return "quorum exceeds guardian count";
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (Object g : l) {
            Object id = member(g, "id");
            if (!(g instanceof Map) || !(id instanceof String) || ((String) id).isEmpty()) return "guardian id must be a non-empty string";
            ids.add((String) id);
        }
        return ids.size() != l.size() ? "duplicate guardian ids" : null;
    }

    // ---- durable, fenced leader lease ---------------------------------------------------------------------------------------

    /**
     * The persistence contract. {@code cas} replaces the record iff the stored one equals {@code expected} (null = none), atomically and
     * linearizably, and says whether it did; {@code next.epoch} must never be below the stored epoch. {@code now} is the STORE's clock (epoch ms):
     * every expiry decision uses it, never the caller's. A store that cannot answer throws an unchecked exception: the caller then refuses.
     */
    public interface LeaseStore {
        /** The stored record (a lease map), or null when none. */
        Object read();
        boolean cas(Object expected, Object next);
        double now();
    }

    private static boolean validRecord(Object r) {
        if (!(r instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) r;
        Double e = fin(m.get("epoch")), x = fin(m.get("expiresAt"));
        return m.get("holder") instanceof String && isSafeInteger(e) && e >= 1 && x != null && x >= 0;
    }

    private static boolean eqLease(Object a, Object b) {
        if (a == null || b == null) return a == null && b == null;
        Double ae = fin(member(a, "epoch")), be = fin(member(b, "epoch")), ax = fin(member(a, "expiresAt")), bx = fin(member(b, "expiresAt"));
        return member(a, "holder") instanceof String && member(a, "holder").equals(member(b, "holder"))
            && ae != null && be != null && ae.doubleValue() == be.doubleValue() && ax != null && bx != null && ax.doubleValue() == bx.doubleValue();
    }

    /** The lease options as {@code {ttl, skew}}, or null when invalid: holder 1..256 characters, ttlMs an integer in [2, 3600000], skewMs finite in [0, ttlMs). */
    private static double[] leaseOpts(Object holder, Object o) {
        if (!(holder instanceof String) || ((String) holder).isEmpty() || ((String) holder).length() > MAX_HOLDER_LEN) return null;
        if (!(o instanceof Map)) return null;
        Object sk = member(o, "skewMs");
        Double skew = sk == null ? Double.valueOf(DEFAULT_LEASE_SKEW_MS) : fin(sk);
        Object t = member(o, "ttlMs");
        if (!isInteger(t) || fin(t) < 2 || fin(t) > MAX_LEASE_TTL_MS) return null;
        if (skew == null || skew < 0 || skew >= fin(t)) return null;
        return new double[] {fin(t), skew};
    }

    private static final class Snap {
        final Object cur;
        final double now;
        Snap(Object cur, double now) { this.cur = cur; this.now = now; }
    }

    /** The record and the store clock; a corrupt record or clock is a store error (never "free"). */
    private static Snap snapshot(LeaseStore store) {
        Object cur = store.read();
        double now = store.now();
        if (Double.isNaN(now) || Double.isInfinite(now) || (cur != null && !validRecord(cur))) throw new IllegalStateException("corrupt lease state");
        return new Snap(cur, now);
    }

    private static Map<String, Object> ok(Map<String, Object> lease) { return obj("ok", true, "lease", lease); }

    private static Map<String, Object> no(String reason) { return obj("ok", false, "reason", reason); }

    private static Map<String, Object> storeError(RuntimeException e) {
        Map<String, Object> m = no("store-error");
        m.put("detail", e.getMessage() == null ? "unknown" : e.getMessage());
        return m;
    }

    private static Map<String, Object> record(Object holder, double epoch, double expiresAt) {
        return obj("holder", holder, "epoch", num(epoch), "expiresAt", num(expiresAt));
    }

    private static double d(Object o) { Double x = fin(o); return x == null ? Double.NaN : x; }

    /**
     * Takes the lease when it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
     * {@code {ok: true, lease}} or {@code {ok: false, reason, detail?}} with reason invalid, held, lost-race or store-error.
     */
    public static Map<String, Object> acquireLease(LeaseStore store, Object holder, Object opts) {
        double[] p = leaseOpts(holder, opts);
        if (p == null) return no("invalid");
        try {
            Snap s = snapshot(store);
            if (s.cur != null && d(member(s.cur, "expiresAt")) + p[1] > s.now && d(member(s.cur, "expiresAt")) != 0) return no("held");
            Map<String, Object> next = record(holder, (s.cur == null ? 0 : d(member(s.cur, "epoch"))) + 1, s.now + p[0]);
            return store.cas(s.cur, next) ? ok(next) : no("lost-race");
        } catch (RuntimeException e) {
            return storeError(e);
        }
    }

    private static boolean sameToken(Object cur, Object token) {
        Double ce = fin(member(cur, "epoch")), te = fin(member(token, "epoch"));
        return member(cur, "holder").equals(member(token, "holder")) && ce != null && te != null && ce.doubleValue() == te.doubleValue();
    }

    /** Extends a lease the caller still holds; refused once its own safe window (expiry minus skew) has passed, or after any takeover. */
    public static Map<String, Object> renewLease(LeaseStore store, Object lease, Object opts) {
        double[] p = validRecord(lease) ? leaseOpts(member(lease, "holder"), opts) : null;
        if (p == null) return no("invalid");
        try {
            Snap s = snapshot(store);
            if (s.cur == null || !sameToken(s.cur, lease)) return no("stale");
            if (d(member(s.cur, "expiresAt")) - p[1] <= s.now) return no("expired");
            Map<String, Object> next = record(member(s.cur, "holder"), d(member(s.cur, "epoch")), s.now + p[0]);
            return store.cas(s.cur, next) ? ok(next) : no("lost-race");
        } catch (RuntimeException e) {
            return storeError(e);
        }
    }

    /** Gives the lease up early ({@code expiresAt} 0, epoch kept); only the current holder at the current epoch can. */
    public static Map<String, Object> releaseLease(LeaseStore store, Object lease) {
        if (!validRecord(lease)) return no("invalid");
        try {
            Snap s = snapshot(store);
            if (s.cur == null || !sameToken(s.cur, lease) || d(member(s.cur, "expiresAt")) == 0) return no("stale");
            Map<String, Object> next = record(member(s.cur, "holder"), d(member(s.cur, "epoch")), 0);
            return store.cas(s.cur, next) ? ok(next) : no("lost-race");
        } catch (RuntimeException e) {
            return storeError(e);
        }
    }

    /** Is this exact (holder, epoch) still the leader with its safe window open? {@code {ok: true}} or {@code {ok: false, reason}} (stale, expired, store-error); any error answers no. */
    public static Map<String, Object> assertFence(LeaseStore store, Object token, double skewMs) { return assertFence(store, token, (Object) skewMs); }

    public static Map<String, Object> assertFence(LeaseStore store, Object token) { return assertFence(store, token, (Object) null); }

    /** {@code skewMs}: any value; null means the default, a non-number or negative one answers stale. */
    static Map<String, Object> assertFence(LeaseStore store, Object token, Object skewMs) {
        try {
            Double skew = skewMs == null ? Double.valueOf(DEFAULT_LEASE_SKEW_MS) : fin(skewMs);
            if (token == null || Boolean.FALSE.equals(token) || skew == null || skew < 0) return no("stale");
            Snap s = snapshot(store);
            if (s.cur == null || !sameToken(s.cur, token)) return no("stale");
            return d(member(s.cur, "expiresAt")) - skew > s.now ? obj("ok", true) : no("expired");
        } catch (RuntimeException e) {
            return no("store-error");
        }
    }

    /** Thrown by a fenced signer; {@link #reason} is stale, expired, store-error or no-lease. */
    public static final class FenceError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String reason;
        public FenceError(String reason) { super("fenced: " + reason); this.reason = reason; }
    }

    /** The co-sign step of a fenced signer. */
    @FunctionalInterface public interface Sign<R> { R run() throws Exception; }

    /** What a fenced signer returns: the signature step's result and the fencing epoch it ran under. */
    public static final class Signed<R> {
        public final R result;
        public final Object epoch;
        Signed(R result, Object epoch) { this.result = result; this.epoch = epoch; }
    }

    @FunctionalInterface public interface Fenced<R> { Signed<R> call() throws Exception; }

    /**
     * Wraps a co-sign step so it only runs while the caller is the fenced leader. The fence is checked before AND after the step: a leader that lost
     * the lease mid-signature gets a {@link FenceError} and the result is discarded. Check-then-sign is inherently racy: the downstream must also
     * {@link FenceGuard#admit} the epoch.
     */
    public static <R> Fenced<R> fencedSigner(LeaseStore store, Supplier<Object> getLease, Sign<R> sign, double skewMs) { return fencedSigner(store, getLease, sign, (Object) skewMs); }

    public static <R> Fenced<R> fencedSigner(LeaseStore store, Supplier<Object> getLease, Sign<R> sign) { return fencedSigner(store, getLease, sign, (Object) null); }

    static <R> Fenced<R> fencedSigner(LeaseStore store, Supplier<Object> getLease, Sign<R> sign, Object skewMs) {
        return () -> {
            Object lease = getLease.get();
            if (lease == null) throw new FenceError("no-lease");
            Map<String, Object> pre = assertFence(store, lease, skewMs);
            if (!Boolean.TRUE.equals(pre.get("ok"))) throw new FenceError((String) pre.get("reason"));
            R result = sign.run();
            Map<String, Object> post = assertFence(store, lease, skewMs);
            if (!Boolean.TRUE.equals(post.get("ok"))) throw new FenceError((String) post.get("reason"));
            return new Signed<>(result, member(lease, "epoch"));
        };
    }

    /** Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write). */
    public static final class FenceGuard {
        private double hi;

        FenceGuard(Object initial) { hi = isSafeInteger(initial) && fin(initial) > 0 ? fin(initial) : 0; }

        public synchronized boolean admit(Object epoch) {
            Double e = fin(epoch);
            if (!isSafeInteger(epoch) || e < 1 || e < hi) return false;
            hi = e;
            return true;
        }

        public boolean admit(long epoch) { return admit((Object) epoch); }

        public synchronized long highest() { return (long) hi; }
    }

    public static FenceGuard createFenceGuard(long initial) { return new FenceGuard(initial); }

    public static FenceGuard createFenceGuard() { return new FenceGuard(0L); }

    static FenceGuard createFenceGuard(Object initial) { return new FenceGuard(initial); }

    /** The reference {@link LeaseStore} over any {@link AtomicKv} (its {@code update} is the atomic compare-and-swap). */
    public static final class KvLeaseStore implements LeaseStore {
        private final AtomicKv kv;
        private final String key;
        private final DoubleSupplier clock;

        public KvLeaseStore(AtomicKv kv, String key, DoubleSupplier clock) {
            this.kv = kv;
            this.key = key == null ? DEFAULT_LEASE_KEY : key;
            this.clock = clock == null ? System::currentTimeMillis : clock;
        }

        public KvLeaseStore(AtomicKv kv) { this(kv, null, null); }

        @Override public Object read() {
            Object v = kv.get(key);
            if (v != null && !validRecord(v)) throw new IllegalStateException("corrupt lease state");
            return v;
        }

        @Override public boolean cas(Object expected, Object next) {
            if (!validRecord(next)) throw new IllegalArgumentException("invalid lease record");
            Map<String, Object> copy = new LinkedHashMap<>(IntentJs.obj(next));
            boolean[] matched = {false};
            kv.update(key, prev -> {
                matched[0] = false;
                if (prev != null && !validRecord(prev)) return null;
                if (!eqLease(prev, expected) || d(copy.get("epoch")) < (prev == null ? 0 : d(member(prev, "epoch")))) return null;
                matched[0] = true;
                return copy;
            });
            return matched[0];
        }

        @Override public double now() { return clock.getAsDouble(); }
    }
}
