package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A {@link StateStore} over any {@link AtomicKv}: the replay counter, the trust budget and the one-time-use slots of a deployment that
 * already has an atomic key/value backend (a {@link PcaJdbcAtomicKv}, a Redis script, an in-process {@link MemoryAtomicKv}). Every claim is ONE
 * {@link AtomicKv#update}, so it is correct across every process and node that shares the backend; a claim that cannot decide throws and the
 * guard denies. The state of a stream is {@code {lastCounter, budget?, lastEpoch?, lastBeaconSeq?}} under {@code prefix + key}.
 *
 * <p>{@code shared} states whether the backend is shared by every instance (a durable or networked one: {@code true}) or lives in this process
 * only ({@code false}: a guard declared {@code multiInstance} then refuses the store).
 */
public final class AtomicKvStateStore implements StateStore, LastStore {
    private final AtomicKv kv;
    private final String prefix;
    private final boolean shared;

    public AtomicKvStateStore(AtomicKv kv, String prefix, boolean shared) {
        if (kv == null) throw new IllegalArgumentException("an AtomicKv is required");
        this.kv = kv;
        this.prefix = prefix == null ? "pca-state:" : prefix;
        this.shared = shared;
    }

    public AtomicKvStateStore(AtomicKv kv) { this(kv, null, true); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> read(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }

    private static boolean sameBudget(Map<String, Object> a, Map<String, Object> b) {
        if (a == null || b == null) return a == b;
        for (String k : new String[] {"B", "tau", "asOf"}) {
            Double x = Caveats.fin(a.get(k)), y = Caveats.fin(b.get(k));
            if (x == null ? y != null : !x.equals(y)) return false;
        }
        return true;
    }

    @Override public boolean holdsBudgets() { return true; }

    @Override public boolean processScoped() { return !shared; }

    @Override
    public Map<String, Object> budget(String key) {
        Map<String, Object> st = read(kv.get(prefix + key));
        Map<String, Object> b = st == null ? null : read(st.get("budget"));
        return b == null ? null : new LinkedHashMap<>(b);
    }

    @Override
    public Long last(String key) {
        Map<String, Object> st = read(kv.get(prefix + key));
        return st == null || !Json.isSafeInt(st.get("lastCounter")) ? null : Long.valueOf(Json.asLong(st.get("lastCounter")));
    }

    /** The counter alone: the stored budget is neither checked nor changed. */
    @Override public ClaimResult claim(String key, long counter) { return claimInternal(key, counter, null, null, false); }

    @Override
    public ClaimResult claim(String key, long counter, Map<String, Object> budgetBefore, Map<String, Object> budgetAfter) {
        return claimInternal(key, counter, budgetBefore, budgetAfter, true);
    }

    private ClaimResult claimInternal(String key, long counter, Map<String, Object> budgetBefore, Map<String, Object> budgetAfter, boolean checkBudget) {
        if (key == null) return ClaimResult.replay(null);
        AtomicReference<ClaimResult> result = new AtomicReference<>(ClaimResult.conflict());
        kv.update(prefix + key, prev -> {
            Map<String, Object> cur = read(prev);
            Long lastC = cur != null && Json.isSafeInt(cur.get("lastCounter")) ? Long.valueOf(Json.asLong(cur.get("lastCounter"))) : null;
            if (lastC != null && !(counter > lastC)) { result.set(ClaimResult.replay(lastC)); return null; }
            if (checkBudget && !sameBudget(cur == null ? null : read(cur.get("budget")), budgetBefore)) { result.set(ClaimResult.conflict()); return null; }
            Map<String, Object> next = new LinkedHashMap<>();
            if (cur != null) next.putAll(cur);
            Object budget = budgetAfter != null ? new LinkedHashMap<>(budgetAfter) : cur == null ? null : cur.get("budget");
            if (budget != null) next.put("budget", budget);
            next.put("lastCounter", StoreJs.num(counter));
            result.set(ClaimResult.claimed());
            return next;
        });
        return result.get();
    }

    /** Atomically raise a monotone pin ({@code lastEpoch} or {@code lastBeaconSeq}) to {@code value} when it is higher; never lowers it. */
    public void raisePin(String key, String pin, long value) {
        if (!pin.equals("lastEpoch") && !pin.equals("lastBeaconSeq")) throw new IllegalArgumentException("raisePin: pin must be lastEpoch or lastBeaconSeq");
        kv.update(prefix + key, prev -> {
            Map<String, Object> cur = read(prev);
            if (cur != null && Json.isSafeInt(cur.get(pin)) && Json.asLong(cur.get(pin)) >= value) return null;
            Map<String, Object> next = new LinkedHashMap<>();
            if (cur != null) next.putAll(cur);
            next.put(pin, StoreJs.num(value));
            return next;
        });
    }

    /** The pin ({@code lastEpoch} / {@code lastBeaconSeq}) stored for {@code key}, or null. */
    public Long pin(String key, String pin) {
        Map<String, Object> st = read(kv.get(prefix + key));
        return st == null || !Json.isSafeInt(st.get(pin)) ? null : Long.valueOf(Json.asLong(st.get(pin)));
    }

    @Override
    public boolean consumeOnce(String key, long retainUntilMs, long nowMs) {
        if (key == null || key.isEmpty() || retainUntilMs < nowMs) throw new IllegalArgumentException("consumeOnce: invalid key or retention horizon");
        AtomicReference<Boolean> first = new AtomicReference<>(Boolean.FALSE);
        kv.update(prefix + "once:" + key, prev -> {
            Long until = Json.isSafeInt(prev) ? Long.valueOf(Json.asLong(prev)) : null;
            boolean live = until != null && until >= nowMs;
            first.set(!live);
            return StoreJs.num(live ? Math.max(until, retainUntilMs) : retainUntilMs);
        });
        return first.get();
    }
}
