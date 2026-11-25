package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The persistence contract of a durable aggregate budget (no overspend at principal, org and fleet scope), given a ledger that is
 * linearizable per key and durable. A reservation counts as soon as it is made; the ledger refuses a reservation whose post-value would
 * pass the accumulator's {@code domain_max} inside the same atomic step that records it.
 *
 * <p>Two phases: {@code reserve} (counted at once), then {@code start} (recorded BEFORE the effect runs), then {@code commit} (the effect
 * happened) or {@code release} (it did not). {@code expire} frees only a reservation that was never started. A committed event is never
 * released and a released one is never committed. Each operation is atomic per key; the same reservation again is a replay that changes
 * nothing; acknowledged writes survive a crash; {@link #durable()} is true only for a store that does. Events are the JSON objects
 * {@code {id, verb, resource, params, t, status, exp?, started?, rel?}}.
 */
public interface BudgetLedger {
    /** A reservation request. {@code accumulators} are the declarations of THIS key (each {@code domain_max} is the cap). */
    final class ReserveRequest {
        /** {id, verb, resource, params, t}. */
        public Map<String, Object> event;
        public List<Map<String, Object>> accumulators;
        /** An action schema (or null). */
        public Object schema;
        /** Refuse ({@code conflict}) unless the key is at this version. */
        public Long expectedVersion;
        public Long expiresAt;
    }

    /** {@code reserved} (+post), {@code replayed} (+status), {@code over_cap} (+acc, post, cap), {@code conflict}, {@code id_conflict}. */
    final class ReserveOutcome {
        public final String outcome;
        public final long version;
        public final Map<String, Long> post;
        public final String status, acc;
        public final Long postValue;
        public final Double cap;

        public ReserveOutcome(String outcome, long version, Map<String, Long> post, String status, String acc, Long postValue, Double cap) {
            this.outcome = outcome;
            this.version = version;
            this.post = post;
            this.status = status;
            this.acc = acc;
            this.postValue = postValue;
            this.cap = cap;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            m.put("version", StoreJs.num(version));
            if (post != null) {
                Map<String, Object> p = new LinkedHashMap<>();
                for (Map.Entry<String, Long> e : post.entrySet()) p.put(e.getKey(), StoreJs.num((long) e.getValue()));
                m.put("post", p);
            }
            if (status != null) m.put("status", status);
            if (acc != null) {
                m.put("acc", acc);
                m.put("post", StoreJs.num((long) postValue));
                m.put("cap", StoreJs.num((double) cap));
            }
            return m;
        }
    }

    /** {@code settled}, {@code replayed}, {@code unknown} or {@code refused} (+status of the entry). */
    final class SettleOutcome {
        public final String outcome;
        public final long version;
        public final String status;

        public SettleOutcome(String outcome, long version, String status) { this.outcome = outcome; this.version = version; this.status = status; }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            m.put("version", StoreJs.num(version));
            if (status != null) m.put("status", status);
            return m;
        }
    }

    /** The result of {@link #expire}: the released ids and the version afterwards. */
    final class Expired {
        public final List<String> released;
        public final long version;

        public Expired(List<String> released, long version) { this.released = released; this.version = version; }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("released", new ArrayList<Object>(released));
            m.put("version", StoreJs.num(version));
            return m;
        }
    }

    /** A copy of a key's events and its version. */
    final class Snapshot {
        public final long version;
        public final List<Map<String, Object>> events;

        public Snapshot(long version, List<Map<String, Object>> events) { this.version = version; this.events = events; }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("version", StoreJs.num(version));
            m.put("events", new ArrayList<Object>(events));
            return m;
        }
    }

    /** True ONLY when acknowledged writes survive a restart or crash. Non-session scopes refuse a ledger that does not say so. */
    boolean durable();

    Snapshot snapshot(String key);

    ReserveOutcome reserve(String key, ReserveRequest req);

    /** The effect is about to run: mark the reservation non-expirable. {@code refused} once released; {@code replayed} when already started or committed. */
    SettleOutcome start(String key, String id);

    SettleOutcome commit(String key, String id);

    /** {@code evidence} (a signed release, see {@link Budgets#signRelease}) may be null. */
    SettleOutcome release(String key, String id, Map<String, Object> evidence);

    /** Release every open, never-started reservation whose {@code exp} is at or before {@code now}. */
    Expired expire(String key, long now);
}
