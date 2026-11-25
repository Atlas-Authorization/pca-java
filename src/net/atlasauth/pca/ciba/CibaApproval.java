package net.atlasauth.pca.ciba;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;

/**
 * The durable approval broker: the production-shaped counterpart of the in-memory broker. State lives behind an {@link ApprovalStore}
 * (compare-and-set), so a restart or a second process cannot lose, double-apply or replay a human decision. Sessions are JSON
 * objects with the reference's member names ({@code auth_req_id, request, status, createdAt, expiresAt, decidedBy, decidedAt}).
 */
public final class CibaApproval {
    private CibaApproval() {}

    private static final SecureRandom RNG = new SecureRandom();
    static final int MAX_CAS_TRIES = 8;

    /** A versioned value; version 0 means absent and every successful write bumps it. */
    public static final class Versioned {
        public final long version;
        public final Object value;
        public Versioned(long version, Object value) { this.version = version; this.value = value; }
    }

    /**
     * Persistence seam: a JSON key-value store with compare-and-set. {@code cas} writes {@code value} only if the stored version equals
     * {@code expectedVersion} (0 = the key must be absent) and returns whether it wrote. Any failure must throw.
     */
    public interface ApprovalStore {
        /** The stored record, or null when the key is absent. */
        Versioned get(String key);
        boolean cas(String key, long expectedVersion, Object value);
    }

    /** The synchronous broker contract: start, poll, token (POLL-mode token endpoint semantics), resolve and read a session. */
    public interface ApprovalBroker {
        Map<String, Object> start(Map<String, Object> stepUp, Map<String, Object> opts);
        Map<String, Object> poll(String authReqId);
        Map<String, Object> token(String authReqId);
        Map<String, Object> resolve(String authReqId, String decision, String by);
        /** The session snapshot, or null when unknown. */
        Map<String, Object> get(String authReqId);
    }

    /** Options of {@link #createDurableCibaBroker}. {@code authReqIdSource} defaults to 160 random bits, base64url (a test hook). */
    public static final class DurableBrokerOptions {
        public ApprovalStore store;
        public java.util.function.LongSupplier now = System::currentTimeMillis;
        /** How long an approval stays redeemable after the human decided, in seconds. Default 300. */
        public Double decisionTtlSec;
        /** Called after a decision is durably recorded (PING/PUSH). A throw does not undo the decision. */
        public Consumer<Map<String, Object>> onComplete;
        public Supplier<String> authReqIdSource = CibaApproval::randomAuthReqId;
    }

    static String randomAuthReqId() {
        byte[] b = new byte[20];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    // ---- file store --------------------------------------------------------------------------------------------------------------

    /**
     * Durable reference store: one JSON file, rewritten atomically (temp file then rename) on each write. Correct for ONE process at a
     * time; use a database store when several processes share the approvals.
     */
    public static ApprovalStore createFileApprovalStore(Path path) {
        return new ApprovalStore() {
            private Map<String, Object> load() {
                try {
                    if (!Files.exists(path)) return new LinkedHashMap<>();
                    Object parsed = Json.parseLenient(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)); // a corrupt file throws: fail closed
                    if (!(parsed instanceof Map)) throw new IllegalStateException("ciba: approval store file is corrupt");
                    return map(parsed);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override public Versioned get(String key) {
                Object v = load().get(key);
                if (v == null) return null;
                Object ver = CibaJs.member(v, "version");
                return new Versioned(ver == null ? 0 : (long) (double) CibaJs.num(ver), CibaJs.member(v, "value"));
            }

            @Override public boolean cas(String key, long expectedVersion, Object value) {
                Map<String, Object> all = load();
                Object cur = all.get(key);
                Double cv = cur == null ? null : CibaJs.num(CibaJs.member(cur, "version"));
                if ((cv == null ? 0 : (long) (double) cv) != expectedVersion) return false;
                all.put(key, Issue.obj("version", expectedVersion + 1, "value", value));
                try {
                    Path tmp = Path.of(path + "." + ProcessHandle.current().pid() + ".tmp");
                    net.atlasauth.pca.PrivateFiles.write(tmp, Json.utf8(CibaJs.stringify(all)));
                    Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    return true;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
    }

    /** Single-process in-memory store (a test double: not durable). */
    public static ApprovalStore createMemoryApprovalStore() {
        Map<String, Versioned> m = new java.util.HashMap<>();
        return new ApprovalStore() {
            @Override public synchronized Versioned get(String k) {
                Versioned v = m.get(k);
                return v == null ? null : new Versioned(v.version, CibaJs.deepCopy(v.value));
            }

            @Override public synchronized boolean cas(String k, long exp, Object value) {
                Versioned v = m.get(k);
                if ((v == null ? 0 : v.version) != exp) return false;
                m.put(k, new Versioned(exp + 1, CibaJs.deepCopy(value)));
                return true;
            }
        };
    }

    // ---- the durable broker ------------------------------------------------------------------------------------------------------

    private static final class Result<T> {
        final Map<String, Object> next;
        final T out;
        Result(Map<String, Object> next, T out) { this.next = next; this.out = out; }
    }

    private interface Mutation<T> { Result<T> apply(Map<String, Object> rec, long now); }

    private static boolean finite(Object o) { Double d = CibaJs.num(o); return d != null && !Double.isNaN(d) && !Double.isInfinite(d); }

    /** The stored record, checked: a malformed one throws (fail closed). */
    private static Map<String, Object> asRec(Object v) {
        if (!(v instanceof Map) || !(CibaJs.member(map(v).get("request"), "auth_req_id") instanceof String) || !finite(map(v).get("createdAt"))
            || !finite(map(v).get("expiresAt")) || !finite(map(v).get("interval")))
            throw new IllegalStateException("ciba: stored approval record is malformed");
        return map(v);
    }

    private static double d(Object o) { Double x = CibaJs.num(o); return x == null ? Double.NaN : x; }

    private static Map<String, Object> snapshot(Map<String, Object> r, String status) {
        Map<String, Object> s = Issue.obj("auth_req_id", map(r.get("request")).get("auth_req_id"), "request", r.get("request"), "status", status,
            "createdAt", r.get("createdAt"), "expiresAt", r.get("expiresAt"));
        if (r.containsKey("decidedBy")) s.put("decidedBy", r.get("decidedBy"));
        if (r.containsKey("decidedAt")) s.put("decidedAt", r.get("decidedAt"));
        return s;
    }

    private static Map<String, Object> outcome(boolean ok, String error, Object interval) { return Issue.obj("ok", ok, "error", error, "interval", interval); }

    /** The durable broker over {@code opts.store}: every transition is a compare-and-set, so concurrent callers cannot double-apply a decision. */
    public static ApprovalBroker createDurableCibaBroker(DurableBrokerOptions opts) {
        if (opts == null || opts.store == null) throw new IllegalArgumentException("createDurableCibaBroker: `store` is required");
        final ApprovalStore store = opts.store;
        final java.util.function.LongSupplier clock = opts.now;
        final double ttlMs = (opts.decisionTtlSec != null ? opts.decisionTtlSec : 300.0) * 1000;
        if (Double.isNaN(ttlMs) || Double.isInfinite(ttlMs) || ttlMs <= 0) throw new IllegalArgumentException("createDurableCibaBroker: decisionTtlSec must be a positive number");

        final class Impl implements ApprovalBroker {
            String status(Map<String, Object> r, long now) {
                Object dec = r.get("decision");
                if ("deny".equals(dec)) return "denied";
                if ("approve".equals(dec)) return !(now < d(r.get("decidedAt")) + ttlMs) ? "expired" : "approved";
                return !(now < d(r.get("expiresAt"))) ? "expired" : "pending";
            }

            Map<String, Object> snap(Map<String, Object> r, long now) { return snapshot(r, status(r, now)); }

            Object[] load(String id) { // {rec, version} or null
                Versioned v = store.get("a:" + id);
                return v == null ? null : new Object[] {asRec(v.value), v.version};
            }

            <T> T mutate(String id, Mutation<T> fn) {
                for (int i = 0; i < MAX_CAS_TRIES; i++) {
                    Object[] cur = load(id);
                    Result<T> res = fn.apply(cur == null ? null : map(CibaJs.deepCopy(cur[0])), clock.getAsLong());
                    if (res.next == null) return res.out;
                    if (store.cas("a:" + id, cur == null ? 0 : (Long) cur[1], res.next)) return res.out;
                }
                throw new IllegalStateException("ciba: approval store contention, gave up");
            }

            @Override public Map<String, Object> start(Map<String, Object> stepUp, Map<String, Object> reqOpts) {
                String liveKey = "s:" + CibaJs.str(CibaJs.get(stepUp, "id"));
                for (int i = 0; i < MAX_CAS_TRIES; i++) {
                    long now = clock.getAsLong();
                    Versioned idx = store.get(liveKey);
                    if (idx != null) {
                        Object[] ex = load(CibaJs.str(idx.value));
                        // Never reset a flow that is still waiting or already approved: that would discard a decision.
                        if (ex != null) {
                            String st = status(map(ex[0]), now);
                            if ((st.equals("pending") || st.equals("approved")) && !CibaJs.truthy(map(ex[0]).get("consumed"))) return map(map(ex[0]).get("request"));
                        }
                    }
                    Map<String, Object> o = reqOpts == null ? new LinkedHashMap<>() : new LinkedHashMap<>(reqOpts);
                    o.put("authReqId", opts.authReqIdSource.get());
                    Map<String, Object> request = Ciba.toCibaAuthRequest(stepUp, o);
                    Map<String, Object> rec = Issue.obj("request", request, "createdAt", now, "expiresAt", (long) (now + d(request.get("requested_expiry")) * 1000),
                        "interval", request.get("interval"));
                    String id = (String) request.get("auth_req_id");
                    if (!store.cas("a:" + id, 0, rec)) continue;
                    if (store.cas(liveKey, idx == null ? 0 : idx.version, id)) return request;
                }
                throw new IllegalStateException("ciba: approval store contention, gave up");
            }

            @Override public Map<String, Object> poll(String id) {
                Object[] c = load(id);
                if (c == null) throw new IllegalStateException("ciba: unknown auth_req_id " + id);
                return Issue.obj("status", status(map(c[0]), clock.getAsLong()));
            }

            @Override public Map<String, Object> token(String id) {
                return mutate(id, (r, now) -> {
                    if (r == null) return new Result<>(null, outcome(false, "invalid_grant", 5L));
                    if (CibaJs.truthy(r.get("consumed"))) return new Result<>(null, outcome(false, "invalid_grant", r.get("interval")));
                    boolean tooSoon = r.containsKey("lastPollAt") && !(now - d(r.get("lastPollAt")) >= d(r.get("interval")) * 1000);
                    r.put("lastPollAt", now);
                    if (tooSoon) {
                        r.put("interval", d(r.get("interval")) + 5);
                        return new Result<>(r, outcome(false, "slow_down", r.get("interval")));
                    }
                    String st = status(r, now);
                    if (st.equals("pending")) return new Result<>(r, outcome(false, "authorization_pending", r.get("interval")));
                    if (st.equals("denied")) return new Result<>(r, outcome(false, "access_denied", r.get("interval")));
                    if (st.equals("expired")) return new Result<>(r, outcome(false, "expired_token", r.get("interval")));
                    r.put("consumed", true); // single use: a replayed approval gets invalid_grant
                    return new Result<>(r, Issue.obj("ok", true, "session", snap(r, now)));
                });
            }

            @Override public Map<String, Object> resolve(String id, String decision, String by) {
                if (!"approve".equals(decision) && !"deny".equals(decision)) throw new IllegalArgumentException("ciba: decision must be \"approve\" or \"deny\"");
                if (by == null || by.isEmpty()) throw new IllegalArgumentException("ciba: `by` (the authenticated decider) is required");
                Map<String, Object> session = mutate(id, (r, now) -> {
                    if (r == null) throw new IllegalStateException("ciba: unknown auth_req_id " + id);
                    String cur = status(r, now);
                    if (!cur.equals("pending")) throw new IllegalStateException("ciba: cannot resolve " + id + " \u2014 already " + cur);
                    r.put("decision", decision);
                    r.put("decidedBy", by);
                    r.put("decidedAt", now);
                    return new Result<>(r, snap(r, now));
                });
                if (opts.onComplete != null) {
                    try { opts.onComplete.accept(session); } catch (RuntimeException e) { /* the decision is already recorded; a failing notifier must not undo or hide it */ }
                }
                return session;
            }

            @Override public Map<String, Object> get(String id) {
                Object[] c = load(id);
                return c == null ? null : snap(map(c[0]), clock.getAsLong());
            }
        }
        return new Impl();
    }

    // ---- the in-memory broker (test double) ---------------------------------------------------------------------------------------

    /** Options of {@link #createCibaBroker}. */
    public static final class BrokerOptions {
        public java.util.function.LongSupplier now = System::currentTimeMillis;
        /** PING/PUSH: called once, synchronously, when a session is resolved. A throw propagates after the decision is recorded. */
        public Consumer<Map<String, Object>> onComplete;
        public Supplier<String> authReqIdSource = CibaApproval::randomAuthReqId;
    }

    /**
     * An in-memory CIBA broker: models the backchannel lifecycle without any network. Single-process, loses everything on restart: for
     * tests of code that takes a broker, never to guard a real approval.
     */
    public static ApprovalBroker createCibaBroker(BrokerOptions opts) {
        final BrokerOptions o = opts == null ? new BrokerOptions() : opts;
        final Map<String, Map<String, Object>> sessions = new java.util.HashMap<>();
        final Map<String, String> liveByStepUp = new java.util.HashMap<>();
        final class Mem implements ApprovalBroker {
            String effective(Map<String, Object> s, long now) {
                if ("approve".equals(s.get("decision"))) return "approved";
                if ("deny".equals(s.get("decision"))) return "denied";
                return !(now < d(s.get("expiresAt"))) ? "expired" : "pending";
            }

            @Override public synchronized Map<String, Object> start(Map<String, Object> stepUp, Map<String, Object> reqOpts) {
                long now = o.now.getAsLong();
                String existingId = liveByStepUp.get(CibaJs.str(CibaJs.get(stepUp, "id")));
                Map<String, Object> existing = existingId != null ? sessions.get(existingId) : null;
                if (existing != null) {
                    String st = effective(existing, now);
                    if (st.equals("pending") || st.equals("approved")) return map(existing.get("request"));
                }
                Map<String, Object> ro = reqOpts == null ? new LinkedHashMap<>() : new LinkedHashMap<>(reqOpts);
                ro.put("authReqId", o.authReqIdSource.get());
                Map<String, Object> request = Ciba.toCibaAuthRequest(stepUp, ro);
                Map<String, Object> stored = Issue.obj("request", request, "createdAt", now, "expiresAt", (long) (now + d(request.get("requested_expiry")) * 1000),
                    "interval", request.get("interval"));
                sessions.put((String) request.get("auth_req_id"), stored);
                liveByStepUp.put(CibaJs.str(CibaJs.get(stepUp, "id")), (String) request.get("auth_req_id"));
                return request;
            }

            @Override public synchronized Map<String, Object> poll(String id) {
                Map<String, Object> s = sessions.get(id);
                if (s == null) throw new IllegalStateException("ciba: unknown auth_req_id " + id);
                return Issue.obj("status", effective(s, o.now.getAsLong()));
            }

            @Override public synchronized Map<String, Object> token(String id) {
                Map<String, Object> s = sessions.get(id);
                if (s == null) return outcome(false, "invalid_grant", 5L);
                long now = o.now.getAsLong();
                if (CibaJs.truthy(s.get("consumed"))) return outcome(false, "invalid_grant", s.get("interval"));
                boolean tooSoon = s.containsKey("lastPollAt") && !(now - d(s.get("lastPollAt")) >= d(s.get("interval")) * 1000);
                s.put("lastPollAt", now);
                if (tooSoon) {
                    s.put("interval", d(s.get("interval")) + 5);
                    return outcome(false, "slow_down", s.get("interval"));
                }
                String st = effective(s, now);
                if (st.equals("pending")) return outcome(false, "authorization_pending", s.get("interval"));
                if (st.equals("denied")) return outcome(false, "access_denied", s.get("interval"));
                if (st.equals("expired")) return outcome(false, "expired_token", s.get("interval"));
                s.put("consumed", true);
                return Issue.obj("ok", true, "session", snapshot(s, st));
            }

            @Override public synchronized Map<String, Object> resolve(String id, String decision, String by) {
                Map<String, Object> s = sessions.get(id);
                if (s == null) throw new IllegalStateException("ciba: unknown auth_req_id " + id);
                long now = o.now.getAsLong();
                String current = effective(s, now);
                if (!current.equals("pending")) throw new IllegalStateException("ciba: cannot resolve " + id + " \u2014 already " + current);
                s.put("decision", decision);
                s.put("decidedBy", by);
                s.put("decidedAt", now);
                Map<String, Object> snap = snapshot(s, effective(s, now));
                if (o.onComplete != null) o.onComplete.accept(snap);
                return snap;
            }

            @Override public synchronized Map<String, Object> get(String id) {
                Map<String, Object> s = sessions.get(id);
                return s == null ? null : snapshot(s, effective(s, o.now.getAsLong()));
            }
        }
        return new Mem();
    }

    /** All the session statuses a broker reports. */
    public static List<String> statuses() { return new ArrayList<>(List.of("pending", "approved", "denied", "expired")); }
}
