package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * The scoped-admission and signed-release side of the aggregate {@link BudgetLedger}: scope keys, {@link #admitAggregateAction},
 * {@link #startAggregate} / {@link #settleAggregate}, and signed releases that can be anchored in a {@link LedgerStore}.
 *
 * <p>A release is a signed statement by the releaser (the verifier or sequencer) that a reservation's effect did NOT happen; a release
 * that never arrives only over-restricts (a crash costs budget, never safety).
 */
public final class Budgets {
    private Budgets() {}

    public static final String RELEASE_DOMAIN = "atlas-pca/budget-release/v1\0";
    private static final List<String> RELEASE_REASONS = List.of("effect_failed", "effect_not_run", "denied_downstream", "rollback");

    /** The ledger key of a scope ({@code principal}, {@code org}, {@code fleet}) and its id; injective (the id is percent-encoded). */
    public static String scopeKey(String scope, String id) {
        if (!BudgetDoc.idOk(id)) throw new BudgetLedgerError("invalid", "a scope id is a non-empty string of at most 256 characters without control characters");
        return scope + "/" + encodeURIComponent(id);
    }

    /** JavaScript encodeURIComponent. */
    static String encodeURIComponent(String s) {
        if (Json.hasLoneSurrogate(s)) throw new IllegalArgumentException("URI malformed"); // the JavaScript URIError
        StringBuilder sb = new StringBuilder();
        for (byte b : Json.utf8(s)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".indexOf(c) >= 0) sb.append((char) c);
            else sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
        }
        return sb.toString();
    }

    // ---- signed, anchored releases ----

    private static byte[] releaseMessage(Map<String, Object> r) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : new String[] {"v", "key", "id", "reason", "at", "signer"}) body.put(k, r.get(k));
        return Pca.concat(RELEASE_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
    }

    /** Sign a release of {@code key}/{@code id}: reason is one of effect_failed, effect_not_run, denied_downstream, rollback. */
    public static Map<String, Object> signRelease(String key, String id, String reason, long at, Keys.EdKey secret) {
        if (!RELEASE_REASONS.contains(reason) || at < -9007199254740991L || at > 9007199254740991L || !BudgetDoc.idOk(key) || !BudgetDoc.idOk(id)) throw new IllegalArgumentException("signRelease: a malformed release");
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("v", StoreJs.num(1));
        base.put("key", key);
        base.put("id", id);
        base.put("reason", reason);
        base.put("at", StoreJs.num(at));
        base.put("signer", secret.id());
        base.put("sig", Keys.b64u(secret.sign(releaseMessage(base))));
        return base;
    }

    /** True iff {@code r} is well formed and signed by {@code expectedSigner} over exactly its content. Never throws. */
    public static boolean verifyRelease(Object ro, String expectedSigner) {
        try {
            Map<String, Object> r = StoreJs.map(ro);
            if (r == null || !StoreJs.isInt(r.get("v")) || StoreJs.lng(r.get("v")) != 1 || !java.util.Objects.equals(r.get("signer"), expectedSigner) || !RELEASE_REASONS.contains(r.get("reason"))
                || !StoreJs.isInt(r.get("at")) || !BudgetDoc.idOk(r.get("key")) || !BudgetDoc.idOk(r.get("id")) || Pca.decodeB64uStrict(r.get("sig"), 64) == null) return false;
            return Pca.verifyB64u(expectedSigner, releaseMessage(r), (String) r.get("sig"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static String releaseDigest(Map<String, Object> r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/budget-release-ref/v1");
        m.put("r", r);
        return Pca.hashCanonical(m);
    }

    /** The log leaf of a release. */
    public static String releaseCommit(Map<String, Object> r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/budget-release-leaf/v1");
        m.put("digest", releaseDigest(r));
        return Pca.hashCanonical(m);
    }

    /** Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index. */
    public static long anchorRelease(LedgerStore log, Map<String, Object> r) {
        String commit = releaseCommit(r);
        for (int i = 0; i < 64; i++) {
            long size = log.size();
            LedgerStore.AppendOutcome o = log.append(size, List.of(commit));
            if ("appended".equals(o.outcome) || "replayed".equals(o.outcome)) return size;
        }
        throw new BudgetLedgerError("conflict_exhausted", "could not anchor the release: the log kept moving");
    }

    // ---- scoped admission ----

    /** One reservation made by an admission. */
    public static final class Reservation {
        public final String key, id;
        public Reservation(String key, String id) { this.key = key; this.id = id; }
    }

    /** The outcome of {@link #admitAggregateAction}. */
    public static final class Admission {
        public boolean admitted;
        public String reason;
        /** The host verifier's verdict (a map with at least {@code allow}); may be null on a refusal. */
        public Map<String, Object> verdict;
        public List<Reservation> reservations;
        public Map<String, Object> state;
    }

    /** The ledger key of an accumulator for this admission, or null when it is session-scoped. Throws {@code scope_unbound}. */
    public static String aggregateKeyOf(Map<String, Object> a, Map<String, String> ids) {
        Object scope = a.get("scope");
        if (scope == null || "session".equals(scope)) return null;
        String id = ids.get((String) scope);
        if (id == null) throw new BudgetLedgerError("scope_unbound", "accumulator " + a.get("id") + " is " + scope + "-scoped but no " + scope + " id was given");
        return scopeKey((String) scope, id);
    }

    private static boolean isScoped(Map<String, Object> a) { return a.get("scope") != null && !"session".equals(a.get("scope")); }

    /**
     * Admit one action against every non-session accumulator, atomically per key: read each key's snapshot and compute the pre-states, call
     * {@code verify(state)}, and on allow {@code reserve} in every key with {@code expectedVersion} = the snapshot's. A moved key repeats
     * from the top (optimistic concurrency); a key over its cap denies and releases what the earlier keys reserved. Throws
     * {@code not_durable} for a ledger that is not durable, always.
     */
    public static Admission admitAggregateAction(BudgetLedger ledger, Map<String, String> ids, List<Map<String, Object>> accumulators, Object schema, Map<String, Object> event,
                                                 Function<Map<String, Object>, Map<String, Object>> verify, Long expiresAt, Integer maxAttempts) {
        List<Map<String, Object>> scoped = new ArrayList<>();
        for (Map<String, Object> a : accumulators) if (isScoped(a)) scoped.add(a);
        if (!scoped.isEmpty() && (ledger == null || !ledger.durable())) throw new BudgetLedgerError("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)");
        Map<String, List<Map<String, Object>>> byKey = new TreeMap<>();
        try {
            for (Map<String, Object> a : scoped) byKey.computeIfAbsent(aggregateKeyOf(a, ids), x -> new ArrayList<>()).add(a);
        } catch (BudgetLedgerError e) {
            if ("scope_unbound".equals(e.code())) {
                Admission r = new Admission();
                r.admitted = false;
                r.reason = "scope_unbound: " + e.getMessage();
                return r;
            }
            throw e;
        }
        List<String> keys = new ArrayList<>(byKey.keySet());
        int attempts = maxAttempts == null ? 256 : maxAttempts;
        for (int attempt = 0; attempt < attempts; attempt++) {
            Map<String, BudgetLedger.Snapshot> snaps = new LinkedHashMap<>();
            Map<String, Object> state = new LinkedHashMap<>();
            for (String k : keys) {
                BudgetLedger.Snapshot s = ledger.snapshot(k);
                snaps.put(k, s);
                for (Map<String, Object> a : byKey.get(k)) {
                    Map<String, Object> holder = StoreJs.map(a.get("holder"));
                    if (holder == null || !"site_local".equals(holder.get("kind"))) continue;
                    Map<String, Object> params = StoreJs.map(event.get("params"));
                    if (a.get("key") != null && IntentHistory.accKeyOf(a, params) == null) continue; // the verifier fails the claim (missing key)
                    state.put((String) a.get("id"), IntentHistory.accPreState(a, s.events, params, event.get("t"), schema));
                }
            }
            Map<String, Object> verdict = verify.apply(state);
            if (!Boolean.TRUE.equals(verdict.get("allow"))) {
                Admission r = new Admission();
                r.admitted = false;
                r.reason = "verifier denied";
                r.verdict = verdict;
                return r;
            }
            List<Reservation> done = new ArrayList<>();
            boolean moved = false;
            for (String k : keys) {
                BudgetLedger.ReserveRequest req = new BudgetLedger.ReserveRequest();
                req.event = event;
                req.accumulators = byKey.get(k);
                req.schema = schema;
                req.expectedVersion = snaps.get(k).version;
                req.expiresAt = expiresAt;
                BudgetLedger.ReserveOutcome r = ledger.reserve(k, req);
                if ("reserved".equals(r.outcome) || ("replayed".equals(r.outcome) && "reserved".equals(r.status))) {
                    done.add(new Reservation(k, (String) event.get("id")));
                    continue;
                }
                for (Reservation d : done) ledger.release(d.key, d.id, null);
                if ("conflict".equals(r.outcome)) {
                    moved = true;
                    break;
                }
                String why = "over_cap".equals(r.outcome) ? "over_cap: " + r.acc + " would reach " + r.postValue + " (cap " + AttestCommon.jsNumString(r.cap) + ")"
                    : "replayed".equals(r.outcome) ? "already " + r.status : r.outcome;
                Admission out = new Admission();
                out.admitted = false;
                out.reason = "aggregate: " + why;
                out.verdict = verdict;
                return out;
            }
            if (!moved) {
                Admission out = new Admission();
                out.admitted = true;
                out.verdict = verdict;
                out.reservations = done;
                out.state = state;
                return out;
            }
        }
        throw new BudgetLedgerError("conflict_exhausted", "the aggregate kept moving under this admission");
    }

    /**
     * BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (released or expired in the
     * meantime): the effect must NOT run then.
     */
    public static boolean startAggregate(BudgetLedger ledger, List<Reservation> reservations) {
        for (Reservation r : reservations) {
            BudgetLedger.SettleOutcome o = ledger.start(r.key, r.id);
            if (!"settled".equals(o.outcome) && !"replayed".equals(o.outcome)) return false;
        }
        return true;
    }

    /** After the effect: {@code committed} (it happened) or {@code released} (it did not; a signed {@code evidence} is stored and can be anchored). */
    public static List<BudgetLedger.SettleOutcome> settleAggregate(BudgetLedger ledger, List<Reservation> reservations, String status, Function<Reservation, Map<String, Object>> evidence) {
        List<BudgetLedger.SettleOutcome> out = new ArrayList<>();
        for (Reservation r : reservations) out.add("committed".equals(status) ? ledger.commit(r.key, r.id) : ledger.release(r.key, r.id, evidence == null ? null : evidence.apply(r)));
        return out;
    }
}
