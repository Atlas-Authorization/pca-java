package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Break-glass grants (verification side): time-boxed, loud, auto-revoked, with a mandatory signed review. {@link Registry} keeps state
 * in a durable {@link AtomicKv}, sharded by holder. Total. Replays packages/pca/conformance/break-glass-vectors.json. Results are plain maps that mirror
 * the vectors' expected objects.
 */
public final class BreakGlass {
    private BreakGlass() {}

    public static final String DOMAIN = "atlas-pca/break-glass/v1\u0000";
    public static final String REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\u0000";
    public static final long MAX_WINDOW_MS = 86_400_000L;
    public static final long MAX_USES = 16;
    public static final long MAX_REVIEW_WITHIN_MS = 30L * 86_400_000L;
    private static final String[] BODY_KEYS = {"v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"};
    private static final String[] REVIEW_KEYS = {"v", "id", "outcome", "notes_digest", "at", "reviewer"};

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }
    private static long n(Map<String, Object> m, String k) { return Json.asLong(m.get(k)); }

    @SuppressWarnings("unchecked")
    static boolean wellFormed(Object v) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> b = (Map<String, Object>) v;
        if (!Json.isSafeInt(b.get("v")) || Json.asLong(b.get("v")) != 1) return false;
        if (!str(b.get("id"), 128) || !str(b.get("holder"), 128) || !str(b.get("grant_ref"), 256) || !str(b.get("reason_digest"), 128)) return false;
        if (!str(b.get("notify_to"), 256) || !str(b.get("authority"), 128)) return false;
        for (String k : new String[] {"max_uses", "issued_at", "expires_at", "review_within"}) if (!nat(b.get(k))) return false;
        if (n(b, "max_uses") < 1 || n(b, "max_uses") > MAX_USES) return false;
        if (n(b, "expires_at") <= n(b, "issued_at") || n(b, "expires_at") - n(b, "issued_at") > MAX_WINDOW_MS) return false;
        return n(b, "review_within") >= 1 && n(b, "review_within") <= MAX_REVIEW_WITHIN_MS;
    }

    private static Map<String, Object> body(Map<String, Object> o, String[] keys) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : keys) b.put(k, o.get(k));
        return b;
    }

    @SuppressWarnings("unchecked")
    public static boolean verify(Object v) {
        if (!wellFormed(v)) return false;
        Map<String, Object> b = (Map<String, Object>) v;
        return K3.verifyBody(DOMAIN, body(b, BODY_KEYS), (String) b.get("authority"), b.get("sig"));
    }

    @SuppressWarnings("unchecked")
    static boolean reviewWellFormed(Object v) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> r = (Map<String, Object>) v;
        return Json.isSafeInt(r.get("v")) && Json.asLong(r.get("v")) == 1 && str(r.get("id"), 128)
            && ("justified".equals(r.get("outcome")) || "unjustified".equals(r.get("outcome"))) && str(r.get("notes_digest"), 128) && nat(r.get("at")) && str(r.get("reviewer"), 128);
    }

    @SuppressWarnings("unchecked")
    public static boolean verifyReview(Object v) {
        if (!reviewWellFormed(v)) return false;
        Map<String, Object> r = (Map<String, Object>) v;
        return K3.verifyBody(REVIEW_DOMAIN, body(r, REVIEW_KEYS), (String) r.get("reviewer"), r.get("sig"));
    }

    /** Grants, uses and reviews in a durable {@link AtomicKv}: one document per holder shard {@code {grants: {id: {rec, uses: [{n, action_digest, at}], review?}}}}. {@code authorities} and {@code reviewers} are the pinned keys. */
    public static final class Registry {
        private final List<String> authorities, reviewers;
        private final AtomicKv kv;
        private final int shards;
        private boolean metaOk;

        /** @param kv the durable store (required: a process-local default would forget uses and reviews on restart; {@link MemoryAtomicKv} is for tests and one process). */
        public Registry(List<String> authorities, List<String> reviewers, AtomicKv kv) { this(authorities, reviewers, kv, Lease.DEFAULT_SHARDS); }

        public Registry(List<String> authorities, List<String> reviewers, AtomicKv kv, int shards) {
            if (kv == null) throw new IllegalArgumentException("BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)");
            if (shards < 1 || shards > Lease.MAX_SHARDS) throw new IllegalArgumentException("BreakGlassRegistry: shards must be an integer from 1 to 4096");
            this.authorities = authorities;
            this.reviewers = reviewers;
            this.kv = kv;
            this.shards = shards;
        }

        private static Map<String, Object> res(Object... kv) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
            return m;
        }
        private static Map<String, Object> no(String code) { return res("ok", false, "code", code); }

        private synchronized boolean ready() {
            if (!metaOk) metaOk = Lease.pinShards(kv, "breakglass/meta", shards);
            return metaOk;
        }

        private String key(String holder) { return "breakglass/" + shards + "/" + Lease.shardOf(holder, shards); }

        /** A private copy of a shard's grants (the store's value is never mutated in place). */
        @SuppressWarnings("unchecked")
        private static Map<String, Map<String, Object>> load(Object prev) {
            Map<String, Map<String, Object>> out = new LinkedHashMap<>();
            if (prev instanceof Map && ((Map<?, ?>) prev).get("grants") instanceof Map) {
                for (Map.Entry<String, Object> e : ((Map<String, Object>) ((Map<?, ?>) prev).get("grants")).entrySet()) {
                    Map<String, Object> g = new LinkedHashMap<>((Map<String, Object>) e.getValue());
                    g.put("uses", new ArrayList<>((List<Object>) g.get("uses")));
                    out.put(e.getKey(), g);
                }
            }
            return out;
        }

        private static Map<String, Object> doc(Map<String, Map<String, Object>> grants) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("grants", new LinkedHashMap<String, Object>(grants));
            return d;
        }

        @SuppressWarnings("unchecked")
        private static List<Object> usesOf(Map<String, Object> g) { return (List<Object>) g.get("uses"); }

        @SuppressWarnings("unchecked")
        private static long useAt(Object u) { return n((Map<String, Object>) u, "at"); }

        /** Frozen: a grant of this holder was judged unjustified, or has uses, no review and a review clock that has run out. */
        @SuppressWarnings("unchecked")
        private static boolean frozenIn(Map<String, Map<String, Object>> grants, String holder, long now) {
            for (Map<String, Object> g : grants.values()) {
                Map<String, Object> rec = (Map<String, Object>) g.get("rec");
                if (!holder.equals(rec.get("holder"))) continue;
                Map<String, Object> review = (Map<String, Object>) g.get("review");
                if (review != null ? "unjustified".equals(review.get("outcome")) : (!usesOf(g).isEmpty() && now >= useAt(usesOf(g).get(0)) + n(rec, "review_within"))) return true;
            }
            return false;
        }

        /** Register an issued record. A frozen holder gets no new one. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> accept(Object rec, Object now) {
            try {
                if (!verify(rec) || !nat(now)) return no("bad_record");
                Map<String, Object> b = (Map<String, Object>) rec;
                if (!authorities.contains(b.get("authority"))) return no("unknown_authority");
                if (!ready()) return no("store_unreachable");
                Map<String, Object>[] out = new Map[] {no("store_unreachable")};
                String holder = (String) b.get("holder");
                String id = (String) b.get("id");
                kv.update(key(holder), prev -> {
                    Map<String, Map<String, Object>> grants = load(prev);
                    Map<String, Object> cur = grants.get(id);
                    if (cur != null) {
                        out[0] = ((Map<String, Object>) cur.get("rec")).get("sig").equals(b.get("sig")) ? res("ok", true, "replaced", false) : no("id_conflict");
                        return null;
                    }
                    if (frozenIn(grants, holder, Json.asLong(now))) { out[0] = no("holder_frozen"); return null; }
                    Map<String, Object> g = new LinkedHashMap<>();
                    g.put("rec", b);
                    g.put("uses", new ArrayList<Object>());
                    grants.put(id, g);
                    out[0] = res("ok", true, "replaced", true);
                    return doc(grants);
                });
                return out[0];
            } catch (RuntimeException e) {
                return no("store_unreachable");
            }
        }

        /** Record one use. {@code notified} must be true: the enforcement point delivered the notification before acting. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> use(Object id, Object holder, Object actionDigest, Object now, Object notified) {
            if (!str(id, 128) || !str(holder, 128) || !str(actionDigest, 128) || !nat(now) || !(notified instanceof Boolean)) return res("decision", "deny", "code", "bad_input");
            try {
                long t = Json.asLong(now);
                if (!ready()) return deny("store_unreachable", id);
                Map<String, Object>[] out = new Map[] {deny("store_unreachable", id)};
                kv.update(key((String) holder), prev -> {
                    Map<String, Map<String, Object>> grants = load(prev);
                    Map<String, Object> g = grants.get(id);
                    if (g == null) { out[0] = deny("unknown_break_glass", id); return null; }
                    Map<String, Object> rec = (Map<String, Object>) g.get("rec");
                    if (!holder.equals(rec.get("holder"))) { out[0] = deny("wrong_holder", id); return null; }
                    if (frozenIn(grants, (String) holder, t)) { out[0] = deny("holder_frozen", id); return null; }
                    Map<String, Object> review = (Map<String, Object>) g.get("review");
                    if (review != null && "unjustified".equals(review.get("outcome"))) { out[0] = deny("revoked", id); return null; }
                    if (t < n(rec, "issued_at")) { out[0] = deny("not_yet_valid", id); return null; }
                    if (t >= n(rec, "expires_at")) { out[0] = deny("expired", id); return null; }
                    List<Object> uses = usesOf(g);
                    if (uses.size() >= n(rec, "max_uses")) { out[0] = deny("budget_exhausted", id); return null; }
                    if (!((Boolean) notified)) { out[0] = deny("not_notified", id); return null; }
                    Map<String, Object> u = new LinkedHashMap<>();
                    u.put("n", IntentJs.ofLong(uses.size() + 1L));
                    u.put("action_digest", actionDigest);
                    u.put("at", IntentJs.ofLong(t));
                    uses.add(u);
                    out[0] = res("decision", "allow", "id", id, "use", (long) uses.size(), "remaining", n(rec, "max_uses") - uses.size(), "review_due", useAt(uses.get(0)) + n(rec, "review_within"));
                    return doc(grants);
                });
                return out[0];
            } catch (RuntimeException ex) {
                return deny("store_unreachable", id);
            }
        }

        private static Map<String, Object> deny(String code, Object id) { return res("decision", "deny", "code", code, "id", id); }

        /** Record the signed review. The first review of a grant is final; a review may be late (it then lifts an overdue freeze). */
        @SuppressWarnings("unchecked")
        public Map<String, Object> review(Object rec, Object holder, Object now) {
            try {
                if (!verifyReview(rec) || !str(holder, 128) || !nat(now)) return no("bad_record");
                Map<String, Object> r = (Map<String, Object>) rec;
                if (!reviewers.contains(r.get("reviewer"))) return no("unknown_reviewer");
                if (!ready()) return no("store_unreachable");
                Map<String, Object>[] out = new Map[] {no("store_unreachable")};
                kv.update(key((String) holder), prev -> {
                    Map<String, Map<String, Object>> grants = load(prev);
                    Map<String, Object> g = grants.get(r.get("id"));
                    Map<String, Object> grec = g == null ? null : (Map<String, Object>) g.get("rec");
                    if (g == null || !holder.equals(grec.get("holder"))) { out[0] = no("unknown_break_glass"); return null; }
                    if (r.get("reviewer").equals(grec.get("holder")) || r.get("reviewer").equals(grec.get("authority"))) { out[0] = no("sod"); return null; }
                    Map<String, Object> review = (Map<String, Object>) g.get("review");
                    if (review != null) { out[0] = review.get("sig").equals(r.get("sig")) ? res("ok", true, "replaced", false) : no("already_reviewed"); return null; }
                    List<Object> uses = usesOf(g);
                    if (uses.isEmpty()) { out[0] = no("nothing_to_review"); return null; }
                    if (n(r, "at") < useAt(uses.get(0)) || n(r, "at") > Json.asLong(now)) { out[0] = no("bad_time"); return null; }
                    g.put("review", r);
                    out[0] = res("ok", true, "replaced", true);
                    return doc(grants);
                });
                return out[0];
            } catch (RuntimeException ex) {
                return no("store_unreachable");
            }
        }

        /** Is the holder frozen (fail closed: malformed input or an unreachable store reads as frozen)? */
        public boolean frozen(Object holder, Object now) {
            if (!str(holder, 128) || !nat(now)) return true; // fail closed
            try {
                if (!ready()) return true;
                return frozenIn(load(kv.get(key((String) holder))), (String) holder, Json.asLong(now));
            } catch (RuntimeException e) {
                return true;
            }
        }

        /** The numbered use log of a grant, oldest first. */
        @SuppressWarnings("unchecked")
        public List<Object> uses(String holder, String id) {
            if (!ready()) return new ArrayList<>();
            Map<String, Object> g = load(kv.get(key(holder))).get(id);
            return g == null ? new ArrayList<>() : new ArrayList<>(usesOf(g));
        }
    }
}
