package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Break-glass grants (verification side): time-boxed, loud, auto-revoked, with a mandatory signed review. {@link Registry} keeps state
 * grouped by holder (in memory). Total. Replays packages/pca/conformance/break-glass-vectors.json. Results are plain maps that mirror
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

    private static final class Entry {
        final Map<String, Object> rec;
        final List<Long> uses = new ArrayList<>(); // the time of each use, oldest first
        Map<String, Object> review;
        Entry(Map<String, Object> rec) { this.rec = rec; }
    }

    /** Grants, uses and reviews grouped by holder. {@code authorities} and {@code reviewers} are the pinned keys. */
    public static final class Registry {
        private final List<String> authorities, reviewers;
        private final Map<String, Map<String, Entry>> holders = new HashMap<>();

        public Registry(List<String> authorities, List<String> reviewers) { this.authorities = authorities; this.reviewers = reviewers; }

        private static Map<String, Object> res(Object... kv) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
            return m;
        }
        private static Map<String, Object> no(String code) { return res("ok", false, "code", code); }

        private static boolean frozenIn(Map<String, Entry> st, String holder, long now) {
            for (Entry e : st.values()) {
                if (!holder.equals(e.rec.get("holder"))) continue;
                if (e.review != null ? "unjustified".equals(e.review.get("outcome")) : (!e.uses.isEmpty() && now >= e.uses.get(0) + n(e.rec, "review_within"))) return true;
            }
            return false;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> accept(Object rec, Object now) {
            try {
                if (!verify(rec) || !nat(now)) return no("bad_record");
                Map<String, Object> b = (Map<String, Object>) rec;
                if (!authorities.contains(b.get("authority"))) return no("unknown_authority");
                Map<String, Entry> st = holders.computeIfAbsent((String) b.get("holder"), x -> new HashMap<>());
                Entry cur = st.get((String) b.get("id"));
                if (cur != null) return cur.rec.get("sig").equals(b.get("sig")) ? res("ok", true, "replaced", false) : no("id_conflict");
                if (frozenIn(st, (String) b.get("holder"), Json.asLong(now))) return no("holder_frozen");
                st.put((String) b.get("id"), new Entry(b));
                return res("ok", true, "replaced", true);
            } catch (RuntimeException e) {
                return no("store_unreachable");
            }
        }

        public Map<String, Object> use(Object id, Object holder, Object actionDigest, Object now, Object notified) {
            if (!str(id, 128) || !str(holder, 128) || !str(actionDigest, 128) || !nat(now) || !(notified instanceof Boolean)) return res("decision", "deny", "code", "bad_input");
            try {
                long t = Json.asLong(now);
                Map<String, Entry> st = holders.getOrDefault(holder, Map.of());
                Entry e = st.get(id);
                if (e == null) return deny("unknown_break_glass", id);
                if (frozenIn(st, (String) holder, t)) return deny("holder_frozen", id);
                if (e.review != null && "unjustified".equals(e.review.get("outcome"))) return deny("revoked", id);
                if (t < n(e.rec, "issued_at")) return deny("not_yet_valid", id);
                if (t >= n(e.rec, "expires_at")) return deny("expired", id);
                if (e.uses.size() >= n(e.rec, "max_uses")) return deny("budget_exhausted", id);
                if (!((Boolean) notified)) return deny("not_notified", id);
                e.uses.add(t);
                return res("decision", "allow", "id", id, "use", (long) e.uses.size(), "remaining", n(e.rec, "max_uses") - e.uses.size(), "review_due", e.uses.get(0) + n(e.rec, "review_within"));
            } catch (RuntimeException ex) {
                return deny("store_unreachable", id);
            }
        }

        private static Map<String, Object> deny(String code, Object id) { return res("decision", "deny", "code", code, "id", id); }

        @SuppressWarnings("unchecked")
        public Map<String, Object> review(Object rec, Object holder, Object now) {
            try {
                if (!verifyReview(rec) || !str(holder, 128) || !nat(now)) return no("bad_record");
                Map<String, Object> r = (Map<String, Object>) rec;
                if (!reviewers.contains(r.get("reviewer"))) return no("unknown_reviewer");
                Entry e = holders.getOrDefault(holder, Map.of()).get(r.get("id"));
                if (e == null) return no("unknown_break_glass");
                if (r.get("reviewer").equals(e.rec.get("holder")) || r.get("reviewer").equals(e.rec.get("authority"))) return no("sod");
                if (e.review != null) return e.review.get("sig").equals(r.get("sig")) ? res("ok", true, "replaced", false) : no("already_reviewed");
                if (e.uses.isEmpty()) return no("nothing_to_review");
                if (n(r, "at") < e.uses.get(0) || n(r, "at") > Json.asLong(now)) return no("bad_time");
                e.review = r;
                return res("ok", true, "replaced", true);
            } catch (RuntimeException ex) {
                return no("store_unreachable");
            }
        }

        public boolean frozen(Object holder, Object now) {
            if (!str(holder, 128) || !nat(now)) return true; // fail closed
            try {
                return frozenIn(holders.getOrDefault(holder, Map.of()), (String) holder, Json.asLong(now));
            } catch (RuntimeException e) {
                return true;
            }
        }
    }
}
