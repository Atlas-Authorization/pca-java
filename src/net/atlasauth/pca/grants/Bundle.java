package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Signed policy bundles and decision records: the signing, log and replay sides. Verification (verifyBundle, verifyLogHead,
 * verifyRecordInclusion, verifyBatch, bundleDigest, compareVersion, recordCommit) is {@link K3}; those are re-exposed here under the
 * reference names so a reader can map one to one.
 */
public final class Bundle {
    private Bundle() {}

    public static final String BUNDLE_DOMAIN = K3.BUNDLE_DOMAIN;
    public static final String BUNDLE_REF_DOMAIN = K3.BUNDLE_REF_DOMAIN;
    public static final String RECORD_DOMAIN = K3.RECORD_DOMAIN;
    public static final String LOG_HEAD_DOMAIN = K3.LOG_HEAD_DOMAIN;

    public static String bundleDigest(Object bundle) { return K3.bundleDigest(bundle); }

    public static int compareVersion(String a, String b) { return K3.compareVersion(a, b); }

    public static String recordCommit(Object record) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", RECORD_DOMAIN);
        m.put("r", record);
        return Pca.hashCanonical(m); // throws outside the strict profile, like the reference
    }

    private static Map<String, Object> bodyOf(Map<String, Object> b) {
        Map<String, Object> out = new LinkedHashMap<>(b);
        out.remove("sigs");
        return out;
    }

    /** One signer's {signer, sig} over the bundle body. Collect k of them and call {@link #assembleBundle}. Throws on a malformed body. */
    public static Map<String, Object> signBundle(Map<String, Object> body, Keys.EdKey secret) {
        String e = K3.bundleShapeError(body);
        if (e != null) throw new IllegalArgumentException("signBundle: " + e);
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("signer", Sig.signerOf(secret));
        s.put("sig", Sig.signBody(BUNDLE_DOMAIN, bodyOf(body), secret));
        return s;
    }

    public static Map<String, Object> assembleBundle(Map<String, Object> body, List<Object> sigs) {
        Map<String, Object> b = bodyOf(body);
        b.put("sigs", sigs);
        return b;
    }

    /** Mask by data CLASS: every detail field whose class is in {@code maskClasses} becomes a commitment. Returns the record itself when it has no detail or classes. */
    public static Map<String, Object> maskRecord(Map<String, Object> r, List<String> maskClasses) {
        Map<String, Object> detail = Sig.map(r.get("detail"));
        Map<String, Object> classes = Sig.map(r.get("classes"));
        if (detail == null || classes == null) return r;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> en : detail.entrySet()) {
            Object cls = classes.get(en.getKey());
            if (cls instanceof String && maskClasses.contains(cls)) {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("d", "atlas-pca/mask/v1");
                h.put("k", en.getKey());
                h.put("v", en.getValue());
                out.put(en.getKey(), "masked:" + cls + ":" + Pca.hashCanonical(h));
            } else {
                out.put(en.getKey(), en.getValue());
            }
        }
        Map<String, Object> res = new LinkedHashMap<>(r);
        res.put("detail", out);
        return res;
    }

    public static boolean verifyLogHead(Object head, String signer) { return K3.verifyLogHead(head, signer); }

    /** Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs. */
    public static final class DecisionLog {
        private final List<Map<String, Object>> recs = new ArrayList<>();
        private final Keys.EdKey secret;
        private final List<String> maskClasses;

        public DecisionLog(Keys.EdKey secret) { this(secret, new ArrayList<String>()); }

        public DecisionLog(Keys.EdKey secret, List<String> maskClasses) { this.secret = secret; this.maskClasses = maskClasses; }

        public int size() { return recs.size(); }

        /** Mask, chain and store a record (without v, seq, prev); returns the stored record. */
        public synchronized Map<String, Object> append(Map<String, Object> r) {
            Map<String, Object> masked = maskRecord(r, maskClasses);
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("v", 1L);
            rec.putAll(masked);
            rec.put("seq", (long) recs.size());
            rec.put("prev", recs.isEmpty() ? "" : recordCommit(recs.get(recs.size() - 1)));
            recs.add(rec);
            return rec;
        }

        private List<Object> commits() {
            List<Object> c = new ArrayList<>();
            for (Map<String, Object> r : recs) c.add(recordCommit(r));
            return c;
        }

        public synchronized Map<String, Object> head(long now) {
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("v", 1L);
            base.put("size", (long) recs.size());
            base.put("root", Pca.merkleRoot(commits())); // throws on an empty log, like the reference
            base.put("last_commit", recordCommit(recs.get(recs.size() - 1)));
            base.put("issued_at", now);
            base.put("signer", Sig.signerOf(secret));
            Map<String, Object> out = new LinkedHashMap<>(base);
            out.put("sig", Sig.signBody(LOG_HEAD_DOMAIN, base, secret));
            return out;
        }

        public synchronized Map<String, Object> proof(int seq) { return GrantSigning.merkleProof(commits(), seq); }

        /** Records [from, to) clamped to the log (JavaScript slice semantics for non-negative bounds). */
        public synchronized List<Object> slice(int from, int to) {
            int a = Math.min(Math.max(from, 0), recs.size());
            int b = Math.min(Math.max(to, a), recs.size());
            return new ArrayList<Object>(recs.subList(a, b));
        }
    }

    /** Offline: this record is in the log the signed head commits to, and the head is by the pinned signer. */
    public static boolean verifyRecordInclusion(Object rec, Object proof, Object head, String signer) { return K3.verifyRecordInclusion(rec, proof, head, signer); }

    /** The next batch of at most {@code max} records from {@code from} with a freshly signed head: {from, records, head}. */
    public static Map<String, Object> nextBatch(DecisionLog log, Object from, Object max, Object now) {
        if (!Sig.isSafeInt(from) || !Json.isSafeInt(max) || Json.asLong(max) < 1) throw new IllegalArgumentException("nextBatch: bad cursor or size");
        long f = Json.asLong(from), m = Json.asLong(max);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("from", f);
        b.put("records", log.slice((int) Math.min(f, Integer.MAX_VALUE), (int) Math.min(f + m, Integer.MAX_VALUE)));
        b.put("head", log.head(Json.asLong(now)));
        return b;
    }

    public static K3.BatchVerdict verifyBatch(Object batch, long stateNext, String stateLastCommit, String signer) { return K3.verifyBatch(batch, stateNext, stateLastCommit, signer); }

    private static int rank(Object k) { return "deny".equals(k) ? 0 : "escalate".equals(k) ? 1 : "allow".equals(k) ? 2 : -1; }

    /**
     * "What would have changed": re-run two pure decision functions over recorded traffic. {@code cases} are {action_digest, input}.
     * A change is {action_digest, before, after, direction}. Analysis tooling: it runs outside the trusted core.
     */
    public static List<Object> semanticDiff(List<Object> cases, Function<Object, String> oldDecide, Function<Object, String> newDecide) {
        List<Object> out = new ArrayList<>();
        for (Object co : cases) {
            Map<String, Object> c = Sig.map(co);
            String before = oldDecide.apply(c.get("input"));
            String after = newDecide.apply(c.get("input"));
            if (before == null ? after != null : !before.equals(after)) {
                Map<String, Object> ch = new LinkedHashMap<>();
                ch.put("action_digest", c.get("action_digest"));
                if (before != null) ch.put("before", before); // an undefined decision is absent from the reference's JSON
                if (after != null) ch.put("after", after);
                ch.put("direction", rank(after) >= 0 && rank(before) >= 0 && rank(after) > rank(before) ? "widened" : "tightened");
                out.add(ch);
            }
        }
        return out;
    }

    /** Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift). */
    public static List<Object> auditReplay(List<Object> records, List<Object> cases, BiFunction<Object, Object, String> decide) {
        Map<Object, Object> byAction = new LinkedHashMap<>();
        for (Object co : cases) byAction.put(Sig.map(co).get("action_digest"), Sig.map(co).get("input"));
        List<Object> out = new ArrayList<>();
        for (Object ro : records) {
            Map<String, Object> r = Sig.map(ro);
            if (!byAction.containsKey(r.get("action_digest"))) continue;
            String d = decide.apply(byAction.get(r.get("action_digest")), r.get("bundle_revision"));
            if (d == null ? r.get("decision") != null : !d.equals(r.get("decision"))) out.add(ro);
        }
        return out;
    }
}
