package net.atlasauth.pca.grants;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * "Which objects of this type may this agent touch?" Authority = capability AND relationship: the capability ({@code permits}) decides
 * and a relation source can only NARROW. Every page is charged to a read accumulator (scanned and returned objects), pages are bound
 * by a signed cursor and the result carries a signed receipt. Verification of receipts and cursors is {@link K3}.
 */
public final class ListAuthorized {
    private ListAuthorized() {}

    public static final String LIST_RECEIPT_DOMAIN = K3.LIST_RECEIPT_DOMAIN;
    public static final String LIST_CURSOR_DOMAIN = K3.LIST_CURSOR_DOMAIN;
    public static final int MAX_PAGE_LIMIT = 500;

    /** One page of candidate objects; {@code next} null or empty ends the scan. */
    public static final class CandidatePage {
        public final List<String> objects;
        public final String next;
        public CandidatePage(List<String> objects, String next) { this.objects = objects; this.next = next; }
    }

    public interface CandidateSource {
        CandidatePage page(String type, String cursor, int limit) throws Exception;
    }

    public interface RelationSource {
        /** May {@code subject} have {@code relation} on {@code object}? Only ever narrows. */
        boolean check(String subject, String relation, String object) throws Exception;

        /** Whether {@link #listObjects} is implemented. */
        default boolean supportsListObjects() { return false; }

        default CandidatePage listObjects(String subject, String relation, String type, String cursor, int limit) throws Exception {
            throw new UnsupportedOperationException("listObjects");
        }
    }

    /** Adapt a relation source's list-objects into a candidate source for one subject + relation. */
    public static CandidateSource candidatesFromRelation(RelationSource rel, String subject, String relation) {
        if (!rel.supportsListObjects()) throw new IllegalArgumentException("candidatesFromRelation: the relation source has no listObjects");
        return (type, cursor, limit) -> rel.listObjects(subject, relation, type, cursor, limit);
    }

    /** Charges reads against a budget keyed by (subject, type). False when the charge would exceed the cap. */
    public interface ReadAccumulator {
        boolean charge(String key, long units, long now) throws Exception;
    }

    /** Reference accumulator: {@code cap} units per {@code windowMs} fixed window per key. */
    public static final class WindowReadAccumulator implements ReadAccumulator {
        private final Map<String, long[]> used = new HashMap<>();
        private final long cap;
        private final long windowMs;

        public WindowReadAccumulator(long cap, long windowMs) { this.cap = cap; this.windowMs = windowMs; }

        @Override
        public synchronized boolean charge(String key, long units, long now) {
            long[] e = used.get(key);
            long[] cur = e == null || now - e[0] >= windowMs ? new long[] {now, 0} : e;
            if (cur[1] + units > cap) return false;
            cur[1] += units;
            used.put(key, cur);
            return true;
        }
    }

    public static String objectsDigest(List<?> objects) { return K3.objectsDigest(objects); }

    public static boolean verifyListReceipt(Object r, String signer, List<?> objects) { return K3.verifyListReceipt(r, signer, objects); }

    public static final class ListError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** read_budget_exhausted | bad_cursor | bad_limit */
        public final String code;

        public ListError(String code, String message) { super(message); this.code = code; }
    }

    /** Arguments of {@link #listAuthorized}; fields mirror the reference. */
    public static final class Args {
        public String subject;
        public String resourceType;
        /** The capability: true iff the grant permits the object. */
        public Predicate<String> permits;
        public CandidateSource candidates;
        public RelationSource relationSource;
        /** The relation name; null when no relation filter is used. */
        public String relation;
        public String filterId;
        public String policyDigest;
        public String freshAtDigest;
        public String cursor;
        public long limit;
        public ReadAccumulator reads;
        public long now;
        public Keys.EdKey signingSecret;
        /** Max candidates scanned per call; null means 4x limit. At most 1000 either way. */
        public Long maxScan;
    }

    /** {objects, next_cursor?, receipt}. */
    public static final class Result {
        public final List<String> objects;
        public final String nextCursor;
        public final Map<String, Object> receipt;
        Result(List<String> objects, String nextCursor, Map<String, Object> receipt) { this.objects = objects; this.nextCursor = nextCursor; this.receipt = receipt; }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("objects", new ArrayList<Object>(objects));
            if (nextCursor != null) m.put("next_cursor", nextCursor);
            m.put("receipt", receipt);
            return m;
        }
    }

    private static Map<String, Object> bindInputs(Args a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", a.subject);
        m.put("resourceType", a.resourceType);
        m.put("filterId", a.filterId);
        m.put("policyDigest", a.policyDigest);
        if (a.relation != null) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("relation", a.relation);
            m.put("relation", r);
        }
        m.put("limit", a.limit);
        return m;
    }

    /** What a cursor is bound to: {subject, resourceType, filterId, policyDigest, relation?: {relation}, limit}. */
    public static String listBind(Map<String, Object> a) { return K3.listBind(a); }

    /** Verify a page cursor (never throws); {@code bind} null skips the binding check. */
    public static K3.CursorVerdict verifyListCursor(Object tok, String signer, Map<String, Object> bind) { return K3.verifyListCursor(tok, signer, bind); }

    private static String encCursor(String inner, long skip, String bind, String signer, Keys.EdKey secret) {
        // Member order is the reference's JSON.stringify order (v, inner?, skip, bind, signer); the signature covers the canonical form.
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("v", 1L);
        if (inner != null) c.put("inner", inner);
        c.put("skip", skip);
        c.put("bind", bind);
        c.put("signer", signer);
        StringBuilder sb = new StringBuilder("{\"v\":1");
        if (inner != null) sb.append(",\"inner\":").append(Json.canonicalize(inner));
        sb.append(",\"skip\":").append(skip).append(",\"bind\":").append(Json.canonicalize(bind)).append(",\"signer\":").append(Json.canonicalize(signer)).append('}');
        return Keys.b64u(Json.utf8(sb.toString())) + "." + Sig.signBody(LIST_CURSOR_DOMAIN, c, secret);
    }

    public static Result listAuthorized(Args a) throws Exception {
        if (a.limit < 1 || a.limit > MAX_PAGE_LIMIT) throw new ListError("bad_limit", "limit must be 1.." + MAX_PAGE_LIMIT);
        int limit = (int) a.limit;
        String signer = Sig.signerOf(a.signingSecret);
        Map<String, Object> bi = bindInputs(a);
        String bind = K3.listBind(bi);
        String inner = null;
        long skipIn = 0;
        if (a.cursor != null) {
            K3.CursorVerdict c = K3.verifyListCursor(a.cursor, signer, bi);
            if (!c.ok) throw new ListError("bad_cursor", "bind".equals(c.reason) ? "subject, type, filter, policy or limit changed between pages" : "the page cursor is malformed, forged or from another signer");
            inner = c.inner;
            skipIn = c.skip;
        }
        long maxScan = Math.min(a.maxScan != null ? a.maxScan : a.limit * 4, 1000);
        Map<String, Object> kk = new LinkedHashMap<>();
        kk.put("s", a.subject);
        kk.put("t", a.resourceType);
        String key = Pca.hashCanonical(kk);
        List<String> out = new ArrayList<>();
        long scanned = 0;
        String pageStart = inner;
        long skip = skipIn;
        boolean haveResume = false;
        String resumeInner = null;
        long resumeSkip = 0;
        for (;;) {
            CandidatePage pg = a.candidates.page(a.resourceType, pageStart, limit);
            List<String> objs = pg.objects.size() > limit ? pg.objects.subList(0, limit) : pg.objects;
            // Charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack.
            if (!a.reads.charge(key, Math.max(objs.size() - skip, 1), a.now)) throw new ListError("read_budget_exhausted", "the read budget for this subject and type is exhausted");
            int i = (int) Math.min(skip, Integer.MAX_VALUE);
            for (; i < objs.size() && out.size() < limit; i++) {
                scanned++;
                String o = objs.get(i);
                if (!a.permits.test(o)) continue;
                if (a.relation != null && !a.relationSource.check(a.subject, a.relation, o)) continue;
                out.add(o);
            }
            if (i < objs.size()) {
                haveResume = true;
                resumeInner = pageStart;
                resumeSkip = i;
                break;
            }
            if (pg.next == null || pg.next.isEmpty() || objs.isEmpty()) break;
            pageStart = pg.next;
            skip = 0;
            if (out.size() >= limit || scanned >= maxScan) {
                haveResume = true;
                resumeInner = pg.next;
                resumeSkip = 0;
                break;
            }
        }
        Map<String, Object> receipt = new LinkedHashMap<>();
        receipt.put("v", 1L);
        receipt.put("subject", a.subject);
        receipt.put("resource_type", a.resourceType);
        receipt.put("policy_digest", a.policyDigest);
        receipt.put("fresh_at", a.freshAtDigest);
        receipt.put("filter_digest", a.filterId);
        receipt.put("count", (long) out.size());
        receipt.put("objects_digest", K3.objectsDigest(out));
        receipt.put("issued_at", a.now);
        receipt.put("signer", signer);
        Map<String, Object> signed = new LinkedHashMap<>(receipt);
        signed.put("sig", Sig.signBody(LIST_RECEIPT_DOMAIN, receipt, a.signingSecret));
        String next = haveResume ? encCursor(resumeInner, resumeSkip, bind, signer, a.signingSecret) : null;
        return new Result(out, next, signed);
    }
}
