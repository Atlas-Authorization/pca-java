package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * K3 operational-plane artifact verification: consistency tokens ({@code fresh_at}), signed policy bundles, decision-log
 * heads / records / batches, list receipts and cursors, and grant-management signatures (amend, revoke, need approval).
 * Verification only. Every signature is Ed25519 (strict verify) over {@code domain || strictCanonicalJSON(body)}. Inputs are
 * parsed JSON values ({@link Json#parseLenient}); every function is total: malformed input yields the failure value
 * (false, null or a failing verdict), never an exception.
 */
public final class K3 {
    private K3() {}

    public static final String FRESH_AT_DOMAIN = "atlas-pca/fresh-at/v1\0";
    public static final String FRESH_AT_REF_DOMAIN = "atlas-pca/fresh-at-ref/v1";
    public static final String BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\0";
    public static final String BUNDLE_REF_DOMAIN = "atlas-pca/policy-bundle-ref/v1";
    public static final String RECORD_DOMAIN = "atlas-pca/decision-record/v1";
    public static final String LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\0";
    public static final String LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\0";
    public static final String LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\0";
    public static final String GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\0";
    public static final String GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\0";
    public static final String NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\0";

    // ---- shared helpers ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static boolean isStr(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }

    /** JavaScript {@code Number.isSafeInteger(n) && n >= 0}. */
    private static boolean isNonNeg(Object o) { return IntentJs.isSafeInteger(o) && IntentJs.num(o) >= 0; }

    /** JavaScript {@code o === 1}. */
    private static boolean isOne(Object o) { Double d = IntentJs.num(o); return d != null && d == 1.0; }

    private static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        Double d = IntentJs.num(o);
        if (d != null) return d != 0.0 && !d.isNaN();
        if (o instanceof String) return !((String) o).isEmpty();
        return true;
    }

    private static Map<String, Object> without(Map<String, Object> m, String key) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        out.remove(key);
        return out;
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** base64url(sha256(strictCanonical(v))), or null when v is outside the strict profile. */
    private static String digestOf(Object v) {
        try {
            return Pca.hashCanonical(v);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** True iff {@code sig} is a canonical 64-byte b64u signature by {@code signer} over exactly domain || canonical(body). Never throws. */
    static boolean verifyBody(String domain, Object body, String signer, Object sig) {
        try {
            if (signer == null || !(sig instanceof String) || Pca.decodeB64uStrict(sig, 64) == null) return false;
            byte[] msg = Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
            return Pca.verifyB64u(signer, msg, (String) sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** How JavaScript prints a safe-integer number in a message; "undefined" for a non-number. */
    private static String jsNum(Object o) {
        Double d = IntentJs.num(o);
        if (d == null) return "undefined";
        double v = d;
        if (v == Math.rint(v) && Math.abs(v) <= 9007199254740991.0) return Long.toString((long) v);
        return Double.toString(v);
    }

    // =====================================================================================================================
    // fresh_at: consistency tokens
    // =====================================================================================================================

    private static final String[] NUMERIC = {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"};
    private static final List<String> FRESH_KEYS = Arrays.asList(
        "v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer", "sig");

    /** Well formed and signed by {@code signer} over exactly its content. Never throws. */
    public static boolean verifyFreshAt(Object token, String signer) {
        Map<String, Object> t = map(token);
        if (t == null || signer == null || !isOne(t.get("v")) || !signer.equals(t.get("signer")) || !isStr(t.get("scope"), 256)
            || !isStr(t.get("policy_digest"), 128) || !isNonNeg(t.get("issued_at"))) return false;
        for (String k : NUMERIC) if (!isNonNeg(t.get(k))) return false;
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : new String[] {"v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer"})
            body.put(k, t.get(k));
        return verifyBody(FRESH_AT_DOMAIN, body, signer, t.get("sig"));
    }

    /** The content address a PCActn or request signs to bind the token it carried; null outside the strict profile. */
    public static String freshAtDigest(Object token) {
        return digestOf(obj("d", FRESH_AT_REF_DOMAIN, "t", token));
    }

    /** Outcome of {@link #checkFreshAt}: decision ok | escalate (code stale_state, behind) | deny (code). */
    public static final class FreshVerdict {
        public final String decision;
        public final String code;
        public final List<String> behind;
        FreshVerdict(String decision, String code, List<String> behind) { this.decision = decision; this.code = code; this.behind = behind; }
        static FreshVerdict deny(String code) { return new FreshVerdict("deny", code, Collections.<String>emptyList()); }
    }

    /**
     * May the verifier decide against {@code local} for a request carrying {@code token}? Signature/shape, scope, issued in the future
     * (more than 60 s of skew), token age ({@code maxTokenAgeMs}; null = absent), policy fork, then any of the four counters behind the
     * token is an escalate {@code stale_state}. {@code local} holds the verifier's own counters as a parsed JSON object.
     */
    public static FreshVerdict checkFreshAt(Object token, Map<String, Object> local, String signer, String scope, long now, Double maxTokenAgeMs) {
        try {
            if (!verifyFreshAt(token, signer)) return FreshVerdict.deny("bad_token");
            Map<String, Object> t = map(token);
            if (!Objects.equals(t.get("scope"), scope)) return FreshVerdict.deny("wrong_scope");
            double issued = IntentJs.num(t.get("issued_at"));
            if (!(issued <= (double) now + 60000.0)) return FreshVerdict.deny("token_from_the_future");
            if (maxTokenAgeMs != null && !((double) now - issued <= maxTokenAgeMs)) return FreshVerdict.deny("token_too_old");
            Double lrev = local == null ? null : IntentJs.num(local.get("policy_revision"));
            double trev = IntentJs.num(t.get("policy_revision"));
            if (lrev != null && lrev == trev && !Objects.equals(t.get("policy_digest"), local.get("policy_digest"))) return FreshVerdict.deny("policy_fork");
            List<String> behind = new ArrayList<>();
            for (String k : NUMERIC) {
                Double lv = local == null ? null : IntentJs.num(local.get(k));
                double tv = IntentJs.num(t.get(k));
                if (lv == null || !(lv >= tv)) behind.add(k);
            }
            return behind.isEmpty() ? new FreshVerdict("ok", null, Collections.<String>emptyList()) : new FreshVerdict("escalate", "stale_state", behind);
        } catch (RuntimeException e) {
            return FreshVerdict.deny("bad_token");
        }
    }

    /** Wire shape of the PCActn {@code fresh_at} member (closed key set). Returns the problem or null. Does NOT check the signature. */
    public static String validateFreshAtWire(Object v) {
        Map<String, Object> m = map(v);
        if (m == null) return "'fresh_at' must be an object";
        for (String k : m.keySet()) if (!FRESH_KEYS.contains(k)) return "'fresh_at' has an unknown field '" + k + "'";
        if (!isOne(m.get("v"))) return "'fresh_at.v' must be 1";
        if (!isStr(m.get("scope"), 256) || !isStr(m.get("policy_digest"), 128)) return "'fresh_at' scope and policy_digest must be non-empty strings";
        for (String k : new String[] {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"})
            if (!isNonNeg(m.get(k))) return "'fresh_at." + k + "' must be a non-negative safe integer";
        if (Pca.decodeB64uStrict(m.get("signer"), 32) == null) return "'fresh_at.signer' is not canonical base64url (32 bytes)";
        if (Pca.decodeB64uStrict(m.get("sig"), 64) == null) return "'fresh_at.sig' is not canonical base64url (64 bytes)";
        return null;
    }

    /** Verifier-side configuration of the {@code fresh_at} check. */
    public static final class FreshAtPolicy {
        /** The pinned token signer (b64u Ed25519 public key). */
        public final String signer;
        /** The scope this verifier decides for. */
        public final String scope;
        /** The verifier's OWN current counters (revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest). */
        public final Map<String, Object> local;
        /** Refuse a token older than this (ms); null = no age limit. */
        public final Double maxTokenAgeMs;
        /** Every PCActn must carry (or have side-carried) a token; none is an escalate "refresh and retry". */
        public final boolean require;
        /** A token that travelled beside the PCActn (pre-member form); read only when the PCActn has no member. */
        public final boolean hasSideCarried;
        public final Object sideCarried;

        public FreshAtPolicy(String signer, String scope, Map<String, Object> local, Double maxTokenAgeMs, boolean require, boolean hasSideCarried, Object sideCarried) {
            this.signer = signer;
            this.scope = scope;
            this.local = local;
            this.maxTokenAgeMs = maxTokenAgeMs;
            this.require = require;
            this.hasSideCarried = hasSideCarried;
            this.sideCarried = sideCarried;
        }

        /** From the snake_case JSON form {@code {signer, scope, local, max_token_age_ms?, require?, side_carried?}}; null when absent or not an object. */
        public static FreshAtPolicy fromJson(Object o) {
            Map<String, Object> m = map(o);
            if (m == null) return null;
            Double max = null;
            if (m.containsKey("max_token_age_ms")) {
                Double d = IntentJs.num(m.get("max_token_age_ms"));
                max = d == null ? Double.valueOf(Double.NaN) : d;
            }
            return new FreshAtPolicy(m.get("signer") instanceof String ? (String) m.get("signer") : null,
                m.get("scope") instanceof String ? (String) m.get("scope") : null, map(m.get("local")), max, truthy(m.get("require")),
                m.containsKey("side_carried"), m.get("side_carried"));
        }
    }

    /** Result of {@link #decideFreshAt}: status "none" (not reported), "pass" or "fail" (with the reason after {@code "fresh_at: "}). */
    public static final class FreshAtCheck {
        public final String status;
        public final String reason;
        FreshAtCheck(String status, String reason) { this.status = status; this.reason = reason; }
    }

    /**
     * The verifier's {@code fresh_at} check. Reported only when the PCActn carries the member, a side-carried token is read, or the
     * policy requires one; otherwise "none" (byte-identical to before). A stale verifier is an {@code escalate:} failure, anything
     * else a hard failure.
     */
    public static FreshAtCheck decideFreshAt(boolean hasMember, Object member, FreshAtPolicy policy, long now) {
        if (policy == null) {
            return hasMember ? new FreshAtCheck("fail", "the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)") : new FreshAtCheck("none", null);
        }
        boolean hasToken = hasMember || policy.hasSideCarried;
        Object token = hasMember ? member : policy.sideCarried;
        if (!hasToken) {
            return policy.require
                ? new FreshAtCheck("fail", "escalate: a consistency token is required (refresh and retry with the token of your latest write)")
                : new FreshAtCheck("none", null);
        }
        FreshVerdict v = checkFreshAt(token, policy.local, policy.signer, policy.scope, now, policy.maxTokenAgeMs);
        if (v.decision.equals("ok")) return new FreshAtCheck("pass", null);
        if (v.decision.equals("escalate")) return new FreshAtCheck("fail", "escalate: stale_state (verifier state is behind the token on " + String.join(", ", v.behind) + ")");
        return new FreshAtCheck("fail", v.code);
    }

    // =====================================================================================================================
    // signed policy bundles
    // =====================================================================================================================

    private static final Pattern VERSION_RE = Pattern.compile("\\d{1,6}(\\.\\d{1,6}){0,3}");
    private static final int MAX_LIST = 4096;

    private static Map<String, Object> bundleBody(Map<String, Object> b) { return without(b, "sigs"); }

    /** Digest of the bundle body (the signatures are not part of it); null when malformed. */
    public static String bundleDigest(Object bundle) {
        Map<String, Object> b = map(bundle);
        return b == null ? null : digestOf(obj("d", BUNDLE_REF_DOMAIN, "b", bundleBody(b)));
    }

    /** Dotted numeric version comparison: -1, 0 or 1. */
    public static int compareVersion(String a, String b) {
        String[] pa = a.split("\\.", -1);
        String[] pb = b.split("\\.", -1);
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            double d = versionPart(pa, i) - versionPart(pb, i);
            if (d != 0) return d < 0 ? -1 : 1; // NaN != 0, as in the reference
        }
        return 0;
    }

    private static double versionPart(String[] parts, int i) {
        if (i >= parts.length) return 0;
        if (parts[i].trim().isEmpty()) return 0;
        try {
            return Double.parseDouble(parts[i].trim());
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    private static boolean strList(Object o, int maxLen, int maxStr) {
        if (!(o instanceof List) || ((List<?>) o).size() > maxLen) return false;
        for (Object x : (List<?>) o) if (!isStr(x, maxStr)) return false;
        return true;
    }

    /** The reason a value is not a well formed policy bundle, or null. */
    public static String bundleShapeError(Object o) {
        Map<String, Object> b = map(o);
        if (b == null || !isOne(b.get("v")) || !"pca-policy-bundle".equals(b.get("kind"))) return "not a policy bundle";
        if (!IntentJs.isSafeInteger(b.get("revision")) || IntentJs.num(b.get("revision")) < 1 || !isNonNeg(b.get("issued_at"))) return "bad revision or time";
        boolean rev1 = IntentJs.num(b.get("revision")) == 1.0;
        if (rev1 ? b.containsKey("prev") : !isStr(b.get("prev"), 128)) return "prev must be absent at revision 1 and present after";
        if (!strList(b.get("grants"), MAX_LIST, 128)) return "bad grants";
        if (!strList(b.get("template_digests"), MAX_LIST, 128)) return "bad template_digests";
        for (String k : new String[] {"schema_digest", "constitution_digest", "flow_rules_digest"})
            if (b.containsKey(k) && !isStr(b.get(k), 128)) return "bad " + k;
        Object mv = b.get("min_verifier_version");
        if (!(mv instanceof String) || !VERSION_RE.matcher((String) mv).matches()) return "bad min_verifier_version";
        return null;
    }

    /** Outcome of {@link #verifyBundle}. */
    public static final class BundleVerdict {
        public final boolean ok;
        /** malformed | below_threshold | rollback | broken_chain | verifier_too_old (when not ok). */
        public final String code;
        public final String reason;
        public final long revision;
        public final String digest;
        public final List<String> signers;
        BundleVerdict(boolean ok, String code, String reason, long revision, String digest, List<String> signers) {
            this.ok = ok; this.code = code; this.reason = reason; this.revision = revision; this.digest = digest; this.signers = signers;
        }
        static BundleVerdict fail(String code, String reason) { return new BundleVerdict(false, code, reason, 0, null, null); }
    }

    /**
     * Verify a signed policy bundle against the pinned signer set, the threshold, this verifier's version and (optionally) the newest
     * accepted {@code lastRevision} / {@code lastDigest} (null {@code lastRevision} = none).
     */
    public static BundleVerdict verifyBundle(Object b, Collection<?> signers, Object threshold, String verifierVersion, Long lastRevision, String lastDigest) {
        try {
            String e = bundleShapeError(b);
            if (e != null) return BundleVerdict.fail("malformed", e);
            Map<String, Object> bundle = map(b);
            Object sigs = bundle.get("sigs");
            boolean thr = IntentJs.isSafeInteger(threshold) && IntentJs.num(threshold) >= 1;
            if (!(sigs instanceof List) || ((List<?>) sigs).size() > 64 || !thr) return BundleVerdict.fail("malformed", "bad sigs or threshold");
            long need = IntentJs.lng(threshold);
            Set<Object> pinned = new HashSet<>(signers);
            Map<String, Object> body = bundleBody(bundle);
            Set<String> good = new LinkedHashSet<>();
            for (Object s : (List<?>) sigs) {
                Map<String, Object> sm = map(s);
                if (sm == null) continue;
                Object sg = sm.get("signer");
                if (sg instanceof String && pinned.contains(sg) && verifyBody(BUNDLE_DOMAIN, body, (String) sg, sm.get("sig"))) good.add((String) sg);
            }
            if (good.size() < need) return BundleVerdict.fail("below_threshold", good.size() + " valid pinned signature(s), need " + need);
            String min = (String) bundle.get("min_verifier_version");
            if (verifierVersion == null || !VERSION_RE.matcher(verifierVersion).matches() || compareVersion(verifierVersion, min) < 0) return BundleVerdict.fail("verifier_too_old", "needs verifier >= " + min);
            long rev = IntentJs.lng(bundle.get("revision"));
            String digest = bundleDigest(bundle);
            if (lastRevision != null) {
                long last = lastRevision;
                if (rev < last) return BundleVerdict.fail("rollback", "revision " + rev + " < accepted " + last);
                if (rev == last && !Objects.equals(digest, lastDigest)) return BundleVerdict.fail("broken_chain", "same revision, different content");
                if (rev == last + 1 && !Objects.equals(bundle.get("prev"), lastDigest)) return BundleVerdict.fail("broken_chain", "prev does not chain to the accepted revision");
            }
            return new BundleVerdict(true, null, null, rev, digest, new ArrayList<>(good));
        } catch (RuntimeException ex) {
            return BundleVerdict.fail("malformed", "malformed bundle");
        }
    }

    // =====================================================================================================================
    // decision log
    // =====================================================================================================================

    /** Commit of a decision record (hash of the record under the record domain); null outside the strict profile. */
    public static String recordCommit(Object record) {
        return digestOf(obj("d", RECORD_DOMAIN, "r", record));
    }

    /** A signed log head by {@code signer}: shape and signature over every member but {@code sig}. Never throws. */
    public static boolean verifyLogHead(Object head, String signer) {
        Map<String, Object> h = map(head);
        if (h == null || signer == null || !isOne(h.get("v")) || !signer.equals(h.get("signer")) || !isNonNeg(h.get("size")) || !isNonNeg(h.get("issued_at"))
            || !(h.get("root") instanceof String) || !(h.get("last_commit") instanceof String)) return false;
        return verifyBody(LOG_HEAD_DOMAIN, without(h, "sig"), signer, h.get("sig"));
    }

    /** Offline: this record is in the log the signed head commits to, and the head is by the pinned signer. */
    public static boolean verifyRecordInclusion(Object record, Object proof, Object head, String signer) {
        try {
            if (!verifyLogHead(head, signer)) return false;
            String c = recordCommit(record);
            if (c == null) return false;
            return Ledger.verifyLedgerInclusion((String) map(head).get("root"), proof, c);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Outcome of {@link #verifyBatch}. */
    public static final class BatchVerdict {
        public final boolean ok;
        public final long next;
        public final String lastCommit;
        public final String reason;
        BatchVerdict(boolean ok, long next, String lastCommit, String reason) { this.ok = ok; this.next = next; this.lastCommit = lastCommit; this.reason = reason; }
        static BatchVerdict bad(String reason) { return new BatchVerdict(false, 0, null, reason); }
    }

    /**
     * Receiver side of the decision stream: contiguous sequence from the receiver's state ({@code stateNext}, {@code stateLastCommit}),
     * intact hash chain, and (when the batch reaches the head) the head's last commit and size match. Never throws.
     */
    public static BatchVerdict verifyBatch(Object batch, long stateNext, String stateLastCommit, String signer) {
        try {
            Map<String, Object> b = map(batch);
            if (b == null) return BatchVerdict.bad("malformed batch");
            Double from = IntentJs.num(b.get("from"));
            if (from == null || from.doubleValue() != (double) stateNext)
                return BatchVerdict.bad("gap or replay: batch starts at " + jsNum(b.get("from")) + ", expected " + stateNext);
            if (!verifyLogHead(b.get("head"), signer)) return BatchVerdict.bad("head not signed by the pinned log signer");
            Object recs = b.get("records");
            if (!(recs instanceof List)) return BatchVerdict.bad("malformed batch");
            String last = stateLastCommit;
            long n = stateNext;
            for (Object r : (List<?>) recs) {
                Map<String, Object> rm = map(r);
                if (rm == null) return BatchVerdict.bad("malformed batch");
                Double seq = IntentJs.num(rm.get("seq"));
                if (seq == null || seq.doubleValue() != (double) n || !Objects.equals(rm.get("prev"), last)) return BatchVerdict.bad("chain broken at seq " + jsNum(rm.get("seq")));
                String c = recordCommit(rm);
                if (c == null) return BatchVerdict.bad("malformed batch");
                last = c;
                n++;
            }
            Map<String, Object> head = map(b.get("head"));
            long size = IntentJs.lng(head.get("size"));
            if (n > size) return BatchVerdict.bad("batch is longer than the signed head");
            if (n == size && !Objects.equals(last, head.get("last_commit"))) return BatchVerdict.bad("batch end does not match the signed head");
            return new BatchVerdict(true, n, last, null);
        } catch (RuntimeException e) {
            return BatchVerdict.bad("malformed batch");
        }
    }

    // =====================================================================================================================
    // list receipts and cursors
    // =====================================================================================================================

    /** Digest of the returned object ids, in order; null outside the strict profile. */
    public static String objectsDigest(List<?> objects) {
        return digestOf(obj("d", "atlas-pca/list-objects/v1", "o", objects));
    }

    /**
     * A signed list receipt by {@code signer}. With {@code objects} (null = not given) the receipt must also commit to exactly those
     * ids (count and digest). Never throws.
     */
    public static boolean verifyListReceipt(Object receipt, String signer, List<?> objects) {
        try {
            Map<String, Object> r = map(receipt);
            if (r == null || signer == null || !isOne(r.get("v")) || !signer.equals(r.get("signer")) || !isStr(r.get("subject"), 512)
                || !isStr(r.get("resource_type"), 512) || !isNonNeg(r.get("count")) || !isNonNeg(r.get("issued_at"))) return false;
            if (!verifyBody(LIST_RECEIPT_DOMAIN, without(r, "sig"), signer, r.get("sig"))) return false;
            if (objects == null) return true;
            Double count = IntentJs.num(r.get("count"));
            return count.doubleValue() == (double) objects.size() && Objects.equals(objectsDigest(objects), r.get("objects_digest"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * What a cursor is bound to: {@code {subject, resourceType, filterId, policyDigest, relation?: {relation}, limit}}; changing any of
     * them between pages is refused. Null outside the strict profile.
     */
    public static String listBind(Map<String, Object> a) {
        if (a == null) return null;
        Map<String, Object> rel = map(a.get("relation"));
        Object relation = rel == null ? null : rel.get("relation");
        return digestOf(obj("s", a.get("subject"), "t", a.get("resourceType"), "f", a.get("filterId"), "p", a.get("policyDigest"), "r", relation, "l", a.get("limit")));
    }

    /** Outcome of {@link #verifyListCursor}. */
    public static final class CursorVerdict {
        public final boolean ok;
        public final String inner;
        public final long skip;
        /** malformed | signature | bind (when not ok). */
        public final String reason;
        CursorVerdict(boolean ok, String inner, long skip, String reason) { this.ok = ok; this.inner = inner; this.skip = skip; this.reason = reason; }
        static CursorVerdict bad(String reason) { return new CursorVerdict(false, null, 0, reason); }
    }

    /** Verify a page cursor: shape, signature by {@code signer}, and (when {@code bind} is given) that it was issued for exactly those inputs. Never throws. */
    public static CursorVerdict verifyListCursor(Object tok, String signer, Map<String, Object> bind) {
        try {
            if (!(tok instanceof String)) return CursorVerdict.bad("malformed");
            String[] parts = ((String) tok).split("\\.", -1);
            String p = parts[0];
            String s = parts.length > 1 ? parts[1] : null;
            Object parsed = null;
            try {
                byte[] raw = p.isEmpty() ? null : Pca.decodeB64uStrict(p, -1);
                parsed = raw == null ? null : Json.parseLenient(new String(raw, StandardCharsets.UTF_8));
            } catch (RuntimeException e) {
                return CursorVerdict.bad("malformed");
            }
            Map<String, Object> c = map(parsed);
            if (parts.length > 2 || c == null || s == null || s.isEmpty() || !isOne(c.get("v")) || !(c.get("bind") instanceof String)
                || !isNonNeg(c.get("skip")) || (c.containsKey("inner") && !(c.get("inner") instanceof String))) return CursorVerdict.bad("malformed");
            if (signer == null || !signer.equals(c.get("signer")) || !verifyBody(LIST_CURSOR_DOMAIN, c, signer, s)) return CursorVerdict.bad("signature");
            if (bind != null && !Objects.equals(c.get("bind"), listBind(bind))) return CursorVerdict.bad("bind");
            return new CursorVerdict(true, c.containsKey("inner") ? (String) c.get("inner") : null, IntentJs.lng(c.get("skip")), null);
        } catch (RuntimeException e) {
            return CursorVerdict.bad("malformed");
        }
    }

    // =====================================================================================================================
    // authority + grant management
    // =====================================================================================================================

    /** The comparable shape of a grant's authority: verbs, resource patterns, named numeric ceilings, optional expiry. */
    private static final class Auth {
        final List<Object> verbs;
        final List<Object> resources;
        /** Ceiling name to number; null = absent. */
        final Map<String, Object> limits;
        /** Epoch ms; null = never expires. */
        final Object expires;

        Auth(List<Object> verbs, List<Object> resources, Map<String, Object> limits, Object expires) {
            this.verbs = verbs; this.resources = resources; this.limits = limits; this.expires = expires;
        }

        /** The authority, or null when it is not well formed (the reference checkAuthority). */
        static Auth of(Object o) {
            Map<String, Object> a = map(o);
            if (a == null) return null;
            Object v = a.get("verbs");
            Object r = a.get("resources");
            if (!strList(v, 256, 128) || !strList(r, 1024, 512)) return null;
            Map<String, Object> limits = null;
            if (a.containsKey("limits")) {
                limits = map(a.get("limits"));
                if (limits == null) return null;
                for (Object x : limits.values()) {
                    Double d = IntentJs.num(x);
                    if (d == null || !IntentJs.isFinite(x) || d < 0) return null;
                }
            }
            Object exp = null;
            if (a.containsKey("expires_at")) {
                exp = a.get("expires_at");
                if (!isNonNeg(exp)) return null;
            }
            @SuppressWarnings("unchecked") List<Object> vl = (List<Object>) v;
            @SuppressWarnings("unchecked") List<Object> rl = (List<Object>) r;
            return new Auth(vl, rl, limits, exp);
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verbs", new ArrayList<>(verbs));
            m.put("resources", new ArrayList<>(resources));
            if (limits != null && !limits.isEmpty()) m.put("limits", limits);
            if (expires != null) m.put("expires_at", expires);
            return m;
        }
    }

    private static boolean resCovers(String p, String r) { return p.endsWith("*") ? r.startsWith(p.substring(0, p.length() - 1)) : p.equals(r); }

    private static boolean resSubset(List<Object> small, List<Object> big) {
        for (Object so : small) {
            String s = (String) so;
            boolean ok = false;
            for (Object bo : big) {
                String b = (String) bo;
                if (resCovers(b, s) && (!s.endsWith("*") || b.endsWith("*") || b.equals(s))) { ok = true; break; }
            }
            if (!ok) return false;
        }
        return true;
    }

    /** a <= b: everything a allows, b allows. */
    private static boolean le(Auth a, Auth b) {
        if (!b.verbs.containsAll(a.verbs) || !resSubset(a.resources, b.resources)) return false;
        if (a.limits != null) {
            for (Map.Entry<String, Object> en : a.limits.entrySet()) {
                Object bv = b.limits == null ? null : b.limits.get(en.getKey());
                if (bv != null && !(IntentJs.num(en.getValue()) <= IntentJs.num(bv))) return false;
            }
        }
        if (b.limits != null) for (String k : b.limits.keySet()) if (a.limits == null || a.limits.get(k) == null) return false;
        double ae = a.expires == null ? Double.POSITIVE_INFINITY : IntentJs.num(a.expires);
        double be = b.expires == null ? Double.POSITIVE_INFINITY : IntentJs.num(b.expires);
        return ae <= be;
    }

    private static String order(Auth o, Auth n) {
        boolean nle = le(n, o);
        boolean ole = le(o, n);
        return nle && ole ? "equal" : nle ? "narrower" : ole ? "wider" : "incomparable";
    }

    /** Order of the new authority against the old: narrower | equal | wider | incomparable (a malformed authority is incomparable). */
    public static String compareAuthority(Object oldA, Object newA) {
        try {
            Auth o = Auth.of(oldA);
            Auth n = Auth.of(newA);
            return o == null || n == null ? "incomparable" : order(o, n);
        } catch (RuntimeException e) {
            return "incomparable";
        }
    }

    /** Digest of an authority with its verbs and resources sorted; null when malformed. */
    public static String authorityDigest(Object authority) {
        try {
            Map<String, Object> a = map(authority);
            if (a == null || !(a.get("verbs") instanceof List) || !(a.get("resources") instanceof List)) return null;
            List<Object> verbs = new ArrayList<>((List<?>) a.get("verbs"));
            List<Object> resources = new ArrayList<>((List<?>) a.get("resources"));
            for (Object x : verbs) if (!(x instanceof String)) return null;
            for (Object x : resources) if (!(x instanceof String)) return null;
            Collections.sort(verbs, (x, y) -> ((String) x).compareTo((String) y));
            Collections.sort(resources, (x, y) -> ((String) x).compareTo((String) y));
            Map<String, Object> copy = new LinkedHashMap<>(a);
            copy.put("verbs", verbs);
            copy.put("resources", resources);
            return digestOf(obj("d", "atlas-pca/authority/v1", "a", copy));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept. */
    private static Auth mergeAuthority(Auth a, Auth d) {
        Map<String, Object> limits = new LinkedHashMap<>();
        if (a.limits != null) {
            for (Map.Entry<String, Object> en : a.limits.entrySet()) {
                Object dv = d.limits == null ? null : d.limits.get(en.getKey());
                limits.put(en.getKey(), dv != null && IntentJs.num(dv) > IntentJs.num(en.getValue()) ? dv : en.getValue());
            }
        }
        Object exp = a.expires;
        if (exp != null && d.expires != null && IntentJs.num(d.expires) > IntentJs.num(exp)) exp = d.expires;
        Set<Object> verbs = new LinkedHashSet<>(a.verbs);
        verbs.addAll(d.verbs);
        Set<Object> resources = new LinkedHashSet<>(a.resources);
        resources.addAll(d.resources);
        return new Auth(new ArrayList<>(verbs), new ArrayList<>(resources), limits.isEmpty() ? null : limits, exp);
    }

    /** Outcome of {@link #verifyAmendment}. */
    public static final class AmendVerdict {
        public final boolean ok;
        public final String code;
        public final boolean widens;
        /** The resulting authority (a parsed JSON object) when ok. */
        public final Map<String, Object> next;
        AmendVerdict(boolean ok, String code, boolean widens, Map<String, Object> next) { this.ok = ok; this.code = code; this.widens = widens; this.next = next; }
        static AmendVerdict fail(String code) { return new AmendVerdict(false, code, false, null); }
    }

    /**
     * Decide an amendment against the grant facts {@code {id, rev, principal, agent, status, authority}}. Check order: request shape,
     * authority shape, grant active, classification (a narrow that changes nothing or widens is not_narrower), signature
     * (signature_required, then bad_signature; widening needs the principal), then step-up for a widening.
     */
    public static AmendVerdict verifyAmendment(Object cur, Object req, boolean stepUpOk) {
        try {
            Map<String, Object> g = map(cur);
            Map<String, Object> r = map(req);
            Object action = r == null ? null : r.get("action");
            if (!("narrow".equals(action) || "merge".equals(action) || "replace".equals(action))) return AmendVerdict.fail("bad_request");
            Auth ra = Auth.of(r.get("authority"));
            Auth ca = g == null ? null : Auth.of(g.get("authority"));
            if (ra == null || ca == null) return AmendVerdict.fail("bad_request");
            if (!"active".equals(g.get("status"))) return AmendVerdict.fail("not_active");
            boolean merge = "merge".equals(action);
            Auth merged = merge ? mergeAuthority(ca, ra) : null;
            String ord = order(ca, merge ? merged : ra);
            boolean widens = ord.equals("wider") || ord.equals("incomparable");
            boolean narrow = "narrow".equals(action);
            if (!widens && narrow && ord.equals("equal")) return AmendVerdict.fail("not_narrower");
            if (widens && narrow) return AmendVerdict.fail("not_narrower");
            Object sig = r.get("sig");
            Object by = r.get("signed_by");
            if (!(sig instanceof String) || !("holder".equals(by) || "principal".equals(by))) return AmendVerdict.fail("signature_required");
            if (widens && !"principal".equals(by)) return AmendVerdict.fail("signature_required");
            Object signer = "principal".equals(by) ? g.get("principal") : g.get("agent");
            Map<String, Object> msg = obj("grant", g.get("id"), "rev", g.get("rev"), "action", action, "authority", authorityDigest(r.get("authority")));
            if (!(signer instanceof String) || !verifyBody(GRANT_AMEND_DOMAIN, msg, (String) signer, sig)) return AmendVerdict.fail("bad_signature");
            if (widens && !stepUpOk) return AmendVerdict.fail("step_up_required");
            return new AmendVerdict(true, null, widens, merge ? merged.toMap() : map(r.get("authority")));
        } catch (RuntimeException e) {
            return AmendVerdict.fail("bad_request");
        }
    }

    /** Outcome of {@link #verifyRevokeSignature}. */
    public static final class RevokeVerdict {
        public final boolean ok;
        public final String scope;
        public final String code;
        RevokeVerdict(boolean ok, String scope, String code) { this.ok = ok; this.scope = scope; this.code = code; }
    }

    /** Decide a revocation's authority: the principal's signature over {@code {grant: id, scope}} for {@code root = {id, principal}}. */
    public static RevokeVerdict verifyRevokeSignature(Object root, Object scope, Object sig) {
        try {
            Map<String, Object> g = map(root);
            if (!("grant".equals(scope) || "agent".equals(scope) || "subtree".equals(scope))) return new RevokeVerdict(false, null, "bad_request");
            Object principal = g == null ? null : g.get("principal");
            if (!(principal instanceof String) || !verifyBody(GRANT_REVOKE_DOMAIN, obj("grant", g.get("id"), "scope", scope), (String) principal, sig))
                return new RevokeVerdict(false, null, "bad_signature");
            return new RevokeVerdict(true, (String) scope, null);
        } catch (RuntimeException e) {
            return new RevokeVerdict(false, null, "bad_request");
        }
    }

    /** Outcome of {@link #verifyNeedApproval}. */
    public static final class NeedVerdict {
        public final boolean ok;
        public final String code;
        /** The merged authority (a parsed JSON object) when ok. */
        public final Map<String, Object> authority;
        NeedVerdict(boolean ok, String code, Map<String, Object> authority) { this.ok = ok; this.code = code; this.authority = authority; }
        static NeedVerdict fail(String code) { return new NeedVerdict(false, code, null); }
    }

    /**
     * Decide a needs approval: principal signature over {@code {need, grant, rev, approved}}, same count, each approved need names the
     * same verb and resource with amounts only LOWERED (and only when adjustable), then step-up. Yields the merged authority.
     * {@code needRequest} = {id, grant_id, needs, status}; {@code grant} = the grant facts.
     */
    public static NeedVerdict verifyNeedApproval(Object needRequest, Object grant, Object approved, Object sig, boolean stepUpOk) {
        try {
            Map<String, Object> nr = map(needRequest);
            Map<String, Object> g = map(grant);
            if (nr == null || g == null) return NeedVerdict.fail("bad_request");
            if (!"pending".equals(nr.get("status"))) return NeedVerdict.fail("conflict");
            Object principal = g.get("principal");
            Map<String, Object> msg = obj("need", nr.get("id"), "grant", nr.get("grant_id"), "rev", g.get("rev"), "approved", approved);
            if (!(principal instanceof String) || !verifyBody(NEED_APPROVE_DOMAIN, msg, (String) principal, sig)) return NeedVerdict.fail("bad_signature");
            Object needs = nr.get("needs");
            if (!(approved instanceof List) || !(needs instanceof List) || ((List<?>) approved).size() != ((List<?>) needs).size()) return NeedVerdict.fail("need_not_lowered_only");
            Auth ga = Auth.of(g.get("authority"));
            if (ga == null) return NeedVerdict.fail("bad_request");
            List<Object> dverbs = new ArrayList<>();
            List<Object> dres = new ArrayList<>();
            Map<String, Object> dlimits = new LinkedHashMap<>();
            for (int i = 0; i < ((List<?>) approved).size(); i++) {
                Map<String, Object> a = map(((List<?>) approved).get(i));
                Map<String, Object> want = map(((List<?>) needs).get(i));
                if (a == null || want == null || !(a.get("verb") instanceof String) || !(a.get("resource") instanceof String)
                    || !a.get("verb").equals(want.get("verb")) || !a.get("resource").equals(want.get("resource"))) return NeedVerdict.fail("need_not_lowered_only");
                Object al = a.get("limits");
                if (al != null) {
                    Map<String, Object> alm = map(al);
                    if (alm == null) return NeedVerdict.fail("need_not_lowered_only");
                    Map<String, Object> wlm = map(want.get("limits"));
                    for (Map.Entry<String, Object> en : alm.entrySet()) {
                        Object w = wlm == null ? null : wlm.get(en.getKey());
                        Double v = IntentJs.num(en.getValue());
                        Double wd = w == null ? null : IntentJs.num(w);
                        if (v == null || wd == null || v > wd) return NeedVerdict.fail("need_not_lowered_only");
                        if (v < wd && !truthy(want.get("adjustable"))) return NeedVerdict.fail("need_not_adjustable");
                    }
                    for (Map.Entry<String, Object> en : alm.entrySet()) {
                        double v = IntentJs.num(en.getValue());
                        double cur = dlimits.containsKey(en.getKey()) ? IntentJs.num(dlimits.get(en.getKey())) : 0.0;
                        if (v > cur) dlimits.put(en.getKey(), en.getValue());
                        else if (!dlimits.containsKey(en.getKey())) dlimits.put(en.getKey(), new Json.Num("0")); // omission is the lowest amount
                    }
                }
                dverbs.add(a.get("verb"));
                dres.add(a.get("resource"));
            }
            if (!stepUpOk) return NeedVerdict.fail("step_up_required");
            Auth delta = new Auth(dverbs, dres, dlimits.isEmpty() ? null : dlimits, null);
            return new NeedVerdict(true, null, mergeAuthority(ga, delta).toMap());
        } catch (RuntimeException e) {
            return NeedVerdict.fail("bad_request");
        }
    }
}
