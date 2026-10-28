package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Transparency-ledger verification (extension layer): RFC 6962 inclusion of ledger commits, RFC 9162 consistency,
 * guardian-signed tree heads, witness cosignatures, head-to-head consistency, checkpoint chains and legacy witnessed
 * heads. Inputs are parsed JSON values ({@link Json#parseLenient}); every verifier returns false on malformed input and
 * never throws. Every suite {@link Pq#supportedSuites} lists verifies; a pure-PQ or hybrid artifact only under the PQ key the
 * verifier pins for the identity it names ({@code pins}: Ed25519 identity to ML-DSA public key; null = absent, so cosigners fall back to the
 * policy's {@code pqPins}; an empty map is explicit and replaces them). A suite this build lacks is refused.
 */
public final class Ledger {
    private Ledger() {}

    public static final String STH_DOMAIN = "atlas-pca/sth/v1\0";
    public static final String STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\0";
    public static final String LEDGER_HEAD_DOMAIN = "atlas-pca/ledger-head/v1\0";
    /** The longest consistency path any tree of fewer than 2^53 leaves can need (2*53+1), plus one of slack as the reference. */
    static final int MAX_CONSISTENCY_PATH = 2 * 53 + 2;

    /** Root of the empty tree (RFC 9162 2.1.1: SHA-256 of the empty string), base64url. */
    public static final String EMPTY_TREE_ROOT = Pca.b64(Pca.sha(new byte[0]));

    // ---- shared helpers (also used by Optimistic) ----

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }

    static String str(Map<String, Object> m, String k) { Object v = m.get(k); return v instanceof String ? (String) v : null; }

    /** A JavaScript safe integer (integral, |n| &lt;= 2^53-1), else null. */
    static Double safeInt(Object v) { return IntentJs.isSafeInteger(v) ? IntentJs.num(v) : null; }

    /** The number's value, or 0 when it is not a number (the Go/Rust ports read a missing size as 0). */
    static double numOr0(Object v) { Double d = IntentJs.num(v); return d == null ? 0.0 : d; }

    /**
     * A signature of {@code m} (alg, pq_pk, sig, pq_sig) over domain || strict-canonical(bindSuite(base)) under the Ed25519
     * {@code identity}, suite-agile; a PQ half verifies only under {@code pins[identity]}.
     */
    static boolean signed(String identity, String domain, Map<String, Object> base, Map<String, Object> m, Map<String, Object> pins) {
        if (identity == null || !(m.get("sig") instanceof String)) return false;
        byte[] msg;
        try {
            Map<String, Object> bound = IntentJs.bindSuiteFields(base, m.get("alg"), m.containsKey("alg"), m.get("pq_pk"), m.containsKey("pq_pk"));
            msg = Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(bound));
        } catch (RuntimeException e) {
            return false;
        }
        return IntentJs.verifyPinnedSuite(m.get("alg"), m.containsKey("alg"), identity, m.get("pq_pk"), msg, m.get("sig"), m.get("pq_sig"), pins);
    }

    /** Copies the named members; null when one is absent (the reference throws on undefined). */
    static Map<String, Object> pick(Map<String, Object> m, String... keys) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : keys) {
            if (!m.containsKey(k)) return null;
            out.put(k, m.get(k));
        }
        return out;
    }

    /** JavaScript === on JSON values, through their strict canonical form (both must be canonicalizable). */
    static boolean same(Object a, Object b) {
        try {
            return java.util.Arrays.equals(Pca.canonBytes(a), Pca.canonBytes(b));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- inclusion / consistency ----

    /** A ledger commit (string leaf) against a root with an RFC 6962 inclusion proof. */
    public static boolean verifyLedgerInclusion(String root, Object proof, Object commit) {
        Map<String, Object> p = map(proof);
        return p != null && Pca.verifyInclusion(root, p, commit);
    }

    /**
     * RFC 9162 2.1.4.2 consistency verification. Sizes are JSON safe integers. Size 0 pins oldRoot to the empty-tree root
     * and requires an empty path. Never throws.
     */
    public static boolean verifyLedgerConsistency(Object oldRoot, Object newRoot, Object proof) {
        try {
            return consistency(oldRoot, newRoot, proof);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean consistency(Object oldRoot, Object newRoot, Object proof) {
        Map<String, Object> p = map(proof);
        if (!(oldRoot instanceof String) || !(newRoot instanceof String) || p == null) return false;
        String or = (String) oldRoot, nr = (String) newRoot;
        Double ff = safeInt(p.get("oldSize")), sf = safeInt(p.get("newSize"));
        if (ff == null || sf == null || !(p.get("path") instanceof List)) return false;
        List<?> rawPath = (List<?>) p.get("path");
        if (ff < 0 || ff > sf || rawPath.size() > MAX_CONSISTENCY_PATH) return false;
        long first = (long) (double) ff, second = (long) (double) sf;
        if (first == 0) {
            if (!rawPath.isEmpty() || !or.equals(EMPTY_TREE_ROOT)) return false;
            if (second == 0) return nr.equals(EMPTY_TREE_ROOT);
            return true; // vacuous for a non-empty new tree
        }
        if (first == second) return rawPath.isEmpty() && or.equals(nr);
        List<byte[]> path = new ArrayList<>();
        if ((first & (first - 1)) == 0) {
            byte[] h = Pca.decodeB64uStrict(or, -1);
            if (h == null) return false;
            path.add(h);
        }
        for (Object e : rawPath) {
            byte[] h = Pca.decodeB64uStrict(e, -1);
            if (h == null) return false;
            path.add(h);
        }
        if (path.isEmpty()) return false;
        long fn = first - 1, sn = second - 1;
        while ((fn & 1) == 1) { fn >>= 1; sn >>= 1; }
        byte[] fr = path.get(0), sr = path.get(0);
        for (int i = 1; i < path.size(); i++) {
            byte[] c = path.get(i);
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn) {
                fr = Pca.nodeHash(c, fr);
                sr = Pca.nodeHash(c, sr);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            } else {
                sr = Pca.nodeHash(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && Pca.b64(fr).equals(or) && Pca.b64(sr).equals(nr);
    }

    // ---- legacy witnessed heads ----

    /** Verifies a legacy witnessed head {principal,size,root,witness,sig} against the witness key. */
    public static boolean verifyWitnessedHead(Object wh, String witnessPublic) { return verifyWitnessedHead(wh, witnessPublic, null); }

    public static boolean verifyWitnessedHead(Object wh, String witnessPublic, Map<String, Object> pins) {
        Map<String, Object> m = map(wh);
        if (m == null || witnessPublic == null) return false;
        if (!witnessPublic.equals(m.get("witness"))) return false;
        Map<String, Object> body = pick(m, "principal", "size", "root");
        return body != null && signed(witnessPublic, LEDGER_HEAD_DOMAIN, body, m, pins);
    }

    /** True when a and b are both validly witnessed for the same principal and size but carry different roots (a split view). */
    public static boolean detectEquivocation(Object a, Object b, String witnessPublic) { return detectEquivocation(a, b, witnessPublic, null); }

    public static boolean detectEquivocation(Object a, Object b, String witnessPublic, Map<String, Object> pins) {
        Map<String, Object> am = map(a), bm = map(b);
        if (am == null || bm == null || !verifyWitnessedHead(a, witnessPublic, pins) || !verifyWitnessedHead(b, witnessPublic, pins)) return false;
        String ar = str(am, "root"), br = str(bm, "root");
        boolean rootsDiffer = !(ar == null ? "" : ar).equals(br == null ? "" : br);
        return same(am.get("principal"), bm.get("principal")) && numOr0(am.get("size")) == numOr0(bm.get("size")) && rootsDiffer;
    }

    // ---- tree heads and witnesses ----

    /** One cosignature of a tree head under a trusted witness key, bound to {instance_id, principal, size, root, prev_root, guardian_epoch}. */
    public static boolean verifyWitnessCosignature(Object sth, Object cosig, String witnessPublic) { return verifyWitnessCosignature(sth, cosig, witnessPublic, null); }

    public static boolean verifyWitnessCosignature(Object sth, Object cosig, String witnessPublic, Map<String, Object> pins) {
        Map<String, Object> sm = map(sth), cm = map(cosig);
        if (sm == null || cm == null || witnessPublic == null) return false;
        if (!witnessPublic.equals(cm.get("key"))) return false;
        Map<String, Object> body = pick(sm, "instance_id", "principal", "size", "root", "prev_root");
        if (body == null) return false;
        Object e = sm.get("guardian_epoch");
        body.put("guardian_epoch", e != null ? e : (Object) Long.valueOf(0L)); // absent or null = epoch 0
        return signed(witnessPublic, STH_WITNESS_DOMAIN, body, cm, pins);
    }

    /**
     * The k-of-n check: at least policy.threshold DISTINCT trusted witnesses (policy witnessKeys) carry a valid cosignature
     * over this exact head. Unknown, duplicate and mis-bound cosignatures do not count; threshold 0 is vacuously met; a
     * non-integer or negative threshold fails.
     */
    public static boolean verifyWitnessCosignatures(Object sth, Map<String, Object> policy) { return verifyWitnessCosignatures(sth, policy, null); }

    /** {@code pins} null (absent) falls back to the policy's own {@code pqPins}; an empty map pins nothing. */
    public static boolean verifyWitnessCosignatures(Object sth, Map<String, Object> policy, Map<String, Object> pins) {
        Map<String, Object> sm = map(sth);
        if (sm == null || policy == null) return false;
        if (pins == null) pins = map(policy.get("pqPins"));
        Double tf = IntentJs.num(policy.get("threshold"));
        if (tf == null || tf.isNaN() || tf != (tf < 0 ? Math.ceil(tf) : Math.floor(tf)) || tf < 0) return false;
        if (tf == 0) return true;
        Set<String> trusted = new HashSet<>();
        if (policy.get("witnessKeys") instanceof List) {
            for (Object k : (List<?>) policy.get("witnessKeys")) if (k instanceof String) trusted.add((String) k);
        }
        if (trusted.isEmpty() || !(sm.get("witnesses") instanceof List)) return false;
        Set<String> counted = new HashSet<>();
        for (Object w : (List<?>) sm.get("witnesses")) {
            Map<String, Object> wm = map(w);
            if (wm == null) continue;
            String key = str(wm, "key");
            if (key == null || str(wm, "sig") == null || !trusted.contains(key) || counted.contains(key)) continue;
            if (!verifyWitnessCosignature(sth, w, key, pins)) continue;
            counted.add(key);
            if (counted.size() >= tf) return true;
        }
        return counted.size() >= tf;
    }

    /**
     * A guardian-signed tree head against the pinned guardian key: the head names that guardian, its size is a non-negative
     * safe integer, the signature covers {instance_id, principal, size, root, prev_root, timestamp}, and, when policy is
     * non-null, enough trusted witnesses cosigned it.
     */
    public static boolean verifyTreeHead(Object sth, String guardianPublic, Map<String, Object> policy) { return verifyTreeHead(sth, guardianPublic, policy, null); }

    public static boolean verifyTreeHead(Object sth, String guardianPublic, Map<String, Object> policy, Map<String, Object> pins) {
        Map<String, Object> m = map(sth);
        if (m == null || guardianPublic == null) return false;
        if (!guardianPublic.equals(m.get("guardian"))) return false;
        Double size = safeInt(m.get("size"));
        if (size == null || size < 0) return false;
        Map<String, Object> body = pick(m, "instance_id", "principal", "size", "root", "prev_root", "timestamp");
        if (body == null || !signed(guardianPublic, STH_DOMAIN, body, m, pins)) return false;
        return policy == null || verifyWitnessCosignatures(sth, policy, pins);
    }

    /**
     * Both heads are genuine for the pinned guardian, belong to the same instance and log, the proof connects exactly their
     * sizes, the signed prev_root equals older.root when the heads are adjacent, and the RFC 9162 path verifies.
     */
    public static boolean verifyHeadConsistency(Object older, Object newer, Object proof, String guardianPublic, Map<String, Object> policy) { return verifyHeadConsistency(older, newer, proof, guardianPublic, policy, null); }

    public static boolean verifyHeadConsistency(Object older, Object newer, Object proof, String guardianPublic, Map<String, Object> policy, Map<String, Object> pins) {
        if (!verifyTreeHead(older, guardianPublic, policy, pins) || !verifyTreeHead(newer, guardianPublic, policy, pins)) return false;
        Map<String, Object> om = map(older), nm = map(newer), pm = map(proof);
        if (om == null || nm == null || pm == null || !same(om.get("instance_id"), nm.get("instance_id")) || !same(om.get("principal"), nm.get("principal"))) return false;
        double os = numOr0(om.get("size")), ns = numOr0(nm.get("size"));
        Double ps = IntentJs.num(pm.get("oldSize")), pn = IntentJs.num(pm.get("newSize"));
        if (ps == null || pn == null || ps != os || pn != ns) return false;
        if (ns == os + 1 && !same(nm.get("prev_root"), om.get("root"))) return false;
        return verifyLedgerConsistency(om.get("root"), nm.get("root"), proof);
    }

    // ---- checkpoint chains ----

    /** Result of {@link #verifyCheckpointChain}: ok, or {@code at} = index of the first checkpoint that fails. */
    public static final class CheckpointVerdict {
        public final boolean ok;
        public final int at;
        CheckpointVerdict(boolean ok, int at) { this.ok = ok; this.at = at; }
        @Override public String toString() { return "CheckpointVerdict{ok=" + ok + ", at=" + at + "}"; }
    }

    /**
     * Pinned checkpoints end to end: every head is genuine (and witnessed when policy is non-null), the first needs no proof,
     * every later one carries a consistency proof from the checkpoint before. An empty or non-array chain fails at 0.
     */
    public static CheckpointVerdict verifyCheckpointChain(Object chain, String guardianPublic, Map<String, Object> policy) { return verifyCheckpointChain(chain, guardianPublic, policy, null); }

    public static CheckpointVerdict verifyCheckpointChain(Object chain, String guardianPublic, Map<String, Object> policy, Map<String, Object> pins) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return new CheckpointVerdict(false, 0);
        List<?> cs = (List<?>) chain;
        Object prev = null;
        for (int i = 0; i < cs.size(); i++) {
            Map<String, Object> cm = map(cs.get(i));
            if (cm == null || !verifyTreeHead(cm.get("sth"), guardianPublic, policy, pins)) return new CheckpointVerdict(false, i);
            if (i > 0) {
                Object pr = cm.get("proof");
                if (pr == null || Boolean.FALSE.equals(pr)) return new CheckpointVerdict(false, i);
                if (!verifyHeadConsistency(prev, cm.get("sth"), pr, guardianPublic, policy, pins)) return new CheckpointVerdict(false, i);
            }
            prev = cm.get("sth");
        }
        return new CheckpointVerdict(true, 0);
    }
}
