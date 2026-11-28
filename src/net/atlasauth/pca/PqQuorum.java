package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Post-quantum t-of-n authorization by composition: a quorum certificate. A quorum set is n registered post-quantum signers (ML-DSA,
 * SLH-DSA, FN-DSA, or Ed25519 hybrids of them), a threshold {@code t} and a diversity commitment {@code minHashBased} (the least
 * number of hash-based, i.e. SLH-DSA, signers a valid quorum must contain). A proof is at least {@code t} INDEPENDENT per-signer
 * signatures over one domain-separated message that binds the set, an epoch and an action digest. Rotation: the old quorum signs the
 * next set at the next epoch, and {@link #verifyRotationChain} enforces linkage and monotone epochs. No new cryptography: counting,
 * binding and de-duplication on top of the signature suites.
 *
 * <p>Values are decoded JSON (the wire members {@code i}, {@code sig}, {@code pq_sig}, {@code set_id}, {@code sigs},
 * {@code from_set_id}, {@code from_epoch}, {@code to_set}, {@code to_epoch}, {@code proof} are kept verbatim). The verifiers never
 * throw and return {@code {ok:false, reason}} with the reference's reason; the signers and the digest helpers throw.
 */
public final class PqQuorum {
    private PqQuorum() {}

    /** The most signers a quorum set may register. */
    public static final int PQ_QUORUM_MAX_SIGNERS = 256;
    /** The most rotation certificates a chain may carry. */
    public static final int PQ_QUORUM_MAX_CHAIN = 1024;

    private static final String SET_DOMAIN = "atlas-pca/pq-quorum-set/v1";
    private static final byte[] MSG_DOMAIN = "atlas-pca/pq-quorum-msg/v1\0".getBytes(StandardCharsets.UTF_8);
    private static final String ROTATION_KIND = "pq-quorum-rotation";
    private static final Object NONE = new Object();

    private static Map<String, Object> rec(Object x) { return StoreJs.map(x); }

    private static Map<String, Object> no(String reason) { return Issue.obj("ok", false, "reason", reason); }

    private static byte[] sha384(byte[] b) { return Pca.hashWithSuite(b, "sha384"); }

    // ---- the set -----------------------------------------------------------------------------------------------------------

    /** One registered signer in normal form. */
    private static final class Entry {
        final Pq.Suite suite;
        final String ed; // null unless the suite is a hybrid
        final String pq;
        Entry(Pq.Suite suite, String ed, String pq) {
            this.suite = suite;
            this.ed = ed;
            this.pq = pq;
        }
        String key() { return suite.alg + "|" + (ed == null ? "" : ed) + "|" + pq; }
        boolean hashBased() { return suite.pq == Pq.Prim.SLH_DSA_SHA2_128F || suite.pq == Pq.Prim.SLH_DSA_SHA2_256S; }
        Map<String, Object> json() { return ed == null ? Issue.obj("alg", suite.alg, "pq", pq) : Issue.obj("alg", suite.alg, "ed", ed, "pq", pq); }
    }

    /** A set that passed every rule, with its canonical signer order. */
    private static final class Loaded {
        final long t, k;
        final List<Entry> signers;
        final String id;
        final Map<String, Object> set;
        Loaded(long t, long k, List<Entry> signers) {
            this.t = t;
            this.k = k;
            this.signers = signers;
            List<Object> wire = new ArrayList<>(), body = new ArrayList<>();
            for (Entry e : signers) {
                wire.add(e.json());
                body.add(Issue.obj("a", e.suite.alg, "e", e.ed, "p", e.pq));
            }
            this.id = Pca.hashCanonical(Issue.obj("d", SET_DOMAIN, "t", IntentJs.ofLong(t), "k", IntentJs.ofLong(k), "s", body), "sha384");
            this.set = Issue.obj("t", IntentJs.ofLong(t), "minHashBased", IntentJs.ofLong(k), "signers", wire, "id", id);
        }
    }

    /** The post-quantum suite an entry names: an absent alg is ed25519, which (like the LESS suites) cannot be a quorum signer. */
    private static Pq.Suite pqSuite(Object alg, boolean algPresent) {
        Pq.Suite s = algPresent ? Pq.suiteShape(alg) : null;
        return s == null || s.pq == null || s.pq == Pq.Prim.LESS_CAT1 ? null : s;
    }

    private static String keySlot(Pq.Prim p) {
        switch (p) {
            case ML_DSA_65: return "mlDsaPub";
            case ML_DSA_87: return "mlDsa87Pub";
            case SLH_DSA_SHA2_128F: return "slhDsaPub";
            case FN_DSA_512: return "fnDsa512Pub";
            case FN_DSA_1024: return "fnDsa1024Pub";
            default: return "slhDsa256sPub";
        }
    }

    /** The normal form of one entry, or null: keys must be canonical base64url of the suite's exact lengths; {@code ed} only on a hybrid. */
    private static Entry normalize(Pq.Suite s, Object ed, boolean edPresent, Object pq) {
        if (s == null || Pca.decodeB64uStrict(pq, s.pq.pkBytes) == null) return null;
        if (s.hasEd25519) return Pca.decodeB64uStrict(ed, 32) == null ? null : new Entry(s, (String) ed, (String) pq);
        return edPresent ? null : new Entry(s, null, (String) pq);
    }

    /** Sizes, threshold and diversity bounds, the canonical order, and distinctness of every key component across the whole set. */
    private static Loaded finish(List<Entry> entries, Object t, Object k) {
        int n = entries.size();
        if (n < 1 || n > PQ_QUORUM_MAX_SIGNERS) return null;
        if (!IntentJs.isInt(t) || IntentJs.lng(t) < 1 || IntentJs.lng(t) > n) return null;
        if (!IntentJs.isInt(k) || IntentJs.lng(k) < 0 || IntentJs.lng(k) > IntentJs.lng(t)) return null;
        List<Entry> sorted = new ArrayList<>(entries);
        sorted.sort((a, b) -> a.key().compareTo(b.key()));
        Set<String> seen = new HashSet<>();
        long hashBased = 0;
        for (Entry e : sorted) {
            if (e.ed != null && !seen.add(e.ed)) return null;
            if (!seen.add(e.pq)) return null;
            if (e.hashBased()) hashBased++;
        }
        return hashBased < IntentJs.lng(k) ? null : new Loaded(IntentJs.lng(t), IntentJs.lng(k), sorted);
    }

    private static Loaded build(Object signers, Object t, Object k) {
        try {
            if (!(signers instanceof List)) return null;
            List<Entry> entries = new ArrayList<>();
            for (Object so : (List<?>) signers) {
                Map<String, Object> s = rec(so), keys = s == null ? null : rec(s.get("keys"));
                if (keys == null) return null;
                Pq.Suite suite = pqSuite(s.get("alg"), s.containsKey("alg"));
                Entry e = suite == null ? null : normalize(suite, keys.get("edPub"), keys.containsKey("edPub"), keys.get(keySlot(suite.pq)));
                if (e == null) return null;
                entries.add(e);
            }
            return finish(entries, t, k);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Loaded load(Object x) {
        try {
            Map<String, Object> m = rec(x);
            if (m == null || !(m.get("signers") instanceof List) || !(m.get("id") instanceof String)) return null;
            List<Entry> entries = new ArrayList<>();
            for (Object so : (List<?>) m.get("signers")) {
                Map<String, Object> s = rec(so);
                Entry e = s == null ? null : normalize(pqSuite(s.get("alg"), s.containsKey("alg")), s.get("ed"), s.containsKey("ed"), s.get("pq"));
                if (e == null) return null;
                entries.add(e);
            }
            Loaded r = finish(entries, m.get("t"), m.get("minHashBased"));
            if (r == null) return null;
            // the wire order must already be the canonical order, so the index a share names is unambiguous
            for (int i = 0; i < entries.size(); i++) if (!r.signers.get(i).key().equals(entries.get(i).key())) return null;
            return r.id.equals(m.get("id")) ? r : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Map<String, Object> setResult(Loaded l) { return l == null ? no("bad-set") : Issue.obj("ok", true, "set", l.set); }

    /** {@link #buildQuorumSet(Object, Object, Object)} with no diversity commitment. */
    public static Map<String, Object> buildQuorumSet(Object signers, Object t) { return setResult(build(signers, t, IntentJs.ofLong(0))); }

    /**
     * Build a quorum set from {@code [{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?,
     * fnDsa1024Pub?}}]} (base64url public keys), a threshold and the least number of hash-based signers. Returns {@code {ok:true, set:
     * {t, minHashBased, signers: [{alg, ed?, pq}], id}}} or {@code {ok:false, reason:"bad-set"}}: unknown or non-post-quantum suites,
     * keys of the wrong length or encoding, a key component used twice anywhere in the set, {@code t} outside 1..n, {@code minHashBased}
     * outside 0..t or above the number of hash-based signers, and more than {@link #PQ_QUORUM_MAX_SIGNERS} signers are refused. The id
     * commits to t, the diversity commitment and the signers in canonical order.
     */
    public static Map<String, Object> buildQuorumSet(Object signers, Object t, Object minHashBased) { return setResult(build(signers, t, minHashBased)); }

    /** Validate an untrusted quorum set: every rule of {@link #buildQuorumSet}, the canonical signer order, and the id RE-DERIVED from the content. */
    public static Map<String, Object> loadQuorumSet(Object x) { return setResult(load(x)); }

    // ---- messages, shares and proofs ------------------------------------------------------------------------------------------

    /**
     * The exact bytes each quorum signer signs: a domain prefix, then SHA-384 of the canonical {@code {set_id, epoch, action}}. The
     * arguments are any JSON values (the verifier is what requires a string id, a natural epoch and a string digest); a value with no
     * canonical form throws.
     */
    public static byte[] quorumMessage(Object setId, Object epoch, Object actionDigest) {
        return Pca.concat(MSG_DOMAIN, sha384(Pca.canonBytes(Issue.obj("set_id", setId, "epoch", epoch, "action", actionDigest))));
    }

    /** The action digest of an opaque message, for approving bytes that are not already a digest: bytes, or text as UTF-8. Anything else throws. */
    public static String quorumActionDigest(Object message) {
        if (message instanceof byte[]) return Pca.b64(sha384((byte[]) message));
        if (message instanceof String) return Pca.b64(sha384(Json.utf8((String) message)));
        throw new IllegalArgumentException("quorumActionDigest: bytes expected");
    }

    /** JavaScript {@code list[index]}: the element, or NONE when the index does not name one. */
    private static Object at(List<?> list, Object index) {
        String k = IntentRevocation.jsText(index, true);
        return k.matches("0|[1-9][0-9]{0,8}") && Integer.parseInt(k) < list.size() ? list.get(Integer.parseInt(k)) : NONE;
    }

    /**
     * One signer's share for {@code (epoch, actionDigest)} under {@code set}: {@code {i, sig, pq_sig?}}, signed with the key material
     * the signer's suite needs. Throws on an index that names no signer and on missing key material; it does not validate the set
     * (the verifier does).
     */
    public static Map<String, Object> signQuorumShare(Object set, Object index, Object epoch, Object actionDigest, Pq.SuiteSecretKeys keys) {
        Map<String, Object> s = rec(set);
        if (s == null || !(s.get("signers") instanceof List) || !s.containsKey("id")) throw new IllegalArgumentException("signQuorumShare: not a quorum set");
        Object entry = at((List<?>) s.get("signers"), index);
        if (entry == NONE || entry == null) throw new IllegalArgumentException("signQuorumShare: no such signer index");
        Map<String, Object> e = rec(entry);
        // as in the reference, an entry with no alg member signs under the ed25519 default; an alg that is present but null is unknown
        boolean hasAlg = e != null && e.containsKey("alg");
        if (hasAlg && e.get("alg") == null) throw new IllegalArgumentException("signWithSuite: unknown signature alg 'null'");
        Pq.SuiteSignatureParts p = Pq.signWithSuite(hasAlg ? e.get("alg") : null, keys, quorumMessage(s.get("id"), epoch, actionDigest));
        return p.pqSig == null ? Issue.obj("i", index, "sig", p.sig) : Issue.obj("i", index, "sig", p.sig, "pq_sig", p.pqSig);
    }

    private static List<Object> shareList(Object shares) {
        if (shares instanceof List) return new ArrayList<Object>((List<?>) shares);
        if (!(shares instanceof String)) throw new IllegalArgumentException("shares is not a list");
        List<Object> out = new ArrayList<>(); // the reference spreads a string into its code points
        ((String) shares).codePoints().forEach(cp -> out.add(new String(Character.toChars(cp))));
        return out;
    }

    /** Assemble shares into a proof {@code {set_id, sigs}}. Order is irrelevant; the shares are copied untouched and nothing is validated here. */
    public static Map<String, Object> assembleQuorumProof(Object set, Object shares) {
        if (set == null) throw new IllegalArgumentException("assembleQuorumProof: the set is required");
        Map<String, Object> s = rec(set), out = new LinkedHashMap<>();
        if (s != null && s.containsKey("id")) out.put("set_id", s.get("id"));
        out.put("sigs", shareList(shares));
        return out;
    }

    /**
     * Verify a t-of-n quorum proof for {@code {set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}}, in this order: the
     * set loads ({@code bad-set}); it is the pinned set ({@code set-mismatch}); the epoch is a natural and the digest a string
     * ({@code malformed}); the proof is {@code {set_id, sigs}} for this set ({@code malformed}, {@code set-mismatch}); it carries no
     * more shares than signers ({@code too-many-signatures}, before any signature work); then each share in order: its shape
     * ({@code malformed}), its index ({@code unknown-signer}), that index not seen before ({@code duplicate-signer}), its signature
     * under the registered key ({@code bad-signature}); then {@code below-threshold} and {@code diversity-unmet}, where the diversity
     * required is the larger of the set's commitment and {@code requireHashBased}. Returns {@code {ok:true, signers, count, hashBased}}
     * or {@code {ok:false, reason, detail?}} ({@code detail} is the signer index); never throws.
     */
    public static Map<String, Object> verifyQuorum(Object input) {
        try {
            Map<String, Object> in = rec(input);
            if (in == null) return no("malformed");
            Loaded set = load(in.get("set"));
            if (set == null) return no("bad-set");
            if (in.containsKey("expectedSetId") && !set.id.equals(in.get("expectedSetId"))) return no("set-mismatch");
            return verifyLoaded(set, in.get("epoch"), in.get("actionDigest"), in.get("proof"), in.get("requireHashBased"));
        } catch (RuntimeException e) {
            return no("malformed");
        }
    }

    private static Map<String, Object> verifyLoaded(Loaded set, Object epoch, Object actionDigest, Object proof, Object requireHashBased) {
        if (!IntentJs.isNonNeg(epoch) || !(actionDigest instanceof String)) return no("malformed");
        Map<String, Object> p = rec(proof);
        if (p == null || !(p.get("set_id") instanceof String) || !(p.get("sigs") instanceof List)) return no("malformed");
        if (!set.id.equals(p.get("set_id"))) return no("set-mismatch");
        List<?> sigs = (List<?>) p.get("sigs");
        int n = set.signers.size();
        if (sigs.size() > n) return no("too-many-signatures");
        byte[] msg = quorumMessage(set.id, epoch, actionDigest);
        Set<Long> seen = new TreeSet<>();
        long hashBased = 0;
        for (Object ro : sigs) {
            Map<String, Object> raw = rec(ro);
            if (raw == null || !(raw.get("sig") instanceof String)) return no("malformed");
            Object io = raw.get("i");
            if (!IntentJs.isNonNeg(io) || IntentJs.lng(io) >= n) return no("unknown-signer");
            long i = IntentJs.lng(io);
            if (!seen.add(i)) return Issue.obj("ok", false, "reason", "duplicate-signer", "detail", IntentJs.ofLong(i));
            Entry e = set.signers.get((int) i);
            // a hybrid carries pq_sig and nothing else does; the key each half verifies under is the REGISTERED one, never one from the proof
            boolean good = e.suite.needsPqSig == raw.containsKey("pq_sig")
                && Pq.verifyWithSuite(e.suite.alg, e.ed, Pq.resolvePqKey(e.ed == null ? "" : e.ed, null, null, null, e.pq), msg, raw.get("sig"), raw.get("pq_sig"));
            if (!good) return Issue.obj("ok", false, "reason", "bad-signature", "detail", IntentJs.ofLong(i));
            if (e.hashBased()) hashBased++;
        }
        if (seen.size() < set.t) return no("below-threshold");
        // the caller's floor can only raise the set's commitment; the reference reads it as a JavaScript number (null is 0)
        double k = Math.max((double) set.k, requireHashBased == null ? 0 : MeshFederation.jsNumber(requireHashBased));
        if (Double.isNaN(k) || k != Math.rint(k) || Math.abs(k) > 9007199254740991d || k < 0) return no("malformed");
        if (hashBased < k) return no("diversity-unmet");
        List<Object> signers = new ArrayList<>();
        for (long i : seen) signers.add(IntentJs.ofLong(i));
        return Issue.obj("ok", true, "signers", signers, "count", IntentJs.ofLong(seen.size()), "hashBased", IntentJs.ofLong(hashBased));
    }

    /**
     * Approve opaque message bytes: true exactly when {@link #verifyQuorum} accepts {@code quorumActionDigest(message)} at {@code epoch}.
     * {@code opts} (null for none) may carry {@code expectedSetId} and {@code requireHashBased}; as in the reference its members are
     * laid over the verifier input, so {@code set}, {@code proof}, {@code epoch} and {@code actionDigest} in it take precedence. A
     * null message is refused.
     */
    public static boolean verifyQuorumApproval(Object set, Object proof, byte[] message, Object epoch, Map<String, Object> opts) {
        try {
            if (message == null) return false;
            Map<String, Object> in = Issue.obj("set", set, "proof", proof, "epoch", epoch, "actionDigest", quorumActionDigest(message));
            if (opts != null) in.putAll(opts); // the reference spreads the options over the input, so they may also replace set / proof / epoch / actionDigest
            return Boolean.TRUE.equals(verifyQuorum(in).get("ok"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- rotation ---------------------------------------------------------------------------------------------------------------

    /** The action digest an old quorum signs to rotate to the set {@code toSetId} at {@code toEpoch}. Throws on a value with no canonical form. */
    public static String rotationActionDigest(Object toSetId, Object toEpoch) {
        return Pca.hashCanonical(Issue.obj("kind", ROTATION_KIND, "to_set_id", toSetId, "to_epoch", toEpoch), "sha384");
    }

    /** JavaScript {@code x + 1}: a number is incremented, anything else is joined with the text "1" (the reference does arithmetic only). */
    private static Object plusOne(Object x) {
        Double d = IntentJs.num(x);
        if (d != null) return StoreJs.num(d + 1);
        if (x == null) return IntentJs.ofLong(1);
        if (x instanceof Boolean) return IntentJs.ofLong((Boolean) x ? 2 : 1);
        return IntentRevocation.jsText(x, true) + "1";
    }

    private static Object idOf(Object set, String what) {
        Map<String, Object> m = rec(set);
        if (m == null || !m.containsKey("id")) throw new IllegalArgumentException(what + ": not a quorum set");
        return m.get("id");
    }

    /**
     * Assemble a rotation certificate from the old quorum's shares: {@code {from_set_id, from_epoch, to_set, to_epoch, proof}} with
     * {@code to_epoch = from_epoch + 1}. Nothing is validated here; {@link #verifyRotationChain} decides.
     */
    public static Map<String, Object> buildRotationCert(Object from, Object fromEpoch, Object to, Object shares) {
        if (from == null) throw new IllegalArgumentException("buildRotationCert: the old set is required");
        Map<String, Object> f = rec(from), out = new LinkedHashMap<>();
        if (f != null && f.containsKey("id")) out.put("from_set_id", f.get("id"));
        out.put("from_epoch", fromEpoch);
        out.put("to_set", to);
        out.put("to_epoch", plusOne(fromEpoch));
        out.put("proof", assembleQuorumProof(from, shares));
        return out;
    }

    /** One old-quorum signer's share authorizing the rotation {@code from -> to} at {@code fromEpoch}. */
    public static Map<String, Object> signRotationShare(Object from, Object index, Object fromEpoch, Object to, Pq.SuiteSecretKeys keys) {
        return signQuorumShare(from, index, fromEpoch, rotationActionDigest(idOf(to, "signRotationShare"), plusOne(fromEpoch)), keys);
    }

    private static Map<String, Object> chainFail(String reason, long at) { return Issue.obj("ok", false, "reason", reason, "at", IntentJs.ofLong(at)); }

    /**
     * Verify a rotation chain from a trusted genesis set and epoch to the current one. Per link, in order: its shape
     * ({@code malformed}); it names the current set ({@code chain-broken}); it goes from the current epoch to the next
     * ({@code non-monotone-epoch}); the successor loads and is a different set ({@code bad-rotation}); the CURRENT quorum authorized
     * exactly that successor at that epoch (the quorum verdict's reason). A bad genesis is {@code bad-set}, a chain that is not a list
     * {@code malformed}, more than {@link #PQ_QUORUM_MAX_CHAIN} links {@code chain-too-long}, all at -1. Returns {@code {ok:true, set,
     * epoch, length}} or {@code {ok:false, reason, at}}; never throws.
     */
    public static Map<String, Object> verifyRotationChain(Object genesisSet, Object genesisEpoch, Object chain) {
        try {
            Loaded cur = load(genesisSet);
            if (cur == null || !IntentJs.isNonNeg(genesisEpoch)) return chainFail("bad-set", -1);
            if (!(chain instanceof List)) return chainFail("malformed", -1);
            List<?> links = (List<?>) chain;
            if (links.size() > PQ_QUORUM_MAX_CHAIN) return chainFail("chain-too-long", -1);
            long epoch = IntentJs.lng(genesisEpoch);
            for (int n = 0; n < links.size(); n++) {
                Map<String, Object> c = rec(links.get(n));
                if (c == null || !(c.get("from_set_id") instanceof String) || !IntentJs.isNonNeg(c.get("from_epoch")) || !IntentJs.isNonNeg(c.get("to_epoch"))) return chainFail("malformed", n);
                if (!cur.id.equals(c.get("from_set_id"))) return chainFail("chain-broken", n);
                if (IntentJs.lng(c.get("from_epoch")) != epoch || IntentJs.lng(c.get("to_epoch")) != epoch + 1) return chainFail("non-monotone-epoch", n);
                Loaded next = load(c.get("to_set"));
                if (next == null || next.id.equals(cur.id)) return chainFail("bad-rotation", n);
                Map<String, Object> v = verifyLoaded(cur, IntentJs.ofLong(epoch), rotationActionDigest(next.id, c.get("to_epoch")), c.get("proof"), null);
                if (!Boolean.TRUE.equals(v.get("ok"))) return chainFail((String) v.get("reason"), n);
                cur = next;
                epoch = epoch + 1;
            }
            return Issue.obj("ok", true, "set", cur.set, "epoch", IntentJs.ofLong(epoch), "length", IntentJs.ofLong(links.size()));
        } catch (RuntimeException e) {
            return chainFail("malformed", -1);
        }
    }

    /** JavaScript {@code a.k === b.k} over decoded JSON members: absent equals absent, values by type and value, containers never. */
    private static boolean strictEq(Map<String, Object> a, Map<String, Object> b, String k) {
        if (!a.containsKey(k) || !b.containsKey(k)) return !a.containsKey(k) && !b.containsKey(k);
        Object x = a.get(k), y = b.get(k);
        if (x == null || y == null) return x == y;
        if (x instanceof String || x instanceof Boolean) return x.equals(y);
        Double dx = IntentJs.num(x), dy = IntentJs.num(y);
        return dx != null && dy != null && dx.doubleValue() == dy.doubleValue();
    }

    /**
     * Two rotation certificates that rotate the SAME set at the SAME epoch to DIFFERENT successors: a fork of the signer set. A purely
     * structural comparison (it verifies neither certificate); for monitors and transparency logs.
     */
    public static boolean isRotationFork(Object a, Object b) {
        Map<String, Object> x = rec(a), y = rec(b);
        Map<String, Object> xt = x == null ? null : rec(x.get("to_set")), yt = y == null ? null : rec(y.get("to_set"));
        if (xt == null || yt == null) return false;
        return strictEq(x, y, "from_set_id") && strictEq(x, y, "from_epoch") && xt.get("id") instanceof String && yt.get("id") instanceof String
            && !xt.get("id").equals(yt.get("id"));
    }

    // ---- size accounting ------------------------------------------------------------------------------------------------------------

    private static long shareBytes(Object entry) {
        Map<String, Object> e = rec(entry);
        Pq.Suite s = e == null ? null : Pq.suiteShape(e.get("alg"));
        if (s == null) throw new IllegalArgumentException("quorumProofSize: unknown suite");
        return s.needsPqSig ? Pq.ED25519_SIGNATURE_BYTES + s.pq.sigBytes : s.sigBytes;
    }

    /** JavaScript's relative slice bound over an array of {@code len} elements. */
    private static int bound(double d, int len) {
        if (Double.isNaN(d)) return 0;
        d = d < 0 ? Math.ceil(d) : Math.floor(d);
        return (int) (d < 0 ? Math.max(len + d, 0) : Math.min(d, len));
    }

    private static Map<String, Object> proofSize(Object set, Object indices, boolean chosen) {
        Map<String, Object> s = rec(set);
        if (s == null || !(s.get("signers") instanceof List)) throw new IllegalArgumentException("quorumProofSize: not a quorum set");
        List<?> signers = (List<?>) s.get("signers");
        List<Long> sizes = new ArrayList<>();
        for (Object e : signers) sizes.add(shareBytes(e));
        sizes.sort(null);
        int len = sizes.size();
        boolean hasT = s.containsKey("t");
        double t = hasT ? MeshFederation.jsNumber(s.get("t")) : Double.NaN;
        long min = 0, max = 0;
        for (int i = 0, end = hasT ? bound(t, len) : len; i < end; i++) min += sizes.get(i);
        for (int i = hasT ? bound(len - t, len) : 0; i < len; i++) max += sizes.get(i);
        Map<String, Object> out = Issue.obj("minBytes", IntentJs.ofLong(min), "maxBytes", IntentJs.ofLong(max));
        if (hasT) out.put("t", s.get("t"));
        out.put("compact", false);
        if (chosen) {
            if (!(indices instanceof List)) throw new IllegalArgumentException("quorumProofSize: indices is not a list");
            long sum = 0;
            for (Object i : (List<?>) indices) {
                Object e = at(signers, i);
                if (e != NONE) sum += shareBytes(e);
            }
            out.put("chosenBytes", IntentJs.ofLong(sum));
        }
        return out;
    }

    /**
     * What a quorum proof costs in signature bytes: {@code {minBytes, maxBytes, t, compact:false}} for the t smallest and the t largest
     * signers. It is t independent signatures, never one compact threshold signature. Throws on a value that is not a set of known suites.
     */
    public static Map<String, Object> quorumProofSize(Object set) { return proofSize(set, null, false); }

    /** {@link #quorumProofSize(Object)} plus {@code chosenBytes} for the given signer indices (an index that names no signer counts 0). */
    public static Map<String, Object> quorumProofSize(Object set, Object indices) { return proofSize(set, indices, true); }
}
