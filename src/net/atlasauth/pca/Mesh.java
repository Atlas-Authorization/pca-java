package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cross-domain mesh proofs (the agent mesh, mesh.ts {@code verifyMeshProof}). A MeshProof carries a capability chain, one
 * witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action.
 * {@link #verifyMeshProof} checks all of it offline and returns the reference's reason and failing hop, including RFC 9162
 * consistency proofs from a pinned head. The witness side (cosigning, head publication) is not here: a verifier only needs to
 * check what they produced. Total: any malformed input is a verdict, never an exception.
 */
public final class Mesh {
    private Mesh() {}

    static final String HEAD_DOMAIN = "atlas-pca/mesh-head/v1\0";
    static final String COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\0";
    static final String BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\0";
    static final String ACTION_DOMAIN = "atlas-pca/mesh-action/v1\0";
    private static final byte[] REVSET_PREFIX = "pca-revset/v1\0".getBytes(StandardCharsets.UTF_8);

    /** Default freshness window of a cosigned head, in milliseconds. */
    public static final double DEFAULT_MAX_HEAD_AGE_MS = 5 * 60_000;
    static final double DEFAULT_MAX_SKEW_MS = 60_000;
    static final long DEFAULT_MAX_CHAIN = 64;
    /** Default tolerance for a head or action timestamped ahead of the verifier's clock, in milliseconds. */
    public static final double DEFAULT_MAX_CLOCK_SKEW_MS = DEFAULT_MAX_SKEW_MS;
    /** Default bound on the delegation chain length (and on the depth of a federated budget tree). */
    public static final long DEFAULT_MAX_CHAIN_LENGTH = DEFAULT_MAX_CHAIN;
    static final int MAX_COSIGS = 256;
    static final int MAX_PATH = 128;

    /** The result of {@link #verifyMeshProof}; {@code hop} is -1 when no hop is named. */
    public static final class Verdict {
        public final boolean ok;
        public final String reason;
        public final int hop;
        Verdict(boolean ok, String reason, int hop) { this.ok = ok; this.reason = reason; this.hop = hop; }
        @Override public String toString() { return "Verdict{ok=" + ok + ", reason=" + reason + ", hop=" + hop + "}"; }
    }

    private static Verdict fail(String reason, int hop) { return new Verdict(false, reason, hop); }

    // ---- value helpers ----

    private static Map<String, Object> rec(Object x) { return Ledger.map(x); }
    private static String str(Object x) { return x instanceof String ? (String) x : null; }
    /** A canonical safe-integer lexeme that is &gt;= 0. */
    private static boolean nat(Object x) { return Json.isSafeInt(x) && Json.asLong(x) >= 0; }
    /** The value of a member a {@link #nat} check (or a validator built on it) has already admitted. */
    private static long natV(Object x) { return Json.asLong(x); }
    private static boolean num(Object x) { return IntentJs.isFinite(x); }
    /** The value of a member a {@link #num} check (or a validator built on it) has already admitted. */
    private static double jf(Object x) { return IntentJs.num(x); }

    // throws on a body strict canonical JSON refuses (a lone surrogate ...): the caller's verdict is "malformed", as the reference's
    private static byte[] msg(String domain, Object body) {
        return Pca.concat(Json.utf8(domain), Pca.canonBytes(body));
    }

    private static boolean sigOk(String pub, byte[] message, String sig) { return Pca.verifyB64u(pub, message, sig); }

    /** The text JavaScript prints for a decoded JSON member in a template literal. */
    private static String jsText(Object v, boolean present) {
        if (!present) return "undefined";
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object e : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (e != null) sb.append(jsText(e, true));
            }
            return sb.toString();
        }
        if (v instanceof Map) return "[object Object]";
        return jsNum(IntentJs.num(v)); // a decoded JSON member that is none of the above is a number
    }

    /** JavaScript String(n) (exponent form at 1e21 and below 1e-6, like the reference). */
    private static String jsNum(double d) { return AttestCommon.jsNumString(d); }

    // ---- shape validators ----

    private static Map<String, Object> validHead(Object h) {
        Map<String, Object> m = rec(h);
        if (m == null || str(m.get("domain")) == null) return null;
        String root = str(m.get("root"));
        if (root == null || str(m.get("rev_root")) == null) return null;
        if (!nat(m.get("size")) || !nat(m.get("rev_size")) || !num(m.get("timestamp"))) return null;
        return (natV(m.get("size")) == 0) == root.isEmpty() ? m : null;
    }

    private static Map<String, Object> validConsistency(Object c) {
        Map<String, Object> m = rec(c);
        if (m == null || !nat(m.get("oldSize")) || !nat(m.get("newSize"))) return null;
        if (!(m.get("path") instanceof List) || ((List<?>) m.get("path")).size() > MAX_PATH) return null;
        for (Object p : (List<?>) m.get("path")) if (!(p instanceof String)) return null;
        return m;
    }

    private static Map<String, Object> validInclusion(Object i) {
        Map<String, Object> m = rec(i);
        if (m == null || !nat(m.get("index")) || !nat(m.get("size"))) return null;
        return m.get("path") instanceof List && ((List<?>) m.get("path")).size() <= MAX_PATH ? m : null;
    }

    private static Map<String, Object> validAction(Object a) {
        Map<String, Object> m = rec(a);
        if (m == null) return null;
        for (String k : new String[] {"type", "resource", "service_domain", "nonce"}) if (str(m.get(k)) == null) return null;
        if (!num(m.get("at"))) return null;
        if (m.containsKey("amount") && !num(m.get("amount"))) return null;
        return m;
    }

    // ---- effective authority ----

    static final class Auth {
        List<String> actions = new ArrayList<>();
        boolean hasAct;
        List<String> prefixes = new ArrayList<>();
        double maxAmount;
        boolean hasAmount;
        double expiresAt;
        boolean hasExp;
        List<String> audience = new ArrayList<>();
        boolean hasAud;
        double maxHops;
        boolean hasHops;
        String err;
    }

    private static List<String> intersect(boolean have, List<String> a, List<String> b) {
        List<String> out = new ArrayList<>();
        if (!have) {
            out.addAll(new LinkedHashSet<>(b));
            out.sort(Json::compareUtf8);
            return out;
        }
        for (String x : a) if (b.contains(x)) out.add(x);
        return out;
    }

    private static List<String> strings(Object v) {
        if (!(v instanceof List)) return null;
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) v) {
            if (!(x instanceof String)) return null;
            out.add((String) x);
        }
        return out;
    }

    private static double min(boolean have, double cur, double v) { return have ? Math.min(cur, v) : v; }

    /** effectiveAuthority: the conjunction of the caveats; an unknown or malformed caveat is an error. */
    static Auth effective(Object caveats) {
        Auth e = new Auth();
        if (!(caveats instanceof List)) { e.err = "malformed proof"; return e; }
        for (Object cv : (List<?>) caveats) {
            Map<String, Object> c = rec(cv);
            if (c == null) { e.err = "malformed proof"; return e; }
            Object t = c.get("type");
            String ty = t instanceof String ? (String) t : "";
            switch (ty) {
                case "scope": {
                    List<String> a = strings(c.get("actions"));
                    if (a == null) { e.err = "malformed scope caveat"; return e; }
                    e.actions = intersect(e.hasAct, e.actions, a);
                    e.hasAct = true;
                    break;
                }
                case "resource": {
                    String p = str(c.get("prefix"));
                    if (p == null) { e.err = "malformed resource caveat"; return e; }
                    e.prefixes.add(p);
                    break;
                }
                case "max_amount":
                    if (!num(c.get("max"))) { e.err = "malformed max_amount caveat"; return e; }
                    e.maxAmount = min(e.hasAmount, e.maxAmount, jf(c.get("max")));
                    e.hasAmount = true;
                    break;
                case "expires":
                    if (!num(c.get("at"))) { e.err = "malformed expires caveat"; return e; }
                    e.expiresAt = min(e.hasExp, e.expiresAt, jf(c.get("at")));
                    e.hasExp = true;
                    break;
                case "audience": {
                    List<String> d = strings(c.get("domains"));
                    if (d == null) { e.err = "malformed audience caveat"; return e; }
                    e.audience = intersect(e.hasAud, e.audience, d);
                    e.hasAud = true;
                    break;
                }
                case "max_hops":
                    if (!num(c.get("n"))) { e.err = "malformed max_hops caveat"; return e; }
                    e.maxHops = min(e.hasHops, e.maxHops, jf(c.get("n")));
                    e.hasHops = true;
                    break;
                default:
                    e.err = "unknown caveat type \"" + jsText(c.get("type"), c.containsKey("type")) + "\" (fail closed)";
                    return e;
            }
        }
        return e;
    }

    private static boolean subset(List<String> child, List<String> parent) {
        for (String c : child) if (!parent.contains(c)) return false;
        return true;
    }

    /**
     * True iff the child caveat list narrows the parent's: the reference's "hop widens authority" relation, which a validly chained
     * proof always satisfies (each hop's caveats start with its parent's), so verifyMeshProof needs no check of its own.
     */
    static boolean narrowsCaveats(Object childCaveats, Object parentCaveats) {
        Auth c = effective(childCaveats), p = effective(parentCaveats);
        return c.err == null && p.err == null && narrows(c, p);
    }

    static boolean narrows(Auth child, Auth parent) {
        if (parent.hasAct && (!child.hasAct || !subset(child.actions, parent.actions))) return false;
        if (parent.hasAud && (!child.hasAud || !subset(child.audience, parent.audience))) return false;
        if (parent.hasAmount && (!child.hasAmount || child.maxAmount > parent.maxAmount)) return false;
        if (parent.hasExp && (!child.hasExp || child.expiresAt > parent.expiresAt)) return false;
        if (parent.hasHops && (!child.hasHops || child.maxHops > parent.maxHops)) return false;
        return subset(parent.prefixes, child.prefixes);
    }

    private static String admits(Auth e, Map<String, Object> a, double now, int chainLen) {
        String typ = str(a.get("type")) == null ? "" : str(a.get("type"));
        String res = str(a.get("resource")) == null ? "" : str(a.get("resource"));
        String svc = str(a.get("service_domain")) == null ? "" : str(a.get("service_domain"));
        if (e.hasAct && !e.actions.contains(typ)) return "action \"" + typ + "\" not in scope";
        for (String p : e.prefixes) if (!res.startsWith(p)) return "resource \"" + res + "\" outside prefix \"" + p + "\"";
        if (e.hasAmount && (!a.containsKey("amount") || jf(a.get("amount")) > e.maxAmount)) return "amount exceeds ceiling " + jsNum(e.maxAmount);
        if (e.hasExp && !(Double.isFinite(now) && now <= e.expiresAt)) return "capability expired";
        if (e.hasAud && !e.audience.contains(svc)) return "service domain not in audience";
        if (e.hasHops && (double) chainLen > e.maxHops) return "chain exceeds max_hops " + jsNum(e.maxHops);
        return "";
    }

    // ---- revocation sets and Merkle proofs ----

    // never throws: a safe-integer size and a base64url tree hash always admit the strict canonical encoding
    static String bindRevRoot(long size, String tree) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("size", IntentJs.ofLong(size));
        m.put("tree", tree);
        return Pca.b64(Pca.sha(REVSET_PREFIX, Pca.canonBytes(m)));
    }

    /** Package-private for the kill tests: one revocation-set leaf at {@code proof.index} under the bound root. */
    static boolean leafOk(String root, long size, String id, Map<String, Object> proof) {
        if (!Json.isSafeInt(proof.get("size")) || !Json.isSafeInt(proof.get("index"))) return false;
        long psize = Json.asLong(proof.get("size")), index = Json.asLong(proof.get("index"));
        if (psize != size || index < 0 || index >= size) return false;
        List<String> sides = Pca.pathShape(index, size);
        if (!(proof.get("path") instanceof List) || ((List<?>) proof.get("path")).size() != sides.size()) return false;
        List<?> path = (List<?>) proof.get("path");
        byte[] h;
        try {
            h = Pca.leafHash(id);
        } catch (RuntimeException e) {
            return false;
        }
        for (int i = 0; i < path.size(); i++) {
            Map<String, Object> step = rec(path.get(i));
            if (step == null) return false;
            String side = str(step.get("side"));
            if (side == null || !side.equals(sides.get(i))) return false;
            byte[] sib = Pca.decodeB64uStrict(step.get("hash"), 32);
            if (sib == null) return false;
            h = side.equals("L") ? Pca.nodeHash(sib, h) : Pca.nodeHash(h, sib);
        }
        return bindRevRoot(size, Pca.b64(h)).equals(root);
    }

    /** verifyNonMembership over an expanded proof {size, lo?, hi?}. */
    static boolean nonMembership(String root, Map<String, Object> nm, String id) {
        if (!Json.isSafeInt(nm.get("size")) || Json.asLong(nm.get("size")) < 0) return false;
        long size = Json.asLong(nm.get("size"));
        Map<String, Object> lo = rec(nm.get("lo")), hi = rec(nm.get("hi"));
        if (size == 0) return lo == null && hi == null && bindRevRoot(0, Ledger.EMPTY_TREE_ROOT).equals(root);
        if (lo == null && hi == null) return false;
        if (lo != null) {
            String loId = str(lo.get("id")) == null ? "" : str(lo.get("id"));
            Map<String, Object> lp = rec(lo.get("proof"));
            if (lp == null || !(Json.compareUtf8(loId, id) < 0) || !leafOk(root, size, loId, lp)) return false;
            if (hi == null && natV(lp.get("index")) != size - 1) return false;
        }
        if (hi != null) {
            String hiId = str(hi.get("id")) == null ? "" : str(hi.get("id"));
            Map<String, Object> hp = rec(hi.get("proof"));
            if (hp == null || !(Json.compareUtf8(id, hiId) < 0) || !leafOk(root, size, hiId, hp)) return false;
            if (lo == null && natV(hp.get("index")) != 0) return false;
        }
        // both bounds verified above: they must be adjacent leaves
        return lo == null || hi == null || natV(rec(hi.get("proof")).get("index")) == natV(rec(lo.get("proof")).get("index")) + 1;
    }

    /**
     * verifyLedgerConsistency (RFC 9162 section 2.1.4.2), with strict 32-byte base64url hashes, for what checkHeadAdvance
     * admits: 1 &lt;= first &lt; second and a path of at most MAX_PATH strings (validConsistency). (An empty old tree, whose
     * root is the empty-tree root, is consistent with any larger tree under an empty path: checkHeadAdvance decides it.)
     */
    private static boolean consistency(String oldRoot, String newRoot, long first, long second, List<?> raw) {
        if (first < 1 || first >= second || raw.size() > MAX_PATH) return false;
        List<byte[]> path = new ArrayList<>();
        if ((first & (first - 1)) == 0) {
            byte[] o = Pca.decodeB64uStrict(oldRoot, 32);
            if (o == null) return false;
            path.add(o);
        }
        for (Object p : raw) {
            byte[] b = Pca.decodeB64uStrict(p, 32);
            if (b == null) return false;
            path.add(b);
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
        return sn == 0 && Pca.b64(fr).equals(oldRoot) && Pca.b64(sr).equals(newRoot);
    }

    // ---- heads ----

    static String checkHeadAdvance(Object prev, Object next, Object proof) {
        Map<String, Object> p = validHead(prev);
        if (p == null) return "malformed head";
        Map<String, Object> n = validHead(next);
        if (n == null) return "malformed head";
        if (!p.get("domain").equals(n.get("domain"))) return "head is for a different domain";
        if (natV(n.get("size")) < natV(p.get("size")) || natV(n.get("rev_size")) < natV(p.get("rev_size"))) return "head rolls back";
        if (natV(n.get("size")) == natV(p.get("size"))) {
            if (!n.get("root").equals(p.get("root"))) return "equivocation (same size, different log)";
        } else {
            Map<String, Object> c = validConsistency(proof);
            if (c == null || natV(c.get("oldSize")) != natV(p.get("size")) || natV(c.get("newSize")) != natV(n.get("size"))) {
                return "consistency proof required for a larger head";
            }
            List<?> path = (List<?>) c.get("path");
            long first = natV(p.get("size")), second = natV(n.get("size"));
            if (first == 0 ? !path.isEmpty() : !consistency((String) p.get("root"), (String) n.get("root"), first, second, path)) {
                return "head is not consistent with the previous head (fork or rewrite)";
            }
        }
        if (natV(n.get("rev_size")) == natV(p.get("rev_size")) && !n.get("rev_root").equals(p.get("rev_root"))) return "equivocation (revocation set)";
        return "";
    }

    private static final class Trust {
        String human;
        Set<String> witnesses = new HashSet<>();
        long threshold;
        double now, maxHeadAge, maxSkew, maxActionAge;
        boolean hasActionAge;
        long maxChain;
        List<String> allowed;
        String rootDomain;
        Map<String, Object> issuerDoms, pinned, pqPins;
        String err;
    }

    private static Double opt(Map<String, Object> t, String k, double def) {
        if (!t.containsKey(k)) return def;
        Object v = t.get(k);
        return !num(v) || jf(v) < 0 ? null : jf(v);
    }

    private static Trust validTrust(Object traw) {
        Trust c = new Trust();
        Map<String, Object> t = rec(traw);
        if (t == null) { c.err = "invalid trust configuration"; return c; }
        String human = str(t.get("humanPrincipal"));
        List<String> ws = strings(t.get("witnesses"));
        if (human == null || ws == null) { c.err = "invalid trust configuration"; return c; }
        c.human = human;
        c.witnesses.addAll(ws);
        if (!nat(t.get("threshold")) || natV(t.get("threshold")) < 1 || natV(t.get("threshold")) > c.witnesses.size()) {
            c.err = "invalid trust configuration: threshold";
            return c;
        }
        c.threshold = natV(t.get("threshold"));
        if (!num(t.get("now"))) { c.err = "invalid trust configuration: now"; return c; }
        c.now = jf(t.get("now"));
        Double v = opt(t, "maxHeadAgeMs", DEFAULT_MAX_HEAD_AGE_MS);
        if (v == null) { c.err = "invalid trust configuration: maxHeadAgeMs"; return c; }
        c.maxHeadAge = v;
        v = opt(t, "maxClockSkewMs", DEFAULT_MAX_SKEW_MS);
        if (v == null) { c.err = "invalid trust configuration: maxClockSkewMs"; return c; }
        c.maxSkew = v;
        if (t.containsKey("maxActionAgeMs")) {
            v = opt(t, "maxActionAgeMs", 0);
            if (v == null) { c.err = "invalid trust configuration: maxActionAgeMs"; return c; }
            c.maxActionAge = v;
            c.hasActionAge = true;
        }
        c.maxChain = DEFAULT_MAX_CHAIN;
        if (t.containsKey("maxChainLength")) {
            Object mc = t.get("maxChainLength");
            if (!nat(mc) || natV(mc) < 1) { c.err = "invalid trust configuration: maxChainLength"; return c; }
            c.maxChain = natV(mc);
        }
        List<String> ad = strings(t.get("allowedDomains"));
        if (ad == null || ad.isEmpty()) { c.err = "invalid trust configuration: allowedDomains is required"; return c; }
        c.allowed = ad;
        String rd = str(t.get("rootDomain"));
        if (rd == null || !ad.contains(rd)) {
            c.err = "invalid trust configuration: rootDomain is required and must be in allowedDomains";
            return c;
        }
        c.rootDomain = rd;
        if (t.containsKey("issuerDomains")) {
            Map<String, Object> m = rec(t.get("issuerDomains"));
            if (m == null) { c.err = "invalid trust configuration: issuerDomains"; return c; }
            for (Object x : m.values()) if (!(x instanceof String)) { c.err = "invalid trust configuration: issuerDomains"; return c; }
            c.issuerDoms = m;
        }
        if (t.containsKey("pinnedHeads")) {
            Map<String, Object> m = rec(t.get("pinnedHeads"));
            if (m == null) { c.err = "invalid trust configuration: pinnedHeads"; return c; }
            c.pinned = m;
        }
        // as given, like the reference (mesh.ts passes t.pqPins to verifyChain): a non-string pin never equals a root's pq_pk
        c.pqPins = rec(t.get("pqPins"));
        return c;
    }

    private static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = IntentJs.num(v);
        return d == null || (d != 0 && !d.isNaN());
    }

    /** The cosigned head {@code chm} whose head {@code h} the caller has matched to the hop's (string) domain. */
    private static String checkCosignedHead(Map<String, Object> chm, Map<String, Object> h, Trust t, Object pinProof) {
        try {
            return cosignedHeadError(chm, h, t, pinProof);
        } catch (RuntimeException e) {
            return "malformed head";
        }
    }

    private static String cosignedHeadError(Map<String, Object> chm, Map<String, Object> h, Trust t, Object pinProof) {
        if (validHead(h) == null) return "malformed head";
        String sig = str(chm.get("sig"));
        if (sig == null) return "malformed head";
        String domain = (String) h.get("domain");
        if (!sigOk(domain, msg(HEAD_DOMAIN, h), sig)) return "head not signed by its domain key";
        if (!(chm.get("cosigs") instanceof List) || ((List<?>) chm.get("cosigs")).size() > MAX_COSIGS) return "malformed head";
        Set<String> good = new HashSet<>();
        byte[] cm = msg(COSIG_DOMAIN, h);
        for (Object c : (List<?>) chm.get("cosigs")) {
            Map<String, Object> cr = rec(c);
            if (cr == null) continue;
            String w = str(cr.get("witness")), s = str(cr.get("sig"));
            if (w != null && s != null && t.witnesses.contains(w) && !good.contains(w) && sigOk(w, cm, s)) good.add(w);
        }
        if (good.size() < t.threshold) return "head has " + good.size() + "/" + t.threshold + " trusted witness cosignatures";
        double ts = jf(h.get("timestamp"));
        if (ts > t.now + t.maxSkew) return "head timestamp is in the future";
        if (t.now - ts > t.maxHeadAge) return "head is stale";
        if (t.pinned != null && truthy(t.pinned.get(domain))) { // an absent pin reads as undefined: falsy
            String why = checkHeadAdvance(t.pinned.get(domain), h, pinProof);
            if (!why.isEmpty()) return why + " (vs pinned head)";
        }
        return "";
    }

    private static Map<String, Object> expandNm(Object c, List<?> leaves) {
        Map<String, Object> m = rec(c);
        if (m == null || !nat(m.get("size"))) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("size", m.get("size"));
        for (String side : new String[] {"lo", "hi"}) {
            if (!m.containsKey(side)) continue;
            Object ix = m.get(side);
            if (!nat(ix) || natV(ix) >= leaves.size()) return null;
            out.put(side, leaves.get((int) natV(ix)));
        }
        return out;
    }

    // ---- the verifier ----

    /**
     * Verifies a mesh proof end to end, offline. Both arguments are parsed JSON ({@link Json#parseLenient} values). Total: any
     * malformed input is a verdict, never an exception.
     */
    public static Verdict verifyMeshProof(Object proof, Object trust) {
        try {
            return verify(proof, trust);
        } catch (RuntimeException e) {
            return fail("malformed proof", -1);
        }
    }

    private static Verdict verify(Object proof, Object trust) {
        Trust t = validTrust(trust);
        if (t.err != null) return fail(t.err, -1);
        Map<String, Object> p = rec(proof);
        if (p == null) return fail("malformed proof", -1);
        if (!(p.get("chain") instanceof List) || !(p.get("hops") instanceof List) || !(p.get("heads") instanceof List) || !(p.get("rev_leaves") instanceof List)) {
            return fail("malformed proof", -1);
        }
        List<Object> chain = Pca.asList(p.get("chain"));
        List<?> hops = (List<?>) p.get("hops"), heads = (List<?>) p.get("heads"), revLeaves = (List<?>) p.get("rev_leaves");
        Map<String, Object> action = validAction(p.get("action"));
        String actionSig = str(p.get("action_sig"));
        if (actionSig == null || action == null) return fail("malformed action", -1);
        if (p.containsKey("pin_proofs")) {
            if (!(p.get("pin_proofs") instanceof List) || ((List<?>) p.get("pin_proofs")).size() > MAX_COSIGS) return fail("malformed pin proofs", -1);
            for (Object x : (List<?>) p.get("pin_proofs")) {
                Map<String, Object> xm = rec(x);
                if (xm == null || str(xm.get("domain")) == null || validConsistency(xm.get("proof")) == null) return fail("malformed pin proofs", -1);
            }
        }
        if (chain.size() < 1 || chain.size() > t.maxChain) return fail("chain length out of bounds", -1);
        if (heads.size() > chain.size() || revLeaves.size() > 2 * chain.size()) return fail("evidence tables exceed chain size", -1);
        String chainWhy = Pca.verifyChain(chain, t.human, true, null, t.pqPins, null);
        if (!chainWhy.isEmpty()) return fail("chain: " + chainWhy, -1);
        if (hops.size() != chain.size()) return fail("hop evidence count does not match chain length", -1);
        for (Object l : revLeaves) {
            Map<String, Object> lm = rec(l);
            if (lm == null || str(lm.get("id")) == null || validInclusion(lm.get("proof")) == null) return fail("malformed revocation leaves", -1);
        }
        Set<Long> used = new HashSet<>();
        for (Object h : hops) {
            Map<String, Object> ev = rec(h);
            if (ev != null && nat(ev.get("head"))) used.add(natV(ev.get("head")));
        }
        if (used.size() != heads.size()) return fail("unreferenced or missing head in evidence table", -1);

        Map<Long, String> headErrs = new HashMap<>();
        Set<Long> headDone = new HashSet<>();
        Auth prev = null;
        for (int i = 0; i < chain.size(); i++) {
            Map<String, Object> cap = rec(chain.get(i));
            Map<String, Object> ev = rec(hops.get(i));
            if (ev == null) return fail("malformed hop evidence", i);
            String domain = str(ev.get("domain"));
            if (domain == null || !nat(ev.get("head")) || natV(ev.get("head")) >= heads.size() || rec(ev.get("revocation")) == null) {
                return fail("malformed hop evidence", i);
            }
            if (!t.allowed.contains(domain)) return fail("issuing domain not allowed by policy", i);
            if (i == 0 && !domain.equals(t.rootDomain)) return fail("root capability must be anchored in the pinned root domain", i);
            String issuer = (String) cap.get("issuer"); // verifyChain admitted a well-typed chain: id, issuer, holder are strings
            if (i > 0 && t.issuerDoms != null && t.issuerDoms.containsKey(issuer) && !domain.equals(t.issuerDoms.get(issuer))) {
                return fail("issuer key is pinned to a different domain", i);
            }
            long hi = natV(ev.get("head"));
            Map<String, Object> chm = rec(heads.get((int) hi));
            if (chm == null || chm.get("head") == null) return fail("malformed proof", -1); // `ch.head.domain` throws in the reference
            Map<String, Object> headM = rec(chm.get("head"));
            if (headM == null || !domain.equals(headM.get("domain"))) return fail("source-domain anchor: head is for a different domain", i);
            // a head is checked once, for the first hop that names it (every later hop naming it has passed the same domain match)
            if (!headDone.contains(hi)) {
                Object pinProof = null;
                if (p.get("pin_proofs") instanceof List) {
                    for (Object x : (List<?>) p.get("pin_proofs")) {
                        Map<String, Object> xm = rec(x);
                        if (xm != null && domain.equals(xm.get("domain"))) { pinProof = xm.get("proof"); break; }
                    }
                }
                headErrs.put(hi, checkCosignedHead(chm, headM, t, pinProof));
                headDone.add(hi);
            }
            String he = headErrs.get(hi);
            if (!he.isEmpty()) return fail("source-domain anchor: " + he, i);

            Map<String, Object> incl = validInclusion(ev.get("inclusion"));
            if (incl == null || natV(incl.get("size")) != natV(headM.get("size"))) return fail("hop not included in the issuing domain log", i);
            String capDigest;
            try {
                capDigest = Pca.capHash(cap); // only the tip can throw here: verifyChain hashed every parent
            } catch (RuntimeException e) {
                return fail("hop not included in the issuing domain log", i);
            }
            String root = str(headM.get("root")) == null ? "" : str(headM.get("root"));
            if (!Pca.verifyInclusion(root, incl, capDigest)) return fail("hop not included in the issuing domain log", i);

            if (i > 0) {
                Map<String, Object> b = rec(ev.get("binding"));
                String role = b == null ? null : str(b.get("role")), bsig = b == null ? null : str(b.get("sig"));
                if (b == null || role == null || bsig == null || !issuer.equals(b.get("agent")) || !domain.equals(b.get("domain"))) {
                    return fail("missing or mismatched domain binding for issuer", i);
                }
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("agent", b.get("agent"));
                body.put("domain", b.get("domain"));
                body.put("role", role);
                if (!sigOk(domain, msg(BINDING_DOMAIN, body), bsig)) return fail("domain binding signature invalid", i);
            }

            Map<String, Object> rev = rec(ev.get("revocation"));
            String revRoot = str(headM.get("rev_root")) == null ? "" : str(headM.get("rev_root"));
            String id = (String) cap.get("id");
            Map<String, Object> nmCap = expandNm(rev.get("cap"), revLeaves);
            if (nmCap == null || !nonMembership(revRoot, nmCap, id)) return fail("capability revoked (or revocation proof invalid)", i);
            Map<String, Object> nmKey = expandNm(rev.get("issuer_key"), revLeaves);
            if (nmKey == null || !nonMembership(revRoot, nmKey, "key:" + issuer)) return fail("issuer key revoked (or revocation proof invalid)", i);

            Auth eff = effective(cap.get("caveats"));
            if (eff.err != null) return fail(eff.err, i);
            if (prev != null && !narrows(eff, prev)) return fail("hop widens authority", i);
            prev = eff;
        }

        double actTs = jf(action.get("at"));
        if (actTs > t.now + t.maxSkew) return fail("action timestamp is in the future", -1);
        if (t.hasActionAge && t.now - actTs > t.maxActionAge) return fail("action is stale", -1);
        Map<String, Object> tip = rec(chain.get(chain.size() - 1));
        String tipHash;
        try {
            tipHash = Pca.capHash(tip);
        } catch (RuntimeException e) {
            return fail("action not signed by the chain tip holder", -1);
        }
        String holder = (String) tip.get("holder");
        Map<String, Object> ab = new LinkedHashMap<>();
        ab.put("action", action);
        ab.put("tip", tipHash);
        if (!sigOk(holder, msg(ACTION_DOMAIN, ab), actionSig)) return fail("action not signed by the chain tip holder", -1);
        String denied = admits(prev, action, t.now, chain.size());
        if (!denied.isEmpty()) return fail("action not admitted: " + denied, -1);
        return new Verdict(true, "", -1);
    }

    // ---- action signing and proof assembly ---------------------------------------------------------------------------------

    /** The leaf holder signs the action, bound to the chain tip: {@code b64u(sign(leafKey, ACTION_DOMAIN || canon({action, tip})))}. */
    public static String signMeshAction(List<Map<String, Object>> chain, Map<String, Object> action, Keys.EdKey leafKey) {
        if (chain == null || chain.isEmpty()) throw new IllegalArgumentException("signMeshAction: the chain is empty");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("action", action);
        body.put("tip", Pca.capHash(chain.get(chain.size() - 1)));
        return Keys.b64u(leafKey.sign(msg(ACTION_DOMAIN, body)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o, String what) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("assembleMeshProof: " + what + " must be an object");
        return (Map<String, Object>) o;
    }

    private static Map<String, Object> compactNm(Map<String, Object> n, List<Object> leaves, Map<String, Integer> leafIdx) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (n.containsKey("size")) out.put("size", n.get("size")); // an absent member stays absent, as in the reference
        for (String k : new String[] {"lo", "hi"}) {
            Object l = n.get(k);
            if (!truthy(l)) continue;
            String key = Pca.b64(Pca.canonBytes(l)); // canonical: the same leaf in any member order is one entry
            Integer i = leafIdx.get(key);
            if (i == null) {
                i = leaves.size();
                leaves.add(l);
                leafIdx.put(key, i);
            }
            out.put(k, StoreJs.num((long) i));
        }
        return out;
    }

    /**
     * Assemble a compact proof from uncompacted per-hop evidence ({@link MeshDomain#evidence}). Hops issued against the same head share ONE table
     * entry (cosignatures for the same head are merged, first seen wins) and identical revocation bracketing leaves are carried once. {@code pinProofs}
     * ({@code {domain, proof}} each) may be null or empty.
     */
    public static Map<String, Object> assembleMeshProof(List<Map<String, Object>> chain, List<Map<String, Object>> hops, Map<String, Object> action,
                                                        Keys.EdKey leafKey, List<Object> pinProofs) {
        List<Object> heads = new ArrayList<>(), leaves = new ArrayList<>(), outHops = new ArrayList<>();
        Map<String, Integer> headIdx = new LinkedHashMap<>(), leafIdx = new LinkedHashMap<>();
        for (Map<String, Object> ev : hops) {
            Map<String, Object> eh = asMap(ev.get("head"), "hop head");
            String k = eh.get("sig") + "|" + Pca.b64(Pca.canonBytes(eh.get("head")));
            Integer i = headIdx.get(k);
            List<?> cosigs = eh.get("cosigs") instanceof List ? (List<?>) eh.get("cosigs") : null;
            if (cosigs == null) throw new IllegalArgumentException("assembleMeshProof: cosigs must be a list");
            if (i == null) {
                i = heads.size();
                Map<String, Object> h = new LinkedHashMap<>();
                if (eh.containsKey("head")) h.put("head", eh.get("head"));
                if (eh.containsKey("sig")) h.put("sig", eh.get("sig"));
                h.put("cosigs", new ArrayList<Object>(cosigs));
                heads.add(h);
                headIdx.put(k, i);
            } else {
                @SuppressWarnings("unchecked") List<Object> have = (List<Object>) ((Map<String, Object>) heads.get(i)).get("cosigs");
                java.util.Set<Object> seen = new java.util.HashSet<>();
                for (Object c : have) seen.add(asMap(c, "cosig").get("witness"));
                for (Object c : cosigs) if (!seen.contains(asMap(c, "cosig").get("witness"))) have.add(c);
            }
            Map<String, Object> rv = asMap(ev.get("revocation"), "revocation");
            Map<String, Object> revOut = new LinkedHashMap<>();
            revOut.put("cap", compactNm(asMap(rv.get("cap"), "revocation.cap"), leaves, leafIdx));
            revOut.put("issuer_key", compactNm(asMap(rv.get("issuer_key"), "revocation.issuer_key"), leaves, leafIdx));
            Map<String, Object> out = new LinkedHashMap<>();
            if (ev.containsKey("domain")) out.put("domain", ev.get("domain"));
            out.put("head", StoreJs.num((long) i));
            if (ev.containsKey("inclusion")) out.put("inclusion", ev.get("inclusion"));
            out.put("revocation", revOut);
            Object binding = ev.get("binding");
            if (truthy(binding)) out.put("binding", binding);
            outHops.add(out);
        }
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("chain", new ArrayList<Object>(chain));
        proof.put("heads", heads);
        proof.put("rev_leaves", leaves);
        proof.put("hops", outHops);
        proof.put("action", action);
        proof.put("action_sig", signMeshAction(chain, action, leafKey));
        if (pinProofs != null && !pinProofs.isEmpty()) proof.put("pin_proofs", new ArrayList<Object>(pinProofs));
        return proof;
    }

    // ---- ids, authority, size and latency models -----------------------------------------------------------------------------

    /** The id a domain's revocation set uses to revoke an agent KEY (it kills every capability that key issues): {@code "key:" + agentPublic}. */
    public static String keyRevocationId(Object agentPublic) { return "key:" + jsText(agentPublic, true); }

    static Map<String, Object> authJson(Auth e) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (e.err != null) {
            m.put("error", e.err);
            return m;
        }
        m.put("prefixes", new ArrayList<Object>(e.prefixes));
        if (e.hasAct) m.put("actions", new ArrayList<Object>(e.actions));
        if (e.hasAmount) m.put("maxAmount", StoreJs.num(e.maxAmount));
        if (e.hasExp) m.put("expiresAt", StoreJs.num(e.expiresAt));
        if (e.hasAud) m.put("audience", new ArrayList<Object>(e.audience));
        if (e.hasHops) m.put("maxHops", StoreJs.num(e.maxHops));
        return m;
    }

    /**
     * The conjunction of a caveat list as one authority: {@code {prefixes, actions?, maxAmount?, expiresAt?, audience?, maxHops?}}, or
     * {@code {error}} when a caveat is unknown or malformed (fail closed; the first failing caveat is the one reported). The first
     * {@code scope} / {@code audience} is de-duplicated and sorted, a later one intersects it; the numeric caveats take the minimum.
     * Throws when {@code caveats} is not a list or holds a null.
     */
    public static Map<String, Object> effectiveAuthority(Object caveats) {
        if (!(caveats instanceof List)) throw new IllegalArgumentException("effectiveAuthority: caveats is not a list");
        List<?> cs = (List<?>) caveats;
        int k = 0;
        while (k < cs.size() && cs.get(k) instanceof Map) k++;
        Auth e = effective(k == cs.size() ? cs : cs.subList(0, k));
        if (e.err == null && k < cs.size()) {
            if (cs.get(k) == null) throw new IllegalArgumentException("effectiveAuthority: a caveat is null");
            e.err = "unknown caveat type \"undefined\" (fail closed)"; // a caveat that is not an object has no type
        }
        return authJson(e);
    }

    private static final Object UNDEF = new Object();

    /** JavaScript {@code container[key]} over decoded JSON: UNDEF when there is no such member; a null container throws, as the reference does. */
    private static Object jsIndex(Object container, Object key, boolean keyPresent) {
        if (container == null) throw new IllegalArgumentException("meshProofSize: malformed proof");
        String k = jsText(key, keyPresent);
        if (container instanceof Map) return ((Map<?, ?>) container).containsKey(k) ? ((Map<?, ?>) container).get(k) : UNDEF;
        int n = container instanceof List ? ((List<?>) container).size() : container instanceof String ? ((String) container).length() : 0;
        if (!k.matches("0|[1-9][0-9]{0,8}") || Integer.parseInt(k) >= n) return UNDEF;
        int i = Integer.parseInt(k);
        return container instanceof List ? ((List<?>) container).get(i) : String.valueOf(((String) container).charAt(i));
    }

    private static Map<String, Object> expandForSize(Object c, Object leaves) {
        Map<String, Object> m = rec(c);
        if (m == null || !m.containsKey("size")) throw new IllegalArgumentException("meshProofSize: malformed revocation proof");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("size", m.get("size"));
        for (String side : new String[] {"lo", "hi"}) {
            if (!m.containsKey(side)) continue;
            Object leaf = jsIndex(leaves, m.get(side), true);
            if (leaf != UNDEF && truthy(leaf)) out.put(side, leaf);
        }
        return out;
    }

    private static long memberBytes(Map<String, Object> p, String k) {
        if (!p.containsKey(k)) throw new IllegalArgumentException("meshProofSize: " + k + " is missing");
        return Pca.canonBytes(p.get(k)).length;
    }

    /**
     * Size accounting of a compact proof, in bytes of canonical JSON: {@code {total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes,
     * hops_bytes, uncompacted_bytes}}, the last being the size had every hop carried its own head copy and inline revocation leaves.
     * Throws on a value that is not a proof (a missing table, a hop naming a head that is not there, a value with no canonical form).
     */
    public static Map<String, Object> meshProofSize(Object proof) {
        Map<String, Object> p = rec(proof);
        if (p == null) throw new IllegalArgumentException("meshProofSize: not a proof");
        long uncompacted = memberBytes(p, "chain") + memberBytes(p, "action") + memberBytes(p, "action_sig");
        if (!(p.get("hops") instanceof List)) throw new IllegalArgumentException("meshProofSize: hops is not a list");
        for (Object ho : (List<?>) p.get("hops")) {
            Map<String, Object> h = rec(ho);
            Map<String, Object> rv = h == null ? null : rec(h.get("revocation"));
            if (rv == null || !rv.containsKey("cap") || !rv.containsKey("issuer_key")) throw new IllegalArgumentException("meshProofSize: malformed hop");
            Object head = jsIndex(p.get("heads"), h.get("head"), h.containsKey("head"));
            if (head == UNDEF) throw new IllegalArgumentException("meshProofSize: a hop names a head that is not in the table");
            Map<String, Object> full = new LinkedHashMap<>(h);
            full.put("head", head);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("cap", expandForSize(rv.get("cap"), p.get("rev_leaves")));
            r.put("issuer_key", expandForSize(rv.get("issuer_key"), p.get("rev_leaves")));
            full.put("revocation", r);
            uncompacted += Pca.canonBytes(full).length;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total_bytes", StoreJs.num((long) Pca.canonBytes(p).length));
        out.put("chain_bytes", StoreJs.num(memberBytes(p, "chain")));
        out.put("heads_bytes", StoreJs.num(memberBytes(p, "heads")));
        out.put("rev_leaves_bytes", StoreJs.num(memberBytes(p, "rev_leaves")));
        out.put("hops_bytes", StoreJs.num(memberBytes(p, "hops")));
        out.put("uncompacted_bytes", StoreJs.num(uncompacted));
        return out;
    }

    /** Worst-case time from "revocation made" until it is enforced, per verifier posture (milliseconds; infinite and not viable for unusable inputs). */
    public static final class LatencyBound {
        /** Until the revocation is visible in a head that new provers hold. */
        public final double publishedMs;
        /** A verifier that does not pin: a head from before the revocation is rejected as stale by then. */
        public final double unpinnedMs;
        /** A pinning verifier: the smaller of {@link #unpinnedMs} and the pin refresh interval. */
        public final double pinnedMs;
        /** Honest provers can always hold a fresh head only when the head interval (plus skew) is below the head age limit. */
        public final boolean honestProversViable;
        LatencyBound(double publishedMs, double unpinnedMs, double pinnedMs, boolean honestProversViable) {
            this.publishedMs = publishedMs;
            this.unpinnedMs = unpinnedMs;
            this.pinnedMs = pinnedMs;
            this.honestProversViable = honestProversViable;
        }
    }

    private static boolean okMs(Object x) { return num(x) && jf(x) >= 0; }

    /**
     * The revocation latency bound for {@code {maxHeadAgeMs, headIntervalMs, maxClockSkewMs?, pinRefreshMs?}}: a head from before the
     * revocation stops verifying no later than {@code maxHeadAgeMs + skew} after it, a head that contains it is available within
     * {@code headIntervalMs}, and a pinning verifier rejects the older head as soon as its pin advances. A missing, non-finite or
     * negative input gives the unusable bound.
     */
    public static LatencyBound revocationLatencyBound(Object params) {
        Map<String, Object> p = rec(params);
        double inf = Double.POSITIVE_INFINITY;
        if (p == null || !okMs(p.get("maxHeadAgeMs")) || !okMs(p.get("headIntervalMs")) || (p.containsKey("maxClockSkewMs") && !okMs(p.get("maxClockSkewMs")))
            || (p.containsKey("pinRefreshMs") && !okMs(p.get("pinRefreshMs")))) {
            return new LatencyBound(inf, inf, inf, false);
        }
        double age = jf(p.get("maxHeadAgeMs")), interval = jf(p.get("headIntervalMs"));
        double skew = p.containsKey("maxClockSkewMs") ? jf(p.get("maxClockSkewMs")) : 0;
        double unpinned = age + skew;
        return new LatencyBound(interval, unpinned, p.containsKey("pinRefreshMs") ? Math.min(unpinned, jf(p.get("pinRefreshMs"))) : unpinned, interval + skew < age);
    }

    // ---- worked example: human -> orchestrator (org A) -> tool agent (org B) -> service (org C) -------------------------------

    /** The parts of {@link #buildMeshExample}, exposed so callers can build variants (revocation, widening, forks). */
    public static final class Example {
        public final Map<String, Object> trust;
        public final Map<String, Object> proof;
        /** The uncompacted evidence the proof was assembled from. */
        public final List<Map<String, Object>> evidence;
        /** Keyed {@code A}, {@code B}, {@code C}. */
        public final Map<String, MeshDomain> domains;
        public final List<MeshWitness> witnesses;
        /** Keyed {@code human}, {@code orchestrator}, {@code tool}, {@code service}, {@code leaf}. */
        public final Map<String, Keys.EdKey> keys;
        public final List<Map<String, Object>> chain;
        /** {@code A0} is A's earlier head (size 1); {@code A} its current head (size 2), cosigned only after a verified consistency proof; {@code B}; {@code C}. */
        public final Map<String, Map<String, Object>> heads;
        /** Keyed {@code orchestrator}, {@code tool}, {@code service}. */
        public final Map<String, Map<String, Object>> bindings;
        Example(Map<String, Object> trust, Map<String, Object> proof, List<Map<String, Object>> evidence, Map<String, MeshDomain> domains, List<MeshWitness> witnesses,
                Map<String, Keys.EdKey> keys, List<Map<String, Object>> chain, Map<String, Map<String, Object>> heads, Map<String, Map<String, Object>> bindings) {
            this.trust = trust;
            this.proof = proof;
            this.evidence = evidence;
            this.domains = domains;
            this.witnesses = witnesses;
            this.keys = keys;
            this.chain = chain;
            this.heads = heads;
            this.bindings = bindings;
        }
    }

    /** The example's fixed keys: the first 32 bytes of the TEXT of a canonical hash (not its decoded bytes), as the reference derives them. */
    private static Keys.EdKey exampleKey(String label) {
        return Keys.edFromSeed(Pca.hashCanonical(Issue.obj("seed", "atlas-pca/mesh-example/" + label)).substring(0, 32).getBytes(StandardCharsets.US_ASCII));
    }

    private static List<Object> listOf(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    /** {@link #buildMeshExample(double)} at the reference's default time. */
    public static Example buildMeshExample() { return buildMeshExample(1_800_000_000_000d); }

    /**
     * Four hops across three organisations (the human's home is org A): human to orchestrator (logged in A), orchestrator to tool agent
     * (logged in A), tool agent to service agent (logged in B), service agent to leaf worker (logged in C). The leaf then performs
     * {@code payments.refund} for 25 under /orders/42. Org A publishes two successive heads; every witness cosigns the second only after
     * verifying the consistency proof between them, and hops 0 and 1 share one head in the proof. Deterministic for a given {@code now}.
     */
    public static Example buildMeshExample(double now) {
        Map<String, Keys.EdKey> keys = new LinkedHashMap<>();
        for (String k : new String[] {"human", "orchestrator", "tool", "service", "leaf"}) keys.put(k, exampleKey(k));
        MeshDomain a = new MeshDomain("org-A", exampleKey("domain-A")), b = new MeshDomain("org-B", exampleKey("domain-B")), c = new MeshDomain("org-C", exampleKey("domain-C"));
        List<MeshWitness> witnesses = new ArrayList<>();
        for (int i = 1; i <= 3; i++) witnesses.add(new MeshWitness(exampleKey("witness-" + i)));

        Map<String, Object> root = Issue.mintRoot(Keys.ed25519(keys.get("human")), keys.get("orchestrator").id(), null, listOf(
            Issue.obj("type", "scope", "actions", listOf("payments.refund", "payments.read", "orders.read")),
            Issue.obj("type", "resource", "prefix", "/orders/"),
            Issue.obj("type", "max_amount", "max", StoreJs.num(500L)),
            Issue.obj("type", "expires", "at", StoreJs.num(now + 3_600_000)),
            Issue.obj("type", "audience", "domains", listOf(c.id))));
        Map<String, Object> c1 = Issue.delegate(root, keys.get("tool").id(), listOf(
            Issue.obj("type", "scope", "actions", listOf("payments.refund", "payments.read")), Issue.obj("type", "max_amount", "max", StoreJs.num(100L))),
            Keys.ed25519(keys.get("orchestrator")), null);
        Map<String, Object> c2 = Issue.delegate(c1, keys.get("service").id(), listOf(
            Issue.obj("type", "resource", "prefix", "/orders/42"), Issue.obj("type", "max_hops", "n", StoreJs.num(4L))), Keys.ed25519(keys.get("tool")), null);
        Map<String, Object> c3 = Issue.delegate(c2, keys.get("leaf").id(), listOf(
            Issue.obj("type", "scope", "actions", listOf("payments.refund")), Issue.obj("type", "max_amount", "max", StoreJs.num(50L))), Keys.ed25519(keys.get("service")), null);
        List<Map<String, Object>> chain = new ArrayList<>(Arrays.asList(root, c1, c2, c3));

        a.record(root);
        Map<String, Object> hA0 = a.publishHead(witnesses, now - 2_000, null);
        a.record(c1);
        Map<String, Object> hA = a.publishHead(witnesses, now - 1_000, null); // size 1 -> 2: consistency-proven by every witness
        b.record(c2);
        c.record(c3);
        Map<String, Object> hB = b.publishHead(witnesses, now - 1_000, null);
        Map<String, Object> hC = c.publishHead(witnesses, now - 1_000, null);
        Map<String, Object> bOrch = a.enroll(keys.get("orchestrator").id(), "orchestrator");
        Map<String, Object> bTool = b.enroll(keys.get("tool").id(), "tool-agent");
        Map<String, Object> bSvc = c.enroll(keys.get("service").id(), "service-agent");

        List<Map<String, Object>> evidence = new ArrayList<>(Arrays.asList(a.evidence(root, hA, null), a.evidence(c1, hA, bOrch), b.evidence(c2, hB, bTool), c.evidence(c3, hC, bSvc)));
        Map<String, Object> action = Issue.obj("type", "payments.refund", "resource", "/orders/42/line/1", "amount", StoreJs.num(25L), "service_domain", c.id,
            "nonce", "n-0001", "at", StoreJs.num(now));
        Map<String, Object> proof = assembleMeshProof(chain, evidence, action, keys.get("leaf"), null);
        List<Object> witnessIds = new ArrayList<>();
        for (MeshWitness w : witnesses) witnessIds.add(w.id);
        Map<String, Object> trust = Issue.obj("humanPrincipal", keys.get("human").id(), "witnesses", witnessIds, "threshold", StoreJs.num(2L), "now", StoreJs.num(now),
            "allowedDomains", listOf(a.id, b.id, c.id), "rootDomain", a.id);

        Map<String, MeshDomain> domains = new LinkedHashMap<>();
        domains.put("A", a);
        domains.put("B", b);
        domains.put("C", c);
        Map<String, Map<String, Object>> heads = new LinkedHashMap<>();
        heads.put("A0", hA0);
        heads.put("A", hA);
        heads.put("B", hB);
        heads.put("C", hC);
        Map<String, Map<String, Object>> bindings = new LinkedHashMap<>();
        bindings.put("orchestrator", bOrch);
        bindings.put("tool", bTool);
        bindings.put("service", bSvc);
        return new Example(trust, proof, evidence, domains, witnesses, keys, chain, heads, bindings);
    }

    private static Map<String, Object> forkCap(Keys.EdKey human, int n) {
        return Issue.mintRoot(Keys.ed25519(human), human.id(), null, listOf(Issue.obj("type", "scope", "actions", listOf("a" + n))));
    }

    /**
     * A worked demonstration that witnesses verify real RFC 9162 consistency: a malicious domain rewrites an early log entry and grows the
     * forked log PAST the size the witness last saw. A size-only check would accept it; the consistency proof (necessarily computed over
     * the forked log) does not. Returns {@code {honest_extension_cosigned, fork_larger_than_prior, size_only_check_would_accept,
     * fork_rejected, fork_reason}}.
     */
    public static Map<String, Object> demonstrateForkRejection() {
        Keys.EdKey k = exampleKey("fork-domain"), hk = exampleKey("fork-human");
        List<MeshWitness> ws = Collections.singletonList(new MeshWitness(exampleKey("fork-witness")));
        MeshDomain honest = new MeshDomain("X", k);
        honest.record(forkCap(hk, 0));
        honest.record(forkCap(hk, 1));
        honest.publishHead(ws, 100, null);
        honest.record(forkCap(hk, 2));
        boolean honestOk = true;
        try {
            honest.publishHead(ws, 200, null);
        } catch (RuntimeException e) {
            honestOk = false;
        }
        long prior = Json.asLong(ws.get(0).lastSeen(honest.id).get("size"));
        MeshDomain fork = new MeshDomain("X", k); // same key, rewritten history (entry 0 differs), grown past the prior size
        for (int n : new int[] {100, 1, 2, 3}) fork.record(forkCap(hk, n));
        String reason = "";
        boolean rejected = false;
        try {
            fork.publishHead(ws, 300, null);
        } catch (RuntimeException e) {
            rejected = true;
            reason = String.valueOf(e.getMessage());
        }
        return Issue.obj("honest_extension_cosigned", honestOk, "fork_larger_than_prior", 4 > prior, "size_only_check_would_accept", 4 >= prior,
            "fork_rejected", rejected, "fork_reason", reason);
    }
}
