package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

    static final double DEFAULT_MAX_HEAD_AGE_MS = 5 * 60_000;
    static final double DEFAULT_MAX_SKEW_MS = 60_000;
    static final long DEFAULT_MAX_CHAIN = 64;
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
        return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
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

    private static boolean narrows(Auth child, Auth parent) {
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
        if (e.hasExp && now > e.expiresAt) return "capability expired";
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
}
