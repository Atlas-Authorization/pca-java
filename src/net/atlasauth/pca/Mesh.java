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
    private static long natV(Object x) { return Json.isSafeInt(x) ? Json.asLong(x) : 0; }
    private static boolean num(Object x) { return IntentJs.isFinite(x); }
    private static double jf(Object x) { Double d = IntentJs.num(x); return d == null ? Double.NaN : d; }

    /** JavaScript === on decoded JSON members (numbers by value; objects and arrays are never equal). */
    private static boolean eq(Object a, Object b) {
        if (a == null || b == null) return a == null && b == null;
        if (a instanceof String || b instanceof String || a instanceof Boolean || b instanceof Boolean) return a.equals(b);
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    private static byte[] msg(String domain, Object body) {
        try {
            return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean sigOk(String pub, byte[] message, String sig) { return message != null && Pca.verifyB64u(pub, message, sig); }

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
        Double d = IntentJs.num(v);
        return d == null ? String.valueOf(v) : jsNum(d);
    }

    private static String jsNum(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0) return "0"; // String(-0) is "0"
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new java.math.BigDecimal(d).toPlainString();
        return IntentJs.shortest(d);
    }

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

    private static final class Auth {
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
    private static Auth effective(Object caveats) {
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

    private static String bindRevRoot(long size, String tree) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("size", IntentJs.ofLong(size));
        m.put("tree", tree);
        try {
            return Pca.b64(Pca.sha(REVSET_PREFIX, Pca.canonBytes(m)));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean leafOk(String root, long size, String id, Map<String, Object> proof) {
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
        String bound = bindRevRoot(size, Pca.b64(h));
        return bound != null && bound.equals(root);
    }

    /** verifyNonMembership over an expanded proof {size, lo?, hi?}. */
    private static boolean nonMembership(String root, Map<String, Object> nm, String id) {
        if (!Json.isSafeInt(nm.get("size")) || Json.asLong(nm.get("size")) < 0) return false;
        long size = Json.asLong(nm.get("size"));
        Map<String, Object> lo = rec(nm.get("lo")), hi = rec(nm.get("hi"));
        if (size == 0) {
            String bound = bindRevRoot(0, Ledger.EMPTY_TREE_ROOT);
            return lo == null && hi == null && bound != null && bound.equals(root);
        }
        if (lo == null && hi == null) return false;
        long loIdx = 0, hiIdx = 0;
        if (lo != null) {
            String loId = str(lo.get("id")) == null ? "" : str(lo.get("id"));
            Map<String, Object> lp = rec(lo.get("proof"));
            if (lp == null || !(Json.compareUtf8(loId, id) < 0) || !leafOk(root, size, loId, lp)) return false;
            loIdx = natV(lp.get("index"));
            if (hi == null && loIdx != size - 1) return false;
        }
        if (hi != null) {
            String hiId = str(hi.get("id")) == null ? "" : str(hi.get("id"));
            Map<String, Object> hp = rec(hi.get("proof"));
            if (hp == null || !(Json.compareUtf8(id, hiId) < 0) || !leafOk(root, size, hiId, hp)) return false;
            hiIdx = natV(hp.get("index"));
            if (lo == null && hiIdx != 0) return false;
        }
        return !(lo != null && hi != null && hiIdx != loIdx + 1);
    }

    /** verifyLedgerConsistency (RFC 9162 section 2.1.4.2), with strict 32-byte base64url hashes. */
    private static boolean consistency(String oldRoot, String newRoot, Map<String, Object> proof) {
        if (!Json.isSafeInt(proof.get("oldSize")) || !Json.isSafeInt(proof.get("newSize"))) return false;
        long first = Json.asLong(proof.get("oldSize")), second = Json.asLong(proof.get("newSize"));
        if (first < 0 || first > second) return false;
        List<?> raw = proof.get("path") instanceof List ? (List<?>) proof.get("path") : new ArrayList<Object>();
        if (raw.size() > MAX_PATH) return false;
        String empty = Ledger.EMPTY_TREE_ROOT;
        if (first == 0) {
            if (!raw.isEmpty() || !oldRoot.equals(empty)) return false;
            if (second == 0) return newRoot.equals(empty);
            return true;
        }
        if (first == second) return raw.isEmpty() && oldRoot.equals(newRoot);
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

    private static String checkHeadAdvance(Object prev, Object next, Object proof) {
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
            if (!consistency((String) p.get("root"), (String) n.get("root"), c)) return "head is not consistent with the previous head (fork or rewrite)";
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
        if (t.containsKey("pqPins")) {
            Map<String, Object> m = rec(t.get("pqPins"));
            if (m != null) {
                c.pqPins = new LinkedHashMap<>();
                for (Map.Entry<String, Object> en : m.entrySet()) if (en.getValue() instanceof String) c.pqPins.put(en.getKey(), en.getValue());
            }
        }
        return c;
    }

    private static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = IntentJs.num(v);
        return d == null || (d != 0 && !d.isNaN());
    }

    private static String checkCosignedHead(Object ch, String expectedDomain, Trust t, Object pinProof) {
        Map<String, Object> chm = rec(ch);
        if (chm == null) chm = new LinkedHashMap<>();
        Map<String, Object> h = rec(chm.get("head"));
        if (h == null || !expectedDomain.equals(h.get("domain"))) return "head is for a different domain";
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
        if (t.pinned != null && t.pinned.containsKey(domain) && truthy(t.pinned.get(domain))) {
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
            Object issuerO = cap.get("issuer");
            String issuer = issuerO instanceof String ? (String) issuerO : "";
            if (i > 0 && t.issuerDoms != null && issuerO instanceof String && t.issuerDoms.containsKey(issuer) && !eq(t.issuerDoms.get(issuer), domain)) {
                return fail("issuer key is pinned to a different domain", i);
            }
            long hi = natV(ev.get("head"));
            Object ch = heads.get((int) hi);
            if (!headDone.contains(hi)) {
                Map<String, Object> chm0 = rec(ch);
                Map<String, Object> headM0 = chm0 == null ? null : rec(chm0.get("head"));
                String dom = headM0 != null && str(headM0.get("domain")) != null ? str(headM0.get("domain")) : "";
                Object pinProof = null;
                if (p.get("pin_proofs") instanceof List) {
                    for (Object x : (List<?>) p.get("pin_proofs")) {
                        Map<String, Object> xm = rec(x);
                        if (xm != null && dom.equals(xm.get("domain"))) { pinProof = xm.get("proof"); break; }
                    }
                }
                headErrs.put(hi, checkCosignedHead(ch, dom, t, pinProof));
                headDone.add(hi);
            }
            Map<String, Object> chm = rec(ch);
            if (chm == null || chm.get("head") == null) return fail("malformed proof", -1); // `ch.head.domain` throws in the reference
            Map<String, Object> headM = rec(chm.get("head"));
            if (headM == null || !domain.equals(headM.get("domain"))) return fail("source-domain anchor: head is for a different domain", i);
            String he = headErrs.get(hi);
            if (!he.isEmpty()) return fail("source-domain anchor: " + he, i);

            Map<String, Object> incl = validInclusion(ev.get("inclusion"));
            if (incl == null || natV(incl.get("size")) != natV(headM.get("size"))) return fail("hop not included in the issuing domain log", i);
            String capDigest;
            try {
                capDigest = Pca.capHash(cap);
            } catch (RuntimeException e) {
                return fail("hop not included in the issuing domain log", i);
            }
            String root = str(headM.get("root")) == null ? "" : str(headM.get("root"));
            if (!Pca.verifyInclusion(root, incl, capDigest)) return fail("hop not included in the issuing domain log", i);

            if (i > 0) {
                Map<String, Object> b = rec(ev.get("binding"));
                String role = b == null ? null : str(b.get("role")), bsig = b == null ? null : str(b.get("sig"));
                if (b == null || role == null || bsig == null || !eq(b.get("agent"), cap.get("issuer")) || !eq(b.get("domain"), ev.get("domain"))) {
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
            String id = str(cap.get("id")) == null ? "" : str(cap.get("id"));
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
        String holder = str(tip.get("holder")) == null ? "" : str(tip.get("holder"));
        Map<String, Object> ab = new LinkedHashMap<>();
        ab.put("action", action);
        ab.put("tip", tipHash);
        if (!sigOk(holder, msg(ACTION_DOMAIN, ab), actionSig)) return fail("action not signed by the chain tip holder", -1);
        String denied = admits(prev, action, t.now, chain.size());
        if (!denied.isEmpty()) return fail("action not admitted: " + denied, -1);
        return new Verdict(true, "", -1);
    }
}
