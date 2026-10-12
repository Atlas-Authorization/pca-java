package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * Reference verifier for the CORE PCActn checks, wire format v2. Byte-matches @atlasauth/pca.
 * Normative check order: wire, version, audience, validity, chain, plan_inclusion, leaf_signature, counter
 * (wire failure is terminal). Requires BouncyCastle (bcprov-jdk18on, org.bouncycastle.math.ec.rfc8032.Ed25519).
 */
public final class Pca {
    private Pca() {}

    public static final int WIRE_VERSION = 2;
    public static final int MAX_CHAIN_HOPS = 16;
    /** Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain. */
    public static final int MAX_CAVEATS_PER_HOP = 256;
    public static final int MAX_CAVEATS_PER_CHAIN = 1024;
    /** Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing. */
    public static final int MAX_ARTIFACT_BYTES = 524288;
    public static final String ARTIFACT_SIZE_REASON = "artifact exceeds size limit (max " + MAX_ARTIFACT_BYTES + " bytes)";

    /** True when the raw document exceeds MAX_ARTIFACT_BYTES UTF-8 bytes (O(1) for clearly small/large strings). */
    public static boolean artifactTooLarge(String text) {
        if (text.length() > MAX_ARTIFACT_BYTES) return true;
        if ((long) text.length() * 3 <= MAX_ARTIFACT_BYTES) return false;
        return text.getBytes(StandardCharsets.UTF_8).length > MAX_ARTIFACT_BYTES;
    }
    public static final String CAVEAT_LIMIT_REASON =
        "chain exceeds caveat limit (max " + MAX_CAVEATS_PER_HOP + " per hop, " + MAX_CAVEATS_PER_CHAIN + " per chain)";

    /** True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work. */
    static boolean caveatLimitExceeded(List<Object> chain) {
        long total = 0;
        for (Object c : chain) {
            if (!(c instanceof Map)) continue;
            Object cv = ((Map<?, ?>) c).get("caveats");
            int n = cv instanceof List ? ((List<?>) cv).size() : 0;
            if (n > MAX_CAVEATS_PER_HOP) return true;
            total += n;
            if (total > MAX_CAVEATS_PER_CHAIN) return true;
        }
        return false;
    }
    public static final long MAX_LIFETIME_MS = 3_600_000L;
    public static final long MAX_SKEW_MS = 60_000L;
    public static final int MAX_AUD_LEN = 256;
    public static final int MAX_NONCE_LEN = 128;

    static final byte[] SIG_DOMAIN = "atlas-pca/actn/v2\0".getBytes(StandardCharsets.UTF_8);
    static final byte[] CAP_DOMAIN = "atlas-pca/cap/v1\0".getBytes(StandardCharsets.UTF_8);
    static final String DEFAULT_REV = "reversible";

    /** `checks` holds, in normative order, wire alone (wire failure) or all eight checks. */
    public static final class Verdict {
        public boolean allow;
        public final Map<String, Boolean> checks = new LinkedHashMap<>();
        public String reason = "";
        Verdict() {}
        void fail(String name, String why) {
            checks.put(name, false);
            if (reason.isEmpty()) reason = name + ": " + why;
        }
    }

    // ---- helpers ----
    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /**
     * Strict base64url (RFC 4648 s5): alphabet A-Za-z0-9-_ only, no padding / whitespace, len % 4 != 1, zero
     * trailing bits (re-encode must reproduce the input). `len` &gt;= 0 additionally pins the decoded byte length.
     * Returns null when invalid.
     */
    public static byte[] decodeB64uStrict(Object o, int len) {
        if (!(o instanceof String)) return null;
        String s = (String) o;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return null;
        }
        if (s.length() % 4 == 1) return null;
        if (len >= 0 && s.length() != (len * 4 + 2) / 3) return null;
        byte[] b;
        try { b = Base64.getUrlDecoder().decode(s); } catch (IllegalArgumentException e) { return null; }
        if (!b64(b).equals(s)) return null; // non-canonical trailing bits
        if (len >= 0 && b.length != len) return null;
        return b;
    }

    static byte[] sha(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : new ArrayList<>();
    }

    static String asStr(Object o) { return o instanceof String ? (String) o : ""; }

    /**
     * Canonical bytes of every protocol digest (capHash / hop body digest, Merkle leaves, params/conditions digests, the
     * signer-set hash): the STRICT form, exactly as hash.ts canonicalBytes. An out-of-profile value (nesting deeper than
     * {@link Json#MAX_DEPTH}, a non-canonical number, a lone surrogate) throws here (fail closed) instead of hashing under
     * the lenient form that the reference never produces.
     */
    static byte[] canonBytes(Object v) { return Json.canonicalizeStrict(v).getBytes(StandardCharsets.UTF_8); }

    public static String hashCanonical(Object v) { return b64(sha(canonBytes(v))); }

    /** base64url(sha256(strictCanonical(v))). */
    public static String hashStrict(Object v) { return b64(sha(Json.canonicalizeStrict(v).getBytes(StandardCharsets.UTF_8))); }

    // ---- Merkle ----
    static byte[] leafHash(Object leaf) { return sha(new byte[] {0x00}, canonBytes(leaf)); }

    static byte[] nodeHash(byte[] l, byte[] r) { return sha(new byte[] {0x01}, l, r); }

    public static String merkleRoot(List<Object> leaves) {
        if (leaves.isEmpty()) throw new IllegalArgumentException("empty leaf set");
        List<byte[]> hs = new ArrayList<>();
        for (Object l : leaves) hs.add(leafHash(l));
        return b64(build(hs));
    }

    static int split(int n) { int k = 1; while (k * 2 < n) k *= 2; return k; }

    static byte[] build(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = split(hs.size());
        return nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size())));
    }

    /** Sibling sides (leaf to root) for leaf `index` of `size` leaves (RFC 6962 split). Requires 0 &lt;= index &lt; size. */
    static List<String> pathShape(long index, long size) {
        List<String> out = new ArrayList<>();
        long idx = index, n = size;
        while (n > 1) {
            long k = 1;
            while (k * 2 < n) k *= 2;
            if (idx < k) { out.add("R"); n = k; }
            else { out.add("L"); idx -= k; n -= k; }
        }
        java.util.Collections.reverse(out);
        return out;
    }

    /** Never throws; malformed proofs return false. index/size are bound to the path shape. */
    public static boolean verifyInclusion(String root, Map<String, Object> proof, Object leaf) {
        try {
            if (proof == null || !(proof.get("path") instanceof List)) return false;
            if (!Json.isSafeInt(proof.get("index")) || !Json.isSafeInt(proof.get("size"))) return false;
            long index = Json.asLong(proof.get("index")), size = Json.asLong(proof.get("size"));
            if (size < 1 || index < 0 || index >= size) return false;
            List<String> shape = pathShape(index, size);
            List<Object> path = asList(proof.get("path"));
            if (shape.size() != path.size()) return false;
            byte[] h = leafHash(leaf);
            for (int i = 0; i < path.size(); i++) {
                if (!(path.get(i) instanceof Map)) return false;
                Map<String, Object> step = asMap(path.get(i));
                if (!shape.get(i).equals(step.get("side"))) return false;
                byte[] sib = decodeB64uStrict(step.get("hash"), 32);
                if (sib == null) return false;
                h = shape.get(i).equals("L") ? nodeHash(sib, h) : nodeHash(h, sib);
            }
            return b64(h).equals(root);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static String paramsDigest(Object params) {
        return hashCanonical(params == null ? new LinkedHashMap<String, Object>() : params);
    }

    static String conditionsDigest(Object pre, Object post) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pre", pre);
        m.put("post", post);
        return hashCanonical(m);
    }

    static Map<String, Object> planLeaf(Object nodeId, Map<String, Object> action, String cond) {
        if (nodeId == null) throw new IllegalArgumentException("missing node_id");
        Object pd = action.get("params_digest");
        if (pd == null) pd = paramsDigest(null);
        Object rc = action.get("reversibility_class");
        if (rc == null) rc = DEFAULT_REV;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("node_id", nodeId);
        m.put("verb", action.get("verb"));
        m.put("resource", action.get("resource"));
        m.put("params_digest", pd);
        m.put("reversibility_class", rc);
        m.put("conditions", cond);
        return m;
    }

    // ---- Ed25519 (strict RFC 8032) ----
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    /** y-coordinates of every small-order point: identity (1), order 2 (p-1), order 4 (0), order 8 (two values). */
    private static final BigInteger[] SMALL_ORDER_Y = {
        BigInteger.ONE,
        P.subtract(BigInteger.ONE),
        BigInteger.ZERO,
        new BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
        new BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16),
    };

    private static BigInteger leInt(byte[] b, int off, int len, boolean clearTopBit) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) be[len - 1 - i] = b[off + i];
        if (clearTopBit) be[0] &= 0x7f;
        return new BigInteger(1, be);
    }

    /** True iff the 32-byte point encoding has a non-canonical y (>= p) or is one of the small-order points. */
    static boolean badPointEncoding(byte[] b, int off) {
        BigInteger y = leInt(b, off, 32, true); // sign bit ignored: both x signs share the same y
        if (y.compareTo(P) >= 0) return true;
        for (BigInteger s : SMALL_ORDER_Y) if (y.equals(s)) return true;
        return false;
    }

    /**
     * Strict Ed25519 verify: rejects non-canonical S (>= L), non-canonical y, small-order and mixed-order
     * public keys AND R (explicit small-order table + BouncyCastle full subgroup validation), then verifies.
     */
    static boolean ed25519Strict(byte[] pk, byte[] msg, byte[] sig) {
        try {
            if (pk == null || sig == null || pk.length != 32 || sig.length != 64) return false;
            if (badPointEncoding(pk, 0) || badPointEncoding(sig, 0)) return false;
            if (leInt(sig, 32, 32, false).compareTo(L) >= 0) return false;
            if (!Ed25519.validatePublicKeyFull(pk, 0)) return false;
            if (!Ed25519.validatePublicKeyFull(sig, 0)) return false;
            return Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length);
        } catch (RuntimeException e) {
            return false;
        }
    }

    static boolean verifyB64u(String pub, byte[] msg, String sig) {
        byte[] pk = decodeB64uStrict(pub, 32);
        byte[] sg = decodeB64uStrict(sig, 64);
        if (pk == null || sg == null) return false;
        return ed25519Strict(pk, msg, sg);
    }

    // ---- capability chain ----
    public static String capHash(Map<String, Object> c) { return hashCanonical(c); }

    static Map<String, Object> bodyOf(Map<String, Object> c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", c.get("issuer"));
        m.put("holder", c.get("holder"));
        m.put("caveats", c.get("caveats"));
        m.put("parent", c.get("parent"));
        if (c.containsKey("holder_pq")) m.put("holder_pq", c.get("holder_pq"));
        return m;
    }

    /**
     * bodyOf + the suite fields (alg, pq_pk) bound in for a non-default suite (so a downgrade or ML-DSA
     * key-swap breaks the hop digest), byte-identical to bodyOf for ed25519. Mirrors signableBody in
     * capability.ts. Returns null for an unknown alg (fail-closed).
     */
    static Map<String, Object> signableHopBody(Map<String, Object> c) {
        boolean algPresent = c.containsKey("alg");
        Pq.Suite suite = Pq.resolveSigAlg(c.get("alg"), algPresent);
        if (suite == null) return null;
        Map<String, Object> body = bodyOf(c);
        if (!suite.alg.equals("ed25519")) {
            body.put("alg", suite.alg);
            if (suite.needsPqPk && c.get("pq_pk") instanceof String) body.put("pq_pk", c.get("pq_pk"));
        }
        return body;
    }

    static final byte[] HOLDER_PQ_DOMAIN = "atlas-pca/holder-pq/v1\0".getBytes(StandardCharsets.UTF_8);

    /** holder_pq commitment: b64u(sha256(domain || utf8(pq_pk string))). Mirrors holderPqCommitment in capability.ts. */
    static String holderPqCommitment(String pqPk) {
        return b64(sha(HOLDER_PQ_DOMAIN, pqPk.getBytes(StandardCharsets.UTF_8)));
    }

    /** F-2: a PQ-key suite (ml-dsa-65 / hybrid) is accepted only under the pq_pk the signer's holder committed to. Returns null when fine. */
    static String pqBindingError(Object alg, boolean algPresent, Object pqPk, Object committed, String label) {
        Pq.Suite suite = Pq.resolveSigAlg(alg, algPresent);
        if (suite == null || !suite.needsPqPk) return null;
        if (!(committed instanceof String))
            return label + ": suite '" + suite.alg + "' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)";
        if (!(pqPk instanceof String) || !holderPqCommitment((String) pqPk).equals(committed))
            return label + ": pq_pk does not match the signer's committed holder_pq (F-2)";
        return null;
    }

    /** allowedSuites policy (absent alg == ed25519); null list == no policy. Returns null when fine. */
    static String suitePolicyError(Object alg, boolean algPresent, String label, List<String> allowed) {
        if (allowed == null) return null;
        String a = algPresent ? (alg instanceof String ? (String) alg : null) : "ed25519";
        return a != null && allowed.contains(a) ? null : label + ": signature suite is not allowed by this verifier's suite policy";
    }

    /** Returns "" when OK, else an error label. */
    static String checkSig(Map<String, Object> c, String signer, String label, Pq.PinnedPq pq) {
        // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
        Map<String, Object> body = signableHopBody(c);
        if (body == null) return label + ": unknown signature alg '" + String.valueOf(c.get("alg")) + "'";
        String digest;
        try { digest = hashCanonical(body); } catch (RuntimeException e) { return label + ": malformed body"; }
        String bd = asStr(c.get("body_digest"));
        String id = asStr(c.get("id"));
        if (!digest.equals(bd) || !id.equals(bd)) return label + ": body digest mismatch";
        byte[] raw = decodeB64uStrict(bd, 32);
        if (raw == null) return label + ": bad signature (not signed by expected key)";
        // Suite-agile hop verification (mirrors verifyLeafSuite): ed25519 == verifyB64u(signer, msg, sig);
        // hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under the resolved key);
        // pure ml-dsa-65 verifies `sig` under the resolved key (never the hop's own pq_pk). The signer is the expected Ed25519 key.
        boolean ok = Pq.verifyLeafSuite(c.get("alg"), c.containsKey("alg"), signer, pq,
            concat(CAP_DOMAIN, raw), c.get("sig"), c.get("pq_sig"));
        if (!ok) return label + ": bad signature (not signed by expected key)";
        return "";
    }

    static final String ROOT_PQ_PIN_REASON_FMT = "hop 0: root suite '%s' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";

    /** Root PQ authority (mirrors rootPq in capability.ts): a verifier-side pin or the verifier's own stored copy of the root. */
    private static Object[] resolveRootPq(Map<String, Object> root, Map<String, Object> pqPins, Map<String, Object> trustedRoot) {
        Pq.Suite suite = Pq.resolveSigAlg(root.get("alg"), root.containsKey("alg"));
        if (suite == null || !suite.needsPqPk) return new Object[] {null, null};
        Object pk = root.get("pq_pk");
        String trusted = null;
        if (trustedRoot != null && pk instanceof String) {
            try { if (capHash(trustedRoot).equals(capHash(root))) trusted = (String) pk; } catch (RuntimeException e) { trusted = null; }
        }
        Object issuer = root.get("issuer");
        Pq.PinnedPq key = Pq.resolvePqKey(issuer instanceof String ? (String) issuer : null, pk, null, pqPins, trusted);
        if (key == null) return new Object[] {null, String.format(ROOT_PQ_PIN_REASON_FMT, suite.alg)};
        return new Object[] {key, null};
    }

    /** Backward-compatible overload: no PQ pins, no trusted root (a PQ root is then refused). */
    public static String verifyChain(List<Object> chain, String expectedRootIssuer, boolean haveIssuer, List<String> allowed) {
        return verifyChain(chain, expectedRootIssuer, haveIssuer, allowed, null, null);
    }

    /**
     * Standalone chain verification. Returns "" when valid, else the failure reason. R4-01: a non-ed25519 (pure-PQ or
     * hybrid) ROOT is accepted only if {@code pqPins[root.issuer]} equals the root's pq_pk, or {@code trustedRoot} is the
     * root itself (the verifier's own stored grant); otherwise it is refused. The 16-hop cap is enforced BEFORE any signature work.
     */
    public static String verifyChain(List<Object> chain, String expectedRootIssuer, boolean haveIssuer, List<String> allowed,
                                     Map<String, Object> pqPins, Map<String, Object> trustedRoot) {
        // TOTAL (R6-05): a hostile chain is a refusal, never an exception.
        try {
            return verifyChainUnchecked(chain, expectedRootIssuer, haveIssuer, allowed, pqPins, trustedRoot);
        } catch (RuntimeException ex) {
            return "malformed capability chain: " + ex.getClass().getSimpleName();
        }
    }

    /**
     * Mirrors {@code wellTyped} in capability.ts: id/issuer/holder/body_digest/sig are strings; alg/pq_pk/pq_sig/holder_pq/
     * parent are absent or strings (JSON null is NOT absent); caveats is a list of objects each with a string {@code type}.
     */
    static boolean wellTyped(Object o) {
        if (!(o instanceof Map)) return false;
        Map<?, ?> c = (Map<?, ?>) o;
        for (String k : new String[] {"id", "issuer", "holder", "body_digest", "sig"}) if (!(c.get(k) instanceof String)) return false;
        for (String k : new String[] {"alg", "pq_pk", "pq_sig", "holder_pq", "parent"}) if (c.containsKey(k) && !(c.get(k) instanceof String)) return false;
        if (!(c.get("caveats") instanceof List)) return false;
        for (Object cv : (List<?>) c.get("caveats")) if (!(cv instanceof Map) || !(((Map<?, ?>) cv).get("type") instanceof String)) return false;
        return true;
    }

    private static String verifyChainUnchecked(List<Object> chain, String expectedRootIssuer, boolean haveIssuer, List<String> allowed,
                                               Map<String, Object> pqPins, Map<String, Object> trustedRoot) {
        if (chain == null || chain.isEmpty()) return "empty chain";
        if (chain.size() > MAX_CHAIN_HOPS) return "chain too long (max " + MAX_CHAIN_HOPS + " hops)";
        if (caveatLimitExceeded(chain)) return CAVEAT_LIMIT_REASON;
        for (int i = 0; i < chain.size(); i++)
            if (!wellTyped(chain.get(i))) return "hop " + i + ": malformed capability";
        Map<String, Object> root = asMap(chain.get(0));
        if (root.containsKey("parent")) return "hop 0: root must not have a parent";
        if (haveIssuer && !Objects.equals(root.get("issuer"), expectedRootIssuer))
            return "hop 0: root issuer is not the expected principal";
        String pol0 = suitePolicyError(root.get("alg"), root.containsKey("alg"), "hop 0", allowed);
        if (pol0 != null) return pol0;
        Object[] rp = resolveRootPq(root, pqPins, trustedRoot);
        if (rp[1] != null) return (String) rp[1];
        String e = checkSig(root, asStr(root.get("issuer")), "hop 0", (Pq.PinnedPq) rp[0]);
        if (!e.isEmpty()) return e;
        for (int i = 1; i < chain.size(); i++) {
            String label = "hop " + i;
            Map<String, Object> parent = asMap(chain.get(i - 1));
            Map<String, Object> c = asMap(chain.get(i));
            String ph;
            try { ph = capHash(parent); } catch (RuntimeException ex) { return label + ": broken parent link"; }
            if (!Objects.equals(c.get("parent"), ph)) return label + ": broken parent link";
            if (!Objects.equals(c.get("issuer"), parent.get("holder"))) return label + ": issuer is not the parent's bound holder";
            String pol = suitePolicyError(c.get("alg"), c.containsKey("alg"), label, allowed);
            if (pol != null) return pol;
            String unb = pqBindingError(c.get("alg"), c.containsKey("alg"), c.get("pq_pk"), parent.get("holder_pq"), label);
            if (unb != null) return unb;
            e = checkSig(c, asStr(parent.get("holder")), label,
                Pq.resolvePqKey(parent.get("holder") instanceof String ? (String) parent.get("holder") : null, c.get("pq_pk"), parent.get("holder_pq"), null, null));
            if (!e.isEmpty()) return e;
            List<Object> pc = asList(parent.get("caveats"));
            List<Object> cc = asList(c.get("caveats"));
            if (cc.size() < pc.size()) return label + ": drops parent caveat(s)";
            for (int j = 0; j < pc.size(); j++) {
                boolean same;
                try { same = hashCanonical(cc.get(j)).equals(hashCanonical(pc.get(j))); } catch (RuntimeException ex) { same = false; }
                if (!same) return label + ": caveat " + j + " altered or reordered";
            }
        }
        return "";
    }

    // ---- wire format v2 ----
    private static final List<String> REQUIRED = java.util.Arrays.asList(
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness",
        "counter", "risk_claim", "aud", "iat", "exp", "sig");
    private static final List<String> OPTIONAL = java.util.Arrays.asList(
        "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
        "threshold", "zk_compliance", "bond_ref",
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        "alg", "pq_pk", "pq_sig");

    /** Length unit for aud / nonce limits is UTF-8 BYTES. */
    private static int utf8Len(String s) { return s.getBytes(StandardCharsets.UTF_8).length; }

    /**
     * Closed capability-hop key set (parent optional). The B4 crypto-agility fields (alg/pq_pk/pq_sig) are
     * additive on a hop exactly as at the top level: absent alg == ed25519 (pq_pk/pq_sig forbidden, byte-identical).
     */
    private static final List<String> CAP_KEYS = java.util.Arrays.asList("id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig", "holder_pq");

    private static boolean isObj(Object o) { return o instanceof Map; }
    private static boolean isStr(Object o) { return o instanceof String; }

    private static String closedKeys(Map<String, Object> m, String where, String... allowed) {
        List<String> ok = Arrays.asList(allowed);
        for (String k : m.keySet()) if (!ok.contains(k)) return "unknown field '" + where + "." + k + "'";
        return null;
    }

    /** Wire v2 structural + lexical validation. Returns null when well-formed, else a short reason. Never throws. */
    @SuppressWarnings("unchecked")
    public static String validateWireV2(Object po) {
        try {
            if (!isObj(po)) return "PCActn is not an object";
            Map<String, Object> p = (Map<String, Object>) po;
            for (String k : p.keySet()) if (!REQUIRED.contains(k) && !OPTIONAL.contains(k)) return "unknown field '" + k + "'";
            for (String k : REQUIRED) if (!p.containsKey(k)) return "missing field '" + k + "'";
            // every signed byte must admit the strict canonical encoding (sig/threshold/pq_sig are unsigned)
            Map<String, Object> body = new LinkedHashMap<>(p);
            body.remove("sig");
            body.remove("threshold");
            body.remove("pq_sig");
            try { Json.canonicalizeStrict(body); } catch (RuntimeException e) { return e.getMessage(); }

            if (!Json.isSafeInt(p.get("ver"))) return "'ver' must be a safe integer";
            if (!Json.isSafeInt(p.get("counter"))) return "'counter' must be a safe integer";
            if (!Json.isSafeInt(p.get("iat"))) return "'iat' must be a safe integer";
            if (!Json.isSafeInt(p.get("exp"))) return "'exp' must be a safe integer";
            Object aud = p.get("aud");
            if (!isStr(aud) || ((String) aud).isEmpty() || utf8Len((String) aud) > MAX_AUD_LEN) return "'aud' must be a non-empty string";
            if (p.containsKey("nonce")) {
                Object n = p.get("nonce");
                if (!isStr(n) || ((String) n).isEmpty() || utf8Len((String) n) > MAX_NONCE_LEN) return "'nonce' must be a non-empty string";
            }
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. With no `alg` this asserts exactly
            // the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent. Unknown `alg` fails closed.
            String sigWire = Pq.validateSignatureWire(p);
            if (sigWire != null) return sigWire;
            if (decodeB64uStrict(p.get("grant_ref"), 32) == null) return "'grant_ref' is not canonical base64url (32 bytes)";

            if (!isObj(p.get("action"))) return "'action' must be an object";
            Map<String, Object> a = (Map<String, Object>) p.get("action");
            String e = closedKeys(a, "action", "verb", "resource", "params_digest", "reversibility_class");
            if (e != null) return e;
            if (!isStr(a.get("verb")) || !isStr(a.get("resource")) || !isStr(a.get("reversibility_class")))
                return "action.verb/resource/reversibility_class must be strings";
            if (decodeB64uStrict(a.get("params_digest"), 32) == null) return "'action.params_digest' is not canonical base64url (32 bytes)";

            if (!isObj(p.get("plan"))) return "'plan' must be an object";
            Map<String, Object> pl = (Map<String, Object>) p.get("plan");
            e = closedKeys(pl, "plan", "root", "inclusion_proof", "node_id", "conditions_digest");
            if (e != null) return e;
            if (decodeB64uStrict(pl.get("root"), 32) == null) return "'plan.root' is not canonical base64url (32 bytes)";
            if (!isStr(pl.get("node_id"))) return "'plan.node_id' must be a string";
            if (pl.containsKey("conditions_digest") && decodeB64uStrict(pl.get("conditions_digest"), 32) == null)
                return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
            if (!isObj(pl.get("inclusion_proof"))) return "'plan.inclusion_proof' must be an object";
            Map<String, Object> ip = (Map<String, Object>) pl.get("inclusion_proof");
            e = closedKeys(ip, "plan.inclusion_proof", "index", "size", "path");
            if (e != null) return e;
            if (!Json.isSafeInt(ip.get("index"))) return "'plan.inclusion_proof.index' must be a safe integer";
            if (!Json.isSafeInt(ip.get("size"))) return "'plan.inclusion_proof.size' must be a safe integer";
            if (!(ip.get("path") instanceof List)) return "'plan.inclusion_proof.path' must be an array";
            List<Object> path = (List<Object>) ip.get("path");
            for (int i = 0; i < path.size(); i++) {
                if (!isObj(path.get(i))) return "proof step " + i + " must be an object";
                Map<String, Object> st = (Map<String, Object>) path.get(i);
                for (String k : st.keySet()) if (!k.equals("side") && !k.equals("hash")) return "unknown field 'path[" + i + "]." + k + "'";
                if (!"L".equals(st.get("side")) && !"R".equals(st.get("side"))) return "proof step " + i + ": side must be 'L' or 'R'";
                if (decodeB64uStrict(st.get("hash"), 32) == null) return "proof step " + i + ": hash is not canonical base64url (32 bytes)";
            }

            if (!(p.get("cap_chain") instanceof List)) return "'cap_chain' must be an array";
            List<Object> chain = (List<Object>) p.get("cap_chain");
            for (int i = 0; i < chain.size(); i++) {
                if (!isObj(chain.get(i))) return "cap_chain[" + i + "] must be an object";
                Map<String, Object> c = (Map<String, Object>) chain.get(i);
                for (String k : c.keySet())
                    if (!CAP_KEYS.contains(k)) return "unknown field 'cap_chain[" + i + "]." + k + "'";
                for (String k : new String[] {"id", "issuer", "holder", "body_digest"})
                    if (decodeB64uStrict(c.get(k), 32) == null) return "cap_chain[" + i + "]." + k + " is not canonical base64url (32 bytes)";
                // B4 crypto-agility: validate the hop's alg/sig/pq_pk/pq_sig per suite, exactly as the leaf.
                // Absent alg asserts a 64-byte sig and that pq_pk/pq_sig are absent (byte-identical pre-B4 hop).
                String hopSigWire = Pq.validateSignatureWire(c);
                if (hopSigWire != null) return "cap_chain[" + i + "]: " + hopSigWire;
                if (c.containsKey("parent") && decodeB64uStrict(c.get("parent"), 32) == null)
                    return "cap_chain[" + i + "].parent is not canonical base64url (32 bytes)";
                if (c.containsKey("holder_pq") && decodeB64uStrict(c.get("holder_pq"), 32) == null)
                    return "cap_chain[" + i + "].holder_pq is not canonical base64url (32 bytes)";
                if (!(c.get("caveats") instanceof List)) return "cap_chain[" + i + "].caveats must be an array of {type,...} objects";
                for (Object cv : (List<Object>) c.get("caveats"))
                    if (!isObj(cv) || !isStr(((Map<String, Object>) cv).get("type")))
                        return "cap_chain[" + i + "].caveats must be an array of {type,...} objects";
            }

            if (!isObj(p.get("attestation"))) return "'attestation' must be an object with an integer 'epoch'";
            Map<String, Object> at = (Map<String, Object>) p.get("attestation");
            if (!Json.isSafeInt(at.get("epoch"))) return "'attestation' must be an object with an integer 'epoch'";
            if (!isStr(at.get("quote_digest")) || !isStr(at.get("model_id")) || !isStr(at.get("measurement")) || !isStr(at.get("operator")))
                return "attestation string fields must be strings";
            if (!isObj(p.get("provenance"))) return "'provenance' is malformed";
            Map<String, Object> pv = (Map<String, Object>) p.get("provenance");
            if (!isStr(pv.get("causal_hash")) || !Json.isStrictNumber(pv.get("taint_level")) || !(pv.get("trusted_refs") instanceof List))
                return "'provenance' is malformed";
            for (Object r : (List<Object>) pv.get("trusted_refs")) if (!isStr(r)) return "'provenance' is malformed";
            if (!isObj(p.get("freshness"))) return "'freshness' is malformed";
            Map<String, Object> fr = (Map<String, Object>) p.get("freshness");
            if (!Json.isSafeInt(fr.get("epoch")) || !isStr(fr.get("beacon_ref")) || !isStr(fr.get("accumulator_witness"))) return "'freshness' is malformed";
            if (!isObj(p.get("risk_claim"))) return "'risk_claim' is malformed";
            Map<String, Object> rc = (Map<String, Object>) p.get("risk_claim");
            if (!Json.isStrictNumber(rc.get("r")) || !isObj(rc.get("inputs"))) return "'risk_claim' is malformed";

            if (p.containsKey("caution")) {
                Object c = p.get("caution");
                if (!Json.isStrictNumber(c)) return "'caution' must be a number in [0,1]";
                java.math.BigDecimal d = Json.asDecimal(c);
                if (d.signum() < 0 || d.compareTo(java.math.BigDecimal.ONE) > 0) return "'caution' must be a number in [0,1]";
            }
            if (p.containsKey("rationale_commitment") && decodeB64uStrict(p.get("rationale_commitment"), 32) == null)
                return "'rationale_commitment' is not canonical base64url (32 bytes)";
            if (p.containsKey("tool_binding") && decodeB64uStrict(p.get("tool_binding"), 32) == null)
                return "'tool_binding' is not canonical base64url (32 bytes)";
            if (p.containsKey("progress_step") && !isObj(p.get("progress_step"))) return "'progress_step' must be an object";
            if (p.containsKey("prohibition_evidence") && !isObj(p.get("prohibition_evidence")) && !(p.get("prohibition_evidence") instanceof List))
                return "'prohibition_evidence' must be an object or array";
            if (p.containsKey("threshold")) {
                if (!isObj(p.get("threshold")) || !(((Map<String, Object>) p.get("threshold")).get("shares") instanceof List))
                    return "'threshold' must be {shares:[...]}";
                List<Object> shares = (List<Object>) ((Map<String, Object>) p.get("threshold")).get("shares");
                for (int i = 0; i < shares.size(); i++) {
                    if (!isObj(shares.get(i)) || !isStr(((Map<String, Object>) shares.get(i)).get("role"))) return "threshold.shares[" + i + "] is malformed";
                    Map<String, Object> sh = (Map<String, Object>) shares.get(i);
                    if (decodeB64uStrict(sh.get("publicKey"), 32) == null) return "threshold.shares[" + i + "].publicKey is not canonical base64url (32 bytes)";
                    if (decodeB64uStrict(sh.get("sig"), 64) == null) return "threshold.shares[" + i + "].sig is not canonical base64url (64 bytes)";
                }
            }
            return null;
        } catch (RuntimeException e) {
            return "malformed: " + e;
        }
    }

    // ---- PCActn ----
    /** Signed message: "atlas-pca/actn/v2\0" || sha256(strictCanonical(body without sig/threshold/pq_sig)). */
    public static byte[] thresholdMessage(Map<String, Object> p) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (Map.Entry<String, Object> en : p.entrySet()) {
            String k = en.getKey();
            // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
            if (!k.equals("sig") && !k.equals("threshold") && !k.equals("pq_sig")) body.put(k, en.getValue());
        }
        return concat(SIG_DOMAIN, sha(Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8)));
    }

    /** Verify raw PCActn JSON text: strict-profile parse first (any failure, or a non-object, is a wire failure). */
    public static Verdict verifyPcactnJson(String text, Map<String, Object> grant, long now, String audience) {
        return verifyPcactnJson(text, grant, now, audience, null);
    }

    /** As above with an optional allowed-suites policy (null = none; an empty list refuses every suite). */
    public static Verdict verifyPcactnJson(String text, Map<String, Object> grant, long now, String audience, List<String> allowedSuites) {
        if (text != null && artifactTooLarge(text)) { // FIRST: before any parsing (null: refused by the strict parse below)
            Verdict big = new Verdict();
            big.fail("wire", ARTIFACT_SIZE_REASON);
            return big;
        }
        Object parsed;
        try {
            parsed = Json.parse(text);
        } catch (RuntimeException e) {
            Verdict v = new Verdict();
            v.fail("wire", "strict JSON: " + e.getMessage());
            return v;
        }
        return verifyPcactn(parsed, grant, now, audience, allowedSuites);
    }

    /**
     * Verify a parsed PCActn (Json.parse / parseLenient tree). Check order: wire (terminal), version, audience,
     * validity, chain, plan_inclusion, leaf_signature, counter. allow = every check true.
     */
    public static Verdict verifyPcactn(Object pcactn, Map<String, Object> grant, long now, String audience) {
        return verifyPcactn(pcactn, grant, now, audience, null);
    }

    /** As above with an optional allowed-suites policy (null = none; an empty list refuses every suite). */
    public static Verdict verifyPcactn(Object pcactn, Map<String, Object> grant, long now, String audience, List<String> allowedSuites) {
        // TOTAL (R6-05): any residual fault on hostile input is a terminal wire refusal, never an exception.
        try {
            return verifyPcactnUnchecked(pcactn, grant, now, audience, allowedSuites);
        } catch (RuntimeException ex) {
            Verdict w = new Verdict();
            w.fail("wire", "malformed input (" + ex.getClass().getSimpleName() + ")");
            return w;
        }
    }

    private static Verdict verifyPcactnUnchecked(Object pcactn, Map<String, Object> grant, long now, String audience, List<String> allowedSuites) {
        Verdict v = new Verdict();
        String wire = validateWireV2(pcactn);
        if (wire != null) {
            v.fail("wire", wire);
            return v;
        }
        Map<String, Object> p = asMap(pcactn);
        v.checks.put("wire", true);
        try {
            // version
            if (Json.asLong(p.get("ver")) == WIRE_VERSION) v.checks.put("version", true);
            else v.fail("version", "unsupported ver (this verifier requires " + WIRE_VERSION + ")");

            // audience
            if (audience != null && audience.equals(p.get("aud"))) v.checks.put("audience", true);
            else v.fail("audience", "aud does not match this resource server / instance");

            // validity
            long iat = Json.asLong(p.get("iat")), exp = Json.asLong(p.get("exp"));
            if (!(exp > iat)) v.fail("validity", "exp must be greater than iat");
            else if (exp - iat > MAX_LIFETIME_MS) v.fail("validity", "lifetime exceeds " + MAX_LIFETIME_MS + " ms");
            else if (iat > now + MAX_SKEW_MS) v.fail("validity", "iat is in the future (clock skew)");
            else if (now > exp) v.fail("validity", "the PCActn has expired");
            else v.checks.put("validity", true);

            // chain (<= 16 hops, checked before any signature work; root == grant)
            List<Object> chain = asList(p.get("cap_chain"));
            String why;
            if (chain.isEmpty()) why = "empty chain";
            else if (chain.size() > MAX_CHAIN_HOPS) why = "chain too long (max " + MAX_CHAIN_HOPS + " hops)";
            else if (caveatLimitExceeded(chain)) why = CAVEAT_LIMIT_REASON;
            else if (!capHash(asMap(chain.get(0))).equals(capHash(grant))) why = "chain root is not the grant";
            else why = verifyChain(chain, asStr(grant.get("issuer")), grant.get("issuer") instanceof String, allowedSuites, null, grant); // chain[0] == grant checked above
            if (why.isEmpty()) v.checks.put("chain", true); else v.fail("chain", why);

            // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
            // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
            // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
            Object gref = p.get("grant_ref");
            Object rootId = !chain.isEmpty() && chain.get(0) instanceof Map ? ((Map<?, ?>) chain.get(0)).get("id") : null;
            if (gref instanceof String && !((String) gref).isEmpty() && rootId instanceof String && gref.equals(rootId)) {
                v.checks.put("grant_ref_bound", true);
            } else {
                v.fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain");
            }

            // plan inclusion (leaf recomputed from the action itself)
            Map<String, Object> plan = asMap(p.get("plan"));
            Map<String, Object> action = asMap(p.get("action"));
            String cond = plan.get("conditions_digest") instanceof String
                ? (String) plan.get("conditions_digest") : conditionsDigest(null, null);
            boolean incl;
            try {
                incl = verifyInclusion(asStr(plan.get("root")), asMap(plan.get("inclusion_proof")),
                    planLeaf(plan.get("node_id"), action, cond));
            } catch (RuntimeException e) { incl = false; }
            if (incl) v.checks.put("plan_inclusion", true);
            else v.fail("plan_inclusion", "action is not a node of the committed plan");

            // leaf signature: the B4 crypto-agility seam. ed25519 is byte-identical to the classical path;
            // ml-dsa-65 / hybrid add ML-DSA-65 (FIPS-204) over the SAME signed message. Fail-closed.
            boolean sigOk = false;
            if (!chain.isEmpty()) {
                Map<String, Object> leafCap = asMap(chain.get(chain.size() - 1));
                String holder = asStr(leafCap.get("holder"));
                String lerr = suitePolicyError(p.get("alg"), p.containsKey("alg"), "leaf", allowedSuites);
                if (lerr == null) lerr = pqBindingError(p.get("alg"), p.containsKey("alg"), p.get("pq_pk"), leafCap.get("holder_pq"), "leaf");
                if (lerr == null) sigOk = Pq.verifyLeafSuite(p.get("alg"), p.containsKey("alg"), holder,
                    Pq.resolvePqKey(holder, p.get("pq_pk"), leafCap.get("holder_pq"), null, null), thresholdMessage(p), p.get("sig"), p.get("pq_sig"));
            }
            if (sigOk) v.checks.put("leaf_signature", true);
            else v.fail("leaf_signature", "signature does not verify under the leaf holder key");

            // counter
            if (Json.isSafeInt(p.get("counter")) && Json.asLong(p.get("counter")) >= 0) v.checks.put("counter", true);
            else v.fail("counter", "missing or not a non-negative safe integer");
        } catch (RuntimeException e) {
            if (v.reason.isEmpty()) v.reason = "malformed PCActn: " + e;
        }
        // any check not reached (internal error) is a failure; keep normative key order
        Map<String, Boolean> ordered = new LinkedHashMap<>();
        for (String k : new String[] {"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"})
            ordered.put(k, Boolean.TRUE.equals(v.checks.get(k)));
        v.checks.clear();
        v.checks.putAll(ordered);
        v.allow = !v.checks.containsValue(Boolean.FALSE);
        return v;
    }
}
