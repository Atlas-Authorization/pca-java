package net.atlasauth.pca.ratchet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * The Capability Ratchet: puncturable forward-secure capability keys (cryptographic one-time-use). A holder commits, up front, to a Merkle
 * root over 2^depth one-time Ed25519 leaf keys derived from a GGM puncturable-PRF tree; signing at a leaf produces an offline-verifiable
 * signature AND returns a state in which that leaf is PUNCTURED: its key material is dropped and can never be re-derived, so the same leaf
 * can never sign twice ("already spent" becomes "key no longer exists").
 *
 * <p>The PRG is HMAC-SHA256 (a PRF), {@code PRG(seed) = (HMAC(seed, D||0x00), HMAC(seed, D||0x01))}. The secret state is a co-path of disjoint
 * covering node seeds whose subtrees are exactly the leaves that can still sign; puncturing expands the covering node down to the leaf, keeps
 * every off-path sibling and drops every on-path seed.
 */
public final class Ratchet {
    private Ratchet() {}

    /** Longest tree accepted: setup derives all 2^depth leaf public keys, so this bounds that cost. */
    public static final int MAX_RATCHET_DEPTH = 20;

    private static final byte[] PRG_DOMAIN = "atlas-pca-ratchet/ggm-prg/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] LEAFKEY_DOMAIN = "atlas-pca-ratchet/ggm-leafkey/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ROOT_DOMAIN = "atlas-pca-ratchet/ggm-root/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NULLIFIER_DOMAIN = "atlas-pca-ratchet/nullifier/v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SIG_DOMAIN = "atlas-pca-ratchet/leaf-sig/v1\0".getBytes(StandardCharsets.UTF_8);

    /** A covering node of the secret co-path: {@code level} 0 is the root, {@code depth} a leaf. */
    public static final class CoverNode {
        public final int level;
        public final long nodeIndex;
        final byte[] seed;

        CoverNode(int level, long nodeIndex, byte[] seed) {
            this.level = level;
            this.nodeIndex = nodeIndex;
            this.seed = seed;
        }
    }

    /**
     * The live ratchet. {@code leafPubKeys} are public. {@code covering} is the SECRET co-path: punctured leaves are absent from every covering
     * subtree. Immutable: signing returns a new state.
     */
    public static final class RatchetState {
        public final int depth;
        public final long leafCount;
        public final String rootCommitment;
        public final List<String> leafPubKeys;
        final Map<String, CoverNode> covering;

        RatchetState(int depth, long leafCount, String rootCommitment, List<String> leafPubKeys, Map<String, CoverNode> covering) {
            this.depth = depth;
            this.leafCount = leafCount;
            this.rootCommitment = rootCommitment;
            this.leafPubKeys = leafPubKeys;
            this.covering = covering;
        }
    }

    /** The result of {@link #deriveRatchetRoot}. */
    public static final class Derived {
        public final String rootCommitment;
        public final RatchetState state;

        Derived(String rootCommitment, RatchetState state) {
            this.rootCommitment = rootCommitment;
            this.state = state;
        }
    }

    /** The result of {@link #signAtLeaf}: the signature (a JSON-shaped map: edSig, leafPubKey, merklePath, nullifier) and the punctured state. */
    public static final class Signed {
        public final Map<String, Object> signature;
        public final RatchetState newState;

        Signed(Map<String, Object> signature, RatchetState newState) {
            this.signature = signature;
            this.newState = newState;
        }
    }

    // ---- GGM -------------------------------------------------------------------------------------------------------------

    private static byte[] hmac(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(msg);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] prg(byte[] seed, int bit) {
        byte[] m = new byte[PRG_DOMAIN.length + 1];
        System.arraycopy(PRG_DOMAIN, 0, m, 0, PRG_DOMAIN.length);
        m[PRG_DOMAIN.length] = (byte) bit;
        return hmac(seed, m);
    }

    private static byte[] leafSigningSeed(byte[] leafSeed) { return hmac(leafSeed, LEAFKEY_DOMAIN); }

    private static String leafPublicKey(byte[] leafSeed) { return Keys.b64u(Keys.edFromSeed(leafSigningSeed(leafSeed)).pub); }

    private static boolean covers(int level, long nodeIndex, long leafIndex, int depth) { return (leafIndex >>> (depth - level)) == nodeIndex; }

    /** The bit chosen when descending from {@code level} towards {@code leafIndex} (0 = left, 1 = right). */
    private static int descendBit(int level, long leafIndex, int depth) { return (int) ((leafIndex >>> (depth - level - 1)) & 1L); }

    private static byte[] deriveLeafSeed(CoverNode node, long leafIndex, int depth) {
        byte[] seed = node.seed;
        for (int level = node.level; level < depth; level++) seed = prg(seed, descendBit(level, leafIndex, depth));
        return seed;
    }

    /** The off-path siblings that together cover every leaf under {@code node} except {@code leafIndex}; the on-path seeds are never returned. */
    private static List<CoverNode> punctureSiblings(CoverNode node, long leafIndex, int depth) {
        List<CoverNode> out = new ArrayList<>();
        byte[] seed = node.seed;
        long nodeIndex = node.nodeIndex;
        for (int level = node.level; level < depth; level++) {
            int bit = descendBit(level, leafIndex, depth);
            byte[] left = prg(seed, 0);
            byte[] right = prg(seed, 1);
            long childBase = nodeIndex * 2;
            out.add(new CoverNode(level + 1, childBase + (1 - bit), bit == 0 ? right : left));
            seed = bit == 0 ? left : right;
            nodeIndex = childBase + bit;
        }
        return out;
    }

    private static void allLeaves(byte[] seed, int level, int depth, int base, String[] out) {
        if (level == depth) {
            out[base] = leafPublicKey(seed);
            return;
        }
        int half = 1 << (depth - level - 1);
        allLeaves(prg(seed, 0), level + 1, depth, base, out);
        allLeaves(prg(seed, 1), level + 1, depth, base + half, out);
    }

    private static String coverKey(int level, long nodeIndex) { return level + ":" + nodeIndex; }

    // ---- Merkle (RFC 6962 shape, over the base64url leaf public keys) -------------------------------------------------

    private static String merkleRoot(List<String> leaves) { return Pca.merkleRoot(new ArrayList<Object>(leaves)); }

    private static int split(int n) {
        int k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    private static void prove(List<String> leaves, int idx, List<Object> out) {
        if (leaves.size() == 1) return;
        int k = split(leaves.size());
        Map<String, Object> step = new LinkedHashMap<>();
        if (idx < k) {
            prove(leaves.subList(0, k), idx, out);
            step.put("side", "R");
            step.put("hash", merkleRoot(leaves.subList(k, leaves.size())));
        } else {
            prove(leaves.subList(k, leaves.size()), idx - k, out);
            step.put("side", "L");
            step.put("hash", merkleRoot(leaves.subList(0, k)));
        }
        out.add(step);
    }

    private static Map<String, Object> merkleProof(List<String> leaves, int index, Object indexOut) {
        List<Object> path = new ArrayList<>();
        prove(leaves, index, path);
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("index", indexOut);
        proof.put("size", Long.valueOf(leaves.size()));
        proof.put("path", path);
        return proof;
    }

    // ---- public API ------------------------------------------------------------------------------------------------------

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Double jsNum(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        return o instanceof Number ? Double.valueOf(((Number) o).doubleValue()) : null;
    }

    /** A leaf index as the reference's BigInt(x) takes it: an integer-valued number; anything else throws (a TypeError / RangeError there). */
    private static long leafLong(Object leafIndex) {
        // BigInt(x): a boolean is 0/1 and a string is parsed as an integer literal (trimmed; empty is 0; 0x/0o/0b prefixes)
        if (leafIndex instanceof Boolean) return ((Boolean) leafIndex) ? 1 : 0;
        if (leafIndex instanceof String) {
            String t = ((String) leafIndex).strip();
            try {
                if (t.isEmpty()) return 0;
                if (t.matches("0[xX][0-9a-fA-F]+")) return new java.math.BigInteger(t.substring(2), 16).longValue();
                if (t.matches("0[oO][0-7]+")) return new java.math.BigInteger(t.substring(2), 8).longValue();
                if (t.matches("0[bB][01]+")) return new java.math.BigInteger(t.substring(2), 2).longValue();
                if (t.matches("[+-]?[0-9]+")) return new java.math.BigInteger(t.startsWith("+") ? t.substring(1) : t).longValue();
            } catch (NumberFormatException e) { /* falls to the refusal */ }
            throw new IllegalArgumentException("leafIndex is not an integer");
        }
        Double d = jsNum(leafIndex);
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d)) throw new IllegalArgumentException("leafIndex is not an integer");
        return new java.math.BigDecimal(d).toBigInteger().longValue();
    }

    /** The per-leaf nullifier a verifier records to detect leaf reuse: {@code b64u(sha256(domain || len(root) || root || index))}. */
    public static String leafNullifier(String rootCommitment, Object leafIndex) {
        byte[] root = Json.utf8(rootCommitment);
        ByteBuffer out = ByteBuffer.allocate(NULLIFIER_DOMAIN.length + 4 + root.length + 8);
        out.put(NULLIFIER_DOMAIN);
        out.putInt(root.length);
        out.put(root);
        out.putLong(leafLong(leafIndex));
        return Keys.b64u(sha256(out.array()));
    }

    /** The signed message: domain, the 8-byte big-endian leaf index (so a signature cannot be lifted elsewhere), then the message. */
    private static byte[] leafSigMessage(Object leafIndex, byte[] message) {
        ByteBuffer out = ByteBuffer.allocate(SIG_DOMAIN.length + 8 + message.length);
        out.put(SIG_DOMAIN);
        out.putLong(leafLong(leafIndex));
        out.put(message);
        return out.array();
    }

    /**
     * Build a ratchet from a root seed (at least 32 bytes of entropy) and a tree depth in [1, MAX_RATCHET_DEPTH]. {@code depth} is any value (a
     * non-integer is refused as invalid_depth, as in the reference).
     */
    public static Derived deriveRatchetRoot(byte[] seed, Object depth) {
        Double d = jsNum(depth);
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || d < 1 || d > MAX_RATCHET_DEPTH) {
            throw new RatchetError("invalid_depth", "depth must be an integer in [1, " + MAX_RATCHET_DEPTH + "]");
        }
        if (seed == null || seed.length < 32) throw new RatchetError("invalid_seed", "seed must be a Uint8Array of at least 32 bytes");
        int dep = d.intValue();
        byte[] root = hmac(seed, ROOT_DOMAIN);
        String[] pubs = new String[1 << dep];
        allLeaves(root, 0, dep, 0, pubs);
        List<String> leafPubKeys = Collections.unmodifiableList(new ArrayList<>(java.util.Arrays.asList(pubs)));
        String rootCommitment = merkleRoot(leafPubKeys);
        Map<String, CoverNode> covering = new LinkedHashMap<>();
        covering.put(coverKey(0, 0), new CoverNode(0, 0, root));
        return new Derived(rootCommitment, new RatchetState(dep, 1L << dep, rootCommitment, leafPubKeys, covering));
    }

    private static CoverNode findCovering(RatchetState state, long leafIndex) {
        for (CoverNode n : state.covering.values()) if (covers(n.level, n.nodeIndex, leafIndex, state.depth)) return n;
        return null;
    }

    private static long checkedLeaf(RatchetState state, Object leafIndex) {
        Double d = jsNum(leafIndex);
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || d < 0 || d >= state.leafCount)
            throw new RatchetError("leaf_out_of_range", "leaf " + leafIndex + " is out of range [0, " + state.leafCount + ")");
        return d.longValue();
    }

    /**
     * Sign {@code message} at leaf {@code leafIndex}, then puncture that leaf. Throws {@link RatchetError} if the leaf is out of range or already
     * punctured (a spent leaf can never sign again).
     */
    public static Signed signAtLeaf(RatchetState state, Object leafIndex, byte[] message) {
        long idx = checkedLeaf(state, leafIndex);
        CoverNode node = findCovering(state, idx);
        if (node == null) throw new RatchetError("leaf_punctured", "leaf " + idx + " is already punctured (spent) and cannot sign");
        byte[] leafSeed = deriveLeafSeed(node, idx, state.depth);
        Keys.EdKey key = Keys.edFromSeed(leafSigningSeed(leafSeed));
        String edSig = Keys.b64u(key.sign(leafSigMessage(Long.valueOf(idx), message)));
        String leafPub = Keys.b64u(key.pub);
        // the reference copies the caller's index into the proof, so a negative zero stays one (and such a proof never verifies, as there)
        Double given = jsNum(leafIndex);
        Object indexOut = given != null && given == 0.0 && Double.doubleToRawLongBits(given) != 0L ? new Json.Num("-0") : (Object) Long.valueOf(idx);
        Map<String, Object> merklePath = merkleProof(state.leafPubKeys, (int) idx, indexOut);
        Map<String, CoverNode> covering = new LinkedHashMap<>(state.covering);
        covering.remove(coverKey(node.level, node.nodeIndex));
        for (CoverNode sib : punctureSiblings(node, idx, state.depth)) covering.put(coverKey(sib.level, sib.nodeIndex), sib);
        Map<String, Object> sig = new LinkedHashMap<>();
        sig.put("edSig", edSig);
        sig.put("leafPubKey", leafPub);
        sig.put("merklePath", merklePath);
        sig.put("nullifier", leafNullifier(state.rootCommitment, Long.valueOf(idx)));
        return new Signed(sig, new RatchetState(state.depth, state.leafCount, state.rootCommitment, state.leafPubKeys, covering));
    }

    /**
     * Verify a ratchet signature offline against the root commitment, with no shared state: the Ed25519 signature must be valid under
     * {@code leafPubKey} and {@code merklePath} must prove it is the leaf at {@code leafIndex} under {@code rootCommitment}. Never throws.
     */
    public static boolean verifyLeafSignature(String rootCommitment, Object leafIndex, byte[] message, Object signature) {
        try {
            if (!(signature instanceof Map) && !(signature instanceof List)) return false;
            Map<?, ?> s = signature instanceof Map ? (Map<?, ?>) signature : new LinkedHashMap<Object, Object>();
            Object edSig = s.get("edSig");
            Object leafPubKey = s.get("leafPubKey");
            Object merklePath = s.get("merklePath");
            Object nullifier = s.get("nullifier");
            if (!(nullifier instanceof String) || !nullifier.equals(leafNullifier(rootCommitment, leafIndex))) return false;
            if (!(edSig instanceof String) || !(leafPubKey instanceof String) || merklePath == null || !(merklePath instanceof Map || merklePath instanceof List)) return false;
            Double mi = merklePath instanceof Map ? jsNum(((Map<?, ?>) merklePath).get("index")) : null;
            Double li = jsNum(leafIndex);
            if (mi == null || li == null || mi.doubleValue() != li.doubleValue()) return false;
            // the inclusion verifier refuses a negative-zero index and any hash suite but sha256 (the Java Merkle check does not read hash_suite)
            if (mi == 0.0 && Double.doubleToRawLongBits(mi) != 0L) return false;
            Map<?, ?> mp = (Map<?, ?>) merklePath;
            if (mp.containsKey("hash_suite") && !"sha256".equals(mp.get("hash_suite"))) return false;
            byte[] pk = Pca.decodeB64uStrict(leafPubKey, 32);
            byte[] sg = Pca.decodeB64uStrict(edSig, 64);
            if (pk == null || sg == null || !EdStrict.verify(pk, leafSigMessage(leafIndex, message), sg)) return false;
            @SuppressWarnings("unchecked")
            Map<String, Object> path = (Map<String, Object>) merklePath;
            return Pca.verifyInclusion(rootCommitment, path, leafPubKey);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Indices of leaves that can still sign (not yet punctured), ascending. */
    public static List<Long> availableLeaves(RatchetState state) {
        List<Long> out = new ArrayList<>();
        for (CoverNode n : state.covering.values()) {
            long span = 1L << (state.depth - n.level);
            long base = n.nodeIndex * span;
            for (long i = 0; i < span; i++) out.add(base + i);
        }
        Collections.sort(out);
        return out;
    }

    /**
     * Whether leaf {@code leafIndex} can still sign. As in the reference, the test is {@code floor(leafIndex / 2^(depth-level)) === nodeIndex} on
     * JavaScript numbers, so a fractional index inside a covered subtree reads as available; NaN, infinities and other types are not.
     */
    public static boolean isLeafAvailable(RatchetState state, Object leafIndex) {
        Double d = jsNum(leafIndex);
        if (d == null || d.isNaN()) return false;
        for (CoverNode n : state.covering.values()) {
            if (Math.floor(d / Math.pow(2, state.depth - n.level)) == (double) n.nodeIndex) return true;
        }
        return false;
    }
}
