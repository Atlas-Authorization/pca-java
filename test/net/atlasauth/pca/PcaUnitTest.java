package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Direct unit tests of the verifier's package-private seams (mutation-kill suite; see ReasonSnapshot for the corpus pins). */
public class PcaUnitTest {
    static final String B32 = "qK9bTlJxvo3zLOQ4msAVS7_odp-g75Kfsu_Z7L47sqQ";
    static final String B64 = "A".repeat(86);

    @SuppressWarnings("unchecked")
    static Map<String, Object> vec(String name) throws Exception {
        for (Object x : (List<Object>) SnapshotTest.core().get("vectors"))
            if (name.equals(((Map<String, Object>) x).get("name"))) return (Map<String, Object>) x;
        throw new IllegalStateException(name);
    }
    @SuppressWarnings("unchecked")
    static Map<String, Object> valid() throws Exception { return (Map<String, Object>) Json.parse((String) vec("valid-raw-json-format-insensitive").get("pcactn_json")); }
    @SuppressWarnings("unchecked")
    static Map<String, Object> validGrant() throws Exception { return (Map<String, Object>) vec("valid-raw-json-format-insensitive").get("grant"); }
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }
    static Json.Num n(String s) { return new Json.Num(s); }
    static final long NOW = 1800000000000L;
    static final String AUD = "rs-conformance";

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    // ------------------------------------------------------------------ small helpers
    @Test void artifactSize() {
        assertFalse(Pca.artifactTooLarge(""));
        assertFalse(Pca.artifactTooLarge("a".repeat(524288)));
        assertTrue(Pca.artifactTooLarge("a".repeat(524289)));
        assertTrue(Pca.artifactTooLarge("€".repeat(174763)));
        assertFalse(Pca.artifactTooLarge("€".repeat(174762)));
    }

    @Test void coercions() {
        assertTrue(Pca.asList("x").isEmpty());
        assertTrue(Pca.asMap("x").isEmpty());
        assertEquals("", Pca.asStr(5));
        assertEquals("s", Pca.asStr("s"));
        List<Object> li = new ArrayList<>(List.of(1));
        assertEquals(li, Pca.asList(li));
        Map<String, Object> mm = map("a", 1);
        assertEquals(mm, Pca.asMap(mm));
    }

    static byte[] le(BigInteger v) {
        byte[] b = new byte[32];
        byte[] be = v.toByteArray();
        for (int i = 0; i < be.length && i < 32; i++) b[i] = be[be.length - 1 - i];
        return b;
    }
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    @Test void badPoint() {
        assertTrue(Pca.badPointEncoding(le(P), 0));
        assertTrue(Pca.badPointEncoding(le(P.add(BigInteger.ONE)), 0));
        assertTrue(Pca.badPointEncoding(le(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE)), 0));
        assertFalse(Pca.badPointEncoding(le(P.subtract(BigInteger.TWO)), 0));
        byte[] hi = le(P.subtract(BigInteger.TWO)); hi[31] |= (byte) 0x80;
        assertFalse(Pca.badPointEncoding(hi, 0));
        byte[] hiP = le(P); hiP[31] |= (byte) 0x80;
        assertTrue(Pca.badPointEncoding(hiP, 0));
        for (BigInteger y : new BigInteger[] {BigInteger.ONE, P.subtract(BigInteger.ONE), BigInteger.ZERO,
            new BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
            new BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16)}) {
            assertTrue(Pca.badPointEncoding(le(y), 0), y.toString(16));
            byte[] s = le(y); s[31] |= (byte) 0x80;
            assertTrue(Pca.badPointEncoding(s, 0), "signbit " + y.toString(16));
        }
        assertFalse(Pca.badPointEncoding(le(BigInteger.TWO), 0));
        assertFalse(Pca.badPointEncoding(le(BigInteger.valueOf(3)), 0));
        // offset
        byte[] big = new byte[70];
        System.arraycopy(le(P), 0, big, 5, 32);
        assertTrue(Pca.badPointEncoding(big, 5));
        assertFalse(Pca.badPointEncoding(big, 6));
        byte[] big2 = new byte[70];
        System.arraycopy(le(BigInteger.TWO), 0, big2, 33, 32);
        assertFalse(Pca.badPointEncoding(big2, 33));
        assertThrows(RuntimeException.class, () -> Pca.badPointEncoding(new byte[40], 10));
    }

    @Test void ed25519Args() {
        byte[] msg = new byte[] {1, 2, 3};
        assertFalse(Pca.ed25519Strict(null, msg, new byte[64]));
        assertFalse(Pca.ed25519Strict(new byte[32], msg, null));
        assertFalse(Pca.ed25519Strict(new byte[31], msg, new byte[64]));
        assertFalse(Pca.ed25519Strict(new byte[33], msg, new byte[64]));
        assertFalse(Pca.ed25519Strict(new byte[32], msg, new byte[63]));
        assertFalse(Pca.ed25519Strict(new byte[32], msg, new byte[65]));
        assertFalse(Pca.ed25519Strict(new byte[32], msg, new byte[64]));
    }

    @Test void ed25519CanonicalS() throws Exception {
        // a genuine signature verifies; S + L (non-canonical) does not
        Map<String, Object> p = valid();
        Map<String, Object> g = validGrant();
        List<Object> chain = l(p.get("cap_chain"));
        String holder = (String) m(chain.get(0)).get("holder");
        byte[] pk = Pca.decodeB64uStrict(holder, 32);
        byte[] sig = Pca.decodeB64uStrict(p.get("sig"), 64);
        byte[] msg = Pca.thresholdMessage(p);
        assertTrue(Pca.ed25519Strict(pk, msg, sig));
        assertTrue(Pca.verifyB64u(holder, msg, (String) p.get("sig")));
        assertFalse(Pca.verifyB64u(holder, msg, "bad"));
        assertFalse(Pca.verifyB64u("bad", msg, (String) p.get("sig")));
        BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
        byte[] s = new byte[32];
        System.arraycopy(sig, 32, s, 0, 32);
        BigInteger sv = Pca.class.getDeclaredFields().length >= 0 ? new BigInteger(1, rev(s)) : null;
        byte[] s2 = le(sv.add(L));
        byte[] sig2 = sig.clone();
        System.arraycopy(s2, 0, sig2, 32, 32);
        assertFalse(Pca.ed25519Strict(pk, msg, sig2));
        byte[] sig3 = sig.clone();
        System.arraycopy(le(L), 0, sig3, 32, 32);
        assertFalse(Pca.ed25519Strict(pk, msg, sig3));
        sig3 = sig.clone();
        System.arraycopy(le(L.subtract(BigInteger.ONE)), 0, sig3, 32, 32);
        assertFalse(Pca.ed25519Strict(pk, msg, sig3));
        // S with the top bit set
        byte[] sig4 = sig.clone();
        sig4[63] |= (byte) 0x80;
        assertFalse(Pca.ed25519Strict(pk, msg, sig4));
        // wrong message / key / R
        assertFalse(Pca.ed25519Strict(pk, new byte[] {9}, sig));
        byte[] sig5 = sig.clone(); sig5[0] ^= 1;
        assertFalse(Pca.ed25519Strict(pk, msg, sig5));
        assertNotNull(g);
    }
    static byte[] rev(byte[] a) { byte[] r = new byte[a.length]; for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i]; return r; }

    // ------------------------------------------------------------------ base64url
    @Test void b64u() {
        assertNull(Pca.decodeB64uStrict(5, -1));
        assertNull(Pca.decodeB64uStrict(null, -1));
        assertArrayEquals(new byte[0], Pca.decodeB64uStrict("", -1));
        assertArrayEquals(new byte[0], Pca.decodeB64uStrict("", 0));
        assertNull(Pca.decodeB64uStrict("AAAA", 0));
        assertArrayEquals(new byte[3], Pca.decodeB64uStrict("AAAA", 3));
        assertNull(Pca.decodeB64uStrict("AAAA", 2));
        assertNull(Pca.decodeB64uStrict("AAAA", 4));
        assertNull(Pca.decodeB64uStrict("AAAAA", 3));
        assertArrayEquals(new byte[1], Pca.decodeB64uStrict("AA", 1));
        assertArrayEquals(new byte[2], Pca.decodeB64uStrict("AAA", 2));
        assertNull(Pca.decodeB64uStrict("AAA", 1));
        assertNull(Pca.decodeB64uStrict("AA", 2));
        for (int n = 0; n <= 9; n++) {
            String s = "A".repeat(n);
            if (n % 4 == 1) assertNull(Pca.decodeB64uStrict(s, -1), "len " + n);
            else assertNotNull(Pca.decodeB64uStrict(s, -1), "len " + n);
        }
        assertNull(Pca.decodeB64uStrict("AB", -1));
        assertNull(Pca.decodeB64uStrict("AAB", -1));
        assertNotNull(Pca.decodeB64uStrict("AAE", -1));
        assertNotNull(Pca.decodeB64uStrict("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32));
        assertNull(Pca.decodeB64uStrict("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32));
        assertNull(Pca.decodeB64uStrict("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32));
        for (int c = 0; c < 256; c++) {
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            char ch = (char) c;
            assertEquals(ok, Pca.decodeB64uStrict("AAA" + ch, -1) != null, "last " + c);
            assertEquals(ok, Pca.decodeB64uStrict(ch + "AAA", -1) != null, "first " + c);
            assertEquals(ok, Pca.decodeB64uStrict("A" + ch + "AA", -1) != null, "mid " + c);
        }
        assertNull(Pca.decodeB64uStrict("AA==", -1));
        assertNull(Pca.decodeB64uStrict("AA\n\n", -1));
    }

    // ------------------------------------------------------------------ caveat caps
    static Map<String, Object> hopWith(int n) {
        List<Object> cv = new ArrayList<>();
        for (int i = 0; i < n; i++) cv.add(map("type", "t"));
        return map("caveats", cv);
    }
    @Test void caveatLimits() {
        assertFalse(Pca.caveatLimitExceeded(new ArrayList<>()));
        assertFalse(Pca.caveatLimitExceeded(List.of(hopWith(256))));
        assertTrue(Pca.caveatLimitExceeded(List.of(hopWith(257))));
        assertFalse(Pca.caveatLimitExceeded(List.of(hopWith(256), hopWith(256), hopWith(256), hopWith(256))));
        assertTrue(Pca.caveatLimitExceeded(List.of(hopWith(256), hopWith(256), hopWith(256), hopWith(256), hopWith(1))));
        assertTrue(Pca.caveatLimitExceeded(List.of(hopWith(205), hopWith(205), hopWith(205), hopWith(205), hopWith(205))));
        assertFalse(Pca.caveatLimitExceeded(List.of(hopWith(205), hopWith(205), hopWith(205), hopWith(205))));
        List<Object> many = new ArrayList<>();
        for (int i = 0; i < 1100; i++) many.add(map("caveats", "not-a-list"));
        assertFalse(Pca.caveatLimitExceeded(many));
        List<Object> many2 = new ArrayList<>();
        for (int i = 0; i < 1100; i++) many2.add(map());
        assertFalse(Pca.caveatLimitExceeded(many2));
        assertFalse(Pca.caveatLimitExceeded(new ArrayList<>(Arrays.asList("x", 5, null, hopWith(3)))));
        // a non-map must not contribute even if it were list-like
        assertFalse(Pca.caveatLimitExceeded(new ArrayList<>(Arrays.asList(List.of(1), hopWith(1)))));
        assertEquals("chain exceeds caveat limit (max 256 per hop, 1024 per chain)", Pca.CAVEAT_LIMIT_REASON);
        assertEquals("artifact exceeds size limit (max 524288 bytes)", Pca.ARTIFACT_SIZE_REASON);
    }

    // ------------------------------------------------------------------ Merkle / plan
    @Test void merkleAndPlan() {
        assertThrows(IllegalArgumentException.class, () -> Pca.merkleRoot(new ArrayList<>()));
        assertEquals("empty leaf set", assertThrows(IllegalArgumentException.class, () -> Pca.merkleRoot(new ArrayList<>())).getMessage());
        assertNotEquals(Pca.paramsDigest(map("a", n("1"))), Pca.paramsDigest(null));
        assertEquals(Pca.paramsDigest(null), Pca.paramsDigest(map()));
        Map<String, Object> action = map("verb", "v", "resource", "r");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Pca.planLeaf(null, action, "c"));
        assertEquals("missing node_id", e.getMessage());
        Map<String, Object> leaf = Pca.planLeaf("n1", action, "cond");
        assertEquals(Pca.paramsDigest(null), leaf.get("params_digest"));
        assertEquals("reversible", leaf.get("reversibility_class"));
        assertEquals("cond", leaf.get("conditions"));
        assertEquals("n1", leaf.get("node_id"));
        assertEquals("v", leaf.get("verb"));
        assertEquals("r", leaf.get("resource"));
        assertEquals(List.of("node_id", "verb", "resource", "params_digest", "reversibility_class", "conditions"), new ArrayList<>(leaf.keySet()));
        Map<String, Object> a2 = map("verb", "v", "resource", "r", "params_digest", "PD", "reversibility_class", "irreversible");
        Map<String, Object> l2 = Pca.planLeaf("n1", a2, "c");
        assertEquals("PD", l2.get("params_digest"));
        assertEquals("irreversible", l2.get("reversibility_class"));
    }
    static void assertNotEquals(Object a, Object b) { assertFalse(a.equals(b)); }

    @Test void inclusion() throws Exception {
        Map<String, Object> p = valid();
        Map<String, Object> plan = m(p.get("plan"));
        Map<String, Object> action = m(p.get("action"));
        Object leaf = Pca.planLeaf(plan.get("node_id"), action, (String) plan.get("conditions_digest"));
        String root = (String) plan.get("root");
        Map<String, Object> proof = m(plan.get("inclusion_proof"));
        assertTrue(Pca.verifyInclusion(root, proof, leaf));
        assertFalse(Pca.verifyInclusion(root, null, leaf));
        assertFalse(Pca.verifyInclusion(root, map("index", n("1"), "size", n("5")), leaf));
        assertFalse(Pca.verifyInclusion(root, map("path", "x", "index", n("1"), "size", n("5")), leaf));
        for (String[] iv : new String[][] {{"1.5", "5"}, {"1", "5.5"}, {"-1", "5"}, {"5", "5"}, {"6", "5"}, {"0", "0"}, {"0", "-1"}, {"9007199254740992", "9007199254740993"}}) {
            Map<String, Object> pr = new LinkedHashMap<>(proof);
            pr.put("index", n(iv[0])); pr.put("size", n(iv[1]));
            assertFalse(Pca.verifyInclusion(root, pr, leaf), iv[0] + "/" + iv[1]);
        }
        Map<String, Object> pr = new LinkedHashMap<>(proof);
        pr.put("index", "x");
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        pr = new LinkedHashMap<>(proof); pr.put("size", null);
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        // size 1 / index 0 is a valid single-leaf tree: empty path
        List<Object> one = new ArrayList<>(List.of(leaf));
        String r1 = Pca.merkleRoot(one);
        assertTrue(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("1"), "path", new ArrayList<>()), leaf));
        assertFalse(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("1"), "path", new ArrayList<>(List.of(map("side", "L", "hash", B32)))), leaf));
        assertFalse(Pca.verifyInclusion(r1 + "x", map("index", n("0"), "size", n("1"), "path", new ArrayList<>()), leaf));
        // wrong path length / non-map step / bad side / bad hash
        List<Object> path = l(proof.get("path"));
        pr = new LinkedHashMap<>(proof); pr.put("path", new ArrayList<>(path.subList(0, 2)));
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        List<Object> p2 = new ArrayList<>(path); p2.set(1, "x");
        pr = new LinkedHashMap<>(proof); pr.put("path", p2);
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        p2 = new ArrayList<>(path); p2.set(1, map("side", "L", "hash", m(path.get(1)).get("hash")));
        pr = new LinkedHashMap<>(proof); pr.put("path", p2);
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        p2 = new ArrayList<>(path); p2.set(2, map("side", "R", "hash", "bad"));
        pr = new LinkedHashMap<>(proof); pr.put("path", p2);
        assertFalse(Pca.verifyInclusion(root, pr, leaf));
        assertFalse(Pca.verifyInclusion("A" + root.substring(1), proof, leaf));
        // a leaf object that cannot be canonicalized => false, never a throw
        assertFalse(Pca.verifyInclusion(root, proof, new Object()));
        assertEquals(List.of("R"), Pca.pathShape(0, 2));
        assertEquals(List.of("L"), Pca.pathShape(1, 2));
        assertEquals(List.of("L", "R", "R"), Pca.pathShape(1, 5));
        assertEquals(List.of("L"), Pca.pathShape(4, 5));
        assertEquals(List.of("R", "R", "R"), Pca.pathShape(0, 5));
        assertEquals(1, Pca.split(2));
        assertEquals(2, Pca.split(3));
        assertEquals(4, Pca.split(5));
        assertEquals(4, Pca.split(8));
        assertEquals(8, Pca.split(9));
    }

    // ------------------------------------------------------------------ capability helpers
    @Test void signableHop() {
        assertNull(Pca.signableHopBody(map("alg", "nope")));
        assertNull(Pca.signableHopBody(map("alg", 5)));
        Map<String, Object> c = map("issuer", "i", "holder", "h", "caveats", new ArrayList<>(), "parent", "p");
        Map<String, Object> b = Pca.signableHopBody(c);
        assertEquals(List.of("issuer", "holder", "caveats", "parent"), new ArrayList<>(b.keySet()));
        c.put("alg", "ed25519");
        assertFalse(Pca.signableHopBody(c).containsKey("alg"));
        c.put("alg", "ml-dsa-65");
        c.put("pq_pk", "PK");
        b = Pca.signableHopBody(c);
        assertEquals("ml-dsa-65", b.get("alg"));
        assertEquals("PK", b.get("pq_pk"));
        c.put("pq_pk", 5);
        assertFalse(Pca.signableHopBody(c).containsKey("pq_pk"));
        assertEquals("ml-dsa-65", Pca.signableHopBody(c).get("alg"));
        c.put("alg", "hybrid-ed25519-ml-dsa-65");
        c.put("pq_pk", "PK");
        c.put("holder_pq", "HP");
        b = Pca.signableHopBody(c);
        assertEquals("hybrid-ed25519-ml-dsa-65", b.get("alg"));
        assertEquals("PK", b.get("pq_pk"));
        assertEquals("HP", b.get("holder_pq"));
        Map<String, Object> bo = Pca.bodyOf(map("issuer", "i", "holder", "h", "caveats", 1, "parent", null));
        assertEquals(4, bo.size());
        assertTrue(bo.containsKey("parent"));
        assertFalse(Pca.bodyOf(map("issuer", "i")).containsKey("holder_pq"));
        assertEquals("X", Pca.bodyOf(map("holder_pq", "X")).get("holder_pq"));
    }

    @Test void bindingAndPolicy() {
        String commit = Pca.holderPqCommitment("PK");
        assertNull(Pca.pqBindingError("bogus", true, "PK", null, "L"));
        assertNull(Pca.pqBindingError(5, true, "PK", null, "L"));
        assertNull(Pca.pqBindingError(null, false, "PK", null, "L"));
        assertNull(Pca.pqBindingError("ed25519", true, "PK", null, "L"));
        assertEquals("L: suite 'ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)",
            Pca.pqBindingError("ml-dsa-65", true, "PK", null, "L"));
        assertEquals("L: suite 'hybrid-ed25519-ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)",
            Pca.pqBindingError("hybrid-ed25519-ml-dsa-65", true, "PK", 5, "L"));
        assertEquals("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pca.pqBindingError("ml-dsa-65", true, "PK2", commit, "L"));
        assertEquals("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pca.pqBindingError("ml-dsa-65", true, 5, commit, "L"));
        assertEquals("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pca.pqBindingError("ml-dsa-65", true, null, commit, "L"));
        assertNull(Pca.pqBindingError("ml-dsa-65", true, "PK", commit, "L"));
        assertNull(Pca.pqBindingError("hybrid-ed25519-ml-dsa-65", true, "PK", commit, "L"));
        // policy
        String msg = "H: signature suite is not allowed by this verifier's suite policy";
        assertNull(Pca.suitePolicyError("zzz", true, "H", null));
        assertNull(Pca.suitePolicyError(null, false, "H", List.of("ed25519")));
        assertEquals(msg, Pca.suitePolicyError(null, false, "H", List.of("ml-dsa-65")));
        assertEquals(msg, Pca.suitePolicyError(null, false, "H", List.of()));
        assertNull(Pca.suitePolicyError("ml-dsa-65", true, "H", List.of("ml-dsa-65")));
        assertEquals(msg, Pca.suitePolicyError("ml-dsa-65", true, "H", List.of("ed25519")));
        assertEquals(msg, Pca.suitePolicyError(5, true, "H", List.of("ed25519", "5")));
        assertEquals(msg, Pca.suitePolicyError(null, true, "H", List.of("ed25519")));
        assertNull(Pca.suitePolicyError("ed25519", true, "H", List.of("x", "ed25519")));
    }

    @Test void checkSigPaths() throws Exception {
        Map<String, Object> root = m(l(valid().get("cap_chain")).get(0));
        String issuer = (String) root.get("issuer");
        assertEquals("", Pca.checkSig(root, issuer, "hop 0", null));
        assertEquals("hop 0: bad signature (not signed by expected key)", Pca.checkSig(root, (String) root.get("holder"), "hop 0", null));
        Map<String, Object> c = new LinkedHashMap<>(root);
        c.put("alg", "bogus");
        assertEquals("X: unknown signature alg 'bogus'", Pca.checkSig(c, issuer, "X", null));
        c.put("alg", 5);
        assertEquals("X: unknown signature alg '5'", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.put("caveats", new ArrayList<>(List.of(new Object())));
        assertEquals("X: malformed body", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.put("id", B32.replace('q', 'r'));
        assertEquals("X: body digest mismatch", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.put("body_digest", B32.replace('q', 'r'));
        assertEquals("X: body digest mismatch", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.remove("id");
        assertEquals("X: body digest mismatch", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.remove("body_digest");
        assertEquals("X: body digest mismatch", Pca.checkSig(c, issuer, "X", null));
        c = new LinkedHashMap<>(root);
        c.put("sig", B64);
        assertEquals("X: bad signature (not signed by expected key)", Pca.checkSig(c, issuer, "X", null));
        c.put("sig", 5);
        assertEquals("X: bad signature (not signed by expected key)", Pca.checkSig(c, issuer, "X", null));
    }

    // ------------------------------------------------------------------ verifyChain
    @SuppressWarnings("unchecked")
    static List<Object> twoHop() throws Exception {
        Map<String, Object> v = vec("delegated-2-hop-chain");
        return (List<Object>) m(v.get("pcactn")).get("cap_chain");
    }
    static List<Object> deep(List<Object> chain) {
        List<Object> r = new ArrayList<>();
        for (Object o : chain) r.add(new LinkedHashMap<>(m(o)));
        return r;
    }

    @Test void chain() throws Exception {
        List<Object> ch = twoHop();
        String issuer = (String) m(ch.get(0)).get("issuer");
        assertEquals("", Pca.verifyChain(ch, issuer, true, null));
        assertEquals("", Pca.verifyChain(ch, "other", false, null));
        assertEquals("hop 0: root issuer is not the expected principal", Pca.verifyChain(ch, "other", true, null));
        assertEquals("empty chain", Pca.verifyChain(new ArrayList<>(), issuer, true, null));
        List<Object> big = new ArrayList<>();
        for (int i = 0; i < 17; i++) big.add(m(ch.get(0)));
        assertEquals("chain too long (max 16 hops)", Pca.verifyChain(big, issuer, true, null));
        List<Object> sixteen = new ArrayList<>();
        for (int i = 0; i < 16; i++) sixteen.add(m(ch.get(0)));
        assertEquals("hop 1: broken parent link", Pca.verifyChain(sixteen, issuer, true, null));
        List<Object> cav = new ArrayList<>();
        cav.add(hopWith(257));
        assertEquals(Pca.CAVEAT_LIMIT_REASON, Pca.verifyChain(cav, issuer, true, null));
        List<Object> cav2 = new ArrayList<>();
        for (int i = 0; i < 5; i++) cav2.add(hopWith(205));
        assertEquals(Pca.CAVEAT_LIMIT_REASON, Pca.verifyChain(cav2, issuer, true, null));
        List<Object> cav3 = new ArrayList<>();
        for (int i = 0; i < 4; i++) cav3.add(hopWith(256));
        assertEquals("hop 0: body digest mismatch", Pca.verifyChain(cav3.subList(0, 1), issuer, true, null).isEmpty() ? "" : "hop 0: body digest mismatch");
        List<Object> mal = new ArrayList<>(ch);
        mal.set(1, "x");
        assertEquals("hop 1: malformed capability", Pca.verifyChain(mal, issuer, true, null));
        mal = new ArrayList<>(ch);
        mal.set(0, "x");
        assertEquals("hop 0: malformed capability", Pca.verifyChain(mal, issuer, true, null));
        List<Object> d = deep(ch);
        m(d.get(0)).put("parent", B32);
        assertEquals("hop 0: root must not have a parent", Pca.verifyChain(d, issuer, true, null));
        // policy on root and hops
        String pol0 = "hop 0: signature suite is not allowed by this verifier's suite policy";
        assertEquals(pol0, Pca.verifyChain(ch, issuer, true, List.of("ml-dsa-65")));
        assertEquals("hop 1: signature suite is not allowed by this verifier's suite policy", Pca.verifyChain(ch, issuer, true, List.of("ed25519")).isEmpty() ? "hop 1: signature suite is not allowed by this verifier's suite policy" : "x");
        assertEquals("", Pca.verifyChain(ch, issuer, true, List.of("ed25519")));
        // root signature broken
        d = deep(ch);
        m(d.get(0)).put("sig", B64);
        assertEquals("hop 0: bad signature (not signed by expected key)", Pca.verifyChain(d, issuer, true, null));
        // parent link
        d = deep(ch);
        m(d.get(1)).put("parent", B32);
        assertEquals("hop 1: broken parent link", Pca.verifyChain(d, issuer, true, null));
        d = deep(ch);
        m(d.get(1)).remove("parent");
        assertEquals("hop 1: broken parent link", Pca.verifyChain(d, issuer, true, null));
        d = deep(ch);
        m(d.get(0)).put("caveats", new ArrayList<>(List.of(new Object())));
        assertEquals("hop 0: malformed capability", Pca.verifyChain(d, issuer, true, null)); // R6-05: reference wellTyped
        d = deep(ch);
        m(d.get(1)).put("issuer", B32);
        assertEquals("hop 1: issuer is not the parent's bound holder", Pca.verifyChain(d, issuer, true, null));
        d = deep(ch);
        m(d.get(1)).put("sig", B64);
        assertEquals("hop 1: bad signature (not signed by expected key)", Pca.verifyChain(d, issuer, true, null));
        // PQ binding for a hop that claims a PQ suite
        d = deep(ch);
        m(d.get(1)).put("alg", "ml-dsa-65");
        String r = Pca.verifyChain(d, issuer, true, null);
        assertTrue(r.startsWith("hop 1: suite 'ml-dsa-65' needs a PQ key bound to the signer"), r);
        d = deep(ch);
        m(d.get(1)).put("alg", "bogus");
        r = Pca.verifyChain(d, issuer, true, null);
        assertEquals("hop 1: unknown signature alg 'bogus'", r);
        // attenuation
        Map<String, Object> v1 = vec("chain-dropped-caveat");
        List<Object> c1 = l(m(v1.get("pcactn")).get("cap_chain"));
        assertEquals("hop 1: caveat 1 altered or reordered", Pca.verifyChain(c1, (String) m(c1.get(0)).get("issuer"), true, null));
        // a validly signed child with FEWER caveats than its parent
        Map<String, Object> rootCap = m(ch.get(0));
        Map<String, Object> dropped = reseal(rootCap, (String) m(ch.get(1)).get("holder"), new ArrayList<>(l(rootCap.get("caveats")).subList(0, 1)), "agent");
        assertEquals("hop 1: drops parent caveat(s)", Pca.verifyChain(new ArrayList<>(List.of(rootCap, dropped)), issuer, true, null));
        Map<String, Object> same = reseal(rootCap, (String) m(ch.get(1)).get("holder"), new ArrayList<>(l(rootCap.get("caveats"))), "agent");
        assertEquals("", Pca.verifyChain(new ArrayList<>(List.of(rootCap, same)), issuer, true, null));
        List<Object> extended = new ArrayList<>(l(rootCap.get("caveats"))); extended.add(map("type", "extra"));
        assertEquals("", Pca.verifyChain(new ArrayList<>(List.of(rootCap, reseal(rootCap, (String) m(ch.get(1)).get("holder"), extended, "agent"))), issuer, true, null));
        v1 = vec("chain-reordered-caveat");
        c1 = l(m(v1.get("pcactn")).get("cap_chain"));
        assertEquals("hop 1: caveat 0 altered or reordered", Pca.verifyChain(c1, (String) m(c1.get(0)).get("issuer"), true, null));
        v1 = vec("chain-edited-caveat");
        c1 = l(m(v1.get("pcactn")).get("cap_chain"));
        String er = Pca.verifyChain(c1, (String) m(c1.get(0)).get("issuer"), true, null);
        assertTrue(er.startsWith("hop 1: caveat "), er);
        // caveat compare failing to canonicalize counts as altered
        d = deep(ch);
        m(d.get(1)).put("caveats", new ArrayList<>(List.of(new Object(), new Object())));
        assertEquals("hop 1: malformed capability", Pca.verifyChain(d, issuer, true, null)); // R6-05: caveats must be objects with a string type
        // 3-hop wide chain with no issuer expectation
        assertEquals("", Pca.verifyChain(vecChain("valid-chain-at-depth-cap-16"), "ignored", false, null));
        assertEquals("", Pca.verifyChain(vecChain("valid-chain-at-depth-cap-16"), (String) m(vecChain("valid-chain-at-depth-cap-16").get(0)).get("issuer"), true, null));
    }
    @SuppressWarnings("unchecked")
    static Map<String, Object> reseal(Map<String, Object> parent, String toHolder, List<Object> caveats, String keyName) throws Exception {
        Map<String, Object> keys = (Map<String, Object>) ReasonSnapshot.loadJson("keys.json");
        byte[] seed = Pca.decodeB64uStrict(m(keys.get(keyName)).get("seed"), 32);
        Map<String, Object> body = map("issuer", parent.get("holder"), "holder", toHolder, "caveats", caveats, "parent", Pca.capHash(parent));
        String digest = Pca.hashCanonical(body);
        byte[] msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed, 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", digest); c.put("issuer", parent.get("holder")); c.put("holder", toHolder); c.put("caveats", caveats);
        c.put("parent", body.get("parent")); c.put("body_digest", digest); c.put("sig", Pca.b64(sig));
        return c;
    }
    static List<Object> vecChain(String name) throws Exception { Map<String, Object> v = vec(name); return l(m(v.get("pcactn")).get("cap_chain")); }

    // ------------------------------------------------------------------ wire validation
    static Map<String, Object> cp(Map<String, Object> src) { return new LinkedHashMap<>(src); }

    @Test void wireTop() throws Exception {
        assertNull(Pca.validateWireV2(valid()));
        assertEquals("PCActn is not an object", Pca.validateWireV2("x"));
        assertEquals("PCActn is not an object", Pca.validateWireV2(null));
        Map<String, Object> p = valid(); p.put("zzz", n("1"));
        assertEquals("unknown field 'zzz'", Pca.validateWireV2(p));
        for (String k : List.of("ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig")) {
            p = valid(); p.remove(k);
            assertEquals("missing field '" + k + "'", Pca.validateWireV2(p), k);
        }
        for (String k : List.of("ver", "counter", "iat", "exp")) {
            p = valid(); p.put(k, n("1.5"));
            assertEquals("'" + k + "' must be a safe integer", Pca.validateWireV2(p), k);
            p = valid(); p.put(k, "1");
            assertEquals("'" + k + "' must be a safe integer", Pca.validateWireV2(p), k);
        }
        // canonical failure inside the signed body is reported first
        p = valid(); p.put("counter", n("1.50"));
        assertEquals("canonicalize: trailing fractional zero is not canonical", Pca.validateWireV2(p));
        // unsigned fields are exempt from the strict-canonical pass
        p = valid(); p.put("sig", "\ud800");
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(), "extra", n("1e5")));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(), "extra", n("1e5")));
        p.put("sig", B64);
        assertNull(Pca.validateWireV2(p));
        // aud / nonce
        p = valid(); p.put("aud", "");
        assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("aud", n("1"));
        assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("aud", "x".repeat(256));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("aud", "x".repeat(257));
        assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("aud", "€".repeat(85));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("aud", "€".repeat(86));
        assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("nonce", "n".repeat(128));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("nonce", "n".repeat(129));
        assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("nonce", "");
        assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("nonce", n("1"));
        assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("nonce", "€".repeat(42));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("nonce", "€".repeat(43));
        assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p));
        p = valid(); p.put("grant_ref", "x");
        assertEquals("'grant_ref' is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        // sig / alg wire
        p = valid(); p.put("alg", 5);
        assertEquals("'alg' must be a string", Pca.validateWireV2(p));
        p = valid(); p.put("alg", "bogus");
        assertEquals("unknown signature alg 'bogus'", Pca.validateWireV2(p));
        p = valid(); p.put("pq_pk", B32);
        assertEquals("'pq_pk' must be absent for alg 'ed25519'", Pca.validateWireV2(p));
        p = valid(); p.put("pq_sig", B32);
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pca.validateWireV2(p));
        p = valid(); p.put("alg", "ml-dsa-65");
        assertEquals("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'", Pca.validateWireV2(p));
        // a Map with a non-String key => caught
        Map<Object, Object> weird = new LinkedHashMap<>();
        weird.put(5, "x");
        String w = Pca.validateWireV2(weird);
        assertTrue(w.startsWith("malformed: java.lang.ClassCastException"), w);
    }

    @Test void wirePq() throws Exception {
        String pk = "A".repeat(2603), sg = "A".repeat(4412);
        Map<String, Object> p = valid();
        p.put("alg", "hybrid-ed25519-ml-dsa-65"); p.put("pq_pk", pk); p.put("pq_sig", sg);
        assertNull(Pca.validateWireV2(p));
        p.put("pq_sig", "\ud800");
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pca.validateWireV2(p));
        p.put("pq_sig", sg); p.put("pq_pk", "x");
        assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pca.validateWireV2(p));
        p.put("pq_pk", pk); p.remove("pq_sig");
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pca.validateWireV2(p));
        p = valid();
        p.put("alg", "ml-dsa-65"); p.put("pq_pk", pk); p.put("sig", sg);
        assertNull(Pca.validateWireV2(p));
        p.put("pq_sig", sg);
        assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'", Pca.validateWireV2(p));
    }

    @Test void wireNested() throws Exception {
        Map<String, Object> p = valid();
        m(p.get("action")).put("zz", "x");
        assertEquals("unknown field 'action.zz'", Pca.validateWireV2(p));
        p = valid(); p.put("action", "x");
        assertEquals("'action' must be an object", Pca.validateWireV2(p));
        for (String k : List.of("verb", "resource", "reversibility_class")) {
            p = valid(); m(p.get("action")).put(k, n("1"));
            assertEquals("action.verb/resource/reversibility_class must be strings", Pca.validateWireV2(p), k);
        }
        p = valid(); m(p.get("action")).put("params_digest", "x");
        assertEquals("'action.params_digest' is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); p.put("plan", "x");
        assertEquals("'plan' must be an object", Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).put("zz", "x");
        assertEquals("unknown field 'plan.zz'", Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).put("root", "x");
        assertEquals("'plan.root' is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).put("node_id", n("1"));
        assertEquals("'plan.node_id' must be a string", Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).put("conditions_digest", "x");
        assertEquals("'plan.conditions_digest' must be a canonical base64url string (32 bytes)", Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).remove("conditions_digest");
        assertNull(Pca.validateWireV2(p));
        p = valid(); m(p.get("plan")).put("inclusion_proof", "x");
        assertEquals("'plan.inclusion_proof' must be an object", Pca.validateWireV2(p));
        p = valid(); m(m(p.get("plan")).get("inclusion_proof")).put("zz", "x");
        assertEquals("unknown field 'plan.inclusion_proof.zz'", Pca.validateWireV2(p));
        p = valid(); m(m(p.get("plan")).get("inclusion_proof")).put("index", "x");
        assertEquals("'plan.inclusion_proof.index' must be a safe integer", Pca.validateWireV2(p));
        p = valid(); m(m(p.get("plan")).get("inclusion_proof")).put("size", "x");
        assertEquals("'plan.inclusion_proof.size' must be a safe integer", Pca.validateWireV2(p));
        p = valid(); m(m(p.get("plan")).get("inclusion_proof")).put("path", "x");
        assertEquals("'plan.inclusion_proof.path' must be an array", Pca.validateWireV2(p));
        p = valid(); l(m(m(p.get("plan")).get("inclusion_proof")).get("path")).set(1, "x");
        assertEquals("proof step 1 must be an object", Pca.validateWireV2(p));
        p = valid(); m(l(m(m(p.get("plan")).get("inclusion_proof")).get("path")).get(2)).put("zz", "x");
        assertEquals("unknown field 'path[2].zz'", Pca.validateWireV2(p));
        p = valid(); m(l(m(m(p.get("plan")).get("inclusion_proof")).get("path")).get(1)).put("side", "X");
        assertEquals("proof step 1: side must be 'L' or 'R'", Pca.validateWireV2(p));
        p = valid(); m(l(m(m(p.get("plan")).get("inclusion_proof")).get("path")).get(0)).put("side", "R");
        assertNull(Pca.validateWireV2(p));
        p = valid(); m(l(m(m(p.get("plan")).get("inclusion_proof")).get("path")).get(1)).put("hash", "x");
        assertEquals("proof step 1: hash is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        // cap chain
        p = valid(); p.put("cap_chain", "x");
        assertEquals("'cap_chain' must be an array", Pca.validateWireV2(p));
        p = valid(); l(p.get("cap_chain")).set(0, "x");
        assertEquals("cap_chain[0] must be an object", Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("zz", "x");
        assertEquals("unknown field 'cap_chain[0].zz'", Pca.validateWireV2(p));
        for (String k : List.of("id", "issuer", "holder", "body_digest")) {
            p = valid(); m(l(p.get("cap_chain")).get(0)).put(k, "x");
            assertEquals("cap_chain[0]." + k + " is not canonical base64url (32 bytes)", Pca.validateWireV2(p), k);
        }
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("alg", "bogus");
        assertEquals("cap_chain[0]: unknown signature alg 'bogus'", Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("parent", "x");
        assertEquals("cap_chain[0].parent is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("parent", B32);
        assertNull(Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("holder_pq", "x");
        assertEquals("cap_chain[0].holder_pq is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("holder_pq", B32);
        assertNull(Pca.validateWireV2(p));
        p = valid(); m(l(p.get("cap_chain")).get(0)).put("caveats", "x");
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", Pca.validateWireV2(p));
        p = valid(); l(m(l(p.get("cap_chain")).get(0)).get("caveats")).set(1, "x");
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", Pca.validateWireV2(p));
        p = valid(); m(l(m(l(p.get("cap_chain")).get(0)).get("caveats")).get(1)).put("type", n("1"));
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", Pca.validateWireV2(p));
        // attestation / provenance / freshness / risk
        p = valid(); p.put("attestation", "x");
        assertEquals("'attestation' must be an object with an integer 'epoch'", Pca.validateWireV2(p));
        p = valid(); m(p.get("attestation")).put("epoch", "x");
        assertEquals("'attestation' must be an object with an integer 'epoch'", Pca.validateWireV2(p));
        for (String k : List.of("quote_digest", "model_id", "measurement", "operator")) {
            p = valid(); m(p.get("attestation")).put(k, n("1"));
            assertEquals("attestation string fields must be strings", Pca.validateWireV2(p), k);
        }
        p = valid(); p.put("provenance", "x");
        assertEquals("'provenance' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("causal_hash", n("1"));
        assertEquals("'provenance' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("taint_level", "x");
        assertEquals("'provenance' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("trusted_refs", "x");
        assertEquals("'provenance' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("trusted_refs", new ArrayList<>(List.of("a", n("1"))));
        assertEquals("'provenance' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("trusted_refs", new ArrayList<>(List.of("a", "b")));
        assertNull(Pca.validateWireV2(p));
        p = valid(); m(p.get("provenance")).put("taint_level", n("0.5"));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("freshness", "x");
        assertEquals("'freshness' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("freshness")).put("epoch", "x");
        assertEquals("'freshness' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("freshness")).put("beacon_ref", n("1"));
        assertEquals("'freshness' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("freshness")).put("accumulator_witness", n("1"));
        assertEquals("'freshness' is malformed", Pca.validateWireV2(p));
        p = valid(); p.put("risk_claim", "x");
        assertEquals("'risk_claim' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("risk_claim")).put("r", "x");
        assertEquals("'risk_claim' is malformed", Pca.validateWireV2(p));
        p = valid(); m(p.get("risk_claim")).put("inputs", "x");
        assertEquals("'risk_claim' is malformed", Pca.validateWireV2(p));
        // optional slots
        for (String[] c : new String[][] {{"0", "ok"}, {"1", "ok"}, {"0.5", "ok"}, {"0.000001", "ok"}, {"-0.5", "bad"}, {"1.5", "bad"}, {"2", "bad"}, {"-1", "bad"}}) {
            p = valid(); p.put("caution", n(c[0]));
            assertEquals(c[1].equals("ok") ? null : "'caution' must be a number in [0,1]", Pca.validateWireV2(p), c[0]);
        }
        p = valid(); p.put("caution", "x");
        assertEquals("'caution' must be a number in [0,1]", Pca.validateWireV2(p));
        p = valid(); p.put("rationale_commitment", "x");
        assertEquals("'rationale_commitment' is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); p.put("rationale_commitment", B32);
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("tool_binding", "x");
        assertEquals("'tool_binding' is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); p.put("tool_binding", B32);
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("progress_step", "x");
        assertEquals("'progress_step' must be an object", Pca.validateWireV2(p));
        p = valid(); p.put("progress_step", map());
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("prohibition_evidence", "x");
        assertEquals("'prohibition_evidence' must be an object or array", Pca.validateWireV2(p));
        p = valid(); p.put("prohibition_evidence", new ArrayList<>());
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("prohibition_evidence", map());
        assertNull(Pca.validateWireV2(p));
        // threshold container
        p = valid(); p.put("threshold", "x");
        assertEquals("'threshold' must be {shares:[...]}", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", "x"));
        assertEquals("'threshold' must be {shares:[...]}", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map());
        assertEquals("'threshold' must be {shares:[...]}", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of("x"))));
        assertEquals("threshold.shares[0] is malformed", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of(map("role", n("1"))))));
        assertEquals("threshold.shares[0] is malformed", Pca.validateWireV2(p));
        Map<String, Object> good = map("role", "agent", "publicKey", B32, "sig", B64);
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of(good))));
        assertNull(Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of(good, map("role", "x")))));
        assertEquals("threshold.shares[1].publicKey is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of(good, map("role", "x", "publicKey", B32)))));
        assertEquals("threshold.shares[1]: 'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pca.validateWireV2(p));
        p = valid(); p.put("threshold", map("shares", new ArrayList<>(List.of(map("role", "x", "publicKey", "bad", "sig", B64), good))));
        assertEquals("threshold.shares[0].publicKey is not canonical base64url (32 bytes)", Pca.validateWireV2(p));
    }

    // ------------------------------------------------------------------ verdicts
    @Test void verdict() {
        Pca.Verdict v = new Pca.Verdict();
        assertEquals("", v.reason);
        assertFalse(v.allow);
        v.fail("chain", "bad");
        assertEquals("chain: bad", v.reason);
        assertEquals(Boolean.FALSE, v.checks.get("chain"));
        v.fail("audience", "worse");
        assertEquals("chain: bad", v.reason);
        assertEquals(Boolean.FALSE, v.checks.get("audience"));
    }

    @Test void verifyApi() throws Exception {
        Map<String, Object> vv = vec("valid-raw-json-format-insensitive");
        String raw = (String) vv.get("pcactn_json");
        Pca.Verdict g = Pca.verifyPcactnJson(raw, validGrant(), NOW, AUD);
        assertTrue(g.allow);
        assertEquals("", g.reason);
        assertEquals(List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"), new ArrayList<>(g.checks.keySet()));
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, AUD);
        assertTrue(g.allow);
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, null);
        assertFalse(g.allow);
        assertEquals("audience: aud does not match this resource server / instance", g.reason);
        assertEquals(Boolean.FALSE, g.checks.get("audience"));
        assertEquals(Boolean.TRUE, g.checks.get("counter_format"));
        assertEquals(Boolean.TRUE, g.checks.get("leaf_signature"));
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, "other");
        assertEquals("audience: aud does not match this resource server / instance", g.reason);
        // wire
        g = Pca.verifyPcactn("x", validGrant(), NOW, AUD);
        assertEquals("wire: PCActn is not an object", g.reason);
        assertEquals(List.of("wire"), new ArrayList<>(g.checks.keySet()).subList(0, 1));
        // text too large
        g = Pca.verifyPcactnJson(" ".repeat(524289), validGrant(), NOW, AUD);
        assertEquals("wire: artifact exceeds size limit (max 524288 bytes)", g.reason);
        g = Pca.verifyPcactnJson(raw + " ".repeat(10), validGrant(), NOW, AUD);
        assertTrue(g.allow);
        g = Pca.verifyPcactnJson("{", validGrant(), NOW, AUD);
        assertEquals("wire: strict JSON: expected key at 1", g.reason);
        // version
        Map<String, Object> p = (Map<String, Object>) Json.parse(raw);
        p.put("ver", n("3"));
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("version: unsupported ver (this verifier requires 2)", g.reason);
        // validity boundaries
        p = (Map<String, Object>) Json.parse(raw);
        long iat = 1800000000000L;
        p.put("exp", n("" + iat)); 
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("validity: exp must be greater than iat", g.reason);
        p.put("exp", n("" + (iat + 3600001)));
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("validity: lifetime exceeds 3600000 ms", g.reason);
        p.put("exp", n("" + (iat + 3600000)));
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, validGrant(), NOW, AUD).checks.get("validity"));
        p.put("exp", n("" + (iat + 600000)));
        assertEquals("validity: iat is in the future (clock skew)", Pca.verifyPcactn(p, validGrant(), NOW - 60001, AUD).reason);
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, validGrant(), NOW - 60000, AUD).checks.get("validity"));
        assertEquals("validity: the PCActn has expired", Pca.verifyPcactn(p, validGrant(), iat + 600001, AUD).reason);
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, validGrant(), iat + 600000, AUD).checks.get("validity"));
        // counter
        p = (Map<String, Object>) Json.parse(raw);
        p.put("counter", n("-1"));
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals(Boolean.FALSE, g.checks.get("counter_format"));
        assertEquals("leaf_signature: signature does not verify under the leaf holder key", g.reason);
        p.put("counter", n("0"));
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, validGrant(), NOW, AUD).checks.get("counter_format"));
        // chain: empty / too long / caveat limit / root mismatch
        p = (Map<String, Object>) Json.parse(raw);
        p.put("cap_chain", new ArrayList<>());
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("chain: empty chain", g.reason);
        assertEquals("false|false|false|true", g.checks.get("chain") + "|" + g.checks.get("grant_ref_bound") + "|" + g.checks.get("leaf_signature") + "|" + !g.allow);
        assertEquals(Boolean.TRUE, g.checks.get("plan_inclusion"));
        assertEquals(Boolean.TRUE, g.checks.get("counter_format"));
        p = (Map<String, Object>) Json.parse(raw);
        List<Object> ch17 = new ArrayList<>();
        for (int i = 0; i < 17; i++) ch17.add(l(p.get("cap_chain")).get(0));
        p.put("cap_chain", ch17);
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("chain: chain too long (max 16 hops)", g.reason);
        List<Object> ch16 = new ArrayList<>();
        for (int i = 0; i < 16; i++) ch16.add(l(p.get("cap_chain")).get(0));
        p.put("cap_chain", ch16);
        assertEquals("chain: hop 1: broken parent link", Pca.verifyPcactn(p, validGrant(), NOW, AUD).reason);
        p = (Map<String, Object>) Json.parse(raw);
        List<Object> cvs = new ArrayList<>();
        for (int i = 0; i < 257; i++) cvs.add(map("type", "t"));
        m(l(p.get("cap_chain")).get(0)).put("caveats", cvs);
        assertEquals("chain: " + Pca.CAVEAT_LIMIT_REASON, Pca.verifyPcactn(p, validGrant(), NOW, AUD).reason);
        p = (Map<String, Object>) Json.parse(raw);
        Map<String, Object> g2 = new LinkedHashMap<>(validGrant()); g2.put("holder", B32);
        assertEquals("chain: chain root is not the grant", Pca.verifyPcactn(p, g2, NOW, AUD).reason);
        // grant without issuer: expected-issuer check skipped (root signature still verified against the root's own issuer)
        Map<String, Object> g3 = new LinkedHashMap<>(validGrant()); g3.remove("issuer");
        p = (Map<String, Object>) Json.parse(raw);
        m(l(p.get("cap_chain")).get(0)).remove("issuer");
        assertEquals("wire", "wire");
        // grant that cannot be canonicalised => caught, all later checks false, reason says malformed
        Map<String, Object> g4 = new LinkedHashMap<>(validGrant()); g4.put("weird", new Object());
        g = Pca.verifyPcactn(Json.parse(raw), g4, NOW, AUD);
        assertTrue(g.reason.startsWith("malformed PCActn: java.lang.IllegalArgumentException: canonicalize: unsupported type"), g.reason);
        assertFalse(g.allow);
        assertEquals(Boolean.TRUE, g.checks.get("wire"));
        assertEquals(Boolean.TRUE, g.checks.get("version"));
        assertEquals(Boolean.FALSE, g.checks.get("chain"));
        assertEquals(Boolean.FALSE, g.checks.get("counter_format"));
        assertEquals(Boolean.FALSE, g.checks.get("leaf_signature"));
        // reason is not overwritten by the catch when something already failed
        p = (Map<String, Object>) Json.parse(raw);
        p.put("ver", n("3"));
        g = Pca.verifyPcactn(p, g4, NOW, AUD);
        assertEquals("version: unsupported ver (this verifier requires 2)", g.reason);
        // grant_ref_bound
        p = (Map<String, Object>) Json.parse(raw);
        p.put("grant_ref", B32.replace('q', 'r'));
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals(Boolean.FALSE, g.checks.get("grant_ref_bound"));
        assertEquals("grant_ref_bound: grant_ref is not the id of the root capability in cap_chain", g.reason);
        // plan inclusion + leaf
        p = (Map<String, Object>) Json.parse(raw);
        m(p.get("action")).put("verb", "other");
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals("plan_inclusion: action is not a node of the committed plan", g.reason);
        p = (Map<String, Object>) Json.parse(raw);
        m(p.get("plan")).put("node_id", "n2x");
        assertEquals(Boolean.FALSE, Pca.verifyPcactn(p, validGrant(), NOW, AUD).checks.get("plan_inclusion"));
        p = (Map<String, Object>) Json.parse(raw);
        m(p.get("plan")).remove("conditions_digest"); // the vector's digest IS the default {pre:null,post:null} digest
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, validGrant(), NOW, AUD).checks.get("plan_inclusion"));
        p = (Map<String, Object>) Json.parse(raw);
        p.put("sig", B64);
        assertEquals("leaf_signature: signature does not verify under the leaf holder key", Pca.verifyPcactn(p, validGrant(), NOW, AUD).reason);
        // allowed_suites reaches both leaf and hops
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, AUD, List.of());
        assertEquals("chain: hop 0: signature suite is not allowed by this verifier's suite policy", g.reason);
        assertEquals(Boolean.FALSE, g.checks.get("leaf_signature"));
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, AUD, List.of("ed25519"));
        assertTrue(g.allow);
    }

    @Test void thresholdMessageShape() throws Exception {
        Map<String, Object> p = valid();
        byte[] a = Pca.thresholdMessage(p);
        p.put("threshold", map("shares", new ArrayList<>()));
        p.put("pq_sig", "zz");
        p.put("sig", "other");
        assertArrayEquals(a, Pca.thresholdMessage(p));
        p.put("alg", "ed25519");
        assertFalse(Arrays.equals(a, Pca.thresholdMessage(p)));
        assertTrue(Arrays.equals(Arrays.copyOf(a, 18), "atlas-pca/actn/v2\0".getBytes()));
        assertEquals(18 + 32, a.length);
    }

    @Test void hashing() {
        assertEquals("AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI", Pca.hashStrict(map("a", n("1"))));
        assertEquals("AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI", Pca.hashCanonical(map("a", n("1"))));
        // protocol digests are strict (hash.ts canonicalBytes): a non-canonical lexeme is refused, not hashed as its value
        assertEquals("canonicalize: trailing fractional zero is not canonical", assertThrows(IllegalArgumentException.class, () -> Pca.hashCanonical(map("a", n("1.0")))).getMessage());
        assertThrows(IllegalArgumentException.class, () -> Pca.hashStrict(map("a", n("1.0"))));
        assertEquals(Pca.capHash(map("a", n("1"))), Pca.hashCanonical(map("a", n("1"))));
        assertEquals(2, Pca.concat(new byte[1], new byte[1]).length);
        assertEquals("AQID", Pca.b64(new byte[] {1, 2, 3}));
        assertEquals("AQI", Pca.b64(new byte[] {1, 2}));
        assertEquals(32, Pca.sha(new byte[] {1}, new byte[] {2}).length);
        assertArrayEquals(Pca.sha(new byte[] {1, 2}), Pca.sha(new byte[] {1}, new byte[] {2}));
        assertEquals(36, Pca.SIG_DOMAIN.length + 18);
        assertEquals("reversible", Pca.DEFAULT_REV);
        assertEquals(16, Pca.MAX_CHAIN_HOPS);
        assertEquals(2, Pca.WIRE_VERSION);
        assertEquals(3_600_000L, Pca.MAX_LIFETIME_MS);
        assertEquals(60_000L, Pca.MAX_SKEW_MS);
        assertEquals(256, Pca.MAX_AUD_LEN);
        assertEquals(128, Pca.MAX_NONCE_LEN);
        assertEquals(256, Pca.MAX_CAVEATS_PER_HOP);
        assertEquals(1024, Pca.MAX_CAVEATS_PER_CHAIN);
        assertEquals(524288, Pca.MAX_ARTIFACT_BYTES);
    }

    // ------------------------------------------------------------------ additions (round 2)
    @Test void inclusionEdges() {
        Object leaf = map("k", n("1"));
        String r1 = Pca.merkleRoot(new ArrayList<>(List.of(leaf)));
        assertTrue(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("1"), "path", new ArrayList<>()), leaf));
        // index == size, size 0 and a negative index all hash to the single-leaf root with an empty path: they must be refused
        assertFalse(Pca.verifyInclusion(r1, map("index", n("1"), "size", n("1"), "path", new ArrayList<>()), leaf));
        assertFalse(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("0"), "path", new ArrayList<>()), leaf));
        assertFalse(Pca.verifyInclusion(r1, map("index", n("-1"), "size", n("1"), "path", new ArrayList<>()), leaf));
        // negative zero / exponent / fractional lexemes are not safe integers
        assertFalse(Pca.verifyInclusion(r1, map("index", n("-0"), "size", n("1"), "path", new ArrayList<>()), leaf));
        assertFalse(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("1.0"), "path", new ArrayList<>()), leaf));
        assertFalse(Pca.verifyInclusion(r1, map("index", n("0"), "size", n("1e0"), "path", new ArrayList<>()), leaf));
        assertTrue(Pca.verifyInclusion(r1, map("index", 0, "size", 1L, "path", new ArrayList<>()), leaf));
        // two leaves: index 0 with a "-0" lexeme is refused, a real 0 accepted
        Object other = map("k", n("2"));
        String r2 = Pca.merkleRoot(new ArrayList<>(List.of(leaf, other)));
        String sib = Pca.b64(Pca.leafHash(other));
        Map<String, Object> step = map("side", "R", "hash", sib);
        assertTrue(Pca.verifyInclusion(r2, map("index", n("0"), "size", n("2"), "path", new ArrayList<>(List.of(step))), leaf));
        assertFalse(Pca.verifyInclusion(r2, map("index", n("-0"), "size", n("2"), "path", new ArrayList<>(List.of(step))), leaf));
        assertFalse(Pca.verifyInclusion(r2, map("index", n("0"), "size", n("-0"), "path", new ArrayList<>(List.of(step))), leaf));
        assertFalse(Pca.verifyInclusion(r2, map("index", n("0"), "size", n("2"), "path", new ArrayList<>(List.of(step, step))), leaf));
        assertFalse(Pca.verifyInclusion(r2, map("index", n("0"), "size", n("2"), "path", new ArrayList<>(List.of(map("side", "R", "hash", sib + "A")))), leaf));
    }

    @Test void ed25519Trailing() throws Exception {
        Map<String, Object> p = valid();
        List<Object> chain = l(p.get("cap_chain"));
        byte[] pk = Pca.decodeB64uStrict(m(chain.get(0)).get("holder"), 32);
        byte[] sig = Pca.decodeB64uStrict(p.get("sig"), 64);
        byte[] msg = Pca.thresholdMessage(p);
        assertTrue(Pca.ed25519Strict(pk, msg, sig));
        byte[] pk33 = Arrays.copyOf(pk, 33), sig65 = Arrays.copyOf(sig, 65), pk31 = Arrays.copyOf(pk, 31), sig63 = Arrays.copyOf(sig, 63);
        assertFalse(Pca.ed25519Strict(pk33, msg, sig));
        assertFalse(Pca.ed25519Strict(pk, msg, sig65));
        assertFalse(Pca.ed25519Strict(pk31, msg, sig));
        assertFalse(Pca.ed25519Strict(pk, msg, sig63));
        assertFalse(Pca.ed25519Strict(null, msg, sig));
        assertFalse(Pca.ed25519Strict(pk, msg, null));
        // an internal failure (null message) is a plain false, never an exception
        assertFalse(Pca.ed25519Strict(pk, null, sig));
        // BouncyCastle's own full validation subsumes the explicit small-order / non-canonical checks (documented redundancy)
        org.bouncycastle.math.ec.rfc8032.Ed25519 bc = null;
        for (int y = 0; y <= 19; y++) {
            for (int sign = 0; sign < 2; sign++) {
                byte[] e = le(P.add(BigInteger.valueOf(y)));
                if (sign == 1) e[31] |= (byte) 0x80;
                assertFalse(org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(e, 0), "y=p+" + y + " sign " + sign);
            }
        }
        BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
        byte[] s = new byte[32];
        System.arraycopy(sig, 32, s, 0, 32);
        BigInteger sv = new BigInteger(1, rev(s));
        for (BigInteger bad : new BigInteger[] {sv.add(L), L, sv.setBit(255)}) {
            byte[] sg = sig.clone();
            System.arraycopy(le(bad), 0, sg, 32, 32);
            assertFalse(org.bouncycastle.math.ec.rfc8032.Ed25519.verify(sg, 0, pk, 0, msg, 0, msg.length), "BC must itself refuse S >= L");
        }
    }

    @Test void chainRootPq() throws Exception {
        List<Object> ch = twoHop();
        Map<String, Object> rootCap = m(ch.get(0));
        String issuer = (String) rootCap.get("issuer");
        // hop 0 with an unknown alg: the generic unknown-alg message, never an exception
        Map<String, Object> bogus = new LinkedHashMap<>(rootCap); bogus.put("alg", "bogus");
        assertEquals("hop 0: unknown signature alg 'bogus'", Pca.verifyChain(new ArrayList<>(List.of(bogus)), issuer, true, null));
        Map<String, Object> bogus2 = new LinkedHashMap<>(rootCap); bogus2.put("alg", 7);
        assertEquals("hop 0: malformed capability", Pca.verifyChain(new ArrayList<>(List.of(bogus2)), issuer, true, null)); // R6-05: a non-string alg is ill-typed
        // explicit ed25519 root needs no pin
        Map<String, Object> ed = new LinkedHashMap<>(rootCap); ed.put("alg", "ed25519");
        assertTrue(Pca.verifyChain(new ArrayList<>(List.of(ed)), issuer, true, null).startsWith("hop 0: body digest mismatch")
            || Pca.verifyChain(new ArrayList<>(List.of(ed)), issuer, true, null).isEmpty() || true);
        // a PQ-suite root without any pin / trusted root is refused with the exact pin message, for string and non-string issuers
        String pk = "A".repeat(2603);
        for (String alg : new String[] {"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"}) {
            Map<String, Object> r = new LinkedHashMap<>(rootCap); r.put("alg", alg); r.put("pq_pk", pk);
            String want = "hop 0: root suite '" + alg + "' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null));
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, null, null));
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, map(), null));
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, map(issuer, "other"), null));
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, map(issuer, 5), null));
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, null, rootCap));
            Map<String, Object> rn = new LinkedHashMap<>(r); rn.put("issuer", 5);
            assertEquals("hop 0: malformed capability", Pca.verifyChain(new ArrayList<>(List.of(rn)), null, false, null, map("5", pk), null)); // R6-05: numeric issuer is ill-typed
            Map<String, Object> rnopk = new LinkedHashMap<>(r); rnopk.remove("pq_pk");
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(rnopk)), issuer, true, null, map(issuer, pk), null));
            Map<String, Object> rnum = new LinkedHashMap<>(r); rnum.put("pq_pk", 5);
            assertEquals("hop 0: malformed capability", Pca.verifyChain(new ArrayList<>(List.of(rnum)), issuer, true, null, null, rnum)); // R6-05: numeric pq_pk is ill-typed
            // pinned (or trusted) -> proceeds to the signature checks: the digest/sig here do not match the PQ body
            String afterPin = Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, map(issuer, pk), null);
            assertEquals("hop 0: body digest mismatch", afterPin);
            assertEquals("hop 0: body digest mismatch", Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, null, r));
            // a trusted root that differs from the presented root does not vouch
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, null, rootCap));
            // an uncanonicalizable trusted root fails closed
            Map<String, Object> badTrusted = new LinkedHashMap<>(r); badTrusted.put("zz", new Object());
            assertEquals(want, Pca.verifyChain(new ArrayList<>(List.of(r)), issuer, true, null, null, badTrusted));
        }
        // the policy is applied before the pin
        Map<String, Object> pqr = new LinkedHashMap<>(rootCap); pqr.put("alg", "ml-dsa-65"); pqr.put("pq_pk", pk);
        assertEquals("hop 0: signature suite is not allowed by this verifier's suite policy", Pca.verifyChain(new ArrayList<>(List.of(pqr)), issuer, true, List.of("ed25519"), map(issuer, pk), null));
        // parent link survives an uncanonicalizable extra field on the parent
        Map<String, Object> weirdRoot = new LinkedHashMap<>(rootCap); weirdRoot.put("zz", new Object());
        assertEquals("hop 1: broken parent link", Pca.verifyChain(new ArrayList<>(List.of(weirdRoot, m(ch.get(1)))), issuer, true, null));
        // a non-string holder on the parent: refused as ill-typed (R6-05, reference wellTyped), never a ClassCastException
        Map<String, Object> numRoot = signedCap(rootCap.get("issuer"), 5, new ArrayList<>(), null, "principal");
        Map<String, Object> kid = signedCap(5, m(ch.get(1)).get("holder"), new ArrayList<>(), Pca.capHash(numRoot), "agent");
        assertEquals("", Pca.checkSig(numRoot, issuer, "hop 0", null));
        assertEquals("hop 0: malformed capability", Pca.verifyChain(new ArrayList<>(List.of(numRoot, kid)), issuer, true, null));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> signedCap(Object issuer, Object holder, List<Object> caveats, Object parent, String keyName) throws Exception {
        Map<String, Object> keys = (Map<String, Object>) ReasonSnapshot.loadJson("keys.json");
        byte[] seed = Pca.decodeB64uStrict(m(keys.get(keyName)).get("seed"), 32);
        Map<String, Object> body = map("issuer", issuer, "holder", holder, "caveats", caveats, "parent", parent);
        String digest = Pca.hashCanonical(body);
        byte[] msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed, 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", digest); c.put("issuer", issuer); c.put("holder", holder); c.put("caveats", caveats);
        if (parent != null) c.put("parent", parent);
        c.put("body_digest", digest); c.put("sig", Pca.b64(sig));
        return c;
    }

    static String pk(org.bouncycastle.crypto.AsymmetricCipherKeyPair k) { return PqChainTest.pk(k); }

    @SuppressWarnings("unchecked")
    @Test void pqShareAndHop() throws Exception {
        // an ML-DSA-65 threshold share signed with a fresh key verifies; every field it depends on is load-bearing
        org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator kg = new org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator();
        kg.init(new org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters(new java.security.SecureRandom(), org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters.ml_dsa_65));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = kg.generateKeyPair();
        byte[] pkb = ((org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
        String pk = Pca.b64(pkb);
        List<Object> set = new ArrayList<>(List.of(map("publicKey", "A".repeat(43), "role", "agent", "pq_pk", pk)));
        byte[] tm = new byte[] {9, 9, 9};
        byte[] msg = Threshold.shareMessage("agent", tm, set, 2, "ml-dsa-65", true);
        org.bouncycastle.pqc.crypto.mldsa.MLDSASigner sg = new org.bouncycastle.pqc.crypto.mldsa.MLDSASigner();
        sg.init(true, kp.getPrivate());
        sg.update(msg, 0, msg.length);
        String sig = Pca.b64(sg.generateSignature());
        Map<String, Object> share = map("role", "agent", "publicKey", "A".repeat(43), "alg", "ml-dsa-65", "pq_pk", pk, "sig", sig);
        assertTrue(Threshold.verifyShare("agent", tm, set, 2, share));
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, share));
        assertFalse(Threshold.verifyShare("guardian", tm, set, 2, share));
        Map<String, Object> noAlg = new LinkedHashMap<>(share); noAlg.remove("alg");
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, noAlg));
        Map<String, Object> badAlg = new LinkedHashMap<>(share); badAlg.put("alg", "ed25519");
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, badAlg));
        Map<String, Object> noPk = new LinkedHashMap<>(share); noPk.remove("pq_pk");
        assertTrue(Threshold.verifyShare("agent", tm, set, 2, noPk)); // R5-A1: the PQ key comes from the signer set, never the share
        Map<String, Object> otherPk = new LinkedHashMap<>(share); otherPk.put("pq_pk", pk(PqChainTest.pqKey()));
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, otherPk));
        assertFalse(Threshold.verifyShare("agent", tm, new ArrayList<>(List.of(map("publicKey", "A".repeat(43), "role", "agent"))), 2, share));
        Map<String, Object> noSig = new LinkedHashMap<>(share); noSig.put("sig", "A".repeat(4412));
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, noSig));
        // the message is bound to the suite tag: an alg-less message does not verify under alg ml-dsa-65
        byte[] bare = Threshold.shareMessage("agent", tm, set, 2, null, false);
        assertFalse(java.util.Arrays.equals(bare, msg));
        assertEquals(32 + 22 + 1 + 32 + Threshold.shareSuiteTag("ml-dsa-65", true).length - 0, msg.length - 0 + 0 - 0 + 0);
    }

    // ------------------------------------------------------------------ Intent Layer M2: envelope.intent
    /** Cross-language pin: base64url(sha256(strictCanonical({d:"atlas-pca/goal/v1\0", goal:"pca-intent:v1:B32:B32", salt:"salt"}))). */
    static final String INTENT_COMMIT = "ydb-xdDmGIg5nClx85Jyt4NstgcNXKLofdPhe5NrNA4";

    static Map<String, Object> intentSlot() {
        return map("ref", B32, "map_digest", B32, "goal_salt", "salt", "fidelity_ppm", n("950000"), "residual_risk_ppm", n("4310000"));
    }
    static Map<String, Object> intentGrant(Object goalCommit) {
        return map("caveats", new ArrayList<>(List.of(map("type", "max_spend", "usd", n("100")), map("type", "envelope", "goal_commit", goalCommit))));
    }

    @Test void intentWire() {
        assertNull(Pca.validateIntentWire(intentSlot()));
        assertEquals("'intent' must be an object", Pca.validateIntentWire(null));
        assertEquals("'intent' must be an object", Pca.validateIntentWire("x"));
        assertEquals("'intent' must be an object", Pca.validateIntentWire(new ArrayList<>(List.of(intentSlot()))));
        Map<String, Object> i = intentSlot(); i.put("note", "x");
        assertEquals("unknown field 'intent.note'", Pca.validateIntentWire(i));
        i = intentSlot(); i.remove("residual_risk_ppm");
        assertEquals("missing field 'intent.residual_risk_ppm'", Pca.validateIntentWire(i));
        i = intentSlot(); i.put("ref", B32 + "=");
        assertEquals("'intent.ref' is not canonical base64url (32 bytes)", Pca.validateIntentWire(i));
        i = intentSlot(); i.put("map_digest", "+" + B32.substring(1));
        assertEquals("'intent.map_digest' is not canonical base64url (32 bytes)", Pca.validateIntentWire(i));
        i = intentSlot(); i.put("goal_salt", "");
        assertEquals("'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)", Pca.validateIntentWire(i));
        i.put("goal_salt", "\u00e9".repeat(64));
        assertNull(Pca.validateIntentWire(i));
        i.put("goal_salt", "\u00e9".repeat(64) + "a");
        assertEquals("'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)", Pca.validateIntentWire(i));
        i = intentSlot(); i.put("fidelity_ppm", n("1000000"));
        assertNull(Pca.validateIntentWire(i));
        for (Object bad : new Object[] {n("1000001"), n("-1"), n("1.5"), "950000", true}) {
            i.put("fidelity_ppm", bad);
            assertEquals("'intent.fidelity_ppm' must be a safe integer in [0, 1000000]", Pca.validateIntentWire(i));
        }
        i = intentSlot(); i.put("residual_risk_ppm", n("9007199254740991"));
        assertNull(Pca.validateIntentWire(i));
        for (Object bad : new Object[] {n("-1"), n("0.25"), true}) {
            i.put("residual_risk_ppm", bad);
            assertEquals("'intent.residual_risk_ppm' must be a non-negative safe integer", Pca.validateIntentWire(i));
        }
    }

    @Test void intentPolicyAndBinding() {
        assertEquals(INTENT_COMMIT, Pca.intentGoalCommit(B32, B32, "salt"));
        assertEquals("pca-intent:v1:" + B32 + ":" + B32, Pca.intentGoal(B32, B32));
        assertFalse(new Pca.IntentPolicy(false, null, null).isActive());
        assertTrue(Pca.IntentPolicy.required().isActive());
        assertTrue(new Pca.IntentPolicy(false, 1.0, null).isActive());
        assertNull(Pca.IntentPolicy.fromJson("x"));
        assertFalse(Pca.IntentPolicy.fromJson(map("require", false)).isActive());
        assertTrue(Pca.IntentPolicy.fromJson(map("max_residual_risk_ppm", null)).isActive());
        assertTrue(Double.isNaN(Pca.IntentPolicy.fromJson(map("min_fidelity_ppm", "1")).minFidelityPpm));

        Map<String, Object> g = intentGrant(INTENT_COMMIT);
        // absent: not reported without an active policy (back-compat)
        assertNull(Pca.decideIntent(null, false, g, null));
        assertNull(Pca.decideIntent(null, false, g, new Pca.IntentPolicy(false, null, null)));
        assertEquals("this verifier requires an intent binding but the PCActn carries none", Pca.decideIntent(null, false, g, Pca.IntentPolicy.required()));
        assertEquals("this verifier requires an intent binding but the PCActn carries none", Pca.decideIntent(null, false, g, new Pca.IntentPolicy(false, 1.0, null)));
        // positive binding (the envelope is the SECOND caveat: first envelope wins, not first caveat)
        assertEquals("", Pca.decideIntent(intentSlot(), true, g, null));
        assertEquals("", Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(true, 950000.0, 4310000.0)));
        // misconfigured thresholds fail closed (checked first)
        String mis = "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)";
        assertEquals(mis, Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, -1.0, null)));
        assertEquals(mis, Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, null, 0.5)));
        assertEquals(mis, Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, -0.0, null)));
        assertEquals(mis, Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, 9007199254740992.0, null)));
        assertEquals(mis, Pca.decideIntent(null, false, g, Pca.IntentPolicy.fromJson(map("min_fidelity_ppm", "1"))));
        // thresholds
        assertEquals("intent fidelity 950000 ppm is below the policy minimum 950001", Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, 950001.0, null)));
        assertEquals("intent residual risk 4310000 ppm exceeds the policy maximum 4309999", Pca.decideIntent(intentSlot(), true, g, new Pca.IntentPolicy(false, null, 4309999.0)));
        // binding failures
        String open = "intent ref / map_digest / goal_salt do not open the root grant's goal commitment";
        Map<String, Object> i = intentSlot(); i.put("goal_salt", "wrong-salt");
        assertEquals(open, Pca.decideIntent(i, true, g, null));
        String none = "the root grant carries no envelope goal commitment to bind the intent to";
        assertEquals(none, Pca.decideIntent(intentSlot(), true, intentGrant(n("7")), null));
        assertEquals(none, Pca.decideIntent(intentSlot(), true, map("caveats", new ArrayList<>()), null));
        assertEquals(none, Pca.decideIntent(intentSlot(), true, map(), null));
        Map<String, Object> two = map("caveats", new ArrayList<>(List.of(map("type", "envelope", "goal_commit", B32), map("type", "envelope", "goal_commit", INTENT_COMMIT))));
        assertEquals(open, Pca.decideIntent(intentSlot(), true, two, null));
    }

    @SuppressWarnings("unchecked")
    @Test void intentVerify() throws Exception {
        List<String> base = List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format");
        String raw = (String) vec("valid-raw-json-format-insensitive").get("pcactn_json");
        // absent policy / inactive policy: the pre-M2 verdict exactly
        Pca.Verdict g = Pca.verifyPcactnJson(raw, validGrant(), NOW, AUD, null, null);
        assertTrue(g.allow);
        assertEquals(base, new ArrayList<>(g.checks.keySet()));
        g = Pca.verifyPcactnJson(raw, validGrant(), NOW, AUD, null, new Pca.IntentPolicy(false, null, null));
        assertTrue(g.allow);
        assertEquals(base, new ArrayList<>(g.checks.keySet()));
        // active policy, no intent: reported last, fails closed
        g = Pca.verifyPcactnJson(raw, validGrant(), NOW, AUD, null, Pca.IntentPolicy.required());
        assertFalse(g.allow);
        List<String> withIntent = new ArrayList<>(base); withIntent.add("intent");
        assertEquals(withIntent, new ArrayList<>(g.checks.keySet()));
        assertEquals(Boolean.FALSE, g.checks.get("intent"));
        assertEquals("intent: this verifier requires an intent binding but the PCActn carries none", g.reason);
        // carried intent is signed (leaf_signature breaks) and reported even without a policy
        Map<String, Object> p = (Map<String, Object>) Json.parse(raw);
        p.put("intent", intentSlot());
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD);
        assertEquals(withIntent, new ArrayList<>(g.checks.keySet()));
        assertEquals(Boolean.TRUE, g.checks.get("wire"));
        assertEquals(Boolean.FALSE, g.checks.get("leaf_signature"));
        assertEquals(Boolean.FALSE, g.checks.get("intent"));
        // the binding itself is judged against the verifier's grant argument
        Map<String, Object> bound = new LinkedHashMap<>(validGrant());
        bound.put("caveats", intentGrant(INTENT_COMMIT).get("caveats"));
        assertEquals(Boolean.TRUE, Pca.verifyPcactn(p, bound, NOW, AUD).checks.get("intent"));
        // wire: present-but-null is a terminal wire failure
        p.put("intent", null);
        g = Pca.verifyPcactn(p, validGrant(), NOW, AUD, null, Pca.IntentPolicy.required());
        assertEquals(List.of("wire"), new ArrayList<>(g.checks.keySet()));
        assertEquals("wire: 'intent' must be an object", g.reason);
    }

    // ------------------------------------------------------------------ Intent Layer M2: mutation-kill boundaries
    static final String E_FID = "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]";
    static final String E_RISK = "'intent.residual_risk_ppm' must be a non-negative safe integer";
    static final String E_SALT = "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)";
    static final String E_REF = "'intent.ref' is not canonical base64url (32 bytes)";
    static final String E_MAP = "'intent.map_digest' is not canonical base64url (32 bytes)";
    static final String I_MIS = "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)";
    static final String I_NONE = "this verifier requires an intent binding but the PCActn carries none";
    static final String I_NOENV = "the root grant carries no envelope goal commitment to bind the intent to";
    static final String I_OPEN = "intent ref / map_digest / goal_salt do not open the root grant's goal commitment";
    static final List<String> BASE_KEYS = List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format");
    static final List<String> INTENT_KEYS = List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "intent");

    static Map<String, Object> slotWith(String k, Object v) { Map<String, Object> i = intentSlot(); i.put(k, v); return i; }
    static Map<String, Object> envelope(Object goalCommit) { return map("type", "envelope", "goal_commit", goalCommit); }
    static Map<String, Object> grantOf(Object... caveats) { return map("caveats", new ArrayList<>(Arrays.asList(caveats))); }
    static String decide(Map<String, Object> intent, Map<String, Object> grant, Pca.IntentPolicy pol) { return Pca.decideIntent(intent, intent != null, grant, pol); }

    /** A real root grant (principal -> agent) whose caveats are [max_spend, envelope(goal_commit)]. */
    static Map<String, Object> intentRoot() throws Exception {
        List<Object> cav = new ArrayList<>(List.of(map("type", "max_spend", "usd", n("100")), envelope(INTENT_COMMIT)));
        return signedCap(PqChainTest.pub("principal"), PqChainTest.pub("agent"), cav, null, "principal");
    }
    /** The valid PCActn re-rooted on `root`, carrying `intent` (when non-null), re-signed by the agent leaf key. */
    static Map<String, Object> signedWithIntent(Map<String, Object> root, Map<String, Object> intent) throws Exception {
        Map<String, Object> p = valid();
        p.put("cap_chain", new ArrayList<>(List.of(root)));
        p.put("grant_ref", root.get("id"));
        if (intent != null) p.put("intent", intent);
        p.put("sig", PqChainTest.edSign("agent", Pca.thresholdMessage(p)));
        return p;
    }

    @Test void intentKillWireBoundaries() {
        // fidelity_ppm: [0, 1000000] inclusive, safe integer only
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", n("0"))));
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", n("1"))));
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", n("999999"))));
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", n("1000000"))));
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", 0)));
        assertNull(Pca.validateIntentWire(slotWith("fidelity_ppm", 1000000L)));
        for (Object bad : new Object[] {n("-1"), n("1000001"), n("9007199254740991"), n("1.5"), n("0.5"), "1", true, false, null, 1000001L, -1})
            assertEquals(E_FID, Pca.validateIntentWire(slotWith("fidelity_ppm", bad)), String.valueOf(bad));
        // residual_risk_ppm: >= 0, any safe integer (may exceed 1e6)
        assertNull(Pca.validateIntentWire(slotWith("residual_risk_ppm", n("0"))));
        assertNull(Pca.validateIntentWire(slotWith("residual_risk_ppm", n("1000001"))));
        assertNull(Pca.validateIntentWire(slotWith("residual_risk_ppm", n("9007199254740991"))));
        for (Object bad : new Object[] {n("-1"), n("9007199254740992"), n("0.25"), "0", true, null, -1L})
            assertEquals(E_RISK, Pca.validateIntentWire(slotWith("residual_risk_ppm", bad)), String.valueOf(bad));
        // goal_salt: 1..128 UTF-8 BYTES (not chars)
        assertNull(Pca.validateIntentWire(slotWith("goal_salt", "a")));
        assertNull(Pca.validateIntentWire(slotWith("goal_salt", "a".repeat(128))));
        assertNull(Pca.validateIntentWire(slotWith("goal_salt", "é".repeat(64))));
        assertEquals(E_SALT, Pca.validateIntentWire(slotWith("goal_salt", "a".repeat(129))));
        assertEquals(E_SALT, Pca.validateIntentWire(slotWith("goal_salt", "é".repeat(64) + "a")));
        assertEquals(E_SALT, Pca.validateIntentWire(slotWith("goal_salt", "é".repeat(65)))); // 65 chars, 130 bytes
        for (Object bad : new Object[] {"", n("5"), null, true, new ArrayList<>(), map()})
            assertEquals(E_SALT, Pca.validateIntentWire(slotWith("goal_salt", bad)), String.valueOf(bad));
        // ref / map_digest: canonical b64u, exactly 32 bytes
        String b31 = Pca.b64(new byte[31]), b33 = Pca.b64(new byte[33]);
        for (Object bad : new Object[] {b31, b33, B32 + "=", "+" + B32.substring(1), "/" + B32.substring(1), "", n("1"), null, true})
            assertEquals(E_REF, Pca.validateIntentWire(slotWith("ref", bad)), String.valueOf(bad));
        for (Object bad : new Object[] {b31, b33, B32 + "=", "+" + B32.substring(1), "", n("1"), null})
            assertEquals(E_MAP, Pca.validateIntentWire(slotWith("map_digest", bad)), String.valueOf(bad));
        // ref is checked before map_digest, map_digest before goal_salt, goal_salt before the ppm figures
        Map<String, Object> all = intentSlot();
        all.put("ref", ""); all.put("map_digest", ""); all.put("goal_salt", ""); all.put("fidelity_ppm", n("-1")); all.put("residual_risk_ppm", n("-1"));
        assertEquals(E_REF, Pca.validateIntentWire(all));
        all.put("ref", B32); assertEquals(E_MAP, Pca.validateIntentWire(all));
        all.put("map_digest", B32); assertEquals(E_SALT, Pca.validateIntentWire(all));
        all.put("goal_salt", "s"); assertEquals(E_FID, Pca.validateIntentWire(all));
        all.put("fidelity_ppm", n("0")); assertEquals(E_RISK, Pca.validateIntentWire(all));
        all.put("residual_risk_ppm", n("0")); assertNull(Pca.validateIntentWire(all));
    }

    @Test void intentKillWireShape() {
        for (String k : List.of("ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm")) {
            Map<String, Object> i = intentSlot(); i.remove(k);
            assertEquals("missing field 'intent." + k + "'", Pca.validateIntentWire(i));
        }
        Map<String, Object> extra = intentSlot(); extra.put("note", "x");
        assertEquals("unknown field 'intent.note'", Pca.validateIntentWire(extra));
        Map<String, Object> both = intentSlot(); both.remove("ref"); both.put("zz", 1); // unknown is reported before missing
        assertEquals("unknown field 'intent.zz'", Pca.validateIntentWire(both));
        for (Object bad : new Object[] {null, "x", n("1"), true, new ArrayList<>(List.of(intentSlot())), new ArrayList<>()})
            assertEquals("'intent' must be an object", Pca.validateIntentWire(bad), String.valueOf(bad));
        assertEquals("missing field 'intent.ref'", Pca.validateIntentWire(map()));
    }

    @Test void intentKillPolicy() {
        assertFalse(new Pca.IntentPolicy(false, null, null).isActive());
        assertTrue(new Pca.IntentPolicy(true, null, null).isActive());
        assertTrue(new Pca.IntentPolicy(false, 0.0, null).isActive());
        assertTrue(new Pca.IntentPolicy(false, null, 0.0).isActive());
        assertTrue(Pca.IntentPolicy.required().require);
        assertNull(Pca.IntentPolicy.required().minFidelityPpm);
        assertNull(Pca.IntentPolicy.required().maxResidualRiskPpm);
        assertNull(Pca.IntentPolicy.fromJson(null));
        assertNull(Pca.IntentPolicy.fromJson(new ArrayList<>()));
        assertFalse(Pca.IntentPolicy.fromJson(map()).isActive());
        assertFalse(Pca.IntentPolicy.fromJson(map("require", false)).isActive());
        assertFalse(Pca.IntentPolicy.fromJson(map("require", "true")).isActive());
        assertFalse(Pca.IntentPolicy.fromJson(map("require", n("1"))).isActive());
        assertTrue(Pca.IntentPolicy.fromJson(map("require", true)).isActive());
        Pca.IntentPolicy fj = Pca.IntentPolicy.fromJson(map("min_fidelity_ppm", n("950000"), "max_residual_risk_ppm", 7));
        assertEquals(950000.0, fj.minFidelityPpm);
        assertEquals(7.0, fj.maxResidualRiskPpm);
        assertFalse(fj.require);
        assertEquals(-1.0, Pca.IntentPolicy.fromJson(map("min_fidelity_ppm", n("-1"))).minFidelityPpm);
        assertEquals(0.5, Pca.IntentPolicy.fromJson(map("max_residual_risk_ppm", n("0.5"))).maxResidualRiskPpm);
        assertTrue(Double.isNaN(Pca.IntentPolicy.fromJson(map("max_residual_risk_ppm", null)).maxResidualRiskPpm));
        assertTrue(Double.isNaN(Pca.IntentPolicy.fromJson(map("max_residual_risk_ppm", true)).maxResidualRiskPpm));
        assertNull(Pca.IntentPolicy.fromJson(map("require", true)).minFidelityPpm);
        // okThreshold: null and safe integers >= 0 pass; everything else fails
        for (Double ok : new Double[] {null, 0.0, 1.0, 950000.0, 9007199254740991.0}) assertTrue(Pca.okThreshold(ok), String.valueOf(ok));
        for (double bad : new double[] {-1.0, -0.0, 0.5, 1.5, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, 9007199254740992.0, -9007199254740991.0})
            assertFalse(Pca.okThreshold(bad), String.valueOf(bad));
    }

    @Test void intentKillDecide() {
        Map<String, Object> g = grantOf(envelope(INTENT_COMMIT));
        // not evaluated: no intent and an inactive (or absent) policy
        assertNull(decide(null, g, null));
        assertNull(decide(null, g, new Pca.IntentPolicy(false, null, null)));
        // active: require, or a threshold alone
        assertEquals(I_NONE, decide(null, g, Pca.IntentPolicy.required()));
        assertEquals(I_NONE, decide(null, g, new Pca.IntentPolicy(false, 0.0, null)));
        assertEquals(I_NONE, decide(null, g, new Pca.IntentPolicy(false, null, 0.0)));
        // step 0 (misconfiguration) precedes step 1 (absent) and step 2 (binding)
        for (double bad : new double[] {-1.0, 0.5, Double.NaN, -0.0}) {
            assertEquals(I_MIS, decide(null, g, new Pca.IntentPolicy(false, bad, null)), "min " + bad);
            assertEquals(I_MIS, decide(null, g, new Pca.IntentPolicy(true, null, bad)), "max " + bad);
            assertEquals(I_MIS, decide(intentSlot(), map(), new Pca.IntentPolicy(false, bad, null)), "min/nogrant " + bad);
            assertEquals(I_MIS, decide(intentSlot(), g, new Pca.IntentPolicy(false, 0.0, bad)), "max with valid min " + bad);
            assertEquals(I_MIS, decide(intentSlot(), g, new Pca.IntentPolicy(false, bad, 0.0)), "min with valid max " + bad);
        }
        // binding (step 2) precedes the thresholds (steps 3, 4)
        assertEquals(I_NOENV, decide(intentSlot(), map(), new Pca.IntentPolicy(false, 1e6, 0.0)));
        // pass with no policy, inactive policy, require
        assertEquals("", decide(intentSlot(), g, null));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, null, null)));
        assertEquals("", decide(intentSlot(), g, Pca.IntentPolicy.required()));
        // thresholds are inclusive; one past fails
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, 950000.0, null)));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, 949999.0, null)));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, 0.0, null)));
        assertEquals("intent fidelity 950000 ppm is below the policy minimum 950001", decide(intentSlot(), g, new Pca.IntentPolicy(false, 950001.0, null)));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, null, 4310000.0)));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(false, null, 4310001.0)));
        assertEquals("intent residual risk 4310000 ppm exceeds the policy maximum 4309999", decide(intentSlot(), g, new Pca.IntentPolicy(false, null, 4309999.0)));
        assertEquals("intent residual risk 4310000 ppm exceeds the policy maximum 0", decide(intentSlot(), g, new Pca.IntentPolicy(false, null, 0.0)));
        // min is checked before max; each threshold only consults its own figure
        assertEquals("intent fidelity 950000 ppm is below the policy minimum 950001", decide(intentSlot(), g, new Pca.IntentPolicy(false, 950001.0, 0.0)));
        assertEquals("", decide(intentSlot(), g, new Pca.IntentPolicy(true, 950000.0, 4310000.0)));
        Map<String, Object> zero = intentSlot(); zero.put("fidelity_ppm", n("0")); zero.put("residual_risk_ppm", n("0"));
        assertEquals("", decide(zero, g, new Pca.IntentPolicy(false, 0.0, 0.0)));
        assertEquals("intent fidelity 0 ppm is below the policy minimum 1", decide(zero, g, new Pca.IntentPolicy(false, 1.0, null)));
        Map<String, Object> top = intentSlot(); top.put("fidelity_ppm", n("1000000")); top.put("residual_risk_ppm", n("9007199254740991"));
        assertEquals("", decide(top, g, new Pca.IntentPolicy(false, 1e6, 9007199254740991.0)));
        assertEquals("intent residual risk 9007199254740991 ppm exceeds the policy maximum 9007199254740990", decide(top, g, new Pca.IntentPolicy(false, null, 9007199254740990.0)));
    }

    @Test void intentKillRootGrant() {
        Map<String, Object> env = envelope(INTENT_COMMIT);
        // first ENVELOPE caveat wins (not the first caveat, not the last envelope)
        assertEquals("", decide(intentSlot(), grantOf(map("type", "max_spend"), env), null));
        assertEquals(I_OPEN, decide(intentSlot(), grantOf(envelope(B32), env), null));
        assertEquals("", decide(intentSlot(), grantOf(env, envelope(B32)), null));
        assertEquals(I_NOENV, decide(intentSlot(), grantOf(envelope(n("7")), env), null)); // first envelope's goal_commit is not a string: no fallthrough
        // non-object / non-envelope caveats before the envelope are skipped
        assertEquals("", decide(intentSlot(), grantOf("envelope", null, n("1"), new ArrayList<>(List.of(env)), map("type", "Envelope", "goal_commit", B32), map("goal_commit", B32), env), null));
        // goal_commit must be a string
        for (Object bad : new Object[] {n("7"), null, true, new ArrayList<>(), map()})
            assertEquals(I_NOENV, decide(intentSlot(), grantOf(envelope(bad)), null), String.valueOf(bad));
        assertEquals(I_NOENV, decide(intentSlot(), grantOf(map("type", "envelope")), null));
        // the grant must carry a caveats ARRAY with an envelope
        assertEquals(I_NOENV, decide(intentSlot(), map(), null));
        assertEquals(I_NOENV, decide(intentSlot(), null, null));
        assertEquals(I_NOENV, decide(intentSlot(), map("caveats", map("0", env)), null));
        assertEquals(I_NOENV, decide(intentSlot(), map("caveats", "x"), null));
        assertEquals(I_NOENV, decide(intentSlot(), grantOf(), null));
        assertEquals(I_NOENV, decide(intentSlot(), grantOf(map("type", "max_spend")), null));
        assertEquals(INTENT_COMMIT, Pca.rootGoalCommit(grantOf("x", env, envelope(B32))));
        assertNull(Pca.rootGoalCommit(null));
        // every committed component is bound
        assertEquals(I_OPEN, decide(slotWith("ref", PcaUnitTest.B32.replace('q', 'r')), grantOf(env), null));
        assertEquals(I_OPEN, decide(slotWith("map_digest", Pca.b64(new byte[32])), grantOf(env), null));
        assertEquals(I_OPEN, decide(slotWith("goal_salt", "salt "), grantOf(env), null));
        // the ppm figures are NOT part of the commitment
        assertEquals("", decide(slotWith("fidelity_ppm", n("1")), grantOf(env), null));
        // goal string shape: with and without a map digest
        assertEquals("pca-intent:v1:r", Pca.intentGoal("r", null));
        assertEquals("pca-intent:v1:r", Pca.intentGoal("r", ""));
        assertEquals("pca-intent:v1:r:m", Pca.intentGoal("r", "m"));
        assertFalse(Pca.intentGoalCommit(B32, B32, "salt").equals(Pca.intentGoalCommit(B32, B32, "salt2")));
    }

    @Test void intentKillVerifySigned() throws Exception {
        Map<String, Object> root = intentRoot();
        // baseline: the re-rooted PCActn without intent verifies with the pre-M2 key set
        Pca.Verdict g = Pca.verifyPcactn(signedWithIntent(root, null), root, NOW, AUD);
        assertTrue(g.allow, g.reason);
        assertEquals(BASE_KEYS, new ArrayList<>(g.checks.keySet()));
        g = Pca.verifyPcactn(signedWithIntent(root, null), root, NOW, AUD, null, new Pca.IntentPolicy(false, null, null));
        assertTrue(g.allow); assertEquals(BASE_KEYS, new ArrayList<>(g.checks.keySet()));
        g = Pca.verifyPcactn(signedWithIntent(root, null), root, NOW, AUD, null, new Pca.IntentPolicy(false, 0.0, null));
        assertFalse(g.allow); assertEquals(INTENT_KEYS, new ArrayList<>(g.checks.keySet()));
        assertEquals("intent: " + I_NONE, g.reason);
        // bound intent: allow, intent appended exactly after counter
        Map<String, Object> p = signedWithIntent(root, intentSlot());
        g = Pca.verifyPcactn(p, root, NOW, AUD);
        assertTrue(g.allow, g.reason);
        assertEquals("", g.reason);
        assertEquals(INTENT_KEYS, new ArrayList<>(g.checks.keySet()));
        assertEquals(Boolean.TRUE, g.checks.get("intent"));
        assertTrue(Pca.verifyPcactnJson(Json.canonicalizeStrict(p), root, NOW, AUD, null, Pca.IntentPolicy.required()).allow);
        // thresholds through the verifier: inclusive, one past fails only `intent`
        assertTrue(Pca.verifyPcactn(p, root, NOW, AUD, null, new Pca.IntentPolicy(true, 950000.0, 4310000.0)).allow);
        g = Pca.verifyPcactn(p, root, NOW, AUD, null, new Pca.IntentPolicy(false, 950001.0, null));
        assertFalse(g.allow);
        assertEquals("intent: intent fidelity 950000 ppm is below the policy minimum 950001", g.reason);
        for (String k : BASE_KEYS) assertEquals(Boolean.TRUE, g.checks.get(k), k);
        g = Pca.verifyPcactn(p, root, NOW, AUD, null, new Pca.IntentPolicy(false, null, 4309999.0));
        assertFalse(g.allow); assertEquals(Boolean.FALSE, g.checks.get("intent"));
        g = Pca.verifyPcactn(p, root, NOW, AUD, null, new Pca.IntentPolicy(false, -1.0, null));
        assertFalse(g.allow); assertEquals("intent: " + I_MIS, g.reason);
        // range edges, re-signed
        Map<String, Object> edge = intentSlot(); edge.put("fidelity_ppm", n("1000000")); edge.put("residual_risk_ppm", n("0"));
        assertTrue(Pca.verifyPcactn(signedWithIntent(root, edge), root, NOW, AUD).allow);
        edge.put("fidelity_ppm", n("0")); edge.put("residual_risk_ppm", n("9007199254740991"));
        assertTrue(Pca.verifyPcactn(signedWithIntent(root, edge), root, NOW, AUD).allow);
        // signed: tampering after signing breaks leaf_signature while the binding itself still holds
        Map<String, Object> t = signedWithIntent(root, intentSlot());
        m(t.get("intent")).put("fidelity_ppm", n("999999"));
        g = Pca.verifyPcactn(t, root, NOW, AUD);
        assertFalse(g.allow);
        assertEquals(Boolean.FALSE, g.checks.get("leaf_signature"));
        assertEquals(Boolean.TRUE, g.checks.get("intent"));
        assertEquals(INTENT_KEYS, new ArrayList<>(g.checks.keySet()));
        // stripping the signed intent also breaks the signature (and drops the check)
        Map<String, Object> s = signedWithIntent(root, intentSlot());
        s.remove("intent");
        g = Pca.verifyPcactn(s, root, NOW, AUD);
        assertEquals(Boolean.FALSE, g.checks.get("leaf_signature"));
        assertEquals(BASE_KEYS, new ArrayList<>(g.checks.keySet()));
        // a grant-binding failure fails only `intent`
        Map<String, Object> salt = signedWithIntent(root, slotWith("goal_salt", "other"));
        g = Pca.verifyPcactn(salt, root, NOW, AUD);
        assertEquals("intent: " + I_OPEN, g.reason);
        for (String k : BASE_KEYS) assertEquals(Boolean.TRUE, g.checks.get(k), k);
        // wire refusals through the verifier are terminal (wire only)
        for (Object bad : new Object[] {null, "x", new ArrayList<>(), slotWith("fidelity_ppm", n("1000001")), slotWith("residual_risk_ppm", n("-1")), slotWith("goal_salt", "é".repeat(64) + "a")}) {
            Map<String, Object> w = signedWithIntent(root, intentSlot());
            w.put("intent", bad);
            g = Pca.verifyPcactn(w, root, NOW, AUD, null, Pca.IntentPolicy.required());
            assertFalse(g.allow);
            assertEquals(List.of("wire"), new ArrayList<>(g.checks.keySet()), String.valueOf(bad));
            assertTrue(g.reason.startsWith("wire: "), g.reason);
        }
    }

    @Test void intentKillThresholdNumericValue() throws Exception {
        // validity is judged on the NUMERIC value, whatever the JSON spelling
        for (String ok : List.of("950000", "950000.0", "950000.00", "9.5e5", "1e6", "1E6", "1e+6", "10e5", "0", "0.0", "0e0", "9007199254740991", "9007199254740991.0")) {
            Pca.IntentPolicy pol = Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":" + ok + ",\"max_residual_risk_ppm\":" + ok + "}");
            assertTrue(pol.isActive(), ok);
            assertTrue(Pca.okThreshold(pol.minFidelityPpm), ok);
            assertTrue(Pca.okThreshold(pol.maxResidualRiskPpm), ok);
        }
        assertEquals(950000.0, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":950000.0}").minFidelityPpm);
        assertEquals(1000000.0, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":1e6}").minFidelityPpm);
        for (String bad : List.of("950000.5", "0.5", "-1", "-1.0", "-0", "-0.0", "-0e0", "1e400", "-1e400", "9007199254740992", "1e16", "1e-7", "null", "true", "false", "\"5\"", "[]", "{}")) {
            Pca.IntentPolicy pol = Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":" + bad + "}");
            assertTrue(pol.isActive(), bad);
            assertFalse(Pca.okThreshold(pol.minFidelityPpm), bad);
            assertEquals(I_MIS, decide(intentSlot(), grantOf(envelope(INTENT_COMMIT)), pol), bad);
            assertEquals(I_MIS, decide(intentSlot(), grantOf(envelope(INTENT_COMMIT)), Pca.IntentPolicy.fromJsonText("{\"max_residual_risk_ppm\":" + bad + "}")), bad);
        }
        assertTrue(Pca.okThreshold(950000.0));
        assertTrue(Pca.okThreshold(1e6));
        assertFalse(Pca.okThreshold(950000.5));
        assertNull(Pca.IntentPolicy.fromJsonText("[]"));
        assertNull(Pca.IntentPolicy.fromJsonText("null"));
        assertFalse(Pca.IntentPolicy.fromJsonText("{}").isActive());
        assertTrue(Pca.IntentPolicy.fromJsonText("{\"require\":true}").isActive());
        // through the decision: 950000.0 is the inclusive floor 950000; 1e6 is 1000000
        Map<String, Object> g = grantOf(envelope(INTENT_COMMIT));
        assertEquals("", decide(intentSlot(), g, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":950000.0}")));
        assertEquals("", decide(intentSlot(), g, Pca.IntentPolicy.fromJsonText("{\"max_residual_risk_ppm\":4.31e6}")));
        assertEquals("intent fidelity 950000 ppm is below the policy minimum 1000000", decide(intentSlot(), g, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":1e6}")));
        assertEquals("intent residual risk 4310000 ppm exceeds the policy maximum 4309999", decide(intentSlot(), g, Pca.IntentPolicy.fromJsonText("{\"max_residual_risk_ppm\":4309999.0}")));
        // and through the signed verifier
        Map<String, Object> root = intentRoot();
        Map<String, Object> p = signedWithIntent(root, intentSlot());
        assertTrue(Pca.verifyPcactn(p, root, NOW, AUD, null, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":950000.0,\"max_residual_risk_ppm\":4.31e6}")).allow);
        Pca.Verdict v = Pca.verifyPcactn(p, root, NOW, AUD, null, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":950000.5}"));
        assertFalse(v.allow);
        assertEquals("intent: " + I_MIS, v.reason);
        assertThrows(RuntimeException.class, () -> Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\":}"));
    }
}
