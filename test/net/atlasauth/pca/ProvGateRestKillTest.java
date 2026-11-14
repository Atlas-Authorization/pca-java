package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link ProvenanceGate}: subject digests, the root level, runtime binding, refusals and RFC 9162 bounds. */
public class ProvGateRestKillTest {
    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    /** A fresh deep copy of the oracle's passing gate input. */
    static Map<String, Object> pass() throws Exception {
        for (Map<String, Object> c : K05Oracle.of("k05-provgate", "provenanceGate"))
            if ("provenanceGate/pass".equals(c.get("name"))) return M(IntentJs.normalize(((List<?>) c.get("args")).get(0)));
        throw new AssertionError("provenanceGate/pass missing");
    }

    static Map<String, Object> facts(Map<String, Object> in) { return M(in.get("facts")); }

    static final String D1 = "c78a0f89bffe8bc82ec3b404bb5486192da52162be88c58ce62a6f0c15ca3b0c";

    @Test void subjectDigestCharacters() throws Exception {
        assertNull(ProvenanceGate.provenanceFactsError(facts(pass())));
        String bad = "facts.subjects must be 1..64 {alg, digest}";
        for (char c : new char[] {'/', ':', '`', 'g', 'A', 'F', ' '}) {
            Map<String, Object> f = facts(pass());
            f.put("subjects", list(m("alg", "sha256", "digest", D1.substring(0, 63) + c)));
            assertEquals(bad, ProvenanceGate.provenanceFactsError(f), "char " + c);
        }
        for (char c : new char[] {'0', '9', 'a', 'f'}) {
            Map<String, Object> f = facts(pass());
            f.put("subjects", list(m("alg", "sha256", "digest", D1.substring(0, 63) + c)));
            assertNull(ProvenanceGate.provenanceFactsError(f), "char " + c);
        }
        Object[][] subjects = {
            {"sha512", "a".repeat(128), null}, {"sha512", "a".repeat(64), bad}, {"sha256", "a".repeat(128), bad},
            {"md5", "", bad}, {"md5", "a".repeat(64), bad}, {"md5", "a".repeat(128), bad}, {5, "a".repeat(64), bad},
        };
        for (Object[] s : subjects) {
            Map<String, Object> f = facts(pass());
            f.put("subjects", list(m("alg", s[0], "digest", s[1])));
            assertEquals(s[2], ProvenanceGate.provenanceFactsError(f), s[0] + "/" + String.valueOf(s[1]).length());
        }
    }

    @Test void refusalLevelIsZero() throws Exception {
        Map<String, Object> in = pass();
        in.put("now", -1);
        ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(in);
        assertFalse(r.ok);
        assertEquals(0L, r.level);
        assertNull(r.claims);
        assertEquals("malformed_facts", r.code);
    }

    @Test void nonObjectAndThrowingInput() {
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate("x").code);
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate(null).code);
        Map<String, Object> hostile = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("x"); }
        };
        ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(hostile);
        assertNotNull(r);
        assertFalse(r.ok);
        assertEquals("malformed_facts", r.code);
    }

    static Map<String, Object> root(int level) {
        return m("oidc_issuer", "https://token.actions.githubusercontent.com", "identity_prefix", "https://github.com/acme/",
            "builder_id", "https://github.com/actions/runner/github-hosted", "level", level);
    }

    @Test void theHighestMatchingRootWins() throws Exception {
        for (int[] levels : new int[][] {{1, 3, 2}, {3, 1}, {2, 3}, {2, 2}}) {
            Map<String, Object> in = pass();
            List<Object> roots = new ArrayList<>();
            int max = 0;
            for (int l : levels) { roots.add(root(l)); max = Math.max(max, l); }
            M(in.get("policy")).put("roots", roots);
            ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(in);
            assertTrue(r.ok, Arrays.toString(levels));
            assertEquals(max, r.level);
            assertEquals(Long.valueOf(max), r.claims.get("slsa_level"));
        }
    }

    @Test void runtimePicksTheMatchingSubject() throws Exception {
        String d2 = "b".repeat(64), d3 = "c".repeat(128);
        Map<String, Object> in = pass();
        facts(in).put("subjects", list(m("alg", "sha256", "digest", D1), m("alg", "sha256", "digest", d2), m("alg", "sha512", "digest", d3)));
        in.put("runtime", m("alg", "sha256", "digest", d2));
        ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(in);
        assertTrue(r.ok);
        assertEquals("sha256", r.claims.get("subject_alg"));
        assertEquals(d2, r.claims.get("subject_digest"));
        assertEquals(true, r.claims.get("runtime_bound"));
        in.put("runtime", m("alg", "sha512", "digest", d3));
        r = ProvenanceGate.provenanceGate(in);
        assertEquals("sha512", r.claims.get("subject_alg"));
        assertEquals(d3, r.claims.get("subject_digest"));
        in.put("runtime", m("alg", "sha256", "digest", "d".repeat(64)));
        assertEquals("runtime_mismatch", ProvenanceGate.provenanceGate(in).code);
    }

    // ---- RFC 9162 -------------------------------------------------------------------------------------------------------------

    static byte[] node(byte[] l, byte[] r) { return Pca.sha(new byte[] {1}, l, r); }
    static byte[] h(int b) { byte[] x = new byte[32]; Arrays.fill(x, (byte) b); return x; }

    /** Index 0 of a tree of {@code size} leaves: every step hashes the running value on the left. */
    static Object[] leftmost(long size) {
        byte[] leaf = ProvenanceGate.rfc9162LeafHash(new byte[] {7});
        List<byte[]> proof = new ArrayList<>();
        byte[] r = leaf;
        for (long sn = size - 1; sn != 0; sn >>= 1) {
            byte[] p = h(proof.size() + 1);
            proof.add(p);
            r = node(r, p);
        }
        return new Object[] {leaf, proof, r};
    }

    @SuppressWarnings("unchecked")
    @Test void sizeBoundAtTheSafeInteger() {
        long max = 9_007_199_254_740_991L;
        Object[] ok = leftmost(max);
        assertEquals(53, ((List<byte[]>) ok[1]).size());
        assertTrue(ProvenanceGate.verifyRfc9162Inclusion((byte[]) ok[0], 0, max, (List<byte[]>) ok[1], (byte[]) ok[2]));
        Object[] over = leftmost(max + 1);
        assertEquals(53, ((List<byte[]>) over[1]).size());
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion((byte[]) over[0], 0, max + 1, (List<byte[]>) over[1], (byte[]) over[2]));
        // the same walk one step short or long fails
        List<byte[]> longer = new ArrayList<>((List<byte[]>) ok[1]);
        longer.add(h(99));
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion((byte[]) ok[0], 0, max, longer, node((byte[]) ok[2], h(99))));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test void malformedProofs() {
        Object[] t = leftmost(4);
        byte[] leaf = (byte[]) t[0], root = (byte[]) t[2];
        List<byte[]> proof = (List<byte[]>) t[1];
        assertTrue(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 4, proof, root));
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 4, null, root));
        List<byte[]> withNull = new ArrayList<>(proof);
        withNull.set(1, null);
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 4, withNull, root));
        List<byte[]> shortEl = new ArrayList<>(proof);
        shortEl.set(1, new byte[31]);
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 4, shortEl, root));
        List raw = new ArrayList();
        raw.add("not bytes");
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 2, (List<byte[]>) raw, root));
        List<byte[]> many = new ArrayList<>();
        for (int i = 0; i < 65; i++) many.add(h(i));
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 4, many, root));
    }
}
