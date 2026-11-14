package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Replays the producer vectors: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519, ML-DSA and SLH-DSA sign deterministically). */
public class ProducerVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("producer-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    static final Map<String, Object> PQ_DOC = Track3Vectors.load("producer-pq-vectors.json");
    static final ProducerOps OPS = new ProducerOps(m(DOC.get("keys")), null);
    static final ProducerOps PQ_OPS = new ProducerOps(m(PQ_DOC.get("ed_keys")), m(PQ_DOC.get("pq_keys")));

    static Keys.EdKey key(String name) { return Keys.edFromSeed(Pca.decodeB64uStrict(m(m(DOC.get("keys")).get(name)).get("seed"), 32)); }
    static String canon(Object o) { return Json.canonicalize(o); }

    static Map<String, Object> args(String name) {
        for (Object c : l(DOC.get("cases"))) if (name.equals(m(c).get("name"))) return m(m(c).get("args"));
        throw new AssertionError("no vector named " + name);
    }

    /** Every case: the output byte for byte, or (for a refusal case) the reference's exact refusal text. */
    static void replay(ProducerOps ops, Map<String, Object> doc, int atLeast) {
        List<Object> cases = l(doc.get("cases"));
        assertTrue(cases.size() >= atLeast, "the corpus shrank: " + cases.size());
        for (Object c : cases) {
            Map<String, Object> v = m(c);
            String name = v.get("name").toString(), op = (String) v.get("op");
            Map<String, Object> want = m(v.get("expect"));
            if (v.get("exact") != null && !l(v.get("exact")).contains("java")) {
                // a suite this SDK cannot sign (FN-DSA): refused with unsupported_suite, never signed some other way
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ops.run(op, m(v.get("args"))), name);
                assertTrue(e.getMessage().startsWith("unsupported_suite: "), name + ": " + e.getMessage());
                continue;
            }
            if (want.size() == 1 && want.get("error") != null) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ops.run(op, m(v.get("args"))), name);
                String w = (String) want.get("error");
                // the canonical profile's wording is per-language: a reference canonicalize refusal needs a canonicalize refusal
                if (w.startsWith("canonicalize: ")) assertTrue(e.getMessage().startsWith("canonicalize: "), name + ": " + e.getMessage());
                else assertEquals(w, e.getMessage(), name);
            } else {
                Object got = ops.run(op, m(v.get("args")));
                assertEquals(canon(want), canon(got), name);
            }
        }
    }

    @Test void everyCaseIsReproducedByteForByte() { replay(OPS, DOC, 89); }

    @Test void everyPqSuiteCaseIsReproducedByteForByte() { replay(PQ_OPS, PQ_DOC, 40); }

    @Test void unknownOpsAndSuitesAreRefusedByName() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OPS.run("sign_nothing", obj()));
        assertEquals("unsupported_op: sign_nothing", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> PQ_OPS.run("pq_keygen", obj("family", "fn-dsa-512", "seed", "AA")));
        assertEquals("unsupported_suite: fn-dsa-512", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> PQ_OPS.run("sign_artifact_suite", obj("kind", "nope", "alg", "ed25519", "signer", "agent")));
        assertEquals("unsupported_op: sign_artifact_suite/nope", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> OPS.run("sign_caution", obj("signer", "nobody", "body", obj())));
        assertEquals("unknown key 'nobody'", e.getMessage());
    }

    static Map<String, Object> expect(String name) {
        for (Object c : l(DOC.get("cases"))) if (name.equals(m(c).get("name"))) return m(m(c).get("expect"));
        throw new AssertionError("no vector named " + name);
    }

    @Test void offerSetsSignExactlyAndRefuseOutOfProfileBodies() {
        Keys.SuiteKey site = Keys.ed25519(key("site"));
        for (String n : List.of("offer-set-complete", "offer-set-partial-page"))
            assertEquals(canon(expect(n)), canon(SignersMore.signOfferSet(m(args(n).get("body")), site)), n);
        for (String n : List.of("offer-set-refuses-unsafe-price", "offer-set-refuses-unsafe-issued-at")) {
            assertEquals("canonicalize: integer outside the safe range (|n| > 2^53-1)", expect(n).get("error"));
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SignersMore.signOfferSet(m(args(n).get("body")), site), n);
            assertEquals("canonicalize: integer outside the safe range", e.getMessage(), n);
        }
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SignersMore.signOfferSet(null, site));
        assertEquals("signOfferSet: not an object", e.getMessage());
        Map<String, Object> body = args("offer-set-complete");
        SignersMore.signOfferSet(m(body.get("body")), site);
        assertTrue(!m(body.get("body")).containsKey("sig"), "the caller's body is not mutated");
    }

    /** Cross-verification: the TS-produced PCActns pass THIS SDK's verifier. */
    @Test void referenceActionsVerify() {
        int n = 0;
        for (Object c : l(DOC.get("cases"))) {
            Map<String, Object> v = m(c);
            if (!"act".equals(v.get("op")) || m(v.get("args")).containsKey("fresh_at")) continue; // fresh_at is refused without a fresh_at policy (fail closed)
            Map<String, Object> a = m(v.get("args"));
            Map<String, Object> pcactn = m(m(v.get("expect")).get("pcactn"));
            Pca.Verdict d = Pca.verifyPcactn(pcactn, m(a.get("grant")), Json.asLong(a.get("iat")) + 1000, (String) a.get("aud"), null, null, null, null, Pca.PlanRoots.SKIP);
            assertTrue(d.allow, v.get("name") + ": " + d.reason);
            n++;
        }
        assertTrue(n >= 4);
    }

    @Test void seededMlDsaKeysAreReproducibleAndKeepTheirSeed() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) i;
        Keys.PqKey a = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed), b = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed);
        assertEquals(a.pkB64u(), b.pkB64u());
        seed[0] ^= 1;
        assertTrue(!a.pkB64u().equals(Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed).pkB64u()));
    }

    /** FIPS 204 KeyGen_internal step 1: (rho, rho', K) = SHAKE256(xi || k || l, 128 bytes), and pk starts with rho. Proves BouncyCastle used the seed as xi. */
    @Test void seededMlDsaKeysFollowFips204KeyGenInternal() {
        Object[][] levels = {{Pq.Prim.ML_DSA_65, 6, 5}, {Pq.Prim.ML_DSA_87, 8, 7}};
        for (Object[] lv : levels) {
            byte[] xi = new byte[32];
            for (int i = 0; i < 32; i++) xi[i] = (byte) (i * 7 + 1);
            org.bouncycastle.crypto.digests.SHAKEDigest d = new org.bouncycastle.crypto.digests.SHAKEDigest(256);
            d.update(xi, 0, 32);
            d.update((byte) (int) lv[1]);
            d.update((byte) (int) lv[2]);
            byte[] out = new byte[128];
            d.doFinal(out, 0, 128);
            Keys.PqKey k = Keys.pqFromSeed((Pq.Prim) lv[0], xi);
            assertArrayEquals(java.util.Arrays.copyOfRange(out, 0, 32), java.util.Arrays.copyOfRange(k.pk, 0, 32), lv[0] + ": rho");
        }
    }
}
