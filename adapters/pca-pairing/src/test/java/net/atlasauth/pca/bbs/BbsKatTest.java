package net.atlasauth.pca.bbs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.pairing.Bls12;
import org.junit.jupiter.api.Test;

/**
 * The official fixtures of draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256; byte-identical across draft revisions
 * -06 through -12), vendored in test-data with provenance, plus the RFC 9380 expand_message_xmd vector.
 */
class BbsKatTest {
    private static final Path SUITE = Path.of("test-data/draft-irtf-cfrg-bbs-signatures/bls12-381-sha-256");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> load(String rel) throws IOException {
        return (Map<String, Object>) Json.parse(Files.readString(SUITE.resolve(rel), StandardCharsets.UTF_8));
    }

    private static byte[] h(Object s) { return HexFormat.of().parseHex((String) s); }

    private static String hx(byte[] b) { return HexFormat.of().formatHex(b); }

    private static List<byte[]> hs(Object list) {
        List<byte[]> out = new ArrayList<>();
        for (Object o : (List<?>) list) out.add(h(o));
        return out;
    }

    private static List<Integer> ints(Object list) {
        List<Integer> out = new ArrayList<>();
        for (Object o : (List<?>) list) out.add(Integer.parseInt(o.toString()));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void expandMessageXmdRfc9380() {
        byte[] out = Bls12.expandMessageXmd(new byte[0], "QUUX-V01-CS02-with-expander-SHA256-128".getBytes(StandardCharsets.US_ASCII), 0x20);
        assertEquals("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235", hx(out));
    }

    @Test void keyGenAndSkToPk() throws Exception {
        Map<String, Object> k = load("keypair.json");
        BigInteger sk = Bbs.keyGen(h(k.get("keyMaterial")), h(k.get("keyInfo")));
        assertEquals(m(k.get("keyPair")).get("secretKey"), hx(Bbs.skToBytes(sk)));
        assertEquals(m(k.get("keyPair")).get("publicKey"), hx(Bbs.skToPk(sk)));
    }

    @Test void hashToScalar() throws Exception {
        Map<String, Object> f = load("h2s.json");
        assertEquals(f.get("scalar"), hx(Bls12.i2osp(Bbs.hashToScalar(h(f.get("message")), new String(h(f.get("dst")), StandardCharsets.US_ASCII)), 32)));
    }

    @Test void mapMessageToScalar() throws Exception {
        Map<String, Object> f = load("MapMessageToScalarAsHash.json");
        for (Object c : (List<?>) f.get("cases")) {
            assertEquals(m(c).get("scalar"), hx(Bls12.i2osp(Bbs.mapMessageToScalarAsHash(h(m(c).get("message"))), 32)));
        }
    }

    @Test void createGenerators() throws Exception {
        Map<String, Object> f = load("generators.json");
        List<?> msg = (List<?>) f.get("MsgGenerators");
        List<byte[]> gens = Bbs.createGenerators(msg.size() + 1);
        assertEquals(f.get("Q1"), hx(gens.get(0)));
        for (int i = 0; i < msg.size(); i++) assertEquals(msg.get(i), hx(gens.get(i + 1)));
    }

    @Test void signAndVerify() throws Exception {
        for (int i = 1; i <= 10; i++) {
            Map<String, Object> f = load(String.format("signature/signature%03d.json", i));
            List<byte[]> msgs = hs(f.get("messages"));
            byte[] pk = h(m(f.get("signerKeyPair")).get("publicKey"));
            Bbs.Result r = Bbs.verifyDetailed(pk, h(f.get("signature")), h(f.get("header")), msgs);
            String name = (String) f.get("caseName");
            if (Boolean.TRUE.equals(m(f.get("result")).get("valid"))) {
                assertTrue(r.ok(), name);
                BigInteger sk = new BigInteger((String) m(f.get("signerKeyPair")).get("secretKey"), 16);
                assertArrayEquals(h(f.get("signature")), Bbs.sign(sk, pk, h(f.get("header")), msgs), name);
            } else {
                assertFalse(r.ok(), name);
                assertEquals(Bbs.PAIRING_MISMATCH, r.reason(), name);
            }
        }
    }

    @Test void proofGenAndVerify() throws Exception {
        for (int i = 1; i <= 15; i++) {
            Map<String, Object> f = load(String.format("proof/proof%03d.json", i));
            String name = (String) f.get("caseName");
            List<byte[]> msgs = hs(f.get("messages"));
            List<Integer> idx = ints(f.get("disclosedIndexes"));
            List<byte[]> disclosed = new ArrayList<>();
            for (int k : idx) disclosed.add(k >= 0 && k < msgs.size() ? msgs.get(k) : new byte[0]);
            byte[] pk = h(f.get("signerPublicKey"));
            Bbs.Result r = Bbs.proofVerifyDetailed(pk, h(f.get("proof")), h(f.get("header")), h(f.get("presentationHeader")), disclosed, idx);
            if (Boolean.TRUE.equals(m(f.get("result")).get("valid"))) {
                assertTrue(r.ok(), name);
                Map<String, Object> rs = m(m(f.get("trace")).get("random_scalars"));
                List<BigInteger> scalars = new ArrayList<>();
                for (String key : new String[] {"r1", "r2", "e_tilde", "r1_tilde", "r3_tilde"}) scalars.add(new BigInteger((String) rs.get(key), 16));
                for (Object x : (List<?>) rs.get("m_tilde_scalars")) scalars.add(new BigInteger((String) x, 16));
                byte[] regen = Bbs.proofGen(pk, h(f.get("signature")), h(f.get("header")), h(f.get("presentationHeader")), msgs, idx, scalars);
                assertEquals(f.get("proof"), hx(regen), name);
            } else {
                assertFalse(r.ok(), name);
            }
        }
    }

    @Test void randomizedProofVerifiesAndTamperingFails() throws Exception {
        Map<String, Object> f = load("signature/signature004.json");
        List<byte[]> msgs = hs(f.get("messages"));
        byte[] pk = h(m(f.get("signerKeyPair")).get("publicKey"));
        byte[] hdr = h(f.get("header"));
        byte[] ph = new byte[] {1, 2, 3};
        List<Integer> idx = List.of(0, 2);
        byte[] proof = Bbs.proofGen(pk, h(f.get("signature")), hdr, ph, msgs, idx);
        List<byte[]> dis = List.of(msgs.get(0), msgs.get(2));
        assertTrue(Bbs.proofVerify(pk, proof, hdr, ph, dis, idx));
        assertFalse(Bbs.proofVerify(pk, proof, hdr, new byte[] {9}, dis, idx));
        assertFalse(Bbs.proofVerify(pk, proof, hdr, ph, List.of(msgs.get(0), msgs.get(1)), idx));
        byte[] bad = proof.clone();
        bad[proof.length - 1] ^= 1;
        assertFalse(Bbs.proofVerify(pk, bad, hdr, ph, dis, idx));
        // two proofs of one signature differ (unlinkability)
        assertFalse(java.util.Arrays.equals(proof, Bbs.proofGen(pk, h(f.get("signature")), hdr, ph, msgs, idx)));
    }
}
