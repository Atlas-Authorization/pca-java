package net.atlasauth.pca.aggsig;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import net.atlasauth.pca.Json;
import org.junit.jupiter.api.Test;

/**
 * Community-standard BLS12-381 vectors (ethereum/bls12-381-tests v0.1.2) for the PoP ciphersuite
 * BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ (draft-irtf-cfrg-bls-signature has no vectors of its own), vendored in test-data
 * with provenance. The same fixtures the TypeScript package replays.
 */
class AggsigKatTest {
    private static final Path ROOT = Path.of("test-data/ethereum-bls12-381-tests-v0.1.2");

    private static byte[] h(String s) { return HexFormat.of().parseHex(s.startsWith("0x") ? s.substring(2) : s); }

    private record Case(String name, Object input, Object output) {}

    @SuppressWarnings("unchecked")
    private static List<Case> cases(String dir) throws IOException {
        List<Case> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(ROOT.resolve(dir))) {
            for (Path p : (Iterable<Path>) s.sorted()::iterator) {
                Map<String, Object> j = (Map<String, Object>) Json.parse(Files.readString(p, StandardCharsets.UTF_8));
                out.add(new Case(p.getFileName().toString(), j.get("input"), j.get("output")));
            }
        }
        assertFalse(out.isEmpty(), dir);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static List<byte[]> hs(Object list) {
        List<byte[]> out = new ArrayList<>();
        for (Object o : (List<?>) list) out.add(h((String) o));
        return out;
    }

    @Test void sign() throws Exception {
        for (Case c : cases("sign")) {
            byte[] sk = h((String) m(c.input).get("privkey"));
            byte[] msg = h((String) m(c.input).get("message"));
            if (c.output == null) assertThrows(RuntimeException.class, () -> AggsigCore.sign(sk, msg), c.name);
            else assertArrayEquals(h((String) c.output), AggsigCore.sign(sk, msg), c.name);
        }
    }

    @Test void verify() throws Exception {
        for (Case c : cases("verify")) {
            Map<String, Object> i = m(c.input);
            assertEquals(c.output, AggsigCore.verify(h((String) i.get("pubkey")), h((String) i.get("message")), h((String) i.get("signature"))), c.name);
        }
    }

    @Test void aggregate() throws Exception {
        for (Case c : cases("aggregate")) {
            List<byte[]> sigs = hs(c.input);
            if (c.output == null) assertThrows(IllegalArgumentException.class, () -> AggsigCore.aggregate(sigs), c.name);
            else assertArrayEquals(h((String) c.output), AggsigCore.aggregate(sigs), c.name);
        }
    }

    @Test void fastAggregateVerify() throws Exception {
        for (Case c : cases("fast_aggregate_verify")) {
            Map<String, Object> i = m(c.input);
            assertEquals(c.output, AggsigCore.fastAggregateVerify(hs(i.get("pubkeys")), h((String) i.get("message")), h((String) i.get("signature"))), c.name);
        }
    }

    @Test void aggregateVerify() throws Exception {
        for (Case c : cases("aggregate_verify")) {
            Map<String, Object> i = m(c.input);
            assertEquals(c.output, AggsigCore.aggregateVerify(hs(i.get("pubkeys")), hs(i.get("messages")), h((String) i.get("signature"))), c.name);
        }
    }

    /** The fixtures test decoding + subgroup; KeyValidate additionally rejects the identity (draft 2.5). */
    @Test void keyValidate() throws Exception {
        for (Case c : cases("deserialization_G1")) {
            String pk = (String) m(c.input).get("pubkey");
            boolean inf = pk.matches("^c0+$");
            assertEquals(((Boolean) c.output) && !inf, AggsigCore.keyValidate(h(pk)), c.name);
        }
    }

    @Test void malformedSignaturesNeverVerify() throws Exception {
        byte[] pk = h("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
        for (Case c : cases("deserialization_G2")) {
            assertFalse(AggsigCore.verify(pk, new byte[32], h((String) m(c.input).get("signature"))), c.name);
        }
    }

    @Test void popAndRogueKey() {
        byte[] sk1 = h("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3");
        byte[] sk2 = h("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138");
        byte[] pk1 = AggsigCore.publicKeyOf(sk1);
        byte[] pk2 = AggsigCore.publicKeyOf(sk2);
        byte[] pop1 = AggsigCore.popProve(sk1);
        assertTrue(AggsigCore.popVerify(pk1, pop1));
        assertFalse(AggsigCore.popVerify(pk2, pop1));
        // domain separation both ways
        assertFalse(AggsigCore.popVerify(pk1, AggsigCore.sign(sk1, pk1)));
        assertFalse(AggsigCore.verify(pk1, pk1, pop1));
        // the public API admits only a verified proof of possession
        assertTrue(Aggsig.registerKey(pk1, pop1).ok);
        assertFalse(Aggsig.registerKey(pk2, pop1).ok);
        KeyRegistry reg = new KeyRegistry();
        assertTrue(reg.register(pk1, pop1).ok);
        assertTrue(reg.has(pk1));
        assertFalse(reg.has(pk2));
        // one signer cannot be counted twice
        byte[] msg = new byte[32];
        byte[] s = Aggsig.sign(sk1, msg);
        RegisteredKey k = reg.get(pk1);
        assertTrue(Aggsig.fastAggregateVerify(List.of(k), msg, s));
        assertFalse(Aggsig.fastAggregateVerify(List.of(k, k, k), msg, Aggsig.aggregate(List.of(s, s, s))));
    }
}
