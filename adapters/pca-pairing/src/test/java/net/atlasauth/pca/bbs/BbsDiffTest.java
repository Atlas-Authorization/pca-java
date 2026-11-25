package net.atlasauth.pca.bbs;

import static net.atlasauth.pca.aggsig.Oracle.bytes;
import static net.atlasauth.pca.aggsig.Oracle.bytesList;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.aggsig.Oracle;
import net.atlasauth.pca.pairing.Bls12;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference corpus (test-data/ref-bbs.json.gz) through the native BBS port. */
class BbsDiffTest {
    private static final String M = "ref-bbs";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static BigInteger unhex(Object s) { return new BigInteger((String) s, 16); }

    private static String hex(BigInteger n) { return String.format("%064x", n); }

    private static List<Integer> ints(Object list) {
        List<Integer> out = new ArrayList<>();
        for (Object o : (List<?>) list) out.add(o == null ? null : Integer.parseInt(o.toString())); // a hole in the reference list is a null
        return out;
    }

    private static Map<String, Object> result(Bbs.Result r) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("ok", r.ok());
        if (!r.ok()) o.put("reason", r.reason());
        return o;
    }

    @Test void hashToScalar() throws Exception { Oracle.each(M, "hashToScalar", a -> hex(Bbs.hashToScalar(bytes(a.get(0)), (String) a.get(1)))); }
    @Test void mapMessageToScalarAsHash() throws Exception { Oracle.each(M, "mapMessageToScalarAsHash", a -> hex(Bbs.mapMessageToScalarAsHash(bytes(a.get(0))))); }

    @Test void createGenerators() throws Exception {
        Oracle.each(M, "createGenerators", a -> Bbs.createGenerators(Integer.parseInt(a.get(0).toString())));
    }

    @Test void keyGen() throws Exception { Oracle.each(M, "keyGen", a -> hex(Bbs.keyGen(bytes(a.get(0)), bytes(a.get(1))))); }
    @Test void skToPk() throws Exception { Oracle.each(M, "skToPk", a -> Bbs.skToPk(unhex(a.get(0)))); }

    @Test void sign() throws Exception {
        Oracle.each(M, "sign", a -> Bbs.sign(unhex(a.get(0)), bytes(a.get(1)), bytes(a.get(2)), bytesList(a.get(3))));
    }

    @Test void verifyDetailed() throws Exception {
        Oracle.each(M, "verifyDetailed", a -> result(Bbs.verifyDetailed(bytes(a.get(0)), bytes(a.get(1)), bytes(a.get(2)), bytesList(a.get(3)))));
    }

    @Test void proofGen() throws Exception {
        Oracle.each(M, "proofGen", a -> {
            List<BigInteger> rs = new ArrayList<>();
            for (Object x : (List<?>) a.get(6)) rs.add(unhex(x));
            return Bbs.proofGen(bytes(a.get(0)), bytes(a.get(1)), bytes(a.get(2)), bytes(a.get(3)), bytesList(a.get(4)), ints(a.get(5)), rs);
        });
    }

    @Test void proofVerifyDetailed() throws Exception {
        Oracle.each(M, "proofVerifyDetailed", a -> result(Bbs.proofVerifyDetailed(bytes(a.get(0)), bytes(a.get(1)), bytes(a.get(2)), bytes(a.get(3)), bytesList(a.get(4)), ints(a.get(5)))));
    }

    @Test void capabilityAttributes() throws Exception { Oracle.each(M, "capabilityAttributes", a -> BbsCredential.capabilityAttributes(m(a.get(0)))); }

    @Test void issueCapabilityCredential() throws Exception {
        Oracle.each(M, "issueCapabilityCredential", a -> BbsCredential.issueCapabilityCredential(m(a.get(0)), unhex(a.get(1)), bytes(a.get(2)), bytes(a.get(3))));
    }

    @Test void verifyCredential() throws Exception { Oracle.each(M, "verifyCredential", a -> BbsCredential.verifyCredential(m(a.get(0)))); }

    @SuppressWarnings("unchecked")
    @Test void verifyPresentation() throws Exception {
        Oracle.each(M, "verifyPresentation", a -> {
            Map<String, Object> opts = m(a.get(1));
            return BbsCredential.verifyPresentation(m(a.get(0)),
                    opts.containsKey("pk") ? bytes(opts.get("pk")) : null,
                    opts.containsKey("disclosed") ? (List<Map<String, Object>>) opts.get("disclosed") : null,
                    opts.containsKey("presentationHeader") ? bytes(opts.get("presentationHeader")) : null);
        });
    }

    /** Presentation round trip through the randomized presentCredential. */
    @Test void presentRoundTrip() {
        BigInteger sk = Bbs.keyGen(new byte[32]);
        byte[] pk = Bbs.skToPk(sk);
        Map<String, Object> cap = new LinkedHashMap<>();
        cap.put("issuer", "i");
        cap.put("holder", "h");
        Map<String, Object> cv = new LinkedHashMap<>();
        cv.put("type", "amount");
        cap.put("caveats", List.of(cv));
        Map<String, Object> cred = BbsCredential.issueCapabilityCredential(cap, sk, pk, null);
        org.junit.jupiter.api.Assertions.assertTrue(BbsCredential.verifyCredential(cred));
        Map<String, Object> pres = BbsCredential.presentCredential(cred, List.of("iss"), new byte[] {1});
        org.junit.jupiter.api.Assertions.assertTrue(BbsCredential.verifyPresentation(pres, null, null, null));
        org.junit.jupiter.api.Assertions.assertTrue(BbsCredential.verifyPresentation(pres, pk, null, new byte[] {1}));
        org.junit.jupiter.api.Assertions.assertFalse(BbsCredential.verifyPresentation(pres, null, null, new byte[] {2}));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> BbsCredential.presentCredential(cred, List.of("nope"), null));
    }
}
