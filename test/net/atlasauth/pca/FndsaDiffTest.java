package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.fndsa.FnDsa;
import net.atlasauth.pca.fndsa.FnDsa.FalconBackend;
import net.atlasauth.pca.fndsa.FnDsa.FalconKat;
import net.atlasauth.pca.fndsa.FnDsa.FalconKeyPair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class FndsaDiffTest {
    private static final String M = "ref-fndsa";

    @AfterEach void reset() { FnDsa.resetFalconBackend(); }

    @SuppressWarnings("unchecked")
    private static byte[] by(Object o) {
        if (o instanceof Map && ((Map<String, Object>) o).get("$bytes") instanceof String) return Keys.unb64u((String) ((Map<String, Object>) o).get("$bytes"));
        throw new IllegalArgumentException("expected a byte array");
    }

    /** Non-bytes arrive as null: the reference's verify guards turn them into false instead of throwing. */
    private static byte[] byOrNull(Object o) { try { return by(o); } catch (IllegalArgumentException e) { return null; } }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static String strOrNull(Object o) { return o instanceof String ? (String) o : null; }

    private static void install(String kind) {
        FnDsa.resetFalconBackend();
        FalconBackend mock = FnDsa.registerTestBackend(null);
        switch (kind) {
            case "mock": return;
            case "none": FnDsa.resetFalconBackend(); return;
            case "verify-only": FnDsa.setFalconBackend(mock::verify); return;
            case "short-sig": FnDsa.setFalconBackend(new FalconBackend() {
                @Override public boolean verify(byte[] p, byte[] m, byte[] s) { return mock.verify(p, m, s); }
                @Override public boolean canSign() { return true; }
                @Override public byte[] sign(byte[] k, byte[] m) { return new byte[10]; }
            }); return;
            case "all-true": FnDsa.setFalconBackend(new FalconBackend() {
                @Override public boolean verify(byte[] p, byte[] m, byte[] s) { return true; }
                @Override public boolean canSign() { return true; }
                @Override public byte[] sign(byte[] k, byte[] m) { return mock.sign(k, m); }
            }); return;
            case "throws": FnDsa.setFalconBackend(new FalconBackend() {
                @Override public boolean verify(byte[] p, byte[] m, byte[] s) { throw new IllegalStateException("backend exploded"); }
                @Override public boolean canSign() { return true; }
                @Override public byte[] sign(byte[] k, byte[] m) { return mock.sign(k, m); }
            }); return;
            default: throw new IllegalArgumentException(kind);
        }
    }

    @Test void resolveFnDsaAlg() throws Exception {
        OracleCases.each(M, "resolveFnDsaAlg", a -> { FnDsa.Suite s = FnDsa.resolveFnDsaAlg(a.get(0)); return s == null ? null : s.toMap(); });
    }
    @Test void isKnownFnDsaAlg() throws Exception { OracleCases.each(M, "isKnownFnDsaAlg", a -> FnDsa.isKnownFnDsaAlg(a.get(0))); }
    @Test void isFnDsaVariant() throws Exception { OracleCases.each(M, "isFnDsaVariant", a -> FnDsa.isFnDsaVariant(a.get(0))); }

    @Test void hashKat() throws Exception { OracleCases.each(M, "hashKat", a -> FnDsa.hashKat(by(a.get(0)), OracleCases.num(a.get(1)).intValue())); }

    @Test void mockKeypair() throws Exception {
        OracleCases.each(M, "mockKeypair", a -> {
            String v = strOrNull(a.get(0));
            FalconKeyPair k = a.size() < 2 ? FnDsa.mockKeypair(v) : FnDsa.mockKeypair(v, a.get(1) instanceof String ? a.get(1) : by(a.get(1)));
            return Map.of("pk", k.pk, "sk", k.sk);
        });
    }

    @Test void fndsaLeafMessage() throws Exception { OracleCases.each(M, "fndsaLeafMessage", a -> FnDsa.fndsaLeafMessage(map(a.get(0)), (String) a.get(1), (String) a.get(2))); }

    @Test void fndsaSignWith() throws Exception {
        OracleCases.each(M, "fndsaSignWith", a -> { install((String) a.get(0)); return FnDsa.fndsaSign(strOrNull(a.get(1)), byOrNull(a.get(2)), byOrNull(a.get(3))); });
    }

    @Test void fndsaVerifyWith() throws Exception {
        OracleCases.each(M, "fndsaVerifyWith", a -> { install((String) a.get(0)); return FnDsa.fndsaVerify(strOrNull(a.get(1)), byOrNull(a.get(2)), byOrNull(a.get(3)), byOrNull(a.get(4))); });
    }

    private static List<FalconKat> kats(Object o) {
        List<FalconKat> out = new ArrayList<>();
        for (Object x : (List<?>) o) { Map<String, Object> m = map(x); out.add(new FalconKat(by(m.get("pk")), by(m.get("msg")), by(m.get("sig")))); }
        return out;
    }

    @Test void fndsaVerifyKat() throws Exception {
        OracleCases.each(M, "fndsaVerifyKat", a -> {
            FnDsa.resetFalconBackend();
            FnDsa.registerTestBackend(kats(a.get(4)));
            return FnDsa.fndsaVerify((String) a.get(0), by(a.get(1)), by(a.get(2)), by(a.get(3)));
        });
    }

    @Test void fndsaSignKat() throws Exception {
        OracleCases.each(M, "fndsaSignKat", a -> {
            List<FalconKat> v = kats(a.get(0));
            String variant = v.get(0).pk.length == FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES ? "fn-dsa-512" : "fn-dsa-1024";
            FnDsa.resetFalconBackend();
            FnDsa.registerTestBackend(v);
            return FnDsa.fndsaSign(variant, FnDsa.mockKeypair(variant, "ref").sk, "m".getBytes(StandardCharsets.UTF_8));
        });
    }

    @Test void signPcaWithFndsa() throws Exception {
        OracleCases.each(M, "signPcaWithFndsa", a -> {
            install("mock");
            Map<String, Object> in = map(a.get(0));
            Object fd = in.get("fnDsa");
            if (!(fd instanceof Map)) throw new IllegalArgumentException("fnDsa required");
            return FnDsa.signPcaWithFndsa(in.get("alg"), map(in.get("leaf")), byOrNull(map(fd).get("pk")), byOrNull(map(fd).get("sk")), byOrNull(in.get("edSecret")));
        });
    }

    private static boolean verifyPca(Object input, String kind) {
        install(kind);
        Map<String, Object> in = map(input);
        return FnDsa.verifyPcaFndsa(in.get("alg"), map(in.get("leaf")), in.get("holder"), in.get("pq_pk"), in.get("sig"), in.get("pq_sig"));
    }

    @Test void verifyPcaFndsa() throws Exception { OracleCases.each(M, "verifyPcaFndsa", a -> verifyPca(a.get(0), "mock")); }
    @Test void verifyPcaFndsaNone() throws Exception { OracleCases.each(M, "verifyPcaFndsaNone", a -> verifyPca(a.get(0), "none")); }

    @Test void sizesAndDefaultBackend() {
        assertEquals(897, FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES);
        assertEquals(1280, FnDsa.FN_DSA_1024_SIGNATURE_BYTES);
        assertNotNull(FnDsa.resolveFnDsaAlg("hybrid-ed25519-fn-dsa-1024"));
        FalconKeyPair k = FnDsa.mockKeypair("fn-dsa-512");
        // the default backend refuses loudly once the length guard has passed, and the guard still returns false on a short signature
        assertThrows(IllegalStateException.class, () -> FnDsa.fndsaVerify("fn-dsa-512", k.pk, new byte[1], new byte[666]));
        assertFalse(FnDsa.fndsaVerify("fn-dsa-512", k.pk, new byte[1], new byte[665]));
        assertTrue(FnDsa.getFalconBackend() != null);
    }
}
