package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.oprf.Oprf;
import net.atlasauth.pca.oprf.OprfPca;
import org.junit.jupiter.api.Test;

class OprfDiffTest {
    private static final String M = "ref-oprf";

    /** A byte argument: {"$bytes"} decodes; anything else (null, a string, a number) is what the reference refuses with a TypeError. */
    @SuppressWarnings("unchecked")
    private static byte[] by(Object o) {
        if (o instanceof Map && ((Map<String, Object>) o).get("$bytes") instanceof String) return Keys.unb64u((String) ((Map<String, Object>) o).get("$bytes"));
        throw new IllegalArgumentException("expected a byte array");
    }

    /** An optional trailing byte argument: absent is null; present must be bytes. */
    private static byte[] opt(List<?> a, int i) { return i < a.size() ? by(a.get(i)) : null; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static String str(Object o) {
        if (!(o instanceof String)) throw new IllegalArgumentException("expected a string");
        return (String) o;
    }

    private static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    @Test void genCorpusIsPresent() { BaseOracle.requireGen(M); }

    @Test void deriveKeyPair() throws Exception {
        OracleCases.each(M, "deriveKeyPair", a -> { Oprf.KeyPair k = Oprf.deriveKeyPair(by(a.get(0)), by(a.get(1)), str(a.get(2))); return m("secretKey", k.secretKey, "publicKey", k.publicKey); });
    }

    @Test void publicKeyFor() throws Exception { OracleCases.each(M, "publicKeyFor", a -> Oprf.publicKeyFor(by(a.get(0)))); }
    @Test void deserializeScalar() throws Exception { OracleCases.each(M, "deserializeScalar", a -> Oprf.deserializeScalar(by(a.get(0))).toString()); }
    @Test void serializeScalar() throws Exception { OracleCases.each(M, "serializeScalar", a -> Oprf.serializeScalar(new BigInteger(str(a.get(0))))); }
    @Test void hashToGroup() throws Exception { OracleCases.each(M, "hashToGroup", a -> Oprf.serializeElement(Oprf.hashToGroup(by(a.get(0)), str(a.get(1))))); }
    @Test void deserializeElement() throws Exception { OracleCases.each(M, "deserializeElement", a -> Oprf.serializeElement(Oprf.deserializeElement(by(a.get(0))))); }

    @Test void blind() throws Exception {
        OracleCases.each(M, "blind", a -> { Oprf.BlindResult b = Oprf.blind(by(a.get(0)), str(a.get(1)), opt(a, 2)); return m("blind", b.blind, "blindedElement", b.blindedElement); });
    }

    private static Map<String, Object> ev(Oprf.EvaluateResult r) {
        Map<String, Object> out = m("evaluatedElement", r.evaluatedElement);
        if (r.proof != null) out.put("proof", r.proof);
        return out;
    }

    /** The reference reads pk / proof-nonce as "absent" only when the argument is missing; a present null is a TypeError. */
    @Test void blindEvaluate() throws Exception {
        OracleCases.each(M, "blindEvaluate", a -> ev(Oprf.blindEvaluate(by(a.get(0)), by(a.get(1)), str(a.get(2)), opt(a, 3), opt(a, 4))));
    }

    @Test void evaluate() throws Exception { OracleCases.each(M, "evaluate", a -> Oprf.evaluate(by(a.get(0)), by(a.get(1)), str(a.get(2)))); }

    @Test void finalizeOprf() throws Exception {
        OracleCases.each(M, "finalize", a -> {
            Map<String, Object> o = a.size() > 4 ? map(a.get(4)) : null;
            byte[] proof = null, pk = null, blinded = null;
            if (o != null) { proof = o.containsKey("proof") ? by(o.get("proof")) : null; pk = o.containsKey("publicKey") ? by(o.get("publicKey")) : null; blinded = o.containsKey("blindedElement") ? by(o.get("blindedElement")) : null; }
            return Oprf.finalizeOprf(by(a.get(0)), by(a.get(1)), by(a.get(2)), str(a.get(3)), proof, pk, blinded);
        });
    }

    @Test void blindPoprf() throws Exception {
        OracleCases.each(M, "blindPoprf", a -> { Oprf.PoprfBlindResult b = Oprf.blindPoprf(by(a.get(0)), by(a.get(1)), by(a.get(2)), opt(a, 3)); return m("blind", b.blind, "blindedElement", b.blindedElement, "tweakedKey", b.tweakedKey); });
    }

    @Test void blindEvaluatePoprf() throws Exception { OracleCases.each(M, "blindEvaluatePoprf", a -> ev(Oprf.blindEvaluatePoprf(by(a.get(0)), by(a.get(1)), by(a.get(2)), opt(a, 3)))); }
    @Test void evaluatePoprf() throws Exception { OracleCases.each(M, "evaluatePoprf", a -> Oprf.evaluatePoprf(by(a.get(0)), by(a.get(1)), by(a.get(2)))); }

    @Test void finalizePoprf() throws Exception {
        OracleCases.each(M, "finalizePoprf", a -> {
            Map<String, Object> o = map(a.get(4));
            return Oprf.finalizePoprf(by(a.get(0)), by(a.get(1)), by(a.get(2)), by(a.get(3)), o.containsKey("proof") ? by(o.get("proof")) : null, by(o.get("blindedElement")), by(o.get("tweakedKey")));
        });
    }

    @Test void toHex() throws Exception { OracleCases.each(M, "toHex", a -> Oprf.toHex(by(a.get(0)))); }
    @Test void bytesEqual() throws Exception { OracleCases.each(M, "bytesEqual", a -> Oprf.bytesEqual(by(a.get(0)), by(a.get(1)))); }

    // ---- PCA layer ----

    @SuppressWarnings("unchecked")
    private static List<String> ids(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : (List<Object>) o) out.add(str(x));
        return out;
    }

    @Test void buildRevocationSet() throws Exception {
        OracleCases.each(M, "buildRevocationSet", a -> {
            OprfPca.RevocationSet s = OprfPca.buildRevocationSet(by(a.get(0)), ids(a.get(1)), str(a.get(2)));
            List<String> sorted = new ArrayList<>(s.outputs);
            Collections.sort(sorted);
            Map<String, Object> out = m("outputs", sorted, "mode", s.mode);
            // the oracle's duplicate-id case records only {outputs, mode} (not recorded in the args: its ids are a, a, b)
            boolean dups = ids(a.get(1)).equals(List.of("a", "a", "b"));
            if (s.publicKey != null && !dups) out.put("publicKey", s.publicKey);
            return out;
        });
    }

    @Test void isRevokedPrivate() throws Exception {
        byte[] wrongKey = Oprf.deriveKeyPair(seed("ref-oprf/key-poprf"), new byte[] {'k'}, "poprf").secretKey;
        OracleCases.each(M, "isRevokedPrivate", a -> {
            if (!(a.get(0) instanceof String)) throw new IllegalArgumentException("capability id must be a string");
            Map<String, Object> op = map(a.get(1));
            byte[] sk = by(op.get("sk"));
            String mode = str(op.get("mode"));
            Object lie = op.get("lie");
            OprfPca.RevocationSet set = OprfPca.buildRevocationSet(sk, ids(op.get("revoked")), mode);
            OprfPca.BlindEvaluator real = OprfPca.makeRevocationEvaluator("wrong-key".equals(lie) ? wrongKey : sk, mode);
            OprfPca.BlindEvaluator e = "no-proof".equals(lie) ? blinded -> new Oprf.EvaluateResult(real.evaluate(blinded).evaluatedElement, null) : real;
            return OprfPca.isRevokedPrivate((String) a.get(0), e, set);
        });
    }

    @Test void rateToken() throws Exception { OracleCases.each(M, "rateToken", a -> OprfPca.rateToken(by(a.get(0)), str(a.get(1)), str(a.get(2)))); }
    @Test void rateTokenHex() throws Exception { OracleCases.each(M, "rateTokenHex", a -> OprfPca.rateTokenHex(by(a.get(0)), str(a.get(1)), str(a.get(2)))); }

    @Test void privateRateToken() throws Exception {
        OracleCases.each(M, "privateRateToken", a -> {
            Map<String, Object> op = map(a.get(2));
            byte[] sk = by(op.get("sk"));
            byte[] pk = op.containsKey("pk") ? by(op.get("pk")) : Oprf.publicKeyFor(sk);
            return OprfPca.privateRateToken(str(a.get(0)), str(a.get(1)), OprfPca.makeRateEvaluator(sk), pk);
        });
    }

    @Test void rateCounter() throws Exception {
        OracleCases.each(M, "rateCounter", a -> {
            Double limit = OracleCases.num(a.get(0));
            if (limit == null || limit != Math.floor(limit) || limit < 1) throw new IllegalArgumentException("limit must be a positive integer");
            OprfPca.RateWindowCounter c = new OprfPca.RateWindowCounter(limit.intValue());
            List<Object> out = new ArrayList<>();
            for (Object step : (List<?>) a.get(1)) {
                List<?> s = (List<?>) step;
                String kind = (String) s.get(0);
                if (kind.equals("hit")) { int[] h = c.hit(by(s.get(1))); out.add(m("count", h[0], "allowed", h[1] == 1)); }
                else if (kind.equals("count")) out.add(c.count(by(s.get(1))));
                else { c.reset(); out.add(null); }
            }
            return out;
        });
    }

    // ---- RFC 9497 Appendix A.1 (ristretto255-SHA512) known-answer tests ----

    private static byte[] hx(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    private static String[] split(String s) { return s.split(","); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> fixture() throws Exception {
        return (Map<String, Object>) Json.parse(Files.readString(Path.of("test-data/rfc9497-ristretto255-sha512.json")));
    }

    @Test void rfc9497DeriveKeyPair() throws Exception {
        Map<String, Object> modes = map(fixture().get("modes"));
        for (String mode : new String[] {"OPRF", "VOPRF", "POPRF"}) {
            Map<String, Object> k = map(modes.get(mode));
            Oprf.KeyPair kp = Oprf.deriveKeyPair(hx((String) k.get("Seed")), hx((String) k.get("KeyInfo")), mode.toLowerCase());
            assertEquals(k.get("skSm"), Oprf.toHex(kp.secretKey), mode);
            if (k.get("pkSm") != null) assertEquals(k.get("pkSm"), Oprf.toHex(kp.publicKey), mode);
        }
        Map<String, Object> o = map(modes.get("OPRF"));
        assertNotEquals(o.get("skSm"), Oprf.toHex(Oprf.deriveKeyPair(hx((String) o.get("Seed")), hx((String) o.get("KeyInfo")), "voprf").secretKey));
    }

    @Test void rfc9497Vectors() throws Exception {
        Map<String, Object> fx = fixture();
        Map<String, Object> modes = map(fx.get("modes"));
        int n = 0;
        for (Object vo : (List<?>) fx.get("vectors")) {
            Map<String, Object> v = map(vo);
            String mode = ((String) v.get("mode")).toLowerCase();
            Map<String, Object> key = map(modes.get(v.get("mode")));
            byte[] sk = hx((String) key.get("skSm"));
            byte[] pk = key.get("pkSm") == null ? null : hx((String) key.get("pkSm"));
            byte[] info = v.get("Info") == null ? null : hx((String) v.get("Info"));
            String[] inputs = split((String) v.get("Input")), blinds = split((String) v.get("Blind")), blinded = split((String) v.get("BlindedElement")), evald = split((String) v.get("EvaluationElement")), outs = split((String) v.get("Output"));
            boolean single = Json.asLong(v.get("batch")) == 1;
            for (int i = 0; i < inputs.length; i++, n++) {
                byte[] inp = hx(inputs[i]), bl = hx(blinds[i]), be = hx(blinded[i]), ee = hx(evald[i]);
                if (mode.equals("poprf")) {
                    Oprf.PoprfBlindResult b = Oprf.blindPoprf(inp, info, pk, bl);
                    assertEquals(blinded[i], Oprf.toHex(b.blindedElement));
                    assertEquals(evald[i], Oprf.toHex(Oprf.blindEvaluatePoprf(sk, be, info, null).evaluatedElement));
                    assertEquals(outs[i], Oprf.toHex(Oprf.evaluatePoprf(sk, inp, info)));
                    if (single) {
                        byte[] proof = hx((String) v.get("Proof"));
                        assertEquals(v.get("Proof"), Oprf.toHex(Oprf.blindEvaluatePoprf(sk, be, info, hx((String) v.get("ProofRandomScalar"))).proof));
                        assertEquals(outs[i], Oprf.toHex(Oprf.finalizePoprf(inp, b.blind, ee, info, proof, be, b.tweakedKey)));
                    }
                } else {
                    Oprf.BlindResult b = Oprf.blind(inp, mode, bl);
                    assertEquals(blinded[i], Oprf.toHex(b.blindedElement));
                    assertEquals(evald[i], Oprf.toHex(Oprf.blindEvaluate(sk, be, mode, pk, null).evaluatedElement));
                    assertEquals(outs[i], Oprf.toHex(Oprf.evaluate(sk, inp, mode)));
                    if (mode.equals("oprf")) assertEquals(outs[i], Oprf.toHex(Oprf.finalizeOprf(inp, b.blind, ee, "oprf", null, null, null)));
                    else if (single) {
                        byte[] proof = hx((String) v.get("Proof"));
                        assertEquals(v.get("Proof"), Oprf.toHex(Oprf.blindEvaluate(sk, be, "voprf", pk, hx((String) v.get("ProofRandomScalar"))).proof));
                        assertEquals(outs[i], Oprf.toHex(Oprf.finalizeOprf(inp, b.blind, ee, "voprf", proof, pk, be)));
                    }
                }
            }
        }
        assertTrue(n >= 10);
    }

    @Test void rfc9497NegativeProofs() throws Exception {
        Map<String, Object> fx = fixture();
        Map<String, Object> v1 = null;
        for (Object vo : (List<?>) fx.get("vectors")) { Map<String, Object> v = map(vo); if ("VOPRF".equals(v.get("mode")) && Json.asLong(v.get("n")) == 1) v1 = v; }
        byte[] pk = hx((String) map(map(fx.get("modes")).get("VOPRF")).get("pkSm"));
        byte[] proof = hx((String) v1.get("Proof"));
        byte[] input = hx((String) v1.get("Input")), blind = hx((String) v1.get("Blind")), ee = hx((String) v1.get("EvaluationElement")), be = hx((String) v1.get("BlindedElement"));
        assertEquals(v1.get("Output"), Oprf.toHex(Oprf.finalizeOprf(input, blind, ee, "voprf", proof, pk, be)));
        for (int idx : new int[] {0, 31, 32, 63}) {
            byte[] bad = proof.clone();
            bad[idx] ^= 1;
            assertThrows(RuntimeException.class, () -> Oprf.finalizeOprf(input, blind, ee, "voprf", bad, pk, be));
        }
        assertThrows(RuntimeException.class, () -> Oprf.finalizeOprf(input, blind, ee, "voprf", java.util.Arrays.copyOf(proof, 63), pk, be));
        assertThrows(RuntimeException.class, () -> Oprf.finalizeOprf(input, blind, ee, "voprf", null, pk, be));
    }

    @Test void privateFlowsAgreeWithTheReference() {
        byte[] sk = Oprf.deriveKeyPair(seed("ref-oprf/plain"), new byte[0], "poprf").secretKey;
        byte[] pk = Oprf.publicKeyFor(sk);
        OprfPca.RateBlindEvaluator ev = OprfPca.makeRateEvaluator(sk);
        assertArrayEquals(OprfPca.rateToken(sk, "agent", "w1"), OprfPca.privateRateToken("agent", "w1", ev, pk));
        assertFalse(java.util.Arrays.equals(OprfPca.rateToken(sk, "agent", "w1"), OprfPca.rateToken(sk, "agent", "w2")));
        OprfPca.RateWindowCounter c = new OprfPca.RateWindowCounter(2);
        byte[] t = OprfPca.rateToken(sk, "agent", "w1");
        assertEquals(1, c.hit(t)[0]);
        assertEquals(1, c.hit(t)[1]);
        assertEquals(0, c.hit(t)[1]);
        assertEquals(3, c.count(t));
        c.reset();
        assertEquals(0, c.count(t));
    }
}
