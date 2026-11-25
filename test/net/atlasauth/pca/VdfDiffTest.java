package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.vdf.Timelock;
import net.atlasauth.pca.vdf.Vdf;
import org.junit.jupiter.api.Test;

class VdfDiffTest {
    private static final String M = "ref-vdf";

    private static BigInteger b(Object o) {
        if (!(o instanceof String)) throw new IllegalArgumentException("bigint arg");
        return new BigInteger((String) o);
    }

    private static String s(BigInteger v) { return v.toString(); }

    /** A JavaScript safe integer >= 0 as a long; anything else is what the reference refuses with a RangeError. */
    private static long lng(Object o) {
        Double d = OracleCases.num(o);
        if (d == null || d < 0 || d > 9007199254740991d || d != Math.floor(d)) throw new IllegalArgumentException("not a safe step count");
        return d.longValue();
    }

    private static double dbl(Object o) { Double d = OracleCases.num(o); return d == null ? Double.NaN : d; }

    private static Map<String, Object> verdict(Vdf.VdfVerdict v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", v.ok);
        if (!v.ok) m.put("reason", v.reason);
        return m;
    }

    private static Map<String, Object> pf(Vdf.VdfProof p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("y", s(p.y));
        m.put("pi", s(p.pi));
        return m;
    }

    @Test void isProbablePrime() throws Exception { OracleCases.each(M, "isProbablePrime", a -> Vdf.isProbablePrime(b(a.get(0)))); }
    @Test void isMillerRabinProbablePrime() throws Exception { OracleCases.each(M, "isMillerRabinProbablePrime", a -> Vdf.isMillerRabinProbablePrime(b(a.get(0)))); }
    @Test void isStrongLucasProbablePrime() throws Exception { OracleCases.each(M, "isStrongLucasProbablePrime", a -> Vdf.isStrongLucasProbablePrime(b(a.get(0)))); }
    @Test void modpow() throws Exception { OracleCases.each(M, "modpow", a -> s(Vdf.modpow(b(a.get(0)), b(a.get(1)), b(a.get(2))))); }
    @Test void gcd() throws Exception { OracleCases.each(M, "gcd", a -> s(Vdf.gcd(b(a.get(0)), b(a.get(1))))); }
    @Test void canonicalVdfOutput() throws Exception { OracleCases.each(M, "canonicalVdfOutput", a -> s(Vdf.canonicalVdfOutput(b(a.get(0)), b(a.get(1))))); }
    @Test void bigIntToBytes() throws Exception { OracleCases.each(M, "bigIntToBytes", a -> Vdf.bigIntToBytes(b(a.get(0)))); }
    @Test void bytesRoundTrip() throws Exception { OracleCases.each(M, "bytesRoundTrip", a -> Vdf.bigIntToBytes(Vdf.bytesToBigInt(Keys.unb64u((String) a.get(0))))); }

    @Test void hashToPrime() throws Exception {
        OracleCases.each(M, "hashToPrime", a -> {
            if (a.size() > 4) {
                Double bits = OracleCases.num(a.get(4));
                if (bits == null || bits != Math.floor(bits)) throw new IllegalArgumentException("bits");
                return s(Vdf.hashToPrime(b(a.get(0)), b(a.get(1)), lng(a.get(2)), b(a.get(3)), bits.intValue()));
            }
            return s(Vdf.hashToPrime(b(a.get(0)), b(a.get(1)), lng(a.get(2)), b(a.get(3))));
        });
    }

    @Test void sequentialSquare() throws Exception { OracleCases.each(M, "sequentialSquare", a -> s(Vdf.sequentialSquare(b(a.get(0)), lng(a.get(1)), b(a.get(2))))); }
    @Test void vdfEval() throws Exception { OracleCases.each(M, "vdfEval", a -> pf(Vdf.vdfEval(b(a.get(0)), lng(a.get(1)), b(a.get(2))))); }
    @Test void vdfEvalCanonical() throws Exception { OracleCases.each(M, "vdfEvalCanonical", a -> pf(Vdf.vdfEvalCanonical(b(a.get(0)), lng(a.get(1)), b(a.get(2))))); }

    @Test void vdfVerifyDetailed() throws Exception {
        OracleCases.each(M, "vdfVerifyDetailed", a -> verdict(Vdf.vdfVerifyDetailed(b(a.get(0)), b(a.get(1)), b(a.get(2)), dbl(a.get(3)), b(a.get(4)))));
    }

    @Test void vdfVerifyCanonicalDetailed() throws Exception {
        OracleCases.each(M, "vdfVerifyCanonicalDetailed", a -> verdict(Vdf.vdfVerifyCanonicalDetailed(b(a.get(0)), b(a.get(1)), b(a.get(2)), dbl(a.get(3)), b(a.get(4)))));
    }

    @Test void checkProductionModulus() throws Exception {
        OracleCases.each(M, "checkProductionModulus", a -> {
            Vdf.ModulusCheck c = Vdf.checkProductionModulus(b(a.get(0)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", c.ok);
            if (!c.ok) m.put("reason", c.reason);
            return m;
        });
    }

    // ---- timelock wrappers (options arrive as a JSON object) ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> opts(Object o) { return (Map<String, Object>) o; }

    private static boolean allow(Map<String, Object> o) { return Boolean.TRUE.equals(o.get("allowInsecureDevModulus")); }

    @Test void deriveTimelockInput() throws Exception { OracleCases.each(M, "deriveTimelockInput", a -> s(Timelock.deriveTimelockInput(a.get(0), b(a.get(1)), a.get(2)))); }

    @Test void requireTimelock() throws Exception {
        OracleCases.each(M, "requireTimelock", a -> {
            Map<String, Object> o = opts(a.get(1));
            Timelock.TimelockRequirement q = Timelock.requireTimelock(a.get(0), lng(o.get("steps")), b(o.get("N")), o.get("beacon"), allow(o));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", q.kind); m.put("x", s(q.x)); m.put("steps", q.steps); m.put("N", s(q.N)); m.put("actionDigest", q.actionDigest);
            return m;
        });
    }

    @Test void proveTimelockElapsed() throws Exception {
        OracleCases.each(M, "proveTimelockElapsed", a -> {
            Map<String, Object> o = opts(a.get(3));
            Timelock.TimelockProof p = Timelock.proveTimelockElapsed(a.get(0), lng(a.get(1)), b(a.get(2)), o.get("beacon"), allow(o));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", p.kind); m.put("y", s(p.y)); m.put("pi", s(p.pi)); m.put("steps", (long) p.steps);
            return m;
        });
    }

    @Test void verifyTimelock() throws Exception {
        OracleCases.each(M, "verifyTimelock", a -> {
            Map<String, Object> o = opts(a.get(2));
            Timelock.TimelockProof p = null;
            if (a.get(1) instanceof Map) {
                Map<String, Object> pm = opts(a.get(1));
                p = new Timelock.TimelockProof(pm.get("kind") instanceof String ? (String) pm.get("kind") : null,
                    pm.get("y") instanceof String ? b(pm.get("y")) : null, pm.get("pi") instanceof String ? b(pm.get("pi")) : null, dbl(pm.get("steps")));
            }
            return Timelock.verifyTimelock(a.get(0), p, dbl(o.get("steps")), b(o.get("N")), o.get("beacon"), allow(o));
        });
    }

    // ---- plain tests the oracle cannot cover ----

    @Test void knownPrimesAndPseudoprimes() {
        for (int e : new int[] {89, 107, 127, 521, 607, 1279}) assertTrue(Vdf.isProbablePrime(BigInteger.TWO.pow(e).subtract(BigInteger.ONE)), "M" + e);
        // Carmichael numbers, strong pseudoprimes to base 2, and Lucas pseudoprimes are all composite
        for (long n : new long[] {561, 41041, 825265, 2047, 3277, 4033, 3215031751L, 5459, 5777, 10877}) assertFalse(Vdf.isProbablePrime(BigInteger.valueOf(n)), "n" + n);
        assertEquals(2048, Vdf.RSA_2048_CHALLENGE_MODULUS.bitLength());
        assertTrue(Vdf.checkProductionModulus(Vdf.RSA_2048_CHALLENGE_MODULUS).ok);
    }

    @Test void devSetupIsRefusedByTheTimelockLayer() {
        Vdf.InsecureDevVdfSetup st = Vdf.insecureDevSetup(256, new SecureRandom());
        assertTrue(st.insecureDevOnly);
        assertEquals(st.N, st.p.multiply(st.q));
        assertFalse(Vdf.checkProductionModulus(st.N).ok);
        assertThrows(IllegalArgumentException.class, () -> Timelock.requireTimelock("a", 10, st.N, "beacon", false));
        Timelock.TimelockProof p = Timelock.proveTimelockElapsed("a", 10, st.N, "beacon", true);
        assertFalse(Timelock.verifyTimelock("a", p, 10, st.N, "beacon", false));
        assertTrue(Timelock.verifyTimelock("a", p, 10, st.N, "beacon", true));
    }

    @Test void productionDefaultEndToEnd() {
        BigInteger n = Vdf.RSA_2048_CHALLENGE_MODULUS;
        Timelock.TimelockProof p = Timelock.proveTimelockElapsed("prod-action", 50, n, "test-beacon-0123456789abcdef", false);
        assertTrue(Timelock.verifyTimelock("prod-action", p, 50, n, "test-beacon-0123456789abcdef", false));
        assertFalse(Timelock.verifyTimelock("other-action", p, 50, n, "test-beacon-0123456789abcdef", false));
        Vdf.VdfProof q = Vdf.vdfEval(BigInteger.valueOf(123456789), 20, n);
        assertTrue(Vdf.vdfVerify(BigInteger.valueOf(123456789), q.y, q.pi, 20, n));
        assertFalse(Vdf.vdfVerify(BigInteger.valueOf(123456789), BigInteger.ZERO, BigInteger.ZERO, 1_000_000_000, n));
    }
}
