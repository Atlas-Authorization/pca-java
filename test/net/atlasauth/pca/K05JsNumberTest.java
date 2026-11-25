package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** JavaScript Number(string), the coercion behind verb floors (traits.ts leq) and bundle versions (bundle.ts compareVersion). */
public class K05JsNumberTest {
    static final String[] NAN = {"+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000",
        "\u0661", "\uff11", "0x\u0661", "infinity", "INFINITY", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L", "1F", "1D", "0x1p3", "0x1.8p1",
        "\u001c1", "\u001d1", "\u001e1", "\u001f1", "1\u001c", "\u00851", "\u200b1", "\u180e1", "1\0", "\u00001"};

    static final Object[][] NUMBER = {
        {"", 0d}, {" ", 0d}, {"\t\n\u000b\f\r", 0d}, {"\ufeff\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000", 0d},
        {" 12 ", 12d}, {"\ufeff12\u00a0", 12d}, {"\u202f12\u2007", 12d},
        {"Infinity", Double.POSITIVE_INFINITY}, {"+Infinity", Double.POSITIVE_INFINITY}, {"-Infinity", Double.NEGATIVE_INFINITY},
        {"0x10", 16d}, {"0X1f", 31d}, {"0o7", 7d}, {"0O7", 7d}, {"0b1", 1d}, {"0B1", 1d}, {"1.", 1d}, {".5", 0.5d}, {"1e3", 1000d}, {"+1.5", 1.5d}, {"-0", -0d},
        {"0x" + "f".repeat(300), Double.POSITIVE_INFINITY}, {"0x" + "f".repeat(5000), Double.POSITIVE_INFINITY},
        {"0x" + "0".repeat(2000) + "1", 1d},
        {"0b1" + "0".repeat(1023), Math.scalb(1d, 1023)}, {"0b1" + "0".repeat(1024), Double.POSITIVE_INFINITY},
    };

    @Test void everyFormJsReadsAsNaNIsNaN() {
        for (String s : NAN) {
            assertTrue(Double.isNaN(AttestNvidia.jsNumber(s)), "helper " + s);
            assertTrue(Double.isNaN(Actions.jsNumber(s, true)), "floor " + s);
        }
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x" + "g".repeat(5000))), "an invalid digit past the digit bound");
    }

    @Test void everyFormJsParsesParses() {
        for (Object[] c : NUMBER) {
            assertEquals((double) c[1], AttestNvidia.jsNumber((String) c[0]), "helper " + c[0]);
            assertEquals((double) c[1], Actions.jsNumber(c[0], true), "floor " + c[0]);
        }
    }

    @Test void aForgedFloorNeverAdmitsARisk() {
        for (String s : NAN) assertTrue(!(0 <= Actions.jsNumber(s, true)), "0 <= " + s);
    }

    @Test void compareVersionReadsPartsLikeNumber() {
        for (String s : new String[] {"1f", "1d", "NaN", "0x1p3"}) assertEquals(1, K3.compareVersion(s, "1"), s + " is NaN: the compare answers 1");
        assertEquals(0, K3.compareVersion("0x10", "16"));
        assertEquals(0, K3.compareVersion("\ufeff2", "2"));
        assertEquals(1, K3.compareVersion("\u001c2", "2"));
    }

    /** intent-history.ts:143: Number(q.slice('pending:'.length)) on the monitor state. */
    @Test void respondsWithinPendingStateReadsLikeNumber() {
        Map<String, Object> m = IntentJs.obj(Json.parseLenient("{\"id\":\"m\",\"kind\":\"responds_within\",\"within\":9,\"p\":{\"verb\":\"shop.verify\",\"resource\":\"*\"},\"q\":{\"verb\":\"shop.buy\",\"resource\":\"*\"}}"));
        Map<String, Object> other = IntentJs.obj(Json.parseLenient("{\"verb\":\"shop.other\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}"));
        assertEquals("missed", IntentHistory.monitorStep(m, "pending:", other), "an empty number is 0");
        assertEquals("missed", IntentHistory.monitorStep(m, "pending:  ", other));
        for (String q : new String[] {" 3 ", "BOM3", "0x3", "0b11", "0o3", "3.", "+3"}) assertEquals("pending:2", IntentHistory.monitorStep(m, "pending:" + q.replace("BOM", "\ufeff"), other), q);
        for (String q : NAN) assertEquals("pending:NaN", IntentHistory.monitorStep(m, "pending:" + q, other), q);
    }

    /** attest-nvidia-spdm.ts:317: Number(key) of a pinned measurement; only an integer in 0..255 is a key. */
    @Test void policyMeasurementKeysReadLikeNumber() {
        String bad = "createNvidiaSpdmVerifier: measurement index out of range";
        for (String k : NAN) assertEquals(bad, AttestNvidiaTest.constructError(policy(k)), k);
        for (String k : new String[] {"0x1", "0b1", "0o7", " 1 ", "BOM1", "1.", "1e1", "+1", "", " "}) assertEquals("no error", AttestNvidiaTest.constructError(policy(k.replace("BOM", "\ufeff"))), k);
    }

    private static String policy(String key) {
        return "{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{" + Json.canonicalize(key) + ":\"aa\"}}}";
    }
}
