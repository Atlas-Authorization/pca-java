package net.atlasauth.pca;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentStats;
import org.junit.jupiter.api.Test;

class IntentStatsDiffTest {
    private static final String M = "ref-intent-stats";

    private static double d(Object o) { return Double.parseDouble(o.toString()); }

    private static int i(Object o) { return (int) d(o); }

    @SuppressWarnings("unchecked")
    private static BigInteger big(Object o) { return new BigInteger((String) ((Map<String, Object>) o).get("$bigint")); }

    private static Map<String, Object> bigJ(BigInteger b) { Map<String, Object> m = new LinkedHashMap<>(); m.put("$bigint", b.toString()); return m; }

    /** A non-finite double is printed {"$num": "NaN"} by the reference. */
    private static Object num(double v) {
        if (Double.isFinite(v)) return v;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("$num", Double.isNaN(v) ? "NaN" : v > 0 ? "Infinity" : "-Infinity");
        return m;
    }

    @Test void clopperPearsonUpper() throws Exception { OracleCases.each(M, "clopperPearsonUpper", a -> IntentStats.clopperPearsonUpper(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }

    @Test void clopperPearsonCertified() throws Exception {
        OracleCases.each(M, "clopperPearsonCertified", a -> {
            IntentStats.CPCertificate c = IntentStats.clopperPearsonCertified(d(a.get(0)), d(a.get(1)), d(a.get(2)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("upper", c.upper());
            m.put("upperUnits", bigJ(c.upperUnits()));
            m.put("lowerUnits", bigJ(c.lowerUnits()));
            return m;
        });
    }

    /** A finite result may differ from the reference in the last digits (the platform's log/exp versus V8's): relative 1e-12. */
    @Test void binomialCdf() throws Exception {
        OracleCases.Fn f = a -> IntentStats.binomialCdf(i(a.get(0)), i(a.get(1)), d(a.get(2)));
        List<String> bad = new java.util.ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, "binomialCdf")) {
            Double want = OracleCases.num(c.get("out"));
            try {
                Object got = f.apply((List<?>) c.get("args"));
                if (want != null && got instanceof Double && Double.isFinite(want) && Double.isFinite((Double) got)
                    && Math.abs((Double) got - want) <= 1e-12 * Math.max(1, Math.abs(want))) continue;
            } catch (Exception e) { /* diff reports it */ }
            String dd = OracleCases.diff(c, c.get("out"), f);
            if (dd != null) bad.add(dd);
        }
        org.junit.jupiter.api.Assertions.assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of binomialCdf:\n" + String.join("\n", bad));
    }

    @Test void doubleToDyadic() throws Exception {
        OracleCases.each(M, "doubleToDyadic", a -> {
            IntentStats.Dyadic y = IntentStats.doubleToDyadic(d(a.get(0)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("num", bigJ(y.num()));
            m.put("exp", y.exp());
            return m;
        });
    }

    @Test void cdfRecNumerator() throws Exception { OracleCases.each(M, "cdfRecNumerator", a -> bigJ(IntentStats.cdfRecNumerator(i(a.get(0)), i(a.get(1)), big(a.get(2))))); }

    @Test void cdfExceeds() throws Exception {
        OracleCases.each(M, "cdfExceeds", a -> {
            @SuppressWarnings("unchecked") Map<String, Object> al = (Map<String, Object>) a.get(3);
            return IntentStats.cdfExceeds(i(a.get(0)), i(a.get(1)), big(a.get(2)), new IntentStats.Dyadic(big(al.get("num")), i(al.get("exp"))));
        });
    }

    @Test void hoeffdingHalfWidth() throws Exception {
        OracleCases.each(M, "hoeffdingHalfWidth", a -> num(a.size() > 2 ? IntentStats.hoeffdingHalfWidth(d(a.get(0)), d(a.get(1)), d(a.get(2))) : IntentStats.hoeffdingHalfWidth(d(a.get(0)), d(a.get(1)))));
    }

    @Test void wilsonInterval() throws Exception {
        OracleCases.each(M, "wilsonInterval", a -> {
            List<?> x = a;
            IntentStats.Wilson w = x.size() > 2 ? IntentStats.wilsonInterval(d(x.get(0)), d(x.get(1)), d(x.get(2))) : IntentStats.wilsonInterval(d(x.get(0)), d(x.get(1)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("p", num(w.p()));
            m.put("lo", num(w.lo()));
            m.put("hi", num(w.hi()));
            return m;
        });
    }
}
