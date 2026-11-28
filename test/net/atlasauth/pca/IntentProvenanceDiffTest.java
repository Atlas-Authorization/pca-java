package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.function.ToDoubleFunction;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentProvenance;
import org.junit.jupiter.api.Test;

class IntentProvenanceDiffTest {
    private static final String M = "ref-intent-provenance";
    private static final String A = "action.params.";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    private static double amt(Outcome o) { Object x = o.values().get(A + "amount"); return x instanceof Double ? (Double) x : 0; }

    private static Predicate<Outcome> admits(String n) {
        switch (n) {
            case "all": return o -> true;
            case "none": return o -> false;
            case "amountLe50": return o -> amt(o) <= 50;
            default: return o -> o.verb().equals("stripe.refund");
        }
    }

    private static ToDoubleFunction<Outcome> utility(String n) {
        switch (n) {
            case "amount": return IntentProvenanceDiffTest::amt;
            case "negAmount": return o -> -amt(o);
            case "zero": return o -> 0;
            case "nan": return o -> Double.NaN;
            default: return o -> amt(o) + ("bob".equals(o.values().get(A + "recipient")) ? 1000 : 0);
        }
    }

    private static IntentProvenance.RegretCase bind(Object co) {
        Map<String, Object> c = mp(co);
        List<Outcome> feasible = new ArrayList<>();
        for (Object x : IntentOmega.arr(c.get("feasible"))) feasible.add(IntentOmega.outcomeFromJson(x));
        return new IntentProvenance.RegretCase(feasible, IntentOmega.outcomeFromJson(c.get("chosen")), admits((String) c.get("admits")), utility((String) c.get("utility")));
    }

    @Test void provenanceBanner() throws Exception {
        OracleCases.each(M, "provenanceBanner", a -> IntentProvenance.provenanceBanner((String) a.get(0), a.size() > 1 ? (String) a.get(1) : null));
    }

    @Test void isTainted() throws Exception { OracleCases.each(M, "isTainted", a -> IntentProvenance.isTainted((String) a.get(0))); }

    @Test void provenanceFriction() throws Exception {
        OracleCases.each(M, "provenanceFriction", a -> IntentProvenance.provenanceFriction((String) a.get(0), (String) a.get(1), (String) a.get(2)));
    }

    @Test void regret() throws Exception { OracleCases.each(M, "regret", a -> IntentProvenance.withinGrantRegret(bind(a.get(0)))); }

    @Test void report() throws Exception {
        OracleCases.each(M, "report", a -> {
            List<IntentProvenance.RegretCase> cs = new ArrayList<>();
            for (Object c : IntentOmega.arr(a.get(0))) cs.add(bind(c));
            return IntentProvenance.regretReport(cs, a.size() > 1 ? IntentOmega.dbl(a.get(1)) : 1);
        });
    }
}
