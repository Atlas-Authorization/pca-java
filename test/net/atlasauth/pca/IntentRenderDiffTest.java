package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentRender;
import net.atlasauth.pca.intent.IntentWitnesses;
import net.atlasauth.pca.intent.IntentWitnesses.Witness;
import org.junit.jupiter.api.Test;

class IntentRenderDiffTest {
    private static final String M = "ref-intent-render";

    private static int[] idx(Object o) {
        List<?> l = (List<?>) o;
        int[] a = new int[l.size()];
        for (int k = 0; k < a.length; k++) a[k] = (int) IntentOmega.dbl(l.get(k));
        return a;
    }

    private static List<Object> jsonList(List<Map<String, Object>> xs) { return new ArrayList<Object>(xs); }

    @Test void renderCondition() throws Exception { OracleCases.each(M, "renderCondition", a -> IntentRender.renderCondition(a.get(0))); }

    @Test void labelOf() throws Exception { OracleCases.each(M, "labelOf", a -> IntentRender.labelOf((String) a.get(0))); }

    @Test void renderCaveat() throws Exception { OracleCases.each(M, "renderCaveat", a -> IntentRender.renderCaveat(a.get(0))); }

    @Test void renderGrant() throws Exception { OracleCases.each(M, "renderGrant", a -> IntentRender.renderGrant(a.get(0))); }

    @Test void renderQuestion() throws Exception {
        OracleCases.each(M, "renderQuestion", a -> IntentRender.renderQuestion(IntentOmega.verbSpaceFromJson(a.get(0)), idx(a.get(1))));
    }

    @Test void renderAction() throws Exception {
        OracleCases.each(M, "renderAction", a -> {
            Map<String, Object> vals = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : IntentOmega.obj(a.get(1)).entrySet()) vals.put(e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
            return IntentRender.renderAction(IntentOmega.verbSpaceFromJson(a.get(0)), vals);
        });
    }

    @Test void claimsOf() throws Exception {
        OracleCases.each(M, "claimsOf", a -> {
            List<Object> out = new ArrayList<>();
            for (IntentRender.VerbClaim c : IntentRender.claimsOf(a.get(0), IntentOmega.omegaFromJson(a.get(1)))) out.add(c.toJson());
            return out;
        });
    }

    private static List<Object> diffs(List<IntentRender.ClaimDiff> ds) {
        List<Object> out = new ArrayList<>();
        for (IntentRender.ClaimDiff d : ds) out.add(d.toJson());
        return out;
    }

    @Test void backTranslationDiff() throws Exception {
        OracleCases.each(M, "backTranslationDiff", a -> diffs(IntentRender.backTranslationDiff(a.get(0), a.get(1), IntentOmega.omegaFromJson(a.get(2)))));
    }

    @Test void claimDiff() throws Exception {
        OracleCases.each(M, "claimDiff", a -> {
            IntentOmega.Omega om = IntentOmega.omegaFromJson(a.get(2));
            if (a.size() > 3) {
                List<?> names = (List<?>) a.get(3);
                return diffs(IntentRender.claimDiff(a.get(0), a.get(1), om, (String) names.get(0), (String) names.get(1)));
            }
            return diffs(IntentRender.claimDiff(a.get(0), a.get(1), om));
        });
    }

    @Test void boundaryWitnesses() throws Exception {
        OracleCases.each(M, "boundaryWitnesses", a -> {
            List<Object> out = new ArrayList<>();
            for (Witness w : IntentWitnesses.boundaryWitnesses(a.get(0), IntentOmega.omegaFromJson(a.get(1)))) out.add(w.toJson());
            return out;
        });
    }

    @SuppressWarnings("unchecked")
    private static Witness witnessFromJson(Object o) {
        Map<String, Object> m = (Map<String, Object>) o;
        return new Witness((String) m.get("kind"), (String) m.get("side"), (String) m.get("verb"), idx(m.get("cell")), IntentOmega.outcomeFromJson(m.get("outcome")),
            (Boolean) m.get("grantAllows"), (String) m.get("facet"), (String) m.get("question"));
    }

    @Test void checkWitnesses() throws Exception {
        OracleCases.each(M, "checkWitnesses", a -> {
            List<Witness> ws = new ArrayList<>();
            for (Object o : (List<?>) a.get(0)) ws.add(witnessFromJson(o));
            String mode = (String) a.get(1);
            Predicate<Witness> oracle = w -> switch (mode) {
                case "agree" -> w.grantAllows();
                case "flip" -> !w.grantAllows();
                case "flip-boundary" -> w.kind().equals("boundary") ? !w.grantAllows() : w.grantAllows();
                default -> w.side().equals("inside") && !w.kind().equals("unconstrained");
            };
            IntentWitnesses.WitnessCheck c = IntentWitnesses.checkWitnesses(ws, oracle);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("questions", c.questions());
            List<Object> bad = new ArrayList<>();
            for (Witness w : c.mismatches()) bad.add(w.toJson());
            out.put("mismatches", bad);
            return out;
        });
    }
}
