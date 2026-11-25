package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionBusinessRules;
import org.junit.jupiter.api.Test;

class ActionsRulesDiffTest {
    private static final String M = "ref-actions-rules";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static Double num(Object o) { Double d = o instanceof Json.Num ? Double.valueOf(((Json.Num) o).raw) : null; return d; }
    private static Map<String, Object> mapOrThrow(Object o) { if (!(o instanceof Map)) throw new IllegalArgumentException("not an object"); return m(o); }

    @Test void businessRulesError() throws Exception { OracleCases.each(M, "businessRulesError", a -> ActionBusinessRules.businessRulesError(m(a.get(0)), a.get(1))); }
    @Test void compile() throws Exception { OracleCases.each(M, "compileBusinessRules", a -> ActionBusinessRules.compileBusinessRules(m(a.get(0)), mapOrThrow(a.get(1)))); }
    @Test void explain() throws Exception { OracleCases.each(M, "explainBusinessRules", a -> ActionBusinessRules.explainBusinessRules(m(a.get(0)), mapOrThrow(a.get(1)))); }
    @Test void lint() throws Exception { OracleCases.each(M, "lintBusinessRules", a -> ActionBusinessRules.lintBusinessRules(m(a.get(0)), a.get(1))); }
    @Test void examples() throws Exception { OracleCases.each(M, "runRuleExamples", a -> ActionBusinessRules.runRuleExamples(m(a.get(0)), mapOrThrow(a.get(1)))); }
    @Test void moneyOf() throws Exception { OracleCases.each(M, "moneyOf", a -> ActionBusinessRules.moneyOf(m(a.get(0)))); }
    @Test void digest() throws Exception { OracleCases.each(M, "businessRulesDigest", a -> ActionBusinessRules.businessRulesDigest((String) a.get(0), m(a.get(1)))); }
    @Test void diff() throws Exception {
        OracleCases.each(M, "diffBusinessRules", a -> ActionBusinessRules.diffBusinessRules(m(a.get(0)), a.get(1) == null ? null : mapOrThrow(a.get(1)), a.get(2) == null ? null : mapOrThrow(a.get(2))));
    }
    @Test void evaluate() throws Exception { OracleCases.each(M, "evaluateBusinessRules", a -> ActionBusinessRules.evaluateBusinessRules(m(a.get(0)), m(a.get(1)))); }
    @Test void clockAt() throws Exception {
        OracleCases.each(M, "clockAt", a -> { Double n = num(a.get(0)); return ActionBusinessRules.clockAt(n == null ? Double.NaN : n, (String) a.get(1)); });
    }
    @Test void formatMoney() throws Exception {
        OracleCases.each(M, "formatMoney", a -> ActionBusinessRules.formatMoney(num(a.get(0)).longValue(), (String) a.get(1), num(a.get(2)).intValue()));
    }
    @Test void minorUnits() throws Exception {
        OracleCases.each(M, "minorUnits", a -> ActionBusinessRules.minorUnits(a.get(0), num(a.get(1)).intValue(), "x"));
    }
    @Test void reviewMessage() throws Exception { OracleCases.each(M, "rulesReviewMessage", a -> ActionBusinessRules.rulesReviewMessage(m(a.get(0)))); }
    @Test void signReview() throws Exception {
        OracleCases.each(M, "signRulesReview", a -> ActionBusinessRules.signRulesReview(m(a.get(0)), Keys.unb64u((String) m(a.get(1)).get("$bytes"))));
    }
    @Test void reviewError() throws Exception {
        OracleCases.each(M, "rulesReviewError", a -> ActionBusinessRules.rulesReviewError(a.get(0), m(a.get(1)), m(a.get(2)), a.get(3)));
    }
}
