package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionLint;
import net.atlasauth.pca.actions.ActionUndo;
import net.atlasauth.pca.policyci.ActionLintRules;
import org.junit.jupiter.api.Test;

class ActionsLintDiffTest {
    private static final String M = "ref-actions-lint";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void lintDefs() throws Exception {
        OracleCases.each(M, "lintDefs", a -> {
            Map<String, Object> opts = a.size() > 1 && a.get(1) != null ? m(a.get(1)) : null;
            Object att = opts == null ? null : opts.get("att");
            return ActionLint.lintDefs(l(a.get(0)), opts, att == null ? null : d -> (Boolean) att);
        });
    }
    @Test void lintRulesDigest() throws Exception { OracleCases.each(M, "lintRulesDigest", a -> ActionLint.lintRulesDigest()); }
    @Test void lintRules() throws Exception {
        OracleCases.each(M, "LINT_RULES", a -> { List<Object> out = new ArrayList<>(); for (String[] r : ActionLintRules.LINT_RULES) out.add(new ArrayList<Object>(List.of(r))); return out; });
    }
    @Test void lintFails() throws Exception { OracleCases.each(M, "lintFails", a -> ActionLint.lintFails(l(a.get(0)), (Boolean) a.get(1))); }
    @Test void lintText() throws Exception { OracleCases.each(M, "lintText", a -> ActionLint.lintText(l(a.get(0)))); }
    @Test void toSarif() throws Exception { OracleCases.each(M, "toSarif", a -> ActionLint.toSarif(l(a.get(0)), a.size() > 1 ? m(a.get(1)) : null)); }
    @Test void reversibilityFor() throws Exception { OracleCases.each(M, "reversibilityFor", a -> ActionUndo.reversibilityFor(m(a.get(0)), m(a.get(1)))); }
    @Test void mayBeReversible() throws Exception { OracleCases.each(M, "mayBeReversible", a -> ActionUndo.mayBeReversible(m(a.get(0)))); }
    @Test void compensationShape() throws Exception { OracleCases.each(M, "compensationShape", a -> ActionUndo.compensationShape(m(a.get(0)), m(a.get(1)))); }
}
