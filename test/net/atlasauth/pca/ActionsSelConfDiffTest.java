package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionConfirmation;
import net.atlasauth.pca.actions.ActionSelectors;
import org.junit.jupiter.api.Test;

class ActionsSelConfDiffTest {
    private static final String M = "ref-actions-sel-conf";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void selectorMatches() throws Exception { OracleCases.each(M, "selectorMatches", a -> ActionSelectors.selectorMatches(a.get(0), l(a.get(1)))); }
    @Test void selectorMatchesFor() throws Exception {
        OracleCases.each(M, "selectorMatchesFor", a -> ActionSelectors.selectorMatchesFor(a.get(0), (String) a.get(1), l(a.get(2)), (Boolean) a.get(3)));
    }
    @Test void selectorHasNot() throws Exception { OracleCases.each(M, "selectorHasNot", a -> ActionSelectors.selectorHasNot(a.get(0))); }
    @Test void allowSelectorError() throws Exception { OracleCases.each(M, "allowSelectorError", a -> ActionSelectors.allowSelectorError(a.get(0), (Boolean) a.get(1))); }
    @Test void policyDecision() throws Exception {
        OracleCases.each(M, "policyDecision", a -> ActionSelectors.policyDecision(m(a.get(0)), (String) a.get(1), l(a.get(2)), (Boolean) a.get(3)));
    }
    @Test void blankReason() throws Exception { OracleCases.each(M, "blankReason", a -> ActionConfirmation.blankReason((String) a.get(0))); }
    @Test void reviewMessage() throws Exception { OracleCases.each(M, "reviewMessage", a -> ActionConfirmation.reviewMessage(m(a.get(0)))); }
    @Test void signReview() throws Exception {
        OracleCases.each(M, "signReview", a -> ActionConfirmation.signReview(m(a.get(0)), Keys.unb64u((String) m(a.get(1)).get("$bytes"))));
    }
    @Test void verbConfirmationError() throws Exception {
        OracleCases.each(M, "verbConfirmationError", a -> ActionConfirmation.verbConfirmationError(m(a.get(0)),
            a.get(1) == null ? Actions.CORE_REGISTRY : Actions.extendRegistry(Actions.CORE_REGISTRY, l(a.get(1))),
            // a native null means no pins (undefined); the reference's explicit null is a pins value that is not an object
            a.get(2) == null ? new Object() : a.get(2)));
    }
}
