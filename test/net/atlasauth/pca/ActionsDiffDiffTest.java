package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionDefDiff;
import net.atlasauth.pca.actions.ActionDiff;
import net.atlasauth.pca.actions.ActionEffective;
import net.atlasauth.pca.actions.ActionIdPattern;
import org.junit.jupiter.api.Test;

class ActionsDiffDiffTest {
    private static final String M = "ref-actions-diff";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void idMatches() throws Exception { OracleCases.each(M, "idMatches", a -> ActionIdPattern.idMatches(a.get(0), (String) a.get(1))); }
    @Test void idPatternContains() throws Exception { OracleCases.each(M, "idPatternContains", a -> ActionIdPattern.idPatternContains(a.get(0), a.get(1))); }
    @Test void join() throws Exception { OracleCases.each(M, "join", a -> ActionEffective.join(m(a.get(0)), m(a.get(1)))); }
    @Test void leq() throws Exception { OracleCases.each(M, "leq", a -> ActionEffective.leq(m(a.get(0)), m(a.get(1)))); }
    @Test void profileEq() throws Exception { OracleCases.each(M, "profileEq", a -> ActionEffective.profileEq(m(a.get(0)), m(a.get(1)))); }
    @Test void effective() throws Exception {
        OracleCases.each(M, "effective", a -> { boolean c = (Boolean) a.get(1); return ActionEffective.effective(m(a.get(0)), CORE, d -> c); });
    }
    @Test void hintTraits() throws Exception { OracleCases.each(M, "hintTraits", a -> ActionEffective.hintTraits(m(a.get(0)))); }
    @Test void prulesViolations() throws Exception { OracleCases.each(M, "prulesViolations", a -> ActionEffective.prulesViolations(m(a.get(0)))); }
    @Test void effWithTrait() throws Exception { OracleCases.each(M, "effWithTrait", a -> ActionEffective.effWithTrait(m(a.get(0)), (String) a.get(1), CORE)); }
    @Test void requiredPrulesViolated() throws Exception { OracleCases.each(M, "requiredPrulesViolated", a -> ActionEffective.requiredPrulesViolated(m(a.get(0)), m(a.get(1)))); }
    @Test void diffDefs() throws Exception {
        OracleCases.each(M, "diffDefs", a -> { boolean c = a.size() > 2 && Boolean.TRUE.equals(a.get(2)); return ActionDiff.diffDefs(m(a.get(0)), m(a.get(1)), CORE, d -> c); });
    }
    @Test void diffIsFree() throws Exception { OracleCases.each(M, "diffIsFree", a -> ActionDiff.diffIsFree((String) a.get(0))); }
    @Test void diffDefsAuthoring() throws Exception { OracleCases.each(M, "diffDefsAuthoring", a -> ActionDefDiff.diffDefs(m(a.get(0)), m(a.get(1)), CORE)); }
    @Test void diffPacks() throws Exception { OracleCases.each(M, "diffPacks", a -> ActionDefDiff.diffPacks(l(a.get(0)), l(a.get(1)), CORE)); }

    /** Key order is not meaning: the same def with the members of a unit, a default and the bindings written in reverse order diffs as equal. */
    @Test void keyOrderIsNotMeaning() throws Exception {
        java.util.Map<String, Object> a = new java.util.LinkedHashMap<>(), b = new java.util.LinkedHashMap<>();
        a.put("kind", "money"); a.put("currency", "EUR"); a.put("nested", new java.util.LinkedHashMap<>(java.util.Map.of("x", 1)));
        b.put("nested", new java.util.LinkedHashMap<>(java.util.Map.of("x", 1))); b.put("currency", "EUR"); b.put("kind", "money");
        java.util.Map<String, Object> p1 = new java.util.LinkedHashMap<>(), p2 = new java.util.LinkedHashMap<>();
        p1.put("type", "int"); p1.put("unit", a);
        p2.put("unit", b); p2.put("type", "int");
        java.util.Map<String, Object> d1 = m(l(java.util.List.of(
            new java.util.LinkedHashMap<String, Object>(java.util.Map.of("v", 1, "kind", "pca-action-def", "verb", "acme.pay", "title", "t", "description", "d",
                "effects", java.util.List.of("read"), "resource", new java.util.LinkedHashMap<String, Object>(java.util.Map.of("type", "acme.x", "id", "*", "scope", "tenant")),
                "params", new java.util.LinkedHashMap<String, Object>(java.util.Map.of("n", p1)))))).get(0));
        java.util.Map<String, Object> d2 = new java.util.LinkedHashMap<>(d1);
        d2.put("params", new java.util.LinkedHashMap<String, Object>(java.util.Map.of("n", p2)));
        org.junit.jupiter.api.Assertions.assertFalse(String.valueOf(ActionDefDiff.diffDefs(d1, d2, CORE)).contains("unit changed"));
        // a real change in a unit still shows
        b.put("currency", "USD");
        org.junit.jupiter.api.Assertions.assertTrue(String.valueOf(ActionDefDiff.diffDefs(d1, d2, CORE)).contains("unit changed"));
    }
}
