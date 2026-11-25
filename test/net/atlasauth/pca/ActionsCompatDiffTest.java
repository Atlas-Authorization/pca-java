package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionCompat;
import org.junit.jupiter.api.Test;

class ActionsCompatDiffTest {
    private static final String M = "ref-actions-compat";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void normalizeReversibility() throws Exception { OracleCases.each(M, "normalizeReversibility", a -> ActionCompat.normalizeReversibility(a.get(0))); }
    @Test void legacyOperationsClass() throws Exception { OracleCases.each(M, "legacyOperationsClass", a -> ActionCompat.legacyOperationsClass((String) a.get(0))); }
    @Test void maxRevOf() throws Exception { OracleCases.each(M, "maxRevOf", a -> ActionCompat.maxRevOf((String) a.get(0), (String) a.get(1))); }
    @Test void unitTagOf() throws Exception { OracleCases.each(M, "unitTagOf", a -> ActionCompat.unitTagOf(m(a.get(0)))); }
    @Test void blastOfFloat() throws Exception { OracleCases.each(M, "blastOfFloat", a -> ActionCompat.blastOfFloat(OracleCases.num(a.get(0)))); }
    @Test void blastExactOfFloat() throws Exception { OracleCases.each(M, "blastExactOfFloat", a -> ActionCompat.blastExactOfFloat(OracleCases.num(a.get(0)))); }
    @Test void fromCatalogSpec() throws Exception { OracleCases.each(M, "fromCatalogSpec", a -> ActionCompat.fromCatalogSpec(m(a.get(0)), a.size() > 1 ? m(a.get(1)) : null)); }
    @Test void fromCatalog() throws Exception { OracleCases.each(M, "fromCatalog", a -> ActionCompat.fromCatalog(l(a.get(0)), a.size() > 1 ? m(a.get(1)) : null)); }
}
