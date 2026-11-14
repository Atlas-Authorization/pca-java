package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Risk context for tests whose grant carries the default risk policy: the server prices the operation at zero risk (every input at its best),
 * so the decision is made on predicates and caveats alone. The risk step itself is covered by {@code RiskTest}; a missing input is priced at
 * its worst case there, never here.
 */
public final class RiskCtx {
    private RiskCtx() {}

    public static Map<String, Object> zero() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("semanticDistance", 0L);
        r.put("reversibility", 1L);
        r.put("blastRadius", 0L);
        r.put("taint", 0L);
        r.put("confidence", 1L);
        r.put("age", 0L);
        return r;
    }

    public static final Authorize.RiskSource ZERO = (operation, grant, pcactn) -> zero();
}
