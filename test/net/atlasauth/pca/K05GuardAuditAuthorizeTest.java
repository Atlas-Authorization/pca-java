package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Guard-deletion audit (Authorize group): the restored explicit refusals, pinned to the reference's verdicts. */
public class K05GuardAuditAuthorizeTest {
    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    @Test
    void isAuthorizedForRefusesANullResult() {
        assertFalse(Authorize.isAuthorizedFor(null, Authorize.Operation.of("read", "doc:1", m())));
    }

    @Test
    void nonObjectAndNonArrayAgentCaveatsAreUnsatisfied() {
        Map<String, Object> ctx = m("now", 1L);
        Map<String, Object> actionCtx = m("action", m("verb", "read", "resource", "doc:1"));
        Caveats.Result r = Authorize.evaluateAgentCaveats(list("sealed"), ctx, actionCtx, null);
        assertFalse(r.ok);
        assertEquals(list("<malformed>"), r.failed);
        Caveats.Result p = Authorize.evaluateAgentCaveats(list(m("type", "predicates", "allow", "read")), ctx, actionCtx, null);
        assertFalse(p.ok);
        assertEquals(list("predicates"), p.failed);
    }

    @Test
    void aLeafWithoutACaveatListIsAMalformedChain() {
        assertNull(CaveatLang.boundCaveats(m("caveats", "x"), null));
        assertNull(CaveatLang.boundCaveats(m(), null));
    }

    @Test
    void aVerdictWithoutAChecksObjectDenies() {
        assertEquals(Decision.DENY, Decision.decisionOf(m("allow", false, "checks", "x")));
        assertEquals(Decision.DENY, Decision.decisionOf(m("allow", false)));
        assertEquals(Decision.DENY, Decision.decisionOf(m("allow", false, "checks", list("fail"))));
    }
}
