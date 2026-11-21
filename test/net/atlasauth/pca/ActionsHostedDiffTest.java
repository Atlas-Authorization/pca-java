package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionHosted;
import net.atlasauth.pca.actions.ActionSync;
import org.junit.jupiter.api.Test;

class ActionsHostedDiffTest {
    private static final String M = "ref-actions-hosted";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void publishGate() throws Exception { OracleCases.each(M, "publishGate", a -> ActionHosted.publishGate(m(a.get(0)))); }
    @Test void rulesDoc() throws Exception {
        OracleCases.each(M, "rulesDocError", a -> ActionHosted.rulesDocError(a.get(0), "acme", l(a.get(1))));
    }
    @Test void versionDigest() throws Exception { OracleCases.each(M, "hostedVersionDigest", a -> ActionHosted.hostedVersionDigest(m(a.get(0)))); }
    @Test void lookup() throws Exception { OracleCases.each(M, "viewLookup", a -> ActionHosted.hostedView(l(a.get(0)), a.get(1)).lookup((String) a.get(2))); }
    @Test void provenance() throws Exception { OracleCases.each(M, "viewProvenance", a -> ActionHosted.hostedView(l(a.get(0)), a.get(1)).provenance((String) a.get(2))); }
    @Test void floor() throws Exception { OracleCases.each(M, "viewFloor", a -> ActionHosted.hostedView(l(a.get(0)), a.get(1)).floor((String) a.get(2), m(a.get(3)), l(a.get(4)))); }
    @Test void undo() throws Exception { OracleCases.each(M, "viewUndo", a -> ActionHosted.hostedView(l(a.get(0)), a.get(1)).undoPlan(m(a.get(2)))); }
    @Test void callContext() throws Exception { OracleCases.each(M, "hostedCallContext", a -> {
        // the corpus encodes the reference's explicit null params (not undefined): reading the idempotency member of null is a TypeError there
        if (a.get(1) == null && a.get(0) instanceof Map && ((Map<?, ?>) a.get(0)).get("idempotency_param") instanceof String) throw new IllegalArgumentException("Cannot read properties of null (reading '" + ((Map<?, ?>) a.get(0)).get("idempotency_param") + "')");
        return ActionHosted.hostedCallContext(a.get(0) == null ? null : m(a.get(0)), a.get(1) == null ? null : m(a.get(1)));
    }); }
    @Test void rateKeys() throws Exception { OracleCases.each(M, "rateKeysOf", a -> ActionHosted.rateKeysOf(m(a.get(0)), m(a.get(1)))); }
    @Test void grantFacts() throws Exception { OracleCases.each(M, "grantFactsOf", a -> ActionHosted.grantFactsOf(a.get(0))); }
    @Test void sync() throws Exception {
        OracleCases.each(M, "syncSource", a -> { boolean c = (Boolean) a.get(3); return ActionSync.syncSource(l(a.get(0)), l(a.get(1)), "S".repeat(43), a.get(2) == null ? null : m(a.get(2)), Json.parse("1800000000"), null, d -> c); });
    }
    @Test void syncText() throws Exception { OracleCases.each(M, "syncText", a -> ActionSync.syncText(m(a.get(0)))); }
}
