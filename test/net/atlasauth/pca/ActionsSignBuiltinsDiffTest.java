package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionBuiltin;
import org.junit.jupiter.api.Test;

/** signBuiltins replayed against the reference: the same defs, attestations and refusals for a seed label's reviewer key. */
class ActionsSignBuiltinsDiffTest {
    @SuppressWarnings("unchecked")
    @Test void signBuiltins() throws Exception {
        OracleCases.each("ref-actions-signbuiltins", "signBuiltins", a -> {
            Map<String, Object> c = (Map<String, Object>) a.get(0);
            byte[] seed = MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + c.get("seed")).getBytes(StandardCharsets.UTF_8));
            return ActionBuiltin.signBuiltins(Actions.CORE_REGISTRY, (String) c.get("kid"), seed, c.get("ts"), (List<Object>) c.get("defs"));
        });
    }
}
