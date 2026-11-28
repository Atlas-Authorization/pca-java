package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentStatement;
import org.junit.jupiter.api.Test;

class IntentStatementDiffTest {
    private static final String M = "ref-intent-statement";

    @Test void signIntent() throws Exception {
        OracleCases.each(M, "signIntent", a -> IntentStatement.signIntent(IntentOmega.obj(a.get(0)), Keys.unb64u((String) a.get(1))));
    }

    @Test void verifyIntent() throws Exception {
        OracleCases.each(M, "verifyIntent", a -> {
            Map<String, Object> opts = IntentOmega.obj(a.get(1));
            Map<String, Object> pins = opts.get("pqPins") == null ? null : IntentOmega.obj(opts.get("pqPins"));
            return IntentStatement.verifyIntent(a.get(0), (String) opts.get("expectedSigner"), pins);
        });
    }

    @Test void intentRef() throws Exception { OracleCases.each(M, "intentRef", a -> IntentStatement.intentRef(a.get(0))); }

    @Test void intentGoal() throws Exception {
        OracleCases.each(M, "intentGoal", a -> IntentStatement.intentGoal((String) a.get(0), a.size() > 1 ? (String) a.get(1) : null));
    }

    @Test void parseIntentGoal() throws Exception { OracleCases.each(M, "parseIntentGoal", a -> IntentStatement.parseIntentGoal(a.get(0))); }
}
