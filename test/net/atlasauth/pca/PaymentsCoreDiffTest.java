package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.payments.Payments;
import org.junit.jupiter.api.Test;

/** Replays the reference vectors of the payments pieces that sit on the core decision and the optimistic path. */
public class PaymentsCoreDiffTest {
    private static final String M = "ref-payments-java-extra";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void authorizeChargeCore() throws Exception {
        OracleCases.each(M, "authorizeChargeCore", a -> Payments.authorizeCharge(m(a.get(0)), m(a.get(1)), a.get(2)));
    }

    @Test void openChargeBond() throws Exception {
        OracleCases.each(M, "openChargeBond", a -> {
            Map<String, Object> o = m(a.get(1));
            Optimistic.OpenOptions op = new Optimistic.OpenOptions((String) o.get("bondRef"), IntentJs.num(o.get("claimedR")));
            if (o.containsKey("challengeWindowMs")) op.challengeWindowMs = IntentJs.num(o.get("challengeWindowMs"));
            if (o.containsKey("issuedAt")) op.issuedAt = IntentJs.num(o.get("issuedAt"));
            if (o.containsKey("serverNow")) op.serverNow = IntentJs.num(o.get("serverNow"));
            return Payments.openChargeBond(m(a.get(0)), op, Keys.edFromSeed(Keys.unb64u((String) a.get(2))));
        });
    }
}
