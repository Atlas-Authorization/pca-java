package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ap2.Ap2;
import org.junit.jupiter.api.Test;

/** Replays the reference vectors of the AP2 PCA binding verification through {@link Ap2#verifyPcaBinding}. */
public class Ap2BindingDiffTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static Ap2.VerifyPcaBindingInput input(Map<String, Object> j) {
        Ap2.VerifyPcaBindingInput i = new Ap2.VerifyPcaBindingInput();
        i.open = m(j.get("open"));
        i.closed = m(j.get("closed"));
        i.openHash = (String) j.get("openHash");
        i.expectedPrincipal = (String) j.get("expectedPrincipal");
        if (j.get("pqPins") instanceof Map) i.pqPins = m(j.get("pqPins"));
        i.audience = (String) j.get("audience");
        if (j.get("now") != null) i.now = IntentJs.num(j.get("now")).longValue();
        if (j.get("mandate") instanceof Map) i.mandate = m(j.get("mandate"));
        if (j.get("recentChargeTimes") instanceof List) i.recentChargeTimes = (List<Object>) j.get("recentChargeTimes");
        if (j.containsKey("hooks")) {
            i.hooks = new PcaCore.Hooks();
            Map<String, Object> h = m(j.get("hooks"));
            if (h.containsKey("threshold")) i.hooks.threshold = hook(h.get("threshold"));
            if (h.containsKey("attestation")) i.hooks.attestation = hook(h.get("attestation"));
            if (h.containsKey("revocation")) i.hooks.revocation = hook(h.get("revocation"));
            if (h.containsKey("zk")) i.hooks.zk = hook(h.get("zk"));
        }
        if (j.containsKey("enforce")) {
            i.enforce = new PcaCore.Enforce();
            Map<String, Object> f = m(m(j.get("enforce")).get("freshness"));
            i.enforce.freshness = new PcaCore.Freshness(IntentJs.num(f.get("maxAgeMs")));
        }
        return i;
    }

    private static PcaCore.Hook hook(Object d) {
        Map<String, Object> h = m(d);
        PcaCore.HookResult r = Boolean.TRUE.equals(h.get("enforced"))
            ? PcaCore.HookResult.enforced(Boolean.TRUE.equals(h.get("ok")), (String) h.get("reason"), h.containsKey("t") ? IntentJs.num(h.get("t")) : null)
            : PcaCore.HookResult.notEnforced();
        return ctx -> r;
    }

    @Test void verifyPcaBinding() throws Exception {
        OracleCases.each("ref-ap2-java-extra", "verifyPcaBinding", a -> Ap2.verifyPcaBinding(input(m(a.get(0)))));
    }
}
