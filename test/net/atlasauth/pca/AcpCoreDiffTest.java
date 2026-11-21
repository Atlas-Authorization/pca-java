package net.atlasauth.pca;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.acp.Acp;
import org.junit.jupiter.api.Test;

/** ACP token verification with a real grant and a real signed PCActn: the core re-verification, including the audience opt-out. */
public class AcpCoreDiffTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void verifyDelegatedPaymentToken() throws Exception {
        OracleCases.each("ref-acp-java-extra", "verifyDelegatedPaymentToken", a -> {
            Map<String, Object> o2 = new LinkedHashMap<>(m(a.get(1)));
            if ("once".equals(o2.get("singleUse"))) {
                HashSet<String> seen = new HashSet<>();
                o2.put("singleUse", (Acp.SingleUseStore) (jti, exp) -> seen.add(jti));
            }
            Map<String, Object> r = new LinkedHashMap<>(Acp.verifyDelegatedPaymentToken(a.get(0), o2));
            if (r.get("reason") instanceof String)
                r.put("reason", ((String) r.get("reason")).replaceAll("(?s)^(token signature did not verify|bound proof failed to verify): .*$", "$1"));
            if (r.get("pcaResult") instanceof Map) {
                Map<String, Object> pr = new LinkedHashMap<>();
                pr.put("allow", m(r.get("pcaResult")).get("allow"));
                r.put("pcaResult", pr);
            }
            return r;
        });
    }
}
