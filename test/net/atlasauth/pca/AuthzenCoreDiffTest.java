package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.authzen.Authzen;
import org.junit.jupiter.api.Test;

/** AuthZEN permit paths: a real grant and signed PCActn, the default Policy-VM decision and the analyzer's static admission. */
class AuthzenCoreDiffTest {
    private static final long NOW = 1_800_000_000_000L;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Authzen.AuthzenPdp pdp(Map<String, Object> d) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("now", (LongSupplier) () -> NOW);
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("grant", d.get("grant"));
        ctx.put("policy", d.get("policy") != null ? d.get("policy") : new LinkedHashMap<String, Object>(Map.of("predicates", List.of(), "caveats", List.of())));
        for (String k : new String[] {"budget", "risk", "plan"}) if (d.get(k) != null) ctx.put(k, d.get(k));
        c.put("resolve", (Authzen.Resolver) r -> ctx);
        if (d.containsKey("audience")) c.put("audience", d.get("audience"));
        if (d.containsKey("insecureSkipPlanRootCheck")) c.put("insecureSkipPlanRootCheck", d.get("insecureSkipPlanRootCheck"));
        if (d.containsKey("authorizedPlanRoots")) c.put("authorizedPlanRoots", d.get("authorizedPlanRoots"));
        if (Boolean.TRUE.equals(d.get("authorizer"))) c.put("authorizer", (Authzen.Authorizer) in -> new LinkedHashMap<String, Object>(Map.of("allow", Boolean.TRUE)));
        if (d.containsKey("requireAuthorizer")) c.put("requireAuthorizer", d.get("requireAuthorizer"));
        if (d.containsKey("requireProof")) c.put("requireProof", d.get("requireProof"));
        return Authzen.authzenPdp(c);
    }

    @Test void evaluate() throws Exception {
        OracleCases.each("ref-authzen-java-extra", "evaluate", a -> pdp(m(a.get(0))).evaluate(a.get(1)));
    }
}
