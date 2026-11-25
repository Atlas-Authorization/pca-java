package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The agent-facing half of approvals (review, goal lineage, batch review, time-boxing) against the reference. */
public class CoreApprovalsDiffTest {
    static final String MODULE = "ref-core-approvals-java";

    static byte[] seed(String label) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/approvals/" + label).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    static Keys.SuiteKey key(Object label) { return Keys.ed25519(Keys.edFromSeed(seed((String) label))); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static Facade.Handle build(Object specO) {
        Map<String, Object> s = m(specO);
        Facade.AgentOptions o = new Facade.AgentOptions(key(s.get("principal")), (String) s.get("goal"), m(s.get("permissions")))
            .holder(key(s.get("holder"))).goalSalt((String) s.get("goalSalt")).now((long) (double) StoreJs.dbl(s.get("now")));
        if (s.get("limits") != null) o.limits(m(s.get("limits")));
        if (s.get("riskPolicy") != null) o.riskPolicy(m(s.get("riskPolicy")));
        if (s.get("budgetModel") != null) o.budgetModel((String) s.get("budgetModel"));
        if (s.get("aud") != null) o.aud((String) s.get("aud"));
        return Agent.fromPrincipal(o);
    }

    static Approvals.Renderer renderer(String mode) {
        return (verb, resource, params) -> {
            if ("throw".equals(mode)) throw new IllegalStateException("boom");
            Map<String, Object> r = new LinkedHashMap<>();
            if ("badshape".equals(mode)) { r.put("v", StoreJs.num(2L)); return r; }
            r.put("v", StoreJs.num(1L));
            r.put("kind", "pca-approval-render");
            r.put("verb", verb);
            r.put("def_digest", "A".repeat(43));
            r.put("unreviewed", true);
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "resource");
            f.put("class", "param");
            f.put("value", resource);
            List<Object> fields = new ArrayList<>();
            fields.add(f);
            r.put("fields", fields);
            return r;
        };
    }

    static Approvals.ReviewOptions opts(Object o) {
        Map<String, Object> m = m(o);
        Approvals.ReviewOptions r = new Approvals.ReviewOptions();
        if (m == null) return r;
        if (m.get("now") != null) r.now = (long) (double) StoreJs.dbl(m.get("now"));
        if (m.get("goal") != null) r.goal = (String) m.get("goal");
        if (m.get("standing") != null) { r.standing = new ArrayList<>(); r.standing.addAll((List<?>) m.get("standing")); }
        if (m.get("renderer") != null) r.renderer = renderer((String) m.get("renderer"));
        r.insecureUnboundApproval = Boolean.TRUE.equals(m.get("insecure"));
        return r;
    }

    @Test void reviewAction() throws Exception {
        OracleCases.each(MODULE, "reviewAction", a -> Approvals.reviewAction(build(a.get(0)), (String) a.get(1), (String) a.get(2), m(a.get(3)), opts(a.get(4))));
    }

    @Test void buildGoalLineage() throws Exception {
        OracleCases.each(MODULE, "buildGoalLineage", a -> {
            Map<String, Object> op = m(a.get(4));
            return Approvals.buildGoalLineage(build(a.get(0)), (String) a.get(1), (String) a.get(2), m(a.get(3)), op == null ? null : (String) op.get("goal"));
        });
    }

    @Test void describeGoalLineage() throws Exception {
        OracleCases.each(MODULE, "describeGoalLineage", a -> Approvals.describeGoalLineage(m(a.get(0))));
    }

    @Test void batchReview() throws Exception {
        OracleCases.each(MODULE, "batchReview", a -> {
            List<Map<String, Object>> calls = new ArrayList<>();
            for (Object c : (List<?>) a.get(1)) calls.add(m(c));
            return Approvals.batchReview(build(a.get(0)), calls, opts(a.get(2)));
        });
    }

    @Test void timeBox() throws Exception {
        OracleCases.each(MODULE, "timeBox", a -> Approvals.timeBox(m(a.get(0)), key(a.get(1)), StoreJs.dbl(a.get(2)), StoreJs.dbl(a.get(3))));
    }

    @Test void auditedAgentWithoutRendererIsDenied() {
        Map<String, Object> perms = new LinkedHashMap<>();
        List<Object> acts = new ArrayList<>();
        acts.add("payout");
        perms.put("stripe", acts);
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("payout", "$100");
        Map<String, Object> rp = new LinkedHashMap<>();
        rp.put("theta1", new Json.Num("0.3"));
        rp.put("theta2", new Json.Num("0.6"));
        Facade.Handle h = Agent.fromPrincipal(new Facade.AgentOptions(key("p"), "g", perms).limits(limits).riskPolicy(rp).now(0));
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("amount", new Json.Num("80"));
        Approvals.ReviewOptions o = new Approvals.ReviewOptions();
        o.now = 1L;
        assertEquals("deny", Approvals.reviewAction(h, "stripe.payout", "acct:1", params, o).get("kind"));
        o.insecureUnboundApproval = true;
        assertTrue("step_up".equals(Approvals.reviewAction(h, "stripe.payout", "acct:1", params, o).get("kind")));
    }
}
