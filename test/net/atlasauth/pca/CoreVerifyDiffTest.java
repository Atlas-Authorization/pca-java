package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Replays the reference vectors of the core verify entry through {@link PcaCore#verify}. */
public class CoreVerifyDiffTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static PcaCore.Hook hook(Object d) {
        Map<String, Object> h = m(d);
        PcaCore.HookResult r = Boolean.TRUE.equals(h.get("enforced"))
            ? PcaCore.HookResult.enforced(Boolean.TRUE.equals(h.get("ok")), (String) h.get("reason"), h.containsKey("t") ? IntentJs.num(h.get("t")) : null)
            : PcaCore.HookResult.notEnforced();
        return ctx -> r;
    }

    @SuppressWarnings("unchecked")
    static PcaCore.Options options(Map<String, Object> j) {
        PcaCore.Options o = new PcaCore.Options(m(j.get("grant")));
        o.grantFromArtifact = Boolean.TRUE.equals(j.get("grantFromArtifact"));
        if (j.containsKey("nowEpoch")) o.nowEpoch = IntentJs.num(j.get("nowEpoch")).longValue();
        if (j.containsKey("pqPins")) o.pqPins = m(j.get("pqPins"));
        if (j.containsKey("allowedSuites")) o.allowedSuites = (List<String>) (List<?>) j.get("allowedSuites");
        if (j.containsKey("audience")) { if (j.get("audience") == null) o.audienceAny(); else o.audience((String) j.get("audience")); }
        List<String> roots = j.containsKey("authorizedPlanRoots") ? (List<String>) (List<?>) j.get("authorizedPlanRoots") : null;
        o.planRoots = Pca.PlanRoots.of(roots, Boolean.TRUE.equals(j.get("insecureSkipPlanRootCheck")));
        if (j.containsKey("hooks")) {
            PcaCore.Hooks h = new PcaCore.Hooks();
            Map<String, Object> hm = m(j.get("hooks"));
            if (hm.containsKey("attestation")) h.attestation = hook(hm.get("attestation"));
            if (hm.containsKey("threshold")) h.threshold = hook(hm.get("threshold"));
            if (hm.containsKey("revocation")) h.revocation = hook(hm.get("revocation"));
            if (hm.containsKey("zk")) h.zk = hook(hm.get("zk"));
            o.hooks = h;
        }
        if (j.containsKey("enforce")) {
            PcaCore.Enforce e = new PcaCore.Enforce();
            Map<String, Object> em = m(j.get("enforce"));
            if (em.containsKey("freshness")) {
                Map<String, Object> f = m(em.get("freshness"));
                PcaCore.Freshness fr = new PcaCore.Freshness(IntentJs.num(f.get("maxAgeMs")));
                if (f.containsKey("epochMs")) fr.epochMs = IntentJs.num(f.get("epochMs"));
                if (f.containsKey("clockSkewMs")) fr.clockSkewMs = IntentJs.num(f.get("clockSkewMs"));
                if (f.containsKey("now")) fr.now = IntentJs.num(f.get("now")).longValue();
                e.freshness = fr;
            }
            if (em.containsKey("attestation")) {
                Map<String, Object> a = m(em.get("attestation"));
                PcaCore.AttestationGate g = new PcaCore.AttestationGate(hook(a.get("verifier")));
                if (a.containsKey("required")) g.required = Boolean.TRUE.equals(a.get("required"));
                e.attestation = g;
            }
            o.enforce = e;
        }
        o.assurance = Boolean.TRUE.equals(j.get("assurance"));
        if (j.containsKey("requireAssurance")) o.requireAssurance = Assurance.Requirement.fromJson(j.get("requireAssurance"));
        if (j.containsKey("intent")) o.intentPolicy = Pca.IntentPolicy.fromJson(j.get("intent"));
        return o;
    }

    static Map<String, Object> out(PcaCore.Result r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allow", r.allow);
        m.put("checks", new LinkedHashMap<String, Object>(r.checks));
        if (r.reason != null) m.put("reason", r.reason);
        if (r.assurance != null) m.put("assurance", r.assurance);
        return m;
    }

    @Test void verifyCore() throws Exception {
        OracleCases.each("ref-core-verify-java", "verifyCore", a -> out(PcaCore.verify(a.get(0), options(m(a.get(1))))));
    }

    /** The reference reports checks in a fixed order; the JSON comparison ignores member order, so pin it here. */
    @Test void checkOrderIsNormative() throws Exception {
        for (Map<String, Object> c : OracleCases.of("ref-core-verify-java", "verifyCore")) {
            Map<String, Object> want = m(m(c.get("out")).get("checks"));
            List<?> a = (List<?>) c.get("args");
            PcaCore.Result r = PcaCore.verify(a.get(0), options(m(a.get(1))));
            assertEquals(new ArrayList<>(want.keySet()), new ArrayList<>(r.checks.keySet()), String.valueOf(c.get("name")));
        }
    }
}
