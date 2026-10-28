package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Assurance labels (T8, B7): the shared assurance vectors (signature_level, report, requirement, multi_root), each compared
 * exactly, and the {@code requireAssurance} gate of {@code Authorize}. A missing vector file or a table of the wrong size FAILS.
 */
public class AssuranceVectorsTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> table(Map<String, Object> doc, String name, int size) {
        Object t = doc.get(name);
        assertTrue(t instanceof List, name + ": missing table");
        assertEquals(size, ((List<?>) t).size(), name + ": vector count");
        return (List<Map<String, Object>>) (List<?>) t;
    }

    /** The hook an input describes: a labelled object, an unlabelled one ("unlabelled"), or none (null). */
    static Object hookOf(Object spec) {
        if (spec == null) return null;
        Object hook = new Object();
        if (spec instanceof Map) {
            Map<String, Object> l = m(spec);
            Assurance.setLabel(hook, new Assurance.Label((String) l.get("level"), (String) l.get("vendor"), Boolean.TRUE.equals(l.get("preview")), (String) l.get("ceremony")));
        }
        return hook;
    }

    @Test void signatureLevels() {
        Map<String, Object> doc = Track3Vectors.load("assurance-vectors.json");
        for (Map<String, Object> v : table(doc, "signature_level", 14)) assertEquals(v.get("level"), Assurance.signatureLevel(v.get("alg")), String.valueOf(v.get("alg")));
    }

    @Test void reports() {
        Map<String, Object> doc = Track3Vectors.load("assurance-vectors.json");
        for (Map<String, Object> v : table(doc, "report", 37)) {
            Assurance.Sources src = new Assurance.Sources();
            Map<String, Object> checks = m(v.get("checks"));
            for (Map.Entry<String, Object> e : checks.entrySet()) src.checks.put(e.getKey(), (String) e.getValue());
            src.pcactn = v.get("pcactn") == null ? null : m(v.get("pcactn"));
            Map<String, Object> hooks = v.get("hooks") == null ? new LinkedHashMap<>() : m(v.get("hooks"));
            src.attestationHook = hookOf(hooks.get("attestation"));
            src.zkHook = hookOf(hooks.get("zk"));
            src.thresholdHook = hookOf(hooks.get("threshold"));
            src.revocationHook = hookOf(hooks.get("revocation"));
            if (v.containsKey("attestation_hook")) src.usedAttestationHook = hookOf(v.get("attestation_hook"));
            if (v.containsKey("threshold_t")) src.thresholdT = v.get("threshold_t");
            src.allowUnboundPq = Boolean.TRUE.equals(v.get("allow_unbound_pq"));
            if (v.get("degraded") != null) {
                src.degraded = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : m(v.get("degraded")).entrySet()) src.degraded.put(e.getKey(), (String) e.getValue());
            }
            assertEquals(Json.canonicalize(v.get("report")), Json.canonicalize(Assurance.report(src)), (String) v.get("name"));
        }
    }

    @Test void requirements() {
        Map<String, Object> doc = Track3Vectors.load("assurance-vectors.json");
        for (Map<String, Object> v : table(doc, "requirement", 44)) {
            String got = Assurance.unmet(m(v.get("report")), Assurance.Requirement.fromJson(v.get("require")));
            assertEquals(v.get("unmet"), got, (String) v.get("name"));
        }
    }

    @Test void multiRoot() {
        Map<String, Object> doc = Track3Vectors.load("assurance-vectors.json");
        for (Map<String, Object> v : table(doc, "multi_root", 10)) {
            List<Assurance.Root> roots = new ArrayList<>();
            for (Object o : (List<?>) v.get("roots")) {
                Map<String, Object> r = m(o);
                roots.add(new Assurance.Root(Assurance.setLabel(new Object(), Assurance.Label.of((String) r.get("level"))), Boolean.TRUE.equals(r.get("required"))));
            }
            assertEquals(v.get("level"), Assurance.multiRootLevel(roots, IntentJs.num(v.get("threshold"))), (String) v.get("name"));
        }
    }

    // ---- labels and the requirement ------------------------------------------------------------------------------------

    static final class Hw implements Assurance.Labelled {
        public Assurance.Label assuranceLabel() { return Assurance.Label.of("hardware").vendor("amd-sev-snp"); }
    }

    @Test void labelsComeFromTheVerifierNotTheEvidence() {
        assertEquals("hardware", Assurance.labelOf(new Hw()).level);
        Object lambda = (Runnable) () -> { };
        assertNull(Assurance.labelOf(lambda), "an unlabelled hook is unknown");
        assertSame(lambda, Assurance.setLabel(lambda, Assurance.Label.of("software")));
        assertEquals("software", Assurance.labelOf(lambda).level);
        Assurance.Sources s = new Assurance.Sources();
        s.checks.put("attestation", "pass");
        s.attestationHook = new Hw();
        Map<String, Object> e = m(Assurance.report(s).get("attestation"));
        assertEquals("hardware", e.get("level"));
        assertEquals("amd-sev-snp", e.get("vendor"));
    }

    @Test void anUnknownRequirementIsRefused() {
        Map<String, Object> report = new LinkedHashMap<>();
        assertEquals("assurance: unknown assurance requirement(s): bogus, zzz (fail closed)",
            Assurance.unmet(report, Assurance.Requirement.fromJson(Json.parseLenient("{\"zzz\":1,\"bogus\":true}"))));
        assertEquals("assurance: unknown assurance requirement(s): invalid (fail closed)", Assurance.unmet(report, Assurance.Requirement.fromJson(null)));
        assertEquals("assurance: unknown attestation requirement 'platinum' (fail closed)", Assurance.unmet(report, new Assurance.Requirement().attestation("platinum")));
        assertEquals("assurance: unknown zk requirement 'x' (fail closed)", Assurance.unmet(report, new Assurance.Requirement().zk("x")));
        assertEquals("assurance: unknown signature requirement 'ed25519' (fail closed)", Assurance.unmet(report, new Assurance.Requirement().signature("ed25519")));
        assertNull(Assurance.unmet(report, new Assurance.Requirement()));
    }

    // ---- Authorize -----------------------------------------------------------------------------------------------------

    @Test void authorizeGatesBeforeAnyReplayStateIsWritten() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Object p = AuthorizeFixtures.pcactn(c, 0);
        StateStore store = new MemoryStateStore();

        Authorize.AuthorizeResult weak = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).stateStore(store).requireAssurance(Assurance.Requirement.pq()));
        assertFalse(weak.allow);
        assertEquals(403, weak.status);
        assertEquals("fail", weak.checks.get("assurance"));
        assertEquals("assurance: post-quantum signatures required but leaf_signature is ed25519", weak.reason);
        assertEquals("ed25519", m(weak.assurance().get("leaf_signature")).get("level"));
        assertEquals("fail", m(weak.assurance().get("assurance")).get("outcome"));

        // the refusal consumed nothing: the same proof still authorizes once the requirement is gone
        Authorize.AuthorizeResult met = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).stateStore(store).requireAssurance(new Assurance.Requirement()));
        assertTrue(met.allow, met.reasons.toString());
        assertEquals("pass", met.checks.get("assurance"));
        assertEquals("pass", m(met.assurance().get("assurance")).get("outcome"));

        // a result of a refusal before verification still carries a report
        Authorize.AuthorizeResult none = Authorize.authorize(p, new Authorize.Input());
        assertEquals("fail", m(none.assurance().get("authorize_config")).get("outcome"));
    }

    @Test void authorizeReportsWhatItCannotVerify() {
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("attestation", "fail");
        checks.put("replay", "pass");
        Map<String, Object> pcactn = new LinkedHashMap<>();
        pcactn.put("bond_ref", "b");
        Map<String, Object> report = Authorize.assuranceOf(checks, pcactn, null);
        assertEquals("unsupported", m(report.get("attestation")).get("outcome"));
        assertEquals("unsupported", m(report.get("bond")).get("outcome"));
        assertEquals("assurance: unsupported: attestation (attestation is not implemented by this verifier); a high-assurance policy never accepts it",
            Assurance.unmet(report, new Assurance.Requirement()));
        // a legacy-polarity admission is degraded and refused by any requirement
        Map<String, Object> degraded = Authorize.assuranceOf(Map.of("replay", "pass"), null, Map.of("tighten", Authorize.DEGRADED_LEGACY_POLARITY));
        assertEquals(Boolean.TRUE, m(degraded.get("tighten")).get("degraded"));
        assertTrue(Assurance.unmet(degraded, new Assurance.Requirement()).startsWith("assurance: tighten rests on a degraded compatibility mode"));
    }
}
