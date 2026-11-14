package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Assurance member by member: labels and their attachment, the multi-root level, signature levels, whole reports for every
 * check kind (hooks, suites, threshold t, degraded, bond), the requirement read from JSON, and every reason {@code unmet} gives.
 */
public class AssuranceKillTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static String canon(Object v) { return Json.canonicalize(v); }

    static Object hook(String level) { return Assurance.setLabel(new Object(), Assurance.Label.of(level)); }

    static Assurance.Sources src(Object... checks) {
        Assurance.Sources s = new Assurance.Sources();
        for (int i = 0; i < checks.length; i += 2) s.checks.put((String) checks[i], (String) checks[i + 1]);
        return s;
    }

    static void assertReport(Map<String, Object> want, Assurance.Sources s) { assertEquals(canon(want), canon(Assurance.report(s))); }

    // ---- labels ----------------------------------------------------------------------------------------------------

    @Test void labels() {
        assertEquals("level", assertThrows(IllegalArgumentException.class, () -> new Assurance.Label(null, "v", true, "c")).getMessage());
        Assurance.Label l = Assurance.Label.of("hardware").vendor("v").awaitingAudit(true).ceremony("c");
        assertEquals("hardware", l.level);
        assertEquals("v", l.vendor);
        assertTrue(l.awaitingAudit);
        assertEquals("c", l.ceremony);
        Assurance.Label back = l.vendor("w").awaitingAudit(false);
        assertEquals("w", back.vendor);
        assertFalse(back.awaitingAudit);
        assertEquals("c", back.ceremony);
        assertEquals("hardware", back.level);
        Assurance.Label base = Assurance.Label.of("software");
        assertNull(base.vendor);
        assertFalse(base.awaitingAudit);
        assertNull(base.ceremony);

        assertEquals("target and label are required", assertThrows(IllegalArgumentException.class, () -> Assurance.setLabel(null, base)).getMessage());
        assertEquals("target and label are required", assertThrows(IllegalArgumentException.class, () -> Assurance.setLabel(new Object(), null)).getMessage());
        Object t = new Object();
        assertSame(t, Assurance.setLabel(t, base));
        assertSame(base, Assurance.labelOf(t));
        assertNull(Assurance.labelOf(null));
        assertNull(Assurance.labelOf(new Object()));
        Assurance.Labelled own = () -> l;
        assertSame(l, Assurance.labelOf(own));

        assertTrue(Assurance.isAwaitingAuditScheme("frost"));
        assertTrue(Assurance.isAwaitingAuditScheme("frost_dkg"));
        assertTrue(Assurance.isAwaitingAuditScheme("mpc"));
        assertFalse(Assurance.isAwaitingAuditScheme("multisig"));
        assertFalse(Assurance.isAwaitingAuditScheme(null));
    }

    @Test void multiRootLevels() {
        Object hw = hook("hardware"), sw = hook("software"), mr = hook("multi_root"), none = new Object();
        // optional roots fill the quorum weakest first
        assertEquals("software", Assurance.multiRootLevel(List.of(new Assurance.Root(hw, false), new Assurance.Root(sw, false)), 1));
        assertEquals("hardware", Assurance.multiRootLevel(List.of(new Assurance.Root(hw, false), new Assurance.Root(sw, false)), 2));
        assertEquals("multi_root", Assurance.multiRootLevel(List.of(new Assurance.Root(hw, false), new Assurance.Root(mr, false)), 2));
        // more required roots than the threshold: no optional root is added, and no error
        assertEquals("multi_root", Assurance.multiRootLevel(List.of(new Assurance.Root(hw, true), new Assurance.Root(hw, true), new Assurance.Root(sw, false)), 1));
        assertEquals("hardware", Assurance.multiRootLevel(List.of(new Assurance.Root(hw, true), new Assurance.Root(sw, true)), 1));
        assertEquals("unknown", Assurance.multiRootLevel(List.of(new Assurance.Root(none, true), new Assurance.Root(sw, true)), 2));
        assertEquals("unknown", Assurance.multiRootLevel(List.of(new Assurance.Root(none, false), new Assurance.Root(hook("bogus"), false)), 2));
        assertEquals("software", Assurance.multiRootLevel(List.of(new Assurance.Root(sw, false), new Assurance.Root(none, false)), 0.5),
            "a fractional remainder rounds down: no optional root, no roots at all");
    }

    @Test void signatureLevels() {
        assertEquals("ed25519", Assurance.signatureLevel(null));
        assertEquals("ed25519", Assurance.signatureLevel("ed25519"));
        assertEquals("unknown", Assurance.signatureLevel(IntentJs.ofLong(1)));
        assertEquals("unknown", Assurance.signatureLevel("foo"));
        assertEquals("pq", Assurance.signatureLevel("ml-dsa-65"));
        assertEquals("pq", Assurance.signatureLevel("fn-dsa-512"));
        assertEquals("hybrid", Assurance.signatureLevel("hybrid-ed25519-ml-dsa-65"));
    }

    // ---- the report ------------------------------------------------------------------------------------------------

    @Test void hookLevels() {
        Assurance.Sources s = src("attestation", "pass", "zk_compliance", "pass", "threshold", "pass", "revocation", "pass", "other", "pass",
            "failing", "fail", "missing", "unsupported");
        s.attestationHook = hook("software");
        s.usedAttestationHook = Assurance.setLabel(new Object(), Assurance.Label.of("hardware").vendor("amd").ceremony("ignored"));
        s.zkHook = Assurance.setLabel(new Object(), Assurance.Label.of("groth16").ceremony("multi-party").vendor("z"));
        s.thresholdHook = hook("frost");
        s.revocationHook = Assurance.setLabel(new Object(), Assurance.Label.of("hardware").vendor("r").awaitingAudit(true));
        assertReport(map(
            "attestation", map("outcome", "pass", "level", "hardware", "vendor", "amd"),
            "zk_compliance", map("outcome", "pass", "level", "groth16", "vendor", "z", "ceremony", "multi-party"),
            "threshold", map("outcome", "pass", "level", "frost", "awaiting_audit", true),
            "revocation", map("outcome", "pass", "level", "hardware", "vendor", "r", "awaiting_audit", true),
            "other", map("outcome", "pass"),
            "failing", map("outcome", "fail"),
            "missing", map("outcome", "unsupported", "reason", "missing is not implemented by this verifier")), s);

        // no hook: attestation and zk are unknown, threshold and the rest have no level; an unlabelled hook is unknown
        Assurance.Sources bare = src("attestation", "pass", "zk_compliance", "pass", "threshold", "pass", "revocation", "pass");
        bare.attestationHook = hook("software");
        bare.revocationHook = new Object();
        assertReport(map("attestation", map("outcome", "pass", "level", "software"), "zk_compliance", map("outcome", "pass", "level", "unknown"),
            "threshold", map("outcome", "pass"), "revocation", map("outcome", "pass")), bare);
        Assurance.Sources unl = src("threshold", "pass", "attestation", "fail");
        unl.thresholdHook = new Object();
        unl.attestationHook = hook("hardware");
        assertReport(map("threshold", map("outcome", "pass", "level", "unknown"), "attestation", map("outcome", "fail")), unl);
        Assurance.Sources aud = src("attestation", "pass", "threshold", "pass");
        aud.attestationHook = Assurance.setLabel(new Object(), Assurance.Label.of("software").awaitingAudit(true));
        aud.thresholdHook = hook("multisig");
        assertReport(map("attestation", map("outcome", "pass", "level", "software", "awaiting_audit", true), "threshold", map("outcome", "pass", "level", "multisig")), aud);
    }

    @Test void thresholdT() {
        Object[][] cases = {{new Json.Num("-0"), "-0"}, {new Json.Num("2.50"), "2.5"}, {3L, "3"}, {2.5, "2.5"}, {7, "7"}};
        for (Object[] c : cases) {
            Assurance.Sources s = src("threshold", "pass");
            s.thresholdHook = hook("multisig");
            s.thresholdT = c[0];
            Object t = ((Map<?, ?>) Assurance.report(s).get("threshold")).get("t");
            assertTrue(t instanceof Json.Num, String.valueOf(c[0]));
            assertEquals(c[1], ((Json.Num) t).raw, String.valueOf(c[0]));
        }
        Assurance.Sources s = src("threshold", "pass");
        s.thresholdHook = hook("multisig");
        s.thresholdT = "3";
        assertFalse(((Map<?, ?>) Assurance.report(s).get("threshold")).containsKey("t"));
        Assurance.Sources noHook = src("threshold", "pass", "attestation", "pass");
        noHook.thresholdT = IntentJs.ofLong(2);
        noHook.attestationHook = hook("hardware");
        assertReport(map("threshold", map("outcome", "pass"), "attestation", map("outcome", "pass", "level", "hardware")), noHook);
    }

    @Test void signatureSuites() {
        Assurance.Sources none = src("leaf_signature", "pass", "cap_chain", "pass");
        assertReport(map("leaf_signature", map("outcome", "pass"), "cap_chain", map("outcome", "pass")), none);

        Assurance.Sources s = src("leaf_signature", "pass", "cap_chain", "pass", "chain", "pass", "other", "fail");
        s.pcactn = map("cap_chain", list(map("alg", "bogus"), map(), "x", map("alg", "hybrid-ed25519-ml-dsa-65")));
        assertReport(map("leaf_signature", map("outcome", "pass", "suites", list("ed25519"), "level", "ed25519"),
            "cap_chain", map("outcome", "pass", "suites", list("bogus", "ed25519", "ed25519", "hybrid-ed25519-ml-dsa-65"), "level", "unknown"),
            "chain", map("outcome", "pass", "suites", list("bogus", "ed25519", "ed25519", "hybrid-ed25519-ml-dsa-65"), "level", "unknown"),
            "other", map("outcome", "fail")), s);

        Object[][] chains = {
            {list(map("alg", "ml-dsa-65"), map("alg", "hybrid-ed25519-ml-dsa-65")), "hybrid"},
            {list(map("alg", "ml-dsa-65"), map("alg", "slh-dsa-sha2-128f")), "pq"},
            {list(map("alg", "hybrid-ed25519-ml-dsa-65"), map()), "ed25519"},
            {list(), "unknown"},
        };
        for (Object[] c : chains) {
            Assurance.Sources x = src("cap_chain", "pass");
            x.pcactn = map("alg", "ml-dsa-65", "cap_chain", c[0]);
            assertEquals(c[1], ((Map<?, ?>) Assurance.report(x).get("cap_chain")).get("level"), String.valueOf(c[0]));
        }

        Assurance.Sources odd = src("cap_chain", "pass", "leaf_signature", "pass");
        odd.pcactn = map("cap_chain", "x", "alg", IntentJs.ofLong(5));
        assertReport(map("cap_chain", map("outcome", "pass"), "leaf_signature", map("outcome", "pass", "suites", list("5"), "level", "unknown")), odd);

        // the unbound-PQ compatibility mode: only a non-Ed25519 suite is reported as unbound
        Assurance.Sources ub = src("leaf_signature", "pass", "cap_chain", "pass");
        ub.allowUnboundPq = true;
        ub.pcactn = map("alg", "ed25519", "cap_chain", list(map(), map("alg", "ed25519")));
        assertReport(map("leaf_signature", map("outcome", "pass", "suites", list("ed25519"), "level", "ed25519"),
            "cap_chain", map("outcome", "pass", "suites", list("ed25519", "ed25519"), "level", "ed25519")), ub);
        ub.pcactn = map("alg", "ml-dsa-65", "cap_chain", list(map(), map("alg", "ml-dsa-65")));
        assertReport(map("leaf_signature", map("outcome", "pass", "suites", list("ml-dsa-65"), "level", "unbound_pq"),
            "cap_chain", map("outcome", "pass", "suites", list("ed25519", "ml-dsa-65"), "level", "unbound_pq")), ub);
    }

    @Test void degradedAndBond() {
        Assurance.Sources s = src("a", "pass", "b", "fail");
        s.degraded = map2("a", "why", "b", "no", "c", "absent");
        s.pcactn = map("bond_ref", null);
        assertReport(map("a", map("outcome", "pass", "degraded", true, "reason", "why"), "b", map("outcome", "fail"),
            "bond", map("outcome", "unsupported", "reason", "bond verification is not implemented by this verifier")), s);
        Assurance.Sources plain = src("a", "pass");
        plain.pcactn = map();
        assertReport(map("a", map("outcome", "pass")), plain);
    }

    static Map<String, String> map2(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    // ---- the requirement -------------------------------------------------------------------------------------------

    @Test void requirementBuildersAndJson() {
        List<String> schemes = new ArrayList<>(List.of("frost"));
        Assurance.Requirement r = new Assurance.Requirement().threshold(schemes);
        schemes.add("mpc");
        assertEquals(List.of("frost"), r.threshold);
        assertNull(r.threshold(null).threshold);
        assertTrue(new Assurance.Requirement().allowAwaitingAudit(true).allowAwaitingAudit);
        assertEquals("pq", Assurance.Requirement.pq().signature);

        assertEquals("assurance: unknown assurance requirement(s): invalid (fail closed)", Assurance.Requirement.fromJson("x").invalid);
        assertEquals("assurance: unknown assurance requirement(s): a, b (fail closed)", Assurance.Requirement.fromJson(map("b", 1, "zk", "proof", "a", 2)).invalid);
        for (String k : new String[] {"allowAwaitingAudit", "allow_awaiting_audit", "allowPreview", "allow_preview"}) {
            Assurance.Requirement on = Assurance.Requirement.fromJson(map(k, true));
            assertNull(on.invalid, k);
            assertTrue(on.allowAwaitingAudit, k);
            assertFalse(Assurance.Requirement.fromJson(map(k, "true")).allowAwaitingAudit, k);
        }
        Assurance.Requirement mixed = Assurance.Requirement.fromJson(map("threshold", list("a", IntentJs.ofLong(1))));
        assertEquals("assurance: unknown threshold requirement a,1 (fail closed)", mixed.invalid);
        assertNull(mixed.threshold);
        assertEquals("assurance: unknown threshold requirement x (fail closed)", Assurance.Requirement.fromJson(map("threshold", "x")).invalid);
        assertEquals("assurance: unknown threshold requirement 5 (fail closed)", Assurance.Requirement.fromJson(map("threshold", IntentJs.ofLong(5))).invalid);
        Assurance.Requirement listed = Assurance.Requirement.fromJson(map("threshold", list("frost", "mpc"), "attestation", IntentJs.ofLong(5), "zk", true, "signature", null));
        assertNull(listed.invalid);
        assertEquals(List.of("frost", "mpc"), listed.threshold);
        assertEquals("5", listed.attestation);
        assertEquals("true", listed.zk);
        assertNull(listed.signature);
        assertFalse(listed.allowAwaitingAudit);
        Assurance.Requirement noThr = Assurance.Requirement.fromJson(map("signature", "pq"));
        assertNull(noThr.threshold);
        assertNull(noThr.invalid);
        assertEquals("pq", noThr.signature);
    }

    // ---- unmet -----------------------------------------------------------------------------------------------------

    static Map<String, Object> pass(String level) { return level == null ? map("outcome", "pass") : map("outcome", "pass", "level", level); }

    static String unmet(Map<String, Object> report, Assurance.Requirement r) { return Assurance.unmet(report, r); }

    static Assurance.Requirement att(String l) { return new Assurance.Requirement().attestation(l); }
    static Assurance.Requirement zk(String l) { return new Assurance.Requirement().zk(l); }

    @Test void unmetPrecedenceAndRequirementErrors() {
        assertEquals("assurance: the requirement could not be evaluated (fail closed)", unmet(null, att("software")));
        assertEquals("assurance: unsupported: x (why); a high-assurance policy never accepts it",
            unmet(map("n", "str", "x", map("outcome", "unsupported", "reason", "why")), null));
        assertEquals("assurance: unsupported: x (not implemented); a high-assurance policy never accepts it", unmet(map("x", map("outcome", "unsupported")), null));
        assertEquals("assurance: x rests on a degraded compatibility mode (why); a high-assurance policy never accepts it",
            unmet(map("n", "str", "f", map("outcome", "fail", "degraded", true), "x", map("outcome", "pass", "degraded", true, "reason", "why")), null));
        assertEquals("assurance: x rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it",
            unmet(map("x", map("outcome", "pass", "degraded", true)), null));
        assertEquals("assurance: unknown assurance requirement(s): invalid (fail closed)", unmet(map("x", map("outcome", "pass", "degraded", "true")), null));
        Assurance.Requirement bad = new Assurance.Requirement();
        bad.invalid = "nope";
        assertEquals("nope", unmet(map(), bad));
        assertEquals("assurance: unknown attestation requirement 'bogus' (fail closed)", unmet(map(), att("bogus")));
        assertEquals("assurance: unknown zk requirement 'bogus' (fail closed)", unmet(map(), zk("bogus")));
        assertEquals("assurance: unknown signature requirement 'classic' (fail closed)", unmet(map(), new Assurance.Requirement().signature("classic")));
        assertNull(unmet(map(), new Assurance.Requirement()));
    }

    @Test void unmetAttestation() {
        assertEquals("assurance: software attestation required but there is no attestation evidence", unmet(map("attestation", "x"), att("software")));
        assertEquals("assurance: hardware attestation required but the attestation check is fail", unmet(map("attestation", map("outcome", "fail")), att("hardware")));
        assertEquals("assurance: hardware attestation required but the attestation check is undefined", unmet(map("attestation", map()), att("hardware")));
        assertEquals("assurance: hardware attestation required but the attestation check is 5", unmet(map("attestation", map("outcome", IntentJs.ofLong(5))), att("hardware")));
        assertEquals("assurance: hardware attestation required but the evidence is unknown",
            unmet(map("attestation", map("outcome", "pass", "level", IntentJs.ofLong(2))), att("hardware")));
        assertEquals("assurance: hardware attestation required but the evidence is software", unmet(map("attestation", pass("software")), att("hardware")));
        assertEquals("assurance: multi_root attestation required but the evidence is hardware", unmet(map("attestation", pass("hardware")), att("multi_root")));
        assertNull(unmet(map("attestation", pass("multi_root")), att("multi_root")));
        assertNull(unmet(map("attestation", pass("hardware")), att("hardware")));
        assertNull(unmet(map("attestation", pass("multi_root")), att("software")));
    }

    @Test void unmetZk() {
        String notBound = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence";
        assertEquals(notBound, unmet(map("zk_compliance", pass("attested_vm")), zk("attested_vm_hardware")));
        assertEquals(notBound, unmet(map("zk_compliance", pass(null)), zk("attested_vm_hardware")));
        assertNull(unmet(map("zk_compliance", pass("attested_vm_hw")), zk("attested_vm_hardware")));
        assertNull(unmet(map("zk_compliance", pass("stark")), zk("attested_vm_hardware")));
        assertEquals("assurance: zk compliance (attested_vm_hardware) required but the evidence is bogus", unmet(map("zk_compliance", pass("bogus")), zk("attested_vm_hardware")));
        assertNull(unmet(map("zk_compliance", pass("attested_vm")), zk("attested_vm")));
        assertEquals("assurance: zk compliance (attested_vm) required but the evidence is unknown", unmet(map("zk_compliance", pass(null)), zk("attested_vm")));
        assertNull(unmet(map("zk_compliance", pass("zkvm")), zk("proof")));
        assertEquals("assurance: zk compliance (proof) required but the evidence is attested_vm_hw", unmet(map("zk_compliance", pass("attested_vm_hw")), zk("proof")));
        assertEquals("assurance: zk compliance (snark) required but the evidence is stark", unmet(map("zk_compliance", pass("stark")), zk("snark")));
        assertNull(unmet(map("zk_compliance", pass("groth16")), zk("snark")));
        assertNull(unmet(map("zk_compliance", pass("policyvm_snark")), zk("snark")));
        assertEquals("assurance: zk compliance (snark) required but there is no zk_compliance evidence", unmet(map(), zk("snark")));
    }

    @Test void unmetSignature() {
        Assurance.Requirement pq = Assurance.Requirement.pq();
        assertNull(unmet(map("leaf_signature", pass("pq"), "chain", pass("hybrid")), pq));
        assertNull(unmet(map("leaf_signature", pass("hybrid"), "cap_chain", pass("pq"), "chain", pass("ed25519")), pq));
        assertEquals("assurance: post-quantum signatures required but there is no cap_chain evidence", unmet(map("leaf_signature", pass("pq")), pq));
        assertEquals("assurance: post-quantum signatures required but leaf_signature is ed25519", unmet(map("leaf_signature", pass("ed25519"), "cap_chain", pass("pq")), pq));
        assertEquals("assurance: post-quantum signatures required but chain is unbound_pq", unmet(map("leaf_signature", pass("pq"), "chain", pass("unbound_pq")), pq));
        assertEquals("assurance: post-quantum signatures required but the cap_chain check is fail",
            unmet(map("leaf_signature", pass("pq"), "cap_chain", map("outcome", "fail")), pq));
    }

    @Test void unmetThresholdAndAwaitingAudit() {
        Assurance.Requirement frost = new Assurance.Requirement().threshold(List.of("frost", "mpc"));
        assertEquals("assurance: threshold (frost | mpc) required but there is no threshold evidence", unmet(map(), frost));
        assertEquals("assurance: threshold (frost | mpc) required but no threshold verifier enforced it", unmet(map("threshold", pass(null)), frost));
        assertEquals("assurance: threshold (frost | mpc) required but the scheme is multisig", unmet(map("threshold", pass("multisig")), frost));
        // a listed scheme awaiting audit is accepted; the same level on another check is still reported
        Map<String, Object> thr = map("outcome", "pass", "level", "frost", "awaiting_audit", true);
        assertNull(unmet(map("threshold", thr), frost));
        assertEquals("assurance: zk_compliance rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            unmet(map("threshold", thr, "zk_compliance", map("outcome", "pass", "level", "frost", "awaiting_audit", true)), frost));
        assertEquals("assurance: threshold rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            unmet(map("threshold", thr), new Assurance.Requirement()));
        assertNull(unmet(map("threshold", thr), new Assurance.Requirement().allowAwaitingAudit(true)));
        // the preview flag counts; a failed check, a string flag and a non-entry do not
        assertEquals("assurance: p rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it",
            unmet(map("n", "str", "f", map("outcome", "fail", "awaiting_audit", true), "s", map("outcome", "pass", "awaiting_audit", "true"),
                "p", map("outcome", "pass", "preview", true)), new Assurance.Requirement()));
        // the list exempts only the threshold check, never another check awaiting audit
        Assurance.Requirement listedNoCheck = new Assurance.Requirement().threshold(List.of("frost"));
        Map<String, Object> rep = map("threshold", map("outcome", "pass", "level", "frost", "awaiting_audit", true), "x", map("outcome", "pass", "level", "mpc", "preview", true));
        assertEquals("assurance: x rests on crypto awaiting audit (mpc); set allowAwaitingAudit or list the scheme to accept it", unmet(rep, listedNoCheck));
    }
}
