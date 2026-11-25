package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The zk compliance module against the reference corpus (1429 cases): every function, every case. The pairing itself lives in the
 * pca-zk adapter, so here the engine is a recording of the reference: for each case it answers with the verdict the corpus records for
 * that case, and notes that it was asked. Every result must then equal the corpus; a case the reference accepts must have asked the
 * engine, and a case the reference refuses in front of the pairing must be refused without asking it. An engine that says yes to
 * everything cannot pass. The adapter's test replays the pairing cases against the real library.
 */
class ZkDiffTest {
    private static final String MOD = "ref-zk";

    /** Answers with the reference's verdict for the case being replayed and records the call. */
    private static final class Stub implements Zk.Groth16Engine {
        boolean reached, verdict;
        @Override public boolean verify(Object vkey, List<?> publicSignals, Object proof) { reached = true; return verdict; }
    }

    @AfterEach void reset() { Zk.resetGroth16Engine(); }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** The corpus conventions: {"$bigint"}, {"$num"}, {"$bytes"} (a seed label, or the key the loader derived from it). */
    private static Object rv(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(rv(x)); return out; }
        Map<String, Object> o = m(v);
        if (o == null) return v;
        if (o.size() == 1 && o.get("$bigint") instanceof String) return new BigInteger((String) o.get("$bigint"));
        if (o.size() == 1 && o.get("$num") instanceof String) {
            String n = (String) o.get("$num");
            return n.equals("NaN") ? Double.NaN : n.equals("Infinity") ? Double.POSITIVE_INFINITY : n.equals("-Infinity") ? Double.NEGATIVE_INFINITY : Double.valueOf(n);
        }
        if (o.size() == 1 && o.containsKey("$bytes")) {
            Object b = o.get("$bytes");
            if (b instanceof String) return Keys.unb64u((String) b);
            return Pca.sha(("atlas-pca-conformance/" + m(b).get("$seed")).getBytes(StandardCharsets.UTF_8));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : o.entrySet()) out.put(e.getKey(), rv(e.getValue()));
        return out;
    }

    /** {"$expectThunk": X} is a supplier of X as written ("throw": one that throws); anything else is the pins, revived when {@code revive}. */
    private static Object expectOf(Object e, boolean revive) {
        Map<String, Object> o = m(e);
        if (o == null || !o.containsKey("$expectThunk")) return revive ? rv(e) : e;
        Object x = o.get("$expectThunk");
        if ("throw".equals(x)) return (Supplier<Object>) () -> { throw new IllegalStateException("thunk"); };
        return (Supplier<Object>) () -> x;
    }

    private static Map<String, Object> opts(Object raw) {
        Map<String, Object> o = m(rv(raw));
        if (o != null && o.containsKey("expect")) o.put("expect", expectOf(m(raw).get("expect"), true));
        return o;
    }

    /** A BigInteger result is {"$bigint": decimal} in the corpus. */
    private static Object big(Object v) {
        if (v instanceof BigInteger) { Map<String, Object> o = new LinkedHashMap<>(); o.put("$bigint", v.toString()); return o; }
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(big(x)); return out; }
        if (v instanceof Map) { Map<String, Object> out = new LinkedHashMap<>(); for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), big(e.getValue())); return out; }
        return v;
    }

    /** The reference refuses null options; this API reads null as "no options", so those cases are refused here. */
    private static Map<String, Object> quantOpts(List<?> a, int i) {
        if (i < a.size() && a.get(i) == null) throw new IllegalArgumentException("null options");
        return m(rv(arg(a, i)));
    }

    private static Object label(Object target) {
        Assurance.Label l = Assurance.labelOf(target);
        if (l == null) return null;
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("level", l.level);
        if (l.vendor != null) o.put("vendor", l.vendor);
        if (l.awaitingAudit) o.put("awaitingAudit", true);
        if (l.ceremony != null) o.put("ceremony", l.ceremony);
        return o;
    }

    private static Map<String, Object> table() {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("ZK_PROVER_BINDING_REF", Zk.ZK_PROVER_BINDING_REF);
        t.put("POLICYVM_PUBLIC_SIGNAL", Zk.POLICYVM_PUBLIC_SIGNAL);
        t.put("POLICYVM_PUBLIC_SIGNAL_COUNT", Zk.POLICYVM_PUBLIC_SIGNAL_COUNT);
        t.put("POLICYVM_BOUND_PUBLIC_SIGNAL", Zk.POLICYVM_BOUND_PUBLIC_SIGNAL);
        t.put("POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT", Zk.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT);
        t.put("POLICYVM_BOUND_RISK_FIELDS", Zk.POLICYVM_BOUND_RISK_FIELDS);
        t.put("POLICYVM_REVERSIBILITY_ORDER", Zk.POLICYVM_REVERSIBILITY_ORDER);
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("DEFAULT_VKEY_PATH", Zk.DEFAULT_VKEY_PATH);
        p.put("DEFAULT_WASM_PATH", Zk.DEFAULT_WASM_PATH);
        p.put("DEFAULT_ZKEY_PATH", Zk.DEFAULT_ZKEY_PATH);
        p.put("POLICYVM_VKEY_PATH", Zk.POLICYVM_VKEY_PATH);
        p.put("POLICYVM_SAMPLE_PROOF_PATH", Zk.POLICYVM_SAMPLE_PROOF_PATH);
        p.put("POLICYVM_WASM_PATH", Zk.POLICYVM_WASM_PATH);
        p.put("POLICYVM_ZKEY_PATH", Zk.POLICYVM_ZKEY_PATH);
        p.put("POLICYVM_BLS12381_VKEY_PATH", Zk.POLICYVM_BLS12381_VKEY_PATH);
        p.put("POLICYVM_BLS12381_SAMPLE_PROOF_PATH", Zk.POLICYVM_BLS12381_SAMPLE_PROOF_PATH);
        p.put("POLICYVM_BOUND_VKEY_PATH", Zk.POLICYVM_BOUND_VKEY_PATH);
        p.put("POLICYVM_BOUND_SAMPLE_PROOF_PATH", Zk.POLICYVM_BOUND_SAMPLE_PROOF_PATH);
        p.put("POLICYVM_BOUND_WASM_PATH", Zk.POLICYVM_BOUND_WASM_PATH);
        p.put("POLICYVM_BOUND_ZKEY_PATH", Zk.POLICYVM_BOUND_ZKEY_PATH);
        t.put("paths", p);
        return t;
    }

    /** The functions that never reach the pairing: replayed by JSON value. */
    private static Map<String, OracleCases.Fn> pure() {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", a -> table());
        f.put("commitmentField", a -> Zk.commitmentField(arg(a, 0)));
        f.put("policyCommitment", a -> Zk.policyCommitment(arg(a, 0)));
        f.put("pinnedPolicyCommitment", a -> Zk.pinnedPolicyCommitment(arg(a, 0)));
        f.put("actionCommitment", a -> Zk.actionCommitment(arg(a, 0)));
        f.put("proverKeyBinding", a -> Zk.proverKeyBinding((String) arg(a, 0), arg(a, 1), (String) arg(a, 2)));
        f.put("policyVmStructHash", a -> Zk.policyVmStructHash(rv(arg(a, 0))));
        f.put("policyVmRiskHash", a -> Zk.policyVmRiskHash(rv(arg(a, 0))));
        f.put("quantizeActionStruct", a -> big(Zk.quantizeActionStruct(rv(arg(a, 0)), quantOpts(a, 1))));
        f.put("policyVmCommitmentFromAction", a -> Zk.policyVmCommitmentFromAction(rv(arg(a, 0)), quantOpts(a, 1)));
        f.put("quantizePlanStruct", a -> big(Zk.quantizePlanStruct(rv(arg(a, 0)), quantOpts(a, 1))));
        f.put("quantizePolicyStruct", a -> big(Zk.quantizePolicyStruct(rv(arg(a, 0)), quantOpts(a, 1))));
        f.put("quantizePolicyVmInputs", a -> big(Zk.quantizePolicyVmInputs(m(rv(arg(a, 0))), quantOpts(a, 1))));
        f.put("decodePolicyVmPublic", a -> Zk.decodePolicyVmPublic(arg(a, 0)));
        f.put("decodePolicyVmBoundPublic", a -> Zk.decodePolicyVmBoundPublic(arg(a, 0)));
        f.put("policyVmContextMatches", a -> {
            List<?> ps = (List<?>) arg(a, 0);
            boolean bound = "bound".equals(arg(a, 2));
            return "$absent".equals(arg(a, 1)) ? Zk.policyVmContextMatches(ps, bound) : Zk.policyVmContextMatches(ps, expectOf(arg(a, 1), false), bound); // this function's cases carry their pins as written
        });
        f.put("isCanonicalGroth16Envelope", a -> Zk.isCanonicalGroth16Envelope(arg(a, 0), arg(a, 1)));
        f.put("circuitVersion", a -> Zk.circuitVersion(arg(a, 0)));
        f.put("vkId", a -> ZkCeremony.vkId(arg(a, 0)));
        f.put("circuitProvenance", a -> ZkCeremony.circuitProvenance(m(arg(a, 0))));
        f.put("checkCircuitProvenance", a -> ZkCeremony.checkCircuitProvenance(arg(a, 0), m(arg(a, 1))));
        f.put("transcriptSha256", a -> ZkCeremony.transcriptSha256(arg(a, 0)));
        f.put("checkTranscript", a -> ZkCeremony.checkTranscript(arg(a, 0), m(arg(a, 1))));
        f.put("ceremonyOf", a -> ZkCeremony.ceremonyOf(arg(a, 0), arg(a, 1)));
        f.put("createAttestedComplianceProver", a -> {
            Zk.AttestedComplianceProver p = Zk.createAttestedComplianceProver((byte[]) rv(arg(a, 0)));
            Map<String, Object> o = m(arg(a, 1));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("publicKey", p.publicKey);
            out.put("statement", p.prove(m(o.get("pcactn")), m(o.get("decideInput")), Json.asLong(o.get("issued_at")), Json.asLong(o.get("expires_at"))));
            return out;
        });
        return f;
    }

    private static final Set<String> ENGINE_FNS = Set.of("verifyPolicyVmProof", "createPolicyVmSnarkBackend", "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend",
        "createPolicyVmBoundSnarkBackend", "createZkVerifier");

    @Test void everyFunctionOfTheCorpusIsReplayed() throws Exception {
        List<Map<String, Object>> all = BaseOracle.of(MOD, null);
        assertEquals(1429, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        Set<String> handled = new TreeSet<>(pure().keySet());
        handled.addAll(ENGINE_FNS);
        handled.add("provePolicyVmCompliance"); // one contract case: proving needs the circuit build, which is not in the repository
        assertEquals(handled, fns);
    }

    @Test void pureFunctions() throws Exception {
        for (Map.Entry<String, OracleCases.Fn> e : pure().entrySet()) OracleCases.each(MOD, e.getKey(), e.getValue());
    }

    /** Cases the reference refuses in front of the pairing, by the stem of the case name. */
    private static final String[] GATE_ONLY = {"expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "signal-count-",
        "allow-0", "signal-noncanonical", "signal-plus-order", "pi_a.x-hex", "pi_a.x+p", "pi_a.x-leading-zero", "pi_a.z-0", "pi_a-infinity", "pi_a-affine-2", "pi_b-short", "proof-null",
        "proof-missing", "proof-string", "protocol-plonk", "proof-curve-wrong", "shape-", "risk-hash-mismatch", "risk-hash-half", "bls-not-allowed", "15-signals", "now-out-of-range",
        "context-pin", "action-hash-wrong", "policy-hash-wrong", "plan-hash-wrong", "other-circuit", "signals-not-array", "policy-tag-mismatch", "plan-tag-mismatch", "action-tag-mismatch",
        "wrong-system", "wrong-circuit", "signals-6", "signals-8", "null", "noncanonical-signal", "risk-wrong", "action-wrong", "v1-circuit", "signals-missing", "no-proof",
        "groth16-compliance-garbage"};

    private static boolean gateOnly(String name) {
        String stem = name.substring(name.lastIndexOf('/') + 1);
        for (String g : GATE_ONLY) if (stem.startsWith(g)) return true;
        return false;
    }

    private interface Run { Object apply(List<?> args) throws Exception; }

    /**
     * Replays the cases of {@code fn} with the recorded engine; {@code okOf} reads the verdict out of a reference result. Returns how
     * many refusals were the pairing's own.
     */
    @SuppressWarnings("unchecked")
    private static int engineCases(String fn, Run run, java.util.function.Function<Object, Boolean> okOf) throws Exception {
        Stub stub = new Stub();
        Zk.setGroth16Engine(stub);
        int pairingRefusals = 0;
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MOD, fn)) {
            String name = (String) c.get("name");
            Object want = c.get("out");
            boolean throwsRef = want instanceof Map && ((Map<String, Object>) want).containsKey("$throws");
            boolean ok = !throwsRef && Boolean.TRUE.equals(okOf.apply(want));
            stub.reached = false;
            stub.verdict = ok;
            Object got;
            try {
                got = OracleCases.toJson(run.apply((List<?>) c.get("args")));
            } catch (Throwable t) {
                if (!throwsRef) bad.add(name + ": threw " + t);
                continue;
            }
            if (throwsRef) { bad.add(name + ": the reference throws, got " + got); continue; }
            if (!IntentJs.jsonEquals(want, IntentJs.normalize(got))) {
                bad.add(name + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + Json.canonicalize(got) + (stub.reached ? " (pairing reached)" : ""));
                continue;
            }
            // an attested-VM statement is accepted without any proof system; everything else accepted must have asked the engine
            boolean proofCase = !fn.equals("createZkVerifier") || name.contains("/snark/");
            if (proofCase && ok && !stub.reached) bad.add(name + ": accepted without a pairing check");
            if (!ok && stub.reached && gateOnly(name)) bad.add(name + ": the reference refuses this in front of the pairing, here the pairing was reached");
            if (!ok && stub.reached) pairingRefusals++;
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
        return pairingRefusals;
    }

    private static Object backendCase(java.util.function.Function<Map<String, Object>, Zk.SnarkBackend> make, List<?> a) throws Exception {
        Zk.SnarkBackend b = make.apply(opts(arg(a, 0)));
        Map<String, Object> in = m(arg(a, 1));
        Map<String, String> pub = new LinkedHashMap<>();
        Map<String, Object> pi = m(in.get("publicInputs"));
        for (String k : new String[] {"action_commit", "policy_commit", "plan_commit"}) pub.put(k, (String) pi.get(k));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verified", b.verify(in.get("proof"), pub, null));
        out.put("label", label(b));
        return out;
    }

    private static Object verdictOf(Object out, String key) { return m(out) == null ? null : m(out).get(key); }

    @Test void proofVerification() throws Exception {
        int d = engineCases("verifyPolicyVmProof", a -> Zk.verifyPolicyVmProof(arg(a, 0), opts(arg(a, 1))), o -> Boolean.TRUE.equals(o));
        assertTrue(d > 40, "only " + d + " refusals came from the pairing");
    }

    @Test void snarkBackends() throws Exception {
        java.util.function.Function<Object, Boolean> ok = o -> Boolean.TRUE.equals(verdictOf(o, "verified"));
        engineCases("createPolicyVmSnarkBackend", a -> backendCase(Zk::createPolicyVmSnarkBackend, a), ok);
        engineCases("createPolicyVmSnarkBackendBls12381", a -> backendCase(Zk::createPolicyVmSnarkBackendBls12381, a), ok);
        engineCases("createGroth16SnarkBackend", a -> backendCase(Zk::createGroth16SnarkBackend, a), ok);
        engineCases("createPolicyVmBoundSnarkBackend", a -> backendCase(Zk::createPolicyVmBoundSnarkBackend, a), ok);
    }

    @SuppressWarnings("unchecked")
    private static Object verifierCase(List<?> a) {
        Map<String, Object> s = m(rv(arg(a, 0)));
        Zk.VerifierOpts o = new Zk.VerifierOpts();
        o.trustedProverKeys = s.get("trustedProverKeys") instanceof List ? (List<String>) s.get("trustedProverKeys") : null;
        o.policyCommitments = s.get("policyCommitments") instanceof List ? (List<String>) s.get("policyCommitments") : null;
        o.revokedProverKeys = s.get("revokedProverKeys") instanceof List ? (List<String>) s.get("revokedProverKeys") : null;
        o.clockSkewMs = s.get("clockSkewMs") instanceof Double ? (Double) s.get("clockSkewMs") : OracleCases.num(s.get("clockSkewMs"));
        long now = Json.asLong(s.get("nowMs"));
        o.now = () -> now;
        Map<String, Object> snark = m(s.get("snark"));
        if (snark != null) {
            Map<String, Object> so = snark.get("opts") == null ? new LinkedHashMap<>() : m(snark.get("opts"));
            String kind = (String) snark.get("kind");
            o.snarkBackend = kind.equals("groth16") ? Zk.createGroth16SnarkBackend(so) : kind.equals("policyvm") ? Zk.createPolicyVmSnarkBackend(so)
                : kind.equals("policyvm-bls") ? Zk.createPolicyVmSnarkBackendBls12381(so) : Zk.createPolicyVmBoundSnarkBackend(so);
        }
        Zk.ZkVerifier hook = Zk.createZkVerifier(o);
        Map<String, Object> ctx = m(arg(a, 1));
        Map<String, Object> result = hook.check(m(ctx.get("pcactn")), m(ctx.get("grant")));
        // the text after the fail-closed prefix is the engine's own and is not compared
        if (result.get("reason") instanceof String) result.put("reason", ((String) result.get("reason")).replaceAll("(?s)(zk verification error \\(fail closed\\)): .*$", "$1"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("result", result);
        out.put("label", label(hook));
        return out;
    }

    @Test void theZkVerifierHook() throws Exception {
        engineCases("createZkVerifier", ZkDiffTest::verifierCase, o -> Boolean.TRUE.equals(verdictOf(verdictOf(o, "result"), "ok")));
    }

    @Test void anEngineThatAcceptsEverythingDoesNotChangeARefusalInFrontOfThePairing() throws Exception {
        Zk.setGroth16Engine((vkey, ps, proof) -> true);
        int refused = 0;
        for (Map<String, Object> c : OracleCases.of(MOD, "verifyPolicyVmProof")) {
            if (!gateOnly((String) c.get("name")) || !Boolean.FALSE.equals(c.get("out"))) continue;
            List<?> a = (List<?>) c.get("args");
            assertFalse(Zk.verifyPolicyVmProof(arg(a, 0), opts(arg(a, 1))), (String) c.get("name"));
            refused++;
        }
        assertTrue(refused > 40, "only " + refused + " gate refusals replayed");
    }

    @Test void withoutAnEngineNothingIsReportedInvalid() throws Exception {
        Map<String, Object> valid = null;
        for (Map<String, Object> c : OracleCases.of(MOD, "verifyPolicyVmProof")) if ("verifyPolicyVmProof/bn/valid".equals(c.get("name"))) valid = c;
        List<?> a = (List<?>) valid.get("args");
        assertThrows(Zk.BackendMissing.class, () -> Zk.verifyPolicyVmProof(arg(a, 0), opts(arg(a, 1))));
        // a refusal in front of the pairing needs no engine
        assertFalse(Zk.verifyPolicyVmProof(new LinkedHashMap<String, Object>(), null));
        assertThrows(IllegalArgumentException.class, () -> Zk.setGroth16Engine(null));
    }
}
