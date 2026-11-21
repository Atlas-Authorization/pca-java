package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * The post-quantum software / HSM attestation root. Where the AMD, Intel and NVIDIA roots are classical (their silicon vendors sign with
 * ECDSA today), this root is a software attestor that signs a statement over the measured harness or workload with ML-DSA and / or SLH-DSA
 * (optionally in a classical + PQ hybrid), so it is the root that holds against a quantum forgery without waiting on any hardware vendor.
 * HONEST SCOPE: it is NOT a TEE. Its measurements are software-measured and then signed by a key the operator holds, so the identity it
 * yields has {@code weights_measured: false} and can never satisfy {@code require_measured_weights} on its own; compose it WITH a hardware
 * root in {@link Attestation#createMultiRootVerifier} to get both properties. The suite, the attestor keys and the binding are signed into
 * the statement, so a downgrade or a key swap invalidates it, and a hybrid needs both signatures to verify.
 */
public final class AttestPqSoftware {
    private AttestPqSoftware() {}

    /** Domain separator of the signed statement body. */
    public static final String PQ_ATTEST_DOMAIN = "atlas-pca/attest-pq/v1\0";

    private static byte[] statementMessage(Map<String, Object> body) {
        return Pca.concat(PQ_ATTEST_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(IntentJs.normalize(body)));
    }

    /** True iff the suite carries a post-quantum signature component (ML-DSA or SLH-DSA; FN-DSA and LESS are not accepted by this root). */
    private static boolean suiteHasPq(Pq.Suite s) {
        return s.pq == Pq.Prim.ML_DSA_65 || s.pq == Pq.Prim.ML_DSA_87 || s.pq == Pq.Prim.SLH_DSA_SHA2_128F || s.pq == Pq.Prim.SLH_DSA_SHA2_256S;
    }

    private static String pqPublicKeyFor(Pq.Suite s, Pq.SuiteSecretKeys k) {
        if (s.pq == Pq.Prim.ML_DSA_65 && k.mlDsa != null) return Pq.encodeMlDsaPublicKey(k.mlDsa.publicKey);
        if (s.pq == Pq.Prim.SLH_DSA_SHA2_128F && k.slhDsa != null) return Pq.encodeSlhDsaPublicKey(k.slhDsa.publicKey);
        if (s.pq == Pq.Prim.ML_DSA_87 && k.mlDsa87 != null) return Pq.encodeMlDsa87PublicKey(k.mlDsa87.publicKey);
        if (s.pq == Pq.Prim.SLH_DSA_SHA2_256S && k.slhDsa256s != null) return Pq.encodeSlhDsa256sPublicKey(k.slhDsa256s.publicKey);
        return null;
    }

    /** An attestor holding a provided root key (never generated here). */
    public static final class Attestor {
        /** The root's PQ public key (b64u) the verifier must trust. */
        public final String pqPublicKey;
        /** The root's Ed25519 public key (b64u) when its key material carries one (hybrid suites), else null. */
        public final String ed25519PublicKey;
        private final Pq.Suite suite;
        private final Pq.SignerSuiteOpts keys;

        private Attestor(Pq.Suite suite, Pq.SignerSuiteOpts keys, String pqPk, String edPub) {
            this.suite = suite;
            this.keys = keys;
            this.pqPublicKey = pqPk == null ? "" : pqPk;
            this.ed25519PublicKey = edPub;
        }

        /**
         * Mint a signed statement over {@code {measurement, holder_pub, grant_ref, epoch, nonce}} plus the optional {@code weights_digest},
         * {@code system_prompt_digest}, {@code tool_manifest_digest}, {@code model_id}, {@code operator}. Throws when the binding is not
         * constructible or a claim has no canonical form.
         */
        public Map<String, Object> attest(Map<String, Object> claims) {
            String binding = Attestation.attestationBindingB64u(Issue.obj("holderPub", claims.get("holder_pub"), "grantRef", claims.get("grant_ref"),
                "epoch", claims.get("epoch"), "nonce", claims.get("nonce")));
            if (!claims.containsKey("measurement")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("measurement", claims.get("measurement"));
            body.put("binding", binding);
            body.put("alg", suite.alg);
            String pqPk = pqPublicKey.isEmpty() ? null : pqPublicKey;
            if (pqPk != null) body.put("pq_pk", pqPk);
            if (ed25519PublicKey != null) body.put("attestor_ed25519", ed25519PublicKey);
            for (String k : new String[] {"weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator"}) {
                if (claims.containsKey(k)) body.put(k, claims.get(k));
            }
            Pq.SuiteSignatureParts parts = Pq.signWithSuite(suite.alg, keys, statementMessage(body));
            Map<String, Object> statement = new LinkedHashMap<>(body);
            statement.put("sig", parts.sig);
            if (parts.pqSig != null) statement.put("pq_sig", parts.pqSig);
            return statement;
        }
    }

    /**
     * Build an attestor from a provided root key: {@code keys.alg} must be a suite with a post-quantum component (a classical-only or
     * unknown suite throws), the matching PQ key material is required, and a hybrid also needs {@code keys.edSecret}.
     */
    public static Attestor createPqSoftwareAttestor(Pq.SignerSuiteOpts keys) {
        Pq.Suite suite = Pq.resolveSigAlg(keys.alg, keys.alg != null);
        if (suite == null) throw new IllegalArgumentException("createPqSoftwareAttestor: unknown signature alg '" + keys.alg + "'");
        if (!suiteHasPq(suite)) throw new IllegalArgumentException("createPqSoftwareAttestor: '" + suite.alg + "' is classical; the PQ root requires a post-quantum suite");
        String pqPk = pqPublicKeyFor(suite, keys);
        if (suite.needsPqPk && pqPk == null) throw new IllegalArgumentException("createPqSoftwareAttestor: '" + suite.alg + "' requires the matching PQ key material");
        if (suite.hasEd25519 && keys.edSecret == null) throw new IllegalArgumentException("createPqSoftwareAttestor: hybrid suite '" + suite.alg + "' requires edSecret");
        String edPub = keys.edSecret != null ? Keys.edFromSeed(keys.edSecret).id() : null;
        return new Attestor(suite, keys, pqPk, edPub);
    }

    /** Acceptance policy of a verified statement. {@code measurements} is REQUIRED and NON-EMPTY (no accept-all). */
    public static final class Policy {
        /** Allowed measurement values. */
        public List<String> measurements;
        /** Allowed measured-weights digests; null or empty: not gated here. */
        public List<String> weightsMeasurements;
        /** Maps a verified statement to the measured identity agent_binding is checked against (null: the default, weights never measured). */
        public Function<Map<String, Object>, Map<String, Object>> deriveIdentity;
    }

    /** The options of {@link #createPqSoftwareVerifier}. */
    public static final class VerifierOptions {
        /** Trusted root PQ public keys (b64u): the statement's {@code pq_pk} must be one of them. At least one is required. */
        public List<String> trustedPqPublicKeys;
        /** Trusted root Ed25519 public keys (b64u); required to accept a hybrid (or classical) statement. */
        public List<String> trustedEd25519PublicKeys;
        /** Require a post-quantum component (default true: a classical-only statement is denied). */
        public boolean requirePq = true;
        /** Require a hybrid suite (default false). */
        public boolean requireHybrid;
        /** A closed allowlist of accepted suites; null means no list, and an empty list refuses every suite. */
        public List<String> allowedSuites;
        public Policy policy;
        /** The evidence seam: the signed statement for an action (null result: none). Without it the verifier fails closed. */
        public BiFunction<Object, Object, Object> resolveEvidence;
    }

    /** The verifier: the hardware-verifier seam, labelled {@code software} (a signed software statement, not silicon). */
    public static final class Verifier implements Attestation.HardwareVerifier, Assurance.Labelled {
        private final List<String> measurements;
        private final List<String> weightsMeasurements;
        private final Set<String> trustedPq, trustedEd, allowed;
        private final boolean requirePq, requireHybrid;
        private final BiFunction<Object, Object, Object> resolve;
        private final Function<Map<String, Object>, Map<String, Object>> derive;
        private static final Assurance.Label LABEL = new Assurance.Label("software", "pq-software", false, null);

        private Verifier(VerifierOptions o) {
            if (o == null || o.policy == null || o.policy.measurements == null || o.policy.measurements.isEmpty()) {
                throw new IllegalArgumentException("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
            }
            // snapshots: an allowlist emptied AFTER construction must not turn the gate into accept-all
            measurements = new ArrayList<>(o.policy.measurements);
            weightsMeasurements = o.policy.weightsMeasurements == null ? null : new ArrayList<>(o.policy.weightsMeasurements);
            trustedPq = new HashSet<>(o.trustedPqPublicKeys == null ? new ArrayList<String>() : o.trustedPqPublicKeys);
            if (trustedPq.isEmpty()) throw new IllegalArgumentException("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)");
            trustedEd = new HashSet<>(o.trustedEd25519PublicKeys == null ? new ArrayList<String>() : o.trustedEd25519PublicKeys);
            requirePq = o.requirePq;
            requireHybrid = o.requireHybrid;
            allowed = o.allowedSuites == null ? null : new HashSet<>(o.allowedSuites);
            resolve = o.resolveEvidence;
            derive = o.policy.deriveIdentity != null ? o.policy.deriveIdentity : AttestPqSoftware::defaultIdentity;
        }

        @Override public Assurance.Label assuranceLabel() { return LABEL; }

        private static Map<String, Object> fail(String why) { return Issue.obj("ok", false, "reason", why); }

        /** Verify the statement the evidence seam resolves for {@code input} ({@code {document, ctx, nowMs, expected}}). Fails closed with a reason. */
        @Override public Object verify(Map<String, Object> input) {
            try {
                if (resolve == null) return fail("no PQ-software evidence resolver configured (fail closed)");
                Object stO = resolve.apply(input.get("document"), input.get("ctx"));
                if (!(stO instanceof Map) || !(((Map<?, ?>) stO).get("alg") instanceof String)) return fail("no PQ-software attestation statement for this action");
                Map<String, Object> st = StoreJs.map(stO);
                String alg = (String) st.get("alg");
                Pq.Suite suite = Pq.resolveSigAlg(alg, true);
                if (suite == null) return fail("PQ statement declares an unknown signature alg '" + alg + "'");
                if (requirePq && !suiteHasPq(suite)) return fail("PQ required: a classical-only suite '" + suite.alg + "' is not accepted by the post-quantum root");
                if (requireHybrid && !(suite.hasEd25519 && suiteHasPq(suite))) return fail("hybrid required: suite '" + suite.alg + "' is not a classical+PQ hybrid");
                if (allowed != null && !allowed.contains(suite.alg)) return fail("suite '" + suite.alg + "' is not in the allowed-suites list");
                if (suite.needsPqPk && (!(st.get("pq_pk") instanceof String) || !trustedPq.contains(st.get("pq_pk")))) return fail("PQ attestor key is not trusted");
                if (suite.hasEd25519 && (!(st.get("attestor_ed25519") instanceof String) || !trustedEd.contains(st.get("attestor_ed25519")))) {
                    return fail("hybrid Ed25519 attestor key is not trusted");
                }
                Map<String, Object> body = new LinkedHashMap<>(st);
                body.remove("sig");
                body.remove("pq_sig");
                byte[] message = statementMessage(body);
                // the PQ key is vouched for by this verifier's own trusted set (checked above), through the choke point
                Pq.PinnedPq pq = suite.needsPqPk ? Pq.resolvePqVerifyKey("", null, null, null, (String) st.get("pq_pk")) : null;
                String edPub = st.get("attestor_ed25519") instanceof String ? (String) st.get("attestor_ed25519") : null;
                if (!Pq.verifyWithSuite(suite.alg, edPub, pq, message, st.get("sig"), st.get("pq_sig"))) return fail("PQ attestation signature does not verify");

                Object expected = input.get("expected");
                if (expected == null) return fail("no expected attestation binding supplied");
                String expectedB64u;
                try {
                    expectedB64u = Attestation.attestationBindingB64u(expected);
                } catch (RuntimeException e) {
                    return fail("binding not constructible: " + (e.getMessage() == null ? "invalid" : e.getMessage()));
                }
                if (!(st.get("binding") instanceof String) || ((String) st.get("binding")).isEmpty()) return fail("PQ statement is not bound (binding absent)");
                if (!expectedB64u.equals(st.get("binding"))) return fail("PQ statement binding mismatch (holder/grant/epoch/nonce)");

                if (!(st.get("measurement") instanceof String) || !measurements.contains(st.get("measurement"))) return fail("measurement not in policy allowlist");
                if (weightsMeasurements != null && !weightsMeasurements.isEmpty()
                    && (!(st.get("weights_digest") instanceof String) || !weightsMeasurements.contains(st.get("weights_digest")))) {
                    return fail("measured weights digest not in policy allowlist");
                }
                Map<String, Object> hostAsserted = new LinkedHashMap<>();
                hostAsserted.put("suite", suite.alg);
                return Issue.obj("ok", true, "bound", true, "measured", derive.apply(st), "hostAsserted", hostAsserted);
            } catch (RuntimeException e) {
                return fail("pq-software verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        }
    }

    /**
     * Build the verifier: it resolves the statement through the evidence seam, enforces the suite requirements, checks the attestor keys
     * against the TRUSTED sets, verifies the PQ (or hybrid) signature over the canonical statement body, confirms the binding equals the
     * expected one, applies the policy and returns the measured identity ({@code weights_measured} always false). It plugs into
     * {@link Attestation#createAttestationVerifier} and {@link Attestation#createMultiRootVerifier} like any hardware root.
     */
    public static Verifier createPqSoftwareVerifier(VerifierOptions opts) { return new Verifier(opts); }

    /** The default mapping of a verified statement: the weights digest is software-measured, so {@code weights_measured} is always false. */
    private static Map<String, Object> defaultIdentity(Map<String, Object> st) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("model_id", st.get("model_id") instanceof String ? st.get("model_id") : "");
        m.put("weights_digest", st.get("weights_digest") instanceof String ? st.get("weights_digest") : "");
        m.put("weights_measured", false);
        m.put("runtime_measurement", st.get("measurement"));
        m.put("operator", st.get("operator") instanceof String ? st.get("operator") : "");
        if (st.get("system_prompt_digest") instanceof String) m.put("system_prompt_digest", st.get("system_prompt_digest"));
        if (st.get("tool_manifest_digest") instanceof String) m.put("tool_manifest_digest", st.get("tool_manifest_digest"));
        return m;
    }
}
