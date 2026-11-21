package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Zero-knowledge / attested compliance for the {@code zk_compliance} check: attested-VM compliance statements (an Ed25519-signed
 * statement over the action, policy and plan commitments), Groth16 verification of snarkjs proofs for the compliance and Policy VM
 * circuits (BN254 and BLS12-381), the derivation of their public inputs (commitment field elements, struct hashes, quantizers), the
 * canonical-envelope gate and the verifier-side context pins.
 *
 * <p>The pairing check and the prover are NOT implemented here: they come from a {@link Groth16Engine} installed with
 * {@link #setGroth16Engine} (the {@code pca-zk} adapter module binds the shared native library). Without an engine every call that
 * needs one throws {@link BackendMissing}; nothing ever reports a proof "invalid" because the library is absent. Everything in front of
 * the pairing (shape, circuit and system tags, signal counts, pins, canonical encoding) is decided here, as in the reference.
 *
 * <p>Values are parsed JSON (maps, lists, strings, {@link Json.Num} or Java numbers); a uint64 above 2^53 is a {@link BigInteger}.
 * Option maps use the reference's member names.
 */
public final class Zk {
    private Zk() {}

    static final String DOMAIN = "atlas-pca/zk-compliance/v1\0";
    /** The {@code grantRef} a prover VM's attestation binds its statement key under. */
    public static final String ZK_PROVER_BINDING_REF = "atlas-pca/zk-prover/v1";

    // ---- the pairing / proving seam ---------------------------------------------------------------------------------------------

    /** The Groth16 primitive: snarkjs-compatible verification (the curve is the key's {@code curve} member) and proving. */
    public interface Groth16Engine {
        /** As snarkjs {@code groth16.verify(vkey, publicSignals, proof)}: true only for a valid proof; a malformed key or proof is false. */
        boolean verify(Object vkey, List<?> publicSignals, Object proof);

        /** As snarkjs {@code groth16.fullProve}: {@code {proof, publicSignals}} for the circuit input, its witness wasm and its proving key. */
        default Map<String, Object> fullProve(String curve, Map<String, Object> input, String wasmPath, String zkeyPath) {
            throw new BackendMissing("this Groth16 engine cannot prove");
        }
    }

    /** No Groth16 engine is installed (or it cannot do what was asked). Never a verdict about a proof. */
    public static final class BackendMissing extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        public BackendMissing(String message) { super(message); }
    }

    private static volatile Groth16Engine engine;

    /** Installs the Groth16 engine used by every verifier and prover of this class. */
    public static void setGroth16Engine(Groth16Engine e) {
        if (e == null) throw new IllegalArgumentException("Zk.setGroth16Engine: an engine is required");
        engine = e;
    }

    /** Removes the installed engine. */
    public static void resetGroth16Engine() { engine = null; }

    private static Groth16Engine engine() {
        Groth16Engine e = engine;
        if (e == null) throw new BackendMissing("no Groth16 engine installed: add the pca-zk adapter and call NativeZk.register(), or Zk.setGroth16Engine");
        return e;
    }

    // ---- JavaScript value helpers -------------------------------------------------------------------------------------------------

    private static final Pattern CANON_DEC = Pattern.compile("0|[1-9][0-9]*");
    private static final Pattern DIGITS = Pattern.compile("[0-9]+");
    private static final BigInteger U64_BOUND = BigInteger.ONE.shiftLeft(64);
    private static final Set<String> OBJECT_PROTOTYPE_KEYS = new HashSet<>(Arrays.asList("constructor", "toString", "toLocaleString", "valueOf", "hasOwnProperty",
        "isPrototypeOf", "propertyIsEnumerable", "__proto__", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"));

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static boolean isNum(Object o, double v) { Double d = IntentJs.num(o); return d != null && d == v; }

    /** JavaScript truthiness of a parsed JSON value. */
    static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        if (o instanceof BigInteger) return ((BigInteger) o).signum() != 0;
        Double d = IntentJs.num(o);
        return d == null || (d != 0 && !Double.isNaN(d));
    }

    private static boolean isJsNumber(Object o) { return !(o instanceof BigInteger) && IntentJs.num(o) != null; }

    private static boolean jsSpace(char c) {
        return c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r' || c == ' ' || c == 0xA0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200A)
            || c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000 || c == 0xFEFF;
    }

    private static BigInteger radix(String digits, int radix, String all) {
        if (digits.isEmpty()) throw new IllegalArgumentException("Cannot convert " + all + " to a BigInt");
        for (int i = 0; i < digits.length(); i++) if (Character.digit(digits.charAt(i), radix) < 0 || digits.charAt(i) > 'z') throw new IllegalArgumentException("Cannot convert " + all + " to a BigInt");
        return new BigInteger(digits, radix);
    }

    /** JavaScript {@code BigInt(string)}: surrounding white space ignored, empty is 0, decimal with an optional sign, or 0x / 0o / 0b digits. */
    private static BigInteger strToBigInt(String all) {
        int a = 0, b = all.length();
        while (a < b && jsSpace(all.charAt(a))) a++;
        while (b > a && jsSpace(all.charAt(b - 1))) b--;
        String s = all.substring(a, b);
        if (s.isEmpty()) return BigInteger.ZERO;
        if (s.length() >= 2 && s.charAt(0) == '0') {
            char p = s.charAt(1);
            if (p == 'x' || p == 'X') return radix(s.substring(2), 16, all);
            if (p == 'o' || p == 'O') return radix(s.substring(2), 8, all);
            if (p == 'b' || p == 'B') return radix(s.substring(2), 2, all);
        }
        boolean signed = s.charAt(0) == '+' || s.charAt(0) == '-';
        String digits = signed ? s.substring(1) : s;
        if (!DIGITS.matcher(digits).matches()) throw new IllegalArgumentException("Cannot convert " + all + " to a BigInt");
        BigInteger v = new BigInteger(digits);
        return s.charAt(0) == '-' ? v.negate() : v;
    }

    /** The exact integer of a JavaScript number, or null when it is not an integer (NaN, an infinity, a fraction). */
    private static BigInteger integerOf(Object n) {
        if (n instanceof Long || n instanceof Integer) return BigInteger.valueOf(((Number) n).longValue());
        Double d = IntentJs.num(n);
        if (d == null || Double.isNaN(d) || Double.isInfinite(d) || d != Math.rint(d)) return null;
        return new BigDecimal(d).toBigInteger();
    }

    /** JavaScript {@code BigInt(v)}; throws where the reference throws. */
    private static BigInteger jsBigInt(Object v) {
        if (v instanceof BigInteger) return (BigInteger) v;
        if (v instanceof Boolean) return (Boolean) v ? BigInteger.ONE : BigInteger.ZERO;
        if (v instanceof String) return strToBigInt((String) v);
        if (isJsNumber(v)) {
            BigInteger i = integerOf(v);
            if (i == null) throw new IllegalArgumentException("The number cannot be converted to a BigInt because it is not an integer");
            return i;
        }
        if (v instanceof List || v instanceof Map) return strToBigInt(IntentRevocation.jsText(v, true));
        throw new IllegalArgumentException("Cannot convert " + v + " to a BigInt");
    }

    private static Map<String, Object> halves(Object hi, Object lo) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("hi", hi);
        m.put("lo", lo);
        return m;
    }

    private static Object readJsonFile(String path) {
        try {
            return Json.parseLenient(Files.readString(Path.of(path), StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    // ---- commitments and attested-VM statements ---------------------------------------------------------------------------------

    /** The commitment a verifier pins for a policy: the grant's {@code id} when it is a string, else the hash of its canonical JSON. */
    public static String policyCommitment(Object grant) {
        Object id = get(grant, "id");
        return id instanceof String ? (String) id : Pca.hashCanonical(grant);
    }

    /** {@link #policyCommitment}, under the name a verifier uses when it pins a policy out of band. */
    public static String pinnedPolicyCommitment(Object grant) { return policyCommitment(grant); }

    /** The hash of the canonical JSON of the PCActn's {@code action} (of null when it has none). */
    public static String actionCommitment(Object pcactn) { return Pca.hashCanonical(get(pcactn, "action")); }

    private static byte[] statementMessage(Map<String, Object> body) { return Pca.concat(DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body)); }

    private static Object planRoot(Object pcactn) {
        Object root = get(get(pcactn, "plan"), "root");
        return root instanceof String ? root : "";
    }

    /** Signs compliance statements as the attestor of a Policy VM run. */
    public static final class AttestedComplianceProver {
        /** The base64url Ed25519 public key a verifier lists in {@code trustedProverKeys}. */
        public final String publicKey;
        private final Keys.EdKey key;

        AttestedComplianceProver(Keys.EdKey key) {
            this.key = key;
            this.publicKey = key.id();
        }

        /**
         * Runs the Policy VM on {@code decideInput} and, when the action is compliant, returns the signed statement binding the action,
         * the policy and the plan commitment for the window {@code [issuedAt, expiresAt]} (epoch ms). Throws when it is not compliant.
         */
        public Map<String, Object> prove(Map<String, Object> pcactn, Map<String, Object> decideInput, long issuedAt, long expiresAt) {
            Map<String, Object> decision = Decide.decide(decideInput);
            if (!Boolean.TRUE.equals(decision.get("releaseGuardianShare"))) {
                StringBuilder sb = new StringBuilder();
                Object rs = decision.get("reasons");
                if (rs instanceof List) for (Object x : (List<?>) rs) sb.append(sb.length() == 0 ? "" : "; ").append(x);
                throw new IllegalStateException("createAttestedComplianceProver: action is not compliant, nothing to prove (" + sb + ")");
            }
            Double r = StoreJs.dbl(decision.get("r"));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("v", 1L);
            body.put("mode", "attested-vm");
            body.put("action_commit", actionCommitment(pcactn));
            body.put("policy_commit", policyCommitment(decideInput.get("grant")));
            body.put("plan_commit", planRoot(pcactn));
            body.put("released", true);
            body.put("r", r == null ? null : StoreJs.num(r.doubleValue()));
            body.put("issued_at", issuedAt);
            body.put("expires_at", expiresAt);
            body.put("prover", publicKey);
            Map<String, Object> out = new LinkedHashMap<>(body);
            out.put("sig", Pca.b64(key.sign(statementMessage(body))));
            return out;
        }
    }

    /** A prover over a 32-byte Ed25519 seed (the attestor's secret key). */
    public static AttestedComplianceProver createAttestedComplianceProver(byte[] attestorSecret) {
        return new AttestedComplianceProver(Keys.edFromSeed(attestorSecret));
    }

    /** Verifies the proof a PCActn carries against the public inputs the verifier derived itself. */
    public interface SnarkBackend {
        /** {@code publicInputs} holds {@code action_commit}, {@code policy_commit} and {@code plan_commit}. */
        boolean verify(Object proof, Map<String, String> publicInputs, PcaCore.Ctx ctx) throws Exception;
    }

    /** The binding a prover VM's hardware evidence must carry for {@code proverPublicKey}: {@code {holderPub, grantRef, epoch, nonce}}. */
    public static Map<String, Object> proverKeyBinding(String proverPublicKey, Object epoch, String nonce) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("holderPub", proverPublicKey);
        m.put("grantRef", ZK_PROVER_BINDING_REF);
        m.put("epoch", epoch);
        m.put("nonce", nonce);
        return m;
    }

    /** Verifies the hardware evidence of a prover VM: returns {@code {ok, reason?, bound?, measured?: {runtime_measurement}}}. */
    public interface HardwareVerifier {
        Map<String, Object> verify(Map<String, Object> document, PcaCore.Ctx ctx, long nowMs, Map<String, Object> expected) throws Exception;
    }

    /** Requires each statement's prover key to be bound to an allowlisted VM measurement by hardware evidence. */
    public static final class ProverAttestation {
        /** Must carry a {@code hardware} or {@code multi_root} assurance label ({@link Assurance#setLabel}). */
        public HardwareVerifier hardwareVerifier;
        /** The binding expected for a prover key (see {@link #proverKeyBinding}). */
        public Function<String, Map<String, Object>> expectedBinding;
        /** The allowlisted runtime measurements. */
        public List<String> measurements;
    }

    /** Options of {@link #createZkVerifier}; copied at construction, so later edits change nothing. */
    public static final class VerifierOpts {
        public List<String> trustedProverKeys;
        /** Null: the policy commitment is derived from the grant of each call. */
        public List<String> policyCommitments;
        public List<String> revokedProverKeys;
        /** When set, the backend alone decides (statements are not read). */
        public SnarkBackend snarkBackend;
        public ProverAttestation proverAttestation;
        /** Epoch ms; null: the system clock. */
        public LongSupplier now;
        /** Null, negative or non-finite: no skew. */
        public Double clockSkewMs;
    }

    /** The {@code zk_compliance} hook: {@link #check} gives the reference's result, {@link #run} adapts it to the core. */
    public static final class ZkVerifier implements PcaCore.Hook {
        private final Set<String> trusted, revoked, expectedPolicy, measurements;
        private final SnarkBackend snark;
        private final ProverAttestation pa;
        private final LongSupplier clock;
        private final double skew;

        ZkVerifier(VerifierOpts o) {
            trusted = new HashSet<>(o.trustedProverKeys == null ? Collections.<String>emptyList() : o.trustedProverKeys);
            revoked = new HashSet<>(o.revokedProverKeys == null ? Collections.<String>emptyList() : o.revokedProverKeys);
            expectedPolicy = o.policyCommitments == null ? null : new HashSet<>(o.policyCommitments);
            snark = o.snarkBackend;
            ProverAttestation p = snark != null ? null : o.proverAttestation;
            if (p != null) {
                ProverAttestation c = new ProverAttestation();
                c.hardwareVerifier = p.hardwareVerifier;
                c.expectedBinding = p.expectedBinding;
                c.measurements = p.measurements == null ? null : new ArrayList<>(p.measurements);
                p = c;
            }
            pa = p;
            measurements = pa == null ? null : new HashSet<>(pa.measurements);
            clock = o.now != null ? o.now : System::currentTimeMillis;
            Double s = o.clockSkewMs;
            skew = s != null && !s.isNaN() && !s.isInfinite() ? Math.max(0, s) : 0;
        }

        private static Map<String, Object> fail(String reason) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("enforced", true);
            m.put("ok", false);
            m.put("reason", reason);
            return m;
        }

        private static Map<String, Object> pass() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("enforced", true);
            m.put("ok", true);
            return m;
        }

        /** {@code {enforced: true, ok, reason?}} for the proof {@code pcactn} carries under {@code grant}. Never throws: any error is a refusal. */
        public Map<String, Object> check(Map<String, Object> pcactn, Map<String, Object> grant) {
            try {
                Object proof = get(pcactn, "zk_compliance");
                if (proof == null) return fail("no zk_compliance proof present");
                String actionCommit = actionCommitment(pcactn);
                Object planCommit = planRoot(pcactn);
                String grantPolicy = expectedPolicy == null ? policyCommitment(grant) : null;
                long nowMs = clock.getAsLong();
                PcaCore.Ctx ctx = new PcaCore.Ctx(pcactn, grant, nowMs);

                if (snark != null) {
                    String policyCommit = expectedPolicy != null && expectedPolicy.size() == 1 ? expectedPolicy.iterator().next() : policyCommitment(grant);
                    Map<String, String> pub = new LinkedHashMap<>();
                    pub.put("action_commit", actionCommit);
                    pub.put("policy_commit", policyCommit);
                    pub.put("plan_commit", (String) planCommit);
                    return snark.verify(proof, pub, ctx) ? pass() : fail("snark backend rejected the proof");
                }

                Map<String, Object> st = map(proof);
                if (st == null || !isNum(st.get("v"), 1) || !"attested-vm".equals(st.get("mode"))) return fail("unrecognized compliance statement");
                if (!Boolean.TRUE.equals(st.get("released"))) return fail("statement does not assert release");
                Object prover = st.get("prover");
                if (!(prover instanceof String) || !trusted.contains(prover)) return fail("prover key is not trusted");
                if (revoked.contains(prover)) return fail("prover key is revoked");

                Object sig = st.get("sig");
                Map<String, Object> body = new LinkedHashMap<>(st);
                body.remove("sig");
                if (!(sig instanceof String) || !Pca.verifyB64u((String) prover, statementMessage(body), (String) sig)) return fail("compliance statement signature does not verify");

                Object iat = st.get("issued_at"), exp = st.get("expires_at");
                if (!isJsNumber(iat) || !isJsNumber(exp) || !IntentJs.isFinite(iat) || !IntentJs.isFinite(exp) || IntentJs.num(exp) < IntentJs.num(iat)) return fail("malformed statement validity window");
                if (nowMs + skew < IntentJs.num(iat)) return fail("compliance statement not yet valid");
                if (nowMs - skew > IntentJs.num(exp)) return fail("compliance statement expired");

                if (!actionCommit.equals(st.get("action_commit"))) return fail("statement does not bind to this action");
                if (!planCommit.equals(st.get("plan_commit"))) return fail("statement does not bind to this plan commitment");
                Object pc = st.get("policy_commit");
                boolean expected = expectedPolicy != null ? expectedPolicy.contains(pc) : grantPolicy.equals(pc);
                if (!(pc instanceof String) || !expected) return fail("statement policy commitment is not an expected policy");

                if (pa != null) {
                    Map<String, Object> want = pa.expectedBinding.apply((String) prover);
                    Map<String, Object> doc = new LinkedHashMap<>();
                    doc.put("attestor", prover);
                    doc.put("mode", "hardware");
                    Map<String, Object> hw = pa.hardwareVerifier.verify(doc, ctx, nowMs, want);
                    if (hw == null || !Boolean.TRUE.equals(hw.get("ok"))) return fail("prover hardware evidence invalid: " + (hw == null ? "no result" : hw.get("reason") == null ? "no reason given" : hw.get("reason")));
                    if (!Boolean.TRUE.equals(hw.get("bound"))) return fail("prover hardware evidence does not bind the prover key");
                    Object m = get(hw.get("measured"), "runtime_measurement");
                    if (!(m instanceof String)) return fail("prover hardware evidence carries no measured identity");
                    if (!measurements.contains(m)) return fail("prover VM measurement is not allowlisted");
                }
                return pass();
            } catch (Exception e) {
                return fail("zk verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        }

        @Override
        public PcaCore.HookResult run(PcaCore.Ctx ctx) {
            Map<String, Object> r = check(ctx == null ? null : ctx.pcactn, ctx == null ? null : ctx.grant);
            return PcaCore.HookResult.enforced(Boolean.TRUE.equals(r.get("ok")), (String) r.get("reason"), null);
        }
    }

    /**
     * The {@code zk_compliance} verifier. With no SNARK backend it accepts attested-VM statements signed by a trusted, unrevoked prover
     * key that are inside their validity window and bind this action, this plan commitment and an expected policy. Its assurance label
     * is the backend's, {@code attested_vm_hw} with prover attestation, else {@code attested_vm}.
     */
    public static ZkVerifier createZkVerifier(VerifierOpts opts) {
        ProverAttestation pa = opts.snarkBackend != null ? null : opts.proverAttestation;
        Assurance.Label hw = null;
        if (pa != null) {
            hw = Assurance.labelOf(pa.hardwareVerifier);
            if (hw == null || (!"hardware".equals(hw.level) && !"multi_root".equals(hw.level))) throw new IllegalArgumentException("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label");
            boolean ok = pa.measurements != null && !pa.measurements.isEmpty();
            if (ok) for (String m : pa.measurements) ok = ok && m != null && !m.isEmpty();
            if (!ok) throw new IllegalArgumentException("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist");
            if (pa.expectedBinding == null) throw new IllegalArgumentException("createZkVerifier: proverAttestation.expectedBinding must be a function");
        }
        Assurance.Label label;
        if (opts.snarkBackend != null) {
            Assurance.Label l = Assurance.labelOf(opts.snarkBackend);
            label = l != null ? l : Assurance.Label.of("unknown");
        } else if (hw != null) {
            label = Assurance.Label.of("attested_vm_hw").vendor("hardware-bound:" + (hw.vendor != null ? hw.vendor : hw.level));
        } else {
            label = Assurance.Label.of("attested_vm");
        }
        return Assurance.setLabel(new ZkVerifier(opts), label);
    }

    // ---- field elements and the canonical envelope gate ---------------------------------------------------------------------------

    private static final BigInteger BN254_FR = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    private static final BigInteger BN254_FQ = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    private static final BigInteger BLS12381_FQ = new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private static final BigInteger BLS12381_FR = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /** A base64url commitment (bytes of any length) as a BN254 scalar-field element, in decimal. Throws on text that is not canonical base64url. */
    public static String commitmentField(Object b64uCommit) {
        if (!(b64uCommit instanceof String)) throw new IllegalArgumentException("commitmentField: string expected");
        return new BigInteger(1, Keys.unb64u((String) b64uCommit)).mod(BN254_FR).toString();
    }

    private static boolean canonDecBelow(Object v, BigInteger bound) {
        if (!(v instanceof String)) return false;
        String s = (String) v;
        return s.length() <= 120 && CANON_DEC.matcher(s).matches() && new BigInteger(s).compareTo(bound) < 0;
    }

    private static boolean sameKeys(Map<?, ?> o, String... keys) { return o.size() == keys.length && o.keySet().containsAll(Arrays.asList(keys)); }

    private static boolean g1(Object a, BigInteger fq) {
        if (!(a instanceof List)) return false;
        List<?> l = (List<?>) a;
        return l.size() == 3 && canonDecBelow(l.get(0), fq) && canonDecBelow(l.get(1), fq) && "1".equals(l.get(2));
    }

    /**
     * Is {@code env} a Groth16 envelope in the one canonical encoding: exactly {@code system, circuit, proof, publicSignals}; every signal a
     * decimal string with no leading zero below the scalar field; the proof exactly {@code pi_a, pi_b, pi_c, protocol, curve} with affine
     * points whose coordinates are canonical decimals below the base field? {@code curve} is {@code "bn254"}, anything else is BLS12-381.
     */
    public static boolean isCanonicalGroth16Envelope(Object env, Object curve) {
        if (!(env instanceof Map)) return false;
        Map<?, ?> e = (Map<?, ?>) env;
        if (!sameKeys(e, "system", "circuit", "proof", "publicSignals")) return false;
        boolean bn = "bn254".equals(curve);
        BigInteger fq = bn ? BN254_FQ : BLS12381_FQ, fr = bn ? BN254_FR : BLS12381_FR;
        if (!(e.get("publicSignals") instanceof List)) return false;
        for (Object x : (List<?>) e.get("publicSignals")) if (!canonDecBelow(x, fr)) return false;
        if (!(e.get("proof") instanceof Map)) return false;
        Map<?, ?> pr = (Map<?, ?>) e.get("proof");
        if (!sameKeys(pr, "pi_a", "pi_b", "pi_c", "protocol", "curve")) return false;
        if (!"groth16".equals(pr.get("protocol")) || !(bn ? "bn128" : "bls12381").equals(pr.get("curve"))) return false;
        if (!g1(pr.get("pi_a"), fq) || !g1(pr.get("pi_c"), fq)) return false;
        if (!(pr.get("pi_b") instanceof List) || ((List<?>) pr.get("pi_b")).size() != 3) return false;
        List<?> b = (List<?>) pr.get("pi_b");
        for (int i = 0; i < 2; i++) {
            if (!(b.get(i) instanceof List)) return false;
            List<?> row = (List<?>) b.get(i);
            if (row.size() != 2 || !canonDecBelow(row.get(0), fq) || !canonDecBelow(row.get(1), fq)) return false;
        }
        if (!(b.get(2) instanceof List)) return false;
        List<?> z = (List<?>) b.get(2);
        return z.size() == 2 && "1".equals(z.get(0)) && "0".equals(z.get(1));
    }

    // ---- the first circuit (pca-compliance-v1) ------------------------------------------------------------------------------------

    private static final int C_SHA_POLICY = 3, C_SHA_PLAN = 4, C_SHA_ACTION = 5, C_ALLOW = 6, C_COUNT = 7;

    /** Where the reference package keeps its build artifacts, relative to the package root. A jar ships none of the {@code build} files. */
    public static final String DEFAULT_VKEY_PATH = "circuits/build/verification_key.json";
    public static final String DEFAULT_WASM_PATH = "circuits/build/compliance_js/compliance.wasm";
    public static final String DEFAULT_ZKEY_PATH = "circuits/build/compliance_final.zkey";
    public static final String POLICYVM_VKEY_PATH = "circuits/policyvm_vkey.json";
    public static final String POLICYVM_SAMPLE_PROOF_PATH = "circuits/policyvm_sample_proof.json";
    public static final String POLICYVM_WASM_PATH = "circuits/build/policyvm_js/policyvm.wasm";
    public static final String POLICYVM_ZKEY_PATH = "circuits/build/policyvm_final.zkey";
    public static final String POLICYVM_BLS12381_VKEY_PATH = "circuits/policyvm_bls12381_vkey.json";
    public static final String POLICYVM_BLS12381_SAMPLE_PROOF_PATH = "circuits/policyvm_bls12381_sample_proof.json";
    public static final String POLICYVM_BOUND_VKEY_PATH = "circuits/build/policyvm_bound_vkey.json";
    public static final String POLICYVM_BOUND_SAMPLE_PROOF_PATH = "circuits/build/policyvm_bound_sample_proof.json";
    public static final String POLICYVM_BOUND_WASM_PATH = "circuits/build/policyvm_bound_js/policyvm_bound.wasm";
    public static final String POLICYVM_BOUND_ZKEY_PATH = "circuits/build/policyvm_bound_final.zkey";

    /** The committed Policy VM verification key (pca-policyvm-v1) on BN254, as parsed snarkjs JSON. */
    public static Object policyVmVerificationKey() { return Json.parseLenient(ZkBundled.POLICYVM_VKEY_JSON); }

    /** The committed Policy VM verification key (pca-policyvm-v1) on BLS12-381, as parsed snarkjs JSON. */
    public static Object policyVmVerificationKeyBls12381() { return Json.parseLenient(ZkBundled.POLICYVM_BLS12381_VKEY_JSON); }

    /** {@code opts.verificationKey}, else the JSON file at {@code opts.verificationKeyPath}, else the committed key of the circuit (if any). */
    private static Object vkeyOf(Map<String, Object> opts, String bundled, String circuit) {
        Object k = opts == null ? null : opts.get("verificationKey");
        if (k != null) return k;
        Object path = opts == null ? null : opts.get("verificationKeyPath");
        if (path != null) return readJsonFile((String) path);
        if (bundled == null) throw new IllegalStateException("no committed verification key for " + circuit + ": pass verificationKey or verificationKeyPath");
        return Json.parseLenient(bundled);
    }

    private static Supplier<Object> lazyVkey(Map<String, Object> opts, String bundled, String circuit) {
        Object[] cached = new Object[1];
        return () -> {
            synchronized (cached) {
                if (cached[0] == null) cached[0] = vkeyOf(opts, bundled, circuit);
                return cached[0];
            }
        };
    }

    private static String ceremonyLabel(Map<String, Object> opts, String circuit) {
        Object c = opts == null ? null : opts.get("ceremony");
        Object evidence = null;
        if (truthy(c)) {
            Map<String, Object> ev = map(c) == null ? new LinkedHashMap<>() : new LinkedHashMap<>(map(c));
            ev.put("circuit", circuit);
            evidence = ev;
        }
        return ZkCeremony.ceremonyOf(opts == null ? null : opts.get("verificationKey"), evidence);
    }

    /**
     * The backend of the first circuit (pca-compliance-v1, BN254): the envelope's SHA tags must be the field elements of the verifier's
     * own commitments. {@code opts} (nullable): {@code verificationKey} | {@code verificationKeyPath} (no key is committed for this
     * circuit) and {@code ceremony}. Label {@code groth16}.
     */
    public static SnarkBackend createGroth16SnarkBackend(Map<String, Object> opts) {
        Supplier<Object> vkey = lazyVkey(opts, null, "pca-compliance-v1");
        SnarkBackend b = new SnarkBackend() {
            @Override public boolean verify(Object proof, Map<String, String> pub, PcaCore.Ctx ctx) {
                Map<String, Object> env = map(proof);
                if (env == null) return false;
                if (!"groth16-bn254".equals(env.get("system")) || !"pca-compliance-v1".equals(env.get("circuit"))) return false;
                Object g16 = env.get("proof");
                if (!(env.get("publicSignals") instanceof List) || ((List<?>) env.get("publicSignals")).size() != C_COUNT || g16 == null) return false;
                List<?> ps = (List<?>) env.get("publicSignals");
                if (!"1".equals(ps.get(C_ALLOW))) return false;
                if (!commitmentField(pub.get("policy_commit")).equals(ps.get(C_SHA_POLICY))) return false;
                if (!commitmentField(pub.get("plan_commit")).equals(ps.get(C_SHA_PLAN))) return false;
                if (!commitmentField(pub.get("action_commit")).equals(ps.get(C_SHA_ACTION))) return false;
                if (!isCanonicalGroth16Envelope(env, "bn254")) return false;
                return engine().verify(vkey.get(), ps, g16);
            }
        };
        return Assurance.setLabel(b, Assurance.Label.of("groth16").ceremony(ceremonyLabel(opts, "pca-compliance-v1")));
    }

    /** JavaScript {@code String(v)} of a circuit input. */
    private static String text(Object v) { return v instanceof String ? (String) v : v instanceof BigInteger ? v.toString() : IntentRevocation.jsText(v, true); }

    private static Map<String, Object> envelope(String system, String circuit, Map<String, Object> proved) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("system", system);
        out.put("circuit", circuit);
        out.put("proof", proved.get("proof"));
        out.put("publicSignals", proved.get("publicSignals"));
        return out;
    }

    private static String need(Map<String, Object> opts, String key) {
        Object v = opts == null ? null : opts.get(key);
        if (!(v instanceof String)) throw new IllegalArgumentException("zk prove: opts." + key + " is required (no circuit build is shipped with this library)");
        return (String) v;
    }

    /**
     * Proves the first circuit: {@code inp} holds the three commitments and the private inputs {@code verb, resource, planVerb,
     * policySalt, planSalt, actionSalt, risk, budget}. {@code opts}: {@code wasmPath} and {@code zkeyPath} of the circuit build.
     */
    public static Map<String, Object> proveGroth16Compliance(Map<String, Object> inp, Map<String, Object> opts) {
        Map<String, Object> input = new LinkedHashMap<>();
        for (String k : new String[] {"verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget"}) input.put(k, text(inp.get(k)));
        input.put("shaPolicy", commitmentField(inp.get("policy_commit")));
        input.put("shaPlan", commitmentField(inp.get("plan_commit")));
        input.put("shaAction", commitmentField(inp.get("action_commit")));
        input.put("allow", "1");
        return envelope("groth16-bn254", "pca-compliance-v1", engine().fullProve("bn128", input, need(opts, "wasmPath"), need(opts, "zkeyPath")));
    }

    // ---- the Policy VM circuits ---------------------------------------------------------------------------------------------------

    private static Map<String, Integer> table(Object... kv) {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], (Integer) kv[i + 1]);
        return Collections.unmodifiableMap(m);
    }

    /** The index of each public signal of pca-policyvm-v1. */
    public static final Map<String, Integer> POLICYVM_PUBLIC_SIGNAL = table("actionHi", 0, "actionLo", 1, "policyHi", 2, "policyLo", 3, "planHi", 4, "planLo", 5,
        "r", 6, "t", 7, "admit", 8, "allow", 9, "now", 10, "blast", 11, "delegationDepth", 12, "recentCount", 13, "allocChild", 14);
    public static final int POLICYVM_PUBLIC_SIGNAL_COUNT = 15;
    /** The index of each public signal of the risk-bound circuit pca-policyvm-v2. */
    public static final Map<String, Integer> POLICYVM_BOUND_PUBLIC_SIGNAL = table("actionHi", 0, "actionLo", 1, "policyHi", 2, "policyLo", 3, "planHi", 4, "planLo", 5,
        "r", 6, "t", 7, "admit", 8, "riskHi", 9, "riskLo", 10, "allow", 11, "now", 12, "blast", 13, "delegationDepth", 14, "recentCount", 15, "allocChild", 16);
    public static final int POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17;
    public static final List<String> POLICYVM_BOUND_RISK_FIELDS = Collections.unmodifiableList(Arrays.asList("revScore", "taint", "conf", "age", "rFloorIn"));
    public static final List<String> POLICYVM_REVERSIBILITY_ORDER = Collections.unmodifiableList(Arrays.asList("reversible", "rate_limited", "irreversible"));

    /**
     * SHA-256 over the fields as 8-byte big-endian uint64, split into two 128-bit halves in decimal: {@code {hi, lo}}. A field is a number,
     * a {@link BigInteger} or integer text; one outside {@code [0, 2^64)} or not an integer throws.
     */
    public static Map<String, Object> policyVmStructHash(Object fields) {
        if (!(fields instanceof List)) throw new IllegalArgumentException("policyVmStructHash: fields must be a list");
        List<?> fs = (List<?>) fields;
        byte[] bytes = new byte[fs.size() * 8];
        for (int idx = 0; idx < fs.size(); idx++) {
            BigInteger v = jsBigInt(fs.get(idx));
            if (v.signum() < 0 || v.compareTo(U64_BOUND) >= 0) throw new IllegalArgumentException("policyVmStructHash: field out of uint64 range");
            long w = v.longValue();
            for (int b = 7; b >= 0; b--) {
                bytes[idx * 8 + b] = (byte) (w & 0xff);
                w >>>= 8;
            }
        }
        byte[] d = Pca.sha(bytes);
        return halves(new BigInteger(1, Arrays.copyOfRange(d, 0, 16)).toString(), new BigInteger(1, Arrays.copyOfRange(d, 16, 32)).toString());
    }

    /** {@link #policyVmStructHash} of exactly the five risk fields ({@link #POLICYVM_BOUND_RISK_FIELDS}). */
    public static Map<String, Object> policyVmRiskHash(Object fields) {
        if (!(fields instanceof List) || ((List<?>) fields).size() != POLICYVM_BOUND_RISK_FIELDS.size()) throw new IllegalArgumentException("policyVmRiskHash: need exactly 5 risk fields");
        return policyVmStructHash(fields);
    }

    private static Map<String, Object> half(List<?> ps, int hi, int lo) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (hi < ps.size()) m.put("hi", ps.get(hi));
        if (lo < ps.size()) m.put("lo", ps.get(lo));
        return m;
    }

    private static Map<String, Object> decode(Object publicSignals, Map<String, Integer> p, boolean bound) {
        if (!(publicSignals instanceof List)) throw new IllegalArgumentException("decodePolicyVmPublic: publicSignals must be a list");
        List<?> ps = (List<?>) publicSignals;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("actionHash", half(ps, p.get("actionHi"), p.get("actionLo")));
        out.put("policyHash", half(ps, p.get("policyHi"), p.get("policyLo")));
        out.put("planHash", half(ps, p.get("planHi"), p.get("planLo")));
        if (bound) out.put("riskHash", half(ps, p.get("riskHi"), p.get("riskLo")));
        for (String k : new String[] {"r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild"}) if (p.get(k) < ps.size()) out.put(k, ps.get(p.get(k)));
        return out;
    }

    /** The public signals of a pca-policyvm-v1 proof by name (a missing signal is left out). */
    public static Map<String, Object> decodePolicyVmPublic(Object publicSignals) { return decode(publicSignals, POLICYVM_PUBLIC_SIGNAL, false); }

    /** The public signals of a pca-policyvm-v2 proof by name, with {@code riskHash}. */
    public static Map<String, Object> decodePolicyVmBoundPublic(Object publicSignals) { return decode(publicSignals, POLICYVM_BOUND_PUBLIC_SIGNAL, true); }

    /** The pinned source hash and toolchain of a circuit: {@code {circuit, sourceSha256, circom, circomlib}}. Throws on an unknown id. */
    public static Map<String, Object> circuitVersion(Object id) {
        Map<String, Object> v = map(Json.parseLenient(ZkBundled.CIRCUIT_VERSIONS_JSON));
        Map<String, Object> c = id instanceof String ? map(map(v.get("circuits")).get(id)) : null;
        if (c == null) throw new IllegalArgumentException("circuitVersion: unknown circuit " + (id instanceof String ? Json.canonicalize(id) : String.valueOf(id)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("circuit", id);
        out.put("sourceSha256", c.get("source_sha256"));
        out.put("circom", v.get("circom"));
        out.put("circomlib", v.get("circomlib"));
        return out;
    }

    // ---- quantization: wire action / plan / policy to the circuit's uint64 structs ----------------------------------------------------

    private static BigInteger contentAddressU64(String domain, String value) {
        byte[] d = Pca.sha(("atlas-pca/policyvm-quantize/" + domain + ":" + value).getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, Arrays.copyOfRange(d, 0, 8));
    }

    private static BigInteger toU64(Object v, String what) {
        BigInteger b = v instanceof BigInteger ? (BigInteger) v : isJsNumber(v) ? integerOf(v) : null;
        if (b == null || b.signum() < 0 || b.compareTo(U64_BOUND) >= 0) throw new IllegalArgumentException("policyvm quantize: " + what + " is not a uint64");
        return b;
    }

    private static BigInteger codeFor(String domain, Object value, Object codes, boolean strict) {
        if (!(value instanceof String)) throw new IllegalArgumentException("policyvm quantize: " + domain + " must be a string");
        if (has(codes, (String) value)) return toU64(get(codes, (String) value), domain + " code");
        if (strict) throw new IllegalArgumentException("policyvm quantize: " + domain + " \"" + value + "\" is not in the catalog (strict)");
        return contentAddressU64(domain, (String) value);
    }

    private static BigInteger paramScalarFrom(Object params, Object field) {
        if (!(field instanceof String) || ((String) field).isEmpty()) return BigInteger.ZERO;
        String f = (String) field;
        if (!has(params, f)) {
            // a name every JavaScript object inherits reads as a function in the reference: not a scalar
            if (params instanceof Map && OBJECT_PROTOTYPE_KEYS.contains(f)) throw new IllegalArgumentException("policyvm quantize: paramScalar is not a non-negative integer");
            return BigInteger.ZERO;
        }
        Object v = get(params, f);
        if (v == null) return BigInteger.ZERO;
        if (v instanceof BigInteger) return toU64(v, "paramScalar");
        if (isJsNumber(v)) {
            Double d = IntentJs.num(v);
            if (integerOf(v) == null || d < 0 || IntentJs.isNegZero(d)) throw new IllegalArgumentException("policyvm quantize: paramScalar must be a non-negative integer");
            return toU64(v, "paramScalar");
        }
        if (v instanceof String && DIGITS.matcher((String) v).matches()) return toU64(new BigInteger((String) v), "paramScalar");
        throw new IllegalArgumentException("policyvm quantize: paramScalar is not a non-negative integer");
    }

    private static BigInteger reversibilityIndex(Object rc, String what) {
        int idx = rc instanceof String ? POLICYVM_REVERSIBILITY_ORDER.indexOf(rc) : -1;
        if (idx < 0) throw new IllegalArgumentException("policyvm quantize: unknown " + what + " class \"" + rc + "\"");
        return BigInteger.valueOf(idx);
    }

    private static boolean strict(Map<String, Object> opts) { return opts != null && Boolean.TRUE.equals(opts.get("strictCatalog")); }

    /**
     * {@code [verb, resource, reversibility, paramScalar]} of an action ({@code {verb, resource, reversibility_class?, params?}}). A verb
     * or resource is its catalog code ({@code opts.verbCodes} / {@code opts.resourceCodes}), else a content-addressed uint64 (or a refusal
     * with {@code opts.strictCatalog}); {@code opts.paramScalarField} names the parameter the circuit bounds. {@code opts} may be null.
     */
    public static List<BigInteger> quantizeActionStruct(Object action, Map<String, Object> opts) {
        if (!(action instanceof Map)) throw new IllegalArgumentException("policyvm quantize: action is missing");
        boolean st = strict(opts);
        BigInteger verb = codeFor("verb", get(action, "verb"), opts == null ? null : opts.get("verbCodes"), st);
        BigInteger resource = codeFor("resource", get(action, "resource"), opts == null ? null : opts.get("resourceCodes"), st);
        Object rc = get(action, "reversibility_class");
        BigInteger rev = reversibilityIndex(rc == null ? "reversible" : rc, "reversibility");
        return Arrays.asList(verb, resource, rev, paramScalarFrom(get(action, "params"), opts == null ? null : opts.get("paramScalarField")));
    }

    /** {@code [verb, resource, semanticDist, planSalt]} of a plan node. */
    public static List<BigInteger> quantizePlanStruct(Object plan, Map<String, Object> opts) {
        if (!(plan instanceof Map)) throw new IllegalArgumentException("policyvm quantize: plan is missing");
        boolean st = strict(opts);
        return Arrays.asList(
            codeFor("verb", get(plan, "verb"), opts == null ? null : opts.get("verbCodes"), st),
            codeFor("resource", get(plan, "resource"), opts == null ? null : opts.get("resourceCodes"), st),
            toU64(get(plan, "semanticDist"), "semanticDist"),
            toU64(get(plan, "planSalt"), "planSalt"));
    }

    /** The 20 policy fields in circuit order (weights, thresholds, budget, the policy's verb and resource, bounds, validity, limits). */
    public static List<BigInteger> quantizePolicyStruct(Object policy, Map<String, Object> opts) {
        if (!(policy instanceof Map) || !(get(policy, "weights") instanceof Map)) throw new IllegalArgumentException("policyvm quantize: policy or its weights are missing");
        boolean st = strict(opts);
        Object w = get(policy, "weights");
        List<BigInteger> out = new ArrayList<>();
        for (String k : new String[] {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}) out.add(toU64(get(w, k), "w" + Character.toUpperCase(k.charAt(0)) + k.substring(1)));
        for (String k : new String[] {"theta1", "theta2", "kappa", "budgetB"}) out.add(toU64(get(policy, k), k));
        out.add(codeFor("verb", get(policy, "policyVerb"), opts == null ? null : opts.get("verbCodes"), st));
        out.add(codeFor("resource", get(policy, "policyResource"), opts == null ? null : opts.get("resourceCodes"), st));
        for (String k : new String[] {"policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth"}) out.add(toU64(get(policy, k), k));
        out.add(reversibilityIndex(get(policy, "revMax"), "revMax"));
        for (String k : new String[] {"rateMax", "allocParent"}) out.add(toU64(get(policy, k), k));
        return out;
    }

    /** {@code {action, plan?, policy?}} quantized: the structs of the parts {@code inp} carries. */
    public static Map<String, List<BigInteger>> quantizePolicyVmInputs(Map<String, Object> inp, Map<String, Object> opts) {
        Map<String, List<BigInteger>> out = new LinkedHashMap<>();
        out.put("action", quantizeActionStruct(inp.get("action"), opts));
        if (truthy(inp.get("plan"))) out.put("plan", quantizePlanStruct(inp.get("plan"), opts));
        if (truthy(inp.get("policy"))) out.put("policy", quantizePolicyStruct(inp.get("policy"), opts));
        return out;
    }

    /** The action hash halves a verifier pins ({@code expectActionHash}), from the wire action. */
    public static Map<String, Object> policyVmCommitmentFromAction(Object action, Map<String, Object> opts) { return policyVmStructHash(quantizeActionStruct(action, opts)); }

    // ---- context pins ---------------------------------------------------------------------------------------------------------------

    private static BigInteger pinBigint(Object v) {
        try {
            if (isJsNumber(v) && !IntentJs.isSafeInteger(v)) return null;
            return jsBigInt(v);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean signalMatchesPin(Object signal, Object pin) {
        if (!(signal instanceof String) || !CANON_DEC.matcher((String) signal).matches()) return false;
        BigInteger x = new BigInteger((String) signal);
        if (pin == null) throw new IllegalArgumentException("policyVmContextMatches: a pin is null");
        if (pin instanceof Map || pin instanceof List) {
            BigInteger lo = pinBigint(get(pin, "min")), hi = pinBigint(get(pin, "max"));
            return lo != null && hi != null && lo.compareTo(hi) <= 0 && x.compareTo(lo) >= 0 && x.compareTo(hi) <= 0;
        }
        BigInteger want = pinBigint(pin);
        return want != null && x.equals(want);
    }

    private static boolean contextMatches(List<?> ps, boolean hasExpect, Object expectSrc, boolean bound) {
        Map<String, Integer> p = bound ? POLICYVM_BOUND_PUBLIC_SIGNAL : POLICYVM_PUBLIC_SIGNAL;
        for (String k : new String[] {"now", "blast", "delegationDepth", "recentCount", "allocChild"}) {
            Object sig = p.get(k) < ps.size() ? ps.get(p.get(k)) : null;
            if (!(sig instanceof String) || !CANON_DEC.matcher((String) sig).matches() || new BigInteger((String) sig).compareTo(U64_BOUND) >= 0) return false;
        }
        if (!hasExpect) return true;
        Object e;
        try {
            e = expectSrc instanceof Supplier ? ((Supplier<?>) expectSrc).get() : expectSrc;
        } catch (RuntimeException ex) {
            return false;
        }
        if (!(e instanceof Map) && !(e instanceof List)) return false;
        for (String k : new String[] {"now", "blast", "delegationDepth", "recentCount", "allocChild", "r", "t"}) {
            if (has(e, k) && !signalMatchesPin(p.get(k) < ps.size() ? ps.get(p.get(k)) : null, get(e, k))) return false;
        }
        if (truthy(get(e, "requireAdmit")) && !"1".equals(p.get("admit") < ps.size() ? ps.get(p.get("admit")) : null)) return false;
        if (truthy(get(e, "requireTier1")) && !"1".equals(p.get("t") < ps.size() ? ps.get(p.get("t")) : null)) return false;
        return true;
    }

    /** The context signals of a v1 proof are in range (each below 2^64); no pins. */
    public static boolean policyVmContextMatches(List<?> publicSignals) { return contextMatches(publicSignals, false, null, false); }

    /**
     * The context signals are in range and equal the verifier's own values. {@code expect} is a map of pins ({@code now, blast,
     * delegationDepth, recentCount, allocChild, r, t}: an exact value or {@code {min, max}}; {@code requireAdmit}, {@code requireTier1}) or
     * a {@link Supplier} of one, read at call time; a supplier that throws, or anything that is not a map, matches nothing. {@code bound}
     * selects the pca-policyvm-v2 signal layout.
     */
    public static boolean policyVmContextMatches(List<?> publicSignals, Object expect, boolean bound) { return contextMatches(publicSignals, true, expect, bound); }

    /** As above with no pins, for the layout {@code bound} selects. */
    public static boolean policyVmContextMatches(List<?> publicSignals, boolean bound) { return contextMatches(publicSignals, false, null, bound); }

    // ---- Policy VM proof verification -----------------------------------------------------------------------------------------------

    /**
     * Verifies a Policy VM proof envelope ({@code {system, circuit, proof, publicSignals}}; circuit pca-policyvm-v1 on BN254 or BLS12-381,
     * or the risk-bound pca-policyvm-v2 on BN254). {@code opts} (nullable): {@code verificationKey} | {@code verificationKeyPath} (default:
     * the committed key of the proof's curve; v2 has none), {@code expect} (context pins, see {@link #policyVmContextMatches}) and
     * {@code expectRiskHash} ({@code {hi, lo}}, v2 only). False for anything but a valid, canonical, in-context proof.
     */
    public static boolean verifyPolicyVmProof(Object env, Map<String, Object> opts) {
        Map<String, Object> p = map(env);
        if (p == null) return false;
        boolean bound = "pca-policyvm-v2".equals(p.get("circuit"));
        if (!"pca-policyvm-v1".equals(p.get("circuit")) && !bound) return false;
        boolean isBls = "groth16-bls12-381".equals(p.get("system"));
        if (!"groth16-bn254".equals(p.get("system")) && !(isBls && !bound)) return false; // the risk-bound circuit is BN254 only
        Map<String, Integer> layout = bound ? POLICYVM_BOUND_PUBLIC_SIGNAL : POLICYVM_PUBLIC_SIGNAL;
        if (!(p.get("publicSignals") instanceof List)) return false;
        List<?> ps = (List<?>) p.get("publicSignals");
        if (ps.size() != (bound ? POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT : POLICYVM_PUBLIC_SIGNAL_COUNT) || p.get("proof") == null) return false;
        if (!"1".equals(ps.get(layout.get("allow")))) return false;
        if (opts != null && opts.containsKey("expectRiskHash")) {
            Object want = opts.get("expectRiskHash");
            if (want == null) throw new IllegalArgumentException("verifyPolicyVmProof: expectRiskHash is null");
            if (!bound || !same(ps.get(9), want, "hi") || !same(ps.get(10), want, "lo")) return false;
        }
        if (!isCanonicalGroth16Envelope(p, isBls ? "bls12-381" : "bn254")) return false;
        if (!contextMatches(ps, opts != null && opts.containsKey("expect"), opts == null ? null : opts.get("expect"), bound)) return false;
        Object vkey = vkeyOf(opts, bound ? null : isBls ? ZkBundled.POLICYVM_BLS12381_VKEY_JSON : ZkBundled.POLICYVM_VKEY_JSON, bound ? "pca-policyvm-v2" : "pca-policyvm-v1");
        Groth16Engine e = engine();
        try {
            return e.verify(vkey, ps, p.get("proof"));
        } catch (BackendMissing missing) {
            throw missing;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** {@code signal === want[k]} for a string signal. */
    private static boolean same(Object signal, Object want, String k) { return signal instanceof String && signal.equals(get(want, k)); }

    private static boolean halvesMatch(List<?> ps, int hi, int lo, Map<String, Object> opts, String key) {
        Object want = opts == null ? null : opts.get(key);
        if (!truthy(want)) return true;
        return hi < ps.size() && lo < ps.size() && same(ps.get(hi), want, "hi") && same(ps.get(lo), want, "lo");
    }

    private static Map<String, Object> verifyOpts(Object vkey, Map<String, Object> opts, boolean risk) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("verificationKey", vkey);
        if (opts != null && opts.containsKey("expect")) o.put("expect", opts.get("expect"));
        if (risk && opts != null && opts.containsKey("expectRiskHash")) o.put("expectRiskHash", opts.get("expectRiskHash"));
        return o;
    }

    private static boolean pinned(Map<String, Object> opts, String... keys) {
        for (String k : keys) if (opts == null || !truthy(opts.get(k))) return false;
        return true;
    }

    private static SnarkBackend policyVmBackend(Map<String, Object> opts, String bundled) {
        Supplier<Object> vkey = lazyVkey(opts, bundled, "pca-policyvm-v1");
        SnarkBackend b = new SnarkBackend() {
            @Override public boolean verify(Object proof, Map<String, String> pub, PcaCore.Ctx ctx) {
                Map<String, Object> env = map(proof);
                if (env == null || !"pca-policyvm-v1".equals(env.get("circuit"))) return false;
                if (env.get("publicSignals") instanceof List) {
                    List<?> ps = (List<?>) env.get("publicSignals");
                    if (!halvesMatch(ps, 0, 1, opts, "expectActionHash") || !halvesMatch(ps, 2, 3, opts, "expectPolicyHash") || !halvesMatch(ps, 4, 5, opts, "expectPlanHash")) return false;
                }
                return verifyPolicyVmProof(env, verifyOpts(vkey.get(), opts, false));
            }
        };
        String ceremony = ceremonyLabel(opts, "pca-policyvm-v1");
        Assurance.Label label = pinned(opts, "expectActionHash", "expectPolicyHash", "expectPlanHash")
            ? Assurance.Label.of("policyvm_snark").ceremony(ceremony) : Assurance.Label.of("unknown").vendor("policyvm-unbound").ceremony(ceremony);
        return Assurance.setLabel(b, label);
    }

    /**
     * The Policy VM backend on BN254. {@code opts} (nullable): the {@link #verifyPolicyVmProof} options plus {@code expectActionHash},
     * {@code expectPolicyHash}, {@code expectPlanHash} ({@code {hi, lo}} halves the verifier derived from the wire values) and
     * {@code ceremony} ({@code {transcript, sha256}}). The label is {@code policyvm_snark} only when all three hashes are pinned.
     */
    public static SnarkBackend createPolicyVmSnarkBackend(Map<String, Object> opts) { return policyVmBackend(opts, ZkBundled.POLICYVM_VKEY_JSON); }

    /** {@link #createPolicyVmSnarkBackend} with the committed BLS12-381 key as the default. */
    public static SnarkBackend createPolicyVmSnarkBackendBls12381(Map<String, Object> opts) { return policyVmBackend(opts, ZkBundled.POLICYVM_BLS12381_VKEY_JSON); }

    /**
     * The risk-bound Policy VM backend (pca-policyvm-v2, BN254; no key is committed, so {@code verificationKey} or
     * {@code verificationKeyPath} is needed). Adds {@code expectRiskHash}; the label is {@code policyvm_snark} only with all four pinned.
     */
    public static SnarkBackend createPolicyVmBoundSnarkBackend(Map<String, Object> opts) {
        Supplier<Object> vkey = lazyVkey(opts, null, "pca-policyvm-v2");
        SnarkBackend b = new SnarkBackend() {
            @Override public boolean verify(Object proof, Map<String, String> pub, PcaCore.Ctx ctx) {
                Map<String, Object> env = map(proof);
                if (env == null || !"pca-policyvm-v2".equals(env.get("circuit")) || !(env.get("publicSignals") instanceof List)) return false;
                List<?> ps = (List<?>) env.get("publicSignals");
                if (!halvesMatch(ps, 0, 1, opts, "expectActionHash") || !halvesMatch(ps, 2, 3, opts, "expectPolicyHash") || !halvesMatch(ps, 4, 5, opts, "expectPlanHash")
                    || !halvesMatch(ps, 9, 10, opts, "expectRiskHash")) return false;
                return verifyPolicyVmProof(env, verifyOpts(vkey.get(), opts, true));
            }
        };
        String ceremony = ceremonyLabel(opts, "pca-policyvm-v2");
        Assurance.Label label = pinned(opts, "expectActionHash", "expectPolicyHash", "expectPlanHash", "expectRiskHash")
            ? Assurance.Label.of("policyvm_snark").ceremony(ceremony) : Assurance.Label.of("unknown").vendor("policyvm-unbound").ceremony(ceremony);
        return Assurance.setLabel(b, label);
    }

    private static Map<String, Object> proveWitness(Map<String, Object> witness, Map<String, Object> opts, String circuit) {
        Map<String, Object> input = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : witness.entrySet()) input.put(e.getKey(), text(e.getValue()));
        return envelope("groth16-bn254", circuit, engine().fullProve("bn128", input, need(opts, "wasmPath"), need(opts, "zkeyPath")));
    }

    /** Proves pca-policyvm-v1 (BN254) for a full witness. {@code opts}: {@code wasmPath} and {@code zkeyPath} of the circuit build. */
    public static Map<String, Object> provePolicyVmCompliance(Map<String, Object> witness, Map<String, Object> opts) { return proveWitness(witness, opts, "pca-policyvm-v1"); }

    /** Proves the risk-bound pca-policyvm-v2 (BN254) for a full witness. */
    public static Map<String, Object> provePolicyVmBoundCompliance(Map<String, Object> witness, Map<String, Object> opts) { return proveWitness(witness, opts, "pca-policyvm-v2"); }
}
