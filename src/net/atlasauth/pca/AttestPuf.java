package net.atlasauth.pca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * An unclonable-device attestation root. A physically unclonable function (PUF) is noisy, so its response is not a key; a
 * code-offset secure sketch over a repetition code (a fuzzy extractor) turns a noisy response into a stable 32-byte secret, which is the
 * device's signing seed (Ed25519, ML-DSA-65 or ML-DSA-87). Enrollment stores only public helper data and the derived public key; the
 * device attestor re-derives the seed from a fresh noisy response and signs a statement bound to holder, grant, epoch and nonce; the
 * verifier resolves the enrollment, checks the statement under the enrolled key and applies the measurement policy. A response beyond the
 * correction bound reproduces a DIFFERENT key, so a wrong or cloned device fails at the signature, never by an exception.
 * HONEST SCOPE: the measurements are asserted by the device software; the root proves a physical device vouched for them, not silicon-
 * measured weights ({@code weights_measured} is always false).
 *
 * <p>A response is a byte array with ONE 0/1 value per bit. Enrollments, helper data and statements are decoded JSON (maps).
 */
public final class AttestPuf {
    private AttestPuf() {}

    public static final String PUF_EXTRACT_INFO = "atlas-pca/puf-extract/v1";
    public static final String PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\0";
    public static final int PUF_KEY_BYTES = 32;
    public static final String TPM_EK_PUF_DOMAIN = "atlas-pca/puf-tpm-ek/v1";

    // ---- helpers ----

    private static boolean isInteger(Double d) { return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static byte[] sha256(byte[]... parts) { return Pca.sha(parts); }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator g = new HKDFBytesGenerator(new SHA256Digest());
        g.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        g.generateBytes(out, 0, length);
        return out;
    }

    private static void assertBits(byte[] b, String where) {
        for (byte x : b) if ((x & 0xff) > 1) throw new IllegalArgumentException(where + ": response must be a 0/1 bit array");
    }

    private static byte[] xorBits(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) ((a[i] ^ b[i]) & 1);
        return out;
    }

    private static byte[] repEncode(byte[] message, int rep) {
        byte[] out = new byte[message.length * rep];
        for (int i = 0; i < message.length; i++) for (int j = 0; j < rep; j++) out[i * rep + j] = (byte) (message[i] & 1);
        return out;
    }

    private static byte[] repDecode(byte[] code, int rep) {
        int k = code.length / rep;
        byte[] out = new byte[k];
        for (int i = 0; i < k; i++) {
            int ones = 0;
            for (int j = 0; j < rep; j++) ones += code[i * rep + j] & 1;
            out[i] = (byte) (ones * 2 > rep ? 1 : 0); // strict majority; ties (even rep) resolve to 0: use an ODD rep
        }
        return out;
    }

    private static byte[] packBits(byte[] bits) {
        byte[] out = new byte[(bits.length + 7) / 8];
        for (int i = 0; i < bits.length; i++) if ((bits[i] & 1) != 0) out[i >> 3] |= (byte) (1 << (i & 7));
        return out;
    }

    private static byte[] unpackBits(byte[] packed, int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) ((packed[i >> 3] >> (i & 7)) & 1);
        return out;
    }

    private static byte[] extractKey(byte[] responseBits, byte[] salt) {
        return hkdf(packBits(responseBits), salt, PUF_EXTRACT_INFO.getBytes(StandardCharsets.UTF_8), PUF_KEY_BYTES);
    }

    private static byte[] unb64u(Object s, String what) {
        byte[] b = Pca.decodeB64uStrict(s, -1);
        if (b == null) throw new IllegalArgumentException(what + " is not canonical base64url");
        return b;
    }

    // ---- fuzzy extractor ----

    /** The most bit errors per repetition block the code corrects: {@code floor((rep - 1) / 2)}. */
    public static double repetitionCorrectionBound(double rep) { return Math.floor((rep - 1) / 2); }

    /** The source of the randomness the enrollment draws: the first call asks for {@code messageBits} bytes (low bit used), the second for 32 salt bytes. */
    @FunctionalInterface
    public interface RandomBytes {
        byte[] apply(int n);
    }

    /** An extracted key and the public helper data that reproduces it. */
    public static final class FuzzyEnrollment {
        /** The 32-byte secret (the device's signing seed): keep it secret. */
        public final byte[] key;
        /** {@code {sketch, salt, rep, messageBits, n}}. */
        public final Map<String, Object> helper;

        FuzzyEnrollment(byte[] key, Map<String, Object> helper) { this.key = key; this.helper = helper; }
    }

    /** {@link #fuzzyEnroll(byte[], double, double, RandomBytes)} for whole-number parameters. */
    public static FuzzyEnrollment fuzzyEnroll(byte[] responseBits, int rep, int messageBits, RandomBytes randomBytes) {
        return fuzzyEnroll(responseBits, (double) rep, (double) messageBits, randomBytes);
    }

    /**
     * Enroll a response: {@code rep} must be an odd positive integer, {@code messageBits} a positive integer and the response exactly
     * {@code rep * messageBits} bits of 0 / 1. Derives the key as HKDF-SHA256 of the packed response under a fresh salt and publishes the
     * sketch (codeword XOR response).
     */
    public static FuzzyEnrollment fuzzyEnroll(byte[] responseBits, double rep, double messageBits, RandomBytes randomBytes) {
        if (!isInteger(rep) || rep < 1 || rep % 2 == 0) throw new IllegalArgumentException("fuzzyEnroll: rep must be an odd positive integer");
        if (!isInteger(messageBits) || messageBits < 1) throw new IllegalArgumentException("fuzzyEnroll: messageBits must be a positive integer");
        double nd = rep * messageBits;
        if (responseBits.length != nd) throw new IllegalArgumentException("fuzzyEnroll: response length " + responseBits.length + " != rep*messageBits " + AttestCommon.jsNumString(nd));
        assertBits(responseBits, "fuzzyEnroll");
        int r = (int) rep, mb = (int) messageBits;
        byte[] m = new byte[mb];
        byte[] mr = randomBytes.apply(mb);
        for (int i = 0; i < mb; i++) m[i] = (byte) (mr[i] & 1);
        byte[] sketch = xorBits(repEncode(m, r), responseBits); // C xor W
        byte[] salt = randomBytes.apply(32);
        byte[] key = extractKey(responseBits, salt);
        Map<String, Object> helper = new LinkedHashMap<>();
        helper.put("sketch", Pca.b64(packBits(sketch)));
        helper.put("salt", Pca.b64(salt));
        helper.put("rep", IntentJs.ofLong(r));
        helper.put("messageBits", IntentJs.ofLong(mb));
        helper.put("n", IntentJs.ofLong((long) r * mb));
        return new FuzzyEnrollment(key, helper);
    }

    /**
     * Reproduce the key from a fresh, noisy response and the helper data. Throws on malformed helper data or a wrong-length or non-bit
     * response. A response within the correction bound reproduces the enrolled key; one beyond it reproduces a different key.
     */
    public static byte[] fuzzyReproduce(byte[] responseBits, Map<String, Object> helper) {
        Double rep = IntentJs.num(get(helper, "rep")), mb = IntentJs.num(get(helper, "messageBits"));
        if (helper == null || !isInteger(rep) || !isInteger(mb) || rep < 1 || rep % 2 == 0) throw new IllegalArgumentException("fuzzyReproduce: malformed helper params");
        double nd = rep * mb;
        Double hn = IntentJs.num(helper.get("n"));
        if (hn == null || hn != nd) throw new IllegalArgumentException("fuzzyReproduce: helper.n inconsistent with rep*messageBits");
        if (responseBits.length != nd) throw new IllegalArgumentException("fuzzyReproduce: response length " + responseBits.length + " != " + AttestCommon.jsNumString(nd));
        assertBits(responseBits, "fuzzyReproduce");
        if (!(helper.get("sketch") instanceof String) || !(helper.get("salt") instanceof String)) throw new IllegalArgumentException("fuzzyReproduce: helper data missing sketch or salt");
        byte[] packedSketch = unb64u(helper.get("sketch"), "fuzzyReproduce: helper sketch or salt");
        byte[] salt = unb64u(helper.get("salt"), "fuzzyReproduce: helper sketch or salt");
        int n = (int) nd, r = rep.intValue();
        if (packedSketch.length != (n + 7) / 8) throw new IllegalArgumentException("fuzzyReproduce: helper sketch has the wrong length");
        if (salt.length != 32) throw new IllegalArgumentException("fuzzyReproduce: helper salt has the wrong length");
        byte[] sketchBits = unpackBits(packedSketch, n);
        byte[] corrupted = xorBits(responseBits, sketchBits); // W' xor s = C xor e
        byte[] cHat = repEncode(repDecode(corrupted, r), r);
        return extractKey(xorBits(cHat, sketchBits), salt); // C_hat xor s = the recovered W
    }

    // ---- PUF providers ----

    /** A source of PUF responses. */
    public interface PufProvider {
        String id();

        byte[] response(byte[] challenge);
    }

    /**
     * A simulated PUF for tests and demos (NOT a security primitive): the golden response is bit-expanded from SHA-256(seed || challenge ||
     * u32be(counter)) and the listed positions are flipped to model noise.
     */
    public static PufProvider createSimulatedPuf(String id, byte[] seed, int length, Iterable<Integer> flip) {
        Set<Integer> flips = new HashSet<>();
        if (flip != null) for (Integer f : flip) flips.add(f);
        return new PufProvider() {
            @Override public String id() { return id; }

            @Override public byte[] response(byte[] challenge) {
                byte[] bits = expand(length, blk -> sha256(seed, challenge, ctr(blk)));
                for (int pos : flips) if (pos >= 0 && pos < bits.length) bits[pos] = (byte) ((bits[pos] ^ 1) & 1);
                return bits;
            }
        };
    }

    private static byte[] ctr(int blk) { return new byte[] {(byte) (blk >>> 24), (byte) (blk >>> 16), (byte) (blk >>> 8), (byte) blk}; }

    private static byte[] expand(int length, java.util.function.IntFunction<byte[]> block) {
        int bytesNeeded = (length + 7) / 8;
        int blocks = Math.max(0, (bytesNeeded + 31) / 32);
        byte[] stream = new byte[blocks * 32];
        for (int blk = 0; blk < blocks; blk++) System.arraycopy(block.apply(blk), 0, stream, blk * 32, 32);
        byte[] bits = new byte[length];
        for (int i = 0; i < length; i++) bits[i] = (byte) ((stream[i >> 3] >> (i & 7)) & 1);
        return bits;
    }

    /** The result of a tpm2-tools invocation. */
    public static final class TpmCommandResult {
        /** The exit status; null when the process did not run to an exit. */
        public Integer status;
        /** Standard output (null: not bytes). */
        public byte[] stdout;
        public String stderr;
        /** A spawn failure; non-empty means the tool is unavailable. */
        public String error;
    }

    /** Runs a command (the seam of {@link TpmEkPufProvider}); a throw or a null result is a refusal. */
    @FunctionalInterface
    public interface TpmCommandRunner {
        TpmCommandResult run(String command, List<String> args) throws Exception;
    }

    /** The default runner: spawns the tool without a shell (15 s timeout, 1 MiB output cap). Prefer an injected runner in tests. */
    public static TpmCommandResult defaultTpmCommandRunner(String command, List<String> args) {
        TpmCommandResult r = new TpmCommandResult();
        List<String> cmd = new ArrayList<>();
        cmd.add(command);
        cmd.addAll(args);
        try {
            Process p = new ProcessBuilder(cmd).start();
            p.getOutputStream().close();
            byte[] out = readCapped(p.getInputStream(), 1 << 20);
            byte[] err = readCapped(p.getErrorStream(), 1 << 20);
            if (!p.waitFor(15, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                r.stdout = out;
                r.error = command + ": timeout";
                return r;
            }
            r.status = p.exitValue();
            r.stdout = out;
            if (r.status != 0) r.stderr = new String(err, StandardCharsets.UTF_8);
        } catch (IOException | InterruptedException e) {
            r.stdout = new byte[0];
            r.error = command + ": spawn failed";
        }
        return r;
    }

    private static byte[] readCapped(InputStream in, int cap) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0 && b.size() < cap) b.write(buf, 0, Math.min(n, cap - b.size()));
        return b.toByteArray();
    }

    /** The options of {@link TpmEkPufProvider}. */
    public static final class TpmEkPufOptions {
        public String id;
        /** The response length in bits: the enrolled {@code rep * messageBits}. */
        public Double length;
        public TpmCommandRunner run;
        /** The tool (default {@code tpm2_readpublic}). */
        public String tool;
        /** The EK handle (default {@code 0x81010001}). */
        public String ekHandle;
        /** The full argument list (default: read the EK handle as DER on stdout). */
        public List<String> args;
        /** The shortest plausible EK public (default 64 bytes). */
        public Double minEkBytes;
    }

    /**
     * A PUF over a TPM's endorsement key: the response is HKDF(ikm = the EK public, salt = {@code TPM_EK_PUF_DOMAIN}, info = challenge)
     * expanded to {@code length} bits. The TPM is reached only through the injected runner; a missing tool, a non-zero exit or an EK that is
     * too short is a refusal.
     */
    public static final class TpmEkPufProvider implements PufProvider {
        private final String id;
        private final int length;
        private final TpmCommandRunner run;
        private final String tool;
        private final List<String> args;
        private final int minEkBytes;

        public TpmEkPufProvider(TpmEkPufOptions o) {
            if (o == null || o.id == null || o.id.isEmpty()) throw new IllegalArgumentException("TpmEkPufProvider: id must be a non-empty string");
            if (!isInteger(o.length) || o.length < 1) throw new IllegalArgumentException("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)");
            if (o.minEkBytes != null && (!isInteger(o.minEkBytes) || o.minEkBytes < 1)) throw new IllegalArgumentException("TpmEkPufProvider: minEkBytes must be a positive integer");
            this.id = o.id;
            this.length = o.length.intValue();
            this.run = o.run != null ? o.run : AttestPuf::defaultTpmCommandRunner;
            this.tool = o.tool != null && !o.tool.isEmpty() ? o.tool : "tpm2_readpublic";
            String handle = o.ekHandle != null && !o.ekHandle.isEmpty() ? o.ekHandle : "0x81010001";
            this.args = o.args != null ? new ArrayList<>(o.args) : Arrays.asList("-c", handle, "-f", "der", "-o", "/dev/stdout", "-Q");
            this.minEkBytes = o.minEkBytes != null ? o.minEkBytes.intValue() : 64;
        }

        @Override public String id() { return id; }

        /** Read the EK public through the runner. Throws (fail closed) on a throwing runner, no result, a spawn error, a non-zero status or a short EK. */
        public byte[] readEkPublic() {
            TpmCommandResult res;
            try {
                res = run.run(tool, args);
            } catch (Exception e) {
                throw new IllegalStateException("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
            if (res == null) throw new IllegalStateException("TpmEkPufProvider: command runner returned no result (fail closed)");
            if (res.error != null && !res.error.isEmpty()) throw new IllegalStateException("TpmEkPufProvider: tpm2-tools unavailable (fail closed): " + res.error);
            if (res.status == null || res.status != 0) {
                throw new IllegalStateException("TpmEkPufProvider: '" + tool + "' exited with status " + (res.status == null ? "null" : res.status.toString()) + " (fail closed)"
                    + (res.stderr != null && !res.stderr.isEmpty() ? ": " + res.stderr.trim() : ""));
            }
            if (res.stdout == null || res.stdout.length < minEkBytes) {
                throw new IllegalStateException("TpmEkPufProvider: EK public too short (" + (res.stdout == null ? 0 : res.stdout.length) + " < " + minEkBytes + " bytes) - TPM unavailable or wrong handle (fail closed)");
            }
            return res.stdout;
        }

        @Override public byte[] response(byte[] challenge) {
            byte[] secret = hkdf(readEkPublic(), TPM_EK_PUF_DOMAIN.getBytes(StandardCharsets.UTF_8), challenge, 32);
            return expand(length, blk -> sha256(secret, ctr(blk)));
        }
    }

    // ---- derived signers ----

    private static String assertPufSuite(Object alg) {
        if ("ed25519".equals(alg) || "ml-dsa-65".equals(alg) || "ml-dsa-87".equals(alg)) return (String) alg;
        throw new IllegalArgumentException("PUF root: unsupported derived suite '" + IntentRevocation.jsText(alg, true) + "' (use ed25519, ml-dsa-65 or ml-dsa-87)");
    }

    private static final class Signer {
        final String publicKey;
        final Pq.SuiteSecretKeys keys = new Pq.SuiteSecretKeys();
        final String alg;

        Signer(String alg, byte[] seed) {
            this.alg = alg;
            switch (alg) {
                case "ed25519":
                    keys.edSecret = seed;
                    publicKey = Keys.edFromSeed(seed).id();
                    break;
                case "ml-dsa-65":
                    keys.mlDsa = Pq.mlDsa65Keygen(seed);
                    publicKey = Pq.encodeMlDsaPublicKey(keys.mlDsa.publicKey);
                    break;
                default:
                    keys.mlDsa87 = Pq.mlDsa87Keygen(seed);
                    publicKey = Pq.encodeMlDsa87PublicKey(keys.mlDsa87.publicKey);
                    break;
            }
        }

        Pq.SuiteSignatureParts sign(byte[] msg) { return Pq.signWithSuite(alg, keys, msg); }
    }

    private static byte[] statementMessage(Map<String, Object> body) {
        return Pca.concat(PUF_ATTEST_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(IntentJs.normalize(body)));
    }

    // ---- enrollment and the device attestor ----

    /** The options of {@link #enrollPuf}: {@code rep}, {@code messageBits}, the derived suite (null: ml-dsa-65) and the randomness (null: the system CSPRNG). */
    public static final class EnrollOptions {
        public double rep, messageBits;
        public String alg;
        public RandomBytes randomBytes;
    }

    /**
     * Enroll a device: read its response to {@code challenge}, extract the key, derive the signing key from it and record only public
     * material {@code {providerId, challenge, alg, publicKey, helper, helperCommitment}}; the secret is not retained.
     */
    public static Map<String, Object> enrollPuf(PufProvider provider, byte[] challenge, EnrollOptions opts) {
        String alg = assertPufSuite(opts.alg == null ? "ml-dsa-65" : opts.alg);
        RandomBytes rnd = opts.randomBytes != null ? opts.randomBytes : n -> {
            byte[] b = new byte[n];
            new java.security.SecureRandom().nextBytes(b);
            return b;
        };
        byte[] bits = provider.response(challenge);
        FuzzyEnrollment fe = fuzzyEnroll(bits, opts.rep, opts.messageBits, rnd);
        Signer signer = new Signer(alg, fe.key);
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("providerId", provider.id());
        e.put("challenge", Pca.b64(challenge));
        e.put("alg", alg);
        e.put("publicKey", signer.publicKey);
        e.put("helper", fe.helper);
        e.put("helperCommitment", Pca.hashCanonical(IntentJs.normalize(fe.helper)));
        return e;
    }

    /** The device side: mints statements by re-deriving the key from a fresh response each time. */
    public static final class Attestor {
        private final PufProvider provider;
        private final String alg;
        private final byte[] challenge;
        private final Object helper;

        private Attestor(PufProvider provider, Map<String, Object> enrollment) {
            this.provider = provider;
            this.alg = assertPufSuite(get(enrollment, "alg"));
            this.challenge = unb64u(get(enrollment, "challenge"), "enrollment challenge");
            this.helper = get(enrollment, "helper");
        }

        /**
         * A statement {@code {provider_id, measurement, weights_digest?, binding, alg, sig, pq_sig?}} over {@code {measurement,
         * weights_digest?, holder_pub, grant_ref, epoch, nonce}}. Throws on malformed helper data or a binding that cannot be built.
         */
        @SuppressWarnings("unchecked")
        public Map<String, Object> attest(Map<String, Object> claims) {
            byte[] key = fuzzyReproduce(provider.response(challenge), helper instanceof Map ? (Map<String, Object>) helper : null);
            Signer signer = new Signer(alg, key);
            String binding = Attestation.attestationBindingB64u(Issue.obj("holderPub", claims.get("holder_pub"), "grantRef", claims.get("grant_ref"),
                "epoch", claims.get("epoch"), "nonce", claims.get("nonce")));
            if (!claims.containsKey("measurement")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("provider_id", provider.id());
            body.put("measurement", claims.get("measurement"));
            body.put("binding", binding);
            body.put("alg", alg);
            if (claims.containsKey("weights_digest")) body.put("weights_digest", claims.get("weights_digest"));
            Pq.SuiteSignatureParts parts = signer.sign(statementMessage(body));
            Map<String, Object> st = new LinkedHashMap<>(body);
            st.put("sig", parts.sig);
            if (parts.pqSig != null) st.put("pq_sig", parts.pqSig);
            return st;
        }
    }

    /** Build the device attestor over a provider and its enrollment. Throws on an unsupported derived suite or a non-canonical challenge. */
    public static Attestor createPufAttestor(PufProvider provider, Map<String, Object> enrollment) { return new Attestor(provider, enrollment); }

    // ---- enrollment registry ----

    /** An in-memory enrollment registry: register, look up, revoke. A revocation outlives re-registration. */
    public static final class EnrollmentRegistry {
        private final Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        private final Set<String> revoked = new HashSet<>();

        private EnrollmentRegistry(List<?> enrollments) {
            if (enrollments != null) for (Object e : enrollments) register(e);
        }

        /** Register (or replace) an enrollment; an entry without a string {@code providerId} is ignored. */
        public synchronized void register(Object enrollment) {
            if (enrollment instanceof Map && ((Map<?, ?>) enrollment).get("providerId") instanceof String) {
                byId.put((String) ((Map<?, ?>) enrollment).get("providerId"), StoreJs.map(enrollment));
            }
        }

        /** The enrollment of a provider, or null when unknown or revoked. */
        public synchronized Map<String, Object> lookup(String providerId) { return revoked.contains(providerId) ? null : byId.get(providerId); }

        public synchronized void revoke(String providerId) { revoked.add(providerId); }

        public synchronized boolean isRevoked(String providerId) { return revoked.contains(providerId); }
    }

    public static EnrollmentRegistry createPufEnrollmentRegistry(List<?> enrollments) { return new EnrollmentRegistry(enrollments); }

    // ---- verifier ----

    /** Acceptance policy. {@code measurements} is REQUIRED and NON-EMPTY (no accept-all). */
    public static final class Policy {
        public List<String> measurements;
        /** Allowed measured-weights digests; null or empty: not gated. */
        public List<String> weightsMeasurements;
        /** Maps a verified (statement, enrollment) to the measured identity (null: the default, weights never measured). */
        public BiFunction<Map<String, Object>, Map<String, Object>, Map<String, Object>> deriveIdentity;
    }

    /** Resolves the enrollment of a provider for an action (null: none). */
    @FunctionalInterface
    public interface EnrollmentResolver {
        Map<String, Object> resolve(String providerId, Object document, Object ctx);
    }

    /** The options of {@link #createPufVerifier}. */
    public static final class VerifierOptions {
        /** Resolves an enrollment: (providerId, document, ctx) to the enrollment map, or null. REQUIRED. */
        public EnrollmentResolver resolveEnrollment;
        public Policy policy;
        /** Require a post-quantum derived suite (default false). */
        public boolean requirePq;
        /** An out-of-band revocation check on the provider id. */
        public Predicate<String> isRevoked;
        /** The evidence seam: the statement for an action (null result: none). Without it the verifier fails closed. */
        public BiFunction<Object, Object, Object> resolveEvidence;
    }

    /** The verifier: the hardware-verifier seam, labelled {@code software}. */
    public static final class Verifier implements Attestation.HardwareVerifier, Assurance.Labelled {
        private final VerifierOptions o;
        private final List<String> measurements, weightsMeasurements;
        private static final Assurance.Label LABEL = new Assurance.Label("software", "puf", false, null);

        private Verifier(VerifierOptions o) {
            if (o == null || o.policy == null || o.policy.measurements == null || o.policy.measurements.isEmpty()) {
                throw new IllegalArgumentException("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
            }
            if (o.resolveEnrollment == null) throw new IllegalArgumentException("createPufVerifier: resolveEnrollment is required");
            this.o = o;
            this.measurements = new ArrayList<>(o.policy.measurements);
            this.weightsMeasurements = o.policy.weightsMeasurements == null ? null : new ArrayList<>(o.policy.weightsMeasurements);
        }

        @Override public Assurance.Label assuranceLabel() { return LABEL; }

        private static Map<String, Object> fail(String why) { return Issue.obj("ok", false, "reason", why); }

        /**
         * Verify the statement the evidence seam resolves for {@code input} ({@code {document, ctx, nowMs, expected}}): the provider is not
         * revoked and is enrolled; the enrollment has not expired and its helper commitment holds; the suite matches the enrolled one (and is
         * post-quantum when required); the signature verifies under the enrolled public key; the binding equals the expected one; and the
         * measurement and weights policies pass. Fails closed with a reason.
         */
        @Override public Object verify(Map<String, Object> input) {
            try {
                if (o.resolveEvidence == null) return fail("no PUF evidence resolver configured (fail closed)");
                Object stO = o.resolveEvidence.apply(input.get("document"), input.get("ctx"));
                if (!(stO instanceof Map) || !(get(stO, "provider_id") instanceof String) || !(get(stO, "alg") instanceof String)) return fail("no PUF attestation statement for this action");
                Map<String, Object> st = StoreJs.map(stO);
                String pid = (String) st.get("provider_id"), alg = (String) st.get("alg");
                if (o.isRevoked != null && o.isRevoked.test(pid)) return fail("PUF enrollment for provider '" + pid + "' is revoked");
                Map<String, Object> enr = o.resolveEnrollment.resolve(pid, input.get("document"), input.get("ctx"));
                if (enr == null) return fail("no PUF enrollment registered for provider '" + pid + "'");
                if (enr.containsKey("notAfter")) {
                    Double now = IntentJs.num(input.get("nowMs"));
                    double na = Actions.jsNumber(enr.get("notAfter"), true);
                    if (!(now != null && Double.isFinite(now) && now < na)) return fail("PUF enrollment has expired");
                }
                if (!enr.containsKey("helper")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
                if (!(enr.get("helperCommitment") instanceof String) || !enr.get("helperCommitment").equals(Pca.hashCanonical(IntentJs.normalize(enr.get("helper"))))) {
                    return fail("PUF enrollment helper commitment mismatch (helper tampered)");
                }
                if (!alg.equals(enr.get("alg"))) return fail("PUF statement suite '" + alg + "' does not match the enrolled suite '" + IntentRevocation.jsText(enr.get("alg"), enr.containsKey("alg")) + "'");
                Pq.Suite suite = Pq.resolveSigAlg(alg, true);
                if (suite == null) return fail("PUF statement declares an unknown signature alg '" + alg + "'");
                boolean hasPq = suite.pq == Pq.Prim.ML_DSA_65 || suite.pq == Pq.Prim.ML_DSA_87 || suite.pq == Pq.Prim.SLH_DSA_SHA2_128F || suite.pq == Pq.Prim.SLH_DSA_SHA2_256S;
                if (o.requirePq && !hasPq) return fail("PQ required: PUF-derived suite '" + suite.alg + "' is classical");
                Map<String, Object> body = new LinkedHashMap<>(st);
                body.remove("sig");
                body.remove("pq_sig");
                String pub = enr.get("publicKey") instanceof String ? (String) enr.get("publicKey") : null;
                Pq.PinnedPq pq = Pq.resolvePqVerifyKey("", null, null, null, pub);
                if (!Pq.verifyWithSuite(suite.alg, pub, pq, statementMessage(body), st.get("sig"), st.get("pq_sig"))) {
                    return fail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)");
                }
                Object expected = input.get("expected");
                if (expected == null) return fail("no expected attestation binding supplied");
                String expectedB64u;
                try {
                    expectedB64u = Attestation.attestationBindingB64u(expected);
                } catch (RuntimeException e) {
                    return fail("binding not constructible: " + (e.getMessage() == null ? "invalid" : e.getMessage()));
                }
                if (!(st.get("binding") instanceof String) || !expectedB64u.equals(st.get("binding"))) return fail("PUF statement binding mismatch (holder/grant/epoch/nonce)");
                if (!(st.get("measurement") instanceof String) || !measurements.contains(st.get("measurement"))) return fail("measurement not in policy allowlist");
                if (weightsMeasurements != null && !weightsMeasurements.isEmpty()
                    && (!(st.get("weights_digest") instanceof String) || !weightsMeasurements.contains(st.get("weights_digest")))) {
                    return fail("measured weights digest not in policy allowlist");
                }
                Map<String, Object> measured = o.policy.deriveIdentity != null ? o.policy.deriveIdentity.apply(st, enr) : defaultIdentity(st);
                Map<String, Object> host = new LinkedHashMap<>();
                host.put("provider_id", pid);
                host.put("suite", suite.alg);
                return Issue.obj("ok", true, "bound", true, "measured", measured, "hostAsserted", host);
            } catch (RuntimeException e) {
                return fail("puf verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        }
    }

    /** Build the PUF verifier; it plugs into {@link Attestation#createAttestationVerifier} and {@link Attestation#createMultiRootVerifier}. */
    public static Verifier createPufVerifier(VerifierOptions opts) { return new Verifier(opts); }

    private static Map<String, Object> defaultIdentity(Map<String, Object> st) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("model_id", "");
        m.put("weights_digest", st.get("weights_digest") instanceof String ? st.get("weights_digest") : "");
        m.put("weights_measured", false);
        m.put("runtime_measurement", st.get("measurement"));
        m.put("operator", "");
        return m;
    }
}
