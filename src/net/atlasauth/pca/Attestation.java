package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Attestation-derived workload identity for an agent: the quote it presents measures the model, the weights, the runtime and the
 * operator, so a swapped model or a tampered runtime changes the measurement and the identity evaporates. Two modes:
 * <ul>
 * <li>SOFTWARE: a signed {@link DevAttestor} document. A real, checkable attestation for development, CI and attested-VM
 *     equivalents, but the measurements are asserted by the signer, not rooted in silicon.
 * <li>HARDWARE: a {@link HardwareVerifier} (a vendor verifier through {@link #fromVendor}) that verifies the vendor evidence; the
 *     identity it measures, never the document's own fields, then feeds the same freshness, nonce-binding and agent-binding checks.
 * </ul>
 * {@link #createMultiRootVerifier} requires several independent roots to agree, and {@link #anchorAttestationEvidence} appends each
 * verified attestation to a transparency log under a signed tree head, so an attestation admitted by mistake stays attributable.
 *
 * <p>Documents, contexts and expected bindings are decoded JSON (maps and lists); results are JSON trees. Verification never
 * throws: every failure is {@code ok: false} with the reason. A post-quantum or hybrid document verifies only under a PQ key the
 * VERIFIER pins for the attestor ({@code pqPins}); the reference's legacy option that trusts the document's own PQ key is not
 * offered, as everywhere in this SDK.
 */
public final class Attestation {
    private Attestation() {}

    public static final String ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\0";
    public static final String ATTEST_ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\0";
    private static final String DOMAIN = "atlas-pca/attest/v1\0";
    /** Hard ceiling on the age of a server-issued attestation nonce at verification time (5 minutes). A caller may only tighten it. */
    public static final long MAX_ATTESTATION_AGE_MS = 5 * 60_000L;
    /** Default retention of a consumed nonce in {@link #memoryNonceStore} (1 hour, 12 times the quote-age ceiling). */
    public static final long DEFAULT_NONCE_RETENTION_MS = 60 * 60 * 1000L;
    /** Minimum entropy of a server-issued attestation nonce, in bytes (128 bits). Not configurable below this. */
    public static final int MIN_ATTESTATION_NONCE_BYTES = 16;
    private static final long DEFAULT_NONCE_STORE_MAX = 100_000L;
    private static final double MAX_SAFE = 9007199254740991d;

    // ---- small JavaScript-shaped helpers ----

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** {@code o?.a?.b}: the member chain, null as soon as a step is not an object. */
    private static Object path(Object o, String... keys) {
        Object cur = o;
        for (String k : keys) cur = get(cur, k);
        return cur;
    }

    private static String msg(Throwable e) { return e.getMessage() == null ? "invalid" : e.getMessage(); }

    private static String text(Object x, boolean present) { return IntentRevocation.jsText(x, present); }

    private static boolean isNum(Object o) { return IntentJs.num(o) != null; }

    private static boolean finite(Object o) { return IntentJs.isFinite(o); }

    /** A string that is a member of the list, or whose characters (a string is iterable) include it. */
    private static Set<String> stringSet(Object iterable) {
        Set<String> out = new HashSet<>();
        if (iterable == null) return out;
        if (iterable instanceof List) {
            for (Object x : (List<?>) iterable) if (x instanceof String) out.add((String) x);
        } else if (iterable instanceof String) {
            ((String) iterable).codePoints().forEach(c -> out.add(new String(Character.toChars(c))));
        } else {
            throw new IllegalArgumentException("object is not iterable");
        }
        return out;
    }

    private static Map<String, Object> mapOf(Object... kv) { return Issue.obj(kv); }

    // ---- binding ----

    static AttestationBinding bindingOf(Object exp) {
        Object h = get(exp, "holderPub"), g = get(exp, "grantRef"), n = get(exp, "nonce"), e = get(exp, "epoch");
        if (!(h instanceof String) || ((String) h).isEmpty()) throw new IllegalArgumentException("binding: holderPub required");
        if (!(g instanceof String) || ((String) g).isEmpty()) throw new IllegalArgumentException("binding: grantRef required");
        if (!(n instanceof String) || ((String) n).isEmpty()) throw new IllegalArgumentException("binding: nonce required");
        if (!IntentJs.isSafeInteger(e) || IntentJs.num(e) < 0) throw new IllegalArgumentException("binding: epoch must be a non-negative safe integer");
        return new AttestationBinding((String) h, (String) g, IntentJs.num(e), (String) n);
    }

    /**
     * The value a quote's report data must carry: {@code SHA-512(ATTEST_BIND_DOMAIN || lp(holderPub) || lp(grantRef) || u64be(epoch) ||
     * lp(nonce))} with {@code lp(x) = u32be(len) || utf8(x)}. 64 bytes, the SEV-SNP report-data width; a quote captured for one
     * holder, grant, epoch or nonce cannot be relayed for another. Throws on a malformed expected binding.
     */
    public static byte[] attestationBinding(Object expected) { return AttestCommon.attestationBindingBytes(bindingOf(expected)); }

    /** {@link #attestationBinding} as base64url (what a software document carries in {@code binding}). */
    public static String attestationBindingB64u(Object expected) { return Pca.b64(attestationBinding(expected)); }

    // ---- software documents ----

    private static byte[] attestMessage(Map<String, Object> body) {
        return Pca.concat(DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(IntentJs.normalize(body)));
    }

    /** base64url(sha256(canonical(document))): a content address for the full signed quote. */
    public static String attestationDigest(Object document) { return Pca.hashCanonical(IntentJs.normalize(document)); }

    /** A software-mode attestor: signs {@link #attest} documents with its key. Build it with {@link #createDevAttestor}. */
    public static final class DevAttestor {
        /** The b64u Ed25519 public key a verifier lists in {@code trustedAttestorKeys}. */
        public final String publicKey;
        private final byte[] secret;
        private final Pq.SignerSuiteOpts suite;
        private final String pqPk;

        private DevAttestor(byte[] secret, Pq.SignerSuiteOpts suite) {
            this.publicKey = Keys.edFromSeed(secret).id();
            String alg = suite == null ? null : suite.alg;
            if (alg != null && !Pq.isKnownSigAlg(alg)) throw new IllegalArgumentException("createDevAttestor: unknown signature alg '" + alg + "'");
            this.secret = secret.clone();
            this.suite = suite;
            this.pqPk = Pq.suitePqPublicKey(alg, Pq.suiteKeysOf(secret, suite));
        }

        /**
         * Sign a software-mode document over the claims {@code {model_id, weights_digest, runtime_measurement, operator, nonce,
         * issued_at, expires_at}} (all required), with optional {@code system_prompt_digest}, {@code tool_manifest_digest} and, when
         * all three are present, {@code holder_pub}, {@code grant_ref}, {@code epoch}, which bind the document to that holder, grant,
         * epoch and nonce. Members the claims do not name are not carried. Throws on a missing claim or a value with no canonical form.
         */
        public Map<String, Object> attest(Map<String, Object> claims) {
            Map<String, Object> body = new LinkedHashMap<>();
            String[] required = {"model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at"};
            boolean binds = claims.containsKey("holder_pub") && claims.containsKey("grant_ref") && claims.containsKey("epoch");
            String binding = binds ? attestationBindingB64u(mapOf("holderPub", claims.get("holder_pub"), "grantRef", claims.get("grant_ref"),
                "epoch", claims.get("epoch"), "nonce", claims.get("nonce"))) : null;
            for (String k : required) {
                if (!claims.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
                body.put(k, claims.get(k));
            }
            body.put("attestor", publicKey);
            body.put("mode", "software");
            // additive: the instruction and tool digests are carried only when supplied
            if (claims.containsKey("system_prompt_digest")) body.put("system_prompt_digest", claims.get("system_prompt_digest"));
            if (claims.containsKey("tool_manifest_digest")) body.put("tool_manifest_digest", claims.get("tool_manifest_digest"));
            if (binding != null) body.put("binding", binding);
            String alg = suite == null ? null : suite.alg;
            Map<String, Object> signed = IntentJs.bindSuiteFields(body, alg, alg != null, pqPk, pqPk != null);
            Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(secret, suite), attestMessage(signed));
            Map<String, Object> doc = new LinkedHashMap<>(signed);
            doc.put("sig", f.sig);
            if (f.alg != null) doc.put("alg", f.alg);
            if (f.pqPk != null) doc.put("pq_pk", f.pqPk);
            if (f.pqSig != null) doc.put("pq_sig", f.pqSig);
            return doc;
        }
    }

    /** A software-mode attestor for development and CI over {@code secret} (an Ed25519 seed), optionally under a PQ or hybrid suite. */
    public static DevAttestor createDevAttestor(byte[] secret, Pq.SignerSuiteOpts suite) { return new DevAttestor(secret, suite); }

    /**
     * The resolver over a set of known documents: it returns the one whose {@code nonce} equals the PCActn's
     * {@code attestation.quote_digest} (null when none does); a later document for a nonce replaces an earlier one. Entries that are
     * not documents with a string nonce are ignored.
     */
    public static Function<Object, Map<String, Object>> attestationRegistry(Object docs) {
        Map<String, Map<String, Object>> byNonce = new LinkedHashMap<>();
        if (docs instanceof List) {
            for (Object d : (List<?>) docs) {
                if (d instanceof Map && ((Map<?, ?>) d).get("nonce") instanceof String) byNonce.put((String) ((Map<?, ?>) d).get("nonce"), StoreJs.map(d));
            }
        }
        return ctx -> {
            Object key = path(ctx, "pcactn", "attestation", "quote_digest");
            return key instanceof String ? byNonce.get(key) : null;
        };
    }

    // ---- single-use nonce store ----

    /** Single-use store for server-issued attestation nonces: {@code consume} is atomic and true only for the first call per nonce. */
    public interface NonceStore {
        boolean consume(Object nonce);
    }

    /** {@link #memoryNonceStore(long, long, LongSupplier)} with the default bound (100000 nonces), retention (1 hour) and the system clock. */
    public static NonceStore memoryNonceStore() { return memoryNonceStore(DEFAULT_NONCE_STORE_MAX, DEFAULT_NONCE_RETENTION_MS, System::currentTimeMillis); }

    /**
     * An in-memory single-process nonce store. A consumed nonce is never re-accepted inside the retention window; the store is bounded
     * by {@code max} entries and, when full of retained nonces, REFUSES new ones (false) rather than evicting a live one, because
     * evicting reopens replay for exactly the nonce dropped. {@code max} and {@code retentionMs} must be positive. A clock reading
     * that is not an integer refuses the nonce (fail closed).
     */
    public static NonceStore memoryNonceStore(long max, long retentionMs, LongSupplier now) {
        return memoryNonceStoreJs((double) max, (double) retentionMs, () -> now.getAsLong());
    }

    static NonceStore memoryNonceStoreJs(Object max, Object retentionMs, DoubleSupplier clock) {
        Double m = max == null ? Double.valueOf(DEFAULT_NONCE_STORE_MAX) : IntentJs.num(max);
        if (m == null || !IntentJs.isSafeInteger(m) || m < 1) {
            throw new IllegalArgumentException("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)");
        }
        Double r = retentionMs == null ? Double.valueOf(DEFAULT_NONCE_RETENTION_MS) : IntentJs.num(retentionMs);
        if (r == null || !IntentJs.isSafeInteger(r) || r <= 0) throw new IllegalArgumentException("memoryNonceStore: retentionMs must be a positive integer (ms)");
        return new MemoryNonceStore(m.longValue(), r.longValue(), clock);
    }

    private static final class MemoryNonceStore implements NonceStore {
        private final long max, retention;
        private final DoubleSupplier clock;
        private final LinkedHashMap<String, Long> seen = new LinkedHashMap<>(); // nonce -> time consumed (insertion order is time order)

        MemoryNonceStore(long max, long retention, DoubleSupplier clock) { this.max = max; this.retention = retention; this.clock = clock; }

        @Override public synchronized boolean consume(Object nonce) {
            if (!(nonce instanceof String)) return false;
            double reading = clock.getAsDouble();
            if (Double.isNaN(reading) || Double.isInfinite(reading) || reading != Math.rint(reading) || Math.abs(reading) > MAX_SAFE) return false;
            long t = (long) reading;
            Long at = seen.get(nonce);
            if (at != null) {
                if (t - at < retention) return false; // retained: a replay
                seen.remove(nonce); // aged out: treated as new (the freshness check refuses such a quote anyway)
            }
            if (seen.size() >= max) {
                for (Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext();) { // make room ONLY from aged-out entries
                    if (t - it.next().getValue() < retention) break;
                    it.remove();
                }
                if (seen.size() >= max) return false; // full of live nonces: fail closed
            }
            seen.put((String) nonce, t);
            return true;
        }
    }

    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]+");
    private static final Pattern B64U = Pattern.compile("[A-Za-z0-9_-]+");

    /** {@link #nonceEntropyOk(Object, Object)} at the 16-byte floor. */
    public static boolean nonceEntropyOk(Object nonce) { return nonceEntropyOk(nonce, null); }

    /**
     * Whether {@code nonce} plausibly carries at least {@code minBytes} bytes (null: 16; never below 16) of entropy: hex (at least
     * twice that many digits) or base64url (at least ceil(bytes*4/3) characters), with at least 8 distinct characters (refusing
     * {@code aaaa...}, counters and words). A syntactic floor only: the server must still draw nonces from a CSPRNG.
     */
    public static boolean nonceEntropyOk(Object nonce, Object minBytes) {
        if (!(nonce instanceof String)) return false;
        String s = (String) nonce;
        double need = Math.max(minBytes == null ? MIN_ATTESTATION_NONCE_BYTES : Actions.jsNumber(minBytes, true), MIN_ATTESTATION_NONCE_BYTES);
        boolean hex = HEX.matcher(s).matches(), b64 = B64U.matcher(s).matches();
        if (!hex && !b64) return false;
        double bytes = hex ? s.length() / 2.0 : Math.floor(s.length() * 3.0 / 4.0);
        if (bytes < need) return false;
        return s.codePoints().distinct().count() >= 8;
    }

    // ---- agent binding ----

    /** True iff the grant's {@code agent_binding} constrains anything: then a bound attestation is REQUIRED. */
    public static boolean requiresAttestation(Object binding) { return Authorize.requiresAttestation(binding); }

    /** True iff {@code doc.nonce} is the nonce the PCActn declares in {@code attestation.quote_digest}. */
    public static boolean nonceBinds(Object doc, Object ctx) {
        Object n = get(doc, "nonce");
        return n instanceof String && n.equals(path(ctx, "pcactn", "attestation", "quote_digest"));
    }

    private static final Pattern SVN_TEXT = Pattern.compile("0|[1-9][0-9]*");
    private static final Object UNDEFINED = new Object();

    private static Object field(Map<String, Object> m, String k) { return m.containsKey(k) ? m.get(k) : UNDEFINED; }

    /** {@code includes}: SameValueZero over the list (an object equals nothing). */
    private static boolean includes(Object list, Object v) {
        if (!(list instanceof List)) return false;
        for (Object e : (List<?>) list) {
            if (v == UNDEFINED) continue;
            if (e == null || v == null) { if (e == v) return true; continue; }
            if (e instanceof Map || e instanceof List || v instanceof Map || v instanceof List) continue;
            Double a = IntentJs.num(e), b = IntentJs.num(v);
            if (a != null || b != null) { if (a != null && b != null && (a.equals(b) || a.doubleValue() == b.doubleValue())) return true; continue; }
            if (e.equals(v)) return true;
        }
        return false;
    }

    private static boolean nonEmptyList(Object x) { return x instanceof List && !((List<?>) x).isEmpty(); }

    private static Double measuredSvn(Object runtime) {
        if (!(runtime instanceof String) || !SVN_TEXT.matcher((String) runtime).matches()) return null;
        double n = Double.parseDouble((String) runtime);
        return n <= MAX_SAFE ? n : null;
    }

    /**
     * Match a measured identity {@code {model_id, weights_digest, weights_measured?, runtime_measurement, operator,
     * system_prompt_digest?, tool_manifest_digest?}} against the grant's {@code agent_binding}; the reason it fails, else null. In order:
     * model allowlist, {@code min_measurement} (absent or "" constrains nothing; a string is an equality pin; {@code {svn: n}} is a
     * floor over a canonical decimal runtime measurement; anything else fails closed), operator, {@code require_measured_weights},
     * weights, system prompt and tool manifest allowlists. A pinned digest the identity does not carry fails closed.
     */
    public static String matchAgentBinding(Object identity, Object binding) {
        if (identity == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'runtime_measurement')");
        Map<String, Object> id = identity instanceof Map ? StoreJs.map(identity) : new LinkedHashMap<>();
        Map<String, Object> b = binding instanceof Map ? StoreJs.map(binding) : new LinkedHashMap<>();
        Object runtime = field(id, "runtime_measurement");
        if (nonEmptyList(b.get("model_allowlist")) && !includes(b.get("model_allowlist"), field(id, "model_id"))) {
            return "model_id " + text(id.get("model_id"), id.containsKey("model_id")) + " not in model_allowlist";
        }
        Object mm = field(b, "min_measurement");
        Double svnFloor = null;
        if (mm != UNDEFINED && !"".equals(mm)) {
            if (mm instanceof String) {
                if (!mm.equals(runtime)) return "runtime_measurement does not match required min_measurement";
            } else if (mm instanceof Map && ((Map<?, ?>) mm).size() == 1 && ((Map<?, ?>) mm).containsKey("svn") && IntentJs.isNonNeg(((Map<?, ?>) mm).get("svn"))) {
                svnFloor = IntentJs.num(((Map<?, ?>) mm).get("svn"));
                Double got = measuredSvn(runtime);
                String floorText = AttestCommon.jsNumString(svnFloor);
                if (got == null) return "runtime_measurement " + text(id.get("runtime_measurement"), id.containsKey("runtime_measurement")) + " is not an integer SVN (required min svn " + floorText + ")";
                if (got < svnFloor) return "runtime_measurement svn " + AttestCommon.jsNumString(got) + " is below required min svn " + floorText;
            } else {
                return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)";
            }
        }
        if (b.get("operator") instanceof String && !((String) b.get("operator")).isEmpty() && !b.get("operator").equals(id.get("operator"))) {
            return "operator " + text(id.get("operator"), id.containsKey("operator")) + " is not the bound operator";
        }
        if (Boolean.TRUE.equals(b.get("require_measured_weights")) && !Boolean.TRUE.equals(id.get("weights_measured"))) {
            return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)";
        }
        if (nonEmptyList(b.get("weights_allowlist")) && !includes(b.get("weights_allowlist"), field(id, "weights_digest"))) {
            return "weights_digest not in weights_allowlist (model swap / fine-tune?)";
        }
        if (nonEmptyList(b.get("system_prompt_allowlist"))
            && (!(id.get("system_prompt_digest") instanceof String) || !includes(b.get("system_prompt_allowlist"), id.get("system_prompt_digest")))) {
            return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)";
        }
        if (nonEmptyList(b.get("tool_manifest_allowlist"))
            && (!(id.get("tool_manifest_digest") instanceof String) || !includes(b.get("tool_manifest_allowlist"), id.get("tool_manifest_digest")))) {
            return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)";
        }
        return null;
    }

    // ---- hardware seam ----

    /**
     * The seam every TEE verifier implements. {@code input} is {@code {document, ctx, nowMs, expected}}; the answer is the JSON form of
     * a hardware result: {@code {ok, reason?, measured?, bound?, hostAsserted?}}. {@code measured} is the HARDWARE-measured identity,
     * and {@code bound} must be true only after the quote's report data was confirmed equal to {@link #attestationBinding}. A throw
     * is a refusal.
     */
    @FunctionalInterface
    public interface HardwareVerifier {
        Object verify(Map<String, Object> input) throws Exception;
    }

    /**
     * A vendor verifier as the seam: {@code evidenceOf} picks the vendor evidence for the action from the verification input (null:
     * none supplied), and the vendor verifier checks it against the expected binding at the input's clock.
     */
    public static HardwareVerifier fromVendor(VendorVerifier vendor, Function<Map<String, Object>, Map<String, Object>> evidenceOf) {
        return input -> {
            AttestationBinding b = bindingOf(input.get("expected"));
            Double now = IntentJs.num(input.get("nowMs"));
            if (now == null) throw new IllegalArgumentException("nowMs is not a number");
            return vendor.verify(evidenceOf.apply(input), b, now.longValue()).wire();
        };
    }

    // ---- verification ----

    private static Map<String, Object> verdict(boolean ok, boolean present, boolean bound, String reason, Object identity) {
        Map<String, Object> m = mapOf("ok", ok, "present", present, "bound", bound);
        if (reason != null) m.put("reason", reason);
        if (identity != null) m.put("identity", identity);
        return m;
    }

    private static Map<String, Object> failed(boolean present, String reason) { return verdict(false, present, false, reason, null); }

    private static String nonceAgeReason(Object issued, double nowMs, double skew, double maxAge) {
        Double v = IntentJs.num(issued);
        if (v == null || Double.isNaN(v) || Double.isInfinite(v)) return "server nonce issue time unknown (cannot establish freshness)";
        if (!(Double.isFinite(nowMs) && Double.isFinite(skew) && nowMs + skew >= v)) return "nonce issued in the future";
        if (!(nowMs - v <= maxAge + skew)) return "attestation nonce expired (stale quote)";
        return null;
    }

    /** {@link #verifyAttestation(Map, HardwareVerifier)} in software mode. */
    public static Map<String, Object> verifyAttestation(Map<String, Object> input) { return verifyAttestation(input, null); }

    /**
     * Verify an attestation. {@code input} is {@code {document, ctx, expected, nowMs, trustedAttestorKeys, pqPins?, maxNonceAgeMs?,
     * clockSkewMs?}}: the optional document, the PCActn context {@code {pcactn, grant}}, the binding the SERVER expects ({@code
     * {holderPub, grantRef, epoch, nonce, nonceIssuedAt?}}), the verifier's clock and the trusted software attestor keys. In order it
     * requires a document; cross-checks the PCActn against {@code expected}; requires the document's nonce to be the expected one;
     * establishes the identity and the binding (hardware: the verifier must confirm the report data, and the document's own fields and
     * dates are ignored; software: the mode, the attestor, the signature and {@code binding} equal to {@link #attestationBinding});
     * checks freshness (hardware: the server's nonce age, which is required; software: the signed validity window, plus the nonce age
     * when {@code nonceIssuedAt} is given); and matches the identity against {@code agent_binding}. The first failure is the result:
     * {@code {ok, present, bound, reason?, identity?}}; {@code bound} is true only for a verified, bound attestation. Never throws.
     */
    public static Map<String, Object> verifyAttestation(Map<String, Object> input, HardwareVerifier hardware) {
        Object doc = input.get("document");
        boolean present = doc instanceof Map || doc instanceof List;
        try {
            Object ctx = input.get("ctx"), expected = input.get("expected"), nowO = input.get("nowMs");
            // an unreadable clock would make every window and age comparison false, i.e. pass: refuse
            if (!finite(nowO)) return failed(present, "verifier clock is not a finite time (fail closed)");
            double nowMs = IntentJs.num(nowO);
            Set<String> trusted = stringSet(input.get("trustedAttestorKeys"));
            double skew = finite(input.get("clockSkewMs")) ? Math.max(0, IntentJs.num(input.get("clockSkewMs"))) : 0;
            double maxAge = Math.min(finite(input.get("maxNonceAgeMs")) && IntentJs.num(input.get("maxNonceAgeMs")) > 0 ? IntentJs.num(input.get("maxNonceAgeMs")) : MAX_ATTESTATION_AGE_MS, MAX_ATTESTATION_AGE_MS);
            boolean hasHw = hardware != null;

            if (!present) return failed(false, "no attestation document for this action");
            String expectedB64;
            try {
                expectedB64 = attestationBindingB64u(expected);
            } catch (RuntimeException e) {
                return failed(true, "attestation binding not constructible: " + msg(e));
            }
            if (!Ledger.jsEq(path(ctx, "pcactn", "grant_ref"), get(expected, "grantRef"))) return failed(true, "attestation binding: PCActn grant_ref differs from expected grant");
            if (!Ledger.jsEq(path(ctx, "pcactn", "attestation", "epoch"), get(expected, "epoch"))) return failed(true, "attestation binding: PCActn attestation epoch differs from expected epoch");
            if (!Ledger.jsEq(path(ctx, "pcactn", "attestation", "quote_digest"), get(expected, "nonce"))) return failed(true, "attestation nonce does not bind to this PCActn");
            if (!Ledger.jsEq(get(doc, "nonce"), get(expected, "nonce"))) return failed(true, "attestation nonce does not match the server-issued nonce");
            Map<String, Object> d = StoreJs.map(doc); // the nonce check passed, so the document is an object

            if (ctx == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'grant')");
            Map<String, Object> env = Authorize.readEnvelope(get(ctx, "grant"));
            Object agentBinding = env == null ? null : env.get("agent_binding");
            boolean requireHw = Boolean.TRUE.equals(get(agentBinding, "require_hardware"));
            if (requireHw && !hasHw) return failed(true, "agent_binding.require_hardware: no hardware verifier is configured (fail closed)");
            if (requireHw && !"hardware".equals(d.get("mode"))) return failed(true, "agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)");

            Object identity;
            if (hasHw) {
                String age = nonceAgeReason(get(expected, "nonceIssuedAt"), nowMs, skew, maxAge);
                if (age != null) return failed(true, age);
                Object res = hardware.verify(mapOf("document", doc, "ctx", ctx, "nowMs", nowO, "expected", expected));
                if (res == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'ok')");
                Map<String, Object> hw = res instanceof Map ? StoreJs.map(res) : new LinkedHashMap<>();
                if (!Zk.truthy(hw.get("ok"))) {
                    Object why = hw.get("reason");
                    return failed(true, "hardware attestation rejected: " + (why == null ? "invalid" : text(why, true)));
                }
                if (!Boolean.TRUE.equals(hw.get("bound"))) return failed(true, "hardware verifier did not confirm report_data binding");
                if (!Zk.truthy(hw.get("measured"))) return failed(true, "hardware verifier returned no measured identity");
                identity = hw.get("measured");
            } else {
                if (!"software".equals(d.get("mode"))) return failed(true, "document mode " + text(d.get("mode"), d.containsKey("mode")) + " needs a hardwareVerifier");
                if (!(d.get("attestor") instanceof String) || !trusted.contains(d.get("attestor"))) return failed(true, "attestor key is not trusted");
                if (!Pq.sigAlgKnown(d.get("alg"), d.containsKey("alg"))) return failed(true, "attestation declares an unknown signature alg");
                boolean sigOk = false;
                if (d.get("sig") instanceof String) {
                    Map<String, Object> body = new LinkedHashMap<>(d);
                    body.remove("sig");
                    body.remove("pq_sig");
                    sigOk = IntentJs.verifyPinnedSuite(d.get("alg"), d.containsKey("alg"), (String) d.get("attestor"), d.get("pq_pk"), attestMessage(body),
                        d.get("sig"), d.get("pq_sig"), StoreJs.map(input.get("pqPins")));
                }
                if (!sigOk) return failed(true, "attestation signature does not verify");
                if (!(d.get("binding") instanceof String) || ((String) d.get("binding")).isEmpty()) return failed(true, "attestation is not bound (binding absent)");
                if (!expectedB64.equals(d.get("binding"))) return failed(true, "attestation binding mismatch (holder/grant/epoch/nonce)");
                if (!finite(d.get("issued_at")) || !finite(d.get("expires_at")) || IntentJs.num(d.get("expires_at")) < IntentJs.num(d.get("issued_at"))) {
                    return failed(true, "malformed attestation validity window");
                }
                if (!(nowMs + skew >= IntentJs.num(d.get("issued_at")))) return failed(true, "attestation not yet valid");
                if (!(nowMs - skew <= IntentJs.num(d.get("expires_at")))) return failed(true, "attestation expired");
                if (isNum(get(expected, "nonceIssuedAt"))) {
                    String age = nonceAgeReason(get(expected, "nonceIssuedAt"), nowMs, skew, maxAge);
                    if (age != null) return failed(true, age);
                }
                Map<String, Object> soft = new LinkedHashMap<>();
                for (String k : new String[] {"model_id", "weights_digest", "runtime_measurement", "operator"}) if (d.containsKey(k)) soft.put(k, d.get(k));
                if (d.get("system_prompt_digest") instanceof String) soft.put("system_prompt_digest", d.get("system_prompt_digest"));
                if (d.get("tool_manifest_digest") instanceof String) soft.put("tool_manifest_digest", d.get("tool_manifest_digest"));
                identity = soft;
            }
            String why = matchAgentBinding(identity, agentBinding);
            if (why != null) return failed(true, why);
            return verdict(true, true, true, null, identity);
        } catch (Exception | StackOverflowError e) {
            return failed(present, "attestation verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }

    // ---- the verifier hook ----

    /** The options of {@link #createAttestationVerifier}. */
    public static final class VerifierOptions {
        /** Single-use nonce store: the nonce is consumed ONCE, only after the attestation verified and is bound. Without it the nonce is only checked for age. */
        public NonceStore nonceStore;
        /** Minimum nonce entropy in bytes (null: 16, the floor). Not applied in the self-declared-nonce mode. */
        public Object minNonceBytes;
        /** The b64u public keys trusted to sign software documents (a list; anything else trusts none). */
        public Object trustedAttestorKeys;
        /** Present: HARDWARE mode, which delegates authenticity to this verifier instead of the signature. */
        public HardwareVerifier hardwareVerifier;
        /** How to find the document for an action (null: resolves nothing). */
        public Function<Object, Map<String, Object>> resolveDocument;
        /** The SERVER-SUPPLIED expected binding of an action (null: none; then the hook fails closed unless the self-declared opt-out is on). */
        public Function<Object, Object> expectedBinding;
        /** LOUD OPT-OUT (legacy, development only): derive the expected binding from the PCActn itself, its {@code quote_digest} as the nonce. Replay protection is void. */
        public boolean insecureSelfDeclaredNonce;
        public Object maxNonceAgeMs;
        public Object clockSkewMs;
        /** Verifier-pinned PQ keys of the software attestors (Ed25519 identity to ML-DSA public key). */
        public Map<String, Object> pqPins;
        /** The clock, epoch milliseconds (null: the system clock). */
        public DoubleSupplier now;
    }

    /** An attestation hook: {@code apply(ctx)} is {@code {enforced: true, ok, reason?, present, bound}}. Never throws; carries its assurance label. */
    public static final class Hook implements Function<Object, Map<String, Object>>, Assurance.Labelled {
        private final NonceStore store;
        private final Object minNonceBytes, maxNonceAgeMs, clockSkewMs;
        private final Object trusted;
        private final HardwareVerifier hardware;
        private final Function<Object, Map<String, Object>> resolve;
        private final Function<Object, Object> expectedBinding;
        private final boolean insecure;
        private final Map<String, Object> pqPins;
        private final DoubleSupplier clock;
        private final Assurance.Label label;

        private Hook(VerifierOptions o) {
            store = o.nonceStore;
            minNonceBytes = o.minNonceBytes;
            maxNonceAgeMs = o.maxNonceAgeMs;
            clockSkewMs = o.clockSkewMs;
            trusted = o.trustedAttestorKeys instanceof List ? new ArrayList<Object>((List<?>) o.trustedAttestorKeys) : new ArrayList<Object>();
            hardware = o.hardwareVerifier;
            resolve = o.resolveDocument;
            expectedBinding = o.expectedBinding;
            insecure = o.insecureSelfDeclaredNonce;
            pqPins = o.pqPins == null ? null : new LinkedHashMap<>(o.pqPins);
            clock = o.now == null ? () -> System.currentTimeMillis() : o.now;
            // the label comes from the configuration, never from a document
            Assurance.Label hw = hardware == null ? null : Assurance.labelOf(hardware);
            label = insecure ? new Assurance.Label("unknown", "insecure-self-declared-nonce", false, null)
                : hardware != null ? (hw != null ? hw : Assurance.Label.of("unknown")) : Assurance.Label.of("software");
        }

        @Override public Assurance.Label assuranceLabel() { return label; }

        private static Map<String, Object> fin(boolean ok, String reason, boolean present, boolean bound) {
            Map<String, Object> m = mapOf("enforced", true, "ok", ok);
            if (reason != null && !reason.isEmpty()) m.put("reason", reason);
            m.put("present", present);
            m.put("bound", bound);
            return m;
        }

        @Override public Map<String, Object> apply(Object ctx) {
            try {
                Map<String, Object> document = resolve == null ? null : resolve.apply(ctx);
                Object expected = null;
                if (expectedBinding != null) {
                    expected = expectedBinding.apply(ctx);
                } else if (insecure) {
                    Object chain = path(ctx, "pcactn", "cap_chain");
                    Object leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? ((List<?>) chain).get(((List<?>) chain).size() - 1) : get(ctx, "grant");
                    expected = mapOf("holderPub", get(leaf, "holder") instanceof String ? get(leaf, "holder") : "", "grantRef", path(ctx, "pcactn", "grant_ref"),
                        "epoch", path(ctx, "pcactn", "attestation", "epoch"), "nonce", path(ctx, "pcactn", "attestation", "quote_digest"));
                }
                if (expected == null) return fin(false, "no server-issued attestation nonce/binding available (fail closed)", document != null, false);
                Object nonce = get(expected, "nonce");
                if (!insecure && !nonceEntropyOk(nonce, minNonceBytes)) {
                    return fin(false, "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)", document != null, false);
                }
                Map<String, Object> in = new LinkedHashMap<>();
                in.put("document", document);
                in.put("ctx", ctx);
                in.put("expected", expected);
                in.put("nowMs", clock.getAsDouble());
                in.put("trustedAttestorKeys", trusted);
                in.put("pqPins", pqPins);
                in.put("maxNonceAgeMs", maxNonceAgeMs);
                in.put("clockSkewMs", clockSkewMs);
                Map<String, Object> v = verifyAttestation(in, hardware);
                boolean ok = Boolean.TRUE.equals(v.get("ok")), bound = Boolean.TRUE.equals(v.get("bound")), pres = Boolean.TRUE.equals(v.get("present"));
                if (ok && bound && store != null && !store.consume(nonce)) return fin(false, "attestation nonce already consumed (replay)", pres, false);
                return fin(ok, (String) v.get("reason"), pres, bound);
            } catch (Exception | StackOverflowError e) {
                return fin(false, "attestation verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), false, false);
            }
        }
    }

    /**
     * The hook over {@link #verifyAttestation}. The expected binding comes from {@code expectedBinding} (the server-issued nonce); with
     * neither it nor the loud self-declared opt-out the hook fails closed. The nonce must carry 128 bits of entropy and, with a store,
     * is consumed once after a verified, bound attestation.
     */
    public static Hook createAttestationVerifier(VerifierOptions opts) { return new Hook(opts); }

    // ---- multi-root ----

    /** One independent attestation root: a distinct hardware or software trust anchor. {@code suite} is an audit label only. */
    public static final class Root {
        public final String id;
        public final HardwareVerifier verifier;
        public final boolean required;
        public final String suite;

        public Root(String id, HardwareVerifier verifier, boolean required, String suite) { this.id = id; this.verifier = verifier; this.required = required; this.suite = suite; }

        public Root(String id, HardwareVerifier verifier) { this(id, verifier, false, null); }
    }

    private static final String[] IDENT_FIELDS = {"model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"};

    /** The verifier {@link #createMultiRootVerifier} builds: the seam, with an assurance label. */
    public static final class MultiRoot implements HardwareVerifier, Assurance.Labelled {
        private final List<Root> roots;
        private final double threshold;
        private final Assurance.Label label;

        private MultiRoot(List<Root> roots, double threshold) {
            this.roots = Collections.unmodifiableList(new ArrayList<>(roots));
            this.threshold = threshold;
            List<Assurance.Root> ar = new ArrayList<>();
            List<String> ids = new ArrayList<>();
            for (Root r : this.roots) { ar.add(new Assurance.Root(r.verifier, r.required)); ids.add(r.id); }
            this.label = new Assurance.Label(Assurance.multiRootLevel(ar, threshold), "multi-root:" + String.join("+", ids), false, null);
        }

        @Override public Assurance.Label assuranceLabel() { return label; }

        private static String[] identOf(Object measured) {
            String[] out = new String[IDENT_FIELDS.length];
            if (measured instanceof Map) {
                for (int i = 0; i < out.length; i++) {
                    Object v = ((Map<?, ?>) measured).get(IDENT_FIELDS[i]);
                    out[i] = v instanceof String && !((String) v).isEmpty() ? (String) v : null;
                }
            }
            return out;
        }

        /**
         * Runs EVERY root against the same input; denies when a REQUIRED root did not verify (ok, bound and measured), naming it; denies
         * below the threshold; reconciles the corroborating roots' identities and denies on a contradiction; else returns the reconciled
         * identity with {@code bound: true}.
         */
        @Override public Object verify(Map<String, Object> input) {
            try {
                List<Integer> passed = new ArrayList<>();
                List<String[]> idents = new ArrayList<>();
                List<Boolean> measuredFlags = new ArrayList<>();
                Map<String, Object> host = new LinkedHashMap<>();
                for (int i = 0; i < roots.size(); i++) {
                    Root root = roots.get(i);
                    Object res;
                    try {
                        res = root.verifier.verify(input);
                    } catch (Exception | StackOverflowError e) {
                        res = mapOf("ok", false, "reason", "root '" + root.id + "' threw (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
                    }
                    Map<String, Object> m = res instanceof Map ? StoreJs.map(res) : res instanceof List ? new LinkedHashMap<>() : null;
                    boolean passes = m != null && Boolean.TRUE.equals(m.get("ok")) && Boolean.TRUE.equals(m.get("bound")) && Zk.truthy(m.get("measured"));
                    if (passes) {
                        passed.add(i);
                        idents.add(identOf(m.get("measured")));
                        measuredFlags.add(Boolean.TRUE.equals(get(m.get("measured"), "weights_measured")));
                        if (m.get("hostAsserted") instanceof Map) {
                            for (Map.Entry<String, Object> e : StoreJs.map(m.get("hostAsserted")).entrySet()) host.put(root.id + "." + e.getKey(), e.getValue());
                        }
                    } else if (root.required) {
                        String why = m == null ? "root '" + root.id + "' returned a malformed result (fail closed)" : m.get("reason") == null ? "invalid" : text(m.get("reason"), true);
                        return mapOf("ok", false, "reason", "required attestation root '" + root.id + "' failed: " + why);
                    }
                }
                if (passed.size() < threshold) {
                    return mapOf("ok", false, "reason", "multi-root attestation below threshold (" + passed.size() + "/" + AttestCommon.jsNumString(threshold) + " independent roots corroborated)");
                }
                String[] chosen = new String[IDENT_FIELDS.length];
                for (int f = 0; f < IDENT_FIELDS.length; f++) {
                    int who = -1;
                    for (int k = 0; k < passed.size(); k++) {
                        String v = idents.get(k)[f];
                        if (v == null) continue;
                        if (chosen[f] == null) { chosen[f] = v; who = passed.get(k); }
                        else if (!chosen[f].equals(v)) {
                            return mapOf("ok", false, "reason", "multi-root attestation identity conflict: roots '" + roots.get(who).id + "' and '" + roots.get(passed.get(k)).id
                                + "' disagree on " + IDENT_FIELDS[f]);
                        }
                    }
                }
                boolean weightsMeasured = false;
                for (int k = 0; k < passed.size() && chosen[1] != null; k++) weightsMeasured |= measuredFlags.get(k) && chosen[1].equals(idents.get(k)[1]);
                Map<String, Object> measured = mapOf("model_id", chosen[0] == null ? "" : chosen[0], "weights_digest", chosen[1] == null ? "" : chosen[1],
                    "weights_measured", weightsMeasured, "runtime_measurement", chosen[2] == null ? "" : chosen[2], "operator", chosen[3] == null ? "" : chosen[3]);
                if (chosen[4] != null) measured.put("system_prompt_digest", chosen[4]);
                if (chosen[5] != null) measured.put("tool_manifest_digest", chosen[5]);
                Map<String, Object> out = mapOf("ok", true, "bound", true, "measured", measured);
                if (!host.isEmpty()) out.put("hostAsserted", host);
                return out;
            } catch (RuntimeException e) {
                return mapOf("ok", false, "reason", "multi-root attestation error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        }
    }

    /**
     * A verifier requiring corroboration from at least {@code threshold} of the independent {@code roots}. It plugs into
     * {@link VerifierOptions#hardwareVerifier} like a single-root verifier. Throws on no roots, a threshold that is not an integer in
     * [1, roots], an empty id or duplicate ids.
     */
    public static MultiRoot createMultiRootVerifier(List<Root> roots, double threshold) {
        if (roots == null || roots.isEmpty()) throw new IllegalArgumentException("createMultiRootVerifier: at least one attestation root is required");
        if (Double.isNaN(threshold) || Double.isInfinite(threshold) || threshold != Math.rint(threshold) || threshold < 1 || threshold > roots.size()) {
            throw new IllegalArgumentException("createMultiRootVerifier: threshold must be an integer in [1, roots.length]");
        }
        Set<String> ids = new HashSet<>();
        for (Root r : roots) {
            if (r == null || r.id == null || r.id.isEmpty()) throw new IllegalArgumentException("createMultiRootVerifier: each root needs a non-empty id");
            if (!ids.add(r.id)) throw new IllegalArgumentException("createMultiRootVerifier: duplicate root id '" + r.id + "'");
        }
        return new MultiRoot(roots, threshold);
    }

    // ---- anchoring ----

    /**
     * The canonical, domain-separated digest of a verified attestation {@code {identity, binding, rootIds?, suite?, verifiedAt}}: the
     * leaf appended to the transparency log. It binds the measured identity AND the holder, grant, epoch and nonce, so two
     * verifications that measured different identities, or bound to different actions, anchor to different leaves. Throws on a member
     * that is missing or has no canonical form.
     */
    public static String attestationEvidenceDigest(Object ev) {
        Object identity = get(ev, "identity"), binding = get(ev, "binding");
        if (!(ev instanceof Map)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'binding')");
        if (!(identity instanceof Map) || !(binding instanceof Map)) throw new IllegalArgumentException("Cannot read properties of undefined");
        Map<String, Object> e = StoreJs.map(ev), id = StoreJs.map(identity), bind = StoreJs.map(binding);
        List<Object> roots = new ArrayList<>();
        Object rid = e.get("rootIds");
        if (rid instanceof List) roots.addAll((List<?>) rid);
        else if (rid instanceof String) ((String) rid).codePoints().forEach(c -> roots.add(new String(Character.toChars(c))));
        else if (rid != null) throw new IllegalArgumentException("object is not iterable");
        roots.sort((a, b) -> text(a, true).compareTo(text(b, true)));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("domain", ATTEST_ANCHOR_DOMAIN);
        for (String[] kv : new String[][] {{"holder", "holderPub"}, {"grant", "grantRef"}, {"epoch", "epoch"}, {"nonce", "nonce"}}) {
            if (!bind.containsKey(kv[1])) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(kv[0], bind.get(kv[1]));
        }
        for (String k : new String[] {"model_id", "weights_digest"}) {
            if (!id.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(k, id.get(k));
        }
        m.put("weights_measured", Boolean.TRUE.equals(id.get("weights_measured")));
        for (String k : new String[] {"runtime_measurement", "operator"}) {
            if (!id.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(k, id.get(k));
        }
        m.put("system_prompt_digest", id.get("system_prompt_digest") == null ? "" : id.get("system_prompt_digest"));
        m.put("tool_manifest_digest", id.get("tool_manifest_digest") == null ? "" : id.get("tool_manifest_digest"));
        m.put("roots", roots);
        m.put("suite", e.get("suite") == null ? "" : e.get("suite"));
        if (!e.containsKey("verifiedAt")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        m.put("verified_at", e.get("verifiedAt"));
        return Pca.hashCanonical(IntentJs.normalize(m));
    }

    /** The options of {@link #anchorAttestationEvidence}. */
    public static final class AnchorOptions {
        /** The transparency log to anchor into (null: no log available, which fails closed). */
        public MerkleLog ledger;
        /** The log's principal, recorded in the tree head. */
        public String principal = "";
        /** The guardian seed that signs the tree head; omitted: the commitment is appended but no head is produced (only when not {@code required}). */
        public byte[] guardianSecret;
        /** The tree-head suite; an ml-dsa-65 or hybrid one makes the accountability record post-quantum. */
        public Pq.SignerSuiteOpts suite;
        /** The instance id recorded in the head. */
        public String instanceId;
        /** The clock for the head's timestamp, epoch milliseconds (null: the system clock). */
        public DoubleSupplier now;
        /** When true, anchoring MUST fully succeed (log present, commitment appended, head signed) or throw. */
        public boolean required;
    }

    private static IllegalStateException anchorFail(String why) { return new IllegalStateException("attestation anchoring (fail closed): " + why); }

    /**
     * Anchor a VERIFIED attestation into the transparency log for post-quantum accountability: compute the evidence digest, append it as
     * a commitment and, with a guardian secret, sign the resulting tree head. It does not prevent a forged attestation in real time; it
     * makes one permanently recorded, consistency-checkable and attributable. With {@code required}, a missing log, a missing guardian
     * secret or a failed head signature throws instead of skipping. Returns {@code {index, commit, sth?}}.
     */
    public static Map<String, Object> anchorAttestationEvidence(Object evidence, AnchorOptions opts) {
        boolean required = opts != null && opts.required;
        if (opts == null || opts.ledger == null) throw anchorFail("no transparency ledger available");
        if (required && opts.guardianSecret == null) throw anchorFail("required anchoring needs a guardian secret to sign the tree head");
        MerkleLog ledger = opts.ledger;
        String commit = attestationEvidenceDigest(evidence);
        String prevRoot = ledger.root();
        int index = ledger.appendCommitment(commit);
        Map<String, Object> head = ledger.head();
        Map<String, Object> sth = null;
        if (opts.guardianSecret != null) {
            double now = opts.now == null ? System.currentTimeMillis() : opts.now.getAsDouble();
            try {
                sth = Ledger.signTreeHead(opts.guardianSecret, mapOf("instance_id", opts.instanceId == null ? "" : opts.instanceId, "principal", opts.principal == null ? "" : opts.principal,
                    "size", head.get("size"), "root", head.get("root"), "prev_root", prevRoot, "timestamp", now), opts.suite);
            } catch (RuntimeException e) {
                if (required) throw anchorFail("tree-head signing failed: " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        }
        Map<String, Object> out = mapOf("index", IntentJs.ofLong(index), "commit", commit);
        if (sth != null) out.put("sth", sth);
        return out;
    }
}
