package net.atlasauth.pca.attesteat;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.AttestEatBridge;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.jose.Jose;

/**
 * Per-session attestation FRESHNESS and CHANNEL BINDING for PCA: emit TEE evidence as an EAT (RFC 9711, a compact JWS with typ
 * {@code eat+jwt}), bind it to the live channel and a fresh nonce (IETF SEAT / RA-TLS), and appraise it against RATS endorsements and
 * reference values (RFC 9334). Port of {@code @atlasauth/pca-attest-eat} (the EAT layer; the post-quantum co-signature is
 * {@link AttestEatPq}, admission {@link AttestEatAdmission}, build provenance {@link AttestEatProvenance}, Sigstore verification the core
 * {@code net.atlasauth.pca.Sigstore}).
 *
 * <p>This layer holds NO AMD certificate or report-signature cryptography of its own: {@link #verifyAmdAttestation} delegates to the
 * core's hardened SEV-SNP verifier. Claims, policies and verdicts are JSON-shaped maps with the reference's member names
 * ({@link Json.Num} / {@link Long} numbers); keys are JDK keys (Ed25519 or P-256). Everything fails CLOSED.
 */
public final class AttestEat {
    private AttestEat() {}

    public static final String EAT_TYP = "eat+jwt";
    public static final String DEFAULT_EAT_ALG = "EdDSA";
    public static final long DEFAULT_MAX_AGE_MS = 5 * 60_000L;
    public static final String CHANNEL_BINDING_DOMAIN = "atlas-pca/eat-channel/v1";
    public static final int AMD_SEV_SNP_SIGNED_REGION_END = 0x2a0;
    public static final String AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)";
    public static final List<Integer> KNOWN_REPORT_VERSIONS = List.of(2, 3, 5);
    /** The pinned AMD ARK SPKI SHA-384 (hex) per family: milan, genoa, turin. */
    public static final Map<String, String> KNOWN_AMD_ARK_SPKI_SHA384 = java.util.Collections.unmodifiableMap(AttestEatBridge.arkPins());
    public static final String AMD_MILAN_ARK_SPKI_SHA384 = KNOWN_AMD_ARK_SPKI_SHA384.get("milan");

    private static final List<String> SUPPORTED_ALGS = List.of("EdDSA", "ES256");
    private static final List<String> DBGSTAT_VALUES = List.of("enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently");

    // ---- helpers ----

    @SuppressWarnings("unchecked")
    static Map<String, Object> rec(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return o instanceof List ? (List<Object>) o : null; }

    static boolean isStr(Object o) { return o instanceof String; }

    private static Double num(Object o) { return Jose.num(o); }

    private static boolean finite(Double d) { return d != null && !d.isNaN() && !d.isInfinite(); }

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static String hexOf(byte[] b) { return AttestCommon.toHexLower(b); }

    /** Constant-time string equality over UTF-8 bytes. */
    static boolean strEq(String a, String b) { return MessageDigest.isEqual(utf8(a), utf8(b)); }

    private static String msg(Throwable e) { return e.getMessage() == null ? "unknown" : e.getMessage(); }

    private static boolean isSupportedAlg(Object v) { return v instanceof String && SUPPORTED_ALGS.contains(v); }

    /** RFC 7515 section 4.1.9: a media type is compared case-insensitively and a {@code typ} without a slash is the application/ form. */
    private static String normalizeTyp(String typ) {
        String t = typ.toLowerCase(Locale.ROOT);
        return t.contains("/") ? t : "application/" + t;
    }

    // ---- keys + JWS ----

    /** Generate an EAT signing key pair for {@code alg} (EdDSA: Ed25519, ES256: P-256). */
    public static KeyPair generateEatKeyPair(String alg) {
        try {
            if ("EdDSA".equals(alg)) return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            if ("ES256".equals(alg)) {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                return g.generateKeyPair();
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        throw new IllegalArgumentException("generateEatKeyPair: unsupported alg '" + alg + "'");
    }

    public static KeyPair generateEatKeyPair() { return generateEatKeyPair(DEFAULT_EAT_ALG); }

    private static String signJws(String alg, PrivateKey key, String signingInput) {
        try {
            byte[] data = utf8(signingInput);
            Signature s = Signature.getInstance("EdDSA".equals(alg) ? "Ed25519" : "SHA256withECDSAinP1363Format");
            s.initSign(key);
            s.update(data);
            return b64u(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e.getMessage() == null ? "sign failed" : e.getMessage(), e);
        }
    }

    /** May throw (a key of the wrong type): the reference throws as well. */
    private static boolean verifyJws(String alg, PublicKey key, String signingInput, byte[] sig) {
        try {
            byte[] data = utf8(signingInput);
            if ("EdDSA".equals(alg)) {
                byte[] enc = key.getEncoded();
                String a = key.getAlgorithm();
                if (!("Ed25519".equals(a) || "EdDSA".equals(a)) || enc == null || enc.length != 44) throw new IllegalArgumentException("Unsupported crypto operation");
                return EdStrict.verify(Arrays.copyOfRange(enc, 12, 44), data, sig);
            }
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initVerify(key);
            s.update(data);
            try {
                return s.verify(sig);
            } catch (java.security.SignatureException e) {
                return false;
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e.getMessage() == null ? "verify failed" : e.getMessage(), e);
        }
    }

    // ---- nonce ----

    /**
     * Mint a fresh, single-use nonce: {@code {value, issuedAt}} where value is b64u(random) + "." + issue time in base 36. {@code now} may
     * be null (the clock); {@code bytes} is the random length (minimum 16, default 32).
     */
    public static Map<String, Object> issueNonce(Long now, Integer bytes) {
        long t = now != null ? now : System.currentTimeMillis();
        int n = Math.max(16, bytes != null ? bytes : 32);
        byte[] r = new byte[n];
        new SecureRandom().nextBytes(r);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", b64u(r) + "." + Long.toString(t, 36));
        m.put("issuedAt", t);
        return m;
    }

    // ---- evidence projection + tolerant parse ----

    /** The JSON-safe EAT evidence projection of a parsed report ({@code AttestEatBridge.parseReport}). */
    public static Map<String, Object> evidenceFromReport(Map<String, Object> report) {
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("version", report.get("version"));
        ev.put("measurement", report.get("measurement"));
        ev.put("reported_tcb", report.get("reported_tcb"));
        ev.put("guest_svn", report.get("guest_svn"));
        ev.put("chip_id", report.get("chip_id"));
        ev.put("debug", report.get("debug"));
        return ev;
    }

    /** The PCA measured identity of a parsed report: runtime_measurement = launch measurement, operator = chip id, no weights. */
    public static Map<String, Object> measuredFromReport(Map<String, Object> report) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("model_id", "");
        m.put("weights_digest", "");
        m.put("weights_measured", false);
        m.put("runtime_measurement", report.get("measurement"));
        m.put("operator", report.get("chip_id"));
        return m;
    }

    private static final int FULL_REPORT_MIN_LEN = 0x2e8 + 72;

    private static Long u32(byte[] b, int off) {
        if (off + 4 > b.length) return null;
        return (b[off] & 0xffL) | (b[off + 1] & 0xffL) << 8 | (b[off + 2] & 0xffL) << 16 | (b[off + 3] & 0xffL) << 24;
    }

    private static Long u64(byte[] b, int off) {
        if (off + 8 > b.length) return null;
        long lo = u32(b, off), hi = u32(b, off + 4);
        return lo | hi << 32;
    }

    private static byte[] slice(byte[] b, int off, int len) { return off + len > b.length ? null : Arrays.copyOfRange(b, off, off + len); }

    private static Map<String, Object> tolerant(boolean ok, long version, boolean known, boolean degraded, List<Object> notes, Map<String, Object> report, Map<String, Object> evidence) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        m.put("version", version);
        m.put("known", known);
        m.put("degraded", degraded);
        m.put("notes", notes);
        if (report != null) m.put("report", report);
        if (evidence != null) m.put("evidence", evidence);
        return m;
    }

    /**
     * Parse an AMD SEV-SNP ATTESTATION_REPORT DEFENSIVELY across format versions: a known version with a full buffer is the core's full parse;
     * an unknown version or a short buffer reads the version-stable header fields and is marked degraded. Never throws.
     * Result: {ok, version, known, degraded, notes, report?, evidence?} ({@code report} is the parsed-field map of {@link AttestEatBridge}).
     */
    public static Map<String, Object> parseReportTolerant(byte[] bytes) {
        List<Object> notes = new ArrayList<>();
        if (bytes == null) {
            notes.add("input is not a Uint8Array");
            return tolerant(false, 0, false, true, notes, null, null);
        }
        Long version = u32(bytes, 0);
        if (version == null) {
            notes.add("buffer too short to read the report version");
            return tolerant(false, 0, false, true, notes, null, null);
        }
        boolean known = KNOWN_REPORT_VERSIONS.contains((int) (long) version) && version == (int) (long) version;
        if (known && bytes.length >= FULL_REPORT_MIN_LEN) {
            try {
                Map<String, Object> report = AttestEatBridge.parseReport(bytes);
                return tolerant(true, (Long) report.get("version"), true, false, notes, report, evidenceFromReport(report));
            } catch (RuntimeException e) {
                notes.add("full parse failed, falling back to the stable header: " + msg(e));
            }
        } else if (!known) {
            notes.add("unknown report version " + version + " — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)");
        } else {
            notes.add("buffer length " + bytes.length + " < full report " + FULL_REPORT_MIN_LEN + " — degraded header-only parse");
        }
        byte[] measurement = slice(bytes, 0x090, 48);
        if (measurement == null) {
            notes.add("buffer too short to read the launch measurement");
            return tolerant(false, version, known, true, notes, null, null);
        }
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("version", version);
        ev.put("measurement", hexOf(measurement));
        ev.put("degraded", true);
        Long svn = u32(bytes, 0x004);
        if (svn != null) ev.put("guest_svn", svn);
        Long policy = u64(bytes, 0x008);
        if (policy != null) ev.put("debug", (policy & (1L << 19)) != 0);
        Long tcb = u64(bytes, 0x180);
        if (tcb != null) ev.put("reported_tcb", Long.toUnsignedString(tcb));
        byte[] chip = slice(bytes, 0x1a0, 64);
        if (chip != null) ev.put("chip_id", hexOf(chip));
        return tolerant(true, version, known, true, notes, null, ev);
    }

    // ---- channel binding ----

    /** {@code cnf.tls_exporter} for a TLS channel id: b64u(sha256(DOMAIN || channelId)); plus {@code jkt} when a thumbprint is given. */
    public static Map<String, Object> deriveChannelCnf(Object channelId, Object holderKeyThumbprint) {
        if (!(channelId instanceof String) || ((String) channelId).isEmpty()) throw new IllegalArgumentException("deriveChannelCnf: channelId is required");
        MessageDigest md = sha256();
        md.update(utf8(CHANNEL_BINDING_DOMAIN));
        md.update(utf8((String) channelId));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("tls_exporter", b64u(md.digest()));
        if (holderKeyThumbprint instanceof String && !((String) holderKeyThumbprint).isEmpty()) cnf.put("jkt", holderKeyThumbprint);
        return cnf;
    }

    public static Map<String, Object> deriveChannelCnf(Object channelId) { return deriveChannelCnf(channelId, null); }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Bind attestation evidence to a channel id and a per-session nonce: {@code {evidence, nonce, cnf}}. */
    public static Map<String, Object> bindChannel(Object evidence, Object channelId, Object nonce) {
        if (!(nonce instanceof String) || ((String) nonce).isEmpty()) throw new IllegalArgumentException("bindChannel: a per-session nonce is required for freshness");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("evidence", evidence);
        m.put("nonce", nonce);
        m.put("cnf", deriveChannelCnf(channelId));
        return m;
    }

    // ---- buildEAT / verifyEAT ----

    private static Map<String, Object> resolveCnf(Map<String, Object> args) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (args.containsKey("channelId")) {
            Map<String, Object> d = deriveChannelCnf(args.get("channelId"));
            if (d.get("tls_exporter") != null) out.put("tls_exporter", d.get("tls_exporter"));
        }
        if (args.containsKey("channelBinding")) {
            Object cbO = args.get("channelBinding");
            if (cbO == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'tls_exporter')");
            Map<String, Object> cb = rec(cbO);
            if (cb != null && cb.get("tls_exporter") instanceof String) out.put("tls_exporter", cb.get("tls_exporter"));
            if (cb != null && cb.get("jkt") instanceof String) out.put("jkt", cb.get("jkt"));
        }
        return out;
    }

    /**
     * Build a signed EAT over the given evidence: a compact JWS with the {@code eat+jwt} typ header, {@code iss}, {@code iat}, the
     * {@code eat_nonce} challenge, the {@code cnf} channel binding and the optional {@code measured} / {@code sevsnp} / {@code measurements} /
     * {@code ueid} / {@code sueid} / {@code oemid} / {@code dbgstat} claims. {@code args}: issuer, key (a {@link PrivateKey}), alg?, nonce,
     * channelBinding?, channelId?, measured?, sevsnp?, measurements?, ueid?, sueid?, dbgstat?, oemid?, now?. Requires a nonce AND a channel binding.
     */
    public static String buildEAT(Map<String, Object> args) {
        if (!(args.get("issuer") instanceof String) || ((String) args.get("issuer")).isEmpty()) throw new IllegalArgumentException("buildEAT: issuer is required");
        if (!(args.get("nonce") instanceof String) || ((String) args.get("nonce")).isEmpty()) throw new IllegalArgumentException("buildEAT: nonce (eat_nonce) is required for freshness");
        Object alg = args.containsKey("alg") && args.get("alg") != null ? args.get("alg") : DEFAULT_EAT_ALG;
        if (!isSupportedAlg(alg)) throw new IllegalArgumentException("buildEAT: unsupported alg '" + alg + "'");
        Map<String, Object> cnf = resolveCnf(args);
        if (cnf.get("tls_exporter") == null && cnf.get("jkt") == null) {
            throw new IllegalArgumentException("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence");
        }
        Double nowD = num(args.get("now"));
        double iatMs = finite(nowD) ? nowD : (double) System.currentTimeMillis();

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", args.get("issuer"));
        claims.put("iat", (long) Math.floor(iatMs / 1000));
        claims.put("eat_nonce", args.get("nonce"));
        claims.put("cnf", cnf);
        for (String k : new String[] {"ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp"}) {
            if (args.containsKey(k) && args.get(k) != null) claims.put(k, args.get(k));
            else if (args.containsKey(k)) claims.put(k, null);
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", EAT_TYP);
        String signingInput = b64u(utf8(Jose.stringify(header))) + "." + b64u(utf8(Jose.stringify(claims)));
        Object key = args.get("key");
        if (!(key instanceof PrivateKey)) throw new IllegalArgumentException("buildEAT: key is required");
        return signingInput + "." + signJws((String) alg, (PrivateKey) key, signingInput);
    }

    private static Map<String, Object> parseCnf(Object v) {
        Map<String, Object> r = rec(v);
        if (r == null) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        if (r.get("tls_exporter") instanceof String) out.put("tls_exporter", r.get("tls_exporter"));
        if (r.get("jkt") instanceof String) out.put("jkt", r.get("jkt"));
        return out.isEmpty() ? null : out;
    }

    private static List<Object> parseMeasurements(Object v) {
        List<Object> l = arr(v);
        if (l == null) return null;
        List<Object> out = new ArrayList<>();
        for (Object e : l) {
            Map<String, Object> r = rec(e);
            if (r != null && r.get("type") instanceof String && r.get("value") instanceof String) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type", r.get("type"));
                m.put("value", r.get("value"));
                out.add(m);
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static Object parseTcbVersion(Object v) {
        if (v instanceof String) return v;
        Double d = num(v);
        if (d != null) return finite(d) ? v : null;
        Map<String, Object> r = rec(v);
        if (r == null) return null;
        Map<String, Object> o = new LinkedHashMap<>();
        for (String k : new String[] {"bootloader", "tee", "snp", "microcode"}) if (num(r.get(k)) != null) o.put(k, r.get(k));
        return o;
    }

    private static Map<String, Object> parseMeasured(Object v) {
        Map<String, Object> r = rec(v);
        if (r == null) return null;
        for (String k : new String[] {"model_id", "weights_digest", "runtime_measurement", "operator"}) if (!(r.get(k) instanceof String)) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("model_id", r.get("model_id"));
        out.put("weights_digest", r.get("weights_digest"));
        out.put("runtime_measurement", r.get("runtime_measurement"));
        out.put("operator", r.get("operator"));
        if (r.get("weights_measured") instanceof Boolean) out.put("weights_measured", r.get("weights_measured"));
        if (r.get("system_prompt_digest") instanceof String) out.put("system_prompt_digest", r.get("system_prompt_digest"));
        if (r.get("tool_manifest_digest") instanceof String) out.put("tool_manifest_digest", r.get("tool_manifest_digest"));
        return out;
    }

    private static Map<String, Object> parseSevSnp(Object v) {
        Map<String, Object> r = rec(v);
        if (r == null || num(r.get("version")) == null || !(r.get("measurement") instanceof String)) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", r.get("version"));
        out.put("measurement", r.get("measurement"));
        Object tcb = parseTcbVersion(r.get("reported_tcb"));
        if (tcb != null) out.put("reported_tcb", tcb);
        if (num(r.get("guest_svn")) != null) out.put("guest_svn", r.get("guest_svn"));
        if (r.get("chip_id") instanceof String) out.put("chip_id", r.get("chip_id"));
        if (r.get("debug") instanceof Boolean) out.put("debug", r.get("debug"));
        if (r.get("degraded") instanceof Boolean) out.put("degraded", r.get("degraded"));
        return out;
    }

    /**
     * Verify an EAT's signature, {@code typ} and {@code iss} and parse it into claims. Throws on an invalid signature, wrong key, failed
     * {@code iss}/{@code typ} check, an unsupported {@code alg} or a missing {@code iss}/{@code iat}. A claim of the wrong type is dropped so
     * downstream checks fail closed. {@code verifyKey} is a {@link PublicKey}; {@code opts}: issuer? (string or list), algorithms? (list),
     * typ?, requireTyp?.
     */
    public static Map<String, Object> verifyEAT(Object eat, PublicKey verifyKey, Map<String, Object> opts) {
        if (!(eat instanceof String)) throw new IllegalArgumentException("EAT invalid: token is not a string");
        Jose.CanonicalJws canon;
        try {
            canon = Jose.assertCanonicalCompactJws(eat, 3, 1 << 20, true);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("EAT invalid: " + msg(e));
        }
        String[] parts = ((String) eat).split("\\.", -1);
        if (parts.length != 3) throw new IllegalArgumentException("EAT invalid: expected a compact JWS (header.payload.signature)");
        String h = parts[0], p = parts[1], s = parts[2];
        if (h.isEmpty() || p.isEmpty() || s.isEmpty()) throw new IllegalArgumentException("EAT invalid: empty JWS segment");
        Map<String, Object> header = canon.header;
        Object alg = header.get("alg");
        if (!isSupportedAlg(alg)) throw new IllegalArgumentException("EAT invalid: missing or unsupported `alg` header");
        Object allowedO = opts.get("algorithms");
        List<Object> allowed = allowedO == null ? new ArrayList<Object>(SUPPORTED_ALGS) : arr(allowedO);
        boolean isAllowed;
        if (allowedO instanceof String) isAllowed = alg instanceof String && ((String) allowedO).contains((String) alg); // String.prototype.includes: a substring test
        else if (allowed == null) throw new IllegalArgumentException("opts.algorithms.includes is not a function");
        else isAllowed = allowed.contains(alg);
        if (!isAllowed) throw new IllegalArgumentException("EAT invalid: alg " + alg + " not in the allowed set");
        if (!Boolean.FALSE.equals(opts.get("requireTyp"))) {
            Object wantO = opts.get("typ") != null ? opts.get("typ") : EAT_TYP;
            if (!(wantO instanceof String)) throw new IllegalArgumentException("typ.toLowerCase is not a function");
            String want = (String) wantO;
            if (!(header.get("typ") instanceof String) || !normalizeTyp((String) header.get("typ")).equals(normalizeTyp(want))) {
                throw new IllegalArgumentException("EAT invalid: typ " + jsString(header.get("typ")) + " is not " + want);
            }
        }
        if (!verifyJws((String) alg, verifyKey, h + "." + p, Jose.decodeCanonicalBase64url(s))) throw new IllegalArgumentException("EAT invalid: signature does not verify");

        Map<String, Object> payload = canon.payload;
        if (!(payload.get("iss") instanceof String)) throw new IllegalArgumentException("EAT invalid: missing or non-string `iss`");
        if (!finite(num(payload.get("iat")))) throw new IllegalArgumentException("EAT invalid: missing or non-numeric `iat`");
        if (opts.containsKey("issuer")) {
            Object io = opts.get("issuer");
            List<Object> allowedIss = io instanceof List ? arr(io) : Arrays.asList(io);
            if (!allowedIss.contains(payload.get("iss"))) throw new IllegalArgumentException("EAT invalid: iss " + payload.get("iss") + " is not an accepted issuer");
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", payload.get("iss"));
        claims.put("iat", payload.get("iat"));
        if (payload.get("eat_nonce") instanceof String) claims.put("eat_nonce", payload.get("eat_nonce"));
        Map<String, Object> cnf = parseCnf(payload.get("cnf"));
        if (cnf != null) claims.put("cnf", cnf);
        if (payload.get("ueid") instanceof String) claims.put("ueid", payload.get("ueid"));
        if (payload.get("sueid") instanceof String) claims.put("sueid", payload.get("sueid"));
        List<Object> measurements = parseMeasurements(payload.get("measurements"));
        if (measurements != null) claims.put("measurements", measurements);
        if (payload.get("dbgstat") instanceof String && DBGSTAT_VALUES.contains(payload.get("dbgstat"))) claims.put("dbgstat", payload.get("dbgstat"));
        if (payload.get("oemid") instanceof String) claims.put("oemid", payload.get("oemid"));
        Map<String, Object> measured = parseMeasured(payload.get("measured"));
        if (measured != null) claims.put("measured", measured);
        Map<String, Object> sevsnp = parseSevSnp(payload.get("sevsnp"));
        if (sevsnp != null) claims.put("sevsnp", sevsnp);
        return claims;
    }

    public static Map<String, Object> verifyEAT(Object eat, PublicKey verifyKey) { return verifyEAT(eat, verifyKey, new LinkedHashMap<String, Object>()); }

    /** JavaScript String(v) for the values a parsed header can hold. */
    private static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num) return Json.canonicalize(v);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(jsString(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    // ---- freshness + channel binding ----

    private static Map<String, Object> check(boolean ok, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /**
     * ANTI-REPLAY FRESHNESS: the EAT's {@code eat_nonce} must equal the server-issued challenge AND its {@code iat} must lie within
     * [now - maxAgeMs, now] (allowing {@code clockSkewMs}). {@code opts}: expectedNonce, maxAgeMs, now?, clockSkewMs?. Result {ok, reason?}.
     */
    public static Map<String, Object> verifyFreshness(Map<String, Object> eat, Map<String, Object> opts) {
        Double nowD = num(opts.get("now"));
        double now = finite(nowD) ? nowD : (double) System.currentTimeMillis();
        // A present skew that is not a finite number (NaN, Infinity, a string, null) would disable the age window: refuse it.
        Double skewD = num(opts.get("clockSkewMs"));
        if (opts.containsKey("clockSkewMs") && !finite(skewD)) return check(false, "invalid clockSkewMs (must be a finite number)");
        double skew = skewD == null ? 0 : Math.max(0, skewD);
        Object expected = opts.get("expectedNonce");
        if (!(expected instanceof String) || ((String) expected).isEmpty()) return check(false, "no expected (server-issued) nonce supplied (fail closed)");
        Object nonce = eat.get("eat_nonce");
        if (!(nonce instanceof String) || ((String) nonce).isEmpty()) return check(false, "EAT carries no eat_nonce — cannot establish freshness (replayable)");
        if (!strEq((String) nonce, (String) expected)) return check(false, "eat_nonce does not match the server-issued challenge (replayed or relayed evidence)");
        Double iat = num(eat.get("iat"));
        if (!finite(iat)) return check(false, "EAT has no valid iat (cannot establish age)");
        Double max = num(opts.get("maxAgeMs"));
        if (!finite(max) || max <= 0) return check(false, "invalid maxAgeMs");
        double iatMs = iat * 1000;
        if (!(iatMs - skew <= now)) return check(false, "EAT iat is in the future");
        if (!(now - iatMs <= max + skew)) return check(false, "EAT is stale (iat older than maxAgeMs) — expired/replayed attestation");
        return check(true, null);
    }

    /**
     * CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from {@code channelId} and/or an explicit {@code expectedCnf}) must be
     * present and equal in the token's {@code cnf}; a token with no cnf, or bound to another channel or key, fails closed. Result {ok, reason?}.
     */
    public static Map<String, Object> verifyChannelBinding(Map<String, Object> eat, Map<String, Object> opts) {
        Map<String, Object> exp = new LinkedHashMap<>();
        if (opts.get("channelId") instanceof String && !((String) opts.get("channelId")).isEmpty()) {
            Map<String, Object> d = deriveChannelCnf(opts.get("channelId"));
            if (d.get("tls_exporter") != null) exp.put("tls_exporter", d.get("tls_exporter"));
        }
        if (opts.containsKey("expectedCnf")) {
            Object ecO = opts.get("expectedCnf");
            if (ecO == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'tls_exporter')");
            Map<String, Object> ec = rec(ecO);
            if (ec != null) {
                if (ec.get("tls_exporter") instanceof String) exp.put("tls_exporter", ec.get("tls_exporter"));
                if (ec.get("jkt") instanceof String) exp.put("jkt", ec.get("jkt"));
            }
        }
        if (exp.isEmpty()) return check(false, "no expected channel binding supplied (fail closed)");
        Map<String, Object> cnf = rec(eat.get("cnf"));
        if (cnf == null || cnf.get("tls_exporter") == null && cnf.get("jkt") == null) {
            return check(false, "EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)");
        }
        if (exp.get("tls_exporter") != null && !(cnf.get("tls_exporter") instanceof String && strEq((String) cnf.get("tls_exporter"), (String) exp.get("tls_exporter")))) {
            return check(false, "TLS-exporter channel binding mismatch (evidence lifted to another channel?)");
        }
        if (exp.get("jkt") != null && !(cnf.get("jkt") instanceof String && strEq((String) cnf.get("jkt"), (String) exp.get("jkt")))) {
            return check(false, "holder-key thumbprint (cnf.jkt) mismatch");
        }
        return check(true, null);
    }

    // ---- RATS appraisal ----

    private static boolean tierTrustworthy(String tier) { return tier.equals("affirming-hw-rooted") || tier.equals("affirming") || tier.equals("warning"); }

    private static BigInteger comp(Map<String, Object> r, String k) {
        if (r == null || !r.containsKey(k)) return BigInteger.ZERO;
        Double d = num(r.get(k));
        if (d == null || d != Math.floor(d) || Double.isInfinite(d) || d < 0 || (d == 0 && 1 / d < 0) || d > 255) return null;
        return BigInteger.valueOf((long) (double) d);
    }

    /** Pack a TCB version (a number, a decimal string, or the SEV-SNP components) into a comparable integer; null when its shape is unknown. */
    static BigInteger packTcb(Object v) {
        Double d = num(v);
        if (d != null) return !Double.isNaN(d) && !Double.isInfinite(d) && d >= 0 ? new BigDecimal(Math.floor(d)).toBigInteger() : null;
        if (v instanceof String) {
            String t = AttestCommon.jsTrim((String) v);
            return t.matches("[0-9]+") ? new BigInteger(t) : null;
        }
        if (!(v instanceof Map)) return null; // true, [] and null are not a TCB version
        Map<String, Object> r = rec(v);
        BigInteger bl = comp(r, "bootloader");
        BigInteger tee = comp(r, "tee");
        BigInteger snp = comp(r, "snp");
        BigInteger uc = comp(r, "microcode");
        if (bl == null || tee == null || snp == null || uc == null) return null;
        return bl.or(tee.shiftLeft(8)).or(snp.shiftLeft(48)).or(uc.shiftLeft(56));
    }

    /** Array.prototype.includes over parsed JSON: numbers by value, other scalars by value, objects never equal. */
    private static boolean includes(List<Object> list, Object x) {
        Double dx = x instanceof Json.Num || x instanceof Number ? num(x) : null;
        for (Object o : list) {
            if (x instanceof Map || x instanceof List) return false;
            Double d = o instanceof Json.Num || o instanceof Number ? num(o) : null;
            if (dx != null || d != null) { if (dx != null && d != null && (dx.equals(d) || dx.doubleValue() == d.doubleValue())) return true; }
            else if (java.util.Objects.equals(o, x)) return true;
        }
        return false;
    }

    private static String lc(Object s) {
        if (!(s instanceof String)) throw new IllegalArgumentException("s.toLowerCase is not a function");
        return ((String) s).toLowerCase(Locale.ROOT);
    }

    private static boolean lcIncludes(List<Object> list, String needle) {
        boolean hit = false;
        for (Object o : list) if (lc(o).equals(needle)) hit = true; // every element is lower-cased (as .map(lc) does), a non-string throws
        return hit;
    }

    private static Object prop(Object o, String k) { Map<String, Object> r = rec(o); return r == null ? null : r.get(k); }

    private static boolean nonEmptyList(Object o) { List<Object> l = arr(o); return l != null && !l.isEmpty(); }

    private static Map<String, Object> verdict(String tier, boolean trustworthy, List<Object> reasons) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("tier", tier);
        m.put("trustworthy", trustworthy);
        m.put("reasons", reasons);
        return m;
    }

    private static List<Object> plusReason(List<Object> reasons, String reason) {
        List<Object> r = new ArrayList<>(reasons);
        r.add(reason);
        return r;
    }

    private static String launchMeasurement(Map<String, Object> eat) {
        Object measured = eat.get("measured");
        if (measured != null && !Boolean.FALSE.equals(measured) && prop(measured, "runtime_measurement") instanceof String && !((String) prop(measured, "runtime_measurement")).isEmpty()) {
            return (String) prop(measured, "runtime_measurement");
        }
        Object sevsnp = eat.get("sevsnp");
        if (sevsnp != null && prop(sevsnp, "measurement") instanceof String) return (String) prop(sevsnp, "measurement");
        return findMeasurement(eat.get("measurements"), "launch", "measurement");
    }

    private static String findMeasurement(Object measurements, String... types) {
        if (measurements == null) return null;
        List<Object> l = arr(measurements);
        if (l == null) throw new IllegalArgumentException("eat.measurements?.find is not a function");
        for (Object e : l) {
            Object t = prop(e, "type");
            for (String ty : types) if (ty.equals(t)) { Object v = prop(e, "value"); return v instanceof String ? (String) v : null; }
        }
        return null;
    }

    private static String weightsMeasurement(Map<String, Object> eat) {
        Object measured = eat.get("measured");
        if (measured != null && prop(measured, "weights_digest") instanceof String && !((String) prop(measured, "weights_digest")).isEmpty()) return (String) prop(measured, "weights_digest");
        return findMeasurement(eat.get("measurements"), "weights");
    }

    /** True/false when the debug status is known, else null (the caller fails closed). */
    private static Boolean isDebugDisabled(Map<String, Object> eat) {
        if (eat.containsKey("dbgstat")) return eat.get("dbgstat") instanceof String && DBGSTAT_VALUES.contains(eat.get("dbgstat")) ? Boolean.valueOf(!"enabled".equals(eat.get("dbgstat"))) : null; // not an RFC 9711 value: unknown
        Object sevsnp = eat.get("sevsnp");
        if (sevsnp != null && prop(sevsnp, "debug") instanceof Boolean) return Boolean.FALSE.equals(prop(sevsnp, "debug"));
        return null;
    }

    /**
     * APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as distinct arguments. Result
     * {tier, trustworthy, reasons}; tiers: affirming-hw-rooted, affirming, warning, contraindicated, rejected. {@code extras}:
     * hardwareVerified?, hardwareRootLabel?. An empty policy is rejected. Does NOT re-verify the AMD chain or report signature.
     */
    public static Map<String, Object> appraise(Map<String, Object> evidence, Map<String, Object> referenceValues, Map<String, Object> endorsements, Map<String, Object> extras) {
        List<Object> reasons = new ArrayList<>();
        if (referenceValues == null || endorsements == null || extras == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'issuers')");
        Map<String, Object> rv = referenceValues;
        Map<String, Object> en = endorsements;
        Map<String, Object> ex = extras;

        boolean hasEndorsements = nonEmptyList(en.get("issuers")) || nonEmptyList(en.get("oemids")) || nonEmptyList(en.get("operators"));
        boolean hasReferenceValues = nonEmptyList(rv.get("measurements")) || nonEmptyList(rv.get("models")) || nonEmptyList(rv.get("weightsMeasurements"))
            || Boolean.TRUE.equals(rv.get("requireMeasuredWeights")) || rv.containsKey("minTcb") || num(rv.get("minGuestSvn")) != null
            || Boolean.TRUE.equals(rv.get("requireDebugDisabled"));
        if (!hasEndorsements && !hasReferenceValues) {
            return verdict("rejected", false, new ArrayList<Object>(List.of("empty appraisal policy: no endorsements or reference values to appraise against (fail closed)")));
        }

        if (nonEmptyList(en.get("issuers"))) {
            if (!includes(arr(en.get("issuers")), evidence.get("iss"))) return verdict("rejected", false, plusReason(reasons, "issuer " + jsString(evidence.get("iss")) + " is not an endorsed attester"));
            reasons.add("issuer endorsed");
        }
        if (nonEmptyList(en.get("oemids"))) {
            if (!(evidence.get("oemid") instanceof String) || !arr(en.get("oemids")).contains(evidence.get("oemid"))) return verdict("rejected", false, plusReason(reasons, "oemid absent or not endorsed (fail closed)"));
            reasons.add("oemid endorsed");
        }
        if (nonEmptyList(en.get("operators"))) {
            Object op = prop(evidence.get("measured"), "operator");
            if (!(op instanceof String) || ((String) op).isEmpty() || !arr(en.get("operators")).contains(op)) return verdict("rejected", false, plusReason(reasons, "hardware operator absent or not endorsed (fail closed)"));
            reasons.add("operator endorsed");
        }

        if (nonEmptyList(rv.get("measurements"))) {
            String m = launchMeasurement(evidence);
            if (m == null) return verdict("rejected", false, plusReason(reasons, "no launch measurement in evidence to compare against reference values (fail closed)"));
            if (!lcIncludes(arr(rv.get("measurements")), m.toLowerCase(Locale.ROOT))) return verdict("contraindicated", false, plusReason(reasons, "launch measurement not in reference values"));
            reasons.add("launch measurement matches a reference value");
        }
        if (nonEmptyList(rv.get("models"))) {
            Object model = prop(evidence.get("measured"), "model_id");
            if (!(model instanceof String) || ((String) model).isEmpty()) return verdict("rejected", false, plusReason(reasons, "no model id in evidence (fail closed)"));
            if (!arr(rv.get("models")).contains(model)) return verdict("contraindicated", false, plusReason(reasons, "model id not in reference values (model swap?)"));
            reasons.add("model id matches a reference value");
        }
        if (Boolean.TRUE.equals(rv.get("requireMeasuredWeights"))) {
            if (!Boolean.TRUE.equals(prop(evidence.get("measured"), "weights_measured"))) {
                return verdict("contraindicated", false, plusReason(reasons, "weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"));
            }
            reasons.add("weights digest is hardware-measured");
        }
        if (nonEmptyList(rv.get("weightsMeasurements"))) {
            String w = weightsMeasurement(evidence);
            if (w == null || w.isEmpty()) return verdict("rejected", false, plusReason(reasons, "no measured-weights digest in evidence (fail closed)"));
            if (!lcIncludes(arr(rv.get("weightsMeasurements")), w.toLowerCase(Locale.ROOT))) return verdict("contraindicated", false, plusReason(reasons, "weights measurement not in reference values (model swap / fine-tune?)"));
            reasons.add("weights measurement matches a reference value");
        }
        if (rv.containsKey("minTcb")) {
            BigInteger min = packTcb(rv.get("minTcb"));
            if (min == null) return verdict("rejected", false, plusReason(reasons, "reference minTcb is not a comparable TCB version"));
            Object rawTcb = prop(evidence.get("sevsnp"), "reported_tcb");
            BigInteger got = rawTcb != null ? packTcb(rawTcb) : null;
            if (got == null) return verdict("rejected", false, plusReason(reasons, "evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)"));
            if (got.compareTo(min) < 0) return verdict("contraindicated", false, plusReason(reasons, "reported TCB is below the reference minimum (downgrade / rollback)"));
            reasons.add("TCB at or above reference minimum");
        }
        if (num(rv.get("minGuestSvn")) != null) {
            Double svn = num(prop(evidence.get("sevsnp"), "guest_svn"));
            if (!finite(svn)) return verdict("rejected", false, plusReason(reasons, "guest_svn absent (fail closed)"));
            double min = num(rv.get("minGuestSvn"));
            if (svn < min) return verdict("contraindicated", false, plusReason(reasons, "guest_svn " + AttestCommon.jsNumString(svn) + " below reference minimum " + AttestCommon.jsNumString(min)));
            reasons.add("guest_svn at or above reference minimum");
        }
        if (Boolean.TRUE.equals(rv.get("requireDebugDisabled"))) {
            Boolean disabled = isDebugDisabled(evidence);
            if (disabled == null) return verdict("rejected", false, plusReason(reasons, "debug status unknown — failing closed"));
            if (!disabled) return verdict("contraindicated", false, plusReason(reasons, "debug is enabled (host can inspect the guest — no confidentiality)"));
            reasons.add("debug disabled");
        }

        if (Boolean.TRUE.equals(prop(evidence.get("sevsnp"), "degraded"))) {
            return verdict("warning", true, plusReason(reasons, "evidence came from a degraded (version-tolerant) parse — review"));
        }
        if (Boolean.TRUE.equals(ex.get("hardwareVerified"))) {
            Object label = ex.containsKey("hardwareRootLabel") && ex.get("hardwareRootLabel") != null ? ex.get("hardwareRootLabel") : AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
            return verdict("affirming-hw-rooted", true, plusReason(reasons, "AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — " + jsString(label)));
        }
        return verdict("affirming", true, reasons);
    }

    public static Map<String, Object> appraise(Map<String, Object> evidence, Map<String, Object> referenceValues, Map<String, Object> endorsements) {
        return appraise(evidence, referenceValues, endorsements, new LinkedHashMap<String, Object>());
    }

    public static Map<String, Object> appraise(Map<String, Object> evidence, Map<String, Object> referenceValues) {
        return appraise(evidence, referenceValues, new LinkedHashMap<String, Object>(), new LinkedHashMap<String, Object>());
    }

    public static Map<String, Object> appraise(Map<String, Object> evidence) {
        return appraise(evidence, new LinkedHashMap<String, Object>(), new LinkedHashMap<String, Object>(), new LinkedHashMap<String, Object>());
    }

    // ---- AMD hardware root of trust (delegated to the core verifier) ----

    private static byte[] certToDer(Object input) {
        if (input instanceof byte[]) return (byte[]) input;
        if (!(input instanceof String)) throw new IllegalArgumentException("certificate input must be DER bytes or a PEM string");
        List<String> blocks = AttestCommon.pemCertBlocks((String) input);
        if (blocks.size() != 1) throw new IllegalArgumentException("expected exactly one PEM certificate, found " + blocks.size());
        String b = blocks.get(0);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----").matcher(b);
        if (!m.find() || m.group(1).isEmpty()) throw new IllegalArgumentException("pemToDer: no certificate found");
        return AttestCommon.nodeB64(m.group(1).replaceAll("\\s+", ""));
    }

    private static String derToPem(byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der).replaceAll("(.{64})", "$1\n");
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private static Map<String, Object> amdResult(boolean ok, String reason, Map<String, Object> report, boolean withEvidence) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        m.put("hardwareRoot", AMD_SEV_SNP_HARDWARE_ROOT_LABEL);
        if (report != null) m.put("report", report);
        if (withEvidence && report != null) {
            m.put("evidence", evidenceFromReport(report));
            m.put("measured", measuredFromReport(report));
        }
        return m;
    }

    /**
     * Verify an AMD SEV-SNP report end to end by delegating to the core's hardened verifier (per-family ARK pin, CA roles, critical
     * extensions, validity windows against {@code nowMs}, VCEK-to-report binding, ECDSA-P384 report signature), then project the verified
     * report into EAT evidence. {@code opts}: vcek, ask, ark (DER bytes or a PEM string), family XOR trustAnchorArkSpkiSha384, nowMs,
     * clockSkewMs?, expectedMeasurement?, allowDebug?. Result {ok, reason?, hardwareRoot, report?, evidence?, measured?}; never throws.
     * (A missing {@code nowMs} fails closed with the clock-required reason straight away.)
     */
    public static Map<String, Object> verifyAmdAttestation(byte[] rawReport, Map<String, Object> opts) {
        try {
            boolean hasFamily = opts.containsKey("family");
            boolean hasPin = opts.containsKey("trustAnchorArkSpkiSha384");
            if (hasFamily == hasPin) return amdResult(false, "exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)", null, false);
            String pin;
            if (hasFamily) {
                Object f = opts.get("family");
                String fromFamily = f instanceof String ? KNOWN_AMD_ARK_SPKI_SHA384.get(f) : null;
                if (fromFamily == null) return amdResult(false, "unknown AMD family " + jsString(f) + " (expected milan | genoa | turin)", null, false);
                pin = fromFamily;
            } else {
                if (!(opts.get("trustAnchorArkSpkiSha384") instanceof String)) throw new IllegalArgumentException("pin.toLowerCase is not a function");
                pin = (String) opts.get("trustAnchorArkSpkiSha384");
            }
            byte[] vcekDer;
            String askArkPem;
            try {
                vcekDer = certToDer(opts.get("vcek"));
                askArkPem = derToPem(certToDer(opts.get("ask"))) + derToPem(certToDer(opts.get("ark")));
            } catch (RuntimeException e) {
                return amdResult(false, "certificate parse failed: " + msg(e), null, false);
            }
            Map<String, Object> parsed;
            try {
                parsed = AttestEatBridge.parseReport(rawReport);
            } catch (RuntimeException e) {
                parsed = null;
            }
            Double now = num(opts.get("nowMs"));
            if (!finite(now)) return amdResult(false, "cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check", parsed, false);
            if (rawReport == null) return amdResult(false, "report parse failed: parseSevSnpReport: expected Uint8Array", null, false); // the reference's report is not a Uint8Array
            Object expected = opts.get("expectedMeasurement");
            String expectedM = expected instanceof String && !((String) expected).isEmpty() ? (String) expected : null;
            Object skew = opts.get("clockSkewMs");
            Map<String, Object> v = AttestEatBridge.verifyGenuineSevSnp(rawReport, vcekDer, askArkPem, pin, (long) (double) now, skew, expectedM, Boolean.TRUE.equals(opts.get("allowDebug")));
            String reason = (String) v.get("reason");
            @SuppressWarnings("unchecked") Map<String, Object> report = (Map<String, Object>) v.get("report");
            if (!reason.isEmpty() || report == null) return amdResult(false, reason.isEmpty() ? "AMD SEV-SNP verification failed" : reason, parsed, false);
            return amdResult(true, null, report, true);
        } catch (RuntimeException e) {
            return amdResult(false, "AMD attestation verification error (fail closed): " + msg(e), null, false);
        }
    }

    // ---- composition: verify + freshness + channel binding + appraisal ----

    private static Map<String, Object> fresh(boolean ok, String tier, List<Object> reasons, Map<String, Object> claims) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (tier != null) m.put("tier", tier);
        m.put("reasons", reasons);
        if (claims != null) m.put("claims", claims);
        return m;
    }

    /**
     * The end-to-end check a resource server runs: verify the EAT's signature, then its FRESHNESS, its CHANNEL BINDING and finally APPRAISE it
     * against the RATS policy; the first failing gate stops the pipeline and names the reason. {@code opts}: verifyKey ({@link PublicKey}),
     * amd? (rawReport, vcek, ask, ark, family | trustAnchorArkSpkiSha384, clockSkewMs?, allowDebug?, expectedMeasurement?), nonce, channelId?,
     * channelBinding?, policy {endorsements?, referenceValues?}, now?, maxAgeMs?, clockSkewMs?, issuer?, algorithms?, typ?, requireTyp?.
     * Result {ok, tier?, reasons, claims?}.
     */
    public static Map<String, Object> verifyFreshAttestedEAT(Object eat, Map<String, Object> opts) {
        List<Object> reasons = new ArrayList<>();
        Map<String, Object> claims;
        try {
            Map<String, Object> vo = new LinkedHashMap<>();
            for (String k : new String[] {"issuer", "algorithms", "typ", "requireTyp"}) if (opts.containsKey(k)) vo.put(k, opts.get(k));
            claims = verifyEAT(eat, (PublicKey) opts.get("verifyKey"), vo);
        } catch (RuntimeException e) {
            return fresh(false, null, new ArrayList<Object>(List.of("EAT signature/claims invalid: " + msg(e))), null);
        }
        reasons.add("signature + typ/iss verified");

        Double nowD = num(opts.get("now"));
        double now = finite(nowD) ? nowD : (double) System.currentTimeMillis();
        Map<String, Object> fo = new LinkedHashMap<>();
        fo.put("expectedNonce", opts.get("nonce"));
        fo.put("maxAgeMs", opts.containsKey("maxAgeMs") && opts.get("maxAgeMs") != null ? opts.get("maxAgeMs") : (Object) DEFAULT_MAX_AGE_MS);
        fo.put("now", now);
        if (opts.containsKey("clockSkewMs") && opts.get("clockSkewMs") != null) fo.put("clockSkewMs", opts.get("clockSkewMs"));
        Map<String, Object> f = verifyFreshness(claims, fo);
        if (!Boolean.TRUE.equals(f.get("ok"))) return fresh(false, null, plusReason(reasons, f.get("reason") != null ? (String) f.get("reason") : "not fresh"), claims);
        reasons.add("fresh (nonce + iat within window)");

        Map<String, Object> co = new LinkedHashMap<>();
        if (opts.containsKey("channelId") && opts.get("channelId") != null) co.put("channelId", opts.get("channelId"));
        if (opts.containsKey("channelBinding")) co.put("expectedCnf", opts.get("channelBinding"));
        Map<String, Object> c = verifyChannelBinding(claims, co);
        if (!Boolean.TRUE.equals(c.get("ok"))) return fresh(false, null, plusReason(reasons, c.get("reason") != null ? (String) c.get("reason") : "channel binding failed"), claims);
        reasons.add("channel-bound (cnf matches live channel)");

        Map<String, Object> extras = new LinkedHashMap<>();
        if (opts.containsKey("amd")) {
            Map<String, Object> amd = rec(opts.get("amd"));
            if (amd == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'expectedMeasurement')");
            Object expectedMeasurement = amd.get("expectedMeasurement") != null ? amd.get("expectedMeasurement") : launchMeasurement(claims);
            Map<String, Object> ao = new LinkedHashMap<>();
            for (String k : new String[] {"vcek", "ask", "ark", "family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug"}) if (amd.containsKey(k)) ao.put(k, amd.get(k));
            ao.put("nowMs", now);
            if (expectedMeasurement != null) ao.put("expectedMeasurement", expectedMeasurement);
            Object raw = amd.get("rawReport");
            Map<String, Object> hw = verifyAmdAttestation(raw instanceof byte[] ? (byte[]) raw : null, ao);
            if (!Boolean.TRUE.equals(hw.get("ok"))) {
                return fresh(false, "contraindicated", plusReason(reasons, "AMD hardware root verification failed: " + (hw.get("reason") != null ? hw.get("reason") : "unknown")), claims);
            }
            reasons.add("AMD SEV-SNP hardware root verified (" + hw.get("hardwareRoot") + ")");
            extras.put("hardwareVerified", true);
            extras.put("hardwareRootLabel", hw.get("hardwareRoot"));
        }
        Map<String, Object> pol = rec(opts.get("policy"));
        if (pol == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'referenceValues')");
        Map<String, Object> rvIn = rec(pol.get("referenceValues")), enIn = rec(pol.get("endorsements"));
        Map<String, Object> app = appraise(claims, rvIn == null ? new LinkedHashMap<String, Object>() : rvIn, enIn == null ? new LinkedHashMap<String, Object>() : enIn, extras);
        List<Object> all = new ArrayList<>(reasons);
        all.addAll(arr(app.get("reasons")));
        return fresh(Boolean.TRUE.equals(app.get("trustworthy")), (String) app.get("tier"), all, claims);
    }
}
