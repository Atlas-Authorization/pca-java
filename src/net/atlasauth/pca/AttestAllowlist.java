package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Signed, versioned, expiring measurement-allowlist manifests: the measurements a verifier may accept (TDX MRTD / RTMR, SEV-SNP, GCP
 * image digests, NVIDIA measurements and driver versions, Azure MAA signing and chain keys, corroboration digests), published by a named
 * issuer under a signature suite, with a validity window, per-entry expiry and revocation, and a rollback floor. A manifest is verified
 * against issuer keys the VERIFIER registers, then projected to the policy fields of each vendor verifier. Manifests, options and results
 * are decoded JSON (maps and lists); a refusal is a result with a {@code code}, never an exception.
 */
public final class AttestAllowlist {
    private AttestAllowlist() {}

    public static final List<String> ALLOWLIST_KINDS = List.of("tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement",
        "nvidia-driver-version", "maa-signing-spki", "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration");
    /** The domain prefix of the signed bytes; it ends in a newline. */
    public static final String DOMAIN = "pca-attest-allowlist/v1\n";

    private static final Pattern HEX96 = Pattern.compile("[0-9a-f]{96}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern IMAGE_DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern DRIVER_VERSION = Pattern.compile("[0-9]{1,6}(\\.[0-9]{1,6}){1,3}");
    private static final Pattern CORROBORATION_LABEL = Pattern.compile("vantages=[1-9][0-9]{0,2};method=[\\x20-\\x7e]{1,150}");
    private static final Pattern ISSUER_URL = Pattern.compile("https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?");
    private static final Set<String> BODY_KEYS = Set.of("version", "issuedAt", "notBefore", "expiresAt", "entries");
    private static final Set<String> ENTRY_KEYS = Set.of("kind", "value", "label", "notAfter", "revoked");
    private static final Set<String> MANIFEST_KEYS = Set.of("body", "issuer", "alg", "sig", "pq_sig");
    private static final int MAX_ENTRIES = 10_000;

    private static boolean onlyKeys(Object r, Set<String> allowed) { return allowed.containsAll(((Map<?, ?>) r).keySet()); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean hasControlChar(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 0x1f || c == 0x7f) return true;
        }
        return false;
    }

    private static String valueError(String kind, String value, String label) {
        switch (kind) {
            case "tdx-mrtd": case "tdx-rtmr": case "sev-snp-measurement": case "nvidia-measurement":
                return HEX96.matcher(value).matches() ? null : kind + " must be 96 lowercase hex chars";
            case "gcp-image-digest":
                return IMAGE_DIGEST.matcher(value).matches() ? null : "gcp-image-digest must be sha256:<64 lowercase hex>";
            case "nvidia-driver-version":
                return DRIVER_VERSION.matcher(value).matches() && value.length() <= 16 ? null : "nvidia-driver-version must be a dotted version of at most 16 chars";
            case "maa-signing-spki":
                if (!HEX64.matcher(value).matches()) return "maa-signing-spki must be 64 lowercase hex chars";
                return ISSUER_URL.matcher(label).matches() ? null : "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)";
            case "maa-chain-root-spki": case "maa-chain-intermediate-spki":
                return HEX64.matcher(value).matches() ? null : kind + " must be 64 lowercase hex chars";
            default: // attest-corroboration
                if (!HEX64.matcher(value).matches()) return "attest-corroboration must be a 64 lowercase hex evidence digest";
                return CORROBORATION_LABEL.matcher(label).matches() ? null : "attest-corroboration label must be vantages=<n>;method=<text>";
        }
    }

    /**
     * Validate and normalize a manifest body {@code {version, issuedAt, notBefore, expiresAt, entries}}: exactly those members; a positive
     * integer version; integer epoch-millisecond times with {@code notBefore < expiresAt} and {@code issuedAt <= expiresAt}; at most 10000
     * entries, each {@code {kind, value, label, notAfter?, revoked?}} with a known kind, a value of that kind's shape, a printable label of
     * 1..200 characters, an integer {@code notAfter} and {@code revoked} only ever true; no duplicate value (per label for a MAA signing key).
     * Throws on any violation; unknown members and non-canonical forms are refused, not dropped.
     */
    static Map<String, Object> parseBody(Object x) {
        if (!(x instanceof Map) || !onlyKeys(x, BODY_KEYS)) throw new IllegalArgumentException("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries");
        Map<String, Object> b = StoreJs.map(x);
        Object version = b.get("version"), issuedAt = b.get("issuedAt"), notBefore = b.get("notBefore"), expiresAt = b.get("expiresAt"), entries = b.get("entries");
        if (!IntentJs.isSafeInteger(version) || IntentJs.num(version) < 1) throw new IllegalArgumentException("version must be a positive integer");
        if (!IntentJs.isNonNeg(issuedAt) || !IntentJs.isNonNeg(notBefore) || !IntentJs.isNonNeg(expiresAt)) throw new IllegalArgumentException("issuedAt/notBefore/expiresAt must be integer epoch ms");
        if (!(IntentJs.num(notBefore) < IntentJs.num(expiresAt))) throw new IllegalArgumentException("notBefore must be before expiresAt");
        if (!(IntentJs.num(issuedAt) <= IntentJs.num(expiresAt))) throw new IllegalArgumentException("issuedAt must not be after expiresAt");
        if (!(entries instanceof List) || ((List<?>) entries).size() > MAX_ENTRIES) throw new IllegalArgumentException("entries must be an array (bounded)");
        Set<String> seen = new HashSet<>();
        List<Object> out = new ArrayList<>();
        int i = 0;
        for (Object eo : (List<?>) entries) {
            if (!(eo instanceof Map) || !onlyKeys(eo, ENTRY_KEYS)) throw new IllegalArgumentException("entry " + i + ": unexpected shape");
            Map<String, Object> e = StoreJs.map(eo);
            Object kind = e.get("kind"), value = e.get("value"), label = e.get("label");
            if (!(kind instanceof String) || !ALLOWLIST_KINDS.contains(kind)) throw new IllegalArgumentException("entry " + i + ": unknown kind");
            if (!(value instanceof String) || !(label instanceof String)) throw new IllegalArgumentException("entry " + i + ": value and label must be strings");
            String l = (String) label, v = (String) value, k = (String) kind;
            if (l.length() < 1 || l.length() > 200 || hasControlChar(l)) throw new IllegalArgumentException("entry " + i + ": label must be 1..200 printable chars");
            String ve = valueError(k, v, l);
            if (ve != null) throw new IllegalArgumentException("entry " + i + ": " + ve);
            if (e.containsKey("notAfter") && !IntentJs.isNonNeg(e.get("notAfter"))) throw new IllegalArgumentException("entry " + i + ": notAfter must be integer epoch ms");
            if (e.containsKey("revoked") && !Boolean.TRUE.equals(e.get("revoked"))) throw new IllegalArgumentException("entry " + i + ": revoked, when present, must be true");
            String dup = k + "\u0000" + (k.equals("maa-signing-spki") ? l + "\u0000" : "") + v;
            if (!seen.add(dup)) throw new IllegalArgumentException("entry " + i + ": duplicate " + k + " value");
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("kind", k);
            row.put("value", v);
            row.put("label", l);
            if (e.containsKey("notAfter")) row.put("notAfter", e.get("notAfter"));
            if (e.containsKey("revoked")) row.put("revoked", true);
            out.add(row);
            i++;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", version);
        body.put("issuedAt", issuedAt);
        body.put("notBefore", notBefore);
        body.put("expiresAt", expiresAt);
        body.put("entries", out);
        return body;
    }

    private static byte[] signedBytes(Map<String, Object> body) {
        return Pca.concat(DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(IntentJs.normalize(body)));
    }

    private static Map<String, Object> fail(String code, String reason) { return Issue.obj("ok", false, "code", code, "reason", reason); }

    private static boolean finiteNumber(Object o) { return IntentJs.isFinite(o); }

    private static String suiteKeyOf(Pq.Suite s, Map<String, Object> keys) {
        Object pk;
        switch (s.pq == null ? Pq.Prim.ML_DSA_65 : s.pq) {
            case ML_DSA_65: pk = keys.get("mlDsaPub"); break;
            case SLH_DSA_SHA2_128F: pk = keys.get("slhDsaPub"); break;
            case ML_DSA_87: pk = keys.get("mlDsa87Pub"); break;
            case SLH_DSA_SHA2_256S: pk = keys.get("slhDsa256sPub"); break;
            case FN_DSA_512: pk = keys.get("fnDsa512Pub"); break;
            case FN_DSA_1024: pk = keys.get("fnDsa1024Pub"); break;
            default: pk = keys.get("lessCat1Pub"); break;
        }
        return pk instanceof String ? (String) pk : null;
    }

    /**
     * Verify a signed manifest {@code {body, issuer, alg, sig, pq_sig?}} against {@code opts = {issuerKeys, nowMs, minVersion?, lastSeenVersion?,
     * lastSeenDigest?, clockSkewMs?, maxLifetimeMs?}}; {@code issuerKeys} maps an issuer to {@code {alg, keys: {edPub?, mlDsaPub?, ...},
     * notAfter?}}. In order: the shape and options; the issuer is registered, for this suite and not expired; the signature (a post-quantum
     * half verifies under the REGISTERED key only); the options; the validity window with skew and the lifetime cap; the version floor and
     * the rollback check. Returns {@code {ok: true, body, issuer, alg, version, digest}} or {@code {ok: false, code, reason}} with the code one
     * of malformed, unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired, rollback, below-min-version, conflict,
     * lifetime-too-long. Never throws.
     */
    public static Map<String, Object> verifyAllowlistManifest(Object manifest, Map<String, Object> opts) {
        try {
            if (!(manifest instanceof Map) || !onlyKeys(manifest, MANIFEST_KEYS)) return fail("malformed", "manifest has an unexpected shape");
            if (!IntentJs.isSafeInteger(get(opts, "nowMs"))) return fail("malformed", "nowMs must be an integer");
            double nowMs = IntentJs.num(get(opts, "nowMs"));
            Map<String, Object> m = StoreJs.map(manifest);
            Object issuer = m.get("issuer"), alg = m.get("alg"), sig = m.get("sig"), pqSig = m.get("pq_sig");
            if (!(issuer instanceof String) || ((String) issuer).isEmpty() || ((String) issuer).length() > 200) return fail("malformed", "issuer must be a string");
            if (!(alg instanceof String) || !Pq.isKnownSigAlg(alg)) return fail("malformed", "unknown signature alg");
            if (!(sig instanceof String)) return fail("malformed", "sig must be a string");
            if (m.containsKey("pq_sig") && !(pqSig instanceof String)) return fail("malformed", "pq_sig must be a string");
            Pq.Suite suite = Pq.resolveSigAlg(alg, true);
            if (suite.needsPqSig != m.containsKey("pq_sig")) return fail("malformed", "pq_sig presence does not match the suite");
            Map<String, Object> body;
            try {
                body = parseBody(m.get("body"));
            } catch (RuntimeException e) {
                return fail("malformed", e.getMessage() == null ? "invalid body" : e.getMessage());
            }
            Object issuerKeys = get(opts, "issuerKeys");
            if (!(issuerKeys instanceof Map)) throw new IllegalArgumentException("Cannot convert undefined or null to object");
            if (!((Map<?, ?>) issuerKeys).containsKey(issuer)) return fail("unknown-issuer", "issuer '" + issuer + "' is not registered");
            Object reg = ((Map<?, ?>) issuerKeys).get(issuer);
            if (reg == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'alg')");
            if (!alg.equals(get(reg, "alg"))) return fail("alg-mismatch", "issuer is registered for '" + IntentRevocation.jsText(get(reg, "alg"), get(reg, "alg") != null) + "', manifest claims '" + alg + "'");
            if (reg instanceof Map && ((Map<?, ?>) reg).containsKey("notAfter") && !(nowMs <= Actions.jsNumber(((Map<?, ?>) reg).get("notAfter"), true))) return fail("issuer-expired", "issuer key is past its notAfter");
            Object keysO = get(reg, "keys");
            if (!(keysO instanceof Map)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'edPub')");
            Map<String, Object> keys = StoreJs.map(keysO);
            String edPub = keys.get("edPub") instanceof String ? (String) keys.get("edPub") : null;
            String pk = suite.needsPqPk ? suiteKeyOf(suite, keys) : null;
            Pq.PinnedPq pq = pk != null ? Pq.resolvePqVerifyKey("", null, null, null, pk) : null;
            if (!Pq.verifyWithSuite(alg, edPub, pq, signedBytes(body), sig, pqSig)) return fail("bad-signature", "signature does not verify under the registered issuer key");
            if (opts.containsKey("clockSkewMs") && !finiteNumber(opts.get("clockSkewMs"))) return fail("malformed", "clockSkewMs must be a finite number");
            if (opts.containsKey("maxLifetimeMs") && !finiteNumber(opts.get("maxLifetimeMs"))) return fail("malformed", "maxLifetimeMs must be a finite number");
            if (opts.containsKey("minVersion") && !IntentJs.isSafeInteger(opts.get("minVersion"))) return fail("malformed", "minVersion must be an integer");
            if (opts.containsKey("lastSeenVersion") && !IntentJs.isSafeInteger(opts.get("lastSeenVersion"))) return fail("malformed", "lastSeenVersion must be an integer");
            double skew = Math.max(0, opts.containsKey("clockSkewMs") ? IntentJs.num(opts.get("clockSkewMs")) : 0);
            double notBefore = IntentJs.num(body.get("notBefore")), expiresAt = IntentJs.num(body.get("expiresAt")), version = IntentJs.num(body.get("version"));
            if (!(nowMs + skew >= notBefore)) return fail("not-yet-valid", "manifest is not yet valid");
            if (!(nowMs - skew <= expiresAt)) return fail("expired", "manifest has expired");
            if (opts.containsKey("maxLifetimeMs") && expiresAt - notBefore > IntentJs.num(opts.get("maxLifetimeMs"))) return fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs");
            if (opts.containsKey("minVersion") && version < IntentJs.num(opts.get("minVersion"))) return fail("below-min-version", "version " + AttestCommon.jsNumString(version) + " < minVersion " + AttestCommon.jsNumString(IntentJs.num(opts.get("minVersion"))));
            String digest = Pca.hashCanonical(IntentJs.normalize(body));
            if (opts.containsKey("lastSeenVersion")) {
                double last = IntentJs.num(opts.get("lastSeenVersion"));
                if (version < last) return fail("rollback", "version " + AttestCommon.jsNumString(version) + " is older than last seen " + AttestCommon.jsNumString(last));
                if (version == last && opts.containsKey("lastSeenDigest") && !digest.equals(opts.get("lastSeenDigest"))) return fail("conflict", "same version as last seen but a different body");
            }
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("body", body);
            ok.put("issuer", issuer);
            ok.put("alg", alg);
            ok.put("version", body.get("version"));
            ok.put("digest", digest);
            return ok;
        } catch (RuntimeException e) {
            return fail("malformed", e.getMessage() == null ? "verification error" : e.getMessage());
        }
    }

    private static final Pattern B64U43 = Pattern.compile("[A-Za-z0-9_-]{43}");

    /** The persisted high-water mark {version, digest}, or null when it is not one. */
    private static Map<String, Object> parseHighWater(Object x) {
        if (!(x instanceof Map)) return null;
        Object v = ((Map<?, ?>) x).get("version"), d = ((Map<?, ?>) x).get("digest");
        if (!IntentJs.isInt(v) || !(d instanceof String) || !B64U43.matcher((String) d).matches()) return null;
        return StoreJs.map(x);
    }

    /**
     * {@link #verifyAllowlistManifest} with the rollback floor persisted in {@code kv} at {@code allowlist/<issuer>} as
     * {@code {version, digest}}: a lower version than the stored one is {@code rollback}, the same version with a different digest is
     * {@code conflict}, a corrupt record is {@code malformed}, and the record is written only after a successful verification, under the
     * store's atomic update (so a newer manifest accepted concurrently is never overwritten). {@code opts} are those of the manifest verifier
     * without {@code lastSeenVersion} / {@code lastSeenDigest}.
     */
    public static Map<String, Object> verifyAllowlistDurable(Object manifest, Map<String, Object> opts, AtomicKv kv) {
        try {
            Object issuerO = get(manifest, "issuer");
            if (!(manifest instanceof Map) || !(issuerO instanceof String) || ((String) issuerO).length() > 200) return fail("malformed", "issuer must be a string");
            String key = "allowlist/" + issuerO;
            Object raw = kv.get(key);
            Map<String, Object> prior = raw == null ? null : parseHighWater(raw);
            if (raw != null && prior == null) return fail("malformed", "persisted allowlist high-water mark is corrupt");
            Map<String, Object> o = new LinkedHashMap<>(opts);
            if (prior != null) { o.put("lastSeenVersion", prior.get("version")); o.put("lastSeenDigest", prior.get("digest")); }
            Map<String, Object> v = verifyAllowlistManifest(manifest, o);
            if (!Boolean.TRUE.equals(v.get("ok"))) return v;
            double version = IntentJs.num(v.get("version"));
            String digest = (String) v.get("digest");
            int[] kind = new int[1]; // the record at update time: 0 missing, 1 corrupt, 2 a high-water mark
            @SuppressWarnings("unchecked") Map<String, Object>[] atUpdate = new Map[1];
            boolean[] ran = new boolean[1];
            Object stored = kv.update(key, cur -> {
                ran[0] = true;
                atUpdate[0] = cur == null ? null : parseHighWater(cur);
                kind[0] = cur == null ? 0 : atUpdate[0] == null ? 1 : 2;
                if (kind[0] == 1) return null; // a corrupt record is left alone
                if (kind[0] == 2 && IntentJs.num(atUpdate[0].get("version")) >= version) return null; // append-only: a stored version >= ours stays
                return Issue.obj("version", v.get("version"), "digest", digest);
            });
            if (!ran[0]) {
                // the store answered without running the updater: the returned record IS the record at update time; nothing parseable means our acceptance was never recorded
                atUpdate[0] = stored == null ? null : parseHighWater(stored);
                if (atUpdate[0] == null) return fail("rollback", "a newer manifest was accepted concurrently");
                kind[0] = 2;
            }
            if (kind[0] == 1) return fail("rollback", "a newer manifest was accepted concurrently");
            boolean kept = kind[0] == 2 && IntentJs.num(atUpdate[0].get("version")) >= version;
            double after = kept ? IntentJs.num(atUpdate[0].get("version")) : version;
            Object afterDigest = kept ? atUpdate[0].get("digest") : digest;
            if (after > version) return fail("rollback", "a newer manifest was accepted concurrently");
            if (after == version && !digest.equals(afterDigest)) return fail("conflict", "same version as the stored high-water mark but a different body");
            return v;
        } catch (RuntimeException e) {
            return fail("malformed", e.getMessage() == null ? "durable verification error" : e.getMessage());
        }
    }

    /** Validate and normalize a manifest body (see {@link #parseBody}); throws on any violation. */
    public static Map<String, Object> createAllowlistManifest(Object body) { return parseBody(body); }

    /** Sign a body under {@code alg} with the issuer's secrets; the signature covers {@code DOMAIN || canonical(body)}. Throws on an invalid body or missing key material. */
    public static Map<String, Object> signAllowlistManifest(Object body, String issuer, String alg, Pq.SuiteSecretKeys secrets) {
        Map<String, Object> clean = parseBody(body);
        Pq.SuiteSignatureParts parts = Pq.signWithSuite(alg, secrets, signedBytes(clean));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("body", clean);
        m.put("issuer", issuer);
        m.put("alg", alg);
        m.put("sig", parts.sig);
        if (parts.pqSig != null) m.put("pq_sig", parts.pqSig);
        return m;
    }

    /**
     * The next manifest body that revokes one entry: version + 1 and the given times; an entry of that kind and value (and, for a MAA signing
     * key, label) is marked revoked, else a tombstone {@code {kind, value, label ?? "revoked", revoked: true}} is appended. Throws when the
     * result is not a valid body. {@code rev = {kind, value, label?}}, {@code times = {issuedAt, notBefore, expiresAt}}.
     */
    public static Map<String, Object> revokeAllowlistEntry(Map<String, Object> prev, Map<String, Object> rev, Map<String, Object> times) {
        Object prevEntries = prev.get("entries");
        if (!(prevEntries instanceof List)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'map')");
        List<Object> entries = new ArrayList<>();
        Map<String, Object> hit = null;
        for (Object e : (List<?>) prevEntries) {
            Map<String, Object> row = e instanceof Map ? new LinkedHashMap<>(StoreJs.map(e)) : new LinkedHashMap<>();
            entries.add(row);
            if (hit == null && Ledger.jsEq(row.get("kind"), rev.get("kind")) && Ledger.jsEq(row.get("value"), rev.get("value"))
                && (!"maa-signing-spki".equals(rev.get("kind")) || Ledger.jsEq(row.get("label"), rev.get("label")))) hit = row;
        }
        if (hit != null) hit.put("revoked", true);
        else entries.add(Issue.obj("kind", rev.get("kind"), "value", rev.get("value"), "label", rev.get("label") != null ? rev.get("label") : "revoked", "revoked", true));
        Double v = IntentJs.num(prev.get("version"));
        Map<String, Object> next = new LinkedHashMap<>();
        next.put("version", v == null ? "invalid" : StoreJs.num(v + 1));
        for (Map.Entry<String, Object> t : times.entrySet()) next.put(t.getKey(), t.getValue());
        next.put("entries", entries);
        return parseBody(next);
    }

    /** The 32 hex-character slot of a dotted driver version: its ASCII bytes in hex, zero padded. Throws on a version that is not 1.2 .. 123456.123456.123456.123456 shaped or is over 16 characters. */
    public static String driverVersionSlotHex(String version) {
        if (!DRIVER_VERSION.matcher(version).matches() || version.length() > 16) throw new IllegalArgumentException("invalid driver version");
        StringBuilder sb = new StringBuilder(AttestCommon.toHexLower(version.getBytes(StandardCharsets.US_ASCII)));
        while (sb.length() < 32) sb.append('0');
        return sb.toString();
    }

    /**
     * Project a VERIFIED manifest to the lists the vendor verifiers take, at {@code opts.nowMs}: revoked values are denied (a revoked value is
     * denied in every label), entries past their {@code notAfter} are listed as expired and not allowed. Throws on a manifest that is not the
     * result of {@link #verifyAllowlistManifest}.
     */
    public static Map<String, Object> projectAllowlist(Map<String, Object> verified, Map<String, Object> opts) {
        Map<String, Object> body = StoreJs.map(verified.get("body"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : new String[] {"tdxMrtds", "tdxRtmrs", "sevSnpMeasurements", "imageDigests", "nvidiaMeasurements", "nvidiaDriverVersions", "nvidiaCcDriverVersions"}) out.put(k, new ArrayList<Object>());
        Map<String, Object> maa = new LinkedHashMap<>();
        out.put("maaSigningSpkis", maa);
        out.put("maaChainRootSpkis", new ArrayList<Object>());
        out.put("maaChainIntermediateSpkis", new ArrayList<Object>());
        out.put("corroboration", new ArrayList<Object>());
        List<Object> revoked = new ArrayList<>(), expired = new ArrayList<>();
        out.put("revoked", revoked);
        out.put("expired", expired);
        out.put("version", body.get("version"));
        out.put("manifestExpiresAt", body.get("expiresAt"));
        double now = IntentJs.num(opts.get("nowMs"));
        Set<String> denied = new HashSet<>();
        List<Map<String, Object>> entries = new ArrayList<>();
        for (Object eo : (List<?>) body.get("entries")) entries.add(StoreJs.map(eo));
        for (Map<String, Object> e : entries) {
            if (Boolean.TRUE.equals(e.get("revoked"))) {
                denied.add(e.get("kind") + "\u0000" + e.get("value"));
                revoked.add(Issue.obj("kind", e.get("kind"), "value", e.get("value"), "label", e.get("label")));
            }
        }
        for (Map<String, Object> e : entries) {
            if (Boolean.TRUE.equals(e.get("revoked"))) continue;
            String kind = (String) e.get("kind"), value = (String) e.get("value");
            if (denied.contains(kind + "\u0000" + value)) continue;
            if (e.containsKey("notAfter") && !(Double.isFinite(now) && now <= IntentJs.num(e.get("notAfter")))) {
                expired.add(Issue.obj("kind", kind, "value", value, "label", e.get("label")));
                continue;
            }
            switch (kind) {
                case "tdx-mrtd": add(out, "tdxMrtds", value); break;
                case "tdx-rtmr": add(out, "tdxRtmrs", value); break;
                case "sev-snp-measurement": add(out, "sevSnpMeasurements", value); break;
                case "gcp-image-digest": add(out, "imageDigests", value); break;
                case "nvidia-measurement": add(out, "nvidiaMeasurements", value); break;
                case "nvidia-driver-version": add(out, "nvidiaDriverVersions", value); add(out, "nvidiaCcDriverVersions", driverVersionSlotHex(value)); break;
                case "maa-signing-spki": {
                    @SuppressWarnings("unchecked") List<Object> l = (List<Object>) maa.computeIfAbsent((String) e.get("label"), k -> new ArrayList<Object>());
                    l.add(value);
                    break;
                }
                case "maa-chain-root-spki": add(out, "maaChainRootSpkis", value); break;
                case "maa-chain-intermediate-spki": add(out, "maaChainIntermediateSpkis", value); break;
                default: add(out, "corroboration", Issue.obj("value", value, "label", e.get("label"))); break;
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void add(Map<String, Object> out, String key, Object v) { ((List<Object>) out.get(key)).add(v); }

    @SuppressWarnings("unchecked")
    private static List<Object> copy(Object l) { return new ArrayList<>((List<Object>) l); }

    /** The Azure MAA policy fields of a projection: {@code tdxMrtds}, {@code sevSnpMeasurements}, {@code tdxRtmrs}, each only when non-empty. */
    public static Map<String, Object> azureMaaPolicyFields(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String[] kv : new String[][] {{"tdxMrtds", "tdxMrtds"}, {"sevSnpMeasurements", "sevSnpMeasurements"}, {"tdxRtmrs", "tdxRtmrs"}}) {
            if (!((List<?>) p.get(kv[0])).isEmpty()) m.put(kv[1], copy(p.get(kv[0])));
        }
        return m;
    }

    /** The Intel DCAP policy fields: {@code mrtds}, and {@code rtmrs} when non-empty. */
    public static Map<String, Object> intelDcapPolicyFields(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mrtds", copy(p.get("tdxMrtds")));
        if (!((List<?>) p.get("tdxRtmrs")).isEmpty()) m.put("rtmrs", copy(p.get("tdxRtmrs")));
        return m;
    }

    /** The SEV-SNP policy fields: {@code measurements}. */
    public static Map<String, Object> sevSnpPolicyFields(Map<String, Object> p) { return Issue.obj("measurements", copy(p.get("sevSnpMeasurements"))); }

    /** The GCP Confidential Space policy fields: {@code imageDigests}. */
    public static Map<String, Object> gcpCsPolicyFields(Map<String, Object> p) { return Issue.obj("imageDigests", copy(p.get("imageDigests"))); }

    /** The NVIDIA CC policy fields: {@code measurements}, and {@code driverVersions} (the 32-hex slots) when non-empty. */
    public static Map<String, Object> nvidiaCcPolicyFields(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("measurements", copy(p.get("nvidiaMeasurements")));
        if (!((List<?>) p.get("nvidiaCcDriverVersions")).isEmpty()) m.put("driverVersions", copy(p.get("nvidiaCcDriverVersions")));
        return m;
    }
}
