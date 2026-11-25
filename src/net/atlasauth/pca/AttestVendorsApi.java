package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;
import java.util.TreeSet;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The public surface of the hardware-vendor attestation modules under the reference's names: the suite and pin constants, the verifier
 * constructors (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google Confidential Space, NVIDIA SPDM), the quote / JWT / TD-report parsers, the x5c chain
 * checks, the PCS collateral helpers, the JWKS fetchers over an injected transport and the OpenSSL time reader. The checks themselves are the
 * vendor classes' ({@link AttestFactory}); this class only exposes them. NVIDIA's chain, SPDM, RIM and OCSP helpers are in {@link AttestNvidiaApi}.
 */
public final class AttestVendorsApi {
    private AttestVendorsApi() {}

    // ---- suite names and pins ---------------------------------------------------------------------------------------------------

    public static final String INTEL_DCAP_SUITE = "intel-tdx-dcap-ecdsa-p256";
    public static final String AMD_SNP_SUITE = "amd-sev-snp-ecdsa-p384";
    public static final String AZURE_MAA_SUITE = "azure-maa-jwt";
    public static final List<String> AZURE_MAA_SUITES = Collections.unmodifiableList(Arrays.asList("ES256", "RS256"));
    public static final String GCP_CS_SUITE = "gcp-confidential-space-jwt";
    public static final List<String> GCP_CS_SUITES = Collections.unmodifiableList(Arrays.asList("RS256", "ES256"));
    public static final String GCP_CS_DEFAULT_ISSUER = "https://confidentialcomputing.googleapis.com";
    public static final String NVIDIA_SPDM_SUITE = "nvidia-gpu-spdm-ecdsa-p384-sha384";
    /** The TCB statuses the Intel collateral check accepts unless the policy names its own. */
    public static final List<String> DEFAULT_ACCEPTED_STATUSES = Collections.unmodifiableList(AttestIntelCollateral.DEFAULT_ACCEPTED_STATUSES);
    /** Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex). */
    public static final String INTEL_SGX_ROOT_CA_SPKI_SHA256 = AttestIntel.SGX_ROOT_CA_SPKI_SHA256;

    /** The suite and pin constants as one record under the reference's member names. */
    public static Map<String, Object> constants() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("INTEL_DCAP_SUITE", INTEL_DCAP_SUITE);
        m.put("AZURE_MAA_SUITE", AZURE_MAA_SUITE);
        m.put("AZURE_MAA_SUITES", new ArrayList<Object>(AZURE_MAA_SUITES));
        m.put("GCP_CS_SUITE", GCP_CS_SUITE);
        m.put("GCP_CS_SUITES", new ArrayList<Object>(GCP_CS_SUITES));
        m.put("GCP_CS_DEFAULT_ISSUER", GCP_CS_DEFAULT_ISSUER);
        m.put("INTEL_SGX_ROOT_CA_SPKI_SHA256", INTEL_SGX_ROOT_CA_SPKI_SHA256);
        m.put("AMD_SNP_SUITE", AMD_SNP_SUITE);
        m.put("AMD_ARK_SPKI_SHA384", new LinkedHashMap<String, Object>(AttestAmd.ARK_SPKI_SHA384));
        m.put("DEFAULT_ACCEPTED_STATUSES", new ArrayList<Object>(DEFAULT_ACCEPTED_STATUSES));
        return m;
    }

    /** The DER of the FIRST certificate block of a PEM text (body whitespace removed, lenient base64); throws when there is none. */
    public static byte[] pemToDer(String pem) {
        Matcher m = Pattern.compile("-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----").matcher(pem);
        if (!m.find() || m.group(1).isEmpty()) throw new IllegalArgumentException("pemToDer: no certificate found");
        StringBuilder b = new StringBuilder();
        for (char c : m.group(1).toCharArray()) if (!AttestCommon.isJsSpace(c)) b.append(c);
        return AttestCommon.nodeB64(b.toString());
    }

    /** The SPKI SHA-384 (lowercase hex) of each AMD family's ARK ({@code milan}, {@code genoa}, {@code turin}). */
    public static Map<String, String> amdArkSpkiSha384() { return Collections.unmodifiableMap(new LinkedHashMap<>(AttestAmd.ARK_SPKI_SHA384)); }

    /** The release issuer keys the built-in MAA pins are rooted in, by issuer id. */
    public static Map<String, Object> builtinMaaPinsIssuerKeys() { return AttestMaaPins.builtinIssuerKeys(); }

    // ---- verifier constructors (a missing allowlist, an absent trust anchor or a malformed pin is an AttestException) ---------------------

    public static VendorVerifier createAmdSnpVerifier(Map<String, Object> options) { return AttestFactory.verifierFromConfig("amd-sev-snp", options); }

    public static VendorVerifier createIntelDcapVerifier(Map<String, Object> options) { return AttestFactory.verifierFromConfig("intel-tdx-dcap", options); }

    public static VendorVerifier createAzureMaaVerifier(Map<String, Object> options) { return AttestFactory.verifierFromConfig("azure-maa", options); }

    public static VendorVerifier createGcpConfidentialSpaceVerifier(Map<String, Object> options) { return AttestFactory.verifierFromConfig("gcp-confidential-space", options); }

    public static VendorVerifier createNvidiaSpdmVerifier(Map<String, Object> options) { return AttestFactory.verifierFromConfig("nvidia-gpu-spdm", options); }

    // ---- JWT parsers ------------------------------------------------------------------------------------------------------------

    /** Parses an Azure MAA compact JWS (strict base64url segments, JSON header and payload); throws on anything malformed. */
    public static AttestJws.JwtParsed parseMaaJwt(String token) { return AttestJws.parseJwt(token, "parseMaaJwt"); }

    /** Parses a Confidential Space compact JWS. */
    public static AttestJws.JwtParsed parseGcpCsJwt(String token) { return AttestJws.parseJwt(token, "parseGcpCsJwt"); }

    /** The isolation family of a Confidential Space {@code hwmodel} ({@code sev-snp} or {@code tdx}), or null when unrecognised. */
    public static String teeTypeOfHwModel(String hwmodel) {
        String t = hwmodel == null ? "" : AttestGcp.gcpTeeType(hwmodel);
        return t.isEmpty() ? null : t;
    }

    // ---- x5c chains --------------------------------------------------------------------------------------------------------------

    /**
     * Verifies an Azure MAA {@code x5c} chain (base64 DER, leaf first) to the configured anchors ({@code rootCertsPem}, {@code rootSpkiSha256}):
     * every certificate inside its validity window (plus the skew), the links signed, an anchor present. {@code {ok, reason?, leafSpkiSha256?}};
     * fails closed.
     */
    public static Map<String, Object> verifyX5cChain(Object x5cIn, Map<String, Object> anchors, long nowMs, Double clockSkewMs) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<?> x5c = x5cIn instanceof List ? (List<?>) x5cIn : null; // a non-array chain is an empty one
        if (x5c == null || x5c.isEmpty()) {
            out.put("ok", false);
            out.put("reason", "empty x5c certificate chain");
            return out;
        }
        try {
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("trustedIssuers", new ArrayList<Object>(List.of("https://maa.invalid")));
            cfg.put("trustAnchors", anchors == null ? new LinkedHashMap<String, Object>() : anchors);
            Map<String, Object> pol = new LinkedHashMap<>();
            pol.put("sevSnpMeasurements", new ArrayList<Object>(List.of("00")));
            cfg.put("policy", pol);
            if (clockSkewMs != null) cfg.put("clockSkewMs", clockSkewMs);
            AttestMaa.Leaf leaf = ((AttestMaa) AttestMaa.create(cfg)).verifyX5cChain(x5c, nowMs);
            out.put("ok", leaf.cert != null);
            if (leaf.cert != null) {
                out.put("leafSpkiSha256", AttestCert.keyOfCert(leaf.cert).spkiSha256());
                out.put("leafDer", leaf.cert.raw);
            }
            else out.put("reason", leaf.why);
        } catch (AttestException e) {
            out.put("ok", false);
            out.put("reason", "no MAA trust anchor configured (fail closed)");
        }
        return out;
    }

    /**
     * Verifies a Confidential Space JWK {@code x5c} chain to the configured anchors ({@code trustedKeySpki}, {@code rootCertsPem}): null when it
     * anchors, else the reason. Fails closed.
     */
    public static String verifyJwkX5cChain(Object x5cIn, Map<String, Object> anchors, long nowMs, double skewMs) {
        List<?> x5c = x5cIn instanceof List ? (List<?>) x5cIn : null;
        if (x5c == null || x5c.isEmpty()) return "empty x5c certificate chain";
        try {
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("trustedIssuers", new ArrayList<Object>(List.of(GCP_CS_DEFAULT_ISSUER)));
            cfg.put("trustAnchors", anchors == null ? new LinkedHashMap<String, Object>() : anchors);
            Map<String, Object> pol = new LinkedHashMap<>();
            pol.put("imageDigests", new ArrayList<Object>(List.of("00")));
            cfg.put("policy", pol);
            cfg.put("clockSkewMs", skewMs);
            String why = ((AttestGcp) AttestGcp.create(cfg)).verifyJwkX5cChain(x5c, nowMs);
            return why.isEmpty() ? null : why;
        } catch (AttestException e) {
            return "x5c chain does not anchor in a configured GCP trust root";
        }
    }

    // ---- JWKS fetchers over an injected transport (it must refuse redirects) -----------------------------------------------------------

    /**
     * Fetches an MAA instance's key set from {@code <issuer><certsPath>} ({@code /certs} when null; trailing slashes of the issuer dropped) over the
     * injected transport and keeps {@code kid, kty, alg, x5c} of each object member. Throws on a non-2xx response or a body without a {@code keys} array.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> fetchMaaJwks(String issuer, AttestMaaKeys.Fetch fetch, String certsPath) throws Exception {
        if (fetch == null) throw new IllegalArgumentException("fetchMaaJwks: no fetch implementation available");
        String url = issuer.replaceAll("/+$", "") + (certsPath == null ? "/certs" : certsPath);
        Object body = jsonBody(fetch, url, "MAA JWKS fetch");
        Object keys = body instanceof Map ? ((Map<String, Object>) body).get("keys") : null;
        if (!(keys instanceof List)) throw new IllegalStateException("MAA JWKS fetch: response has no keys array");
        List<Object> out = new ArrayList<>();
        for (Object k : (List<Object>) keys) {
            if (!(k instanceof Map)) continue;
            Map<String, Object> kr = (Map<String, Object>) k, key = new LinkedHashMap<>();
            for (String f : new String[] {"kid", "kty", "alg"}) if (kr.get(f) instanceof String) key.put(f, kr.get(f));
            if (stringArray(kr.get("x5c")) != null) key.put("x5c", stringArray(kr.get("x5c")));
            out.add(key);
        }
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("keys", out);
        return res;
    }

    /** The members of an all-string array (null when it is not an array or holds a non-string). */
    private static List<Object> stringArray(Object v) {
        if (!(v instanceof List)) return null;
        List<Object> out = new ArrayList<>();
        for (Object c : (List<?>) v) { if (c instanceof String) out.add(c); else return null; }
        return out;
    }

    /**
     * Fetches the Confidential Space issuer's key set: the issuer's OpenID configuration names the {@code jwks_uri} unless {@code jwksUri} is given.
     * A redirect, a non-2xx response, a body over 1 MiB or a response without a {@code keys} array throws.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> fetchGcpConfidentialSpaceJwks(String issuer, AttestMaaKeys.Fetch fetch, String jwksUri) throws Exception {
        if (fetch == null) throw new IllegalArgumentException("fetchGcpConfidentialSpaceJwks: a fetch implementation must be injected");
        String uri = jwksUri;
        if (uri == null || uri.isEmpty()) {
            String base = issuer.replaceAll("/+$", "");
            String conf = base + "/.well-known/openid-configuration";
            Object cj = jsonBody(fetch, conf, "Confidential Space OpenID config fetch");
            Object u = cj instanceof Map ? ((Map<String, Object>) cj).get("jwks_uri") : null;
            if (!(u instanceof String) || ((String) u).isEmpty()) throw new IllegalStateException("Confidential Space OpenID config carries no jwks_uri");
            uri = (String) u;
        }
        Object body = jsonBody(fetch, uri, "Confidential Space JWKS fetch");
        Object keys = body instanceof Map ? ((Map<String, Object>) body).get("keys") : null;
        if (!(keys instanceof List)) throw new IllegalStateException("Confidential Space JWKS fetch: response has no keys array");
        List<Object> out = new ArrayList<>();
        for (Object k : (List<Object>) keys) {
            if (!(k instanceof Map)) continue;
            Map<String, Object> kr = (Map<String, Object>) k, key = new LinkedHashMap<>();
            for (String f : new String[] {"kid", "kty", "alg", "use", "n", "e", "crv", "x", "y"}) if (kr.get(f) instanceof String) key.put(f, kr.get(f));
            if (stringArray(kr.get("x5c")) != null) key.put("x5c", stringArray(kr.get("x5c")));
            out.add(key);
        }
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("keys", out);
        return res;
    }

    private static Object jsonBody(AttestMaaKeys.Fetch fetch, String url, String what) throws Exception {
        AttestMaaKeys.Response r = fetch.get(url);
        if (r.status < 200 || r.status > 299) throw new IllegalStateException(what + " failed: HTTP " + r.status + " for " + url);
        if (r.url != null && !r.url.isEmpty() && !r.url.equals(url)) throw new IllegalStateException(what + ": response URL differs from the request (redirect)");
        byte[] bytes = r.body == null ? new byte[0] : r.body;
        if (bytes.length > 1_048_576) throw new IllegalStateException(what + ": response exceeds the size limit");
        return Json.parseLenient(new String(bytes, StandardCharsets.UTF_8));
    }

    // ---- Intel DCAP / TDX -------------------------------------------------------------------------------------------------------

    /** A NIST P-256 public key as the uncompressed SEC1 point (65 bytes) from a compressed or uncompressed one; throws on an off-curve point. */
    public static byte[] ecdsaP256PublicKey(byte[] sec1) {
        X9ECParameters p = ECNamedCurveTable.getByName("secp256r1");
        ECPoint pt = p.getCurve().decodePoint(sec1); // refuses an off-curve point and a wrong length
        if (pt.isInfinity()) throw new IllegalArgumentException("bad point: ZERO");
        return pt.getEncoded(false);
    }

    private static byte[] at(byte[] b, int off, int len) { return Arrays.copyOfRange(b, off, off + len); }

    /**
     * Parses a genuine 584-byte TD10 report body: {@code teeTcbSvn, mrSeam, mrSignerSeam, tdAttributes, mrTd, mrConfigId, rtmr0..rtmr3, reportData, raw}
     * (fresh byte copies). Throws when the body is too short.
     */
    public static Map<String, Object> parseDcapTdReport(byte[] body) {
        if (body == null) throw new IllegalArgumentException("parseDcapTdReport: expected Uint8Array");
        if (body.length < AttestIntel.TD_REPORT_LEN) throw new IllegalArgumentException("parseDcapTdReport: body too short (" + body.length + " < " + AttestIntel.TD_REPORT_LEN + ")");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("teeTcbSvn", at(body, 0, 16));
        m.put("mrSeam", at(body, 16, 48));
        m.put("mrSignerSeam", at(body, 64, 48));
        m.put("tdAttributes", at(body, 120, 8));
        m.put("mrTd", at(body, 136, 48));
        m.put("mrConfigId", at(body, 184, 48));
        m.put("rtmr0", at(body, 328, 48));
        m.put("rtmr1", at(body, 376, 48));
        m.put("rtmr2", at(body, 424, 48));
        m.put("rtmr3", at(body, 472, 48));
        m.put("reportData", at(body, 520, 64));
        m.put("raw", at(body, 0, AttestIntel.TD_REPORT_LEN));
        return m;
    }

    /**
     * X.509-verifies an Intel PCK chain (PEM) to the pinned SGX Root CA ({@code pin} null: {@link #INTEL_SGX_ROOT_CA_SPKI_SHA256}): every certificate
     * inside its validity at {@code nowMs}, every link signed, the root self-signed and pinned, CA roles, an EC P-256 leaf. {@code {ok, reason?,
     * leafDer?, depth?, failure?}}; fails closed.
     */
    public static Map<String, Object> verifyIntelPckChainX509(String pckChainPem, String pin, long nowMs) {
        AttestIntel.PckChainResult r = AttestIntel.verifyIntelPckChain(pckChainPem, pin == null ? AttestIntel.SGX_ROOT_CA_SPKI_SHA256 : pin, nowMs);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", r.ok);
        if (!r.ok) {
            m.put("reason", r.reason);
            if (r.validity) m.put("failure", "validity");
            return m;
        }
        if (r.leaf != null) m.put("leafDer", r.leaf.raw);
        if (r.leafKey != null) m.put("leafKey", Collections.singletonMap("point", AttestCommon.ecPointOfKey(CertKey.of(r.leafKey, null), "P-256")));
        m.put("depth", r.depth);
        return m;
    }

    /** True iff {@code serialHex} (case and leading zeros ignored) is in the CRL's revoked set. */
    public static boolean serialIsRevoked(Set<String> revoked, String serialHex) { return revoked.contains(AttestCommon.normSerial(serialHex)); }

    /** Decodes a PCS issuer-chain HTTP header value (URL-encoded PEM) to PEM. */
    public static String decodeIssuerChainHeader(String value) {
        StringBuilder out = new StringBuilder();
        java.io.ByteArrayOutputStream run = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%') {
                int h = i + 2 < value.length() ? Character.digit(value.charAt(i + 1), 16) : -1;
                int l = h >= 0 ? Character.digit(value.charAt(i + 2), 16) : -1;
                if (h < 0 || l < 0) throw new IllegalArgumentException("URI malformed");
                run.write(h << 4 | l);
                i += 2;
                continue;
            }
            flushUtf8(run, out);
            out.append(c);
        }
        flushUtf8(run, out);
        return out.toString();
    }

    /** Decodes the pending percent-escaped bytes as strict UTF-8 (a malformed or surrogate sequence is a URIError in the reference). */
    private static void flushUtf8(java.io.ByteArrayOutputStream run, StringBuilder out) {
        if (run.size() == 0) return;
        try {
            out.append(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(run.toByteArray())));
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("URI malformed");
        }
        run.reset();
    }

    // ---- DCAP quote, PCK extension, genuine-quote and collateral entry points (the reference's result shapes) -------------------------

    /** The structure of a DCAP v4 TDX quote: {@code version, attKeyType, teeType, header, tdReportBody, quoteSignature, akPubRaw, qeReportBody, qeReportSignature, qeAuthData, pckChainPem}. Throws on any structural violation. */
    public static Map<String, Object> parseDcapQuote(byte[] quote) {
        AttestIntel.DcapQuote q = AttestIntel.parseDcapQuote(quote);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", (long) q.version);
        m.put("attKeyType", (long) q.attKeyType);
        m.put("teeType", q.teeType);
        m.put("header", q.header);
        m.put("tdReportBody", q.tdReportBody);
        m.put("quoteSignature", q.quoteSignature);
        m.put("akPubRaw", q.akPubRaw);
        m.put("qeReportBody", q.qeReportBody);
        m.put("qeReportSignature", q.qeReportSignature);
        m.put("qeAuthData", q.qeAuthData);
        m.put("pckChainPem", q.pckChainPem);
        return m;
    }

    private static Map<String, Object> pckTcbMap(AttestIntel.PckTcb t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fmspc", t.fmspc);
        m.put("sgxTcbComponents", t.sgx);
        m.put("pcesvn", (long) t.pcesvn);
        m.put("cpusvn", t.cpusvn);
        return m;
    }

    /** The FMSPC and the issued TCB of a PCK leaf's Intel SGX extension: {@code fmspc, sgxTcbComponents (16), pcesvn, cpusvn}; throws on a missing or malformed extension. */
    public static Map<String, Object> extractPckFmspcAndTcb(byte[] leafDer) { return pckTcbMap(AttestIntel.extractPckFmspcAndTcb(leafDer)); }

    /** The binding a wire object {@code {holderPub, grantRef, epoch, nonce}} names (a missing member is empty / NaN, which no binding can be built from). */
    public static AttestationBinding bindingOf(Map<String, Object> m) {
        Double e = AttestCommon.asFinite(m.get("epoch"));
        return new AttestationBinding(m.get("holderPub") instanceof String ? (String) m.get("holderPub") : null, m.get("grantRef") instanceof String ? (String) m.get("grantRef") : null,
            e == null ? Double.NaN : e, m.get("nonce") instanceof String ? (String) m.get("nonce") : null);
    }

    private static List<String> lowerList(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List) for (Object x : (List<?>) v) if (x instanceof String) out.add(((String) x).toLowerCase(java.util.Locale.ROOT));
        return out;
    }

    /**
     * Verifies a genuine DCAP TDX quote offline: the PCK chain to the pinned root ({@code pin} null: Intel's), the QE report, the attestation key,
     * the optional report_data binding ({@code expected}) and the optional policy ({@code mrtds, fmspcs, rtmrs, mrSeams, mrSignerSeams, allowDebug}; an
     * empty mrSeams / mrSignerSeams list refuses everything, an empty mrtds / fmspcs / rtmrs list is not gated). Fails closed.
     */
    public static Map<String, Object> verifyGenuineTdxQuote(byte[] quote, String pin, long nowMs, Map<String, Object> expected, Map<String, Object> policy) {
        AttestIntel.QuotePolicy qp = null;
        if (policy != null) {
            qp = new AttestIntel.QuotePolicy();
            qp.mrtds = lowerList(policy.get("mrtds"));
            qp.fmspcs = lowerList(policy.get("fmspcs"));
            qp.rtmrs = lowerList(policy.get("rtmrs"));
            qp.hasMrSeams = policy.get("mrSeams") instanceof List;
            qp.mrSeams = lowerList(policy.get("mrSeams"));
            qp.hasMrSigner = policy.get("mrSignerSeams") instanceof List;
            qp.mrSignerSeams = lowerList(policy.get("mrSignerSeams"));
            qp.allowDebug = Boolean.TRUE.equals(policy.get("allowDebug"));
        }
        AttestIntel.TdxResult r = AttestIntel.verifyGenuineTdxQuote(quote, pin == null ? AttestIntel.SGX_ROOT_CA_SPKI_SHA256 : pin, nowMs, qp, false, expected == null ? null : bindingOf(expected));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", r.ok);
        if (!r.ok) {
            m.put("reason", r.reason);
            return m;
        }
        m.put("report", parseDcapTdReport(AttestIntel.parseDcapQuote(quote).tdReportBody));
        m.put("fmspc", r.fmspc);
        m.put("pckTcb", pckTcbMap(r.pck));
        m.put("akPub", Collections.singletonMap("point", r.akPoint));
        m.put("chainDepth", (long) r.chainDepth);
        Map<String, Object> meas = new LinkedHashMap<>();
        meas.put("model_id", "");
        meas.put("weights_digest", "");
        meas.put("weights_measured", false);
        meas.put("runtime_measurement", AttestCommon.toHexLower(r.mrTd));
        meas.put("operator", "");
        m.put("measured", meas);
        return m;
    }

    private static CertKey keyOfSpki(byte[] spki) {
        for (String alg : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                return CertKey.of(KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(spki)), spki);
            } catch (java.security.GeneralSecurityException | RuntimeException e) {
                // try the next key type
            }
        }
        throw new IllegalArgumentException("not a SubjectPublicKeyInfo of a supported key type");
    }

    /** Verifies a DER CRL under the issuer key whose SubjectPublicKeyInfo is {@code spkiDer}: {@code {ok: true, revoked: sorted lowercase hex serials}} or {@code {ok: false, reason}}. */
    public static Map<String, Object> verifyCrl(byte[] crlDer, byte[] spkiDer, long nowMs) {
        AttestIntelCollateral.CrlResult r = AttestIntelCollateral.verifyCrl(crlDer, keyOfSpki(spkiDer), nowMs);
        Map<String, Object> m = new LinkedHashMap<>();
        if (r.revoked == null) {
            m.put("ok", false);
            m.put("reason", r.reason);
        } else {
            m.put("ok", true);
            m.put("revoked", new ArrayList<Object>(new TreeSet<>(r.revoked)));
        }
        return m;
    }

    /** Verifies a PCS document {@code {"<name>":{...},"signature":"<128 hex>"}} (ECDSA P-256 over the exact source bytes of the named object): {@code {body}} or {@code {error}}. */
    public static Map<String, Object> verifySignedJson(String text, String name, byte[] spkiDer) {
        AttestIntelCollateral.SignedBody r = AttestIntelCollateral.verifySignedJson(text, name, keyOfSpki(spkiDer));
        Map<String, Object> m = new LinkedHashMap<>();
        if (r.body != null) m.put("body", r.body);
        else m.put("error", r.reason);
        return m;
    }

    private static String textOf(Object v) { return v instanceof String ? (String) v : v instanceof byte[] ? new String((byte[]) v, StandardCharsets.UTF_8) : ""; }

    /**
     * Verifies the quote and its PCS collateral ({@code tcbInfoJson, tcbInfoIssuerChainPem, qeIdentityJson, qeIdentityIssuerChainPem, pckCrlDer, rootCrlDer}; a JSON member is a
     * string or bytes; null: incomplete). {@code policy} = {@code {acceptStatuses?, minTcbEvaluationDataNumber?}}. The component statuses, the smaller evaluation number and the FMSPC
     * are reported whenever the evaluation completed, also when the policy then refuses the status.
     */
    public static Map<String, Object> verifyIntelTdxCollateral(byte[] quote, Map<String, Object> collateral, long nowMs, Map<String, Object> policy, String pin, boolean allowDebug) {
        AttestIntelCollateral.Collateral c = null;
        if (collateral != null) {
            c = new AttestIntelCollateral.Collateral();
            c.tcbInfoJson = textOf(collateral.get("tcbInfoJson"));
            c.tcbInfoChain = textOf(collateral.get("tcbInfoIssuerChainPem"));
            c.qeIdentityJson = textOf(collateral.get("qeIdentityJson"));
            c.qeIdentityChain = textOf(collateral.get("qeIdentityIssuerChainPem"));
            c.pckCrl = collateral.get("pckCrlDer") instanceof byte[] ? (byte[]) collateral.get("pckCrlDer") : null;
            c.rootCrl = collateral.get("rootCrlDer") instanceof byte[] ? (byte[]) collateral.get("rootCrlDer") : null;
        }
        AttestIntelCollateral.Policy pol = null;
        if (policy != null) {
            pol = new AttestIntelCollateral.Policy();
            if (policy.get("acceptStatuses") instanceof List) {
                pol.acceptStatuses = new ArrayList<>();
                for (Object x : (List<?>) policy.get("acceptStatuses")) if (x instanceof String) pol.acceptStatuses.add((String) x);
                pol.hasAccept = true;
            }
            Double f = AttestCommon.asFinite(policy.get("minTcbEvaluationDataNumber"));
            if (f != null) {
                pol.minEval = f;
                pol.hasMinEval = true;
            }
        }
        AttestIntelCollateral.Result r = AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, nowMs, pol, pin == null ? AttestIntel.SGX_ROOT_CA_SPKI_SHA256 : pin, allowDebug);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", r.ok);
        if (!r.ok && r.status.isEmpty()) {
            m.put("reason", r.reason);
            return m;
        }
        if (!r.ok) m.put("reason", r.reason);
        m.put("status", r.status);
        m.put("platformStatus", r.platformStatus);
        m.put("tdxModuleStatus", r.tdxModuleStatus);
        m.put("qeStatus", r.qeStatus);
        m.put("advisoryIds", new ArrayList<Object>(r.advisoryIds));
        m.put("tcbEvaluationDataNumber", r.evalNumber == Math.rint(r.evalNumber) ? (Object) (long) r.evalNumber : (Object) r.evalNumber);
        m.put("fmspc", r.fmspc);
        return m;
    }

    /** The Azure runtime-data binding of a quote's report_data: the failure reason, or null when the quote binds {@code expected}. */
    public static String checkAzureRuntimeDataBinding(byte[] reportData, byte[] runtimeData, Map<String, Object> expected) {
        String why = AttestCommon.checkAzureRuntimeDataBinding(reportData, runtimeData, bindingOf(expected));
        return why.isEmpty() ? null : why;
    }

    /** A parsed compact JWS as the reference's record: {@code header {alg, kid?, jku?, x5c?, typ?}, payload, signingInput, signature}. */
    public static Map<String, Object> jwtRecord(AttestJws.JwtParsed j) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("alg", j.alg);
        if (j.hasKid) h.put("kid", j.kid);
        if (j.jku != null) h.put("jku", j.jku);
        if (j.hasX5c) h.put("x5c", new ArrayList<Object>(j.x5c));
        if (j.typ != null) h.put("typ", j.typ);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("header", h);
        m.put("payload", j.payload);
        m.put("signingInput", j.signingInput);
        m.put("signature", j.signature);
        return m;
    }

    // ---- X.509 validity ----------------------------------------------------------------------------------------------------------

    /** The validity window of a DER certificate in epoch ms ({@code {from, to}}); NaN members when malformed. */
    public static double[] derValidityMs(byte[] der) {
        AttestDer.DerInstant[] v = AttestDer.derValidity(der);
        return new double[] {v[0].ok ? v[0].ms : Double.NaN, v[1].ok ? v[1].ms : Double.NaN};
    }

    /** The validity window of a certificate in epoch ms; NaN members when a bound is unparseable. */
    public static double[] x509ValidityMs(X509Certificate cert) {
        try {
            return derValidityMs(cert.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            return new double[] {Double.NaN, Double.NaN};
        }
    }

    /** True iff both bounds parse and {@code from - skew <= nowMs <= to + skew}; false (fail closed) for any unparseable bound. */
    public static boolean x509ValidAt(X509Certificate cert, long nowMs, double skewMs) {
        double[] w = x509ValidityMs(cert);
        if (Double.isNaN(w[0]) || Double.isNaN(w[1]) || Double.isNaN(skewMs) || Double.isInfinite(skewMs)) return false;
        return (double) nowMs + skewMs >= w[0] && (double) nowMs - skewMs <= w[1];
    }

    private static final String[] MONTHS = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    private static final Pattern RENDERED = Pattern.compile("^([A-Z][a-z]{2}) {1,2}(\\d{1,2}) (\\d{2}):(\\d{2}):(\\d{2})(\\.\\d+)? (\\d{4}) GMT$");

    /** Strict parse of OpenSSL's rendered ASN1_TIME ({@code "Mon DD HH:MM:SS[.fff] YYYY GMT"}) to epoch ms; NaN for anything else. */
    public static double parseOpenSslTime(Object s) {
        if (!(s instanceof String)) return Double.NaN;
        Matcher m = RENDERED.matcher((String) s);
        if (!m.matches()) return Double.NaN;
        int mon = Arrays.asList(MONTHS).indexOf(m.group(1));
        int day = Integer.parseInt(m.group(2)), h = Integer.parseInt(m.group(3)), mi = Integer.parseInt(m.group(4)), sec = Integer.parseInt(m.group(5)), y = Integer.parseInt(m.group(7));
        if (mon < 0 || day < 1 || day > 31 || h > 23 || mi > 59 || sec > 59) return Double.NaN;
        long ms = m.group(6) != null ? (long) Math.floor(Double.parseDouble("0" + m.group(6)) * 1000) : 0;
        try {
            LocalDateTime d = LocalDateTime.of(y, mon + 1, day, h, mi, sec); // a day the month does not have is refused (no roll-over)
            return d.toEpochSecond(ZoneOffset.UTC) * 1000.0 + ms;
        } catch (DateTimeException e) {
            return Double.NaN;
        }
    }
}
