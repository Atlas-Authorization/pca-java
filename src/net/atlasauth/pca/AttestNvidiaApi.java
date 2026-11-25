package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The public surface of the NVIDIA GPU confidential-computing attestation modules under the reference names: the SPDM GET_MEASUREMENTS
 * transcript parse, the device chain to a pinned NVIDIA root, the report signature and the PCA challenge; Reference Integrity Manifest
 * verification, RIM ids, the golden comparison, CRL revocation, the collateral hook and the guarded fetch helpers; the OCSP request build, the
 * response verification and the per-chain OCSP policy. Values are JSON-shaped maps, lists and byte arrays. Fetching is never automatic: the
 * transports are injected. The OCSP request is DER-encoded with the vetted BouncyCastle ASN.1 primitives; nothing here hand-rolls a primitive.
 */
public final class AttestNvidiaApi {
    private AttestNvidiaApi() {}

    /** Suite identifier of the NVIDIA SPDM root (classical ECDSA-P384 / SHA-384). */
    public static final String NVIDIA_SPDM_SUITE = "nvidia-gpu-spdm-ecdsa-p384-sha384";
    /** Opaque-data TLV field ids surfaced by name. */
    public static final Map<String, Integer> NVIDIA_OPAQUE;
    static {
        Map<String, Integer> m = new LinkedHashMap<>();
        m.put("CERT_ISSUER_NAME", 1);
        m.put("CERT_AUTHORITY_KEY_IDENTIFIER", 2);
        m.put("DRIVER_VERSION", 3);
        m.put("GPU_INFO", 4);
        m.put("SKU", 5);
        m.put("VBIOS_VERSION", 6);
        m.put("MANUFACTURER_ID", 7);
        m.put("TAMPER_DETECTION", 8);
        m.put("MSRSCNT", 12);
        m.put("BOARD_ID", 14);
        m.put("FWID", 20);
        m.put("OPAQUE_DATA_VERSION", 34);
        m.put("CHIP_INFO", 35);
        m.put("FEATURE_FLAG", 36);
        NVIDIA_OPAQUE = Collections.unmodifiableMap(m);
    }
    public static final String NVIDIA_RIM_BASE_URL = "https://rim.attestation.nvidia.com/v1/rim/";
    public static final List<String> NVIDIA_GH100_CRL_URLS = List.of("https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl");
    public static final List<String> NVIDIA_GB100_CRL_URLS = List.of("https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl");
    public static final String NVIDIA_OCSP_URL = "http://ocsp.ndis.nvidia.com/";
    public static final long NVIDIA_OCSP_DEFAULT_MAX_AGE_MS = 7L * 24 * 3600 * 1000;

    /** The POST transport of {@link #fetchNvidiaOcsp}. */
    @FunctionalInterface
    public interface Post {
        HardwareSevSnp.Response post(String url, String contentType, byte[] body) throws Exception;
    }

    // ------------------------------------------------------------- certificates

    private static final String[] MONTHS = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    /** OpenSSL's ASN1_TIME_print ("Oct 17 00:00:00 2020 GMT"). */
    private static String opensslTime(AttestDer.DerInstant t) {
        if (!t.ok) return "Bad time value";
        ZonedDateTime z = Instant.ofEpochMilli(t.ms).atZone(ZoneOffset.UTC);
        return String.format(Locale.ROOT, "%s %2d %02d:%02d:%02d %d GMT", MONTHS[z.getMonthValue() - 1], z.getDayOfMonth(), z.getHour(), z.getMinute(), z.getSecond(), z.getYear());
    }

    /** The serial as OpenSSL prints it: uppercase hex of the whole bytes, leading zero bytes dropped. */
    private static String serialText(byte[] serial) {
        int i = 0;
        while (i < serial.length - 1 && serial[i] == 0) i++;
        String h = AttestCommon.toHexLower(Arrays.copyOfRange(serial, i, serial.length)).toUpperCase(Locale.ROOT);
        return h.isEmpty() ? "0" : h;
    }

    /** {subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca} of a certificate. */
    private static Map<String, Object> certSummary(AttCert c) {
        AttestDer.DerInstant[] v = AttestDer.derValidity(c.raw);
        return Issue.obj("subject", AttestCommon.nameText(c.rawSubject), "issuer", AttestCommon.nameText(c.rawIssuer), "serial", serialText(c.serial),
            "notBefore", opensslTime(v[0]), "notAfter", opensslTime(v[1]), "spkiSha256", AttestCert.keyOfCert(c).spkiSha256(),
            "rawSha256", AttestCommon.toHexLower(AttestCommon.sha256Sum(c.raw)), "ca", AttestNvidia.certIsCA(c));
    }

    /** SHA-256 of a certificate's SubjectPublicKeyInfo DER, lowercase hex: the pin format of a root. Throws on text that is not a certificate. */
    public static String spkiSha256Hex(String certPem) { return AttestCert.keyOfCert(AttestCert.certFromPem(certPem)).spkiSha256(); }

    private static List<AttCert> chainOf(String pem) {
        List<String> blocks = AttestCommon.pemCertBlocks(pem);
        if (blocks.isEmpty()) throw new AttestException("parsePemChain: no certificates found");
        if (blocks.size() > AttestNvidia.NVIDIA_MAX_CHAIN) throw new AttestException("parsePemChain: chain longer than " + AttestNvidia.NVIDIA_MAX_CHAIN);
        List<AttCert> out = new ArrayList<>();
        for (String b : blocks) out.add(AttestCert.certFromPem(b));
        return out;
    }

    /** Split a PEM bundle into certificate summaries (leaf first). Throws on none, too many, or an unparseable one. */
    public static List<Object> parsePemChain(String pem) {
        List<Object> out = new ArrayList<>();
        for (AttCert c : chainOf(pem)) out.add(certSummary(c));
        return out;
    }

    /** The device chain: every link signed, every issuer a CA, validity at {@code nowMs}, P-384 throughout, the root self-signed and pinned. {ok, leaf, chain} or {ok: false, reason}. */
    public static Map<String, Object> verifyNvidiaDeviceChain(String pem, List<String> rootSpkiSha256, long nowMs) {
        AttestNvidia.Chain c = AttestNvidia.verifyDeviceChain(pem, rootSpkiSha256, nowMs);
        if (c.certs == null) return Issue.obj("ok", false, "reason", c.reason);
        List<Object> chain = new ArrayList<>();
        for (AttCert x : c.certs) chain.add(certSummary(x));
        return Issue.obj("ok", true, "leaf", certSummary(c.certs.get(0)), "chain", chain);
    }

    // ------------------------------------------------------------- the SPDM report

    /** A parsed transcript as a summary map. Throws {@link AttestException} on any structural problem. */
    public static Map<String, Object> parseNvidiaSpdmEvidence(byte[] bytes) {
        AttestNvidia.SpdmReport r = AttestNvidia.parseSpdmEvidence(bytes);
        List<Object> ms = new ArrayList<>();
        for (AttestNvidia.Measurement m : r.measurements) ms.add(Issue.obj("index", m.index, "valueType", m.valueType, "digest", m.digest));
        Map<String, Object> opaque = new LinkedHashMap<>();
        for (Map.Entry<Integer, byte[]> e : new TreeMap<>(r.opaque).entrySet()) opaque.put(String.valueOf(e.getKey()), e.getValue());
        return Issue.obj("request", Issue.obj("version", r.requestVersion, "code", r.requestCode, "param1", r.requestParam1, "param2", r.requestParam2, "nonce", r.requestNonce, "slot", r.requestSlot),
            "response", Issue.obj("version", r.responseVersion, "code", r.responseCode, "numBlocks", r.numBlocks, "measurements", ms, "responderNonce", r.responderNonce, "opaque", opaque, "signature", r.signature),
            "signedBytesLength", r.signedBytes.length, "signedBytesSha256", AttestCommon.toHexLower(AttestCommon.sha256Sum(r.signedBytes)));
    }

    /** NVIDIA's VBIOS version rendering ("96.00.9f.00.04"). */
    public static String formatVbiosVersion(byte[] raw) { return AttestNvidia.formatVbiosVersion(raw); }

    /** ECDSA P-384 / SHA-384 (IEEE P1363) verification of the report signature under the device chain's leaf key. */
    public static boolean verifyNvidiaSpdmSignature(byte[] evidence, String chainPem) {
        AttestNvidia.SpdmReport rep = AttestNvidia.parseSpdmEvidence(evidence);
        CertKey k = AttestCert.keyOfCert(chainOf(chainPem).get(0));
        return k.pub instanceof ECPublicKey && AttestCommon.verifyRawECDSA((ECPublicKey) k.pub, AttestCommon.sha384Sum(rep.signedBytes), rep.signature);
    }

    /** The 32-byte SPDM challenge that carries the PCA binding: sha256(attestationBinding(expected)). Throws when the binding is not constructible. */
    public static byte[] nvidiaSpdmChallenge(AttestationBinding expected) {
        if (expected == null) throw new AttestException("binding: holderPub required");
        return AttestCommon.sha256Sum(AttestCommon.attestationBindingBytes(expected));
    }

    // ------------------------------------------------------------- RIMs

    private static Map<String, Object> goldenMap(AttestNvidiaRim.Golden g) {
        return Issue.obj("index", g.index, "active", g.active, "alternatives", g.alternatives, "size", g.size, "hashes", new ArrayList<Object>(g.hashes));
    }

    private static Map<String, Object> rimSummary(AttestNvidiaRim.Rim r) {
        List<Object> golden = new ArrayList<>();
        for (AttestNvidiaRim.Golden g : new TreeMap<>(r.golden).values()) golden.add(goldenMap(g));
        return Issue.obj("tagId", r.tagId, "product", r.product, "version", r.version, "golden", golden, "signerSubject", r.signerSubject);
    }

    @SuppressWarnings("unchecked")
    private static AttestNvidiaRim.Rim rimOf(Map<String, Object> s) {
        Map<Long, AttestNvidiaRim.Golden> golden = new java.util.HashMap<>();
        for (Object go : (List<Object>) s.get("golden")) {
            Map<String, Object> g = (Map<String, Object>) go;
            List<String> hashes = new ArrayList<>();
            for (Object h : (List<Object>) g.get("hashes")) hashes.add((String) h);
            long idx = IntentJs.lng(g.get("index"));
            golden.put(idx, new AttestNvidiaRim.Golden(idx, Boolean.TRUE.equals(g.get("active")), IntentJs.lng(g.get("alternatives")), IntentJs.lng(g.get("size")), hashes));
        }
        AttestNvidiaRim.Rim r = new AttestNvidiaRim.Rim((String) s.get("product"), (String) s.get("version"), golden);
        r.tagId = s.get("tagId") instanceof String ? (String) s.get("tagId") : "";
        return r;
    }

    /** Verify a RIM document and return its golden measurements: {ok: true, rim: {tagId, product, version, golden, signerSubject}} or {ok: false, reason}. */
    public static Map<String, Object> verifyNvidiaRim(String xml, List<String> rimRootSpkiSha256, long nowMs) {
        AttestNvidiaRim.RimResult r = AttestNvidiaRim.verifyRim(xml, rimRootSpkiSha256, nowMs);
        return r.rim == null ? Issue.obj("ok", false, "reason", r.reason) : Issue.obj("ok", true, "rim", rimSummary(r.rim));
    }

    /** The RIM ids a report requires (read from the GPU's own signed opaque data), or null when it does not carry them. */
    public static Map<String, Object> nvidiaRimIdsForReport(byte[] evidence) {
        AttestNvidiaRim.RimIds ids = AttestNvidiaRim.rimIdsForReport(AttestNvidia.parseSpdmEvidence(evidence));
        return ids == null ? null : Issue.obj("chip", ids.chip, "driver", ids.driver, "vbios", ids.vbios, "driverVersion", ids.driverVersion, "vbiosVersion", ids.vbiosVersion);
    }

    /** Compare a report with the driver and VBIOS RIM summaries under NVIDIA's merge / alternatives / NVDEC0 rules: {ok: true, checked} or {ok: false, reason, mismatches?}. */
    public static Map<String, Object> compareReportToRims(byte[] evidence, Map<String, Object> driverRim, Map<String, Object> vbiosRim) {
        AttestNvidiaRim.Compared c = AttestNvidiaRim.compare(AttestNvidia.parseSpdmEvidence(evidence), rimOf(driverRim), rimOf(vbiosRim));
        if (c.reason.isEmpty()) return Issue.obj("ok", true, "checked", c.checked);
        Map<String, Object> out = Issue.obj("ok", false, "reason", c.reason);
        if (!c.mismatches.isEmpty()) {
            List<Object> ms = new ArrayList<>();
            for (long[] m : c.mismatches) ms.add(Issue.obj("index", m[0], "source", m[1] == 0 ? "driver" : "vbios"));
            out.put("mismatches", ms);
        }
        return out;
    }

    /**
     * Check the device chain against CRLs: every CRL must verify under a chain certificate and be fresh, no chain certificate may be listed,
     * each required issuer must be covered, and {@code requireFor} ("cdp", "all", "none" or a list of chain indices) names the certificates that
     * need a verified CRL from their issuer. {ok: true, verifiedCrls} or {ok: false, reason}.
     */
    public static Map<String, Object> checkNvidiaChainRevocation(String chainPem, List<byte[]> crls, long nowMs, List<String> requireIssuers, Object requireFor) {
        String why = AttestNvidiaRim.checkChainRevocation(chainOf(chainPem), crls, nowMs, requireIssuers == null ? new ArrayList<>() : requireIssuers, requireFor == null ? "cdp" : requireFor);
        return why.isEmpty() ? Issue.obj("ok", true, "verifiedCrls", crls.size()) : Issue.obj("ok", false, "reason", why);
    }

    /**
     * The collateral hook once: RIM signatures, the golden comparison, the driver / VBIOS version binding and revocation, for one report and
     * chain. {@code opts} = {rimRootSpkiSha256, revocation?, requireCrls?, requireCrlIssuers?, requireCrlFor?, firmware?}; {@code bundle} =
     * {driverRimXml, vbiosRimXml, crls?, ocsp?} (DER lists as base64 strings) or null (nothing supplied). Returns the failure reason, or null when
     * the hook accepts. Throws on a malformed configuration.
     */
    public static String nvidiaCollateralHook(Map<String, Object> opts, Map<String, Object> bundle, byte[] evidence, String chainPem, long nowMs) {
        AttestNvidiaRim.Hook hook = AttestNvidiaRim.Hook.create(opts);
        List<AttCert> chain = chainOf(chainPem);
        AttestNvidia.SpdmReport report = AttestNvidia.parseSpdmEvidence(evidence);
        String why = hook.withBundle(bundle).run(report, chain, nowMs);
        return why.isEmpty() ? null : why;
    }

    private static final Pattern RIM_ID = Pattern.compile("[A-Za-z0-9_.-]+");

    /** Fetch a RIM document by id from the NVIDIA RIM service (injected GET) and return its XML text. */
    public static String fetchNvidiaRim(String id, HardwareSevSnp.Fetch fetch, String baseUrl) throws Exception {
        if (fetch == null) throw new IllegalStateException("fetchNvidiaRim: no fetch implementation available");
        if (id == null || !RIM_ID.matcher(id).matches()) throw new IllegalArgumentException("fetchNvidiaRim: invalid RIM id");
        HardwareSevSnp.Response res = fetch.get((baseUrl == null ? NVIDIA_RIM_BASE_URL : baseUrl) + id);
        if (res.status < 200 || res.status > 299) throw new IllegalStateException("RIM fetch failed: HTTP " + res.status + " for " + id);
        Object body;
        try {
            body = Json.parseLenient(new String(res.body, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Unexpected token in JSON");
        }
        if (body == null) throw new IllegalStateException("Cannot read properties of null (reading 'rim')");
        Object rim = body instanceof Map ? ((Map<?, ?>) body).get("rim") : null;
        if (!(rim instanceof String)) throw new IllegalStateException("RIM fetch: response has no rim field");
        return new String(AttestCommon.nodeB64((String) rim), StandardCharsets.UTF_8);
    }

    /** Fetch a DER CRL through the injected GET. */
    public static byte[] fetchNvidiaCrl(String url, HardwareSevSnp.Fetch fetch) throws Exception {
        if (fetch == null) throw new IllegalStateException("fetchNvidiaCrl: no fetch implementation available");
        HardwareSevSnp.Response res = fetch.get(url);
        if (res.status < 200 || res.status > 299) throw new IllegalStateException("CRL fetch failed: HTTP " + res.status + " for " + url);
        return res.body;
    }

    // ------------------------------------------------------------- OCSP

    private static final Map<String, String[]> HASHES = new java.util.HashMap<>();
    static {
        HASHES.put("sha1", new String[] {"SHA-1", "1.3.14.3.2.26"});
        HASHES.put("sha256", new String[] {"SHA-256", "2.16.840.1.101.3.4.2.1"});
        HASHES.put("sha384", new String[] {"SHA-384", "2.16.840.1.101.3.4.2.2"});
        HASHES.put("sha512", new String[] {"SHA-512", "2.16.840.1.101.3.4.2.3"});
    }

    /** True iff every GeneralizedTime / UTCTime inside the DER value is a well-formed DER time (no calendar roll-over); string contents are opaque. A time the reader refuses is false. */
    public static boolean allAsn1TimesWellFormed(byte[] der) {
        try {
            AttestNvidiaOcsp.Node n = AttestNvidiaOcsp.readNode(der, 0, der.length);
            return AttestNvidiaOcsp.timesWellFormed(der, n);
        } catch (AttestException e) {
            return false;
        }
    }

    /**
     * A DER OCSPRequest for {@code certPem} (issued by {@code issuerPem}): a SHA-384 CertID unless {@code opts.hash} (sha1 / sha256 / sha384 /
     * sha512) names another, plus the nonce extension when {@code opts.nonce} (1..32 bytes) is given. Encoded with the BouncyCastle ASN.1 primitives.
     */
    public static byte[] buildNvidiaOcspRequest(String certPem, String issuerPem, Map<String, Object> opts) {
        AttCert cert = AttestCert.certFromPem(certPem), issuer = AttestCert.certFromPem(issuerPem);
        Object hn = opts == null ? null : opts.get("hash");
        String[] h = HASHES.get(hn == null ? "sha384" : String.valueOf(hn));
        // a hash outside the four names is refused (never hashed with whatever digest the runtime knows)
        if (h == null) throw new IllegalArgumentException("unsupported CertID hash " + AttestNvidia.jsString(hn));
        Object nonceO = opts == null ? null : opts.get("nonce");
        byte[] nonce = nonceO instanceof byte[] ? (byte[]) nonceO : null;
        try {
            MessageDigest md = MessageDigest.getInstance(h[0]);
            byte[] nameHash = md.digest(issuer.rawSubject);
            byte[] keyHash = md.digest(AttestNvidiaOcsp.spkiKeyBits(issuer));
            byte[] oid = new ASN1ObjectIdentifier(h[1]).getEncoded(ASN1Encoding.DER);
            byte[] algId = tlv(0x30, oid, new byte[] {5, 0});
            byte[] certId = tlv(0x30, algId, tlv(4, nameHash), tlv(4, keyHash), new ASN1Integer(new BigInteger(cert.serial)).getEncoded(ASN1Encoding.DER));
            byte[] reqList = tlv(0x30, tlv(0x30, certId));
            if (nonce == null) return tlv(0x30, tlv(0x30, reqList));
            if (nonce.length < 1 || nonce.length > 32) throw new IllegalArgumentException("nonce must be 1..32 bytes");
            byte[] ext = tlv(0x30, new ASN1ObjectIdentifier(AttestNvidiaOcsp.OID_OCSP_NONCE).getEncoded(ASN1Encoding.DER), tlv(4, tlv(4, nonce)));
            return tlv(0x30, tlv(0x30, reqList, tlv(0xa2, tlv(0x30, ext))));
        } catch (java.io.IOException | java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] tlv(int tag, byte[]... parts) {
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p, 0, p.length);
        int n = body.size();
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(tag);
        if (n < 0x80) o.write(n);
        else if (n < 0x100) { o.write(0x81); o.write(n); }
        else { o.write(0x82); o.write(n >> 8); o.write(n & 0xff); }
        o.write(body.toByteArray(), 0, n);
        return o.toByteArray();
    }

    /** The OCSP responder URLs a certificate advertises in its Authority Information Access extension. */
    public static List<String> nvidiaCertOcspUrls(String certPem) { return AttestCert.certFromPem(certPem).ocspServers(); }

    private static Object lng(long v) { return Long.valueOf(v); }

    /**
     * Verify one DER OCSPResponse for {@code chain[certIndex]} (issued by {@code chain[issuerIndex]}, default the next): {chainPem, certIndex, issuerIndex?,
     * nowMs, maxAgeMs?, expectedNonce?, clockSkewMs?}. {ok: true, status, thisUpdate, nextUpdate?, producedAt, revokedAt?, revocationReason?, responder}
     * or {ok: false, reason}. Never throws on a malformed response.
     */
    public static Map<String, Object> verifyNvidiaOcspResponse(byte[] der, Map<String, Object> o) {
        List<AttCert> chain = chainOf((String) o.get("chainPem"));
        int ci = (int) IntentJs.lng(o.get("certIndex"));
        int ii = o.get("issuerIndex") != null ? (int) IntentJs.lng(o.get("issuerIndex")) : ci + 1;
        AttestNvidiaOcsp.Opts opts = new AttestNvidiaOcsp.Opts();
        if (o.get("maxAgeMs") != null) opts.maxAgeMs = IntentJs.num(o.get("maxAgeMs"));
        if (o.get("clockSkewMs") != null) opts.skewMs = IntentJs.num(o.get("clockSkewMs"));
        if (o.get("expectedNonce") instanceof byte[]) opts.expectedNonce = (byte[]) o.get("expectedNonce");
        AttCert cert = ci >= 0 && ci < chain.size() ? chain.get(ci) : null;
        AttCert issuer = ii >= 0 && ii < chain.size() ? chain.get(ii) : null;
        AttestNvidiaOcsp.Result r = AttestNvidiaOcsp.verifyResponse(der, cert, issuer, chain, (long) IntentJs.num(o.get("nowMs")).doubleValue(), opts);
        if (!r.ok) return Issue.obj("ok", false, "reason", r.reason);
        Map<String, Object> out = Issue.obj("ok", true, "status", r.status, "thisUpdate", lng(r.thisUpdate));
        if (r.hasNext) out.put("nextUpdate", lng(r.nextUpdate));
        out.put("producedAt", lng(r.producedAt));
        if (r.revokedAt != null) out.put("revokedAt", lng(r.revokedAt));
        if (r.revocationReason != null) out.put("revocationReason", lng(r.revocationReason));
        out.put("responder", r.responder);
        return out;
    }

    /**
     * Check the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED status fails, and each
     * required certificate needs a GOOD response. {@code opts} = {requireGood? ("aia" | "all" | indices), maxAgeMs?, clockSkewMs?, expectedNonces?}.
     * {ok: true, verifiedCrls: 0, verifiedOcsp, statuses} or {ok: false, reason, statuses?}.
     */
    public static Map<String, Object> checkNvidiaChainOcsp(String chainPem, List<byte[]> responses, long nowMs, Map<String, Object> opts) {
        AttestNvidiaOcsp.ChainOpts co = new AttestNvidiaOcsp.ChainOpts();
        if (opts != null) {
            if (opts.get("requireGood") != null) co.requireGood = opts.get("requireGood");
            if (opts.get("maxAgeMs") != null) co.maxAgeMs = IntentJs.num(opts.get("maxAgeMs"));
            if (opts.get("clockSkewMs") != null) co.skewMs = IntentJs.num(opts.get("clockSkewMs"));
            if (opts.get("expectedNonces") instanceof List) {
                co.expectedNonces = new ArrayList<>();
                for (Object x : (List<?>) opts.get("expectedNonces")) co.expectedNonces.add(x instanceof byte[] ? (byte[]) x : null);
            }
        }
        AttestNvidiaOcsp.ChainResult r = AttestNvidiaOcsp.checkChain(chainOf(chainPem), responses, nowMs, co);
        Map<String, Object> out = r.ok ? Issue.obj("ok", true, "verifiedCrls", lng(0), "verifiedOcsp", lng(r.verified)) : Issue.obj("ok", false, "reason", r.reason);
        if (r.statuses != null) {
            Map<String, Object> st = new LinkedHashMap<>();
            for (int i = 0; i < r.statuses.length; i++) st.put(String.valueOf(i), r.statuses[i]);
            out.put("statuses", st);
        }
        return out;
    }

    /**
     * POST an OCSPRequest for {@code certPem} to the responder ({@code url} or the NVIDIA default) through the injected transport and return
     * {request, response}. Explicit use only.
     */
    public static Map<String, Object> fetchNvidiaOcsp(String certPem, String issuerPem, Post post, String url, byte[] nonce) throws Exception {
        if (post == null) throw new IllegalStateException("fetchNvidiaOcsp: no fetch implementation available");
        Map<String, Object> o = new LinkedHashMap<>();
        if (nonce != null) o.put("nonce", nonce);
        byte[] request = buildNvidiaOcspRequest(certPem, issuerPem, o);
        HardwareSevSnp.Response res = post.post(url == null ? NVIDIA_OCSP_URL : url, "application/ocsp-request", request);
        if (res.status < 200 || res.status > 299) throw new IllegalStateException("OCSP fetch failed: HTTP " + res.status);
        return Issue.obj("request", request, "response", res.body);
    }
}
