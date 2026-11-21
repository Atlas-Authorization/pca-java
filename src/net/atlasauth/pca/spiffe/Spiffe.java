package net.atlasauth.pca.spiffe;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestDer;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.jose.Jose;

/**
 * Bridge PCA agent identity with SPIFFE / SPIRE workload identity: SPIFFE ID parsing, JWT-SVID and X.509-SVID verification against a
 * trust bundle, SVID to PCA holder binding, revocation and trust-bundle caches that fail closed, and blueprint-admission evidence.
 * Every check is fail closed; a failure is a {@link SpiffeError} with a stable code (JOSE failures from a JWT-SVID are
 * {@link Jose.JoseException}).
 *
 * <p>JWT-SVID keys are public JWK maps (or a {@link JwtKeyResolver}); revocation checks and fetchers are synchronous.
 * shortcut: an X.509 {@code checkIssued} covers the subject/issuer name, authority key id, serial and keyCertSign rules.
 */
public final class Spiffe {
    private Spiffe() {}

    // ---- SPIFFE ID -----------------------------------------------------------------------------------------------

    /** A parsed, validated SPIFFE ID. */
    public static final class SpiffeId {
        public final String id, trustDomain, path;
        SpiffeId(String id, String trustDomain, String path) { this.id = id; this.trustDomain = trustDomain; this.path = path; }
        /** {@code {id, trustDomain, path}} as a JSON object. */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("trustDomain", trustDomain);
            m.put("path", path);
            return m;
        }
    }

    private static final String SPIFFE_SCHEME = "spiffe://";
    private static final int MAX_SPIFFE_ID_LENGTH = 2048;
    private static final int MAX_TRUST_DOMAIN_LENGTH = 255;
    private static final Pattern TRUST_DOMAIN_RE = Pattern.compile("[a-z0-9._-]+");
    private static final Pattern PATH_SEGMENT_RE = Pattern.compile("[a-zA-Z0-9._-]+");

    /** Signature algorithms the JWT-SVID specification allows. */
    public static final List<String> JWT_SVID_ALGORITHMS = List.of("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512");

    /**
     * Validate and parse {@code spiffe://<trust-domain>/<path>}: lowercase scheme; non-empty trust domain from [a-z0-9._-] (at most 255);
     * path segments from [a-zA-Z0-9._-] with no empty segment, no "." / ".." segment and no trailing slash; at most 2048 characters.
     * Throws {@link SpiffeError}. A bare {@code spiffe://trust-domain} is valid.
     */
    public static SpiffeId parseSpiffeId(Object sv) {
        if (!(sv instanceof String) || ((String) sv).isEmpty()) throw new SpiffeError("malformed_spiffe_id", "SPIFFE ID must be a non-empty string");
        String s = (String) sv;
        if (s.length() > MAX_SPIFFE_ID_LENGTH) throw new SpiffeError("id_too_long", "SPIFFE ID exceeds " + MAX_SPIFFE_ID_LENGTH + " bytes");
        if (!s.startsWith(SPIFFE_SCHEME)) throw new SpiffeError("malformed_spiffe_id", "SPIFFE ID must begin with \"" + SPIFFE_SCHEME + "\"");
        String rest = s.substring(SPIFFE_SCHEME.length());
        int slash = rest.indexOf('/');
        String trustDomain = slash == -1 ? rest : rest.substring(0, slash);
        String path = slash == -1 ? "" : rest.substring(slash);
        if (trustDomain.isEmpty()) throw new SpiffeError("empty_trust_domain", "SPIFFE ID has an empty trust domain");
        if (trustDomain.length() > MAX_TRUST_DOMAIN_LENGTH) throw new SpiffeError("trust_domain_too_long", "trust domain exceeds " + MAX_TRUST_DOMAIN_LENGTH + " bytes");
        if (!TRUST_DOMAIN_RE.matcher(trustDomain).matches()) throw new SpiffeError("invalid_trust_domain", "trust domain \"" + trustDomain + "\" must be lowercase and contain only [a-z0-9._-]");
        if (!path.isEmpty()) {
            if (path.endsWith("/")) throw new SpiffeError("invalid_path", "SPIFFE ID path must not end with a trailing slash");
            String[] segments = path.split("/", -1);
            for (int i = 1; i < segments.length; i++) {
                String seg = segments[i];
                if (seg.isEmpty()) throw new SpiffeError("invalid_path", "SPIFFE ID path must not contain an empty segment");
                if (seg.equals(".") || seg.equals("..")) throw new SpiffeError("invalid_path", "SPIFFE ID path must not contain a \".\" or \"..\" segment");
                if (!PATH_SEGMENT_RE.matcher(seg).matches()) throw new SpiffeError("invalid_path", "SPIFFE ID path segment \"" + seg + "\" contains an invalid character");
            }
        }
        return new SpiffeId(SPIFFE_SCHEME + trustDomain + path, trustDomain, path);
    }

    // ---- revocation subjects and checks --------------------------------------------------------------------------

    /** What {@link #verifyX509Svid} asks the revocation check about, once per presented certificate (leaf first). */
    public static final class X509RevocationSubject {
        public final String spiffeId, serialNumber, fingerprint256;
        public final int position;
        public final boolean isLeaf;
        public X509RevocationSubject(String spiffeId, String serialNumber, String fingerprint256, int position, boolean isLeaf) {
            this.spiffeId = spiffeId; this.serialNumber = serialNumber; this.fingerprint256 = fingerprint256; this.position = position; this.isLeaf = isLeaf;
        }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("spiffeId", spiffeId);
            m.put("serialNumber", serialNumber);
            m.put("fingerprint256", fingerprint256);
            m.put("position", new Json.Num(Integer.toString(position)));
            m.put("isLeaf", isLeaf);
            return m;
        }
    }

    /** What {@link #verifyJwtSvid} asks the revocation check about. */
    public static final class JwtRevocationSubject {
        public final String spiffeId;
        /** The {@code jti} claim when it is a string, else null. */
        public final String jti;
        /** The {@code exp} claim (a JSON number). */
        public final Object expiresAt;
        /** base64url SHA-256 of the token string. */
        public final String tokenHash;
        public JwtRevocationSubject(String spiffeId, String jti, Object expiresAt, String tokenHash) { this.spiffeId = spiffeId; this.jti = jti; this.expiresAt = expiresAt; this.tokenHash = tokenHash; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("spiffeId", spiffeId);
            if (jti != null) m.put("jti", jti);
            m.put("expiresAt", expiresAt);
            m.put("tokenHash", tokenHash);
            return m;
        }
    }

    /** Return exactly {@link Boolean#FALSE} to admit, {@link Boolean#TRUE} when revoked; anything else, or a throw, refuses ({@code revocation_unavailable}). */
    public interface X509RevocationCheck { Object check(X509RevocationSubject subject) throws Exception; }
    /** As {@link X509RevocationCheck} for a JWT-SVID. */
    public interface JwtRevocationCheck { Object check(JwtRevocationSubject subject) throws Exception; }

    /** Stands for a revocation option that is not a function (the reference's {@code null}): refused as {@code revocation_unavailable}. */
    public static final Object NOT_A_FUNCTION = new Object();

    private static String errMsg(Exception e) { return e.getMessage() == null ? e.toString() : e.getMessage(); }

    // ---- JWT-SVID ------------------------------------------------------------------------------------------------

    /** A key resolver for {@link #verifyJwtSvid}: the (protected header, token) to a public JWK (e.g. a trust bundle's JWKS). */
    public interface JwtKeyResolver { Map<String, Object> resolve(Map<String, Object> protectedHeader, String token) throws Exception; }

    /** Options for {@link #verifyJwtSvid}. */
    public static final class VerifyJwtSvidOptions {
        /** REQUIRED audience(s). */
        public List<String> audience;
        /** A public JWK map, or a {@link JwtKeyResolver}. */
        public Object key;
        /** REQUIRED subject trust domain. */
        public String trustDomain;
        /** Verification time (epoch ms); null = now. */
        public Long currentDateMs;
        /** Permitted algorithms; null = {@link #JWT_SVID_ALGORITHMS}. */
        public List<String> algorithms;
        /** Seconds (Number) or a time-period string such as "30s"; null = 0. */
        public Object clockTolerance;
        /** A {@link JwtRevocationCheck}, {@link #NOT_A_FUNCTION}, or null (not checked). */
        public Object revocation;
    }

    /** A verified JWT-SVID. */
    public static final class JwtSvid {
        public final SpiffeId spiffeId;
        public final Map<String, Object> claims;
        public final List<Object> audience;
        /** {@code exp} as a JSON number. */
        public final Object expiresAt;
        private boolean verified;
        JwtSvid(SpiffeId spiffeId, Map<String, Object> claims, List<Object> audience, Object expiresAt) { this.spiffeId = spiffeId; this.claims = claims; this.audience = audience; this.expiresAt = expiresAt; }
    }

    private static final Pattern SECS = Pattern.compile("^(\\+|-)? ?(\\d+|\\d+\\.\\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$", Pattern.CASE_INSENSITIVE);

    /** The jose time-period parser (seconds); IllegalArgumentException when malformed. */
    static double secs(String str) {
        Matcher m = SECS.matcher(str);
        if (!m.matches() || (m.group(4) != null && m.group(1) != null)) throw new IllegalArgumentException("Invalid time period format");
        double value = Double.parseDouble(m.group(2));
        String unit = m.group(3).toLowerCase(Locale.ROOT);
        double n;
        switch (unit) {
            case "sec": case "secs": case "second": case "seconds": case "s": n = Math.round(value); break;
            case "minute": case "minutes": case "min": case "mins": case "m": n = Math.round(value * 60); break;
            case "hour": case "hours": case "hr": case "hrs": case "h": n = Math.round(value * 3600); break;
            case "day": case "days": case "d": n = Math.round(value * 86400); break;
            case "week": case "weeks": case "w": n = Math.round(value * 604800); break;
            default: n = Math.round(value * (86400 * 365.25)); break;
        }
        return "-".equals(m.group(1)) || "ago".equals(m.group(4)) ? -n : n;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /**
     * Verify a JWT-SVID: the canonical compact spelling, the JWS signature against the key / resolver, the audience, {@code exp} (and
     * {@code nbf}), a valid SPIFFE ID {@code sub} in the pinned trust domain, then the optional revocation check (last).
     */
    @SuppressWarnings("unchecked")
    public static JwtSvid verifyJwtSvid(String token, VerifyJwtSvidOptions opts) {
        if (opts.revocation != null && !(opts.revocation instanceof JwtRevocationCheck)) throw new SpiffeError("revocation_unavailable", "revocation must be a function");
        if (opts.trustDomain == null || opts.trustDomain.isEmpty()) throw new SpiffeError("missing_trust_domain", "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)");
        List<String> audience = opts.audience;
        boolean anyEmpty = false;
        for (String a : audience) if (a.isEmpty()) anyEmpty = true;
        if (audience.isEmpty() || anyEmpty) throw new SpiffeError("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)");
        List<String> algorithms = opts.algorithms != null ? opts.algorithms : new ArrayList<>(JWT_SVID_ALGORITHMS);
        String bad = null;
        for (String a : algorithms) if (a.equals("none") || a.toUpperCase(Locale.ROOT).startsWith("HS")) { bad = a; break; }
        if (bad != null || algorithms.isEmpty()) throw new SpiffeError("forbidden_algorithm", "JWT-SVIDs must not use " + (bad != null ? bad : "an empty algorithm list"));

        // a non-finite tolerance makes every exp/nbf comparison pass
        if (opts.clockTolerance instanceof Number || opts.clockTolerance instanceof Json.Num) {
            double ct = Double.parseDouble(opts.clockTolerance.toString());
            if (!(Double.isFinite(ct) && ct >= 0)) throw new SpiffeError("malformed_token", "verifyJwtSvid: clockTolerance must be a finite number >= 0");
        }

        Jose.CanonicalJws canon;
        try {
            canon = Jose.assertCanonicalCompactJws(token);
        } catch (RuntimeException cause) {
            throw new SpiffeError("malformed_token", cause.getMessage());
        }
        Jose.JwtOptions jo = new Jose.JwtOptions();
        jo.audience = audience;
        jo.algorithms = algorithms;
        jo.currentDateMs = opts.currentDateMs == null ? null : Double.valueOf(opts.currentDateMs);
        Object tol = opts.clockTolerance;
        Map<String, Object> jwk;
        if (opts.key instanceof JwtKeyResolver) {
            Jose.checkCritHeader(canon.header); // crit is refused before any key is resolved, as the reference does
            Object alg = canon.header.get("alg");
            if (!(alg instanceof String) || ((String) alg).isEmpty()) throw new Jose.JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
            if (!algorithms.contains(alg)) throw new Jose.JoseException("\"alg\" (Algorithm) Header Parameter value not allowed");
            try {
                jwk = ((JwtKeyResolver) opts.key).resolve(canon.header, token);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new Jose.JoseException("key resolution failed: " + errMsg(e));
            }
        } else {
            jwk = asMap(opts.key);
            if (jwk == null) throw new Jose.JoseException("Invalid key input");
        }
        if (tol instanceof Number || tol instanceof Json.Num) jo.clockTolerance = Double.parseDouble(tol.toString());
        else if (tol instanceof String) jo.clockTolerance = secs((String) tol);
        else if (tol != null) throw new IllegalArgumentException("Invalid clockTolerance option type");
        Jose.VerifiedJwt v = Jose.jwtVerify(token, jwk, jo);
        Map<String, Object> payload = v.payload;
        Object typ = v.protectedHeader.get("typ");
        if (v.protectedHeader.containsKey("typ") && !"JWT".equals(typ) && !"JOSE".equals(typ)) {
            throw new SpiffeError("invalid_typ", "JWT-SVID header typ must be JWT or JOSE, got '" + typ + "'");
        }
        Object exp = payload.get("exp");
        if (Jose.num(exp) == null) throw new SpiffeError("missing_exp", "JWT-SVID is missing the required \"exp\" claim");
        if (!(payload.get("sub") instanceof String)) throw new SpiffeError("invalid_subject", "JWT-SVID \"sub\" must be a string SPIFFE ID");
        SpiffeId spiffeId;
        try {
            spiffeId = parseSpiffeId(payload.get("sub"));
        } catch (SpiffeError err) {
            throw new SpiffeError("invalid_subject", "JWT-SVID \"sub\" is not a valid SPIFFE ID: " + err.getMessage());
        }
        if (!spiffeId.trustDomain.equals(opts.trustDomain)) {
            throw new SpiffeError("trust_domain_mismatch", "JWT-SVID trust domain \"" + spiffeId.trustDomain + "\" does not match expected \"" + opts.trustDomain + "\"");
        }
        Object aud = payload.get("aud");
        List<Object> resolved = aud == null ? new ArrayList<>() : aud instanceof String ? new ArrayList<>(List.of(aud)) : new ArrayList<>((List<Object>) aud);
        JwtSvid out = new JwtSvid(spiffeId, payload, resolved, exp);
        if (opts.revocation != null) {
            Object verdict;
            try {
                Object jti = payload.get("jti");
                verdict = ((JwtRevocationCheck) opts.revocation).check(new JwtRevocationSubject(spiffeId.id, jti instanceof String ? (String) jti : null, exp, sha256b64u(token)));
            } catch (Exception e) {
                throw new SpiffeError("revocation_unavailable", "revocation check failed: " + errMsg(e));
            }
            if (Boolean.TRUE.equals(verdict)) throw new SpiffeError("svid_revoked", "JWT-SVID for " + spiffeId.id + " is revoked");
            if (!Boolean.FALSE.equals(verdict)) throw new SpiffeError("revocation_unavailable", "revocation check did not return a boolean");
        }
        out.verified = true;
        return out;
    }

    private static String sha256b64u(String s) {
        try {
            return Keys.b64u(MessageDigest.getInstance("SHA-256").digest(Json.utf8(s)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- X.509-SVID ----------------------------------------------------------------------------------------------

    /** A parsed X.509-SVID. */
    public static final class X509Svid {
        public final SpiffeId spiffeId;
        public final X509Certificate certificate;
        /** base64url SPKI DER of the certificate's public key. */
        public final String publicKeyDer;
        private boolean verified;
        X509Svid(SpiffeId spiffeId, X509Certificate certificate, String publicKeyDer) { this.spiffeId = spiffeId; this.certificate = certificate; this.publicKeyDer = publicKeyDer; }
    }

    /** BouncyCastle parses certificates leniently (a SAN URI the JDK parser refuses is still a certificate). */
    private static final java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

    private static final Pattern PEM_CERT_RE = Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");

    private static X509Certificate toCertificate(Object cert) {
        try {
            byte[] der;
            if (cert instanceof byte[]) der = (byte[]) cert;
            else if (cert instanceof String) {
                // the first PEM certificate: its BEGIN line alone on a line, base64 lines, then the END line (as OpenSSL reads it)
                String[] lines = ((String) cert).split("\n", -1);
                int i = 0;
                while (i < lines.length && !lines[i].strip().equals("-----BEGIN CERTIFICATE-----")) i++;
                if (i == lines.length) throw new IllegalArgumentException("no start line");
                StringBuilder body = new StringBuilder();
                boolean ended = false;
                for (int j = i + 1; j < lines.length; j++) {
                    String ln = lines[j].strip();
                    if (ln.equals("-----END CERTIFICATE-----")) { ended = true; break; }
                    body.append(ln);
                }
                if (!ended) throw new IllegalArgumentException("bad end line");
                der = Base64.getDecoder().decode(body.toString());
            } else throw new IllegalArgumentException("certificate must be PEM text or DER bytes");
            Object c = CertificateFactory.getInstance("X.509", BC).generateCertificate(new ByteArrayInputStream(der));
            if (!(c instanceof X509Certificate)) throw new IllegalArgumentException("not a certificate");
            return (X509Certificate) c;
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new SpiffeError("malformed_certificate", "cannot parse certificate: " + errMsg(e));
        }
    }

    private static byte[] raw(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new SpiffeError("malformed_certificate", "cannot encode certificate: " + errMsg(e));
        }
    }

    private static SpiffeDer.CertFacts factsOf(X509Certificate certificate) {
        try {
            return SpiffeDer.readCertFacts(raw(certificate));
        } catch (RuntimeException e) {
            if (e instanceof SpiffeError) throw e;
            throw new SpiffeError("malformed_certificate", "cannot read certificate extensions: " + errMsg(e));
        }
    }

    private static final class Leaf {
        final SpiffeId spiffeId;
        Leaf(SpiffeId spiffeId) { this.spiffeId = spiffeId; }
    }

    /** The X509-SVID leaf rules (section 4.3). */
    private static Leaf validateLeaf(X509Certificate certificate) {
        SpiffeDer.CertFacts facts = factsOf(certificate);
        if (!facts.unknownCritical.isEmpty()) throw new SpiffeError("unsupported_critical_extension", "certificate has an unsupported critical extension (" + String.join(", ", facts.unknownCritical) + ")");
        if (facts.uriSans.isEmpty()) throw new SpiffeError("no_uri_san", "X.509-SVID certificate has no URI SAN");
        if (facts.uriSans.size() > 1) throw new SpiffeError("multiple_uri_san", "X.509-SVID certificate must have exactly one URI SAN, found " + facts.uriSans.size());
        SpiffeId spiffeId = parseSpiffeId(facts.uriSans.get(0));
        if (spiffeId.path.isEmpty()) throw new SpiffeError("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path");
        if (facts.isCa) throw new SpiffeError("leaf_is_ca", "leaf certificate must not have the CA flag set to true");
        if (!facts.digitalSignature) throw new SpiffeError("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage");
        if (facts.keyCertSign) throw new SpiffeError("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage");
        if (facts.crlSign) throw new SpiffeError("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage");
        return new Leaf(spiffeId);
    }

    /** Elements of the constructed value whose content spans [start, end): {element start, content start, content end}. */
    private static List<int[]> childRanges(byte[] d, int start, int end) {
        List<int[]> out = new ArrayList<>();
        int off = start;
        while (off < end) {
            int[] t = tlv(d, off, end);
            if (t == null) break;
            out.add(new int[] {off, t[0], t[1]});
            off = t[1];
        }
        return out;
    }

    /** The certificate's SubjectPublicKeyInfo DER, read from its own bytes. */
    private static byte[] spkiOf(X509Certificate c) {
        byte[] d = raw(c);
        try {
            int[] cert = tlv(d, 0, d.length);
            int[] tbs = tlv(d, cert[0], cert[1]);
            List<int[]> kids = childRanges(d, tbs[0], tbs[1]);
            int i = (d[kids.get(0)[0]] & 0xff) == 0xa0 ? 1 : 0;
            int[] spki = kids.get(i + 5);
            return Arrays.copyOfRange(d, spki[0], spki[2]);
        } catch (RuntimeException e) {
            throw new SpiffeError("malformed_certificate", "cannot read the certificate public key: " + errMsg(e));
        }
    }

    private static String spkiB64u(X509Certificate c) { return Keys.b64u(spkiOf(c)); }

    /** A JDK public key from SubjectPublicKeyInfo DER (EC, RSA or Ed25519); null when none of them takes it. */
    private static PublicKey jdkKey(byte[] spki) {
        for (String alg : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                return java.security.KeyFactory.getInstance(alg).generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
            } catch (GeneralSecurityException | RuntimeException e) {
                // try the next algorithm
            }
        }
        return null;
    }

    /**
     * Parse an X.509-SVID (PEM text or DER bytes) and validate it as a SPIFFE leaf. Does NOT check the chain, validity or revocation:
     * use {@link #verifyX509Svid}. A parsed-only SVID is refused by {@link #svidToHolder}.
     */
    public static X509Svid parseX509Svid(Object cert) {
        X509Certificate certificate = toCertificate(cert);
        Leaf l = validateLeaf(certificate);
        return new X509Svid(l.spiffeId, certificate, spkiB64u(certificate));
    }

    /** Options for {@link #verifyX509Svid}. */
    public static final class VerifyX509SvidOptions {
        /** REQUIRED trust domain. */
        public String trustDomain;
        /** REQUIRED trust bundle authorities: PEM text (possibly several certificates) or DER bytes. */
        public List<Object> roots;
        /** Verification time (epoch ms); null = now. */
        public Long nowMs;
        /** Maximum chain length; null = 8. */
        public Integer maxChainLength;
        /** An {@link X509RevocationCheck}, {@link #NOT_A_FUNCTION}, or null (not checked). */
        public Object revocation;
    }

    private static List<X509Certificate> certsOf(Object input) {
        if (input instanceof String) {
            Matcher m = PEM_CERT_RE.matcher((String) input);
            List<X509Certificate> out = new ArrayList<>();
            while (m.find()) out.add(toCertificate(m.group()));
            if (out.isEmpty()) throw new SpiffeError("malformed_certificate", "no PEM certificate found");
            return out;
        }
        List<X509Certificate> one = new ArrayList<>();
        one.add(toCertificate(input));
        return one;
    }

    private static SpiffeDer.CertFacts validateSigner(X509Certificate cert, String label) {
        SpiffeDer.CertFacts facts = factsOf(cert);
        if (!facts.unknownCritical.isEmpty()) throw new SpiffeError("unsupported_critical_extension", label + " has an unsupported critical extension (" + String.join(", ", facts.unknownCritical) + ")");
        if (!facts.isCa) throw new SpiffeError("chain_not_ca", label + " must have the CA flag set to true");
        if (!facts.keyUsagePresent || !facts.keyCertSign) throw new SpiffeError("chain_no_key_cert_sign", label + " must have 'keyCertSign' set as key usage");
        return facts;
    }

    private static boolean withinValidity(X509Certificate c, long nowMs) { return AttestDer.derValidAt(raw(c), nowMs, 0); }

    // ---- X.509 issuance relation (the reference's X509Certificate.checkIssued) ----

    private static byte[] extValue(X509Certificate c, String oid) {
        byte[] v = c.getExtensionValue(oid); // DER OCTET STRING wrapping the extension's value
        if (v == null) return null;
        return Arrays.copyOfRange(v, derHeaderLen(v), v.length);
    }

    private static int derHeaderLen(byte[] d) {
        int l = d[1] & 0xff;
        return (l & 0x80) == 0 ? 2 : 2 + (l & 0x7f);
    }

    /** [content start, content end) of the TLV at {@code off}, or null when it does not fit. */
    private static int[] tlv(byte[] d, int off, int limit) {
        if (off + 2 > limit) return null;
        long len = d[off + 1] & 0xff;
        int p = off + 2;
        if ((len & 0x80) != 0) {
            int n = (int) (len & 0x7f);
            if (n == 0 || n > 4 || p + n > limit) return null;
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + (d[p + i] & 0xff);
            p += n;
        }
        if (p + len > limit) return null;
        return new int[] {p, (int) (p + len)};
    }

    /** The AuthorityKeyIdentifier members: [0] key id, [1] authorityCertIssuer (raw), [2] serial. Absent members are null. */
    private static byte[][] akid(X509Certificate c) {
        byte[] v = extValue(c, "2.5.29.35");
        byte[][] out = new byte[3][];
        if (v == null) return null;
        int[] seq = tlv(v, 0, v.length);
        if (seq == null) return out;
        int off = seq[0];
        while (off < seq[1]) {
            int[] t = tlv(v, off, seq[1]);
            if (t == null) break;
            int tag = v[off] & 0xff;
            if (tag == 0x80) out[0] = Arrays.copyOfRange(v, t[0], t[1]);
            else if (tag == 0xa1) out[1] = Arrays.copyOfRange(v, t[0], t[1]);
            else if (tag == 0x82) out[2] = Arrays.copyOfRange(v, t[0], t[1]);
            off = t[1];
        }
        return out;
    }

    private static byte[] skid(X509Certificate c) {
        byte[] v = extValue(c, "2.5.29.14");
        if (v == null || v.length < 2 || (v[0] & 0xff) != 0x04) return null;
        int[] t = tlv(v, 0, v.length);
        return t == null ? null : Arrays.copyOfRange(v, t[0], t[1]);
    }

    /** True when {@code issuer} could have issued {@code subject}: names, authority key id / serial / issuer, and keyCertSign. */
    static boolean checkIssued(X509Certificate subject, X509Certificate issuer) {
        if (!subject.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) return false;
        byte[][] a = akid(subject);
        if (a != null) {
            byte[] sk = skid(issuer);
            if (a[0] != null && sk != null && !Arrays.equals(a[0], sk)) return false;
            if (a[2] != null && !new BigInteger(a[2]).equals(issuer.getSerialNumber())) return false;
            if (a[1] != null) {
                // authorityCertIssuer: a directoryName ([4]) must name the issuer's own issuer
                int[] nm = null;
                int off = 0;
                boolean anyDir = false, matched = false;
                while (off < a[1].length) {
                    int[] t = tlv(a[1], off, a[1].length);
                    if (t == null) break;
                    if ((a[1][off] & 0xff) == 0xa4) {
                        anyDir = true;
                        int[] inner = tlv(a[1], t[0], t[1]);
                        if (inner != null) {
                            try {
                                javax.security.auth.x500.X500Principal p = new javax.security.auth.x500.X500Principal(Arrays.copyOfRange(a[1], t[0], t[1]));
                                if (p.equals(issuer.getIssuerX500Principal())) matched = true;
                            } catch (RuntimeException e) { /* not a name */ }
                        }
                    }
                    off = t[1];
                }
                if (nm == null && anyDir && !matched) return false;
            }
        }
        boolean[] ku = issuer.getKeyUsage();
        return ku == null || (ku.length > 5 && ku[5]);
    }

    /** True when {@code cert} carries a valid signature by {@code signer}'s public key. */
    private static boolean verifiedBy(X509Certificate cert, X509Certificate signer) {
        try {
            PublicKey key = jdkKey(spkiOf(signer));
            if (key == null) return false;
            cert.verify(key);
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static String serialHex(X509Certificate c) {
        BigInteger s = c.getSerialNumber();
        String h = s.abs().toString(16).toUpperCase(Locale.ROOT);
        if (h.length() % 2 == 1) h = "0" + h;
        return (s.signum() < 0 ? "-" : "") + h;
    }

    private static String fingerprint256(X509Certificate c) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(raw(c));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", d[i] & 0xff));
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Verify an X.509-SVID against a trust bundle (section 4): the leaf rules, its trust domain, every certificate's validity, each
     * certificate signed by the next, signing certificates with cA and keyCertSign, pathLenConstraint, and an end at (or signed by) a
     * bundle authority. {@code chain} is PEM text (several certificates) or a list of PEM text / DER bytes, leaf first. Revocation is
     * checked only through {@code opts.revocation}. Throws {@link SpiffeError}.
     */
    public static X509Svid verifyX509Svid(Object chain, VerifyX509SvidOptions opts) {
        if (opts.revocation != null && !(opts.revocation instanceof X509RevocationCheck)) throw new SpiffeError("revocation_unavailable", "revocation must be a function");
        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        List<X509Certificate> items = new ArrayList<>();
        if (chain instanceof String) items.addAll(certsOf(chain));
        else for (Object c : (List<?>) chain) items.addAll(certsOf(c));
        if (items.isEmpty()) throw new SpiffeError("chain_empty", "certificate chain is empty");
        if (items.size() > (opts.maxChainLength != null ? opts.maxChainLength : 8)) throw new SpiffeError("chain_too_long", "certificate chain is too long");
        X509Certificate leaf = items.get(0);
        SpiffeId spiffeId = validateLeaf(leaf).spiffeId;
        if (!spiffeId.trustDomain.equals(opts.trustDomain)) throw new SpiffeError("chain_trust_domain_mismatch", "SPIFFE ID trust domain '" + spiffeId.trustDomain + "' is not '" + opts.trustDomain + "'");
        List<X509Certificate> roots = new ArrayList<>();
        for (Object r : opts.roots) roots.addAll(certsOf(r));
        if (roots.isEmpty()) throw new SpiffeError("chain_untrusted_root", "trust bundle has no X.509 authorities");

        for (X509Certificate c : items) {
            if (!withinValidity(c, now)) throw new SpiffeError("chain_expired", "a certificate in the chain is not within its validity period");
        }
        for (int i = 1; i < items.size(); i++) {
            SpiffeDer.CertFacts f = validateSigner(items.get(i), "signing certificate #" + i);
            if (f.pathLen != null && i - 1 > f.pathLen) throw new SpiffeError("chain_path_len", "signing certificate #" + i + " pathLenConstraint exceeded");
        }
        int below = items.size() - 1;
        for (int i = 0; i + 1 < items.size(); i++) {
            X509Certificate cert = items.get(i), next = items.get(i + 1);
            if (!checkIssued(cert, next) || !verifiedBy(cert, next)) throw new SpiffeError("chain_signature", "certificate #" + i + " is not signed by certificate #" + (i + 1));
        }
        X509Certificate top = items.get(items.size() - 1);
        byte[] leafRaw = raw(leaf);
        if (items.size() == 1) {
            for (X509Certificate r : roots) if (Arrays.equals(raw(r), leafRaw)) throw new SpiffeError("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor");
        }
        boolean topIsAnchor = false;
        if (items.size() > 1) {
            byte[] topRaw = raw(top);
            for (X509Certificate r : roots) if (Arrays.equals(raw(r), topRaw)) { topIsAnchor = true; break; }
        }
        if (!topIsAnchor) {
            X509Certificate signer = null;
            for (X509Certificate r : roots) if (checkIssued(top, r) && verifiedBy(top, r)) { signer = r; break; }
            if (signer == null) throw new SpiffeError("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle");
            if (!withinValidity(signer, now)) throw new SpiffeError("chain_expired", "the trust bundle authority is not within its validity period");
            SpiffeDer.CertFacts f = validateSigner(signer, "trust bundle authority");
            if (f.pathLen != null && below > f.pathLen) throw new SpiffeError("chain_path_len", "trust bundle authority pathLenConstraint exceeded");
        }

        if (opts.revocation != null) {
            for (int i = 0; i < items.size(); i++) {
                X509Certificate c = items.get(i);
                Object verdict;
                try {
                    verdict = ((X509RevocationCheck) opts.revocation).check(new X509RevocationSubject(spiffeId.id, serialHex(c), fingerprint256(c), i, i == 0));
                } catch (Exception e) {
                    throw new SpiffeError("revocation_unavailable", "revocation check failed: " + errMsg(e));
                }
                if (Boolean.TRUE.equals(verdict)) {
                    throw new SpiffeError(i == 0 ? "svid_revoked" : "chain_revoked", i == 0 ? "X.509-SVID for " + spiffeId.id + " is revoked" : "signing certificate #" + i + " of the chain is revoked");
                }
                if (!Boolean.FALSE.equals(verdict)) throw new SpiffeError("revocation_unavailable", "revocation check did not return a boolean");
            }
        }
        X509Svid out = new X509Svid(spiffeId, leaf, spkiB64u(leaf));
        out.verified = true;
        return out;
    }

    // ---- SPIFFE ID <-> PCA agent-holder identity -----------------------------------------------------------------

    /** A PCA capability holder bound to a SPIFFE workload identity. */
    public static final class SpiffeHolder {
        /** Core PCA holder identity: a base64url Ed25519 public key. */
        public final String holder, spiffeId, trustDomain, path;
        public SpiffeHolder(String holder, String spiffeId, String trustDomain, String path) { this.holder = holder; this.spiffeId = spiffeId; this.trustDomain = trustDomain; this.path = path; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("holder", holder);
            m.put("spiffeId", spiffeId);
            m.put("trustDomain", trustDomain);
            m.put("path", path);
            return m;
        }
    }

    /** A 32-byte Ed25519 holder key (base64url text or raw bytes) as canonical base64url. */
    private static String normalizeHolderKey(Object holderKey) {
        if (holderKey instanceof byte[]) {
            if (((byte[]) holderKey).length != 32) throw new SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key");
            return Keys.b64u((byte[]) holderKey);
        }
        byte[] bytes = Pca.decodeB64uStrict(holderKey, 32);
        if (bytes == null) throw new SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url");
        return Keys.b64u(bytes);
    }

    /** Domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID. */
    public static byte[] holderBindingMessage(String spiffeId, String holder) {
        return Json.utf8(("pca-spiffe-holder-binding-v1\n" + spiffeId + "\n" + holder));
    }

    /** Options for {@link #svidToHolder}. */
    public static final class SvidToHolderOptions {
        /** A base64url signature over {@link #holderBindingMessage} made with the X.509-SVID's private key (ECDSA is r||s). */
        public String proof;
        /** Accept a holder key for a JWT-SVID that carries no matching {@code cnf.jwk} (only when it is authenticated by other means). */
        public boolean acceptUnboundJwtHolder;
    }

    private static final byte[] ED25519_SPKI_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    private static String ed25519RawOfCert(X509Certificate cert) {
        byte[] spki = spkiOf(cert);
        if (spki.length != 44 || !Arrays.equals(Arrays.copyOfRange(spki, 0, 12), ED25519_SPKI_PREFIX)) return null;
        return Keys.b64u(Arrays.copyOfRange(spki, 12, 44));
    }

    private static boolean proofVerifies(byte[] spki, byte[] msg, byte[] sig) {
        try {
            PublicKey key = jdkKey(spki);
            if (key == null) return false;
            Signature s;
            if (ed25519RawOfSpki(spki) != null) s = Signature.getInstance("Ed25519");
            else if (key instanceof ECPublicKey) {
                int bits = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
                s = Signature.getInstance(bits == 384 ? "SHA384withECDSAinP1363Format" : "SHA256withECDSAinP1363Format");
            } else if (key.getAlgorithm().equals("RSA")) s = Signature.getInstance("SHA256withRSA");
            else return false;
            s.initVerify(key);
            s.update(msg);
            return s.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static String ed25519RawOfSpki(byte[] spki) {
        return spki.length == 44 && Arrays.equals(Arrays.copyOfRange(spki, 0, 12), ED25519_SPKI_PREFIX) ? "ed25519" : null;
    }

    /**
     * Bind a VERIFIED SPIFFE SVID to a PCA agent-holder. {@code svid} MUST be the object returned by {@link #verifyJwtSvid} or
     * {@link #verifyX509Svid}; anything else throws {@code unverified_svid}. {@code holderKey} is base64url text, 32 raw bytes or null.
     * An X.509-SVID with an Ed25519 key is its own holder; another key (or a different holder) needs {@code opts.proof}. A JWT-SVID
     * needs {@code holderKey} and a matching {@code cnf.jwk} unless {@code opts.acceptUnboundJwtHolder}.
     */
    public static SpiffeHolder svidToHolder(Object svid, Object holderKey, SvidToHolderOptions opts) {
        boolean ok = (svid instanceof JwtSvid && ((JwtSvid) svid).verified) || (svid instanceof X509Svid && ((X509Svid) svid).verified);
        if (!ok) throw new SpiffeError("unverified_svid", "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)");
        SvidToHolderOptions o = opts != null ? opts : new SvidToHolderOptions();
        SpiffeId parsed = svid instanceof JwtSvid ? ((JwtSvid) svid).spiffeId : ((X509Svid) svid).spiffeId;
        String holder;
        if (svid instanceof X509Svid) {
            X509Svid x = (X509Svid) svid;
            String certEd = ed25519RawOfCert(x.certificate);
            if (holderKey == null) {
                if (certEd == null) throw new SpiffeError("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof");
                holder = normalizeHolderKey(certEd);
            } else {
                holder = normalizeHolderKey(holderKey);
                if (certEd == null || !certEd.equals(holder)) {
                    if (o.proof == null) throw new SpiffeError("holder_binding_failed", "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required");
                    byte[] sig = Pca.decodeB64uStrict(o.proof, -1);
                    boolean verified = sig != null && proofVerifies(spkiOf(x.certificate), holderBindingMessage(parsed.id, holder), sig);
                    if (!verified) throw new SpiffeError("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key");
                }
            }
        } else {
            if (holderKey == null) throw new SpiffeError("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey");
            holder = normalizeHolderKey(holderKey);
            Map<String, Object> cnf = asMap(((JwtSvid) svid).claims.get("cnf"));
            Map<String, Object> jwk = cnf == null ? null : asMap(cnf.get("jwk"));
            boolean bound = jwk != null && "OKP".equals(jwk.get("kty")) && "Ed25519".equals(jwk.get("crv")) && jwk.get("x") instanceof String && jwk.get("x").equals(holder);
            if (!bound && !o.acceptUnboundJwtHolder) {
                throw new SpiffeError("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)");
            }
        }
        return new SpiffeHolder(holder, parsed.id, parsed.trustDomain, parsed.path);
    }

    /** The (validated, canonical) SPIFFE ID a {@link SpiffeHolder} was bridged from. */
    public static String holderToSpiffeId(SpiffeHolder holder) { return parseSpiffeId(holder.spiffeId).id; }

    /**
     * The SPIFFE ID the K1 {@code spiffe_bound} caveat compares: the workload identity a VERIFIED SVID carries, only when that SVID is
     * bound to {@code leafHolder} (the key that signed the PCActn). Same binding rules as {@link #svidToHolder}.
     */
    public static String spiffeIdForHolder(Object svid, String leafHolder, SvidToHolderOptions opts) {
        SpiffeHolder h = svidToHolder(svid, leafHolder, opts);
        if (!h.holder.equals(leafHolder)) throw new SpiffeError("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder");
        return h.spiffeId;
    }

    /** A K1 discharge-issuer pin for a workload: {@code {label, class: "workload", pk, spiffe_id}} (an X.509-SVID with an Ed25519 key only). */
    public static Map<String, Object> workloadDischargePin(String label, Object svid) {
        SpiffeHolder h = svidToHolder(svid, null, null);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("label", label);
        m.put("class", "workload");
        m.put("pk", h.holder);
        m.put("spiffe_id", h.spiffeId);
        return m;
    }

    // ---- revocation source ---------------------------------------------------------------------------------------

    /** A synchronous fetch that may throw. */
    public interface Fetch<T> { T fetch() throws Exception; }

    private static boolean finitePositiveOrder(double refreshMs, double maxStaleMs, boolean strictPositive) {
        boolean r = !Double.isNaN(refreshMs) && !Double.isInfinite(refreshMs) && refreshMs > 0;
        boolean m = !Double.isNaN(maxStaleMs) && !Double.isInfinite(maxStaleMs) && maxStaleMs >= refreshMs;
        return r && m;
    }

    private static String normHex(String s) { return s.replace(":", "").toUpperCase(Locale.ROOT); }
    private static String normSerial(String s) {
        String h = normHex(s);
        int i = 0;
        while (i < h.length() - 1 && h.charAt(i) == '0') i++;
        return h.substring(i);
    }

    @SuppressWarnings("unchecked")
    private static List<String> listOf(Map<String, Object> raw, String key) {
        if (!raw.containsKey(key)) return new ArrayList<>();
        Object v = raw.get(key);
        if (v instanceof List) {
            for (Object x : (List<Object>) v) if (!(x instanceof String)) v = null;
        }
        if (!(v instanceof List)) throw new SpiffeError("revocation_unavailable", "revocation list field \"" + key + "\" must be an array of strings");
        return (List<String>) v;
    }

    private static final class Snapshot {
        final Set<String> fingerprints = new HashSet<>(), serials = new HashSet<>(), spiffeIds = new HashSet<>(), jtis = new HashSet<>(), tokenHashes = new HashSet<>();
    }

    private static Snapshot toSnapshot(Object list) {
        Map<String, Object> raw = asMap(list);
        if (raw == null) throw new SpiffeError("revocation_unavailable", "revocation list must be an object");
        Snapshot s = new Snapshot();
        for (String x : listOf(raw, "fingerprints")) s.fingerprints.add(normHex(x));
        for (String x : listOf(raw, "serials")) s.serials.add(normSerial(x));
        s.spiffeIds.addAll(listOf(raw, "spiffeIds"));
        s.jtis.addAll(listOf(raw, "jtis"));
        s.tokenHashes.addAll(listOf(raw, "tokenHashes"));
        return s;
    }

    /**
     * A revocation snapshot cache that fails closed: before the first successful fetch, or once the last good snapshot is older than
     * {@code maxStaleMs}, every check refuses with {@code revocation_unavailable}. A successful refresh replaces the snapshot. The
     * fetch returns a JSON object {@code {fingerprints?, serials?, spiffeIds?, jtis?, tokenHashes?}} of string arrays.
     */
    public static final class RevocationSource {
        private final Fetch<Object> fetch;
        private final double refreshMs, maxStaleMs;
        private final LongSupplier now;
        private Snapshot good;
        private long goodAt;
        private SpiffeError lastFailure;
        /** For {@link VerifyX509SvidOptions#revocation}: uses the cached snapshot, so call {@link #ensureFresh} first. */
        public final X509RevocationCheck x509 = s -> {
            Snapshot snap;
            synchronized (this) { snap = usable(); }
            return snap.fingerprints.contains(normHex(s.fingerprint256)) || snap.serials.contains(normSerial(s.serialNumber)) || snap.spiffeIds.contains(s.spiffeId);
        };
        /** For {@link VerifyJwtSvidOptions#revocation}: refreshes the snapshot itself when it is due. */
        public final JwtRevocationCheck jwt = s -> {
            Snapshot snap;
            synchronized (this) { ensureFresh(); snap = usable(); }
            return snap.spiffeIds.contains(s.spiffeId) || (s.jti != null && snap.jtis.contains(s.jti)) || snap.tokenHashes.contains(s.tokenHash);
        };

        RevocationSource(Fetch<Object> fetch, double refreshMs, double maxStaleMs, LongSupplier now) { this.fetch = fetch; this.refreshMs = refreshMs; this.maxStaleMs = maxStaleMs; this.now = now; }

        private void run() {
            try {
                Snapshot snap = toSnapshot(fetch.fetch());
                good = snap;
                goodAt = now.getAsLong();
                lastFailure = null;
            } catch (Exception e) {
                lastFailure = e instanceof SpiffeError ? (SpiffeError) e : new SpiffeError("revocation_unavailable", "revocation fetch failed: " + errMsg(e));
            }
        }

        private Snapshot usable() {
            if (good == null || now.getAsLong() - goodAt > maxStaleMs) {
                throw lastFailure != null ? lastFailure : new SpiffeError("revocation_unavailable", "no revocation snapshot available");
            }
            return good;
        }

        /** Fetch when the snapshot is older than {@code refreshMs}; refuses when no snapshot younger than {@code maxStaleMs} exists afterwards. */
        public synchronized void ensureFresh() {
            if (good == null || now.getAsLong() - goodAt >= refreshMs) run();
            usable();
        }

        /** Fetch now. Throws {@code revocation_unavailable} when the fetch fails or returns a malformed snapshot. */
        public synchronized void refresh() {
            run();
            if (lastFailure != null) throw lastFailure;
        }
    }

    /** Create a {@link RevocationSource}; {@code now} null = the system clock. */
    public static RevocationSource createRevocationSource(Fetch<Object> fetch, double refreshMs, double maxStaleMs, LongSupplier now) {
        if (fetch == null) throw new SpiffeError("revocation_unavailable", "createRevocationSource requires `fetch`");
        if (!finitePositiveOrder(refreshMs, maxStaleMs, true)) throw new SpiffeError("revocation_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)");
        return new RevocationSource(fetch, refreshMs, maxStaleMs, now != null ? now : System::currentTimeMillis);
    }

    // ---- trust bundle source -------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static boolean usableBundle(Object b) {
        Map<String, Object> t = asMap(b);
        if (t == null) return false;
        Map<String, Object> jwks = asMap(t.get("jwks"));
        boolean j = jwks != null && jwks.get("keys") instanceof List && !((List<Object>) jwks.get("keys")).isEmpty();
        boolean x = t.get("x509Authorities") instanceof List && !((List<Object>) t.get("x509Authorities")).isEmpty();
        return j || x;
    }

    /**
     * A trust-bundle cache that fails closed: a rejected or empty / malformed refresh keeps the last good bundle only until
     * {@code maxStaleMs} after its last successful fetch; before the first success, or past that limit, every call throws
     * {@code trust_bundle_unavailable} (fetch failed) or {@code trust_bundle_invalid} (fetched but empty / malformed). A bundle is
     * never merged. The fetch returns {@code {jwks?: {keys: [...]}, x509Authorities?: [...]}}.
     */
    public static final class TrustBundleSource {
        private final Fetch<Object> fetch;
        private final double refreshMs, maxStaleMs;
        private final LongSupplier now;
        private Map<String, Object> good;
        private long goodAt;
        private SpiffeError lastFailure;
        /** Key resolver for {@link VerifyJwtSvidOptions#key}. */
        public final JwtKeyResolver jwtKey = (header, token) -> {
            Map<String, Object> jwks;
            synchronized (this) { jwks = asMap(current().get("jwks")); }
            Object ks = jwks == null ? null : jwks.get("keys");
            if (jwks == null || (ks instanceof List && ((List<?>) ks).isEmpty())) throw new SpiffeError("trust_bundle_invalid", "trust bundle has no JWT authorities");
            return localJwkSet(jwks, header);
        };

        TrustBundleSource(Fetch<Object> fetch, double refreshMs, double maxStaleMs, LongSupplier now) { this.fetch = fetch; this.refreshMs = refreshMs; this.maxStaleMs = maxStaleMs; this.now = now; }

        private void refresh() {
            try {
                Object b = fetch.fetch();
                if (!usableBundle(b)) throw new SpiffeError("trust_bundle_invalid", "fetched trust bundle has no authorities");
                good = asMap(b);
                goodAt = now.getAsLong();
                lastFailure = null;
            } catch (Exception e) {
                lastFailure = e instanceof SpiffeError ? (SpiffeError) e : new SpiffeError("trust_bundle_unavailable", "trust bundle fetch failed: " + errMsg(e));
            }
        }

        private Map<String, Object> current() {
            if (good == null || now.getAsLong() - goodAt >= refreshMs) refresh();
            if (good == null || now.getAsLong() - goodAt > maxStaleMs) {
                throw lastFailure != null ? lastFailure : new SpiffeError("trust_bundle_unavailable", "no trust bundle available");
            }
            return good;
        }

        /** Authorities for {@link VerifyX509SvidOptions#roots}. Throws a {@link SpiffeError} when no usable bundle exists. */
        @SuppressWarnings("unchecked")
        public synchronized List<Object> x509Roots() {
            Object roots = current().get("x509Authorities");
            if (!(roots instanceof List) || ((List<Object>) roots).isEmpty()) throw new SpiffeError("trust_bundle_invalid", "trust bundle has no X.509 authorities");
            return new ArrayList<>((List<Object>) roots);
        }
    }

    /** Create a {@link TrustBundleSource}; {@code now} null = the system clock. */
    public static TrustBundleSource createTrustBundleSource(Fetch<Object> fetch, double refreshMs, double maxStaleMs, LongSupplier now) {
        if (fetch == null) throw new SpiffeError("trust_bundle_unavailable", "createTrustBundleSource requires `fetch`");
        if (!finitePositiveOrder(refreshMs, maxStaleMs, true)) throw new SpiffeError("trust_bundle_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)");
        return new TrustBundleSource(fetch, refreshMs, maxStaleMs, now != null ? now : System::currentTimeMillis);
    }

    /** The selection of a local JWKS (the reference's createLocalJWKSet): the one key matching the header's alg, kid, use and key_ops. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> localJwkSet(Map<String, Object> jwks, Map<String, Object> header) {
        Object keys = jwks.get("keys");
        if (!(keys instanceof List)) throw new Jose.JoseException("JSON Web Key Set malformed");
        for (Object k : (List<Object>) keys) if (!(k instanceof Map)) throw new Jose.JoseException("JSON Web Key Set malformed");
        Object alg = header.get("alg"), kid = header.get("kid");
        String a = alg instanceof String ? (String) alg : "";
        String kty = a.startsWith("RS") || a.startsWith("PS") ? "RSA" : a.startsWith("ES") ? "EC" : a.startsWith("Ed") ? "OKP" : null;
        if (kty == null) throw new Jose.JoseException("Unsupported \"alg\" value for a JSON Web Key Set");
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (Object ko : (List<Object>) keys) {
            Map<String, Object> jwk = (Map<String, Object>) ko;
            boolean c = kty.equals(jwk.get("kty"));
            if (c && kid instanceof String) c = kid.equals(jwk.get("kid"));
            if (c && jwk.get("alg") instanceof String) c = a.equals(jwk.get("alg"));
            if (c && jwk.get("use") instanceof String) c = "sig".equals(jwk.get("use"));
            if (c && jwk.get("key_ops") instanceof List) c = ((List<Object>) jwk.get("key_ops")).contains("verify");
            if (c && a.equals("EdDSA")) c = "Ed25519".equals(jwk.get("crv")) || "Ed448".equals(jwk.get("crv"));
            if (c) {
                switch (a) {
                    case "ES256": c = "P-256".equals(jwk.get("crv")); break;
                    case "ES256K": c = "secp256k1".equals(jwk.get("crv")); break;
                    case "ES384": c = "P-384".equals(jwk.get("crv")); break;
                    case "ES512": c = "P-521".equals(jwk.get("crv")); break;
                    default: break;
                }
            }
            if (c) candidates.add(jwk);
        }
        if (candidates.isEmpty()) throw new Jose.JoseException("no applicable key found in the JSON Web Key Set");
        if (candidates.size() != 1) throw new Jose.JoseException("multiple matching keys found in the JSON Web Key Set");
        Map<String, Object> jwk = candidates.get(0);
        if (jwk.get("d") != null) throw new Jose.JoseException("JSON Web Key Set members must be public keys");
        return jwk;
    }

    // ---- admission evidence --------------------------------------------------------------------------------------

    /** SPIFFE evidence for blueprint admission (a verified SVID bound to the instance key). */
    public static final class SpiffeEvidence {
        /** "x509" or "jwt". */
        public String kind;
        /** x509: PEM text or a list of PEM text / DER bytes. */
        public Object chain;
        public VerifyX509SvidOptions verifyX509;
        /** jwt: the compact token. */
        public String token;
        public VerifyJwtSvidOptions verifyJwt;
        public SvidToHolderOptions bind;
    }

    /** The admission verdict: {@code {ok, bound, identity?: {spiffe_id}, reason?}}. */
    public static final class SpiffeAdmissionEvidenceResult {
        public final boolean ok, bound;
        public final String spiffeId, reason;
        SpiffeAdmissionEvidenceResult(boolean ok, boolean bound, String spiffeId, String reason) { this.ok = ok; this.bound = bound; this.spiffeId = spiffeId; this.reason = reason; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            m.put("bound", bound);
            if (spiffeId != null) { Map<String, Object> id = new LinkedHashMap<>(); id.put("spiffe_id", spiffeId); m.put("identity", id); }
            if (reason != null) m.put("reason", reason);
            return m;
        }
    }

    /**
     * Admit a workload under its verified SPIFFE ID: verify the SVID, bind it to {@code instanceKey}, and return its identity.
     * Anything unverifiable, unbound or for a different key is {@code ok: false} with the error code as the reason ("error" when the
     * failure is not a {@link SpiffeError}).
     */
    public static SpiffeAdmissionEvidenceResult spiffeAdmissionEvidence(SpiffeEvidence e, String instanceKey) {
        try {
            Object svid = "x509".equals(e.kind) ? verifyX509Svid(e.chain, e.verifyX509) : verifyJwtSvid(e.token, e.verifyJwt);
            SpiffeHolder h = svidToHolder(svid, instanceKey, e.bind);
            if (!h.holder.equals(instanceKey)) return new SpiffeAdmissionEvidenceResult(false, false, null, "SVID is bound to a different key");
            return new SpiffeAdmissionEvidenceResult(true, true, h.spiffeId, null);
        } catch (SpiffeError err) {
            return new SpiffeAdmissionEvidenceResult(false, false, null, err.code());
        } catch (RuntimeException err) {
            return new SpiffeAdmissionEvidenceResult(false, false, null, err instanceof Jose.JoseException ? "JOSEError" : err.getClass().getSimpleName());
        }
    }
}
