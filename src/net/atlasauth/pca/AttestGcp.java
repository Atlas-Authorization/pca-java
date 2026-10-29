package net.atlasauth.pca;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Google Cloud Confidential Space: the attestation token (RS256, ES256 defensively) verified under a signing key anchored
 * in the configured trust anchors (a pinned JWKS, SPKI pins or an x5c chain to a configured root), with iss / time window,
 * the Confidential Space claims, the eat_nonce binding and the workload image-digest allowlist. Same checks, order and
 * reason text as the reference verifier. Classical; no network I/O.
 */
final class AttestGcp implements VendorImpl {
    private static final String P = "createGcpConfidentialSpaceVerifier: ";
    private static final Pattern PEM_BLOCK = Pattern.compile("-----BEGIN ([^-\\r\\n]+)-----(.*?)-----END \\1-----", Pattern.DOTALL);

    private final Set<String> issuers = new HashSet<>();
    /** The pinned JWKS keys; an entry is null when the JWKS member was not an object. */
    private final List<Map<String, Object>> trustedKeys = new ArrayList<>();
    private final Set<String> spkiPins = new HashSet<>();
    private List<String> rootCertsPem = new ArrayList<>();
    private final Set<String> images = new HashSet<>();
    private Set<String> teeTypes;
    private String swName = "CONFIDENTIAL_SPACE";
    private Set<String> swVersions;
    private boolean allowDebug;
    private String nonceHash = "";
    private double skew;

    private AttestGcp() {}

    /** The string members of a JSON array (empty when v is not an array). */
    private static List<String> anyStrings(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List) for (Object x : (List<?>) v) if (x instanceof String) out.add((String) x);
        return out;
    }

    /** The members of a JSON array as records (null for a non-object member). */
    private static List<Map<String, Object>> mapList(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List) for (Object x : (List<?>) v) out.add(AttestCommon.asRec(x));
        return out;
    }

    static VendorImpl create(Map<String, Object> cfg) {
        Object issRaw = cfg.get("trustedIssuers");
        if (!(issRaw instanceof List) || ((List<?>) issRaw).isEmpty()) {
            throw new AttestException(P + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs");
        }
        AttestGcp v = new AttestGcp();
        for (Object x : (List<?>) issRaw) {
            if (!(x instanceof String) || ((String) x).isEmpty()) throw new AttestException(P + "every trusted issuer must be a non-empty URL string");
            v.issuers.add((String) x);
        }
        Map<String, Object> anch = AttestCommon.asRec(cfg.get("trustAnchors"));
        if (anch == null) anch = new LinkedHashMap<>();
        Map<String, Object> tj = AttestCommon.asRec(anch.get("trustedJwks"));
        if (tj != null && tj.get("keys") instanceof List) v.trustedKeys.addAll(mapList(tj.get("keys")));
        int spki = AttestMaa.listLen(anch.get("trustedKeySpki"));
        for (String s : anyStrings(anch.get("trustedKeySpki"))) v.spkiPins.add(s.toLowerCase(Locale.ROOT));
        List<String> roots = AttestCommon.asStrList(anch.get("rootCertsPem"));
        if (roots != null) v.rootCertsPem = roots;
        if (v.trustedKeys.size() + spki + AttestMaa.listLen(anch.get("rootCertsPem")) == 0) {
            throw new AttestException(P + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted");
        }
        Map<String, Object> pol = AttestCommon.asRec(cfg.get("policy"));
        if (pol == null) pol = new LinkedHashMap<>();
        List<String> digests = AttestCommon.asStrList(pol.get("imageDigests"));
        if (digests == null || digests.isEmpty()) throw new AttestException(P + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)");
        if (pol.get("allowedTeeTypes") instanceof List) {
            List<?> arr = (List<?>) pol.get("allowedTeeTypes");
            if (arr.isEmpty()) throw new AttestException(P + "policy.allowedTeeTypes, when present, must be non-empty");
            v.teeTypes = new HashSet<>(anyStrings(arr));
        }
        v.skew = AttestMaa.skewOf(cfg);
        for (String d : digests) v.images.add(d.toLowerCase(Locale.ROOT));
        if (pol.get("expectedSwName") instanceof String) v.swName = (String) pol.get("expectedSwName");
        if (pol.get("allowedSwVersions") instanceof List) v.swVersions = new HashSet<>(anyStrings(pol.get("allowedSwVersions")));
        v.allowDebug = Boolean.TRUE.equals(pol.get("allowDebug"));
        if (pol.get("nonceHash") instanceof String) v.nonceHash = (String) pol.get("nonceHash");
        return v;
    }

    /** A resolved key, or the failure reason. */
    static final class Key {
        final CertKey key;
        final String why;

        Key(CertKey key, String why) {
            this.key = key;
            this.why = why;
        }
    }

    private static Key unusable(RuntimeException e) { return new Key(null, "JWKS key is not a usable public key: " + AttestCommon.errMsg(e)); }

    /** jwkKey: a public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain). */
    static Key jwkKey(Map<String, Object> jwk) {
        if (jwk == null) jwk = new LinkedHashMap<>();
        Object n = jwk.get("n"), e = jwk.get("e");
        if (n instanceof String && e instanceof String) {
            try {
                return new Key(AttestJws.jwkRsaKey((String) n, (String) e), "");
            } catch (RuntimeException err) {
                return unusable(err);
            }
        }
        Object crv = jwk.get("crv"), x = jwk.get("x"), y = jwk.get("y");
        if ("EC".equals(jwk.get("kty")) && crv instanceof String && x instanceof String && y instanceof String) {
            try {
                return new Key(AttestJws.jwkEcKey((String) crv, (String) x, (String) y), "");
            } catch (RuntimeException err) {
                return unusable(err);
            }
        }
        Object x5c = jwk.get("x5c");
        if (x5c instanceof List && !((List<?>) x5c).isEmpty() && ((List<?>) x5c).get(0) instanceof String) {
            try {
                AttCert c = AttestCert.parseCertDer(AttestCommon.nodeB64((String) ((List<?>) x5c).get(0)));
                return new Key(AttestCert.keyOfCert(c), "");
            } catch (RuntimeException err) {
                return unusable(err);
            }
        }
        return new Key(null, "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate");
    }

    /** verifyJwkX5cChain: a JWK x5c chain to a configured SPKI pin or root certificate; "" when it anchors. */
    String verifyJwkX5cChain(List<?> x5c, long nowMs) {
        if (x5c.isEmpty()) return "empty x5c certificate chain";
        List<AttCert> certs = new ArrayList<>();
        for (int i = 0; i < x5c.size(); i++) {
            Object e = x5c.get(i);
            if (!(e instanceof String) || ((String) e).isEmpty()) return "empty x5c entry at index " + i;
            AttCert c;
            try {
                c = AttestCert.parseCertDer(AttestCommon.nodeB64((String) e));
            } catch (RuntimeException err) {
                return "malformed x5c certificate at index " + i + ": " + AttestCommon.errMsg(err);
            }
            if (!AttestDer.derValidAtF(c.raw, nowMs, skew)) return "x5c certificate at index " + i + " is outside its validity window";
            certs.add(c);
        }
        for (int i = 0; i < certs.size() - 1; i++) {
            if (!AttestCert.certSigOkBy(certs.get(i), certs.get(i + 1))) return "x5c link " + i + " is not signed by the certificate above it";
        }
        for (AttCert c : certs) {
            try {
                if (spkiPins.contains(AttestCert.keyOfCert(c).spkiSha256())) return "";
            } catch (RuntimeException ignored) {
                // a certificate without a usable key matches no pin
            }
        }
        AttCert top = certs.get(certs.size() - 1);
        for (String pemText : rootCertsPem) {
            CertKey rk = rootKeyFromPem(pemText);
            if (rk != null && AttestCert.certSigOk(top, rk)) return "";
        }
        return "x5c chain does not anchor in a configured GCP trust root";
    }

    /** A trust root given as a certificate or as a bare public key (the first PEM block); null when neither. */
    static CertKey rootKeyFromPem(String pemText) {
        try {
            return AttestCert.keyOfCert(AttestCert.certFromPem(pemText));
        } catch (RuntimeException ignored) {
            // not a certificate: try a bare SubjectPublicKeyInfo
        }
        Matcher m = PEM_BLOCK.matcher(pemText);
        if (!m.find()) return null;
        byte[] der;
        try {
            der = AttestCommon.base64StdDecode(m.group(2).replaceAll("\\s", ""));
        } catch (RuntimeException e) {
            return null;
        }
        for (String alg : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                PublicKey pub = KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
                return CertKey.of(pub, der);
            } catch (java.security.GeneralSecurityException | RuntimeException ignored) {
                // try the next key type
            }
        }
        return null;
    }

    /** pickJwk: the key the token was signed under, by kid if present, else the sole key; null when none. */
    private static Map<String, Object> pickJwk(AttestJws.JwtParsed tok, List<Map<String, Object>> keys) {
        if (tok.hasKid && !tok.kid.isEmpty()) {
            for (Map<String, Object> k : keys) if (k != null && tok.kid.equals(k.get("kid"))) return k;
            return null;
        }
        return keys.size() == 1 ? keys.get(0) : null;
    }

    /** signingKey: the token's signing key, confirmed anchored. */
    Key signingKey(AttestJws.JwtParsed tok, Object evidenceJwks, long nowMs) {
        List<Map<String, Object>> evKeys = new ArrayList<>();
        Map<String, Object> m = AttestCommon.asRec(evidenceJwks);
        if (m != null) evKeys = mapList(m.get("keys"));
        Map<String, Object> jwk = pickJwk(tok, evKeys);
        boolean fromTrusted = false;
        if (jwk == null) {
            jwk = pickJwk(tok, trustedKeys);
            fromTrusted = jwk != null;
        }
        boolean hasKid = tok.hasKid && !tok.kid.isEmpty();
        if (jwk == null && tok.hasX5c && !tok.x5c.isEmpty()) {
            jwk = new LinkedHashMap<>();
            jwk.put("x5c", new ArrayList<Object>(tok.x5c));
        }
        if (jwk == null) {
            if (hasKid) return new Key(null, "no JWKS key matches the token kid '" + tok.kid + "' (untrusted signer)");
            return new Key(null, "no kid on the token and no unambiguous single signing key available");
        }
        Key k = jwkKey(jwk);
        if (!k.why.isEmpty()) return k;
        String spki = k.key.spkiSha256();
        if (fromTrusted || spkiPins.contains(spki)) return k;
        for (Map<String, Object> tk : trustedKeys) {
            Key tb = jwkKey(tk);
            if (tb.why.isEmpty() && tb.key.spkiSha256().equals(spki)) return k;
        }
        Object x5c = jwk.get("x5c");
        if (x5c instanceof List && !((List<?>) x5c).isEmpty() && (!rootCertsPem.isEmpty() || !spkiPins.isEmpty())) {
            String chainErr = verifyJwkX5cChain((List<?>) x5c, nowMs);
            if (chainErr.isEmpty()) return k;
            return new Key(null, "signing key not trusted: " + chainErr);
        }
        return new Key(null, "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)");
    }

    /** gcpTeeType: the isolation family of a Confidential Space hwmodel ("" when unrecognised). */
    static String gcpTeeType(String hwmodel) {
        switch (hwmodel) {
            case "GCP_AMD_SEV":
            case "GCP_AMD_SEV_SNP":
            case "GCP_AMD_SEV_ES":
                return "sev-snp";
            case "GCP_INTEL_TDX":
                return "tdx";
            default:
                break;
        }
        String up = hwmodel.toUpperCase(Locale.ROOT);
        if (up.startsWith("GCP_AMD_SEV")) return "sev-snp";
        if (up.startsWith("GCP_INTEL_TDX")) return "tdx";
        return "";
    }

    private static List<String> nonceCandidates(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof String) {
            if (!((String) v).isEmpty()) out.add((String) v);
            return out;
        }
        List<String> arr = AttestCommon.asStrList(v);
        if (arr == null) return out;
        for (String s : arr) if (!s.isEmpty()) out.add(s);
        return out;
    }

    private static HardwareResult fail(String r) { return HardwareResult.fail(r); }

    private static String shown(Object v) { return v instanceof String ? (String) v : "undefined"; }

    @Override
    public HardwareResult verify(Map<String, Object> ev, AttestationBinding expected, long nowMs) {
        Object tokRaw = ev == null ? null : ev.get("token");
        if (!(tokRaw instanceof String) || ((String) tokRaw).isEmpty()) return fail("no GCP Confidential Space token for this action");
        AttestJws.JwtParsed tok;
        try {
            tok = AttestJws.parseJwt((String) tokRaw, "parseGcpCsJwt");
        } catch (AttestException e) {
            return fail("Confidential Space token parse failed: " + e.getMessage());
        }
        String unsupported = "unsupported JWS alg '" + tok.alg + "' (Confidential Space uses RS256)";
        if (!tok.alg.equals("RS256") && !tok.alg.equals("ES256")) return fail(unsupported);
        Key key = signingKey(tok, ev.get("jwks"), nowMs);
        if (!key.why.isEmpty()) return fail("Confidential Space signing key invalid: " + key.why);
        String sigErr = AttestMaa.jwsSignature(tok, key.key, "Confidential Space");
        if (sigErr == null) sigErr = unsupported;
        if (!sigErr.isEmpty()) return fail(sigErr);

        Map<String, Object> payload = tok.payload;
        Object issRaw = payload.get("iss");
        String iss = issRaw instanceof String ? (String) issRaw : "";
        if (iss.isEmpty() || !issuers.contains(iss)) {
            return fail("token iss '" + shown(issRaw) + "' is not a configured trusted Google attestation issuer");
        }
        double nowSec = Math.floor((double) nowMs / 1000);
        double skewSec = Math.ceil(skew / 1000);
        Double exp = AttestCommon.asFinite(payload.get("exp"));
        Double iat = AttestCommon.asFinite(payload.get("iat"));
        Double nbf = AttestCommon.asFinite(payload.get("nbf"));
        if (exp == null) return fail("token has no exp (cannot bound validity — fail closed)");
        if (nowSec - skewSec > exp) return fail("Confidential Space token expired");
        if (nbf != null && nowSec + skewSec < nbf) return fail("Confidential Space token not yet valid (nbf)");
        if (iat != null && nowSec + skewSec < iat) return fail("Confidential Space token issued in the future (iat)");

        Map<String, Object> submods = AttestCommon.asRec(payload.get("submods"));
        if (submods == null || AttestCommon.asRec(submods.get("confidential_space")) == null) {
            return fail("token carries no submods.confidential_space (not a Confidential Space token)");
        }
        Object sw = payload.get("swname");
        if (!(sw instanceof String) || !sw.equals(swName)) return fail("unexpected swname '" + shown(sw) + "' (expected '" + swName + "')");
        if (swVersions != null) {
            List<String> versions = AttestCommon.asStrList(payload.get("swversion"));
            if (versions == null) {
                versions = new ArrayList<>();
                Object s = payload.get("swversion");
                if (s instanceof String && !((String) s).isEmpty()) versions.add((String) s);
            }
            boolean found = false;
            for (String x : versions) if (swVersions.contains(x)) found = true;
            if (!found) return fail("swversion not in policy allowlist");
        }
        Object hw = payload.get("hwmodel");
        String hwmodel = hw instanceof String ? (String) hw : "";
        if (hwmodel.isEmpty()) return fail("token carries no hwmodel claim");
        String teeType = gcpTeeType(hwmodel);
        if (teeType.isEmpty()) return fail("unrecognized hwmodel '" + hwmodel + "' (not a known AMD SEV-SNP / Intel TDX model)");
        if (teeTypes != null && !teeTypes.contains(teeType)) {
            return fail("attestation type '" + teeType + "' (hwmodel '" + hwmodel + "') is not in the policy allowlist");
        }
        Object dbg = payload.get("dbgstat");
        if (!allowDebug && !"disabled-since-boot".equals(dbg)) {
            return fail("token dbgstat '" + shown(dbg) + "' is not 'disabled-since-boot' (debug build — no confidentiality)");
        }
        if (expected == null) return fail("no expected attestation binding supplied");
        byte[] raw;
        try {
            raw = AttestCommon.attestationBindingBytes(expected);
        } catch (AttestException e) {
            return fail("binding not constructible: " + e.getMessage());
        }
        byte[] bindingBytes = AttestMaa.transformBinding(raw, nonceHash);
        List<String> candidates = nonceCandidates(payload.get("eat_nonce"));
        if (candidates.isEmpty()) return fail("token carries no eat_nonce claim to bind the PCA challenge");
        boolean bound = false;
        for (String c : candidates) {
            byte[] b = AttestCommon.decodeClaimBytes(c);
            if (b != null && AttestCommon.timingSafeEq(b, bindingBytes)) {
                bound = true;
                break;
            }
        }
        if (!bound) return fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        Map<String, Object> container = AttestCommon.asRec(submods.get("container"));
        String imageDigest = AttestMaa.firstString(container, "image_digest");
        if (imageDigest == null) return fail("token carries no submods.container.image_digest to measure the workload");
        if (!images.contains(imageDigest.toLowerCase(Locale.ROOT))) return fail("workload image_digest not in policy allowlist");
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", teeType);
        host.put("hwmodel", hwmodel);
        host.put("image_digest", imageDigest);
        String ref = AttestMaa.firstString(container, "image_reference");
        if (ref != null) host.put("image_reference", ref);
        return HardwareResult.ok(true, HardwareResult.newMeasured(imageDigest, ""), host);
    }
}
