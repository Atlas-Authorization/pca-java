package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Microsoft Azure Attestation (MAA): the signed MAA JWT of an Azure confidential VM (SEV-SNP "sevsnpvm" or TDX "tdxvm"),
 * verified under the token-signing x5c chain anchored in a configured MAA root, with the PCA challenge bound through the
 * report-data or runtime user-data claim. Same checks, order and reason text as the reference verifier. Classical (ES256 /
 * RS256); no network I/O: anchors are configured explicitly (no JWKS fetching or persisted key-rotation store).
 */
final class AttestMaa implements VendorImpl {
    private static final String P = "createAzureMaaVerifier: ";
    /** The TDX TCB statuses accepted when the policy does not list its own. */
    static final List<String> DEFAULT_ACCEPTED_STATUSES = List.of("UpToDate", "SWHardeningNeeded");
    /** {name, claim, hostKey} of the SEV-SNP TCB SVN claims, in reference order. */
    private static final String[][] TCB_CLAIMS = {
        {"bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"},
        {"snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"},
        {"microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"},
        {"tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"},
    };

    private final Set<String> issuers = new HashSet<>();
    private List<String> rootCertsPem = new ArrayList<>();
    private List<String> rootSpki = new ArrayList<>();
    private List<String> sevSnp;
    private List<String> tdx;
    private List<String> sevHost = new ArrayList<>();
    private List<String> tdxRtmrs = new ArrayList<>();
    private Map<String, Double> minTcb;
    private boolean allowDebug;
    private boolean runtimeUserData;
    private List<String> tdxStatuses;
    private String reportDataHash = "";
    private boolean hasSev;
    private boolean hasTdx;
    private double skew;

    private AttestMaa() {}

    /** listLen of the reference: the length of a JSON array or string, else 0. */
    static int listLen(Object v) {
        if (v instanceof List) return ((List<?>) v).size();
        if (v instanceof String) return ((String) v).length();
        return 0;
    }

    static double skewOf(Map<String, Object> cfg) {
        Double f = AttestCommon.asFinite(cfg.get("clockSkewMs"));
        return f == null ? 0 : Math.max(0, f);
    }

    private static List<String> orEmpty(List<String> l) { return l == null ? new ArrayList<>() : l; }

    static VendorImpl create(Map<String, Object> cfg) {
        Object issRaw = cfg.get("trustedIssuers");
        if (!(issRaw instanceof List) || ((List<?>) issRaw).isEmpty()) {
            throw new AttestException(P + "trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs");
        }
        AttestMaa v = new AttestMaa();
        for (Object x : (List<?>) issRaw) {
            if (!(x instanceof String) || ((String) x).isEmpty()) throw new AttestException(P + "every trusted issuer must be a non-empty URL string");
            v.issuers.add((String) x);
        }
        Map<String, Object> anch = AttestCommon.asRec(cfg.get("trustAnchors"));
        if (anch == null) anch = new LinkedHashMap<>();
        if (listLen(anch.get("rootCertsPem")) + listLen(anch.get("rootSpkiSha256")) == 0) {
            throw new AttestException(P + "trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted");
        }
        v.rootCertsPem = orEmpty(AttestCommon.asStrList(anch.get("rootCertsPem")));
        v.rootSpki = orEmpty(AttestCommon.asStrList(anch.get("rootSpkiSha256")));
        Map<String, Object> pol = AttestCommon.asRec(cfg.get("policy"));
        List<String> sev = null, tdx = null;
        if (pol != null) {
            sev = AttestCommon.asStrList(pol.get("sevSnpMeasurements"));
            tdx = AttestCommon.asStrList(pol.get("tdxMrtds"));
        }
        v.hasSev = sev != null && !sev.isEmpty();
        v.hasTdx = tdx != null && !tdx.isEmpty();
        if (pol == null || (!v.hasSev && !v.hasTdx)) {
            throw new AttestException(P + "policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)");
        }
        v.sevSnp = AttestCommon.lowerAll(orEmpty(sev));
        v.tdx = AttestCommon.lowerAll(orEmpty(tdx));
        if (pol.containsKey("sevSnpMinTcb")) {
            Map<String, Object> m = AttestCommon.asRec(pol.get("sevSnpMinTcb"));
            if (m == null) throw new AttestException(P + "policy.sevSnpMinTcb must be an object");
            v.minTcb = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : new TreeMap<>(m).entrySet()) {
                String k = e.getKey();
                boolean known = false;
                for (String[] c : TCB_CLAIMS) if (c[0].equals(k)) known = true;
                if (!known) throw new AttestException(P + "policy.sevSnpMinTcb." + k + " is not a known field (bootloader | snp | microcode | tee)");
                Double f = AttestCommon.asFinite(e.getValue());
                if (f == null || f != Math.floor(f) || f < 0) throw new AttestException(P + "policy.sevSnpMinTcb." + k + " must be a non-negative integer");
                v.minTcb.put(k, f);
            }
        }
        List<String> l = AttestCommon.asStrList(pol.get("sevSnpHostData"));
        if (l != null) v.sevHost = AttestCommon.lowerAll(l);
        l = AttestCommon.asStrList(pol.get("tdxRtmrs"));
        if (l != null) v.tdxRtmrs = AttestCommon.lowerAll(l);
        v.allowDebug = Boolean.TRUE.equals(pol.get("allowDebug"));
        v.runtimeUserData = Boolean.TRUE.equals(pol.get("runtimeUserDataBinding"));
        v.tdxStatuses = AttestCommon.asStrList(pol.get("tdxAllowedTcbStatuses"));
        if (pol.get("reportDataHash") instanceof String) v.reportDataHash = (String) pol.get("reportDataHash");
        v.skew = skewOf(cfg);
        return v;
    }

    // ------------------------------------------------------------- x5c chain

    /** A verified leaf or the failure reason. */
    static final class Leaf {
        final AttCert cert;
        final String why;

        Leaf(AttCert cert, String why) {
            this.cert = cert;
            this.why = why;
        }
    }

    private static Leaf thrown(RuntimeException e) {
        return new Leaf(null, "x5c chain verification error (fail closed): " + AttestCommon.errMsg(e));
    }

    /** verifyX5cChain: an x5c chain (base64 DER, leaf first) to a configured trust anchor. */
    Leaf verifyX5cChain(List<?> x5c, long nowMs) {
        if (x5c.isEmpty()) return new Leaf(null, "empty x5c certificate chain");
        List<AttCert> certs = new ArrayList<>();
        for (int i = 0; i < x5c.size(); i++) {
            Object e = x5c.get(i);
            if (!(e instanceof String) || ((String) e).isEmpty()) return new Leaf(null, "empty x5c entry at index " + i);
            AttCert c;
            try {
                c = AttestCert.parseCertDer(AttestCommon.nodeB64((String) e));
            } catch (RuntimeException err) {
                return new Leaf(null, "malformed x5c certificate at index " + i + ": " + AttestCommon.errMsg(err));
            }
            if (!AttestDer.derValidAtF(c.raw, nowMs, skew)) return new Leaf(null, "x5c certificate at index " + i + " is outside its validity window");
            certs.add(c);
        }
        Set<String> fingerprints = new HashSet<>();
        for (String fp : rootSpki) if (!fp.isEmpty()) fingerprints.add(fp.toLowerCase(Locale.ROOT));
        List<AttCert> roots = new ArrayList<>();
        try {
            for (String pem : rootCertsPem) {
                AttCert c = AttestCert.certFromPem(pem);
                CertKey k = AttestCert.keyOfCert(c);
                roots.add(c);
                fingerprints.add(k.spkiSha256());
            }
        } catch (RuntimeException err) {
            return thrown(err);
        }
        if (fingerprints.isEmpty() && roots.isEmpty()) return new Leaf(null, "no MAA trust anchor configured (fail closed)");
        int anchorIdx = -1;
        try {
            for (int j = 0; j < certs.size(); j++) {
                if (fingerprints.contains(AttestCert.keyOfCert(certs.get(j)).spkiSha256())) {
                    anchorIdx = j;
                    break;
                }
            }
        } catch (RuntimeException err) {
            return thrown(err);
        }
        if (anchorIdx >= 0) {
            for (int i = 0; i < anchorIdx; i++) {
                if (!AttestCert.certSigOkBy(certs.get(i), certs.get(i + 1))) return new Leaf(null, "x5c link " + i + " is not signed by the certificate above it");
            }
            return new Leaf(certs.get(0), "");
        }
        for (int i = 0; i < certs.size() - 1; i++) {
            if (!AttestCert.certSigOkBy(certs.get(i), certs.get(i + 1))) return new Leaf(null, "x5c link " + i + " is not signed by the certificate above it");
        }
        AttCert top = certs.get(certs.size() - 1);
        for (AttCert r : roots) if (AttestCert.certSigOkBy(top, r)) return new Leaf(certs.get(0), "");
        return new Leaf(null, "x5c chain does not anchor in a configured MAA trust root");
    }

    /** resolveSigningX5c: the JWKS entry matched by kid, else the header's own x5c. {chain, null} or {null, reason}. */
    static Object[] resolveSigningX5c(AttestJws.JwtParsed tok, Object jwks) {
        List<?> keys = null;
        Map<String, Object> m = AttestCommon.asRec(jwks);
        if (m != null && m.get("keys") instanceof List) keys = (List<?>) m.get("keys");
        if (keys != null && !keys.isEmpty()) {
            if (!tok.hasKid || tok.kid.isEmpty()) {
                if (keys.size() != 1) return new Object[] {null, "token has no kid and the JWKS publishes multiple keys (ambiguous)"};
                List<?> c = chainOf(keys.get(0));
                if (c != null && !c.isEmpty()) return new Object[] {c, null};
                return new Object[] {null, "JWKS key carries no x5c chain"};
            }
            for (Object k : keys) {
                Map<String, Object> rec = AttestCommon.asRec(k);
                if (rec != null && tok.kid.equals(rec.get("kid"))) {
                    List<?> c = chainOf(k);
                    if (c != null && !c.isEmpty()) return new Object[] {c, null};
                    return new Object[] {null, "JWKS key '" + tok.kid + "' carries no x5c chain"};
                }
            }
            return new Object[] {null, "no JWKS key matches the token kid '" + tok.kid + "' (untrusted signer)"};
        }
        if (tok.hasX5c && !tok.x5c.isEmpty()) return new Object[] {new ArrayList<Object>(tok.x5c), null};
        return new Object[] {null, "no signing x5c available (no JWKS and no header x5c)"};
    }

    private static List<?> chainOf(Object k) {
        Map<String, Object> rec = AttestCommon.asRec(k);
        return rec != null && rec.get("x5c") instanceof List ? (List<?>) rec.get("x5c") : null;
    }

    static String jwsSignature(AttestJws.JwtParsed tok, CertKey k, String who) {
        String[] kc = AttestJws.jwkKtyCrv(k);
        String kty = kc[0], crv = kc[1];
        switch (tok.alg) {
            case "ES256":
                if (!kty.equals("EC") || !crv.equals("P-256")) return "ES256 token but signing key is " + kty + "/" + crv + " (not EC P-256)";
                if (tok.signature.length != 64) return "ES256 signature is " + tok.signature.length + " bytes (expected 64: r‖s)";
                if (!AttestJws.jwsEs256Ok(tok.signature, tok.signingInput, k)) return "JWS ES256 signature does not verify under the " + who + " signing key";
                return "";
            case "RS256":
                if (!kty.equals("RSA")) return "RS256 token but signing key is " + kty + " (not RSA)";
                if (!AttestJws.jwsRs256Ok(tok.signature, tok.signingInput, k)) return "JWS RS256 signature does not verify under the " + who + " signing key";
                return "";
            default:
                return null; // the caller words the unsupported-alg reason
        }
    }

    static String firstString(Map<String, Object> rec, String... keys) {
        if (rec == null) return null;
        for (String k : keys) {
            Object s = rec.get(k);
            if (s instanceof String && !((String) s).isEmpty()) return (String) s;
        }
        return null;
    }

    static byte[] transformBinding(byte[] binding, String mode) {
        if ("sha256".equals(mode)) return AttestCommon.sha256Sum(binding);
        if ("sha512".equals(mode)) return AttestCommon.sha512Sum(binding);
        return binding;
    }

    private static HardwareResult fail(String r) { return HardwareResult.fail(r); }

    @Override
    public HardwareResult verify(Map<String, Object> ev, AttestationBinding expected, long nowMs) {
        Object tokRaw = ev == null ? null : ev.get("token");
        if (!(tokRaw instanceof String) || ((String) tokRaw).isEmpty()) return fail("no Azure MAA token for this action");
        AttestJws.JwtParsed tok;
        try {
            tok = AttestJws.parseJwt((String) tokRaw, "parseMaaJwt");
        } catch (AttestException e) {
            return fail("MAA token parse failed: " + e.getMessage());
        }
        if (!tok.alg.equals("ES256") && !tok.alg.equals("RS256")) return fail("unsupported JWS alg '" + tok.alg + "' (MAA uses ES256 / RS256)");
        Object[] res = resolveSigningX5c(tok, ev.get("jwks"));
        if (res[0] == null) return fail((String) res[1]);
        Leaf leaf = verifyX5cChain((List<?>) res[0], nowMs);
        if (leaf.cert == null) return fail("MAA signing chain invalid: " + leaf.why);
        CertKey k;
        try {
            k = AttestCert.keyOfCert(leaf.cert);
        } catch (RuntimeException err) {
            return fail("x5c chain verification error (fail closed): " + AttestCommon.errMsg(err));
        }
        String sigErr = jwsSignature(tok, k, "MAA");
        if (sigErr == null) sigErr = "unsupported JWS alg '" + tok.alg + "' (MAA uses ES256 / RS256)";
        if (!sigErr.isEmpty()) return fail(sigErr);

        Map<String, Object> payload = tok.payload;
        Object issRaw = payload.get("iss");
        String iss = issRaw instanceof String ? (String) issRaw : "";
        if (iss.isEmpty() || !issuers.contains(iss)) {
            return fail("token iss '" + (issRaw instanceof String ? iss : "undefined") + "' is not a configured trusted MAA instance");
        }
        double nowSec = Math.floor((double) nowMs / 1000);
        double skewSec = Math.ceil(skew / 1000);
        Double exp = AttestCommon.asFinite(payload.get("exp"));
        Double iat = AttestCommon.asFinite(payload.get("iat"));
        Double nbf = AttestCommon.asFinite(payload.get("nbf"));
        if (exp == null) return fail("token has no exp (cannot bound validity — fail closed)");
        if (nowSec - skewSec > exp) return fail("MAA token expired");
        if (nbf != null && nowSec + skewSec < nbf) return fail("MAA token not yet valid (nbf)");
        if (iat != null && nowSec + skewSec < iat) return fail("MAA token issued in the future (iat)");

        Map<String, Object> tee = payload;
        Map<String, Object> iso = AttestCommon.asRec(payload.get("x-ms-isolation-tee"));
        if (iso != null) tee = iso;
        Object isoRaw = tee.get("x-ms-attestation-type");
        if (!(isoRaw instanceof String)) isoRaw = payload.get("x-ms-attestation-type");
        String isolation = isoRaw instanceof String ? (String) isoRaw : null;
        if (isolation == null || (!isolation.equals("sevsnpvm") && !isolation.equals("tdxvm"))) {
            return fail("unexpected x-ms-attestation-type '" + (isolation == null ? "undefined" : isolation) + "' (expected sevsnpvm | tdxvm)");
        }

        if (expected == null) return fail("no expected attestation binding supplied");
        byte[] raw;
        try {
            raw = AttestCommon.attestationBindingBytes(expected);
        } catch (AttestException e) {
            return fail("binding not constructible: " + e.getMessage());
        }
        if (runtimeUserData) {
            Map<String, Object> runtime = AttestCommon.asRec(payload.get("x-ms-runtime"));
            if (runtime == null) return fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)");
            Object ud = runtime.get("user-data");
            if (!(ud instanceof String) || ((String) ud).isEmpty()) return fail("x-ms-runtime carries no user-data to bind the PCA challenge");
            byte[] got = AttestCommon.decodeClaimBytes((String) ud);
            if (got == null || !AttestCommon.timingSafeEq(got, raw)) return fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        } else {
            byte[] bindingBytes = transformBinding(raw, reportDataHash);
            String claim = isolation.equals("sevsnpvm")
                ? firstString(tee, "x-ms-sevsnpvm-reportdata")
                : firstString(tee, "tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata");
            if (claim == null) return fail("token carries no report-data claim to bind the PCA challenge");
            byte[] got = AttestCommon.decodeClaimBytes(claim);
            if (got == null) return fail("report-data claim is not decodable (hex/base64)");
            if (!AttestCommon.timingSafeEq(got, bindingBytes)) return fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        }
        return isolation.equals("sevsnpvm") ? sevSnpResult(tee) : tdxResult(tee);
    }

    private HardwareResult sevSnpResult(Map<String, Object> tee) {
        if (!hasSev) return fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)");
        String measurement = firstString(tee, "x-ms-sevsnpvm-launchmeasurement");
        if (measurement == null) return fail("sevsnpvm token carries no launch-measurement claim");
        String mHex = measurement.toLowerCase(Locale.ROOT);
        if (!sevSnp.contains(mHex)) return fail("SEV-SNP launch measurement not in policy allowlist");
        if (Boolean.TRUE.equals(tee.get("x-ms-sevsnpvm-is-debuggable")) && !allowDebug) return fail("SEV-SNP guest is debuggable (no confidentiality)");
        String hostData = firstString(tee, "x-ms-sevsnpvm-hostdata");
        if (!sevHost.isEmpty() && (hostData == null || !sevHost.contains(hostData.toLowerCase(Locale.ROOT)))) {
            return fail("SEV-SNP host-data not in policy allowlist");
        }
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "sevsnpvm");
        for (String[] c : TCB_CLAIMS) {
            Double f = AttestCommon.asFinite(tee.get(c[1]));
            boolean isSvn = f != null && f == Math.floor(f) && f >= 0;
            if (isSvn) host.put(c[2], AttestCommon.jsNumString(f));
            Double floor = minTcb == null ? null : minTcb.get(c[0]);
            if (floor == null) continue;
            if (!isSvn) return fail("SEV-SNP " + c[0] + " SVN claim '" + c[1] + "' is missing or not a non-negative integer (policy requires a minimum)");
            if (f < floor) return fail("SEV-SNP " + c[0] + " SVN " + AttestCommon.jsNumString(f) + " is below the policy minimum " + AttestCommon.jsNumString(floor));
        }
        if (hostData != null) host.put("host_data", hostData.toLowerCase(Locale.ROOT));
        return HardwareResult.ok(true, HardwareResult.newMeasured(mHex, ""), host);
    }

    private HardwareResult tdxResult(Map<String, Object> tee) {
        if (!hasTdx) return fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)");
        String mrtd = firstString(tee, "tdx_mrtd", "x-ms-tdx-mrtd");
        if (mrtd == null) return fail("tdxvm token carries no MRTD claim");
        String mrtdHex = mrtd.toLowerCase(Locale.ROOT);
        if (!tdx.contains(mrtdHex)) return fail("TDX MRTD not in policy allowlist");
        boolean tdDebug = Boolean.TRUE.equals(tee.get("tdx_td_attributes_debug"));
        Object dbg = tee.get("dbgstat");
        if (!allowDebug && (tdDebug || (dbg instanceof String && !dbg.equals("disabled")))) return fail("TDX guest is debuggable (no confidentiality)");
        Object st = tee.get("attester_tcb_status");
        String tcbStatus = st instanceof String ? (String) st : null;
        if (tcbStatus != null) {
            List<String> accepted = tdxStatuses != null ? tdxStatuses : DEFAULT_ACCEPTED_STATUSES;
            if (!accepted.contains(tcbStatus)) return fail("TDX platform TCB status '" + tcbStatus + "' is not accepted by policy");
        }
        String rtmr0 = firstString(tee, "tdx_rtmr0", "x-ms-tdx-rtmr0");
        if (!tdxRtmrs.isEmpty() && (rtmr0 == null || !tdxRtmrs.contains(rtmr0.toLowerCase(Locale.ROOT)))) return fail("TDX RTMR0 not in policy allowlist");
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "tdxvm");
        if (tcbStatus != null && !tcbStatus.isEmpty()) host.put("tcb_status", tcbStatus);
        if (rtmr0 != null) host.put("rtmr0", rtmr0.toLowerCase(Locale.ROOT));
        return HardwareResult.ok(true, HardwareResult.newMeasured(mrtdHex, ""), host);
    }
}
