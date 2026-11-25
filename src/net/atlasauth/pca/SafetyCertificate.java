package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The safety certificate: a guardian-signed, machine-readable statement of the risk-budget bound a grant's signed parameters imply.
 * Between two consecutive human co-signs the total risk of autonomous actions is at most {@code bMax / kappa}; that is arithmetic over
 * the parameters, and the certificate says so in its statement. It is NOT a claim that the agent or the system is safe.
 * {@link #verifySafetyCertificate} recomputes the bound from the certificate's own parameters and refuses any mismatch, so a signer
 * cannot state a bound its parameters do not give.
 *
 * <p>Values are decoded JSON. A post-quantum or hybrid certificate verifies only under a PQ key the VERIFIER pins for the guardian
 * ({@code pqPins}); the reference's legacy option that trusts the certificate's own PQ key is not offered, as everywhere in this SDK.
 */
public final class SafetyCertificate {
    private SafetyCertificate() {}

    public static final String SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\0";
    public static final int SAFETY_CERT_VERSION = 1;
    public static final String SAFETY_CERT_SCOPE = "risk-budget-bound";
    /** The most check rows a certificate may carry. */
    public static final int MAX_SAFETY_CHECKS = 64;
    private static final int MAX_CHECK_ID = 64;
    private static final int MAX_EVIDENCE_URL = 2048;
    /** The largest encoded certificate {@link #decodeSafetyCertificate} reads, in UTF-8 bytes. */
    private static final int MAX_JSON_BYTES = 1 << 20;
    private static final String[] WEIGHTS_FIRST = {"bMax", "kappa", "theta1", "theta2", "lambda", "rho"};

    private static Map<String, Object> rec(Object x) { return StoreJs.map(x); }

    /** The members of a value the reference reads as an object: a list is one with none of the named members. */
    private static Map<String, Object> members(Object x) { return x instanceof Map ? rec(x) : x instanceof List ? new LinkedHashMap<>() : null; }

    private static String urlProblem(String ref) {
        if (ref.length() > MAX_EVIDENCE_URL) return "long";
        try {
            WhatwgUrl u = WhatwgUrl.parse(ref);
            return "https:".equals(u.protocol()) && u.username().isEmpty() && u.password().isEmpty() ? null : "not plain https";
        } catch (RuntimeException e) {
            return "not a URL";
        }
    }

    /**
     * Validate check rows {@code [{id, status, evidence: {kind, ref}, at}]}; the reason, or null when valid. At most
     * {@link #MAX_SAFETY_CHECKS} rows, unique ids of 1..64 characters, a status of {@code passed}, {@code failed} or {@code not_run},
     * a natural time, and evidence that is a plain https URL (no credentials, at most 2048 characters) or 64 lowercase hex digits.
     */
    public static String validateSafetyChecks(Object checks) {
        if (!(checks instanceof List)) return "checks must be an array";
        List<?> list = (List<?>) checks;
        if (list.size() > MAX_SAFETY_CHECKS) return "more than " + MAX_SAFETY_CHECKS + " checks";
        Set<String> seen = new HashSet<>();
        for (Object c : list) {
            Map<String, Object> k = members(c);
            if (k == null) return "check is not an object";
            if (!(k.get("id") instanceof String) || ((String) k.get("id")).isEmpty() || ((String) k.get("id")).length() > MAX_CHECK_ID) return "check id must be a 1..64 char string";
            String id = (String) k.get("id");
            if (!seen.add(id)) return "duplicate check id '" + id + "'";
            Object status = k.get("status");
            if (!"passed".equals(status) && !"failed".equals(status) && !"not_run".equals(status)) return "check '" + id + "' has an invalid status";
            if (!IntentJs.isNonNeg(k.get("at"))) return "check '" + id + "' has an invalid time";
            Map<String, Object> e = members(k.get("evidence"));
            if (e == null || !(e.get("ref") instanceof String)) return "check '" + id + "' has no evidence link";
            String ref = (String) e.get("ref");
            if ("sha256".equals(e.get("kind"))) {
                if (!ref.matches("[0-9a-f]{64}")) return "check '" + id + "' evidence digest is not 64 lowercase hex";
            } else if ("url".equals(e.get("kind"))) {
                if (urlProblem(ref) != null) return "check '" + id + "' evidence URL must be a plain https URL";
            } else {
                return "check '" + id + "' has an invalid evidence kind";
            }
        }
        return null;
    }

    /** The bound: {@code max(0, bMax) / kappa}, and 0 when {@code kappa} is not above 0. */
    public static double safetyCertificateBound(double bMax, double kappa) { return kappa > 0 ? Math.max(0, bMax) / kappa : 0; }

    /** The fixed, signed statement for a bound (the number as JavaScript prints it). It states only the arithmetic consequence. */
    public static String safetyCertificateStatement(double bound) {
        return "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ "
            + AttestCommon.jsNumString(bound) + " (= B_max / κ). This is not a claim that the agent or the system is safe.";
    }

    /** The exact bytes the guardian signs: the domain prefix, then the canonical claim (the certificate without {@code sig} / {@code pq_sig}). Throws on a non-finite number. */
    public static byte[] safetyCertificateMessage(Map<String, Object> certOrClaim) {
        Map<String, Object> claim = new LinkedHashMap<>(certOrClaim);
        claim.remove("sig");
        claim.remove("pq_sig");
        return Pca.concat(SAFETY_CERT_DOMAIN.getBytes(StandardCharsets.UTF_8), Json.canonicalize(IntentJs.normalize(claim)).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Issue a safety certificate for a signed risk policy {@code {weights, theta1, theta2, kappa, lambda, rho, bMax}}, signed by the
     * guardian's Ed25519 seed (and, for a post-quantum or hybrid {@code suite}, its PQ key). {@code opts} may carry {@code grantRef},
     * {@code instance}, {@code checks} and {@code issuedAt} (milliseconds; the current time when absent); it may be null. Throws on a
     * malformed policy, invalid checks, an unknown suite, or a value with no canonical form.
     */
    public static Map<String, Object> issueSafetyCertificate(Object policy, byte[] guardianSecret, Map<String, Object> opts, Pq.SignerSuiteOpts suite) {
        String bad = Authorize.validateRiskPolicy(policy);
        if (bad != null) throw new IllegalArgumentException("issueSafetyCertificate: " + bad);
        String alg = suite == null ? null : suite.alg;
        if (alg != null && !Pq.isKnownSigAlg(alg)) throw new IllegalArgumentException("issueSafetyCertificate: unknown signature alg '" + alg + "'");
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        if (o.containsKey("checks")) {
            String badChecks = validateSafetyChecks(o.get("checks"));
            if (badChecks != null) throw new IllegalArgumentException("issueSafetyCertificate: " + badChecks);
        }
        Map<String, Object> p = members(policy);
        double bound = safetyCertificateBound(IntentJs.num(p.get("bMax")), IntentJs.num(p.get("kappa")));
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("v", IntentJs.ofLong(SAFETY_CERT_VERSION));
        claim.put("statement", safetyCertificateStatement(bound));
        claim.put("scope", SAFETY_CERT_SCOPE);
        if (o.containsKey("checks")) {
            List<Object> rows = new ArrayList<>();
            for (Object c : (List<?>) o.get("checks")) { // validated: every row is an object with object evidence
                Map<String, Object> k = rec(c), e = rec(k.get("evidence"));
                Map<String, Object> ev = new LinkedHashMap<>();
                if (e.containsKey("kind")) ev.put("kind", e.get("kind"));
                ev.put("ref", e.get("ref"));
                rows.add(Issue.obj("id", k.get("id"), "status", k.get("status"), "evidence", ev, "at", k.get("at")));
            }
            claim.put("checks", rows);
        }
        Map<String, Object> params = new LinkedHashMap<>();
        for (String k : WEIGHTS_FIRST) params.put(k, p.get(k));
        params.put("weights", new LinkedHashMap<>(members(p.get("weights"))));
        claim.put("params", params);
        claim.put("bound", StoreJs.num(bound));
        claim.put("blastRadiusPerCheckpoint", StoreJs.num(bound));
        if (o.containsKey("grantRef")) claim.put("grant_ref", o.get("grantRef"));
        if (o.containsKey("instance")) claim.put("instance", o.get("instance"));
        claim.put("issued_at", o.get("issuedAt") != null ? o.get("issuedAt") : IntentJs.ofLong(System.currentTimeMillis()));
        claim.put("guardian", Keys.edFromSeed(guardianSecret).id());
        Pq.SuiteSecretKeys keys = Pq.suiteKeysOf(guardianSecret, suite);
        String pqPk = Pq.suitePqPublicKey(alg, keys);
        Map<String, Object> signed = IntentJs.bindSuiteFields(claim, alg, alg != null, pqPk, pqPk != null);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, keys, safetyCertificateMessage(signed));
        Map<String, Object> cert = new LinkedHashMap<>(signed);
        cert.put("sig", f.sig);
        if (f.alg != null) cert.put("alg", f.alg);
        if (f.pqPk != null) cert.put("pq_pk", f.pqPk);
        if (f.pqSig != null) cert.put("pq_sig", f.pqSig);
        return cert;
    }

    private static Map<String, Object> no(String reason, Double recomputed) {
        Map<String, Object> m = Issue.obj("ok", false, "reason", reason);
        if (recomputed != null) m.put("recomputedBound", StoreJs.num(recomputed));
        return m;
    }

    /** {@link #verifySafetyCertificate(Object, Map)} with no options. */
    public static Map<String, Object> verifySafetyCertificate(Object cert) { return verifySafetyCertificate(cert, null); }

    /**
     * Verify a safety certificate, in this order: its shape and scope; its check rows; its parameters; that the stated bound and the
     * per-checkpoint blast radius EQUAL the bound recomputed from the parameters; the pinned {@code guardian}; the suite and the
     * guardian's signature ({@code pqPins} is what admits a post-quantum or hybrid certificate); with {@code maxAgeMs}, that it is not
     * issued in the future nor older than that at {@code now} (the current time when absent); every id of {@code requireChecks} is
     * present and passed. Returns {@code {ok:true, recomputedBound}} or {@code {ok:false, reason, recomputedBound?}}; never throws.
     */
    public static Map<String, Object> verifySafetyCertificate(Object certValue, Map<String, Object> options) {
        try {
            Map<String, Object> o = options == null ? new LinkedHashMap<>() : options;
            Map<String, Object> cert = members(certValue);
            Double v = cert == null ? null : IntentJs.num(cert.get("v"));
            if (v == null || v != SAFETY_CERT_VERSION) return no("malformed certificate", null);
            if (!(cert.get("sig") instanceof String) || !(cert.get("guardian") instanceof String)) return no("missing guardian/signature", null);
            if (!SAFETY_CERT_SCOPE.equals(cert.get("scope"))) return no("unknown scope", null);
            if (cert.containsKey("checks")) {
                String badChecks = validateSafetyChecks(cert.get("checks"));
                if (badChecks != null) return no("invalid checks: " + badChecks, null);
            }
            Object params = cert.get("params") instanceof Map ? cert.get("params") : new LinkedHashMap<String, Object>();
            String bad = Authorize.validateRiskPolicy(params);
            if (bad != null) return no("invalid parameters: " + bad, null);

            double recomputed = safetyCertificateBound(IntentJs.num(rec(params).get("bMax")), IntentJs.num(rec(params).get("kappa")));
            if (!IntentJs.isFinite(cert.get("bound")) || IntentJs.num(cert.get("bound")) != recomputed) {
                return no("stated bound does not equal B_max/κ recomputed from the parameters", recomputed);
            }
            Double blast = IntentJs.num(cert.get("blastRadiusPerCheckpoint"));
            if (blast == null || blast != recomputed) return no("blastRadiusPerCheckpoint does not equal the recomputed bound", recomputed);
            String guardian = (String) cert.get("guardian");
            if (o.containsKey("guardian") && !guardian.equals(o.get("guardian"))) return no("guardian key is not the pinned key", recomputed);
            if (cert.containsKey("alg") && !Pq.isKnownSigAlg(cert.get("alg"))) return no("unknown signature alg", recomputed);
            byte[] msg = safetyCertificateMessage(cert);
            if (!IntentJs.verifyPinnedSuite(cert.get("alg"), cert.containsKey("alg"), guardian, cert.get("pq_pk"), msg, cert.get("sig"), cert.get("pq_sig"), rec(o.get("pqPins")))) {
                return no("guardian signature does not verify", recomputed);
            }
            if (o.containsKey("maxAgeMs")) {
                Object now = o.get("now") != null ? o.get("now") : IntentJs.ofLong(System.currentTimeMillis());
                if (!IntentJs.isFinite(o.get("maxAgeMs")) || !IntentJs.isFinite(now) || !IntentJs.isFinite(cert.get("issued_at"))) return no("invalid age policy or issue time", recomputed);
                double issued = IntentJs.num(cert.get("issued_at")), at = IntentJs.num(now);
                if (issued > at) return no("certificate is issued in the future", recomputed);
                if (at - issued > IntentJs.num(o.get("maxAgeMs"))) return no("certificate is older than maxAgeMs", recomputed);
            }
            Object required = o.get("requireChecks");
            if (required != null && !(required instanceof List)) return no("malformed certificate: requireChecks is not a list", null);
            if (required != null) {
                for (Object id : (List<?>) required) {
                    Map<String, Object> found = null;
                    if (cert.get("checks") instanceof List) for (Object c : (List<?>) cert.get("checks")) if (found == null && id instanceof String && id.equals(rec(c).get("id"))) found = rec(c);
                    if (found == null) return no("required check '" + IntentRevocation.jsText(id, true) + "' is not present", recomputed);
                    if (!"passed".equals(found.get("status"))) return no("required check '" + id + "' is " + found.get("status"), recomputed);
                }
            }
            return Issue.obj("ok", true, "recomputedBound", StoreJs.num(recomputed));
        } catch (RuntimeException e) {
            return no("malformed certificate: " + e.getMessage(), null);
        }
    }

    /** The canonical JSON text of a certificate (for transport and storage). Throws on a non-finite number. */
    public static String encodeSafetyCertificate(Map<String, Object> cert) { return Json.canonicalize(IntentJs.normalize(cert)); }

    /**
     * Read a certificate from JSON text: the decoded object when it has the certificate's version, a string {@code sig} and
     * {@code guardian} and object {@code params}; null for anything else (never a throw). It does NOT verify: call
     * {@link #verifySafetyCertificate} on the result.
     */
    public static Map<String, Object> decodeSafetyCertificate(Object text) {
        try {
            if (!(text instanceof String) || Json.utf8((String) text).length > MAX_JSON_BYTES) return null;
            Map<String, Object> v = rec(Json.parseLenient((String) text));
            Double ver = v == null ? null : IntentJs.num(v.get("v"));
            if (ver == null || ver != SAFETY_CERT_VERSION || !(v.get("sig") instanceof String) || !(v.get("guardian") instanceof String)) return null;
            return v.get("params") instanceof Map || v.get("params") instanceof List ? v : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** {@link #safetyCertificateForCompliance(Object, Map)} with no options. */
    public static Map<String, Object> safetyCertificateForCompliance(Object cert) { return safetyCertificateForCompliance(cert, null); }

    /**
     * The compliance evidence row of a certificate that VERIFIES under {@code options}: {@code {control, guardian, issued_at, bound,
     * checks: [{id, status, evidence}]}} with the check rows in their order (a digest as {@code sha256:<hex>}, a URL as it is); null
     * when it does not verify.
     */
    public static Map<String, Object> safetyCertificateForCompliance(Object certValue, Map<String, Object> options) {
        if (!Boolean.TRUE.equals(verifySafetyCertificate(certValue, options).get("ok"))) return null;
        Map<String, Object> cert = rec(certValue);
        List<Object> rows = new ArrayList<>();
        if (cert.get("checks") instanceof List) {
            for (Object c : (List<?>) cert.get("checks")) {
                Map<String, Object> k = rec(c), e = rec(k.get("evidence"));
                rows.add(Issue.obj("id", k.get("id"), "status", k.get("status"), "evidence", "sha256".equals(e.get("kind")) ? "sha256:" + e.get("ref") : e.get("ref")));
            }
        }
        return Issue.obj("control", SAFETY_CERT_SCOPE, "guardian", cert.get("guardian"), "issued_at", cert.get("issued_at"), "bound", cert.get("bound"), "checks", rows);
    }
}
