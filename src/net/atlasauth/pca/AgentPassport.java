package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The agent passport (the reference's {@code passport.ts}): a content-addressed identity statement of an agent (model, weights, prompt,
 * tools, runtime, operator), its match against a grant's {@code agent_binding}, an in-memory registry, a trust score, and the SIGNED passport
 * a verifier checks: the issuer signature, the validity window, the subject, revocation and, for a hardware-rooted passport, a fresh attestation
 * of the same identity bound to the passport. Passports, bindings and results are decoded JSON (maps and lists). {@link Passport#verify} is the
 * typed verifier the request pipeline uses; this class is the full reference surface.
 */
public final class AgentPassport {
    private AgentPassport() {}

    public static final String PASSPORT_SIG_DOMAIN = "atlas-pca/passport-sig/v1\0";
    public static final int PASSPORT_VERSION = 1;
    public static final long DEFAULT_PASSPORT_EVIDENCE_AGE_MS = 24L * 3600_000L;
    private static final double MAX_SKEW_MS = 60_000;

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static Map<String, Object> map(Object o) { return o instanceof Map ? StoreJs.map(o) : new LinkedHashMap<>(); }

    private static String text(Object x, boolean present) { return IntentRevocation.jsText(x, present); }

    private static boolean isStr(Object x) { return x instanceof String && !((String) x).isEmpty(); }

    // ---- identity ----

    /** The content fingerprint of an identity: {@code hashCanonical} of its fields with absent digests as null. Throws on a missing model, operator or hardware flag. */
    public static String passportFingerprint(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/passport/v1");
        for (String k : new String[] {"model_id"}) {
            if (!p.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(k, p.get(k));
        }
        for (String k : new String[] {"weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"}) m.put(k, p.get(k)); // `?? null`
        for (String k : new String[] {"operator", "hardware_rooted"}) {
            if (!p.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(k, p.get(k));
        }
        return Pca.hashCanonical(IntentJs.normalize(m));
    }

    /** The identity with its fingerprint as {@code id}. */
    public static Map<String, Object> issuePassport(Map<String, Object> identity) {
        Map<String, Object> p = new LinkedHashMap<>(identity);
        p.put("id", passportFingerprint(identity));
        return p;
    }

    // ---- binding match ----

    private static boolean includes(Object list, Object v) {
        if (list instanceof List) {
            for (Object e : (List<?>) list) if (sameValueZero(e, v)) return true;
            return false;
        }
        if (list instanceof String) return ((String) list).contains(text(v, true));
        throw new IllegalArgumentException("list.includes is not a function");
    }

    private static boolean sameValueZero(Object a, Object b) {
        if (a == null || b == null) return a == b;
        if (a instanceof Map || a instanceof List || b instanceof Map || b instanceof List) return false;
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        if (x != null || y != null) return x != null && y != null && (x.equals(y) || x.doubleValue() == y.doubleValue());
        return a.equals(b);
    }

    private static boolean nonEmpty(Object l) { return l instanceof List ? !((List<?>) l).isEmpty() : l instanceof String && !((String) l).isEmpty(); }

    /** True when the value is a list or string the reference would read {@code .length} of (anything else is not a usable allowlist). */
    private static boolean hasLength(Object l) { return l instanceof List || l instanceof String; }

    /**
     * Match a passport against an {@code agent_binding}: {@code {ok, reasons}} with the reasons in the reference's order: model, weights,
     * system prompt and tool manifest allowlists (a pinned digest the passport does not carry is a reason), operator, hardware, measured weights,
     * and {@code min_measurement} (an equality pin, or {@code {svn: n}} over a canonical decimal runtime measurement; anything else fails
     * closed). Throws on a null passport or binding.
     */
    public static Map<String, Object> matchesBinding(Map<String, Object> p, Map<String, Object> b) {
        if (p == null || b == null) throw new IllegalArgumentException("Cannot read properties of null");
        List<Object> reasons = new ArrayList<>();
        Object ma = b.get("model_allowlist");
        if (Zk.truthy(ma) && hasLength(ma) && nonEmpty(ma) && !includes(ma, p.get("model_id"))) reasons.add("model_id '" + text(p.get("model_id"), p.containsKey("model_id")) + "' not in allowlist");
        need(reasons, b.get("weights_allowlist"), p, "weights_digest");
        need(reasons, b.get("system_prompt_allowlist"), p, "system_prompt_digest");
        need(reasons, b.get("tool_manifest_allowlist"), p, "tool_manifest_digest");
        if (b.containsKey("operator") && !Ledger.jsEq(p.get("operator"), b.get("operator"))) {
            reasons.add("operator '" + text(p.get("operator"), p.containsKey("operator")) + "' != required '" + text(b.get("operator"), true) + "'");
        }
        if (Zk.truthy(b.get("require_hardware")) && !Zk.truthy(p.get("hardware_rooted"))) reasons.add("binding requires a hardware-rooted attestation");
        if (Zk.truthy(b.get("require_measured_weights")) && !Zk.truthy(p.get("weights_measured"))) reasons.add("binding requires hardware-measured weights");
        if (b.containsKey("min_measurement")) {
            Object mm = b.get("min_measurement");
            if (mm instanceof String) {
                if (!Ledger.jsEq(p.get("runtime_measurement"), mm)) reasons.add("runtime_measurement does not equal the pinned measurement");
            } else {
                Object bound = mm instanceof Map && ((Map<?, ?>) mm).size() == 1 ? ((Map<?, ?>) mm).get("svn") : null;
                if (!IntentJs.isNonNeg(bound)) {
                    reasons.add("min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)");
                } else {
                    Object rm = p.get("runtime_measurement");
                    Double svn = rm instanceof String && ((String) rm).matches("0|[1-9][0-9]*") ? Double.valueOf(Double.parseDouble((String) rm)) : null;
                    if (svn == null || svn > 9007199254740991d || svn < IntentJs.num(bound)) reasons.add("runtime SVN " + text(rm, p.containsKey("runtime_measurement")) + " < required " + text(bound, true));
                }
            }
        }
        return Issue.obj("ok", reasons.isEmpty(), "reasons", reasons);
    }

    private static void need(List<Object> reasons, Object list, Map<String, Object> p, String label) {
        if (!Zk.truthy(list)) return;
        if (list instanceof List && ((List<?>) list).isEmpty()) return;
        if (list instanceof String && ((String) list).isEmpty()) return;
        if (!p.containsKey(label)) reasons.add(label + " required by binding but absent from passport");
        else if (!includes(list, p.get(label))) reasons.add(label + " '" + text(p.get(label), true) + "' not in allowlist");
    }

    // ---- registry ----

    /** An in-memory registry by passport id; a later passport with the same id replaces the earlier one in place. */
    public static final class Registry {
        private final Map<Object, Map<String, Object>> byId = new LinkedHashMap<>();

        private static Object key(Object id) { Double d = IntentJs.num(id); return d != null ? (Object) (d == 0 ? 0.0 : d) : id; }

        Registry(List<?> passports) { for (Object p : passports) byId.put(key(AgentPassport.get(p, "id")), p instanceof Map ? StoreJs.map(p) : null); }

        public Map<String, Object> get(Object id) { return byId.get(key(id)); }

        public boolean has(Object id) { return byId.containsKey(key(id)); }

        public List<Map<String, Object>> all() { return new ArrayList<>(byId.values()); }
    }

    public static Registry buildRegistry(List<?> passports) { return new Registry(passports); }

    // ---- trust score ----

    /**
     * A score in [0, 1] from the passport's evidence: 0.4 hardware-rooted, 0.2 (measured) or 0.1 for a weights digest, 0.1 each for a prompt
     * and a tool manifest digest, 0.2 for an operator in {@code opts.knownOperators}.
     */
    public static double trustScore(Map<String, Object> p, Map<String, Object> opts) {
        double s = 0;
        if (Zk.truthy(p.get("hardware_rooted"))) s += 0.4;
        if (Zk.truthy(p.get("weights_digest"))) s += Zk.truthy(p.get("weights_measured")) ? 0.2 : 0.1;
        if (Zk.truthy(p.get("system_prompt_digest"))) s += 0.1;
        if (Zk.truthy(p.get("tool_manifest_digest"))) s += 0.1;
        Object known = opts == null ? null : opts.get("knownOperators");
        if (known != null && includes(known, p.get("operator"))) s += 0.2;
        return Math.max(0, Math.min(1, s));
    }

    // ---- signed passports ----

    /** The binding a passport's hardware evidence must carry: {@code {holderPub: subject, grantRef: "passport:" + id, epoch: 0, nonce}}. */
    public static Map<String, Object> passportEvidenceBinding(Object passportId, Object subject, Object nonce) {
        return Issue.obj("holderPub", subject, "grantRef", "passport:" + AttestNvidia.jsString(passportId), "epoch", IntentJs.ofLong(0), "nonce", nonce);
    }

    private static byte[] passportMessage(Map<String, Object> body) {
        return Pca.concat(PASSPORT_SIG_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(IntentJs.normalize(body)));
    }

    /**
     * Sign a passport for {@code opts.subject}: {@code opts = {issuerSecret (byte[]), subject, iat?, nbf?, exp, evidence?, suite?}} where
     * {@code iat} defaults to the passport's {@code issued_at}, {@code nbf} to {@code iat}, and {@code evidence = {document, at?}} (required for a
     * hardware-rooted passport) records when it was taken ({@code iat} by default). Throws when the id is not the identity's fingerprint, the
     * evidence is missing, the suite is unknown, or the times are not safe integers with {@code exp > nbf}.
     */
    public static Map<String, Object> signPassport(Map<String, Object> passport, Map<String, Object> opts) {
        if (!Ledger.jsEq(passport.get("id"), passportFingerprint(passport))) throw new IllegalArgumentException("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)");
        Object evidenceO = opts.get("evidence");
        if (Zk.truthy(passport.get("hardware_rooted")) && evidenceO == null) throw new IllegalArgumentException("signPassport: hardware_rooted requires attestation evidence (fail closed)");
        Map<String, Object> ev = evidenceO == null ? null : map(evidenceO);
        if (ev != null && ev.containsKey("at") && !IntentJs.isSafeInteger(ev.get("at"))) throw new IllegalArgumentException("signPassport: evidence.at must be a safe integer");
        Pq.SignerSuiteOpts suite = (Pq.SignerSuiteOpts) opts.get("suite");
        String alg = suite == null ? null : suite.alg;
        if (Pq.resolveSigAlg(alg, alg != null) == null) throw new IllegalArgumentException("signPassport: unknown signature alg '" + alg + "'");
        Object iat = opts.get("iat") != null ? opts.get("iat") : passport.get("issued_at");
        Object nbf = opts.get("nbf") != null ? opts.get("nbf") : iat;
        Object exp = opts.get("exp");
        if (!IntentJs.isSafeInteger(iat) || !IntentJs.isSafeInteger(nbf) || !IntentJs.isSafeInteger(exp) || !(IntentJs.num(exp) > IntentJs.num(nbf))) {
            throw new IllegalArgumentException("signPassport: iat/nbf/exp must be safe integers with exp > nbf");
        }
        byte[] secret = (byte[]) opts.get("issuerSecret");
        Pq.SuiteSecretKeys keys = Pq.suiteKeysOf(secret, suite);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("typ", "atlas-pca/passport");
        body.put("ver", IntentJs.ofLong(PASSPORT_VERSION));
        body.put("passport", new LinkedHashMap<>(passport));
        body.put("iss", Keys.edFromSeed(secret).id());
        if (opts.containsKey("subject") && opts.get("subject") != null) body.put("sub", opts.get("subject"));
        body.put("iat", iat);
        body.put("nbf", nbf);
        body.put("exp", exp);
        if (ev != null) {
            Map<String, Object> e2 = new LinkedHashMap<>(ev);
            if (!ev.containsKey("at") || ev.get("at") == null) e2.put("at", iat);
            body.put("evidence", e2);
        }
        String pqPk = Pq.suitePqPublicKey(alg, keys);
        Map<String, Object> bound = IntentJs.bindSuiteFields(body, alg, alg != null, pqPk, pqPk != null);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, keys, passportMessage(bound));
        Map<String, Object> out = new LinkedHashMap<>(bound);
        out.put("sig", f.sig);
        if (f.alg != null) out.put("alg", f.alg);
        if (f.pqPk != null) out.put("pq_pk", f.pqPk);
        if (f.pqSig != null) out.put("pq_sig", f.pqSig);
        return out;
    }

    private static Map<String, Object> bad(String reason, String detail) {
        Map<String, Object> m = Issue.obj("ok", false, "reason", reason);
        if (detail != null && !detail.isEmpty()) m.put("detail", detail);
        return m;
    }

    /**
     * Verify a signed passport against {@code opts = {trustedIssuers, now, clockSkewMs?, subject?, maxEvidenceAgeMs?, pqPins?}}, a revocation
     * source (REQUIRED: none is a refusal, as is a throwing one) and, for a hardware-rooted passport, a hardware verifier. In order: shape,
     * version and suite; the trusted issuer; the signature (a PQ passport verifies under a verifier-pinned key only); the id; the validity
     * window (skew capped at 60 s); the subject; revocation; and hardware evidence (present, fresh, attested for this passport and subject, and
     * the attested identity equal to the passport's). Returns {@code {ok: true, passport, iss, sub, exp, hardware_verified}} or {@code {ok:
     * false, reason, detail?}}. Never throws.
     */
    public static Map<String, Object> verifyPassport(Object sp, Map<String, Object> o, Function<Map<String, Object>, Object> revocation, Attestation.HardwareVerifier hardware) {
        try {
            if (sp == null || !"atlas-pca/passport".equals(get(sp, "typ")) || get(sp, "passport") == null) return bad("malformed", null);
            Map<String, Object> s = map(sp);
            if (!IntentJs.isSafeInteger(s.get("ver")) || IntentJs.num(s.get("ver")) != PASSPORT_VERSION) return bad("unsupported_version", text(s.get("ver"), s.containsKey("ver")));
            if (s.containsKey("alg") && !Pq.isKnownSigAlg(s.get("alg"))) return bad("unsupported_suite", text(s.get("alg"), true));
            Object po = s.get("passport");
            Map<String, Object> p = map(po);
            if (!isStr(s.get("iss")) || !isStr(s.get("sub")) || !isStr(s.get("sig")) || !isStr(p.get("id")) || !isStr(p.get("model_id")) || !isStr(p.get("operator")) || !(p.get("hardware_rooted") instanceof Boolean)) return bad("malformed", null);
            Object now = o.get("now");
            if (!IntentJs.isSafeInteger(s.get("iat")) || !IntentJs.isSafeInteger(s.get("nbf")) || !IntentJs.isSafeInteger(s.get("exp")) || !IntentJs.isSafeInteger(now)
                || !(IntentJs.num(s.get("exp")) > IntentJs.num(s.get("nbf")))) return bad("malformed", "times");
            Object issuers = o.get("trustedIssuers");
            if (!(issuers instanceof List) || !((List<?>) issuers).contains(s.get("iss"))) return bad("unknown_issuer", null);
            Map<String, Object> body = new LinkedHashMap<>(s);
            body.remove("sig");
            body.remove("pq_sig");
            boolean algPresent = s.containsKey("alg");
            if (!IntentJs.verifyPinnedSuite(s.get("alg"), algPresent, (String) s.get("iss"), s.get("pq_pk"), passportMessage(body), s.get("sig"), s.get("pq_sig"), StoreJs.map(o.get("pqPins")))) return bad("bad_signature", null);
            if (!p.get("id").equals(passportFingerprint(p))) return bad("id_mismatch", null);
            double nowMs = IntentJs.num(now);
            double skew = Math.min(Math.max(o.get("clockSkewMs") == null ? 0 : Actions.jsNumber(o.get("clockSkewMs"), true), 0), MAX_SKEW_MS);
            if (Double.isNaN(skew)) skew = 0; // a NaN tolerance falls back to none
            double nbf = IntentJs.num(s.get("nbf")), exp = IntentJs.num(s.get("exp"));
            if (nowMs + skew < nbf) return bad("not_yet_valid", null);
            if (nowMs - skew >= exp) return bad("expired", null);
            if (o.containsKey("subject") && !Ledger.jsEq(o.get("subject"), s.get("sub"))) return bad("subject_mismatch", null);
            if (revocation == null) return bad("revocation_unavailable", "no revocation source");
            boolean revoked;
            try {
                revoked = Boolean.TRUE.equals(revocation.apply(Issue.obj("id", p.get("id"), "iss", s.get("iss"), "sub", s.get("sub"))));
            } catch (RuntimeException e) {
                return bad("revocation_unavailable", null);
            }
            if (revoked) return bad("revoked", null);
            if (Boolean.TRUE.equals(p.get("hardware_rooted"))) {
                Map<String, Object> ev = s.get("evidence") == null ? new LinkedHashMap<>() : map(s.get("evidence"));
                Object doc = ev.get("document");
                if (!isStr(get(doc, "nonce"))) return bad("hardware_evidence_missing", null);
                Object atO = ev.get("at");
                if (!IntentJs.isSafeInteger(atO)) return bad("hardware_evidence_missing", "evidence.at");
                double at = IntentJs.num(atO);
                double maxAge = o.get("maxEvidenceAgeMs") == null ? DEFAULT_PASSPORT_EVIDENCE_AGE_MS : Actions.jsNumber(o.get("maxEvidenceAgeMs"), true);
                if (Double.isNaN(maxAge) || Double.isInfinite(maxAge) || maxAge < 0 || nowMs - at > maxAge || at - nowMs > skew) return bad("hardware_evidence_stale", null);
                if (hardware == null) return bad("hardware_verifier_missing", null);
                Object r;
                try {
                    Map<String, Object> expected = passportEvidenceBinding((String) p.get("id"), (String) s.get("sub"), (String) get(doc, "nonce"));
                    expected.put("nonceIssuedAt", now);
                    r = hardware.verify(Issue.obj("document", doc, "ctx", new LinkedHashMap<String, Object>(), "nowMs", now, "expected", expected));
                } catch (Exception e) {
                    return bad("hardware_attestation_failed", e.getMessage() == null ? "error" : e.getMessage());
                }
                if (!Zk.truthy(r) || !Boolean.TRUE.equals(get(r, "ok")) || !Boolean.TRUE.equals(get(r, "bound"))) {
                    Object why = get(r, "reason");
                    return bad("hardware_attestation_failed", why == null ? null : text(why, true));
                }
                Object m = get(r, "measured");
                if (!Zk.truthy(m) || !identityMatches(p, m)) return bad("hardware_identity_mismatch", null);
            }
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("passport", po);
            ok.put("iss", s.get("iss"));
            ok.put("sub", s.get("sub"));
            ok.put("exp", s.get("exp"));
            ok.put("hardware_verified", p.get("hardware_rooted"));
            return ok;
        } catch (RuntimeException e) {
            return bad("malformed", e.getMessage() == null ? "error" : e.getMessage());
        }
    }

    private static boolean identityMatches(Map<String, Object> p, Object m) {
        if (!Ledger.jsEq(get(m, "model_id"), p.get("model_id")) || !Ledger.jsEq(get(m, "operator"), p.get("operator"))) return false;
        for (String k : new String[] {"weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"}) {
            if (p.containsKey(k) && !Ledger.jsEq(get(m, k), p.get(k))) return false;
        }
        return !Boolean.TRUE.equals(p.get("weights_measured")) || Boolean.TRUE.equals(get(m, "weights_measured"));
    }

    /**
     * The assurance of an accepted passport: {@code software} when it is not hardware-verified, else the level (and vendor) the hardware verifier
     * declares, or {@code unknown} when it declares none.
     */
    public static Map<String, Object> passportAssurance(Map<String, Object> verdict, Object verifier) {
        if (!Zk.truthy(verdict.get("hardware_verified"))) return Issue.obj("level", "software");
        Assurance.Label l = Assurance.labelOf(verifier);
        Map<String, Object> out = Issue.obj("level", l == null ? "unknown" : l.level);
        if (l != null && l.vendor != null && !l.vendor.isEmpty()) out.put("vendor", l.vendor);
        return out;
    }
}
