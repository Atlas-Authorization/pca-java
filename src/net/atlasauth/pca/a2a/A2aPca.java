package net.atlasauth.pca.a2a;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import net.atlasauth.pca.A2a;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.PcaGrant;
import net.atlasauth.pca.Threshold;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Oauth;

/**
 * The A2A (Agent2Agent) adapter for PCA: proof-carrying Tasks, signed Agent Cards, the AP2 payment-mandate envelope, the AUTH_REQUIRED
 * mapping, per-hop delegation, push tokens, signed task-update receipts and the extended Agent Card. Pure functions over parsed JSON
 * (Map, List, String, Boolean, {@link Json.Num}, null); every verifier is fail-closed. The needs / chain-extension / push / receipt
 * verification core lives in {@link A2a}; this class adds the rest and delegates to it.
 *
 * <p>A PCActn is verified by a {@link PcaVerifier}: the default ({@link #CORE_VERIFIER}) runs the core verifier
 * ({@link Pca#verifyPcactn}) plus the checks the options carry (plan authorization from {@code context.planAuthorized}, the params digest,
 * a revocation predicate, PQ pins) and then demands every required check to PASS; a check the verifier cannot evaluate (no revocation
 * predicate, no authorized plan) is never reported and so fails closed. Plug {@link Authorize#authorize} (or any pipeline) in as the
 * {@link PcaVerifier} to enforce replay state and policy.
 */
public final class A2aPca {
    private A2aPca() {}

    public static final String PCA_A2A_EXTENSION_URI = "https://atlasauth.net/a2a/ext/pca/v2";
    public static final String TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED";
    public static final String TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED";
    public static final String A2A_RECEIPT_DOMAIN = A2a.RECEIPT_DOMAIN;
    public static final String RECEIPT_KEY = PCA_A2A_EXTENSION_URI + "#receipt";
    private static final String NEED_KEY = PCA_A2A_EXTENSION_URI + "#need";
    private static final String PCA_PASSPORT_HEADER = "pca_passport";
    /** The {@code @context} of the PCA payment-mandate envelope (a PCA-defined envelope, not an AP2 credential). */
    public static final List<String> A2A_AP2_CONTEXT = List.of("https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2");
    private static final Set<String> TERMINAL = Set.of("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED");
    private static final Set<String> STATES = Set.of("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED",
        "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED");
    public static final List<String> DEFAULT_REQUIRED_CHECKS = List.of("counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound");

    // ------------------------------------------------------------------------------------------------ JavaScript-ish helpers

    /** Marks a member that is absent (JavaScript undefined) as opposed to JSON null. */
    private static final Object UNDEF = new Object();

    /** {@code o[k]}: UNDEF when absent; a null or undefined o throws (TypeError); a primitive or an array has no such member. */
    private static Object at(Object o, String k) {
        if (o == null || o == UNDEF) throw new IllegalStateException("TypeError: cannot read properties of null (reading '" + k + "')");
        if (o instanceof Map) return ((Map<?, ?>) o).containsKey(k) ? ((Map<?, ?>) o).get(k) : UNDEF;
        return UNDEF;
    }

    /** {@code o?.[k]}: UNDEF for null / non-objects / absent. */
    private static Object opt(Object o, String k) { return o == null || o == UNDEF ? UNDEF : at(o, k); }

    private static Object jsonOf(Object v) { return v == UNDEF ? null : v; }

    private static boolean isObj(Object o) { return o instanceof Map; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    /** {@code {...o}}: own enumerable members of an object, the indices of an array or a string; nothing for other values. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> spread(Object o) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (o instanceof Map) out.putAll((Map<String, Object>) o);
        else if (o instanceof List) { int i = 0; for (Object x : (List<Object>) o) out.put(Integer.toString(i++), x); }
        else if (o instanceof String) { String s = (String) o; for (int i = 0; i < s.length(); i++) out.put(Integer.toString(i), String.valueOf(s.charAt(i))); }
        return out;
    }

    /** {@code [...x]}: a list copy; a string spreads by code point; null / non-iterables throw. */
    @SuppressWarnings("unchecked")
    private static List<Object> spreadList(Object x) {
        if (x instanceof List) return new ArrayList<>((List<Object>) x);
        if (x instanceof String) {
            List<Object> out = new ArrayList<>();
            ((String) x).codePoints().forEach(c -> out.add(new String(Character.toChars(c))));
            return out;
        }
        throw new IllegalStateException("TypeError: not iterable");
    }

    private static boolean in(Set<String> s, Object o) { return o instanceof String && s.contains(o); }

    private static boolean safeNat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    /** JavaScript {@code a === b} for parsed JSON values; objects and arrays are never equal (distinct references). */
    private static boolean strictEq(Object a, Object b) {
        if (a == UNDEF || b == UNDEF) return a == b;
        if (a == null || b == null) return a == b;
        if (a instanceof String && b instanceof String) return a.equals(b);
        if (a instanceof Boolean && b instanceof Boolean) return a.equals(b);
        Double x = JsVal.num(a), y = JsVal.num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    private static boolean jsSpace(int c) { return net.atlasauth.pca.AttestCommon.isJsSpace(c); }

    private static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && jsSpace(s.charAt(a))) a++;
        while (b > a && jsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** {@code new Date(ms).toISOString()}; IllegalArgumentException (RangeError) for an invalid time value. */
    public static String toIsoString(Object msO) {
        Double d = JsVal.num(msO);
        if (d == null || Double.isNaN(d) || Double.isInfinite(d) || Math.abs(d) > 8.64e15) throw new IllegalArgumentException("Invalid time value");
        long ms = (long) (double) d; // TimeClip truncates toward zero
        ZonedDateTime t = Instant.ofEpochMilli(ms).atZone(ZoneOffset.UTC);
        int y = t.getYear();
        String year = y >= 0 && y <= 9999 ? String.format(Locale.ROOT, "%04d", y) : (y < 0 ? "-" : "+") + String.format(Locale.ROOT, "%06d", Math.abs(y));
        return String.format(Locale.ROOT, "%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, t.getMonthValue(), t.getDayOfMonth(), t.getHour(), t.getMinute(), t.getSecond(), t.getNano() / 1_000_000);
    }

    // ------------------------------------------------------------------------------------------------ 1. proof-carrying Tasks

    private static Map<String, Object> withPca(Object metadata, Object pcActn) {
        Map<String, Object> m = spread(metadata == null ? new LinkedHashMap<String, Object>() : metadata);
        m.put(PCA_A2A_EXTENSION_URI, pcActn);
        return m;
    }

    /** Read a PCActn out of a metadata bag (fail-closed: a missing / non-object value yields null). */
    private static Map<String, Object> readPca(Object metadata) {
        if (!(metadata instanceof Map)) return null;
        Object v = ((Map<?, ?>) metadata).get(PCA_A2A_EXTENSION_URI);
        return v instanceof Map ? map(v) : null;
    }

    /** Attach a PCActn to a Task (a copy; the input is not mutated). */
    public static Map<String, Object> attachPcaToA2ATask(Object task, Object pcActn) {
        if (task == null || task == UNDEF) throw new IllegalStateException("TypeError: Cannot read properties of null (reading 'metadata')");
        Map<String, Object> out = spread(task);
        out.put("metadata", withPca(out.get("metadata"), pcActn));
        return out;
    }

    /** Attach a PCActn to a single Message (a copy). */
    public static Map<String, Object> attachPcaToA2AMessage(Object message, Object pcActn) { return attachPcaToA2ATask(message, pcActn); }

    /** The PCActn carried on a Task: task metadata, then the current status message, then the most recent history message. Null when none. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> extractPca(Object task) {
        if (task == null) return null;
        Map<String, Object> onTask = readPca(jsonOf(opt(task, "metadata")));
        if (onTask != null) return onTask;
        Object status = jsonOf(opt(task, "status"));
        if (status instanceof Map) {
            Map<String, Object> onStatus = readPca(jsonOf(opt(jsonOf(opt(status, "message")), "metadata")));
            if (onStatus != null) return onStatus;
        }
        Object history = jsonOf(opt(task, "history"));
        if (history instanceof List) {
            List<Object> h = (List<Object>) history;
            for (int i = h.size() - 1; i >= 0; i--) {
                Map<String, Object> onMsg = readPca(jsonOf(opt(h.get(i), "metadata")));
                if (onMsg != null) return onMsg;
            }
        }
        return null;
    }

    /** The PCActn carried on a single Message (fail-closed). */
    public static Map<String, Object> extractPcaFromMessage(Object message) { return message == null ? null : readPca(jsonOf(opt(message, "metadata"))); }

    // ------------------------------------------------------------------------------------------------ verification

    /** What a {@link PcaVerifier} is asked. */
    public static final class Request {
        public final Map<String, Object> grant, context, pqPins;
        public final String aud;
        public final long now;
        public final List<String> allowedSuites, require;
        public final BiPredicate<Map<String, Object>, Map<String, Object>> isRevoked;
        Request(Map<String, Object> grant, String aud, long now, Map<String, Object> context, List<String> allowedSuites, Map<String, Object> pqPins,
                List<String> require, BiPredicate<Map<String, Object>, Map<String, Object>> isRevoked) {
            this.grant = grant; this.aud = aud; this.now = now; this.context = context; this.allowedSuites = allowedSuites; this.pqPins = pqPins;
            this.require = require; this.isRevoked = isRevoked;
        }
    }

    /** A verifier's verdict: {@code checks} name to "pass" | "fail" (a check it does not evaluate is absent). */
    public static final class Outcome {
        public final boolean allow;
        public final Map<String, String> checks;
        public final List<String> reasons;
        public Outcome(boolean allow, Map<String, String> checks, List<String> reasons) { this.allow = allow; this.checks = checks; this.reasons = reasons; }
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", allow);
            m.put("checks", new LinkedHashMap<String, Object>(checks));
            m.put("reasons", new ArrayList<Object>(reasons));
            return m;
        }
    }

    /** The full PCActn verifier plugged into the A2A surfaces. Must not throw; a throw is a refusal. */
    @FunctionalInterface
    public interface PcaVerifier { Outcome verify(Map<String, Object> pcActn, Request request); }

    /** The default verifier: the core verifier plus plan authorization, params digest, revocation and PQ pins; every required check must pass. */
    @SuppressWarnings("unchecked")
    public static final PcaVerifier CORE_VERIFIER = (p, r) -> {
        Map<String, String> checks = new LinkedHashMap<>();
        List<String> reasons = new ArrayList<>();
        Object plan = p.get("plan");
        Object root = plan instanceof Map ? ((Map<String, Object>) plan).get("root") : null;
        Object pa = r.context.get("planAuthorized");
        Pca.PlanRoots roots = Boolean.TRUE.equals(pa) && root instanceof String ? Pca.PlanRoots.of(List.of((String) root), false)
            : Boolean.FALSE.equals(pa) || Boolean.TRUE.equals(pa) ? Pca.PlanRoots.of(List.of(), false) : Pca.PlanRoots.NONE;
        Pca.Verdict v = Pca.verifyPcactn(p, r.grant, r.now, r.aud, r.allowedSuites, null, null, null, roots);
        boolean allow = v.allow;
        for (Map.Entry<String, Boolean> e : v.checks.entrySet()) checks.put(e.getKey(), e.getValue() ? "pass" : "fail");
        if (v.reason != null && !v.reason.isEmpty()) reasons.add(v.reason);
        if (r.pqPins != null) {
            Object issuer = r.grant.get("issuer"), alg = r.grant.get("alg");
            Object pin = issuer instanceof String ? r.pqPins.get(issuer) : null;
            boolean classical = alg == null || "ed25519".equals(alg);
            boolean ok = pin == null ? classical : !classical && pin.equals(r.grant.get("pq_pk"));
            checks.put("pq_pin", ok ? "pass" : "fail");
            if (!ok) { allow = false; reasons.add("pq_pin: the grant's post-quantum key is not the pinned one for its issuer"); }
        }
        if (r.context.get("params") instanceof Map) {
            Object act = p.get("action");
            Object want = act instanceof Map ? ((Map<String, Object>) act).get("params_digest") : null;
            boolean ok;
            try { ok = Pca.paramsDigest(r.context.get("params")).equals(want); } catch (RuntimeException e) { ok = false; }
            checks.put("params_digest", ok ? "pass" : "fail");
            if (!ok) { allow = false; reasons.add("params_digest: the params do not open action.params_digest"); }
        }
        if (r.isRevoked != null) {
            boolean ok;
            try { ok = !r.isRevoked.test(p, r.grant); } catch (RuntimeException e) { ok = false; }
            checks.put("revocation", ok ? "pass" : "fail");
            if (!ok) { allow = false; reasons.add("revocation: the proof or its chain is revoked (or the revocation check failed)"); }
        }
        for (String name : r.require) {
            if (!"pass".equals(checks.get(name))) { allow = false; reasons.add(name + ": required check did not pass (" + (checks.containsKey(name) ? "failed" : "not enforced") + ")"); }
        }
        return new Outcome(allow, checks, reasons);
    };

    /** Options shared by every PCActn verification surface. One of {@code grant} / {@code expectedRootIssuer} is required. */
    public static final class VerifyOptions {
        /** This resource server / Atlas instance id; compared against the PCActn's signed aud. */
        public String aud;
        /** Verification clock (epoch ms); null: the wall clock. */
        public Long now;
        /** The grant from YOUR store: the chain root must be byte-identical to it. */
        public Map<String, Object> grant;
        /** The principal the chain must be rooted at (b64u). */
        public String expectedRootIssuer;
        /** Verifier-side issuer to pq_pk pins. */
        public Map<String, Object> pqPins;
        public List<String> allowedSuites;
        /** The resource server's view of the action: {@code params}, {@code plan}, {@code planAuthorized}, ...; per PCActn. */
        public Function<Map<String, Object>, Map<String, Object>> context;
        /** Checks that must PASS; null: {@link #DEFAULT_REQUIRED_CHECKS}. */
        public List<String> requireChecks;
        /** Revocation predicate {@code (pcActn, grant) -> revoked?}; absent: the revocation check is not enforced and a default-required run refuses. */
        public BiPredicate<Map<String, Object>, Map<String, Object>> isRevoked;
        /** The verifier; null: {@link #CORE_VERIFIER}. */
        public PcaVerifier verifier;
        /** The human-present signer set of {@link #verifyA2APaymentMandate}. */
        public List<Object> humanSignerSet;
        /** {@link #pcaA2AMiddleware}: a Task with no proof is allowed through (a present proof must still verify). Default true: required. */
        public boolean requireProof = true;

        public VerifyOptions copy() {
            VerifyOptions o = new VerifyOptions();
            o.aud = aud; o.now = now; o.grant = grant; o.expectedRootIssuer = expectedRootIssuer; o.pqPins = pqPins; o.allowedSuites = allowedSuites;
            o.context = context; o.requireChecks = requireChecks; o.isRevoked = isRevoked; o.verifier = verifier; o.humanSignerSet = humanSignerSet;
            o.requireProof = requireProof;
            return o;
        }
    }

    /** Thrown when an A2A verifier is configured without any authority ({@code grant} or {@code expectedRootIssuer}). */
    public static final class A2AAuthorityError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String code = "authority_required";
        public A2AAuthorityError() { super("pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority"); }
    }

    private static void assertAuthority(VerifyOptions o) {
        boolean hasGrant = o != null && o.grant != null;
        boolean hasIssuer = o != null && o.expectedRootIssuer != null && !o.expectedRootIssuer.isEmpty();
        if (!hasGrant && !hasIssuer) throw new A2AAuthorityError();
    }

    /** The result of verifying a proof-carrying A2A artifact. */
    public static final class Verification {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> result;
        /** The PCActn echoed on a refusal, as given (any JSON value, null included); {@code UNDEF} when the refusal carries none. */
        public final Object pcActn;
        Verification(boolean ok, String reason, Map<String, Object> result, Object pcActn) { this.ok = ok; this.reason = reason; this.result = result; this.pcActn = pcActn; }
        /** The JSON form: {@code ok}, then {@code reason}, {@code result}, {@code pcActn} when present. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (reason != null) m.put("reason", reason);
            if (result != null) m.put("result", result);
            if (pcActn != UNDEF) m.put("pcActn", pcActn);
            return m;
        }
    }

    private static Verification bad(String reason, Object pcActn) { return new Verification(false, reason, null, pcActn instanceof Map ? map(pcActn) : UNDEF); }

    @SuppressWarnings("unchecked")
    private static Verification verifyPcActn(Object pcActn, VerifyOptions opts) {
        assertAuthority(opts);
        if (!(pcActn instanceof Map) && !(pcActn instanceof List)) return bad("PCActn is not an object", null);
        Object chain = pcActn instanceof Map ? ((Map<String, Object>) pcActn).get("cap_chain") : null;
        Object root = chain instanceof List && !((List<Object>) chain).isEmpty() ? ((List<Object>) chain).get(0) : null;
        if (!JsVal.truthy(root)) return bad("PCActn carries no capability chain", pcActn);
        if (opts.expectedRootIssuer != null && !strictEq(jsonOf(opt(root, "issuer")), opts.expectedRootIssuer)) return bad("chain root issuer does not match the expected principal", pcActn);
        // Without a stored grant, the root is admitted only under the pinned principal; a non-Ed25519 root then needs a PQ pin.
        Map<String, Object> grant = opts.grant != null ? opts.grant : (root instanceof Map ? (Map<String, Object>) root : new LinkedHashMap<String, Object>());
        Map<String, Object> pqPins = opts.grant == null ? (opts.pqPins != null ? opts.pqPins : new LinkedHashMap<String, Object>()) : opts.pqPins;
        Map<String, Object> context = opts.context != null ? opts.context.apply((Map<String, Object>) pcActn) : new LinkedHashMap<String, Object>();
        if (context == null) context = new LinkedHashMap<>();
        Request req = new Request(grant, opts.aud, opts.now != null ? opts.now : System.currentTimeMillis(), context, opts.allowedSuites, pqPins,
            opts.requireChecks != null ? opts.requireChecks : DEFAULT_REQUIRED_CHECKS, opts.isRevoked);
        Outcome out;
        try {
            out = (opts.verifier != null ? opts.verifier : CORE_VERIFIER).verify((Map<String, Object>) pcActn, req);
        } catch (RuntimeException e) {
            out = new Outcome(false, new LinkedHashMap<>(), List.of("verifier error (fail closed): " + e.getClass().getSimpleName()));
        }
        String reason = out.allow ? null : (out.reasons.isEmpty() ? "PCActn verification failed" : String.join("; ", out.reasons));
        Map<String, Object> result = out.toMap();
        if (reason != null) result.put("reason", reason);
        return out.allow ? new Verification(true, null, result, map(pcActn)) : new Verification(false, reason, result, map(pcActn));
    }

    /** Verify the proof-carrying action on an A2A Task; fail-closed (no PCActn, or one that does not verify, is rejected). */
    public static Verification verifyA2ATask(Object task, VerifyOptions opts) {
        assertAuthority(opts);
        Map<String, Object> pcActn = extractPca(task);
        if (pcActn == null) return bad("no proof-carrying action attached to this task", null);
        return verifyPcActn(pcActn, opts);
    }

    /** The server guard of {@link #pcaA2AMiddleware}: one Task in, a {@link Verification} out. */
    @FunctionalInterface
    public interface PcaA2AGuard { Verification check(Object task); }

    /** A guard that verifies the proof on each incoming Task. A present but invalid proof is always rejected; {@code opts.requireProof} false lets a Task with NO proof through. */
    public static PcaA2AGuard pcaA2AMiddleware(VerifyOptions opts) {
        assertAuthority(opts);
        final boolean require = opts.requireProof;
        return task -> {
            Map<String, Object> pcActn = extractPca(task);
            if (pcActn == null) return require ? bad("proof-carrying action required but none attached to task", null) : new Verification(true, null, null, UNDEF);
            return verifyPcActn(pcActn, opts);
        };
    }

    // ------------------------------------------------------------------------------------------------ 2. signed Agent Cards

    /** The canonical bytes a card signature covers: the card with {@code signatures} removed (RFC 8785). */
    public static byte[] cardSigningBytes(Object card) {
        Map<String, Object> rest = spread(card);
        rest.remove("signatures");
        return A2aCard.jcsBytes(rest);
    }

    /** RFC 8785 canonical bytes (see {@link A2aCard#jcsBytes}). */
    public static byte[] jcsBytes(Object value) { return A2aCard.jcsBytes(value); }

    /** The A2A 1.0 {@code AgentCard} problems (see {@link A2aCard#validateAgentCard1}). */
    public static List<String> validateAgentCard1(Object card) { return A2aCard.validateAgentCard1(card); }

    /** {@code alg} default EdDSA; {@code passport} ({@code id}, optional {@code uri}); {@code kid}; {@code profile} "pca-detached" | "a2a-1.0"; {@code schema} "a2a-1.0". */
    public static final class IssueOptions {
        public String alg;
        public Map<String, Object> passport;
        public String kid;
        public String profile;
        public String schema;
    }

    /**
     * Issue a signed Agent Card: embed the passport reference, sign the canonicalized card (minus {@code signatures}) with the JWK, append the
     * {@code {protected, signature}}. Throws IllegalArgumentException for an invalid card schema, a missing kid under the a2a-1.0 profile or a
     * card with no canonical form; Jose.JoseException for a key that cannot sign.
     */
    public static Map<String, Object> issueSignedAgentCard(Object card, Map<String, Object> signingKey, IssueOptions opts) {
        if (opts == null) opts = new IssueOptions();
        String alg = opts.alg != null ? opts.alg : "EdDSA";
        Object passport;
        boolean passportIdMissing = false; // the reference puts an undefined id into the card, which then has no canonical form
        if (opts.passport != null) {
            passportIdMissing = !opts.passport.containsKey("id");
            Map<String, Object> pp = new LinkedHashMap<>();
            if (opts.passport.containsKey("id")) pp.put("id", opts.passport.get("id"));
            if (opts.passport.containsKey("uri") && opts.passport.get("uri") != null) pp.put("uri", opts.passport.get("uri"));
            passport = pp;
        } else {
            passport = jsonOf(opt(card, "pcaPassport"));
        }
        Map<String, Object> toSign = spread(card);
        if (JsVal.truthy(passport)) toSign.put("pcaPassport", passport);
        if ("a2a-1.0".equals(opts.schema)) {
            List<String> problems = A2aCard.validateAgentCard1(toSign);
            if (!problems.isEmpty()) throw new IllegalArgumentException("issueSignedAgentCard: the card does not match the A2A 1.0 schema: " + String.join("; ", problems));
        }
        if (passportIdMissing) throw new IllegalArgumentException("jcs: unsupported type undefined");
        byte[] payload = cardSigningBytes(toSign);
        boolean spec = "a2a-1.0".equals(opts.profile);
        if (spec && (opts.kid == null || opts.kid.isEmpty())) throw new IllegalArgumentException("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
        Map<String, Object> header = null;
        if (JsVal.truthy(passport) && at(passport, "id") != UNDEF) { header = new LinkedHashMap<>(); header.put(PCA_PASSPORT_HEADER, at(passport, "id")); }
        Map<String, Object> signature = A2aJws.signDetached(payload, signingKey, alg, opts.kid, spec, header);
        Object existing = toSign.get("signatures");
        List<Object> sigs = existing == null ? new ArrayList<>() : spreadList(existing);
        sigs.add(signature);
        toSign.put("signatures", sigs);
        return toSign;
    }

    /** {@code jwks} (a JWKS) or {@code key} (a JWK map), the importJWK {@code alg} (default EdDSA) and the optional {@code schema} "a2a-1.0". */
    public static final class VerifyCardOptions {
        public Object jwks;
        public Object key;
        public String alg;
        public String schema;
    }

    /**
     * Validate an Agent Card against its signatures. Fail-closed: no signatures, an unresolvable key or ANY signature that does not verify is a refusal.
     * Result: {@code ok}, {@code reason} on a refusal; on success the {@code passportRef} the signature commits to and the card's {@code passport}.
     * {@code reason} wording after the first colon of a library failure is this port's own, not the reference library's.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAgentCard(Object card, VerifyCardOptions opts) {
        return verifyCard(card, opts, false);
    }

    /** Shared by the A2A and agent-card verifiers; {@code pcaProof} adds the live proof pointer and the agent-card wording of a malformed signature. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyCard(Object card, VerifyCardOptions opts, boolean agentCardPkg) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(card instanceof Map) && !(card instanceof List)) return refuse("agent card is not an object");
        Object signatures = card instanceof Map ? ((Map<String, Object>) card).get("signatures") : null;
        if (!(signatures instanceof List) || ((List<Object>) signatures).isEmpty()) return refuse("agent card carries no signatures");
        if ("a2a-1.0".equals(opts.schema)) {
            List<String> problems = A2aCard.validateAgentCard1(card);
            if (!problems.isEmpty()) return refuse("agent card does not match the A2A 1.0 schema: " + String.join("; ", problems));
        }
        A2aJws.Resolved res = A2aJws.resolveVerifyKey(opts.jwks, opts.key, opts.alg);
        if (res.error != null) return refuse(res.error);
        byte[] payload;
        try {
            payload = cardSigningBytes(card);
        } catch (IllegalArgumentException e) {
            return refuse("agent card has no canonical form: " + e.getMessage());
        }
        String passportRef = null;
        List<Object> sigs = (List<Object>) signatures;
        for (int i = 0; i < sigs.size(); i++) {
            Object sig = sigs.get(i);
            if (!agentCardPkg) {
                if (!JsVal.truthy(sig) || !(at(sig, "protected") instanceof String) || !(at(sig, "signature") instanceof String)) return refuse("signature " + i + " is malformed");
            } else if (!JsVal.truthy(sig)) return refuse("signature " + i + " is missing");
            A2aJws.Result r = A2aJws.verifyDetached(payload, sig, res.resolver);
            if (!r.ok) return refuse("signature " + i + " did not verify: " + r.reason);
            Object ref = r.protectedHeader.get(PCA_PASSPORT_HEADER);
            if (ref instanceof String && passportRef == null) passportRef = (String) ref;
        }
        out.put("ok", true);
        if (passportRef != null) out.put("passportRef", passportRef);
        Object pp = card instanceof Map ? ((Map<String, Object>) card).get("pcaPassport") : null;
        if (JsVal.truthy(pp)) out.put("passport", pp);
        if (agentCardPkg) {
            Object proof = card instanceof Map ? ((Map<String, Object>) card).get("pcaProof") : null;
            if (JsVal.truthy(proof)) out.put("pcaProof", proof);
        }
        return out;
    }

    private static Map<String, Object> refuse(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    // ------------------------------------------------------------------------------------------------ 3. AP2 payment profile

    private static Object leafOfChain(Object chain) {
        if (chain instanceof List && !((List<?>) chain).isEmpty()) { List<?> l = (List<?>) chain; return l.get(l.size() - 1); }
        return UNDEF;
    }

    private static Object leafHolderOf(Object chain) {
        Object leaf = leafOfChain(chain);
        return leaf == UNDEF ? UNDEF : opt(leaf, "holder");
    }

    /**
     * True only when the PCActn carries threshold shares that verify at t=3 under {@code signerSet} (agent + guardian + principal, one distinct
     * key per role). Stricter than the reference in one respect: EVERY explicit share must verify (a stray invalid share refuses), and the agent
     * may be the leaf signature only for an Ed25519 leaf whose signer-set entry registers no post-quantum key. Never throws.
     */
    @SuppressWarnings("unchecked")
    static boolean verifiedHumanPresent(Map<String, Object> pcActn, Object signerSetO) {
        try {
            if (!(signerSetO instanceof List)) return false;
            List<Object> signerSet = (List<Object>) signerSetO;
            byte[] msg = Pca.thresholdMessage(pcActn);
            Object th = pcActn.get("threshold");
            Object sh = th instanceof Map ? ((Map<String, Object>) th).get("shares") : null;
            List<Object> shares = sh instanceof List ? (List<Object>) sh : new ArrayList<>();
            Set<String> good = new java.util.HashSet<>();
            for (Object s : shares) {
                if (!(s instanceof Map) || !(((Map<String, Object>) s).get("role") instanceof String)) return false;
                String role = (String) ((Map<String, Object>) s).get("role");
                if (!Threshold.verifyShare(role, msg, signerSet, 3, (Map<String, Object>) s)) return false;
                good.add(role);
            }
            if (!good.contains("agent") && agentLeafBaseline(pcActn, signerSet, msg)) good.add("agent");
            return good.contains("agent") && good.contains("guardian") && good.contains("principal");
        } catch (RuntimeException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean agentLeafBaseline(Map<String, Object> p, List<Object> signerSet, byte[] msg) {
        Object holder = leafHolderOf(p.get("cap_chain"));
        Object sig = p.get("sig"), alg = p.get("alg");
        if (!(holder instanceof String) || !(sig instanceof String) || (alg != null && !"ed25519".equals(alg))) return false;
        boolean registered = false;
        for (Object e : signerSet) {
            Map<String, Object> m = (Map<String, Object>) e;
            if ("agent".equals(m.get("role")) && holder.equals(m.get("publicKey"))) { if (m.containsKey("pq_pk")) return false; registered = true; }
        }
        if (!registered) return false;
        byte[] pk = Pca.decodeB64uStrict(holder, 32), sg = Pca.decodeB64uStrict(sig, 64);
        return pk != null && sg != null && Jose.verifyEd25519Strict(pk, msg, sg);
    }

    /**
     * Map a PCActn to an AP2 Payment Mandate. {@code opts}: {@code amount {currency, value}} (value a non-negative integer in minor units),
     * {@code paymentMethod}, {@code merchant}, {@code humanPresent}, {@code humanSignerSet}, {@code issuerPublic}, {@code now}.
     * Throws IllegalArgumentException on a bad amount or no issuer.
     */
    public static Map<String, Object> a2aPaymentMandateFromPca(Object pcActnO, Map<String, Object> opts) {
        Object leaf = leafHolderOf(at(pcActnO, "cap_chain"));
        Object issuerO = opts.containsKey("issuerPublic") && opts.get("issuerPublic") != null ? opts.get("issuerPublic") : leaf;
        if (issuerO == UNDEF) throw new IllegalArgumentException("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain");
        Object amount = opts.get("amount");
        Object value = at(amount, "value");
        boolean negZero = value instanceof Json.Num && "-0".equals(((Json.Num) value).raw); // -0 is a safe integer and not below zero
        if (!negZero && !safeNat(value)) throw new IllegalArgumentException("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units");
        Object humanPresent;
        if (opts.containsKey("humanPresent") && opts.get("humanPresent") != null) humanPresent = opts.get("humanPresent");
        else humanPresent = JsVal.truthy(opts.get("humanSignerSet")) && pcActnO instanceof Map && verifiedHumanPresent(map(pcActnO), opts.get("humanSignerSet"));
        Object now = opts.containsKey("now") && opts.get("now") != null ? opts.get("now") : (Object) Long.valueOf(System.currentTimeMillis());
        Map<String, Object> xpca = new LinkedHashMap<>();
        xpca.put("pcactn_digest", Pca.hashCanonical(pcActnO));
        Object action = at(pcActnO, "action");
        if (action == UNDEF) throw new IllegalStateException("TypeError: cannot read properties of undefined (reading 'verb')");
        Object[][] fields = {{"aud", at(pcActnO, "aud")}, {"verb", at(action, "verb")}, {"resource", at(action, "resource")},
            {"params_digest", at(action, "params_digest")}, {"grant_ref", at(pcActnO, "grant_ref")}};
        for (Object[] f : fields) if (f[1] != UNDEF) xpca.put((String) f[0], f[1]);
        xpca.put("leaf_holder", leaf == UNDEF || leaf == null ? issuerO : leaf); // ?? also skips null
        // x_pca member order: pcactn_digest, aud, verb, resource, params_digest, grant_ref, leaf_holder
        Map<String, Object> contents = new LinkedHashMap<>();
        contents.put("amount", spread(amount));
        Object pm = opts.get("paymentMethod");
        contents.put("payment_method", spread(pm == null ? new LinkedHashMap<String, Object>() : pm));
        contents.put("human_present", humanPresent);
        if (opts.containsKey("merchant") && opts.get("merchant") != null) contents.put("merchant", opts.get("merchant"));
        contents.put("x_pca", xpca);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("@context", new ArrayList<Object>(A2A_AP2_CONTEXT));
        out.put("type", new ArrayList<Object>(List.of("VerifiableCredential", "PaymentMandate")));
        out.put("issuer", issuerO);
        out.put("issuanceDate", toIsoString(now));
        out.put("credentialSubject", contents);
        return out;
    }

    /** Read the PCA binding back out of an AP2 Payment Mandate (the round trip of {@code x_pca}). */
    public static Map<String, Object> pcaBindingFromA2APaymentMandate(Object mandate) {
        return spread(at(at(mandate, "credentialSubject"), "x_pca"));
    }

    private static String mandateBindingError(Object m, Object pcActn, Map<String, Object> params, VerifyOptions opts) {
        Object x = jsonOf(at(m, "x_pca"));
        if (!isObj(x)) return "payment mandate carries no x_pca binding";
        Object action = opt(pcActn, "action");
        Object leafHolder = leafOfChain(opt(pcActn, "cap_chain")) instanceof Map ? opt(leafOfChain(opt(pcActn, "cap_chain")), "holder") : UNDEF;
        // note: for a non-object chain / action the member reads as undefined, which never equals a string
        Object[][] bound = {{"aud", opt(pcActn, "aud")}, {"verb", action == UNDEF ? UNDEF : opt(action, "verb")}, {"resource", action == UNDEF ? UNDEF : opt(action, "resource")},
            {"params_digest", action == UNDEF ? UNDEF : opt(action, "params_digest")}, {"grant_ref", opt(pcActn, "grant_ref")}, {"leaf_holder", leafHolder}};
        for (Object[] b : bound) {
            Object have = at(x, (String) b[0]);
            if (!(have instanceof String) || !strictEq(have, b[1])) return "payment mandate x_pca." + b[0] + " is not the PCActn's";
        }
        Object amt = jsonOf(at(m, "amount"));
        Object av = isObj(amt) ? at(amt, "value") : UNDEF;
        if (!isObj(amt) || !safeNat(av) || !(at(amt, "currency") instanceof String))
            return "payment mandate amount is malformed (value must be a non-negative integer in minor units)";
        Object pa = params.containsKey("amount") ? params.get("amount") : UNDEF;
        if (pa == UNDEF || !safeNat(pa)) return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to";
        if (!(params.get("currency") instanceof String)) return "the PCActn params carry no currency to bind the mandate currency to";
        if (!strictEq(av, pa) || !strictEq(at(amt, "currency"), params.get("currency"))) return "payment mandate amount / currency differ from the authorized PCActn params";
        Object merchant = at(m, "merchant");
        Object pMerchant = params.containsKey("merchant") ? params.get("merchant") : UNDEF;
        if (!strictEq(merchant, pMerchant)) return "payment mandate merchant differs from the authorized PCActn params";
        if (params.containsKey("payment_method")) {
            boolean same;
            try {
                Object mpm = at(m, "payment_method");
                same = mpm != UNDEF && Pca.hashCanonical(mpm).equals(Pca.hashCanonical(params.get("payment_method")));
            } catch (RuntimeException e) { same = false; }
            if (!same) return "payment mandate payment_method differs from the authorized PCActn params";
        }
        Object hp = at(m, "human_present");
        if (!(hp instanceof Boolean)) return "payment mandate human_present must be a boolean";
        if ((Boolean) hp && !(opts.humanSignerSet != null && pcActn instanceof Map && verifiedHumanPresent(map(pcActn), opts.humanSignerSet)))
            return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)";
        return null;
    }

    /**
     * Verify an AP2 Payment Mandate against the PCActn it references (the mandate is unsigned: the PCActn must authorize every field a payer acts on).
     * {@code opts.context} must yield the action's plaintext {@code params}; the {@code params_digest} check is required on this path.
     */
    @SuppressWarnings("unchecked")
    public static Verification verifyA2APaymentMandate(Object mandate, Object pcActn, VerifyOptions opts) {
        assertAuthority(opts);
        Object bound;
        String digest;
        try {
            Object cs = at(mandate, "credentialSubject");
            if (cs == UNDEF) throw new IllegalStateException("credentialSubject is undefined");
            Object xp = at(cs, "x_pca");
            if (xp == UNDEF) throw new IllegalStateException("x_pca is undefined");
            bound = at(xp, "pcactn_digest");
            digest = Pca.hashCanonical(pcActn);
        } catch (RuntimeException e) {
            return bad("malformed payment mandate or PCActn: " + e.getMessage(), null);
        }
        if (!strictEq(bound, digest)) return new Verification(false, "payment mandate is not bound to this PCActn (pcactn_digest mismatch)", null, pcActn);
        if (!(pcActn instanceof Map) && !(pcActn instanceof List)) return bad("PCActn is not an object", null);
        Map<String, Object> context = opts.context != null ? opts.context.apply(pcActn instanceof Map ? (Map<String, Object>) pcActn : new LinkedHashMap<String, Object>()) : new LinkedHashMap<String, Object>();
        if (context == null) throw new IllegalStateException("TypeError: context is null");
        Object params = context.get("params");
        if (!(params instanceof Map)) return bad("context.params (the PCActn params plaintext) is required to bind the payment mandate", pcActn);
        String why = mandateBindingError(at(mandate, "credentialSubject"), pcActn, (Map<String, Object>) params, opts);
        if (why != null) return bad(why, pcActn);
        List<String> require = new ArrayList<>(opts.requireChecks != null ? opts.requireChecks : DEFAULT_REQUIRED_CHECKS);
        if (!require.contains("params_digest")) require.add("params_digest");
        VerifyOptions o = opts.copy();
        final Map<String, Object> ctx = context;
        o.context = p -> ctx;
        o.requireChecks = require;
        return verifyPcActn(pcActn, o);
    }

    // ------------------------------------------------------------------------------------------------ AUTH_REQUIRED mapping, extension, delegation, push

    /** The {@code AgentExtension} object to put in {@code capabilities.extensions}. */
    public static Map<String, Object> pcaExtensionDeclaration(Object params, boolean required) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("uri", PCA_A2A_EXTENSION_URI);
        m.put("description", "Per-action proofs of authority (PCActn) on tasks and messages");
        m.put("required", required);
        m.put("params", params);
        return m;
    }

    public static Map<String, Object> pcaExtensionDeclaration(Object params) { return pcaExtensionDeclaration(params, true); }

    private static Map<String, Object> extFail(String code) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("code", code);
        return m;
    }

    private static final Set<String> PARAM_KEYS = Set.of("aud", "suites", "grants", "policy_digest");

    /** Read and validate the PCA extension from an Agent Card: {@code {ok:true, required, params, grants}} or {@code {ok:false, code}}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> readPcaExtension(Object card) {
        Object caps = isObj(card) ? map(card).get("capabilities") : null;
        Object exts = isObj(caps) ? map(caps).get("extensions") : null;
        if (!(exts instanceof List)) return extFail("not_declared");
        List<Object> found = new ArrayList<>();
        for (Object e : (List<Object>) exts) if (isObj(e) && PCA_A2A_EXTENSION_URI.equals(map(e).get("uri"))) found.add(e);
        if (found.isEmpty()) return extFail("not_declared");
        if (found.size() > 1) return extFail("bad_declaration");
        Map<String, Object> e = map(found.get(0));
        if (e.containsKey("required") && !(e.get("required") instanceof Boolean)) return extFail("bad_declaration");
        Object po = e.get("params");
        if (!isObj(po)) return extFail("bad_params");
        Map<String, Object> p = map(po);
        for (String k : p.keySet()) if (!PARAM_KEYS.contains(k)) return extFail("bad_params");
        if (!(p.get("aud") instanceof String) || ((String) p.get("aud")).isEmpty() || ((String) p.get("aud")).length() > 512) return extFail("bad_params");
        if (p.containsKey("suites")) {
            Object s = p.get("suites");
            boolean ok = s instanceof List && ((List<Object>) s).size() <= 16;
            if (ok) for (Object x : (List<Object>) s) if (!(x instanceof String) || ((String) x).isEmpty() || ((String) x).length() > 64) { ok = false; break; }
            if (!ok) return extFail("bad_params");
        }
        if (p.containsKey("policy_digest")) {
            Object d = p.get("policy_digest");
            if (!(d instanceof String) || ((String) d).isEmpty() || ((String) d).length() > 128) return extFail("bad_params");
        }
        List<Map<String, Object>> grants = new ArrayList<>();
        if (p.containsKey("grants")) {
            PcaGrant.Result g = PcaGrant.parse(p.get("grants"));
            if (g.code != null) return extFail("bad_grants");
            grants = g.details;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("required", Boolean.TRUE.equals(e.get("required")));
        out.put("params", p);
        out.put("grants", new ArrayList<Object>(grants));
        return out;
    }

    /** True iff the {@code A2A-Extensions} service parameter lists the PCA extension (exact URI match in a comma-separated list). */
    public static boolean clientOptsIntoPca(Object header) {
        if (!(header instanceof String)) return false;
        for (String u : ((String) header).split(",", -1)) if (jsTrim(u).equals(PCA_A2A_EXTENSION_URI)) return true;
        return false;
    }

    /** AUTH_REQUIRED in the 1.0 enum spelling; the pre-1.0 {@code auth-required} is also read. */
    public static boolean isAuthRequired(Object state) { return TASK_STATE_AUTH_REQUIRED.equals(state) || "auth-required".equals(state); }

    /**
     * The TaskStatus an agent sets to ask for authority: state AUTH_REQUIRED, a message with the typed need under the extension key.
     * {@code need} is validated by the need codec (IllegalArgumentException when malformed); {@code now} epoch ms (RangeError when invalid).
     */
    public static Map<String, Object> authRequiredStatus(Map<String, Object> need, Object messageId, Object now, String text) {
        String enc = Oauth.encodePcaNeed(need); // validates and bounds
        Map<String, Object> msg = new LinkedHashMap<>();
        if (messageId != null) msg.put("messageId", messageId);
        msg.put("role", "agent");
        Map<String, Object> part = new LinkedHashMap<>();
        part.put("kind", "text");
        part.put("text", text != null ? text : "Authority needed: " + need.get("verb") + " on " + need.get("resource"));
        msg.put("parts", new ArrayList<Object>(List.of(part)));
        msg.put("extensions", new ArrayList<Object>(List.of(PCA_A2A_EXTENSION_URI)));
        Map<String, Object> md = new LinkedHashMap<>();
        md.put(NEED_KEY, enc);
        msg.put("metadata", md);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", TASK_STATE_AUTH_REQUIRED);
        out.put("timestamp", toIsoString(now));
        out.put("message", msg);
        return out;
    }

    private static Map<String, Object> decoded(Object value) {
        A2a.Decoded d = A2a.decodeNeed(value);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", d.need != null);
        if (d.need != null) m.put("need", d.need); else m.put("code", d.code);
        return m;
    }

    /** The need parked in a task status message, decoded ({@code {ok, need}} or {@code {ok:false, code}}); null when there is none. */
    public static Map<String, Object> readAuthRequiredNeed(Object task) {
        Object status = isObj(task) ? map(task).get("status") : null;
        Object msg = isObj(status) ? map(status).get("message") : null;
        Object md = isObj(msg) ? map(msg).get("metadata") : null;
        if (!isObj(md) || !map(md).containsKey(NEED_KEY)) return null;
        return decoded(map(md).get(NEED_KEY));
    }

    /** The answer message to put on the Task: a PCActn for exactly the parked need, plus the need's digest. */
    public static Map<String, Object> answerMessage(Object need, Object pcActn, Object messageId) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("role", "user");
        if (messageId != null) out.put("messageId", messageId);
        Map<String, Object> part = new LinkedHashMap<>();
        part.put("kind", "text");
        part.put("text", "authority provided");
        out.put("parts", new ArrayList<Object>(List.of(part)));
        Map<String, Object> md = new LinkedHashMap<>();
        md.put(PCA_A2A_EXTENSION_URI, pcActn);
        Map<String, Object> nd = new LinkedHashMap<>();
        nd.put("d", "atlas-pca/need/v1");
        nd.put("need", need);
        md.put(NEED_KEY, Pca.hashCanonical(nd)); // the digest is over whatever was given: the reference does not validate it here
        out.put("metadata", md);
        return out;
    }

    /**
     * The pure gate of {@link #resumeAuthRequired}, in the order the checks run. {@code proofAction}: pass {@link #NO_PROOF} for none; an action
     * that is a JSON null throws (the reference dereferences it). Returns the first refusal code, or null.
     */
    public static final Object NO_PROOF = new Object();

    public static String resumeGate(Object state, Object needEncoded, Object answerNeedDigest, Object proofAction) {
        if (!isAuthRequired(state)) return "task_not_auth_required";
        Map<String, Object> need = needEncoded == UNDEF ? null : A2a.decodeNeed(needEncoded).need;
        if (need == null) return "no_valid_need";
        if (!strictEq(answerNeedDigest, A2a.needDigest(need))) return "answer_not_bound_to_need";
        if (proofAction == NO_PROOF) return "no_proof";
        if (proofAction == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'verb')");
        if (!strictEq(jsonOf(opt(proofAction, "verb")), need.get("verb")) || !strictEq(jsonOf(opt(proofAction, "resource")), need.get("resource"))) return "action_mismatch";
        return null;
    }

    /** Does {@code next} (capability ids, root first) extend {@code prev}? */
    public static boolean chainExtends(List<?> prev, List<?> next) {
        if (next.size() < prev.size()) return false;
        for (int k = 0; k < prev.size(); k++) if (!strictEq(prev.get(k), next.get(k))) return false;
        return true;
    }

    /** The chain rule of {@link #verifyA2ADelegation}: {@code {ok:true}} or {@code {ok:false, failedHop, reason}}. */
    public static Map<String, Object> checkChainExtension(Object chainsO) {
        if (chainsO == null || chainsO == UNDEF) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'length')");
        // a string has a length and character "hops" (never arrays); other non-arrays have no length, so nothing is checked
        List<?> chains = chainsO instanceof List ? (List<?>) chainsO : chainsO instanceof String && !((String) chainsO).isEmpty() ? List.of(String.valueOf(((String) chainsO).charAt(0))) : List.of();
        for (int i = 0; i < chains.size(); i++) {
            Object ids = chains.get(i);
            if (!(ids instanceof List) || ((List<?>) ids).isEmpty()) return chainFail(i, "no_chain");
            if (i > 0 && !chainExtends((List<?>) chains.get(i - 1), (List<?>) ids)) return chainFail(i, "chain_does_not_extend_previous_hop");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        return m;
    }

    private static Map<String, Object> chainFail(int hop, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("failedHop", Long.valueOf(hop));
        m.put("reason", reason);
        return m;
    }

    /**
     * Resume a Task parked in AUTH_REQUIRED: only when the Task is in AUTH_REQUIRED, its status carries a decodable need, the answer cites that
     * need's digest, carries a PCActn for the need's exact verb and resource, and that PCActn passes the full verifier. {@code {ok:true, verification}} or {@code {ok:false, reason}}.
     */
    public static Map<String, Object> resumeAuthRequired(Object task, Object answer, VerifyOptions opts) {
        Object status = jsonOf(opt(task, "status"));
        Object smsg = isObj(status) ? map(status).get("message") : null;
        Object smd = isObj(smsg) ? map(smsg).get("metadata") : null;
        Map<String, Object> statusMd = isObj(smd) ? map(smd) : new LinkedHashMap<String, Object>();
        Object amd = isObj(answer) ? map(answer).get("metadata") : null;
        Map<String, Object> md = isObj(amd) ? map(amd) : new LinkedHashMap<String, Object>();
        Map<String, Object> p = extractPcaFromMessage(answer);
        Object state = isObj(status) ? map(status).get("state") : null;
        Object proofAction = p == null ? NO_PROOF : (p.containsKey("action") ? p.get("action") : NO_PROOF);
        String refusal = resumeGate(state, statusMd.containsKey(NEED_KEY) ? statusMd.get(NEED_KEY) : UNDEF, md.containsKey(NEED_KEY) ? md.get(NEED_KEY) : UNDEF, proofAction);
        Map<String, Object> out = new LinkedHashMap<>();
        if (refusal != null) { out.put("ok", false); out.put("reason", refusal); return out; }
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("id", jsonOf(opt(task, "id")));
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("state", "TASK_STATE_WORKING");
        t.put("status", st);
        Map<String, Object> tmd = new LinkedHashMap<>();
        tmd.put(PCA_A2A_EXTENSION_URI, p);
        t.put("metadata", tmd);
        Verification v = verifyA2ATask(t, opts);
        if (v.ok) { out.put("ok", true); out.put("verification", v.toMap()); }
        else { out.put("ok", false); out.put("reason", v.reason != null ? v.reason : "proof_rejected"); }
        return out;
    }

    /** One hop of {@link #verifyA2ADelegation}: the Task and the options (own audience and authority) it is verified under. */
    public static final class Hop {
        public final Object task;
        public final VerifyOptions opts;
        public Hop(Object task, VerifyOptions opts) { this.task = task; this.opts = opts; }
    }

    /**
     * Verify a chain of delegated Tasks, one per A2A hop. Every hop is verified on its own (own PCActn, audience and authority); each hop's
     * capability chain must EXTEND the previous hop's. Stops at the first failure; empty input fails closed.
     * Result: {@code {ok, failedHop?, reason?, chains}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyA2ADelegation(List<Hop> hops) {
        List<Object> chains = new ArrayList<>();
        Map<String, Object> out = new LinkedHashMap<>();
        if (hops.isEmpty()) { out.put("ok", false); out.put("reason", "no_hops"); out.put("chains", chains); return out; }
        for (int i = 0; i < hops.size(); i++) {
            Hop h = hops.get(i);
            Verification v = verifyA2ATask(h.task, h.opts);
            if (!v.ok) return hopFail(i, v.reason != null ? v.reason : "rejected", chains);
            Map<String, Object> p = extractPca(h.task);
            Object cc = p == null ? null : p.get("cap_chain");
            if (!(cc instanceof List)) return hopFail(i, "no_chain", chains);
            List<Object> ids = new ArrayList<>();
            for (Object c : (List<Object>) cc) ids.add(jsonOf(at(c, "id")));
            if (i > 0 && !chainExtends((List<Object>) chains.get(i - 1), ids)) return hopFail(i, "chain_does_not_extend_previous_hop", chains);
            chains.add(ids);
        }
        out.put("ok", true);
        out.put("chains", chains);
        return out;
    }

    private static Map<String, Object> hopFail(int hop, String reason, List<Object> chains) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("failedHop", Long.valueOf(hop));
        m.put("reason", reason);
        m.put("chains", chains);
        return m;
    }

    /** The per-task push token (A2A 3.1.7): a hash of the task id, the digest of the authorizing chain and a secret salt of at least 16 characters (else IllegalArgumentException). */
    public static String pcaPushToken(Object taskId, List<String> chainIds, Object salt) {
        if (!(salt instanceof String) || ((String) salt).length() < 16) throw new IllegalArgumentException("pcaPushToken: the salt must be a secret of at least 16 characters");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/a2a-push/v1");
        m.put("task_id", taskId);
        m.put("chain", PcaGrant.chainDigest(chainIds));
        m.put("salt", salt);
        return Pca.hashCanonical(m);
    }

    /**
     * Receiver-side check of a delivered push notification: the token must equal the one recomputed from the task, chain and salt, and the payload
     * must be about that task. {@code {ok:true}} or {@code {ok:false, reason}} (no_token, token_mismatch, task_mismatch). A short salt with a
     * presented token throws, as the reference does.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> checkPushNotification(String taskId, List<String> chainIds, Object salt, Object token, Object payload) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(token instanceof String) || ((String) token).isEmpty()) return pushFail("no_token");
        String want = pcaPushToken(taskId, chainIds, salt);
        if (!java.security.MessageDigest.isEqual(Json.utf8(want), Json.utf8(((String) token)))) return pushFail("token_mismatch");
        String r = A2a.checkPush(taskId, chainIds, (String) salt, token, payload);
        if (r != null) return pushFail(r);
        out.put("ok", true);
        return out;
    }

    private static Map<String, Object> pushFail(String reason) { return refuse(reason); }

    /** The one error A2A servers return for "no such task" and "not yours" alike (no existence leak). */
    public static Map<String, Object> uniformTaskNotFound() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("code", "TaskNotFoundError");
        m.put("message", "task not found");
        return m;
    }

    // ------------------------------------------------------------------------------------------------ signed task-update receipts

    /** The content address the next receipt cites as {@code prev}. */
    public static String receiptDigest(Object r) { return A2a.receiptDigest(r); }

    /**
     * Sign a receipt with an Ed25519 seed. {@code prev}: the previous receipt of the same task (null for the first). Throws IllegalArgumentException on
     * malformed input, a task id mismatch or a terminal {@code prev}.
     */
    public static Map<String, Object> signTaskReceipt(byte[] secret, Object taskId, Object state, List<String> chainIds, Object issuedAt, Map<String, Object> prev) {
        if (!(taskId instanceof String) || ((String) taskId).isEmpty() || ((String) taskId).length() > 256 || !in(STATES, state)
            || !safeNat(issuedAt) || chainIds.isEmpty()) throw new IllegalArgumentException("signTaskReceipt: malformed input");
        if (prev != null && (!strictEq(prev.get("task_id"), taskId) || in(TERMINAL, prev.get("state")))) throw new IllegalArgumentException("signTaskReceipt: prev is for another task or already terminal");
        if (prev != null && !safeNat(prev.get("seq"))) throw new IllegalArgumentException("signTaskReceipt: prev has no valid seq");
        Keys.EdKey key = Keys.edFromSeed(secret);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", new Json.Num("1"));
        body.put("task_id", taskId);
        body.put("state", state);
        body.put("seq", prev != null ? new Json.Num(Long.toString(Json.asLong(prev.get("seq")) + 1)) : new Json.Num("0"));
        body.put("prev", prev != null ? A2a.receiptDigest(prev) : null);
        body.put("chain", PcaGrant.chainDigest(chainIds));
        body.put("issued_at", issuedAt);
        body.put("signer", key.id());
        byte[] dom = A2A_RECEIPT_DOMAIN.getBytes(StandardCharsets.UTF_8), cb = Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[dom.length + cb.length];
        System.arraycopy(dom, 0, msg, 0, dom.length);
        System.arraycopy(cb, 0, msg, dom.length, cb.length);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", Keys.b64u(key.sign(msg)));
        return out;
    }

    /** Well formed and signed by {@code signer} (the key the receiver pinned) over exactly its content. Never throws. */
    public static boolean verifyTaskReceipt(Object r, String signer) { return A2a.verifyReceipt(r, signer); }

    /** Check an ordered list of receipts for one task: {@code {ok:true, last, terminal}} or {@code {ok:false, code, at?}}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> checkReceiptChain(Object receipts, String signer, String taskId, List<String> chainIds) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(receipts instanceof List) || ((List<Object>) receipts).isEmpty()) { out.put("ok", false); out.put("code", "empty"); return out; }
        List<Object> l = (List<Object>) receipts;
        A2a.ReceiptChain c = A2a.checkReceiptChain(l, signer, taskId, chainIds);
        if (c.code != null) {
            out.put("ok", false);
            out.put("code", c.code);
            out.put("at", Long.valueOf(c.at));
            return out;
        }
        out.put("ok", true);
        out.put("last", l.get(l.size() - 1));
        out.put("terminal", c.terminal);
        return out;
    }

    /** May a workflow start its next step because of this task? Only on a verified, unbroken receipt chain ending in COMPLETED. */
    @SuppressWarnings("unchecked")
    public static boolean mayTriggerNext(Object receipts, String signer, String taskId, List<String> chainIds) {
        return receipts instanceof List && !((List<Object>) receipts).isEmpty() && A2a.mayTriggerNext((List<Object>) receipts, signer, taskId, chainIds);
    }

    /** Put a receipt on a status update or message metadata (a copy). */
    public static Map<String, Object> attachReceipt(Object carrier, Object r) {
        if (carrier == null || carrier == UNDEF) throw new IllegalStateException("TypeError: Cannot read properties of null (reading 'metadata')");
        Map<String, Object> out = spread(carrier);
        Object md = out.get("metadata");
        Map<String, Object> m = spread(md == null ? new LinkedHashMap<String, Object>() : md);
        m.put(RECEIPT_KEY, r);
        out.put("metadata", m);
        return out;
    }

    /** The receipt carried by a push / stream payload ({@code statusUpdate.metadata}, {@code task.metadata}, {@code message.metadata}), or null. Unverified. */
    public static Object receiptOfPayload(Object payload) {
        if (!isObj(payload)) return null;
        for (String k : new String[] {"statusUpdate", "task", "message"}) {
            Object c = map(payload).get(k);
            Object md = isObj(c) ? map(c).get("metadata") : null;
            if (isObj(md) && map(md).containsKey(RECEIPT_KEY)) return map(md).get(RECEIPT_KEY);
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------------ extended Agent Card

    private static Object policyKey(Object v) { return v == UNDEF ? "\u0000undefined" : "v:" + Json.canonicalize(v); }

    private static Object defaultVerbOf(Object s) {
        Object tags = at(s, "tags");
        if (tags == UNDEF || tags == null) return UNDEF;
        if (!(tags instanceof List)) throw new IllegalStateException("TypeError: tags.find is not a function");
        for (Object x : (List<?>) tags) if (x instanceof String && ((String) x).startsWith("pca-verb:")) return ((String) x).substring("pca-verb:".length());
        return UNDEF;
    }

    /**
     * The extended Agent Card from a residual policy (A2A 3.1.11, 13.3): lists the hidden skills a caller may attempt. {@code o}: {@code authenticated}
     * (must be true), {@code hiddenSkills}, {@code envelopes} ({@code verb, status, policyDigest}); {@code verbOf} maps a skill to its PCA verb
     * (null: the skill's {@code pca-verb:<verb>} tag). A verb with no envelope, or a denied one, reveals nothing. The result is unsigned.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> extendedAgentCard(Object publicCard, Map<String, Object> o, Function<Object, String> verbOf) {
        if (!Boolean.TRUE.equals(o.get("authenticated"))) throw new IllegalStateException("extendedAgentCard: the caller must be authenticated (A2A 13.3)");
        List<Object> envelopes = (List<Object>) o.get("envelopes");
        List<Object> hidden = (List<Object>) o.get("hiddenSkills");
        Map<Object, Object> digests = new LinkedHashMap<>();
        for (Object e : envelopes) { Object d = at(e, "policyDigest"); digests.putIfAbsent(policyKey(d), d); }
        if (digests.size() > 1) throw new IllegalArgumentException("extendedAgentCard: envelopes were computed against different policies");
        Map<String, Object> byVerb = new LinkedHashMap<>();
        for (Object e : envelopes) { Object v = at(e, "verb"); if (v instanceof String) byVerb.put((String) v, e); }
        List<Object> revealed = new ArrayList<>();
        for (Object s : hidden) {
            Object verb;
            if (verbOf != null) { String vs = verbOf.apply(s); verb = vs == null ? UNDEF : vs; } else verb = defaultVerbOf(s);
            Object env = verb instanceof String ? byVerb.get(verb) : null;
            if (env == null || "denied".equals(at(env, "status"))) continue;
            Map<String, Object> sk = spread(s);
            Object tags = at(s, "tags");
            List<Object> nt = tags == UNDEF || tags == null ? new ArrayList<>() : spreadList(tags);
            nt.add("autonomous".equals(at(env, "status")) ? "pca:autonomous" : "pca:needs-approval");
            sk.put("tags", nt);
            revealed.add(sk);
        }
        if (publicCard == null) throw new IllegalStateException("TypeError: cannot destructure null");
        Map<String, Object> rest = spread(publicCard);
        rest.remove("signatures");
        Object capsO = rest.get("capabilities");
        Map<String, Object> caps = spread(capsO == null ? new LinkedHashMap<String, Object>() : capsO);
        Object extsO = caps.get("extensions");
        List<Object> exts = extsO instanceof List ? (List<Object>) extsO : new ArrayList<>();
        Object policyDigest = digests.isEmpty() ? UNDEF : digests.values().iterator().next();
        List<Object> next = new ArrayList<>();
        for (Object e : exts) {
            if (policyDigest != UNDEF && PCA_A2A_EXTENSION_URI.equals(at(e, "uri") == UNDEF ? null : at(e, "uri"))) {
                Map<String, Object> ne = spread(e);
                Object pm = at(e, "params");
                Map<String, Object> np = spread(pm == UNDEF || pm == null ? new LinkedHashMap<String, Object>() : pm);
                np.put("policy_digest", policyDigest);
                ne.put("params", np);
                next.add(ne);
            } else {
                next.add(e);
            }
        }
        Object skillsO = rest.get("skills");
        List<Object> skills = skillsO instanceof List ? new ArrayList<>((List<Object>) skillsO) : new ArrayList<>();
        skills.addAll(revealed);
        caps.put("extensions", next);
        rest.put("capabilities", caps);
        rest.put("skills", skills);
        return rest;
    }

    public static Map<String, Object> extendedAgentCard(Object publicCard, Map<String, Object> o) { return extendedAgentCard(publicCard, o, null); }
}
