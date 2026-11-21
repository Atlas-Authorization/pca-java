package net.atlasauth.pca;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * Rotation-safe key trust for Azure MAA token-signing keys. The MAA instance signing certificates rotate, so a hard-coded pin silently
 * breaks; this derives the SPKI pins a verifier needs from a freshly fetched {@code <issuer>/certs} key set under an explicit rotation
 * policy, persists the accepted set, and fails closed when the policy is violated.
 *
 * <ul>
 * <li>Network I/O happens only when the caller asks ({@link #fetchMaaCerts}, {@link Trust#getTrustAnchors}), only for https issuers named in
 * {@code policy.trustedIssuers}, through an INJECTED {@link Fetch} (which must not follow redirects), with a hard timeout and a hard size limit.</li>
 * <li>Every certificate that contributes an anchor is validated: a self-signed instance certificate has a subject that is exactly
 * {@code CN=<issuer URL>}, is genuinely self-signed, inside its validity window (+skew), no older than {@code maxKeyAgeMs} and uses RSA 2048..8192
 * or EC P-256 / P-384 / P-521; a Microsoft-chained key is accepted only through a pinned root (and, when pinned, a pinned intermediate, which then
 * becomes the anchor) with an allowed leaf CN.</li>
 * <li>The accepted set changes only by rotation: at most {@code maxNewKeysPerFetch} unseen keys per fetch and, by default, one key in common with
 * the previous unexpired set; a total replacement needs an operator-signed re-pin manifest. Without persisted state the baseline is the release-signed
 * built-in pins ({@link AttestMaaPins}), explicit {@code initialPins}, a signed re-pin, or the explicit trust-on-first-use opt-in.</li>
 * <li>A transport failure serves the last accepted set for at most {@code maxStaleMs}; a policy violation never falls back to stale data.</li>
 * </ul>
 */
public final class AttestMaaKeys {
    private AttestMaaKeys() {}

    private static final double HOUR = 3_600_000, DAY = 24 * HOUR;
    private static final Pattern ISSUER_URL = Pattern.compile("https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final int MAX_JWKS_KEYS = 32, MAX_X5C = 8, MAX_X5C_B64 = 131_072;
    private static final Set<String> EC_CURVES = Set.of("prime256v1", "secp384r1", "secp521r1");

    // ------------------------------------------------------------- persistence

    /** Caller-supplied persistence of the accepted key sets (a state is {v, issuer, fetchedAtMs, anchors}). */
    public interface StateStore {
        /** The raw stored state of an issuer, or null. */
        Object get(String issuer);

        void set(String issuer, Object state);
    }

    /** An in-memory store (tests, a single process); production callers persist durably. */
    public static final class MemoryStateStore implements StateStore {
        private final Map<String, Object> m = new LinkedHashMap<>();

        @Override public synchronized Object get(String issuer) { return m.get(issuer); }

        @Override public synchronized void set(String issuer, Object state) { m.put(issuer, deepCopy(state)); }

        public synchronized Map<String, Object> snapshot() { return new LinkedHashMap<>(m); }
    }

    public static MemoryStateStore createMemoryMaaKeyStateStore() { return new MemoryStateStore(); }

    /**
     * Persist the accepted key sets in an atomic key / value store. Writes are atomic read-modify-write and monotone in {@code fetchedAtMs}: a
     * stale writer never moves the stored state backwards. A corrupt stored record is returned as it is, so the trust fails closed
     * ({@code corrupt-state}); a corrupt previous record is overwritten.
     */
    public static StateStore durableMaaKeyStateStore(AtomicKv kv) {
        return new StateStore() {
            private String k(String issuer) { return "maa-keys/" + issuer; }

            @Override public Object get(String issuer) { return kv.get(k(issuer)); }

            @Override public void set(String issuer, Object state) {
                Double sf = state instanceof Map ? IntentJs.num(((Map<?, ?>) state).get("fetchedAtMs")) : null;
                kv.update(k(issuer), prev -> {
                    Map<String, Object> p = prev == null ? null : parseState(prev, issuer);
                    return p != null && sf != null && IntentJs.num(p.get("fetchedAtMs")) > sf ? null : state;
                });
            }
        };
    }

    // ------------------------------------------------------------- guarded fetch

    /** An HTTP answer of the injected transport: {@code url} is the final URL (null / empty when not known), {@code contentLength} the declared header. */
    public static final class Response {
        public final int status;
        public final String url;
        public final Double contentLength;
        public final byte[] body;

        public Response(int status, String url, Double contentLength, byte[] body) {
            this.status = status;
            this.url = url;
            this.contentLength = contentLength;
            this.body = body;
        }
    }

    /** The injected GET transport. It must refuse redirects (a redirect is an error, never followed). */
    @FunctionalInterface
    public interface Fetch {
        Response get(String url) throws Exception;
    }

    /** {@code fetch(issuer + "/certs")} with the https-only issuer check, a size limit and a timeout. Throws on any problem. */
    public static Map<String, Object> fetchMaaCerts(String issuer, Fetch fetch, Double timeoutMs, Double maxBytes) {
        if (fetch == null) throw new IllegalArgumentException("fetchMaaCerts: a fetch implementation must be injected");
        if (issuer == null || !ISSUER_URL.matcher(issuer).matches()) throw new IllegalArgumentException("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)");
        double timeout = timeoutMs == null ? 10_000 : timeoutMs;
        double max = maxBytes == null ? 1_048_576 : maxBytes;
        String url = issuer + "/certs";
        CompletableFuture<Object> work = CompletableFuture.supplyAsync(() -> {
            try {
                Response res = fetch.get(url);
                if (res.status < 200 || res.status > 299) throw new IllegalStateException("MAA certs fetch failed: HTTP " + res.status);
                if (res.url != null && !res.url.isEmpty() && !res.url.equals(url)) throw new IllegalStateException("MAA certs fetch: response URL differs from the request (redirect)");
                double declared = res.contentLength == null ? 0 : res.contentLength;
                if (!Double.isNaN(declared) && !Double.isInfinite(declared) && declared > max) throw new IllegalStateException("MAA certs response exceeds the size limit");
                byte[] bytes = res.body == null ? new byte[0] : res.body;
                if (bytes.length > max) throw new IllegalStateException("MAA certs response exceeds the size limit");
                Object parsed;
                try {
                    String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes)).toString();
                    if (text.startsWith("﻿")) text = text.substring(1); // TextDecoder consumes one BOM
                    parsed = Json.parseLenient(text);
                } catch (CharacterCodingException | RuntimeException e) {
                    throw new IllegalStateException("MAA certs response is not valid UTF-8 JSON");
                }
                return parseJwks(parsed);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e.getMessage() == null ? "fetch error" : e.getMessage(), e);
            }
        });
        try {
            @SuppressWarnings("unchecked") Map<String, Object> out = (Map<String, Object>) work.get((long) Math.max(0, Math.min(timeout, Long.MAX_VALUE / 2.0)), TimeUnit.MILLISECONDS);
            return out;
        } catch (TimeoutException e) {
            work.cancel(true);
            throw new IllegalStateException("MAA certs fetch timed out after " + AttestCommon.jsNumString(timeout) + " ms");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("MAA certs fetch interrupted");
        } catch (ExecutionException e) {
            Throwable c = e.getCause() == null ? e : e.getCause();
            throw new IllegalStateException(c.getMessage() == null ? "fetch error" : c.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseJwks(Object x) {
        if (!(x instanceof Map) || !(((Map<String, Object>) x).get("keys") instanceof List)) throw new IllegalStateException("MAA certs: response has no keys array");
        List<Object> raw = (List<Object>) ((Map<String, Object>) x).get("keys");
        if (raw.size() > MAX_JWKS_KEYS) throw new IllegalStateException("MAA certs: too many keys");
        List<Object> keys = new ArrayList<>();
        for (Object k : raw) {
            if (!(k instanceof Map) && !(k instanceof List)) throw new IllegalStateException("MAA certs: malformed key entry");
            Map<String, Object> r = k instanceof Map ? (Map<String, Object>) k : new LinkedHashMap<>();
            Object x5c = r.get("x5c");
            boolean ok = x5c instanceof List && !((List<?>) x5c).isEmpty() && ((List<?>) x5c).size() <= MAX_X5C;
            if (ok) for (Object c : (List<?>) x5c) if (!(c instanceof String) || ((String) c).isEmpty() || ((String) c).length() > MAX_X5C_B64) ok = false;
            if (!ok) throw new IllegalStateException("MAA certs: key without a well-formed x5c");
            Map<String, Object> key = new LinkedHashMap<>();
            for (String f : new String[] {"kid", "kty", "alg"}) if (r.get(f) instanceof String) key.put(f, r.get(f));
            key.put("x5c", new ArrayList<Object>((List<Object>) x5c));
            keys.add(key);
        }
        return Issue.obj("keys", keys);
    }

    // ------------------------------------------------------------- JWKS evaluation

    private static String spkiOf(AttCert c) { return AttestCert.keyOfCert(c).spkiSha256(); }

    /** The CN when the subject is exactly one CN attribute, else null. */
    private static String soleCn(String subject) {
        List<String> lines = new ArrayList<>();
        for (String l : subject.split("\n", -1)) if (!l.isEmpty()) lines.add(l);
        if (lines.size() != 1 || !lines.get(0).startsWith("CN=")) return null;
        String v = lines.get(0).substring(3);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\r' || c == ' ' || c == ' ') return null; // a JavaScript "." does not match these
        }
        return v;
    }

    private static String leafCn(String subject) {
        for (String l : subject.split("\n", -1)) if (l.startsWith("CN=")) return l.substring(3);
        return null;
    }

    private static String keyStrengthError(AttCert c) {
        CertKey k = AttestCert.keyOfCert(c);
        if (k.typ.equals("rsa")) {
            int bits = ((RSAPublicKey) k.pub).getModulus().bitLength();
            if (!(bits >= 2048 && bits <= 8192)) return "RSA key size " + bits + " outside 2048..8192";
            return CertKey.rsaKeyOk(k.pub) ? null : "RSA public exponent must be odd, at least 3 and at most 32 bits";
        }
        if (k.typ.equals("ec")) return EC_CURVES.contains(k.curve) ? null : "EC curve '" + k.curve + "' not allowed";
        return "key type '" + k.typ + "' not allowed";
    }

    private static boolean safeVerify(AttCert child, CertKey k) {
        try {
            return CertKey.rsaKeyOk(k.pub) && AttestCert.certSigOk(child, k);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean linkOk(AttCert child, AttCert parent) { return safeVerify(child, AttestCert.keyOfCert(parent)); }

    private static double numOr(Map<String, Object> m, String k, double d) {
        Object v = m.get(k);
        if (v == null) return d;
        Double n = IntentJs.num(v);
        return n == null ? Double.NaN : n;
    }

    private static Set<String> lowerSet(Object l) {
        Set<String> out = new HashSet<>();
        if (l instanceof List) for (Object s : (List<?>) l) out.add(String.valueOf(s).toLowerCase(java.util.Locale.ROOT));
        return out;
    }

    private static Map<String, Object> acc(String spki, String kind, long from, long to) {
        return Issue.obj("spki", spki, "kind", kind, "notBeforeMs", Long.valueOf(from), "notAfterMs", Long.valueOf(to));
    }

    /**
     * Validate every key of a JWKS against the policy at {@code nowMs}: {accepted: [{spki, kind, notBeforeMs, notAfterMs}], rejected: [{kid,
     * reason}]}. A certificate that does not parse is rejected with the parser's text.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> evaluateMaaJwks(Object jwks, String issuer, Map<String, Object> policy, double nowMs) {
        double skew = numOr(policy, "clockSkewMs", 60_000), maxAge = numOr(policy, "maxKeyAgeMs", 400 * DAY);
        Set<String> roots = lowerSet(policy.get("chainRootSpkiSha256")), inters = lowerSet(policy.get("chainIntermediateSpkiSha256"));
        Map<String, Map<String, Object>> accepted = new LinkedHashMap<>();
        List<Object> rejected = new ArrayList<>();
        Object keysO = jwks instanceof Map ? ((Map<String, Object>) jwks).get("keys") : null;
        if (keysO != null && !(keysO instanceof List)) throw new IllegalArgumentException("jwks.keys is not iterable");
        List<Object> keys = keysO == null ? new ArrayList<>() : (List<Object>) keysO;
        for (int i = 0; i < keys.size(); i++) {
            if (!(keys.get(i) instanceof Map)) throw new IllegalArgumentException("Cannot read properties of a non-object (reading 'kid')");
            Map<String, Object> key = (Map<String, Object>) keys.get(i);
            Object kidO = key.get("kid");
            String kid = kidO == null ? "#" + i : kidO instanceof String ? (String) kidO : String.valueOf(kidO);
            try {
                if (!Double.isFinite(nowMs) || !Double.isFinite(skew)) throw new AttestException("clock and skew must be finite");
                Object x5c = key.get("x5c");
                if (!(x5c instanceof List) || ((List<?>) x5c).isEmpty()) {
                    rejected.add(Issue.obj("kid", kid, "reason", "no x5c"));
                    continue;
                }
                List<AttCert> certs = new ArrayList<>();
                for (Object e : (List<?>) x5c) {
                    if (!(e instanceof String)) throw new AttestException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received " + e);
                    certs.add(AttestCert.parseCertDer(AttestCommon.nodeB64((String) e)));
                }
                AttCert leaf = certs.get(0);
                long[][] val = new long[certs.size()][2];
                for (int j = 0; j < certs.size(); j++) {
                    AttestDer.DerInstant[] v = AttestDer.derValidity(certs.get(j).raw);
                    if (!v[0].ok || !v[1].ok) throw new AttestException("cert " + j + ": unparsable validity");
                    if (!(Double.isFinite(nowMs) && Double.isFinite(skew) && nowMs + skew >= v[0].ms)) throw new AttestException("cert " + j + ": not yet valid");
                    if (!(nowMs - skew <= v[1].ms)) throw new AttestException("cert " + j + ": expired");
                    val[j][0] = v[0].ms;
                    val[j][1] = v[1].ms;
                }
                long lvFrom = val[0][0], lvTo = val[0][1];
                String strength = keyStrengthError(leaf);
                if (strength != null) throw new AttestException(strength);
                String subject = AttestCommon.nameText(leaf.rawSubject);
                if (certs.size() == 1) {
                    if (!(nowMs - lvFrom <= maxAge)) throw new AttestException("key older than maxKeyAgeMs");
                    String cn = soleCn(subject);
                    if (cn == null) throw new AttestException("subject is not a single CN");
                    if (cn.contains("*")) throw new AttestException("wildcard CN rejected");
                    if (!cn.equals(issuer)) throw new AttestException("subject CN does not equal the issuer URL");
                    if (!AttestCommon.nameText(leaf.rawIssuer).equals(subject) || !safeVerify(leaf, AttestCert.keyOfCert(leaf))) throw new AttestException("not a genuine self-signed cert");
                    String spki = spkiOf(leaf);
                    accepted.put(spki, acc(spki, "self-signed", lvFrom, lvTo));
                    continue;
                }
                if (roots.isEmpty()) throw new AttestException("chained key ignored (no chainRootSpkiSha256 configured)");
                for (int j = 0; j < certs.size() - 1; j++) if (!linkOk(certs.get(j), certs.get(j + 1))) throw new AttestException("chain link " + j + " is not signed by the next cert");
                String profile = AttestDer.strictChainErrorOf(certs);
                if (!profile.isEmpty()) throw new AttestException("chain profile: " + profile);
                AttCert top = certs.get(certs.size() - 1);
                if (!AttestCommon.nameText(top.rawIssuer).equals(AttestCommon.nameText(top.rawSubject)) || !safeVerify(top, AttestCert.keyOfCert(top))) throw new AttestException("chain does not end in a self-signed root");
                String rootSpki = spkiOf(top);
                if (!roots.contains(rootSpki)) throw new AttestException("chain root is not pinned");
                if (policy.get("chainLeafCn") != null) {
                    String lc = leafCn(subject);
                    boolean allowed = false;
                    Object cl = policy.get("chainLeafCn");
                    if (cl instanceof List) for (Object a : (List<?>) cl) if ((lc == null ? "\u0000" : lc).equals(a)) allowed = true;
                    if (!allowed) throw new AttestException("chained leaf CN not allowed");
                }
                String anchorSpki = rootSpki, anchorKind = "chained-root";
                long anchorFrom = val[certs.size() - 1][0], anchorTo = val[certs.size() - 1][1];
                if (!inters.isEmpty()) {
                    int mid = -1;
                    for (int j = 1; j < certs.size() - 1; j++) if (inters.contains(spkiOf(certs.get(j)))) { mid = j; break; }
                    if (mid < 0) throw new AttestException("chain does not pass through a pinned intermediate");
                    anchorSpki = spkiOf(certs.get(mid));
                    anchorKind = "chained-intermediate";
                    anchorFrom = val[mid][0];
                    anchorTo = val[mid][1];
                }
                Map<String, Object> prev = accepted.get(anchorSpki);
                long nb = prev == null ? anchorFrom : Math.min((Long) prev.get("notBeforeMs"), anchorFrom);
                long na = Math.min(anchorTo, Math.max(prev == null ? 0L : (Long) prev.get("notAfterMs"), lvTo));
                accepted.put(anchorSpki, acc(anchorSpki, anchorKind, nb, na));
            } catch (RuntimeException e) {
                rejected.add(Issue.obj("kid", kid, "reason", e.getMessage() == null ? "invalid key" : e.getMessage()));
            }
        }
        return Issue.obj("accepted", new ArrayList<Object>(accepted.values()), "rejected", rejected);
    }

    // ------------------------------------------------------------- trust store

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    private static boolean intNotNegZero(Object o) { return IntentJs.isSafeInteger(o) && !IntentJs.isNegZero(IntentJs.num(o)); }

    /** The persisted state as a validated record, or null when it is not one. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseState(Object x, String issuer) {
        if (!(x instanceof Map)) return null;
        Map<String, Object> s = (Map<String, Object>) x;
        Double v = IntentJs.num(s.get("v"));
        if (v == null || v != 1 || !issuer.equals(s.get("issuer")) || !intNotNegZero(s.get("fetchedAtMs")) || !(s.get("anchors") instanceof List)) return null;
        List<Object> anchors = new ArrayList<>();
        for (Object ao : (List<Object>) s.get("anchors")) {
            if (!(ao instanceof Map)) return null;
            Map<String, Object> r = (Map<String, Object>) ao;
            if (!(r.get("spki") instanceof String) || !HEX64.matcher((String) r.get("spki")).matches()) return null;
            Object kind = r.get("kind");
            if (!"self-signed".equals(kind) && !"chained-root".equals(kind) && !"chained-intermediate".equals(kind)) return null;
            for (String f : new String[] {"notBeforeMs", "notAfterMs", "firstSeenMs"}) if (!intNotNegZero(r.get(f))) return null;
            anchors.add(Issue.obj("spki", r.get("spki"), "kind", kind, "notBeforeMs", r.get("notBeforeMs"), "notAfterMs", r.get("notAfterMs"), "firstSeenMs", r.get("firstSeenMs")));
        }
        return Issue.obj("v", Long.valueOf(1), "issuer", issuer, "fetchedAtMs", s.get("fetchedAtMs"), "anchors", anchors);
    }

    private static Map<String, Object> failT(String code, String reason) { return Issue.obj("ok", false, "code", code, "reason", reason); }

    /** A trust store over a policy, a state store and an injected transport. */
    public static final class Trust {
        private final Map<String, Object> policy;
        private final StateStore store;
        private final Fetch fetch;
        private final Set<String> trusted = new HashSet<>();
        private final double ttl, maxStale, maxNew, maxInitial, skew;
        private final boolean requireOverlap;

        @SuppressWarnings("unchecked")
        private Trust(Map<String, Object> policyIn, StateStore store, Fetch fetch) {
            if (fetch == null) throw new IllegalArgumentException("createMaaKeyTrust: fetch must be injected");
            policy = (Map<String, Object>) deepCopy(policyIn == null ? new LinkedHashMap<String, Object>() : policyIn); // later edits must not change what this trust enforces
            Object ti = policy.get("trustedIssuers");
            boolean bad = !(ti instanceof List) || ((List<?>) ti).isEmpty();
            if (!bad) for (Object i : (List<?>) ti) if (!(i instanceof String) || !ISSUER_URL.matcher((String) i).matches()) bad = true;
            if (bad) throw new IllegalArgumentException("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs");
            for (Object i : (List<?>) ti) trusted.add((String) i);
            this.store = store;
            this.fetch = fetch;
            ttl = numOr(policy, "ttlMs", HOUR);
            maxStale = numOr(policy, "maxStaleMs", DAY);
            maxNew = numOr(policy, "maxNewKeysPerFetch", 2);
            maxInitial = numOr(policy, "maxInitialKeys", 8);
            skew = numOr(policy, "clockSkewMs", 60_000);
            if (!Double.isFinite(ttl) || !Double.isFinite(skew) || Double.isNaN(maxStale) || Double.isNaN(maxNew) || Double.isNaN(maxInitial)) throw new IllegalArgumentException("createMaaKeyTrust: ttlMs and clockSkewMs must be finite; maxStaleMs and the key-count limits must not be NaN");
            requireOverlap = policy.get("requireOverlap") == null || Boolean.TRUE.equals(policy.get("requireOverlap"));
        }

        private boolean live(Map<String, Object> r, double nowMs) {
            return Double.isFinite(nowMs) && Double.isFinite(skew) && nowMs - skew <= IntentJs.num(r.get("notAfterMs")) && nowMs + skew >= IntentJs.num(r.get("notBeforeMs"));
        }

        @SuppressWarnings("unchecked")
        private List<Map<String, Object>> filter(List<Object> anchors, double nowMs, Set<String> denied) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object o : anchors) {
                Map<String, Object> r = (Map<String, Object>) o;
                if (live(r, nowMs) && !denied.contains((String) r.get("spki"))) out.add(r);
            }
            return out;
        }

        private Map<String, Object> build(String source, List<Map<String, Object>> anchors, List<String> newKeys, List<String> removed, List<Object> rejected) {
            List<String> spkis = new ArrayList<>(new TreeMap<String, Boolean>(spkiMap(anchors)).keySet());
            if (spkis.isEmpty()) return failT("no-valid-keys", "no unexpired, un-revoked signing keys remain");
            return Issue.obj("ok", true, "trustAnchors", Issue.obj("rootSpkiSha256", new ArrayList<Object>(spkis)), "source", source, "anchors", new ArrayList<Object>(anchors),
                "newKeys", new ArrayList<Object>(newKeys), "removedKeys", new ArrayList<Object>(removed), "rejected", rejected);
        }

        private static Map<String, Boolean> spkiMap(List<Map<String, Object>> anchors) {
            Map<String, Boolean> m = new LinkedHashMap<>();
            for (Map<String, Object> a : anchors) m.put((String) a.get("spki"), Boolean.TRUE);
            return m;
        }

        /**
         * The SPKI pins the issuer's token-signing keys currently validate under. {@code repin} ({manifest, verify}) is an operator-signed
         * allowlist manifest carrying {@code maa-signing-spki} entries labelled with the issuer URL ({@code verify}: its verification options,
         * {@code nowMs} supplied here). Returns {ok: true, trustAnchors: {rootSpkiSha256}, source, anchors, newKeys, removedKeys, rejected} or {ok: false,
         * code, reason}; never throws.
         */
        @SuppressWarnings("unchecked")
        public Map<String, Object> getTrustAnchors(String issuer, Object nowObj, Map<String, Object> repin) {
            try {
                if (!trusted.contains(issuer)) return failT("untrusted-issuer", "issuer is not in policy.trustedIssuers");
                if (!IntentJs.isSafeInteger(nowObj)) return failT("clock-regression", "nowMs must be an integer");
                double nowMs = IntentJs.num(nowObj);
                Set<String> approved = new LinkedHashSet<>(), denied = new HashSet<>();
                if (repin != null) {
                    Map<String, Object> vo = new LinkedHashMap<>();
                    Object verify = repin.get("verify");
                    if (verify instanceof Map) vo.putAll((Map<String, Object>) verify);
                    vo.put("nowMs", nowObj);
                    Map<String, Object> v = AttestAllowlist.verifyAllowlistManifest(repin.get("manifest"), vo);
                    if (!Boolean.TRUE.equals(v.get("ok"))) return failT("repin-invalid", v.get("code") + ": " + v.get("reason"));
                    Map<String, Object> po = new LinkedHashMap<>();
                    po.put("nowMs", nowObj);
                    Map<String, Object> p = AttestAllowlist.projectAllowlist(v, po);
                    Object here = ((Map<String, Object>) p.get("maaSigningSpkis")).get(issuer);
                    if (here != null) for (Object s : (List<Object>) here) approved.add((String) s);
                    for (Object ro : (List<Object>) p.get("revoked")) {
                        Map<String, Object> r = (Map<String, Object>) ro;
                        if ("maa-signing-spki".equals(r.get("kind")) && issuer.equals(r.get("label"))) denied.add((String) r.get("value"));
                    }
                }
                Map<String, Object> effPolicy = policy;
                List<String> builtinBaseline = new ArrayList<>();
                String builtinReason = null;
                Object bp = policy.get("builtinPins");
                if (!Boolean.FALSE.equals(bp)) {
                    Map<String, Object> lo = new LinkedHashMap<>();
                    lo.put("nowMs", nowObj);
                    if (bp instanceof Map) lo.put("source", bp);
                    Map<String, Object> b = AttestMaaPins.loadBuiltinMaaPins(lo);
                    if (Boolean.TRUE.equals(b.get("ok"))) {
                        Object bs = ((Map<String, Object>) b.get("maaSigningSpkis")).get(issuer);
                        if (bs != null) for (Object s : (List<Object>) bs) builtinBaseline.add((String) s);
                        Object rv = ((Map<String, Object>) b.get("revokedSigningSpkis")).get(issuer);
                        if (rv != null) for (Object s : (List<Object>) rv) denied.add((String) s);
                        effPolicy = new LinkedHashMap<>(policy);
                        if (policy.get("chainRootSpkiSha256") == null) effPolicy.put("chainRootSpkiSha256", b.get("maaChainRootSpkis"));
                        if (policy.get("chainIntermediateSpkiSha256") == null) effPolicy.put("chainIntermediateSpkiSha256", b.get("maaChainIntermediateSpkis"));
                        if (policy.get("chainLeafCn") == null) effPolicy.put("chainLeafCn", new ArrayList<Object>(AttestMaaPins.BUILTIN_CHAIN_LEAF_CN));
                        // the pinned Microsoft intermediate only counts for issuers the release actually pinned
                        if (!builtinBaseline.isEmpty()) for (Object s : (List<Object>) b.get("maaChainIntermediateSpkis")) builtinBaseline.add((String) s);
                    } else builtinReason = (String) b.get("reason");
                }

                Object rawState = store.get(issuer);
                Map<String, Object> state = null;
                if (rawState != null) {
                    state = parseState(rawState, issuer);
                    if (state == null) return failT("corrupt-state", "persisted MAA key state failed validation");
                    if (!(nowMs >= IntentJs.num(state.get("fetchedAtMs")) - skew)) return failT("clock-regression", "clock is behind the last persisted fetch time");
                }
                double stateFetched = state == null ? 0 : IntentJs.num(state.get("fetchedAtMs"));

                if (state != null && Double.isFinite(ttl) && nowMs - stateFetched < ttl && nowMs >= stateFetched) {
                    List<Map<String, Object>> a = filter((List<Object>) state.get("anchors"), nowMs, denied);
                    if (!a.isEmpty()) return build("cache", a, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
                }

                Map<String, Object> jwks;
                try {
                    jwks = fetchMaaCerts(issuer, fetch, policy.get("fetchTimeoutMs") == null ? null : IntentJs.num(policy.get("fetchTimeoutMs")),
                        policy.get("maxBodyBytes") == null ? null : IntentJs.num(policy.get("maxBodyBytes")));
                } catch (RuntimeException e) {
                    String why = e.getMessage() == null ? "fetch error" : e.getMessage();
                    if (state == null) return failT("fetch-failed", why + "; no cached key set");
                    if (!(nowMs - stateFetched <= maxStale)) return failT("stale-exceeded", why + "; cached set is older than maxStaleMs");
                    List<Map<String, Object>> a = filter((List<Object>) state.get("anchors"), nowMs, denied);
                    if (a.isEmpty()) return failT("stale-exceeded", why + "; every cached key has expired or been revoked");
                    return build("stale-cache", a, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
                }

                Map<String, Object> ev = evaluateMaaJwks(jwks, issuer, effPolicy, nowMs);
                List<Map<String, Object>> accepted = new ArrayList<>();
                for (Object o : (List<Object>) ev.get("accepted")) if (!denied.contains((String) ((Map<String, Object>) o).get("spki"))) accepted.add((Map<String, Object>) o);
                List<Object> evRejected = (List<Object>) ev.get("rejected");
                if (accepted.isEmpty()) {
                    List<String> parts = new ArrayList<>();
                    for (Object o : evRejected) parts.add(((Map<String, Object>) o).get("kid") + ": " + ((Map<String, Object>) o).get("reason"));
                    return failT("no-valid-keys", "no JWKS key passed validation (" + (parts.isEmpty() ? "empty JWKS" : String.join("; ", parts)) + ")");
                }

                Set<String> baseline = new LinkedHashSet<>();
                if (state != null) for (Map<String, Object> a : filter((List<Object>) state.get("anchors"), nowMs, Collections.emptySet())) baseline.add((String) a.get("spki"));
                if (state == null) {
                    Object ip = policy.get("initialPins") instanceof Map ? ((Map<String, Object>) policy.get("initialPins")).get(issuer) : null;
                    if (ip instanceof List) for (Object p : (List<Object>) ip) baseline.add(((String) p).toLowerCase(java.util.Locale.ROOT));
                    baseline.addAll(builtinBaseline);
                }
                approved.addAll(builtinBaseline);
                Set<String> acceptedSet = new LinkedHashSet<>();
                for (Map<String, Object> a : accepted) acceptedSet.add((String) a.get("spki"));
                List<String> approvedHere = new ArrayList<>(), unapprovedNew = new ArrayList<>();
                for (String s : acceptedSet) {
                    if (approved.contains(s)) approvedHere.add(s);
                    if (!baseline.contains(s) && !approved.contains(s)) unapprovedNew.add(s);
                }
                if (baseline.isEmpty()) {
                    if (approvedHere.isEmpty() && !Boolean.TRUE.equals(policy.get("allowTrustOnFirstUse"))) {
                        if (builtinReason != null) return failT("builtin-pins-invalid", "built-in pins unusable (" + builtinReason + "); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use");
                        return failT("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use");
                    }
                    if (acceptedSet.size() > maxInitial && approvedHere.size() < acceptedSet.size()) return failT("too-many-new-keys", "initial set of " + acceptedSet.size() + " keys exceeds maxInitialKeys");
                } else {
                    if (unapprovedNew.size() > maxNew) return failT("too-many-new-keys", unapprovedNew.size() + " new keys exceed maxNewKeysPerFetch=" + AttestCommon.jsNumString(maxNew));
                    boolean overlap = !approvedHere.isEmpty();
                    for (String s : acceptedSet) if (baseline.contains(s)) overlap = true;
                    if (requireOverlap && !overlap) return failT("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin");
                }

                Map<String, Object> firstSeen = new LinkedHashMap<>();
                if (state != null) for (Object o : (List<Object>) state.get("anchors")) firstSeen.put((String) ((Map<String, Object>) o).get("spki"), ((Map<String, Object>) o).get("firstSeenMs"));
                List<Map<String, Object>> records = new ArrayList<>();
                for (Map<String, Object> a : accepted) {
                    Map<String, Object> r = new LinkedHashMap<>(a);
                    r.put("firstSeenMs", firstSeen.containsKey(a.get("spki")) ? firstSeen.get(a.get("spki")) : (Object) Long.valueOf((long) nowMs));
                    records.add(r);
                }
                long fetchedAt = (long) (state != null ? Math.max(stateFetched, nowMs) : nowMs);
                store.set(issuer, Issue.obj("v", Long.valueOf(1), "issuer", issuer, "fetchedAtMs", Long.valueOf(fetchedAt), "anchors", new ArrayList<Object>(records)));
                List<String> newKeys = new ArrayList<>(), removedKeys = new ArrayList<>();
                for (Map<String, Object> r : records) if (!baseline.contains((String) r.get("spki"))) newKeys.add((String) r.get("spki"));
                for (String s : baseline) if (!acceptedSet.contains(s)) removedKeys.add(s);
                return build("fetched", records, newKeys, removedKeys, evRejected);
            } catch (RuntimeException e) {
                return failT("fetch-failed", e.getMessage() == null ? "unexpected error" : e.getMessage());
            }
        }
    }

    /** Build a trust store: the policy is copied (later edits change nothing), {@code fetch} must be injected, {@code trustedIssuers} a non-empty list of https origins. */
    public static Trust createMaaKeyTrust(Map<String, Object> policy, StateStore store, Fetch fetch) { return new Trust(policy, store, fetch); }

    // ------------------------------------------------------------- multi-vantage corroboration

    private static Map<String, Object> bad(String code, String reason) { return Issue.obj("ok", false, "code", code, "reason", reason); }

    /**
     * Accept a FIRST-USE key set only if at least {@code k} (&gt;= 2) DISTINCT vantage points observed the same issuer and ALL supplied observations
     * validate to the IDENTICAL SPKI set. Any disagreement fails closed. {@code opts = {issuer, nowMs, policy?}}; observations are {vantage, issuer, jwks}.
     * The result is usable as {@code initialPins[issuer]}. Independence of the vantages is the caller's claim, not proven here.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> corroborateMaaKeySets(Object sets, Object k, Map<String, Object> opts) {
        try {
            if (!IntentJs.isSafeInteger(k) || IntentJs.num(k) < 2) return bad("malformed", "k must be an integer >= 2");
            Object issO = opts == null ? null : opts.get("issuer");
            if (!(issO instanceof String) || !ISSUER_URL.matcher((String) issO).matches() || !IntentJs.isSafeInteger(opts.get("nowMs"))) return bad("malformed", "issuer/nowMs invalid");
            if (!(sets instanceof List)) return bad("malformed", "sets must be an array");
            String issuer = (String) issO;
            double nowMs = IntentJs.num(opts.get("nowMs"));
            Map<String, Object> policy = new LinkedHashMap<>();
            policy.put("trustedIssuers", new ArrayList<Object>(List.of(issuer)));
            if (opts.get("policy") instanceof Map) policy.putAll((Map<String, Object>) opts.get("policy"));
            Map<String, String> byVantage = new LinkedHashMap<>();
            for (Object so : (List<Object>) sets) {
                Map<String, Object> o = so instanceof Map ? (Map<String, Object>) so : new LinkedHashMap<>();
                Object vo = o.get("vantage");
                if (!(vo instanceof String) || ((String) vo).isEmpty() || ((String) vo).length() > 100) return bad("malformed", "vantage label must be a non-empty string");
                String vantage = (String) vo;
                if (!issuer.equals(o.get("issuer"))) return bad("malformed", "observation from '" + vantage + "' is for a different issuer");
                Map<String, Object> ev = evaluateMaaJwks(o.get("jwks"), issuer, policy, nowMs);
                List<Object> acc = (List<Object>) ev.get("accepted");
                if (acc.isEmpty()) {
                    List<String> rs = new ArrayList<>();
                    for (Object r : (List<Object>) ev.get("rejected")) rs.add((String) ((Map<String, Object>) r).get("reason"));
                    return bad("no-valid-keys", "vantage '" + vantage + "' observed no valid key (" + (rs.isEmpty() ? "empty" : String.join("; ", rs)) + ")");
                }
                List<String> sp = new ArrayList<>();
                for (Object a : acc) sp.add((String) ((Map<String, Object>) a).get("spki"));
                Collections.sort(sp);
                String fp = String.join(",", sp);
                String prior = byVantage.get(vantage);
                if (prior != null && !prior.equals(fp)) return bad("vantage-disagreement", "vantage '" + vantage + "' supplied two different key sets");
                byVantage.put(vantage, fp);
            }
            long kk = IntentJs.lng(k);
            if (byVantage.size() < kk) return bad("insufficient-vantages", byVantage.size() + " distinct vantage(s) < k=" + kk);
            Set<String> distinct = new LinkedHashSet<>(byVantage.values());
            if (distinct.size() != 1) {
                List<String> parts = new ArrayList<>();
                for (Map.Entry<String, String> e : byVantage.entrySet()) {
                    List<String> sh = new ArrayList<>();
                    for (String x : e.getValue().split(",", -1)) sh.add(x.substring(0, Math.min(8, x.length())));
                    parts.add(e.getKey() + "=" + String.join("+", sh));
                }
                return bad("vantage-disagreement", "vantages disagree: " + String.join(" | ", parts));
            }
            List<Object> spkis = new ArrayList<>(List.of(distinct.iterator().next().split(",", -1)));
            List<Object> vants = new ArrayList<>(byVantage.keySet());
            Collections.sort((List<String>) (List<?>) vants);
            return Issue.obj("ok", true, "issuer", issuer, "spkis", spkis, "vantages", vants, "k", Long.valueOf(kk));
        } catch (RuntimeException e) {
            return bad("malformed", e.getMessage() == null ? "corroboration error" : e.getMessage());
        }
    }
}
