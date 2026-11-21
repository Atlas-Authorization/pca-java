package net.atlasauth.pca.gateway;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.siem.JsFmt;

/**
 * Proof-Carrying Authority enforcement at the gateway / service mesh: every inbound request is verified against the PCActn it carries
 * (header {@code PCA-Action}), the route's required capability, the request binding and a single-use guard, DENY-BY-DEFAULT at every step.
 * The request, the Envoy ext_authz and the Lambda authorizer shapes are plain Maps (a JSON tree: Map / List / String / Boolean /
 * Json.Num / null), so any gateway SDK adapts in a few lines. Verification goes through the native core ({@link Pca}, {@link Authorize}).
 *
 * <p>Differences from the TypeScript reference, all fail-closed: only the {@code revocation} verifier hook exists (attestation, threshold and
 * zk hooks and the opt-in enforcement gates are not offered, so a requireChecks entry for them reads "not-enforced" and denies); the verdict a
 * decision carries lists the checks as pass / fail / not-enforced in the native core's order, not the reference's; the Cloudflare Worker
 * adapter is the runtime-free {@link #cloudflareWorker} (injected next / respond; it does not run on Workers).
 */
public final class Gateway {
    private Gateway() {}

    /** The header carrying the base64url PCActn. */
    public static final String PCA_HEADER = "PCA-Action";

    /** Every header an allow may inject upstream (a gateway that only forwards present headers cannot erase a client-supplied copy). */
    public static final List<String> PCA_INJECTED_HEADERS = Collections.unmodifiableList(java.util.Arrays.asList("x-pca-verdict", "x-pca-verb", "x-pca-grant"));

    /** A JavaScript {@code undefined} (an absent member): JSON null stays Java null. */
    private static final Object UNDEF = new Object();

    // ---- configuration types ----------------------------------------------------------------------------------------------------------

    /** The capability a route requires of a verified PCActn: a PCA verb, optionally bound to a resource. */
    public static final class RequiredCapability {
        public final String verb;
        /** When set, the proof's action.resource must equal this exactly. */
        public final String resource;
        public RequiredCapability(String verb, String resource) { this.verb = verb; this.resource = resource; }
    }

    /** One route to capability rule; the first matching rule wins. {@code method} null / "*" / "ANY" matches any method. */
    public static final class RouteRule {
        public final String method;
        /** "*" or "/*" any path; a trailing "/*" a prefix on a segment boundary; a trailing "*" a raw prefix; otherwise exact. */
        public final String path;
        public final RequiredCapability capability;
        public RouteRule(String method, String path, RequiredCapability capability) { this.method = method; this.path = path; this.capability = capability; }
    }

    /** Which request attributes are bound into the proof (method, path and query always are). */
    public static final class BindRequestOptions {
        /** Also bind the request authority (requires {@code GatewayRequest.authority}). */
        public boolean authority;
        /** true: bind the body hash (requires bodySha256); false: never; null (default): bind it whenever the request carries one. */
        public Boolean body;
    }

    /** The subset of an inbound request the gateway needs. {@code headers} values are a String, a List of Strings or null. */
    public static final class GatewayRequest {
        public String method;
        /** Request path without the query string. */
        public String path;
        /** Raw query string without the "?". */
        public String query;
        public String authority;
        /** Lower-case hex SHA-256 of the body, when the caller can supply it. */
        public String bodySha256;
        /** The raw body text (read only by full-policy mode with the body as params). */
        public String body;
        public Map<String, Object> headers = new LinkedHashMap<>();
        public GatewayRequest() {}
        public GatewayRequest(String method, String path, Map<String, Object> headers) { this.method = method; this.path = path; if (headers != null) this.headers = headers; }
    }

    /** Single-use store for proofs: atomically claim {@code key} until {@code expiresAtMs}; true if first use. */
    public interface ReplayGuard { boolean claim(String key, double expiresAtMs, Double nowMs) throws Exception; }

    /** The gateway's per-session log of untrusted content it relayed ({@code {origin, source}} observations). */
    public interface ProvenanceLog {
        List<Map<String, Object>> seen(String session);
        void add(String session, Map<String, Object> observation);
    }

    /** The outcome of the revocation verifier hook. */
    public static final class HookResult {
        public final boolean enforced;
        public final boolean ok;
        public final String reason;
        public HookResult(boolean enforced, boolean ok, String reason) { this.enforced = enforced; this.ok = ok; this.reason = reason; }
    }

    /** The revocation verifier hook: runs after the core checks; a throw fails the check. */
    public interface RevocationHook { HookResult check(Map<String, Object> pcactn, Map<String, Object> grant, long now) throws Exception; }

    /** Resolves a grant_ref (any JSON value) to the root capability the chain must descend from; null for an unknown grant. */
    public interface GrantResolver { Map<String, Object> resolve(Object grantRef, Map<String, Object> pcactn); }

    /** Context handed to the checkProof hook. */
    public static final class ProofCheckContext {
        public final Map<String, Object> pcactn;
        public final Map<String, Object> grant;
        public final Map<String, Object> verdict;
        public final GatewayRequest request;
        public final RequiredCapability required;
        ProofCheckContext(Map<String, Object> pcactn, Map<String, Object> grant, Map<String, Object> verdict, GatewayRequest request, RequiredCapability required) {
            this.pcactn = pcactn; this.grant = grant; this.verdict = verdict; this.request = request; this.required = required;
        }
    }

    /** Per-proof policy hook: return Boolean, or a Map {allow, reason?}. false / {allow: false} / a throw denies. */
    public interface CheckProof { Object check(ProofCheckContext ctx) throws Exception; }

    /**
     * Full-policy mode: the grant's limits are evaluated against the real params by {@link Authorize#authorize}, with revocation and
     * replay required. The agent signs the params plus the request binding (see {@link #bindParams}).
     */
    public static final class FullPolicy {
        /** true (default): the params are the request body (strict JSON object). */
        public boolean paramsFromBody = true;
        /** Used instead of the body when set; a null return denies. */
        public Function<GatewayRequest, Map<String, Object>> paramsFn;
        public StateStore state;
        public Authorize.RevocationCheck isRevoked;
        /** Further {@link Authorize.Input} settings (plan, intent policy, risk, ...) applied to each request's input. */
        public Consumer<Authorize.Input> configure;
        /** Caveat language v2 input (pins, history, ...) merged under the presented discharges / narrow; null: every K1 caveat refuses. */
        public Map<String, Object> k1;
        public BiFunction<GatewayRequest, Map<String, Object>, Map<String, Object>> k1Fn;
        /** Builds the provenance gate from the gateway's joined {@code observed} (the log of what it let through); null: a default gate. */
        public Function<ArgProvenance.Observed, ArgProvenance.Options> provenanceGate;
        /** The per-gateway log of relayed untrusted content; null: an in-memory one. */
        public ProvenanceLog provenanceLog;
        /** true turns the log off. */
        public boolean provenanceLogOff;
    }

    /** Gateway configuration. */
    public static final class GatewayOptions {
        /** This gateway's audience (the RFC 8707 resource): a proof minted for another audience is denied. */
        public String audience;
        public List<RouteRule> routes = new ArrayList<>();
        public GrantResolver resolveGrant;
        public List<String> authorizedPlanRoots;
        public boolean insecureSkipPlanRootCheck;
        /** "deny" (default), "allow" or "require-proof". */
        public String unmatchedRoute;
        public ReplayGuard replayGuard;
        /** Request binding options (null: the default {@code {}}); see {@link #bindRequestOff}. */
        public BindRequestOptions bindRequest;
        /** true: no request binding (the proof is then a bearer for the matched route). */
        public boolean bindRequestOff;
        public RevocationHook revocation;
        /** Core checks that must report pass (null: ["revocation"] in signature-only mode, none in full mode). */
        public List<String> requireChecks;
        public CheckProof checkProof;
        /** "strict" (default) or "off". */
        public String pathPolicy;
        public LongSupplier now;
        public String realm;
        /** "full", "signature-only" or null (a misconfiguration that denies every request). */
        public String policyMode;
        public FullPolicy full;
        private volatile ProvenanceLog defaultLog;

        ProvenanceLog defaultLog() {
            ProvenanceLog l = defaultLog;
            if (l == null) {
                synchronized (this) {
                    if (defaultLog == null) defaultLog = memoryProvenanceLog(10_000);
                    l = defaultLog;
                }
            }
            return l;
        }
    }

    /** Machine-readable outcome codes of {@link #authorize}. */
    public static final class Decision {
        public final boolean allow;
        /** 200 allow, 400 invalid path, 401 unauthenticated, 403 forbidden, 503 replay guard unavailable. */
        public final int status;
        public final String code;
        public final String reason;
        public final Map<String, String> headers;
        /** {allow, checks, reason?}, when a PCActn was decoded and verified. */
        public final Map<String, Object> verdict;
        public final Map<String, Object> pcactn;
        public final RequiredCapability matched;
        /** Full-policy mode: the full verifier's verdict {allow, checks, reasons}. */
        public final Map<String, Object> policyVerdict;
        Decision(boolean allow, int status, String code, String reason, Map<String, String> headers, Map<String, Object> verdict, Map<String, Object> pcactn, RequiredCapability matched, Map<String, Object> policyVerdict) {
            this.allow = allow; this.status = status; this.code = code; this.reason = reason; this.headers = headers;
            this.verdict = verdict; this.pcactn = pcactn; this.matched = matched; this.policyVerdict = policyVerdict;
        }
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", allow); m.put("status", new Json.Num(Integer.toString(status))); m.put("code", code); m.put("reason", reason);
            m.put("headers", new LinkedHashMap<String, Object>(headers));
            if (verdict != null) m.put("verdict", verdict);
            if (pcactn != null) m.put("pcactn", pcactn);
            if (matched != null) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("verb", matched.verb);
                if (matched.resource != null) r.put("resource", matched.resource);
                m.put("matched", r);
            }
            if (policyVerdict != null) m.put("policyVerdict", policyVerdict);
            return m;
        }
    }

    // ---- JavaScript text helpers -----------------------------------------------------------------------------------------------------

    private static Object g(Object o, String k) {
        if (o instanceof Map) { Map<?, ?> m = (Map<?, ?>) o; return m.containsKey(k) ? m.get(k) : UNDEF; }
        return UNDEF;
    }

    private static String jsStr(Object v) { return v == UNDEF ? "undefined" : JsFmt.str(v); }

    private static String errMsg(Throwable e) { return e.getMessage() != null ? e.getMessage() : e.toString(); }

    private static final String HEX = "0123456789ABCDEF";

    /** {@code encodeURIComponent}: unreserved characters and {@code !'()*} stay; the rest is percent-encoded UTF-8; a lone surrogate throws. */
    static String encodeURIComponent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            int cp;
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { cp = Character.toCodePoint(c, s.charAt(i + 1)); i += 2; }
            else if (Character.isSurrogate(c)) throw new IllegalArgumentException("URI malformed");
            else { cp = c; i++; }
            if (cp < 128 && (Character.isLetterOrDigit(cp) || "-_.!~*'()".indexOf(cp) >= 0)) { sb.append((char) cp); continue; }
            for (byte b : Json.utf8(new String(Character.toChars(cp)))) sb.append('%').append(HEX.charAt((b >> 4) & 15)).append(HEX.charAt(b & 15));
        }
        return sb.toString();
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static int pctByte(String s, int i) {
        if (i + 2 >= s.length() || s.charAt(i) != '%') throw new IllegalArgumentException("URI malformed");
        int h = hexVal(s.charAt(i + 1)), l = hexVal(s.charAt(i + 2));
        if (h < 0 || l < 0) throw new IllegalArgumentException("URI malformed");
        return (h << 4) | l;
    }

    /** {@code decodeURIComponent}: every {@code %XX} must be hex and the bytes well-formed UTF-8, else it throws. */
    static String decodeURIComponent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            if (c != '%') { sb.append(c); i++; continue; }
            if (i + 2 >= s.length()) throw new IllegalArgumentException("URI malformed");
            int b = pctByte(s, i);
            i += 3;
            if (b < 0x80) { sb.append((char) b); continue; }
            int n = (b & 0xE0) == 0xC0 ? 2 : (b & 0xF0) == 0xE0 ? 3 : (b & 0xF8) == 0xF0 ? 4 : 0;
            if (n == 0) throw new IllegalArgumentException("URI malformed");
            int cp = n == 2 ? b & 0x1F : n == 3 ? b & 0x0F : b & 0x07;
            for (int k = 1; k < n; k++) {
                if (i + 2 >= s.length()) throw new IllegalArgumentException("URI malformed");
                int nb = pctByte(s, i);
                if ((nb & 0xC0) != 0x80) throw new IllegalArgumentException("URI malformed");
                cp = (cp << 6) | (nb & 0x3F);
                i += 3;
            }
            boolean ok = n == 2 ? cp >= 0x80 : n == 3 ? cp >= 0x800 && (cp < 0xD800 || cp > 0xDFFF) : cp >= 0x10000 && cp <= 0x10FFFF;
            if (!ok) throw new IllegalArgumentException("URI malformed");
            sb.appendCodePoint(cp);
        }
        return sb.toString();
    }

    // ---- request binding ----------------------------------------------------------------------------------------------------------------

    /**
     * Canonical query: strip a leading "?", drop empty pairs, sort the raw (still percent-encoded) pairs, join with "&". Throws when the query
     * is ambiguous across upstream parsers: a repeated parameter name (percent-decoded, "+" as space, case-insensitive), a ";" separator, or a
     * malformed percent escape in a name.
     */
    public static String canonicalQuery(String query) {
        if (query == null) return "";
        String q = query.startsWith("?") ? query.substring(1) : query;
        if (q.indexOf(';') >= 0) throw new IllegalArgumentException("query contains ';' (parsers disagree on it as a separator)");
        List<String> pairs = new ArrayList<>();
        for (String p : q.split("&", -1)) if (!p.isEmpty()) pairs.add(p);
        Set<String> seen = new LinkedHashSet<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            String rawKey = eq < 0 ? pair : pair.substring(0, eq);
            String key;
            try {
                key = decodeURIComponent(rawKey.replace('+', ' ')).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("query parameter name has a malformed percent escape");
            }
            if (!seen.add(key)) throw new IllegalArgumentException("duplicate query parameter '" + key + "'");
        }
        Collections.sort(pairs);
        return String.join("&", pairs);
    }

    /**
     * The canonical binding of a request: upper-cased method, the path, the canonical query and optionally the authority and the body hash.
     * Agents pass this object as the action params so params_digest commits to it; the gateway recomputes it from the live request.
     */
    public static Map<String, Object> requestBinding(GatewayRequest req, BindRequestOptions opts) {
        BindRequestOptions o = opts != null ? opts : new BindRequestOptions();
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", new Json.Num("2"));
        b.put("method", req.method.toUpperCase(Locale.ROOT));
        b.put("path", req.path);
        b.put("query", canonicalQuery(req.query));
        if (o.authority) b.put("authority", (req.authority != null ? req.authority : "").toLowerCase(Locale.ROOT));
        if (Boolean.TRUE.equals(o.body) || (o.body == null && req.bodySha256 != null)) b.put("body_sha256", (req.bodySha256 != null ? req.bodySha256 : "").toLowerCase(Locale.ROOT));
        return b;
    }

    /** The params an agent signs for a full-policy gateway: the params plus the request binding as a "binding" member (null binding: the params). */
    public static Map<String, Object> bindParams(Map<String, Object> params, Map<String, Object> binding) {
        if (binding == null) return params;
        if (params.containsKey("binding")) throw new IllegalArgumentException("params already have a 'binding' member");
        Map<String, Object> out = new LinkedHashMap<>(params);
        out.put("binding", binding);
        return out;
    }

    // ---- replay guard, provenance log -----------------------------------------------------------------------------------------------

    /**
     * In-process replay guard (per process: use a shared store for a fleet). A claim stays live through {@code expiresAtMs} inclusive. Fails
     * CLOSED when {@code maxEntries} unexpired claims are held (throws) rather than evicting a live claim.
     */
    public static ReplayGuard memoryReplayGuard(int maxEntries, LongSupplier now) {
        final LongSupplier clock = now != null ? now : System::currentTimeMillis;
        final Map<String, Double> seen = new LinkedHashMap<>();
        return (key, expiresAtMs, nowMs) -> {
            synchronized (seen) {
                double t = nowMs != null ? nowMs : (double) clock.getAsLong();
                if (seen.size() >= maxEntries) {
                    for (Iterator<Map.Entry<String, Double>> it = seen.entrySet().iterator(); it.hasNext(); ) if (it.next().getValue() < t) it.remove();
                    if (seen.size() >= maxEntries) throw new IllegalStateException("replay guard full");
                }
                Double existing = seen.get(key);
                if (existing != null && existing >= t) return false;
                seen.put(key, expiresAtMs);
                return true;
            }
        };
    }

    private static boolean strictEq(Object a, Object b) {
        if (a == UNDEF || b == UNDEF) return a == b;
        if (a == null || b == null) return a == b;
        Double x = JsVal.num(a), y = JsVal.num(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        if (a instanceof String || a instanceof Boolean) return a.equals(b);
        return a == b;
    }

    /** An in-memory {@link ProvenanceLog}: at most {@code maxSessions} sessions (oldest dropped first), 256 observations each. */
    public static ProvenanceLog memoryProvenanceLog(int maxSessions) {
        final Map<String, List<Map<String, Object>>> m = new LinkedHashMap<>();
        return new ProvenanceLog() {
            @Override public List<Map<String, Object>> seen(String k) {
                synchronized (m) {
                    List<Map<String, Object>> cur = m.get(k);
                    List<Map<String, Object>> out = new ArrayList<>();
                    if (cur != null) for (Map<String, Object> o : cur) out.add(new LinkedHashMap<>(o));
                    return out;
                }
            }
            @Override public void add(String k, Map<String, Object> o) {
                synchronized (m) {
                    List<Map<String, Object>> cur = m.remove(k);
                    if (cur == null) cur = new ArrayList<>();
                    boolean dup = false;
                    for (Map<String, Object> x : cur) if (strictEq(g(x, "origin"), g(o, "origin")) && strictEq(g(x, "source"), g(o, "source"))) dup = true;
                    if (!dup && cur.size() < 256) {
                        Map<String, Object> n = new LinkedHashMap<>();
                        if (o.containsKey("origin")) n.put("origin", o.get("origin"));
                        if (o.containsKey("source")) n.put("source", o.get("source"));
                        cur.add(n);
                    }
                    m.put(k, cur);
                    while (m.size() > maxSessions) m.remove(m.keySet().iterator().next());
                }
            }
        };
    }

    // ---- headers, presented artifacts ----------------------------------------------------------------------------------------------

    /** Case-insensitive single-value header lookup: the first value of a repeated header; null when absent. */
    static String getHeader(Map<String, Object> headers, String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, Object> e : headers.entrySet()) {
            if (!e.getKey().toLowerCase(Locale.ROOT).equals(lower)) continue;
            Object v = e.getValue();
            if (v instanceof List) { List<?> l = (List<?>) v; return l.isEmpty() || !(l.get(0) instanceof String) ? null : (String) l.get(0); }
            return v instanceof String ? (String) v : null;
        }
        return null;
    }

    /** The header text decoded strictly (unpadded base64url, well-formed UTF-8), or an error message. */
    private static String decodeHeaderText(String value, String[] err) {
        if (value.isEmpty()) { err[0] = "PCA-Action header is empty"; return null; }
        byte[] raw = Pca.decodeB64uStrict(value, -1);
        if (raw == null) { err[0] = "PCA-Action header is not strict unpadded base64url"; return null; }
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            err[0] = "PCA-Action header does not decode to UTF-8 text";
            return null;
        }
    }

    /** The marker {@link #presentedProvenance} returns when the request presents no provenance (JSON null is a presented, unreadable one). */
    public static final Object ABSENT = UNDEF;

    /** A strictly parsed JSON object of the body, or null when the body is not a non-empty JSON object. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyObject(GatewayRequest req) {
        if (req.body == null || req.body.isEmpty()) return null;
        try {
            Object b = Json.parse(req.body);
            return b instanceof Map ? (Map<String, Object>) b : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Object strictHeaderValue(String h) {
        String[] err = new String[1];
        String text = decodeHeaderText(h, err);
        if (text == null) throw new IllegalArgumentException(err[0]);
        return Json.parse(text);
    }

    /** The provenance bundle a request presents: header PCA-Provenance (strict base64url JSON; unreadable gives null), else body member pca_provenance when the body is not the signed params. {@link #ABSENT} when none. */
    public static Object presentedProvenance(GatewayRequest req, FullPolicy policy) {
        String h = getHeader(req.headers, "pca-provenance");
        if (h != null && !h.isEmpty()) {
            try { return strictHeaderValue(h); } catch (RuntimeException e) { return null; }
        }
        if (!policy.paramsFromBody || policy.paramsFn != null) {
            Map<String, Object> b = bodyObject(req);
            if (b != null && b.containsKey("pca_provenance")) return b.get("pca_provenance");
        }
        return ABSENT;
    }

    /** The discharges and narrow block a request presents (headers, then body members when the body is not the signed params). */
    public static Map<String, Object> presentedArtifacts(GatewayRequest req, FullPolicy policy) {
        Map<String, Object> out = new LinkedHashMap<>();
        String d = getHeader(req.headers, "pca-discharges");
        if (d != null && !d.isEmpty()) {
            try { Object arr = strictHeaderValue(d); if (arr instanceof List) out.put("discharges", arr); } catch (RuntimeException e) { /* unreadable: no discharges */ }
        }
        String n = getHeader(req.headers, "pca-narrow");
        if (n != null && !n.isEmpty()) {
            try { out.put("narrow", strictHeaderValue(n)); } catch (RuntimeException e) { /* unreadable: no narrow block */ }
        }
        if (!policy.paramsFromBody || policy.paramsFn != null) {
            Map<String, Object> b = bodyObject(req);
            if (b != null) {
                if (!out.containsKey("discharges") && b.get("pca_discharges") instanceof List) out.put("discharges", b.get("pca_discharges"));
                if (!out.containsKey("narrow") && b.containsKey("pca_narrow")) out.put("narrow", b.get("pca_narrow"));
            }
        }
        return out;
    }

    // ---- path hardening, route matching -------------------------------------------------------------------------------------------------

    private static final Pattern PCT = Pattern.compile("%([0-9a-fA-F]{2})");
    private static final Pattern BAD_PCT = Pattern.compile("%(?![0-9a-fA-F]{2})");

    /** Why {@code path} is ambiguous for route matching (dot segments, "//", backslashes, control characters, ";" parameters, encoded delimiters or unreserved characters, malformed escapes), or null when canonical. */
    public static String ambiguousPathReason(String path) {
        for (int i = 0; i < path.length(); i++) { char c = path.charAt(i); if (c <= 0x1f || c == 0x7f || c == '\\') return "control character or backslash in path"; }
        if (path.contains("//")) return "repeated slash in path";
        if (path.indexOf(';') >= 0) return "path parameter (;) in path";
        for (String seg : path.split("/", -1)) if (seg.equals(".") || seg.equals("..")) return "dot segment in path";
        Matcher m = PCT.matcher(path);
        while (m.find()) {
            int code = Integer.parseInt(m.group(1), 16);
            char ch = (char) code;
            if (code < 0x20 || code == 0x7f) return "percent-encoded control character in path";
            if (ch == '/' || ch == '\\') return "percent-encoded slash in path";
            if (ch == ';') return "percent-encoded path parameter delimiter in path";
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_' || ch == '~') return "non-canonical percent-encoding in path";
        }
        if (BAD_PCT.matcher(path).find()) return "malformed percent-encoding in path";
        return null;
    }

    private static boolean matchMethod(RouteRule rule, String method) {
        String m = rule.method;
        if (m == null || m.equals("*") || m.toUpperCase(Locale.ROOT).equals("ANY")) return true;
        return m.toUpperCase(Locale.ROOT).equals(method.toUpperCase(Locale.ROOT));
    }

    private static boolean matchPath(String pattern, String path) {
        if (pattern.equals("*") || pattern.equals("/*")) return true;
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        if (pattern.endsWith("*")) return path.startsWith(pattern.substring(0, pattern.length() - 1));
        return path.equals(pattern);
    }

    private static RouteRule matchRoute(List<RouteRule> routes, String method, String path) {
        for (RouteRule r : routes) if (matchMethod(r, method) && matchPath(r.path, path)) return r;
        return null;
    }

    // ---- decisions ------------------------------------------------------------------------------------------------------------------------

    private static String errorToken(String code) {
        switch (code) {
            case "no-proof": return "missing_proof";
            case "invalid-proof": case "unknown-grant": case "verify-failed": return "invalid_proof";
            case "wrong-audience": return "invalid_resource";
            case "insufficient-capability": return "insufficient_capability";
            case "unmapped-route": case "proof-rejected": return "access_denied";
            case "invalid-path": return "invalid_request";
            case "replayed-proof": return "replayed_proof";
            case "replay-guard-unavailable": return "temporarily_unavailable";
            case "request-mismatch": return "proof_not_bound_to_request";
            default: throw new IllegalArgumentException(code);
        }
    }

    private static Decision deny(String code, int status, String reason, String realm, Map<String, Object> verdict, Map<String, Object> pcactn, RequiredCapability matched, Map<String, Object> policyVerdict) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("www-authenticate", "PCA realm=\"" + realm + "\", error=\"" + errorToken(code) + "\"");
        return new Decision(false, status, code, reason, headers, verdict, pcactn, matched, policyVerdict);
    }

    private static Decision deny(String code, int status, String reason, String realm) { return deny(code, status, reason, realm, null, null, null, null); }

    private static Decision deny(String code, int status, String reason, String realm, Map<String, Object> verdict, Map<String, Object> pcactn) { return deny(code, status, reason, realm, verdict, pcactn, null, null); }

    private static Decision allowDecision(String reason, Map<String, Object> verdict, Map<String, Object> pcactn, RequiredCapability matched, Map<String, Object> policyVerdict) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (verdict != null) headers.put("x-pca-verdict", JsFmt.stringify(verdict));
        if (pcactn != null) {
            headers.put("x-pca-verb", jsStr(g(g(pcactn, "action"), "verb")));
            headers.put("x-pca-grant", jsStr(g(pcactn, "grant_ref")));
        }
        return new Decision(true, 200, "allow", reason, headers, verdict, pcactn, matched, policyVerdict);
    }

    private static Map<String, Object> verdictMap(boolean allow, Map<String, String> checks, String reason) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("allow", allow);
        v.put("checks", new LinkedHashMap<String, Object>(checks));
        if (reason != null && !reason.isEmpty()) v.put("reason", reason);
        return v;
    }

    // ---- configuration checks ---------------------------------------------------------------------------------------------------------------

    private static final List<String> DEFAULT_REQUIRE_CHECKS = Collections.singletonList("revocation");

    private static String missingText(GatewayOptions opts, List<String> missing) {
        String mode = opts.policyMode;
        return (mode == null || mode.equals("signature-only") ? "the gateway" : "full policy mode") + " is missing " + String.join(", ", missing);
    }

    /** What is missing from the configuration (empty when complete). */
    private static List<String> missingPolicy(GatewayOptions opts) {
        String mode = opts.policyMode;
        List<String> m = new ArrayList<>();
        if (mode == null) { m.add("policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"); return m; }
        if (mode.equals("signature-only")) {
            if (opts.replayGuard == null) m.add("replayGuard (signature-only mode needs a single-use guard)");
            if ((opts.requireChecks != null ? opts.requireChecks : DEFAULT_REQUIRE_CHECKS).contains("revocation") && opts.revocation == null)
                m.add("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)");
            return m;
        }
        if (!mode.equals("full")) { m.add("a known policy mode (got '" + mode + "')"); return m; }
        FullPolicy f = opts.full != null ? opts.full : new FullPolicy();
        for (String c : Authorize.missingAuthorizeComponents(opts.audience, opts.resolveGrant, f.state, f.isRevoked)) m.add(c.equals("stateStore") ? "state" : c);
        if (!f.paramsFromBody && f.paramsFn == null) m.add("params ('body' or a function)");
        return m;
    }

    /** Full-policy mode: the params the agent must have signed for this request: {params} or {error}. */
    private static Object[] signedParams(GatewayRequest req, FullPolicy policy, BindRequestOptions bind, boolean bindOff) {
        Object params;
        if (policy.paramsFn == null && policy.paramsFromBody) {
            if (req.body == null) return new Object[] {null, "full policy mode reads the params from the body, and the request carries none"};
            try {
                params = Json.parse(req.body);
            } catch (RuntimeException e) {
                return new Object[] {null, "the body is not strict JSON: " + errMsg(e)};
            }
        } else {
            params = policy.paramsFn.apply(req);
        }
        if (!(params instanceof Map)) return new Object[] {null, "the request params are not a JSON object"};
        @SuppressWarnings("unchecked") Map<String, Object> obj = (Map<String, Object>) params;
        if (bindOff) return new Object[] {obj, null};
        if (obj.containsKey("binding")) return new Object[] {null, "the request params carry a 'binding' member (reserved for the request binding)"};
        if ((bind.authority && isEmpty(req.authority)) || (Boolean.TRUE.equals(bind.body) && isEmpty(req.bodySha256)))
            return new Object[] {null, "request lacks an attribute the proof must bind (authority / body hash)"};
        try {
            BindRequestOptions b = new BindRequestOptions();
            b.authority = bind.authority;
            b.body = Boolean.TRUE.equals(bind.body);
            Map<String, Object> out = new LinkedHashMap<>(obj);
            out.put("binding", requestBinding(req, b));
            return new Object[] {out, null};
        } catch (RuntimeException e) {
            return new Object[] {null, "the request cannot be bound: " + errMsg(e)};
        }
    }

    private static boolean isEmpty(String s) { return s == null || s.isEmpty(); }

    // ---- the core -----------------------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> decodePcactn(String raw, String[] err) {
        String text = decodeHeaderText(raw, err);
        if (text == null) return null;
        if (Pca.artifactTooLarge(text)) { err[0] = Pca.ARTIFACT_SIZE_REASON; return null; }
        Object v;
        try {
            v = Json.parse(text);
        } catch (RuntimeException e) {
            err[0] = errMsg(e);
            return null;
        }
        if (!(v instanceof Map)) { err[0] = "decodePCActn: not an object"; return null; }
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    private static String checkStatus(Boolean b) { return b == null ? null : b ? "pass" : "fail"; }

    /**
     * The framework-agnostic core: extract the PCActn from the headers, map (method, path) to the required capability, verify the proof
     * offline (fail closed) with the audience bound to this gateway, enforce the route's capability and the request binding, run the
     * required checks, the per-proof hook, full-policy mode when configured and the single-use guard. DENY-BY-DEFAULT at every step.
     */
    @SuppressWarnings("unchecked")
    public static Decision authorize(GatewayRequest req, GatewayOptions opts) {
        String realm = opts.realm != null ? opts.realm : opts.audience;
        String unmatched = opts.unmatchedRoute != null ? opts.unmatchedRoute : "deny";

        // 0. Ambiguous request targets are never matched against the route map.
        if (opts.pathPolicy == null || opts.pathPolicy.equals("strict")) {
            String bad = ambiguousPathReason(req.path);
            if (bad != null) return deny("invalid-path", 400, bad, realm);
        }

        // 1. Route to required capability.
        RouteRule rule = matchRoute(opts.routes, req.method, req.path);
        if (rule == null) {
            if (unmatched.equals("allow")) return allowDecision("route " + req.method + " " + req.path + " is unmapped (unmatchedRoute=allow)", null, null, null, null);
            if (unmatched.equals("deny")) return deny("unmapped-route", 403, "no capability mapping for " + req.method + " " + req.path + " (deny-by-default)", realm);
        }
        RequiredCapability required = rule == null ? null : rule.capability;

        // 2. Extract the proof (fail closed).
        String raw = getHeader(req.headers, PCA_HEADER);
        if (raw == null || raw.isEmpty()) return deny("no-proof", 401, "no " + PCA_HEADER + " header", realm);
        String[] err = new String[1];
        Map<String, Object> pcactn = decodePcactn(raw, err);
        if (pcactn == null) return deny("invalid-proof", 401, "undecodable " + PCA_HEADER + " header: " + err[0], realm);

        // 3. Resolve the grant the chain must root in; unknown grant denies.
        Map<String, Object> grant = opts.resolveGrant == null ? null : opts.resolveGrant.resolve(g(pcactn, "grant_ref") == UNDEF ? null : pcactn.get("grant_ref"), pcactn);
        if (grant == null) return deny("unknown-grant", 401, "unknown grant_ref " + jsStr(g(pcactn, "grant_ref")), realm, null, pcactn);

        // 3b. A configuration with a missing component denies every request (fail closed).
        List<String> missingCfg = missingPolicy(opts);
        if (!missingCfg.isEmpty()) return deny("proof-rejected", 403, missingText(opts, missingCfg) + " (fail closed)", realm, null, pcactn);

        // 4. Offline verification (fail closed), audience bound to THIS gateway.
        long now = opts.now != null ? opts.now.getAsLong() : System.currentTimeMillis();
        Pca.PlanRoots roots = Pca.PlanRoots.of(opts.authorizedPlanRoots, opts.insecureSkipPlanRootCheck);
        Pca.Verdict v = Pca.verifyPcactn(pcactn, grant, now, opts.audience, null, null, null, null, roots);
        Map<String, String> statuses = new LinkedHashMap<>();
        for (Map.Entry<String, Boolean> e : v.checks.entrySet()) statuses.put(e.getKey(), checkStatus(e.getValue()));
        statuses.put("attestation", "not-enforced");
        statuses.put("threshold", "not-enforced");
        String revStatus = "not-enforced";
        boolean allow = v.allow;
        String reason = v.reason;
        if (opts.revocation != null) {
            try {
                HookResult hr = opts.revocation.check(pcactn, grant, now);
                if (!hr.enforced) revStatus = "not-enforced";
                else if (hr.ok) revStatus = "pass";
                else {
                    revStatus = "fail";
                    if (allow) { allow = false; reason = "revocation: " + (hr.reason != null ? hr.reason : "rejected"); }
                }
            } catch (Exception e) {
                // the reference reports a hook that throws as a malformed PCActn
                revStatus = null;
                statuses.put("malformed", "fail");
                if (allow) { allow = false; reason = "malformed PCActn: " + errMsg(e); }
            }
        }
        if (revStatus != null) statuses.put("revocation", revStatus);
        statuses.put("taint_gate", "not-enforced");
        Map<String, Object> verdict = verdictMap(allow, statuses, reason);
        if (!allow) {
            boolean audienceFailed = Boolean.FALSE.equals(v.checks.get("audience"));
            return deny(audienceFailed ? "wrong-audience" : "verify-failed", audienceFailed ? 403 : 401,
                reason != null && !reason.isEmpty() ? reason : "PCActn verification failed", realm, verdict, pcactn);
        }

        // 5. Capability enforcement: the verified proof must carry the verb (+ resource) the route requires.
        Object action = g(pcactn, "action");
        Object proofVerb = g(action, "verb"), proofResource = g(action, "resource");
        if (required != null) {
            if (!strictEq(proofVerb, required.verb))
                return deny("insufficient-capability", 403, "route requires capability '" + required.verb + "' but the proof authorizes '" + jsStr(proofVerb) + "'", realm, verdict, pcactn, required, null);
            if (required.resource != null && !strictEq(proofResource, required.resource))
                return deny("insufficient-capability", 403, "route is bound to resource '" + required.resource + "' but the proof targets '" + jsStr(proofResource) + "'", realm, verdict, pcactn, required, null);
        }

        FullPolicy policy = "full".equals(opts.policyMode) ? (opts.full != null ? opts.full : new FullPolicy()) : null;
        Map<String, Object> fullParams = null;
        Object proofDigest = g(action, "params_digest");
        if (policy != null) {
            // 5b (full). The agent signed the real params plus the request binding: rebuild them from THIS request.
            Object[] sp = signedParams(req, policy, opts.bindRequest != null ? opts.bindRequest : new BindRequestOptions(), opts.bindRequestOff);
            if (sp[1] != null) return deny("request-mismatch", 403, (String) sp[1], realm, verdict, pcactn);
            if (!strictEq(proofDigest, Pca.paramsDigest(sp[0]))) return deny("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)", realm, verdict, pcactn);
            fullParams = (Map<String, Object>) sp[0];
        } else if (!opts.bindRequestOff) {
            // 5b. Request binding: the signed params digest must be the digest of THIS request.
            BindRequestOptions b = opts.bindRequest != null ? opts.bindRequest : new BindRequestOptions();
            if ((b.authority && isEmpty(req.authority)) || (Boolean.TRUE.equals(b.body) && isEmpty(req.bodySha256)))
                return deny("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)", realm, verdict, pcactn);
            String bound;
            try {
                bound = Pca.paramsDigest(requestBinding(req, b));
            } catch (RuntimeException e) {
                return deny("request-mismatch", 403, "the request cannot be bound: " + errMsg(e), realm, verdict, pcactn);
            }
            if (!strictEq(proofDigest, bound)) return deny("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)", realm, verdict, pcactn);
        }

        // 5c. Required checks must have PASSED (not merely "not-enforced").
        List<String> require = opts.requireChecks != null ? opts.requireChecks : (policy == null ? DEFAULT_REQUIRE_CHECKS : Collections.<String>emptyList());
        for (String c : require) {
            String st = statuses.get(c);
            if (!"pass".equals(st)) return deny("proof-rejected", 403, "required check '" + c + "' is " + (st != null ? st : "absent"), realm, verdict, pcactn);
        }

        // 5d. Per-proof policy hook (limits, budgets, revocation lists). Throws deny.
        if (opts.checkProof != null) {
            try {
                Object r = opts.checkProof.check(new ProofCheckContext(pcactn, grant, verdict, req, required));
                boolean ok;
                String why = "rejected by checkProof";
                if (r instanceof Boolean) ok = (Boolean) r;
                else {
                    ok = JsVal.truthy(g(r, "allow") == UNDEF ? null : ((Map<?, ?>) r).get("allow"));
                    Object rs = g(r, "reason");
                    if (rs != UNDEF && JsVal.truthy(rs)) why = jsStr(rs);
                }
                if (!ok) return deny("proof-rejected", 403, why, realm, verdict, pcactn);
            } catch (Exception e) {
                return deny("proof-rejected", 403, "checkProof failed: " + errMsg(e), realm, verdict, pcactn);
            }
        }

        // 5e. Full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget.
        Map<String, Object> policyVerdict = null;
        if (policy != null && fullParams != null) {
            Map<String, Object> k1 = null;
            if (policy.k1 != null || policy.k1Fn != null) {
                try {
                    Map<String, Object> own = policy.k1Fn != null ? policy.k1Fn.apply(req, pcactn) : policy.k1;
                    k1 = new LinkedHashMap<>(presentedArtifacts(req, policy));
                    if (own != null) k1.putAll(own);
                } catch (RuntimeException e) {
                    return deny("proof-rejected", 403, "k1 input failed: " + errMsg(e) + " (fail closed)", realm, verdict, pcactn);
                }
            }
            Object bundle = presentedProvenance(req, policy);
            ProvenanceLog log = policy.provenanceLogOff ? null : policy.provenanceLog != null ? policy.provenanceLog : opts.defaultLog();
            Object chain = g(pcactn, "cap_chain");
            Object leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? g(((List<?>) chain).get(((List<?>) chain).size() - 1), "holder") : UNDEF;
            Object receipts = g(bundle, "receipts");
            Object session = receipts instanceof List && !((List<?>) receipts).isEmpty() ? g(((List<?>) receipts).get(0), "session") : UNDEF;
            String logKey = jsStr(g(pcactn, "grant_ref")) + "\n" + jsStr(leaf) + "\n" + (session instanceof String ? (String) session : "-");
            String verb = required != null ? required.verb : jsStr(proofVerb);
            String resource = required != null && required.resource != null ? required.resource : jsStr(proofResource);

            Authorize.Input in = new Authorize.Input();
            if (policy.configure != null) policy.configure.accept(in);
            in.operation(Authorize.Operation.of(verb, resource, fullParams)).audience(opts.audience).now(now).stateStore(policy.state).isRevoked(policy.isRevoked);
            in.resolveGrant(ref -> opts.resolveGrant.resolve(ref, pcactn));
            if (k1 != null) in.k1(k1);
            if (bundle != UNDEF) in.provenance(ArgProvenance.Presented.bundle(bundle));
            if (log != null) {
                final ProvenanceLog fl = log;
                final String key = logKey;
                ArgProvenance.Observed joined = (p, op, sess) -> new ArrayList<Object>(fl.seen(key));
                in.provenanceGate(policy.provenanceGate != null ? policy.provenanceGate.apply(joined) : new ArgProvenance.Options().observed(joined));
            } else if (policy.provenanceGate != null) {
                in.provenanceGate(policy.provenanceGate.apply(null));
            }
            Authorize.AuthorizeResult d = Authorize.authorize(pcactn, in);
            Map<String, Object> pv = new LinkedHashMap<>();
            pv.put("allow", d.allow);
            pv.put("checks", new LinkedHashMap<String, Object>(d.checks));
            pv.put("reasons", new ArrayList<Object>(d.reasons));
            // what this call returns flows back into the agent's context: the session has now seen untrusted content
            if (d.allow && log != null) {
                Map<String, Object> obs = new LinkedHashMap<>();
                obs.put("origin", "tool");
                obs.put("source", jsStr(proofVerb));
                log.add(logKey, obs);
            }
            if (!d.allow) {
                String st = d.checks.get("replay");
                String code = "fail".equals(st) ? "replayed-proof"
                    : "fail".equals(d.checks.get("operation")) || "fail".equals(d.checks.get("params_digest")) ? "insufficient-capability"
                    : d.status == 401 ? "verify-failed" : "proof-rejected";
                return deny(code, d.status, d.reason == null ? "denied" : d.reason, realm, verdict, pcactn, null, pv);
            }
            policyVerdict = pv;
        }

        // 6. Single use (only for a proof that would otherwise be allowed, so denied attempts never burn it).
        if (opts.replayGuard != null) {
            boolean first;
            try {
                Object exp = g(pcactn, "exp");
                Double expD = exp == UNDEF ? null : JsVal.num(exp);
                first = opts.replayGuard.claim(jsStr(g(pcactn, "grant_ref")) + ":" + jsStr(g(pcactn, "sig")), expD != null ? expD : Double.NaN, (double) now);
            } catch (Exception e) {
                return deny("replay-guard-unavailable", 503, "replay guard unavailable: " + errMsg(e), realm, verdict, pcactn);
            }
            if (!first) return deny("replayed-proof", 403, "this proof has already been used", realm, verdict, pcactn);
        }

        return allowDecision(policyVerdict != null ? "proof-carrying action authorized (full policy)" : "proof-carrying action verified", verdict, pcactn, required, policyVerdict);
    }

    /**
     * Build a reusable authorizer bound to one configuration. Throws when a component is missing (the policy, a replay guard in signature-only
     * mode, the state store and revocation check in full mode). The configuration is not copied: do not change it afterwards.
     */
    public static Function<GatewayRequest, Decision> createGateway(GatewayOptions opts) {
        List<String> missing = missingPolicy(opts);
        if (!missing.isEmpty()) throw new JsVal.TypeError("pca-gateway: " + missingText(opts, missing));
        final GatewayOptions frozen = opts;
        return req -> authorize(req, frozen);
    }

    // ---- Envoy HTTP ext_authz -----------------------------------------------------------------------------------------------------------

    private static String strOr(Object v) { return v instanceof String ? (String) v : null; }

    private static Map<String, Object> mapOf(Object v) {
        @SuppressWarnings("unchecked") Map<String, Object> m = v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<>();
        return m;
    }

    /** The raw query (no "?", no "#fragment") of a request target. */
    private static String queryOfTarget(String target) {
        int q = target.indexOf('?');
        if (q < 0) return "";
        String rest = target.substring(q + 1);
        int h = rest.indexOf('#');
        return h >= 0 ? rest.substring(0, h) : rest;
    }

    /** The gateway request of an Envoy check ({method?, path?, authority?, headers?, body?}); the ":method" / ":path" / ":authority" pseudo-headers are the fallback. */
    static GatewayRequest envoyRequest(Map<String, Object> check) {
        Map<String, Object> headers = mapOf(g(check, "headers") == UNDEF ? null : check.get("headers"));
        String method = strOr(check.get("method")) != null ? strOr(check.get("method")) : strOr(headers.get(":method")) != null ? strOr(headers.get(":method")) : "*";
        String target = strOr(check.get("path")) != null ? strOr(check.get("path")) : strOr(headers.get(":path")) != null ? strOr(headers.get(":path")) : "/";
        int mark = -1;
        for (int i = 0; i < target.length(); i++) { char c = target.charAt(i); if (c == '?' || c == '#') { mark = i; break; } }
        String rawPath = mark >= 0 ? target.substring(0, mark) : target;
        String path = rawPath.isEmpty() ? "/" : rawPath;
        String authority = strOr(check.get("authority")) != null ? strOr(check.get("authority")) : strOr(headers.get(":authority"));
        GatewayRequest r = new GatewayRequest(method, path, headers);
        r.query = queryOfTarget(target);
        r.authority = authority;
        r.body = strOr(check.get("body"));
        return r;
    }

    /**
     * Envoy HTTP ext_authz handler. On a valid proof it answers 200 and forwards the verdict upstream on x-pca-verdict / x-pca-verb /
     * x-pca-grant (every injected header is overwritten, unset ones blank); on deny it answers the guard's 401 / 403 / 400 / 503 with a
     * WWW-Authenticate challenge and a JSON error body. Maps in, Map out: {status, headers, body}.
     */
    public static Function<Map<String, Object>, Map<String, Object>> envoyExtAuthz(GatewayOptions opts) {
        Function<GatewayRequest, Decision> gateway = createGateway(opts);
        return check -> {
            Decision d = gateway.apply(envoyRequest(check));
            Map<String, Object> out = new LinkedHashMap<>();
            Map<String, Object> headers = new LinkedHashMap<>();
            if (d.allow) {
                for (String h : PCA_INJECTED_HEADERS) headers.put(h, "");
                headers.putAll(d.headers);
                out.put("status", new Json.Num("200"));
                out.put("headers", headers);
                out.put("body", "");
                return out;
            }
            headers.put("content-type", "application/json");
            headers.putAll(d.headers);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", d.code);
            body.put("reason", d.reason);
            out.put("status", new Json.Num(Integer.toString(d.status)));
            out.put("headers", headers);
            out.put("body", JsFmt.stringify(body));
            return out;
        };
    }

    // ---- Envoy gRPC ext_authz -------------------------------------------------------------------------------------------------------------

    private static final int GRPC_OK = 0, GRPC_UNAUTHENTICATED = 16, GRPC_PERMISSION_DENIED = 7, GRPC_UNAVAILABLE = 14, OVERWRITE_IF_EXISTS_OR_ADD = 2;

    private static List<Object> headerOptions(Map<String, String> h) {
        List<Object> out = new ArrayList<>();
        for (Map.Entry<String, String> e : h.entrySet()) {
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("key", e.getKey());
            header.put("value", e.getValue());
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("header", header);
            o.put("appendAction", new Json.Num(Integer.toString(OVERWRITE_IF_EXISTS_OR_ADD)));
            out.add(o);
        }
        return out;
    }

    private static Map<String, Object> status(int code, String message) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("code", new Json.Num(Integer.toString(code)));
        if (message != null) s.put("message", message);
        return s;
    }

    /**
     * Envoy gRPC ext_authz handler ({@code envoy.service.auth.v3.Authorization/Check}) over the decoded CheckRequest as a Map (camelCase
     * fields); same decisions as {@link #envoyExtAuthz}. On allow it lists every injected header it did not set in {@code headersToRemove}.
     */
    public static Function<Map<String, Object>, Map<String, Object>> envoyGrpcExtAuthz(GatewayOptions opts) {
        Function<GatewayRequest, Decision> gateway = createGateway(opts);
        return check -> {
            Object http = g(g(g(check, "attributes"), "request"), "http");
            Map<String, Object> out = new LinkedHashMap<>();
            if (!(http instanceof Map)) {
                Map<String, Object> denied = new LinkedHashMap<>();
                denied.put("status", status(403, null));
                denied.put("headers", new ArrayList<Object>());
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("error", "invalid-request");
                body.put("reason", "CheckRequest carried no HTTP attributes");
                denied.put("body", JsFmt.stringify(body));
                out.put("status", status(GRPC_PERMISSION_DENIED, "no http request attributes"));
                out.put("deniedResponse", denied);
                return out;
            }
            Map<String, Object> h = mapOf(http);
            Map<String, Object> headers = mapOf(h.get("headers"));
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("headers", headers);
            String method = strOr(h.get("method")) != null ? strOr(h.get("method")) : strOr(headers.get(":method"));
            if (method != null) req.put("method", method);
            String path = strOr(h.get("path")) != null ? strOr(h.get("path")) : strOr(headers.get(":path"));
            if (path != null) req.put("path", path);
            String authority = strOr(h.get("host")) != null ? strOr(h.get("host")) : strOr(headers.get(":authority"));
            if (authority != null) req.put("authority", authority);
            if (strOr(h.get("body")) != null) req.put("body", strOr(h.get("body")));
            Decision d = gateway.apply(envoyRequest(req));
            if (d.allow) {
                Map<String, Object> ok = new LinkedHashMap<>();
                ok.put("headers", headerOptions(d.headers));
                List<Object> remove = new ArrayList<>();
                for (String x : PCA_INJECTED_HEADERS) if (!d.headers.containsKey(x)) remove.add(x);
                ok.put("headersToRemove", remove);
                out.put("status", status(GRPC_OK, ""));
                out.put("okResponse", ok);
                return out;
            }
            Map<String, String> dh = new LinkedHashMap<>();
            dh.put("content-type", "application/json");
            dh.putAll(d.headers);
            Map<String, Object> denied = new LinkedHashMap<>();
            denied.put("status", status(d.status, null));
            denied.put("headers", headerOptions(dh));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", d.code);
            body.put("reason", d.reason);
            denied.put("body", JsFmt.stringify(body));
            out.put("status", status(d.status == 401 ? GRPC_UNAUTHENTICATED : d.status == 503 ? GRPC_UNAVAILABLE : GRPC_PERMISSION_DENIED, d.reason));
            out.put("deniedResponse", denied);
            return out;
        };
    }

    // ---- AWS API Gateway REQUEST (Lambda) authorizer -----------------------------------------------------------------------------------------

    private static String lambdaResource(Map<String, Object> event) {
        String a = strOr(event.get("methodArn"));
        if (a != null) return a;
        String b = strOr(event.get("routeArn"));
        return b != null ? b : "*";
    }

    private static String[] lambdaMethodPath(Map<String, Object> event) {
        Object http = g(g(event, "requestContext"), "http");
        String method = strOr(g(http, "method") == UNDEF ? null : ((Map<?, ?>) http).get("method"));
        if (method == null) method = strOr(event.get("httpMethod"));
        String path = strOr(event.get("rawPath"));
        if (path == null) path = strOr(event.get("path"));
        if (path == null && http instanceof Map) path = strOr(((Map<?, ?>) http).get("path"));
        if (method != null && path != null) return new String[] {method, path};
        String arn = strOr(event.get("methodArn"));
        if (arn == null) arn = strOr(event.get("routeArn"));
        if (arn != null) {
            String[] colon = arn.split(":", -1);
            StringBuilder tail = new StringBuilder();
            for (int i = 5; i < colon.length; i++) { if (i > 5) tail.append(':'); tail.append(colon[i]); }
            String[] parts = tail.toString().split("/", -1);
            String arnMethod = parts.length > 2 ? parts[2].split(" ", -1)[0] : null;
            StringBuilder rest = new StringBuilder();
            for (int i = 3; i < parts.length; i++) { if (i > 3) rest.append('/'); rest.append(parts[i]); }
            return new String[] {method != null ? method : arnMethod != null ? arnMethod : "*", path != null ? path : "/" + rest};
        }
        return new String[] {method != null ? method : "*", path != null ? path : "/"};
    }

    private static String lambdaQuery(Map<String, Object> event) {
        Object raw = event.get("rawQueryString");
        if (raw instanceof String) return (String) raw;
        Object multi = event.get("multiValueQueryStringParameters");
        Object single = event.get("queryStringParameters");
        List<String> pairs = new ArrayList<>();
        if (JsVal.truthy(multi) && multi instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) multi).entrySet()) {
                if (!(e.getValue() instanceof List)) continue;
                for (Object v : (List<?>) e.getValue()) pairs.add(encodeURIComponent((String) e.getKey()) + "=" + encodeURIComponent(jsStr(v)));
            }
        } else if (JsVal.truthy(single) && single instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) single).entrySet()) pairs.add(encodeURIComponent((String) e.getKey()) + "=" + encodeURIComponent(jsStr(e.getValue())));
        }
        return String.join("&", pairs);
    }

    private static GatewayRequest lambdaRequest(Map<String, Object> event) {
        String[] mp = lambdaMethodPath(event);
        GatewayRequest r = new GatewayRequest(mp[0], mp[1], mapOf(event.get("headers")));
        r.query = lambdaQuery(event);
        return r;
    }

    private static Map<String, Object> lambdaPolicy(String effect, Map<String, Object> event) {
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("Action", "execute-api:Invoke");
        st.put("Effect", effect);
        st.put("Resource", lambdaResource(event));
        List<Object> sts = new ArrayList<>();
        sts.add(st);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("Version", "2012-10-17");
        doc.put("Statement", sts);
        return doc;
    }

    private static Map<String, Object> lambdaContext(Decision d) {
        Map<String, Object> c = new LinkedHashMap<>();
        if (d.allow) {
            if (d.verdict != null) c.put("pcaVerdict", JsFmt.stringify(d.verdict));
            return c;
        }
        c.put("pcaDenied", "true");
        c.put("pcaCode", d.code);
        c.put("pcaReason", d.reason);
        c.put("pcaStatus", Integer.toString(d.status));
        return c;
    }

    /**
     * AWS API Gateway REQUEST (Lambda) authorizer over the event Map. A valid, capability-matching proof gets an Allow IAM policy (verdict on
     * {@code context.pcaVerdict}); anything else a Deny policy. REST ({@code methodArn}) and HTTP-API ({@code routeArn}) payloads.
     */
    public static Function<Map<String, Object>, Map<String, Object>> lambdaAuthorizer(GatewayOptions opts) {
        Function<GatewayRequest, Decision> gateway = createGateway(opts);
        return event -> {
            Decision d = gateway.apply(lambdaRequest(event));
            Map<String, Object> out = new LinkedHashMap<>();
            Object grant = d.pcactn == null ? UNDEF : g(d.pcactn, "grant_ref");
            out.put("principalId", grant instanceof String ? grant : "anonymous");
            out.put("policyDocument", lambdaPolicy(d.allow ? "Allow" : "Deny", event));
            out.put("context", lambdaContext(d));
            return out;
        };
    }

    /** HTTP-API simple-response variant ({@code enableSimpleResponses}): {isAuthorized, context} instead of an IAM policy. */
    public static Function<Map<String, Object>, Map<String, Object>> lambdaSimpleAuthorizer(GatewayOptions opts) {
        Function<GatewayRequest, Decision> gateway = createGateway(opts);
        return event -> {
            Decision d = gateway.apply(lambdaRequest(event));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("isAuthorized", d.allow);
            out.put("context", lambdaContext(d));
            return out;
        };
    }

    // ---- Cloudflare Worker (fetch-style middleware, runtime-free) -------------------------------------------------------------------------

    /** The subset of a Fetch request the Worker adapter reads; no Workers runtime type is needed. */
    public interface WorkerRequest {
        String method();
        String url();
        /** The first value of a header (case-insensitive), or null. */
        String header(String name);
        /** Every inbound header name, so the adapter can find all {@code x-pca-*}; null when the request cannot enumerate them. */
        Iterable<String> headerNames();
        /** The body text read from a copy (full-policy mode with the body as params), or null when the request cannot be cloned. */
        default String bodyText() { return null; }
    }

    /** Returns a copy of the request without the named (lower-case) headers, or null when it cannot. */
    @FunctionalInterface public interface RewriteRequest<Req> { Req rewrite(Req request, List<String> dropHeaders); }

    /** Builds the deny response (e.g. a runtime Response) from a JSON body, a status and the headers. */
    @FunctionalInterface public interface WorkerResponder<Res> { Res respond(String body, int status, Map<String, String> headers); }

    /** Names (lower-case) of the inbound {@code x-pca-*} headers a client sent. */
    private static List<String> inboundPcaHeaders(WorkerRequest request) {
        Set<String> found = new LinkedHashSet<>();
        Iterable<String> names = request.headerNames();
        if (names != null) for (String k : names) if (k.toLowerCase(Locale.ROOT).startsWith("x-pca-")) found.add(k.toLowerCase(Locale.ROOT));
        for (String n : PCA_INJECTED_HEADERS) if (request.header(n) != null) found.add(n);
        return new ArrayList<>(found);
    }

    /** The path, authority and raw query of a request URL string, without a URL parser. */
    private static String[] pathFromUrl(String url) {
        String rest = url, authority = "";
        int scheme = rest.indexOf("://");
        if (scheme >= 0) {
            rest = rest.substring(scheme + 3);
            int slash = rest.indexOf('/');
            if (slash >= 0) { authority = rest.substring(0, slash); rest = rest.substring(slash); }
            else { authority = rest; rest = "/"; }
        }
        int mark = -1;
        for (int i = 0; i < rest.length(); i++) { char c = rest.charAt(i); if (c == '?' || c == '#') { mark = i; break; } }
        String path = mark >= 0 ? rest.substring(0, mark) : rest;
        return new String[] {path.isEmpty() ? "/" : path, authority, queryOfTarget(rest)};
    }

    /**
     * Cloudflare Worker middleware: verifies the inbound PCActn and, on allow, calls {@code next} to forward upstream; on deny answers through
     * {@code respond} with the guard's 401 / 403 / 400 / 503, the {@code WWW-Authenticate} challenge and a JSON error body. On allow every inbound
     * {@code x-pca-*} header is removed first so a client cannot forge the headers the gateway owns: through {@code rewriteRequest}; with none
     * (null) a request that carries one is answered 400 {@code forged-pca-header} instead of forwarded.
     */
    public static <Req extends WorkerRequest, Res> Function<Req, Res> cloudflareWorker(GatewayOptions opts, Function<Req, Res> next, RewriteRequest<Req> rewriteRequest, WorkerResponder<Res> respond) {
        Function<GatewayRequest, Decision> gateway = createGateway(opts);
        return request -> {
            String[] p = pathFromUrl(request.url());
            Map<String, Object> headers = new LinkedHashMap<>();
            for (String h : new String[] {"pca-action", "pca-discharges", "pca-narrow"}) { String v = request.header(h); if (v != null) headers.put(h, v); }
            GatewayRequest gr = new GatewayRequest(request.method(), p[0], headers);
            gr.authority = p[1];
            gr.query = p[2];
            if ("full".equals(opts.policyMode) && opts.full != null && opts.full.paramsFromBody && opts.full.paramsFn == null) gr.body = request.bodyText();
            Decision d = gateway.apply(gr);
            if (d.allow) {
                List<String> forged = inboundPcaHeaders(request);
                if (forged.isEmpty()) return next.apply(request);
                Req clean = rewriteRequest == null ? null : rewriteRequest.rewrite(request, forged);
                if (clean != null) return next.apply(clean);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("error", "forged-pca-header");
                body.put("reason", "inbound x-pca-* header cannot be removed");
                Map<String, String> h = new LinkedHashMap<>();
                h.put("content-type", "application/json");
                return respond.respond(JsFmt.stringify(body), 400, h);
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", d.code);
            body.put("reason", d.reason);
            Map<String, String> h = new LinkedHashMap<>();
            h.put("content-type", "application/json");
            h.putAll(d.headers);
            return respond.respond(JsFmt.stringify(body), d.status, h);
        };
    }
}
