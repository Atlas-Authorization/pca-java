package net.atlasauth.pca.gnap;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Issue;

/**
 * GNAP interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1): the four start modes, the two finish methods, the interaction hash,
 * one-time interaction references, and an authorization-server state machine (pending, approved, finalized). The approved
 * interaction then continues through the PCA step-up continuation ({@link Gnap#beginGnapContinuation} / {@link Gnap#completeGnapContinuation}).
 */
public final class Interaction {
    private Interaction() {}

    public static final List<String> START_MODES = Collections.unmodifiableList(Arrays.asList("redirect", "app", "user_code", "user_code_uri"));
    public static final List<String> FINISH_METHODS = Collections.unmodifiableList(Arrays.asList("redirect", "push"));
    /** Named Information hash names (IANA) this implementation computes, with the JDK digest each maps to. */
    public static final Map<String, String> HASH_METHODS;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("sha-256", "SHA-256");
        m.put("sha-384", "SHA-384");
        m.put("sha-512", "SHA-512");
        m.put("sha3-256", "SHA3-256");
        m.put("sha3-512", "SHA3-512");
        HASH_METHODS = Collections.unmodifiableMap(m);
    }

    /** The names JavaScript's {@code in} finds on a plain object besides its own keys (a hash_method of one of these passes {@link #validateInteractRequest}). */
    private static final Set<String> OBJECT_PROTO_NAMES = Set.of("constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__",
        "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString");

    private static final SecureRandom RNG = new SecureRandom();

    private static boolean inHashMethods(Object m) {
        String k = Js.str(m);
        return HASH_METHODS.containsKey(k) || OBJECT_PROTO_NAMES.contains(k);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) { return (List<Object>) o; }

    private static String randomB64u(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String startName(Object e) {
        if (e instanceof String) return (String) e;
        return e instanceof Map && map(e).get("mode") instanceof String ? (String) map(e).get("mode") : null;
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // callback URIs
    // ---------------------------------------------------------------------------------------------------------------------

    private static final Set<String> SPECIAL = Set.of("http", "https", "ftp", "ws", "wss", "file");

    /** The text a WHATWG URL parser works on: leading and trailing C0 controls and spaces dropped, tab, LF and CR removed. */
    private static String urlInput(String s) {
        int a = 0, b = s.length();
        while (a < b && s.charAt(a) <= 0x20) a++;
        while (b > a && s.charAt(b - 1) <= 0x20) b--;
        StringBuilder sb = new StringBuilder();
        for (int i = a; i < b; i++) { char c = s.charAt(i); if (c != '\t' && c != '\n' && c != '\r') sb.append(c); }
        return sb.toString();
    }

    private static boolean isHostChar(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'; }

    private static boolean numericLabel(String label) {
        if (label.isEmpty()) return false;
        if (label.matches("[0-9]+")) return true;
        return label.matches("0[xX][0-9a-fA-F]*");
    }

    /** A dotted-quad IPv4 literal of four decimal parts each at most 255 (the only numeric host this check accepts). */
    private static boolean plainIpv4(String host) {
        String[] p = host.split("\\.", -1);
        if (p.length != 4) return false;
        for (String x : p) {
            if (!x.matches("[0-9]{1,3}") || (x.length() > 1 && x.charAt(0) == '0') || Integer.parseInt(x) > 255) return false;
        }
        return true;
    }

    /** The parsed shape of a callback URI: lowercase scheme, host (lowercase; null when the scheme has none), the text after the authority. */
    private static final class Url {
        String scheme;
        String host; // as URL.hostname prints it ("[::1]" keeps its brackets)
        String userinfo;
        String port; // as given, "" when absent
        String rest; // path, query (no fragment: callbackUriOk refuses those)
        boolean hasAuthority;
    }

    /**
     * A conservative reading of what {@code new URL(uri)} accepts. Anything this parser is unsure about (a special scheme without
     * {@code //}, an internationalized or exotic host, a short IPv4 form, an IPv6 literal other than {@code [::1]}) is refused:
     * the result is never more permissive than the reference.
     */
    private static Url parseUrl(String uri) {
        String s = urlInput(uri);
        int colon = s.indexOf(':');
        if (colon <= 0) return null;
        String scheme = s.substring(0, colon);
        if (!scheme.matches("[A-Za-z][A-Za-z0-9+.\\-]*")) return null;
        Url u = new Url();
        u.scheme = scheme.toLowerCase(Locale.ROOT);
        String after = s.substring(colon + 1);
        boolean special = SPECIAL.contains(u.scheme);
        if (!after.startsWith("//")) {
            if (special) return null;
            u.rest = after;
            return u;
        }
        String auth = after.substring(2);
        int end = auth.length();
        for (int i = 0; i < auth.length(); i++) { char c = auth.charAt(i); if (c == '/' || c == '?' || (special && c == '\\')) { end = i; break; } }
        u.rest = auth.substring(end);
        auth = auth.substring(0, end);
        u.hasAuthority = true;
        int at = auth.lastIndexOf('@');
        u.userinfo = at >= 0 ? auth.substring(0, at) : null;
        String hostport = at >= 0 ? auth.substring(at + 1) : auth;
        int pc = hostport.lastIndexOf(':');
        String host = hostport, port = "";
        if (hostport.startsWith("[")) {
            int close = hostport.indexOf(']');
            if (close < 0) return null;
            host = hostport.substring(0, close + 1);
            String tail = hostport.substring(close + 1);
            if (!tail.isEmpty()) { if (!tail.startsWith(":")) return null; port = tail.substring(1); }
            if (!host.equals("[::1]")) return null; // the only IPv6 literal this check reads
        } else if (pc >= 0) {
            host = hostport.substring(0, pc);
            port = hostport.substring(pc + 1);
        }
        if (!port.isEmpty()) {
            if (!port.matches("[0-9]+") || port.length() > 9 || Long.parseLong(port) > 65535) return null;
        }
        u.port = port;
        if (!host.startsWith("[")) {
            for (int i = 0; i < host.length(); i++) if (!isHostChar(host.charAt(i))) return null;
            if (host.isEmpty() && special && !u.scheme.equals("file")) return null;
            String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
            String last = h.contains(".") ? h.substring(h.lastIndexOf('.') + 1) : h;
            if (numericLabel(last) && !plainIpv4(host)) return null;
            for (String label : host.split("\\.", -1)) if (label.toLowerCase(Locale.ROOT).startsWith("xn--")) return null;
        }
        u.host = host.toLowerCase(Locale.ROOT);
        return u;
    }

    /** RFC 9635 2.5.2: absolute URI, no fragment; HTTPS, loopback, or an application-specific scheme (not plain http to a remote host). */
    public static boolean callbackUriOk(Object uri) {
        if (!(uri instanceof String) || ((String) uri).length() > 2048) return false;
        String s = (String) uri;
        Url u = parseUrl(s);
        if (u == null) return false;
        if (s.indexOf('#') >= 0) return false;
        if (u.scheme.equals("https")) return true;
        if (u.scheme.equals("http")) return u.host != null && (u.host.equals("localhost") || u.host.equals("127.0.0.1") || u.host.equals("[::1]"));
        return !u.scheme.equals("javascript") && !u.scheme.equals("data") && !u.scheme.equals("file") && !u.scheme.equals("blob");
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // request validation, hashes, codes
    // ---------------------------------------------------------------------------------------------------------------------

    private static boolean printableAscii(String s) {
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x21 || c > 0x7e) return false; }
        return !s.isEmpty();
    }

    /** Validate an {@code interact} request; returns the problems (empty = valid). Unknown start modes are tolerated (the registry is open). */
    public static List<String> validateInteractRequest(Object r) {
        List<String> e = new ArrayList<>();
        if (!(r instanceof Map)) return new ArrayList<>(List.of("interact must be an object"));
        Map<String, Object> o = map(r);
        Object start = o.get("start");
        if (!(start instanceof List) || ((List<?>) start).isEmpty() || ((List<?>) start).size() > 16) e.add("start must be a non-empty array of modes");
        else for (Object s : (List<?>) start) if (startName(s) == null) e.add("each start entry is a mode name or an object with a mode");
        if (o.containsKey("finish")) {
            Object f = o.get("finish");
            if (!Js.isObject(f)) e.add("finish must be an object");
            else {
                Object method = Js.member(f, "method");
                if (!(method instanceof String) || !FINISH_METHODS.contains(method)) e.add("finish.method must be redirect or push");
                if (!callbackUriOk(Js.member(f, "uri"))) e.add("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment");
                Object nonce = Js.member(f, "nonce");
                if (!(nonce instanceof String) || ((String) nonce).length() < 8 || ((String) nonce).length() > 256 || !printableAscii((String) nonce))
                    e.add("finish.nonce must be 8..256 printable ASCII characters");
                if (Js.has(f, "hash_method") && !inHashMethods(map(f).get("hash_method"))) e.add("finish.hash_method is not a supported Named Information hash");
            }
        }
        return e;
    }

    private static byte[] asciiBytes(String s) {
        // Node's 'ascii' encoding keeps the low byte of each UTF-16 code unit
        byte[] b = new byte[s.length()];
        for (int i = 0; i < b.length; i++) b[i] = (byte) s.charAt(i);
        return b;
    }

    private static String hashName(Object method) {
        Object m = method == null ? "sha-256" : method;
        if (!inHashMethods(m)) throw new InteractionError("unsupported_hash", "hash_method " + Js.str(m) + " is not supported");
        String name = m instanceof String ? HASH_METHODS.get(m) : null;
        if (name == null) throw new IllegalArgumentException("hash_method names no digest");
        return name;
    }

    /** RFC 9635 4.2.3: base64url (no padding) of HASH(clientNonce LF asNonce LF interactRef LF grantEndpointUri). {@code a}: clientNonce, asNonce, interactRef, grantEndpoint, hashMethod. */
    public static String interactionHash(Map<String, Object> a) {
        String name = hashName(a.get("hashMethod"));
        String text = Js.str(Js.get(a, "clientNonce")) + "\n" + Js.str(Js.get(a, "asNonce")) + "\n" + Js.str(Js.get(a, "interactRef")) + "\n"
            + Js.str(Js.get(a, "grantEndpoint"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Js.sha(name, asciiBytes(text)));
    }

    /** Client side: does the callback's {@code hash} match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent. */
    public static boolean verifyInteractionHash(Object received, Map<String, Object> a) {
        if (!(received instanceof String)) return false;
        byte[] want = Json.utf8(interactionHash(a));
        byte[] got = Json.utf8(((String) received));
        return want.length == got.length && MessageDigest.isEqual(want, got);
    }

    private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    /** {@code len} (6..12) characters from an alphabet without look-alikes; compared case-insensitively (RFC 9635 3.3.3). */
    public static String newUserCode(int len) {
        if (len < 6 || len > 12) throw new IllegalArgumentException("user code length 6..12");
        byte[] b = new byte[len];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(CODE_ALPHABET.charAt((b[i] & 0xff) % 32)); // 32 symbols, 256 % 32 == 0: no modulo bias
        return sb.toString();
    }

    public static String newUserCode() { return newUserCode(8); }

    private static String normCode(String c) {
        // /[\s-]/g, then upper-case
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < c.length(); i++) {
            char ch = c.charAt(i);
            boolean ws = ch == '-' || ch == ' ' || (ch >= '\t' && ch <= '\r') || ch == '\u00a0' || ch == '\u1680' || (ch >= '\u2000' && ch <= '\u200a') || ch == '\u2028'
                || ch == '\u2029' || ch == '\u202f' || ch == '\u205f' || ch == '\u3000' || ch == '\ufeff';
            if (!ws) sb.append(ch);
        }
        return sb.toString().toUpperCase(Locale.ROOT);
    }

    // ---------------------------------------------------------------------------------------------------------------------
    // the authorization-server state machine
    // ---------------------------------------------------------------------------------------------------------------------

    /** One interaction: state pending, approved or finalized. */
    public static final class State {
        public final String id;
        public String state = "pending";
        public final String grantEndpoint;
        public List<String> modes;
        public Map<String, Object> finish; // method, uri, clientNonce, asNonce, hashMethod
        public String userCode;
        public String interactRef;
        public boolean refUsed;
        public long expiresAt;

        State(String id, String grantEndpoint) { this.id = id; this.grantEndpoint = grantEndpoint; }

        /** The object the reference holds (members that were never set are absent). */
        public Map<String, Object> toMap() {
            Map<String, Object> m = Issue.obj("id", id, "state", state, "grantEndpoint", grantEndpoint, "modes", new ArrayList<Object>(modes));
            if (finish != null) m.put("finish", finish);
            if (userCode != null) m.put("userCode", userCode);
            if (interactRef != null) m.put("interactRef", interactRef);
            m.put("refUsed", refUsed);
            m.put("expiresAt", expiresAt);
            return m;
        }
    }

    /**
     * The authorization server's interaction endpoint. {@code supports}: the modes this AS supports; {@code redirectUri}, {@code appUri}
     * build the interaction URIs; {@code userCodeUri} is the user-code page; {@code ttlSec} (default 600); {@code now} is the clock in seconds.
     */
    public static final class Server {
        private final Map<String, State> byId = new HashMap<>();
        private final Map<String, String> byCode = new HashMap<>();
        private final Map<String, String> byRef = new HashMap<>();
        private final String grantEndpoint;
        private final List<String> supports;
        private final Function<String, String> redirectUri;
        private final Function<String, String> appUri;
        private final String userCodeUri;
        private final Long ttlSec;
        private final LongSupplier now;

        public Server(String grantEndpoint, List<String> supports, Function<String, String> redirectUri, Function<String, String> appUri, String userCodeUri,
                      Long ttlSec, LongSupplier now) {
            this.grantEndpoint = grantEndpoint;
            this.supports = supports;
            this.redirectUri = redirectUri;
            this.appUri = appUri;
            this.userCodeUri = userCodeUri;
            this.ttlSec = ttlSec;
            this.now = now;
        }

        /** Start an interaction from an {@code interact} request: {@code {interaction, response}}. The response never names a mode the client did not ask for nor one the AS does not support (RFC 9635 3.3). */
        public Map<String, Object> start(Map<String, Object> req) {
            List<String> problems = validateInteractRequest(req);
            if (!problems.isEmpty()) throw new InteractionError("invalid_request", String.join("; ", problems));
            Set<String> asked = new LinkedHashSet<>();
            for (Object s : list(req.get("start"))) asked.add(startName(s));
            List<String> modes = new ArrayList<>();
            for (String m : supports) {
                if (asked.contains(m) && (!m.equals("app") || appUri != null) && (!m.equals("user_code_uri") || (userCodeUri != null && !userCodeUri.isEmpty()))) modes.add(m);
            }
            boolean hasFinish = Js.truthy(req.get("finish"));
            if (modes.isEmpty() && !hasFinish) throw new InteractionError("invalid_interaction", "no requested interaction mode is supported");
            String id = randomB64u(16);
            long ttl = ttlSec != null ? ttlSec : 600;
            State it = new State(id, grantEndpoint);
            it.modes = modes;
            it.expiresAt = now.getAsLong() + ttl;
            Map<String, Object> res = Issue.obj("expires_in", ttl);
            if (modes.contains("redirect")) res.put("redirect", redirectUri.apply(id));
            if (modes.contains("app")) res.put("app", appUri.apply(id));
            if (modes.contains("user_code") || modes.contains("user_code_uri")) {
                it.userCode = newUserCode();
                byCode.put(it.userCode, id);
                if (modes.contains("user_code")) res.put("user_code", it.userCode);
                if (modes.contains("user_code_uri")) res.put("user_code_uri", Issue.obj("code", it.userCode, "uri", userCodeUri));
            }
            if (hasFinish) {
                Map<String, Object> f = map(req.get("finish"));
                String asNonce = randomB64u(24);
                Object hm = f.get("hash_method");
                it.finish = Issue.obj("method", f.get("method"), "uri", f.get("uri"), "clientNonce", f.get("nonce"), "asNonce", asNonce, "hashMethod", hm != null ? hm : "sha-256");
                res.put("finish", asNonce);
            }
            byId.put(id, it);
            return Issue.obj("interaction", it, "response", res);
        }

        /** The resource owner typed a code. Case-insensitive. A 32^8 code space is only safe behind a per-source rate limit on this lookup: the caller MUST apply one. */
        public State lookupUserCode(String code) {
            String id = byCode.get(normCode(code));
            State it = id != null ? byId.get(id) : null;
            if (it == null || !it.state.equals("pending") || now.getAsLong() > it.expiresAt) return null;
            return it;
        }

        public State get(String id) { return byId.get(id); }

        private State live(String id) {
            State it = byId.get(id);
            if (it == null) throw new InteractionError("unknown_interaction", "no such interaction");
            if (now.getAsLong() > it.expiresAt) throw new InteractionError("expired", "the interaction expired");
            return it;
        }

        /** The resource owner approved. Returns {@code {interactRef, finish?}}: the finish message to deliver (redirect URL or push body), if the client asked for one. */
        public Map<String, Object> approve(String id) {
            State it = live(id);
            if (!it.state.equals("pending")) throw new InteractionError("wrong_state", "interaction is " + it.state);
            it.state = "approved";
            it.interactRef = randomB64u(18);
            byRef.put(it.interactRef, id);
            if (it.userCode != null) byCode.remove(it.userCode);
            if (it.finish == null) return Issue.obj("interactRef", it.interactRef);
            Map<String, Object> hashArgs = Issue.obj("clientNonce", it.finish.get("clientNonce"), "asNonce", it.finish.get("asNonce"), "interactRef", it.interactRef,
                "grantEndpoint", it.grantEndpoint, "hashMethod", it.finish.get("hashMethod"));
            String hash = interactionHash(hashArgs);
            if ("push".equals(it.finish.get("method")))
                return Issue.obj("interactRef", it.interactRef, "finish", Issue.obj("method", "push", "uri", it.finish.get("uri"), "body", Issue.obj("hash", hash, "interact_ref", it.interactRef)));
            return Issue.obj("interactRef", it.interactRef, "finish", Issue.obj("method", "redirect", "url", redirectUrl((String) it.finish.get("uri"), hash, it.interactRef)));
        }

        /** Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is {@code too_many_attempts}. */
        public State consume(String interactRef) {
            String id = byRef.get(interactRef);
            State it = id != null ? byId.get(id) : null;
            if (it == null) throw new InteractionError("unknown_interaction", "no such interaction reference");
            if (it.refUsed || it.state.equals("finalized")) {
                it.state = "finalized";
                throw new InteractionError("too_many_attempts", "the interaction reference was already used");
            }
            if (now.getAsLong() > it.expiresAt) throw new InteractionError("expired", "the interaction expired");
            if (!it.state.equals("approved")) throw new InteractionError("wrong_state", "interaction is " + it.state);
            it.refUsed = true;
            return it;
        }

        public void finalizeInteraction(String id) {
            State it = byId.get(id);
            if (it != null) it.state = "finalized";
        }
    }

    // ---- the redirect URL: the finish URI with hash and interact_ref set in its query ----------------------------------

    private static String formDecode(String s) {
        try { return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (IllegalArgumentException e) { return s; }
    }

    private static String formEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte bb : Json.utf8(s)) {
            int b = bb & 0xff;
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_') sb.append((char) b);
            else if (b == ' ') sb.append('+');
            else sb.append('%').append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * {@code new URL(uri)} with {@code hash} and {@code interact_ref} set via {@code searchParams.set}, printed. Covers the callback
     * forms {@link #callbackUriOk} accepts: the scheme and host in lower case, the scheme's default port dropped, an empty path of a
     * special scheme printed as {@code /}; the query is re-serialized as {@code application/x-www-form-urlencoded}.
     */
    private static String redirectUrl(String uri, String hash, String ref) {
        Url u = parseUrl(uri);
        if (u == null) throw new IllegalArgumentException("not a URL: " + uri);
        String rest = u.rest == null ? "" : u.rest;
        int q = rest.indexOf('?');
        String path = q >= 0 ? rest.substring(0, q) : rest;
        String query = q >= 0 ? rest.substring(q + 1) : "";
        List<String[]> params = new ArrayList<>();
        if (!query.isEmpty()) {
            for (String pair : query.split("&", -1)) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String k = formDecode((eq >= 0 ? pair.substring(0, eq) : pair).replace('+', ' ')), v = formDecode((eq >= 0 ? pair.substring(eq + 1) : "").replace('+', ' '));
                params.add(new String[] {k, v});
            }
        }
        for (String[] kv : new String[][] {{"hash", hash}, {"interact_ref", ref}}) {
            boolean set = false;
            for (int i = 0; i < params.size(); i++) {
                if (!params.get(i)[0].equals(kv[0])) continue;
                if (!set) { params.get(i)[1] = kv[1]; set = true; } else params.remove(i--);
            }
            if (!set) params.add(kv);
        }
        StringBuilder qs = new StringBuilder();
        for (String[] kv : params) { if (qs.length() > 0) qs.append('&'); qs.append(formEncode(kv[0])).append('=').append(formEncode(kv[1])); }
        StringBuilder out = new StringBuilder(u.scheme).append(':');
        if (u.hasAuthority) {
            out.append("//");
            if (u.userinfo != null && !u.userinfo.isEmpty()) out.append(u.userinfo).append('@');
            out.append(u.host);
            String dp = u.scheme.equals("https") || u.scheme.equals("wss") ? "443" : u.scheme.equals("http") || u.scheme.equals("ws") ? "80" : u.scheme.equals("ftp") ? "21" : "";
            String port = u.port == null ? "" : u.port.replaceFirst("^0+(?=[0-9])", "");
            if (!port.isEmpty() && !port.equals(dp)) out.append(':').append(port);
            if (path.isEmpty() && SPECIAL.contains(u.scheme)) path = "/";
        }
        out.append(path).append('?').append(qs);
        return out.toString();
    }

    /**
     * Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or throws
     * {@code unknown_interaction}. {@code ctx}: clientNonce, asNonce, grantEndpoint, hashMethod.
     */
    public static String acceptFinish(Map<String, Object> cb, Map<String, Object> ctx) {
        Object ref = cb.get("interact_ref");
        if (!(ref instanceof String) || ((String) ref).isEmpty() || !(cb.get("hash") instanceof String))
            throw new InteractionError("unknown_interaction", "hash and interact_ref are required");
        Map<String, Object> a = new LinkedHashMap<>(ctx);
        a.put("interactRef", ref);
        if (!verifyInteractionHash(cb.get("hash"), a)) throw new InteractionError("unknown_interaction", "the callback hash does not validate");
        return (String) ref;
    }

    /**
     * One need ({@code {verb, resource}}) per (action, location) pair, the resource namespaced as {@code gnap:<type>:<location>} exactly like
     * {@link Gnap#gnapActionResource}. An access right with no {@code actions} or no {@code locations} is a wildcard and is REFUSED here.
     */
    public static List<Object> accessToNeeds(List<Object> access) {
        List<Object> out = new ArrayList<>();
        for (Object ao : access) {
            Object actions = Js.member(ao, "actions"), locations = Js.member(ao, "locations");
            if (ao == null) throw new IllegalArgumentException("access entry is null");
            if (!(actions instanceof List) || ((List<?>) actions).isEmpty() || !(locations instanceof List) || ((List<?>) locations).isEmpty())
                throw new InteractionError("invalid_request", "access \"" + Js.str(Js.member(ao, "type")) + "\" needs explicit actions and locations to become a need");
            for (Object verb : (List<?>) actions) for (Object loc : (List<?>) locations)
                out.add(Issue.obj("verb", verb, "resource", "gnap:" + Js.str(Js.member(ao, "type")) + ":" + Js.str(loc)));
        }
        return out;
    }
}
