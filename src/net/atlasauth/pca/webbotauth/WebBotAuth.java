package net.atlasauth.pca.webbotauth;

import static net.atlasauth.pca.webbotauth.WbaJs.def;
import static net.atlasauth.pca.webbotauth.WbaJs.get;
import static net.atlasauth.pca.webbotauth.WbaJs.sfString;
import static net.atlasauth.pca.webbotauth.WbaJs.trim;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.WhatwgUrl;
import net.atlasauth.pca.webbotauth.WbaJs.ParseError;

/**
 * Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests, in the Cloudflare / AWS WAF
 * "web-bot-auth" profile, so a PCA agent passes automated-traffic bot verification AND carries its per-action proof in the SAME request.
 * The signature base is built byte for byte as the reference builds it.
 *
 * <p>{@link #signRequest} builds the {@code Signature-Input} / {@code Signature} header values with the agent's Ed25519 identity;
 * {@link #verifySignedRequest} rebuilds the base from the request, resolves the key by {@code keyid} (a {@link KeyResolver} or a JWKS directory),
 * verifies the Ed25519 signature strictly (RFC 8032: canonical S, no small-order or non-canonical points) and enforces {@code created} /
 * {@code expires} freshness and the {@code web-bot-auth} tag. It FAILS CLOSED: a parse error, a missing field, a stale window, a wrong tag, an
 * unknown key or a bad signature returns {valid:false, reason} and never throws. A valid signature proves the holder of the key signed THIS
 * request's covered components inside the window; it does not by itself prove the action is authorized (the PCActn verifier's job).
 *
 * <p>Values are parsed JSON (Map, List, String, Boolean, Json.Num, null); input and option bags are Maps keyed by the reference's names. Keys are
 * {@link Keys.EdKey} or a map with a b64u {@code secretKey} (the 32-byte seed). The reference's async calls are plain blocking calls.
 *
 * <p>shortcut: request URLs must be http(s) (ws, wss and ftp too); other schemes are refused where the reference would accept them, and a
 * {@code @target-uri} covering a URL with credentials or a fragment is refused. Upgrade if a non-HTTP request target is ever signed.
 */
public final class WebBotAuth {
    private WebBotAuth() {}

    public static final String WEB_BOT_AUTH_TAG = "web-bot-auth";
    public static final String WEB_BOT_AUTH_ALG = "ed25519";
    public static final String WELL_KNOWN_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
    public static final String DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json";
    public static final String DEFAULT_SIGNATURE_LABEL = "sig1";
    public static final int DEFAULT_EXPIRES_SEC = 300;
    public static final String SIGNATURE_AGENT_HEADER = "Signature-Agent";
    public static final String PCA_HEADER = "PCA-Action";
    /** The covered-component (lowercase) name of the PCA proof header. */
    public static final String PCA_PROOF_COMPONENT = "pca-action";

    /** Maps a keyid to its Ed25519 public key: a 32-byte {@code byte[]}, a public JWK map, or null for unknown. */
    @FunctionalInterface
    public interface KeyResolver { Object resolve(String keyid) throws Exception; }

    /** Single-use store for accepted signatures: true if {@code key} was claimed for the first time (until {@code expiresAtSec}). */
    @FunctionalInterface
    public interface ReplayCache { boolean claim(String key, double expiresAtSec, double nowSec) throws Exception; }

    /** In-process {@link ReplayCache}. Fails CLOSED (throws) when {@code maxEntries} unexpired claims are held. */
    public static ReplayCache memoryReplayCache(int maxEntries) {
        Map<String, Double> seen = new LinkedHashMap<>();
        return (key, expiresAtSec, nowSec) -> {
            if (!Double.isFinite(nowSec) || !Double.isFinite(expiresAtSec)) return false;
            synchronized (seen) {
                if (seen.size() >= maxEntries) {
                    for (Iterator<Map.Entry<String, Double>> it = seen.entrySet().iterator(); it.hasNext(); ) if (it.next().getValue() < nowSec) it.remove();
                    if (seen.size() >= maxEntries) throw new IllegalStateException("replay cache full");
                }
                Double existing = seen.get(key);
                if (existing != null && !(existing < nowSec)) return false;
                seen.put(key, expiresAtSec);
                return true;
            }
        };
    }

    public static ReplayCache memoryReplayCache() { return memoryReplayCache(100_000); }

    // ---- keys ----

    /** An Ed25519 signing identity from a {@link Keys.EdKey} or a map with a b64u {@code secretKey} seed. */
    static Keys.EdKey edKey(Object k) {
        if (k instanceof Keys.EdKey) return (Keys.EdKey) k;
        Object sk = get(k, "secretKey");
        if (!(sk instanceof String)) throw new IllegalArgumentException("key must carry a secretKey");
        return Keys.edFromSeed(Keys.unb64u((String) sk));
    }

    /** RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK). */
    public static String jwkThumbprint(byte[] publicKey) {
        try {
            String canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Keys.b64u(publicKey) + "\"}";
            return Keys.b64u(MessageDigest.getInstance("SHA-256").digest(Json.utf8(canonical)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- structured-field helpers ----

    private static List<String> splitTopLevel(String s, char sep) {
        List<String> out = new ArrayList<>();
        int depth = 0, start = 0;
        boolean inStr = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') depth = Math.max(0, depth - 1);
            else if (c == sep && depth == 0) { out.add(s.substring(start, i)); start = i + 1; }
        }
        out.add(s.substring(Math.min(start, s.length())));
        return out;
    }

    private static final class Sf {
        final String value;
        final int next;
        Sf(String value, int next) { this.value = value; this.next = next; }
    }

    private static Sf readSfString(String s, int i) {
        if (i >= s.length() || s.charAt(i) != '"') throw new ParseError("expected a quoted string");
        StringBuilder out = new StringBuilder();
        for (int j = i + 1; j < s.length(); j++) {
            char c = s.charAt(j);
            if (c == '\\') {
                if (j + 1 >= s.length() || (s.charAt(j + 1) != '"' && s.charAt(j + 1) != '\\')) throw new ParseError("invalid escape in string");
                out.append(s.charAt(j + 1));
                j++;
            } else if (c == '"') {
                return new Sf(out.toString(), j + 1);
            } else {
                out.append(c);
            }
        }
        throw new ParseError("unterminated string");
    }

    private static final Pattern INT = Pattern.compile("-?\\d+");
    private static final Pattern DEC = Pattern.compile("-?\\d+\\.\\d+");

    private static Object parseParamValue(String raw) {
        String s = trim(raw);
        if (s.isEmpty()) return Boolean.TRUE;
        if (s.charAt(0) == '"') {
            Sf sf = readSfString(s, 0);
            if (sf.next != s.length()) throw new ParseError("trailing characters after string parameter");
            return sf.value;
        }
        if (s.equals("?1")) return Boolean.TRUE;
        if (s.equals("?0")) return Boolean.FALSE;
        if (INT.matcher(s).matches() || DEC.matcher(s).matches()) return Double.valueOf(Double.parseDouble(s));
        return s;
    }

    private static Map<String, Object> parseParams(String paramStr) {
        Map<String, Object> params = new LinkedHashMap<>();
        String trimmed = trim(paramStr);
        if (trimmed.isEmpty()) return params;
        if (trimmed.charAt(0) != ';') throw new ParseError("expected parameters to start with \";\"");
        for (String part : splitTopLevel(trimmed.substring(1), ';')) {
            String seg = trim(part);
            if (seg.isEmpty()) continue;
            int eq = indexOfTopLevel(seg, '=');
            if (eq == -1) params.put(seg, Boolean.TRUE);
            else params.put(trim(seg.substring(0, eq)), parseParamValue(seg.substring(eq + 1)));
        }
        return params;
    }

    private static int matchingParen(String s, int open) {
        if (open >= s.length() || s.charAt(open) != '(') return -1;
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static int indexOfTopLevel(String s, char ch) {
        int depth = 0;
        boolean inStr = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '(') depth++;
            else if (c == ')') depth = Math.max(0, depth - 1);
            else if (c == ch && depth == 0) return i;
        }
        return -1;
    }

    private static final class Comp {
        final String id, raw, key;
        Comp(String id, String raw, String key) { this.id = id; this.raw = raw; this.key = key; }
    }

    private static final class SigInput {
        final String label, paramsRaw;
        final List<Comp> components;
        final Map<String, Object> params;
        SigInput(String label, List<Comp> components, String paramsRaw, Map<String, Object> params) {
            this.label = label; this.components = components; this.paramsRaw = paramsRaw; this.params = params;
        }
    }

    private static final Pattern KEY_PARAM = Pattern.compile(";key=(\"(?:[^\"\\\\]|\\\\[^\\n\\r\\u2028\\u2029])*\")");

    private static List<SigInput> parseSignatureInput(String value) {
        List<SigInput> entries = new ArrayList<>();
        for (String memberRaw : splitTopLevel(value, ',')) {
            String member = trim(memberRaw);
            if (member.isEmpty()) continue;
            int eq = indexOfTopLevel(member, '=');
            if (eq == -1) throw new ParseError("malformed Signature-Input member");
            String label = trim(member.substring(0, eq));
            String paramsRaw = trim(member.substring(eq + 1));
            if (paramsRaw.isEmpty() || paramsRaw.charAt(0) != '(') throw new ParseError("Signature-Input value must be an inner list");
            int close = matchingParen(paramsRaw, 0);
            if (close == -1) throw new ParseError("unterminated inner list");
            String inner = paramsRaw.substring(1, close);
            List<Comp> components = new ArrayList<>();
            for (String chunkRaw : splitTopLevel(inner, ' ')) {
                String chunk = trim(chunkRaw);
                if (chunk.isEmpty()) continue;
                Sf sf = readSfString(chunk, 0);
                String lowered = WbaJs.lower(sf.value);
                String rest = trim(chunk.substring(sf.next));
                if (rest.isEmpty()) { components.add(new Comp(lowered, "\"" + lowered + "\"", null)); continue; }
                // The only component parameter supported is `key` (dictionary member), on header components.
                Matcher m = KEY_PARAM.matcher(rest);
                if (!m.matches() || lowered.startsWith("@")) throw new ParseError("unsupported component parameters on \"" + sf.value + "\"");
                String key = readSfString(m.group(1), 0).value;
                components.add(new Comp(lowered, "\"" + lowered + "\";key=" + sfString(key), key));
            }
            entries.add(new SigInput(label, components, paramsRaw, parseParams(paramsRaw.substring(close + 1))));
        }
        return entries;
    }

    private static Map<String, byte[]> parseSignature(String value) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (String memberRaw : splitTopLevel(value, ',')) {
            String member = trim(memberRaw);
            if (member.isEmpty()) continue;
            int eq = indexOfTopLevel(member, '=');
            if (eq == -1) throw new ParseError("malformed Signature member");
            String label = trim(member.substring(0, eq));
            String v = trim(member.substring(eq + 1));
            if (v.length() < 2 || v.charAt(0) != ':' || v.charAt(v.length() - 1) != ':') throw new ParseError("Signature value must be a byte sequence (:base64:)");
            out.put(label, WbaJs.nodeBase64(v.substring(1, v.length() - 1)));
        }
        return out;
    }

    // ---- signature base (RFC 9421 section 2.5) ----

    private static final class Ctx {
        String method, authority, path, targetUri, scheme, query, requestTarget;
        Map<String, String> headers;
    }

    private static Map<String, String> normalizeHeaders(Object h) {
        Map<String, String> m = new LinkedHashMap<>();
        if (!(h instanceof Map)) return m;
        for (Map.Entry<?, ?> e : ((Map<?, ?>) h).entrySet()) {
            String name = WbaJs.lower((String) e.getKey());
            Object v = e.getValue();
            String value;
            if (v instanceof List) {
                List<String> parts = new ArrayList<>();
                for (Object x : (List<?>) v) {
                    if (!(x instanceof String)) throw new IllegalStateException("x.trim is not a function");
                    parts.add(trim((String) x));
                }
                value = String.join(", ", parts);
            } else if (v instanceof String) {
                value = trim((String) v);
            } else {
                throw new IllegalStateException("v.trim is not a function");
            }
            String prev = m.get(name);
            m.put(name, prev == null ? value : prev + ", " + value);
        }
        return m;
    }

    private static Ctx buildContext(String method, String url, Map<String, String> headers) {
        WhatwgUrl u = WhatwgUrl.parse(url);
        if (u == null) throw new IllegalArgumentException("Invalid URL");
        if (u.origin().equals("null")) throw new IllegalArgumentException("unsupported URL scheme");
        Ctx c = new Ctx();
        String hostport = u.host + (u.port.isEmpty() ? "" : ":" + u.port);
        c.method = method.toUpperCase(java.util.Locale.ROOT);
        c.authority = WbaJs.lower(hostport);
        c.path = u.pathname.isEmpty() ? "/" : u.pathname;
        int hash = url.indexOf('#');
        String noFrag = hash >= 0 ? url.substring(0, hash) : url;
        int slashes = noFrag.indexOf("//");
        int authEnd = noFrag.length();
        for (int k = slashes + 2; k < noFrag.length(); k++) { char ch = noFrag.charAt(k); if (ch == '/' || ch == '\\' || ch == '?') { authEnd = k; break; } }
        boolean plain = hash < 0 && !(slashes >= 0 && noFrag.substring(slashes + 2, authEnd).indexOf('@') >= 0);
        c.targetUri = plain ? u.protocol + "//" + hostport + u.pathname + u.search + (u.search.isEmpty() && noFrag.indexOf('?') >= 0 ? "?" : "") : null;
        c.scheme = WbaJs.lower(u.protocol.replaceFirst(":$", ""));
        c.query = u.search.isEmpty() ? "?" : u.search;
        c.requestTarget = c.path + u.search;
        c.headers = headers;
        return c;
    }

    private static final Pattern CANON_PARAMS = Pattern.compile("(;[a-z*][a-z0-9_.*-]*(=(\"(?:[^\"\\\\]|\\\\[^\\n\\r\\u2028\\u2029])*\"|[A-Za-z0-9_.:/*+%-]+))?)*");

    private static String deriveComponentValue(Comp component, Ctx ctx) {
        String id = component.id;
        switch (id) {
            case "@method": return ctx.method;
            case "@authority": return ctx.authority;
            case "@path": return ctx.path;
            case "@target-uri":
                if (ctx.targetUri == null) throw new ParseError("@target-uri is not supported for a URL with credentials or a fragment");
                return ctx.targetUri;
            case "@scheme": return ctx.scheme;
            case "@query": return ctx.query;
            case "@request-target": return ctx.requestTarget;
            default: {
                if (id.startsWith("@")) throw new ParseError("unsupported derived component \"" + id + "\"");
                String v = ctx.headers.get(id);
                if (v == null) throw new ParseError("covered header \"" + id + "\" is absent from the request");
                if (component.key != null) return dictionaryMember(v, component.key, id);
                return v;
            }
        }
    }

    /** RFC 9421 section 2.1.2: the serialized value of dictionary member {@code key} of a Structured Field dictionary header (string members only). */
    private static String dictionaryMember(String header, String key, String headerName) {
        for (String memberRaw : splitTopLevel(header, ',')) {
            String member = trim(memberRaw);
            int eq = indexOfTopLevel(member, '=');
            if (eq == -1 || !trim(member.substring(0, eq)).equals(key)) continue;
            String value = trim(member.substring(eq + 1));
            Sf sf = readSfString(value, 0);
            // Parameters are allowed only in compact canonical form, so the verbatim text IS the serialization.
            if (!CANON_PARAMS.matcher(value.substring(sf.next)).matches()) throw new ParseError("member \"" + key + "\" of \"" + headerName + "\" is not in canonical form");
            return value;
        }
        throw new ParseError("\"" + headerName + "\" has no dictionary member \"" + key + "\"");
    }

    private static String buildSignatureBase(List<Comp> components, String paramsRaw, Ctx ctx) {
        List<String> lines = new ArrayList<>();
        for (Comp c : components) lines.add(c.raw + ": " + deriveComponentValue(c, ctx));
        lines.add("\"@signature-params\": " + paramsRaw);
        return String.join("\n", lines);
    }

    // ---- signRequest ----

    private static final Pattern HAS_QUERY = Pattern.compile("\\?[^#]");


    /**
     * Build the {@code Signature-Input} + {@code Signature} header values over the RFC 9421 signature base. {@code input}: method, url, headers?,
     * key (signing identity), keyid, created? (epoch seconds, default now), expiresInSec? (default 300), agentDirectoryUrl? (also emits and covers
     * {@code Signature-Agent}), agentDirectoryKey? (dictionary form, requires agentDirectoryUrl), components? (derived components replacing the default
     * {@code @authority @method @path}; {@code @authority} required), coverHeaders?, nonce?, label?. Returns {signatureInput, signature,
     * signatureAgent?, covered, headers}.
     */
    public static Map<String, Object> signRequest(Map<String, Object> input) {
        String label = input.get("label") != null ? WbaJs.anyStr(input.get("label")) : DEFAULT_SIGNATURE_LABEL;
        double created = input.get("created") != null ? WbaJs.number(input.get("created")) : (double) (System.currentTimeMillis() / 1000);
        double expires = created + (input.get("expiresInSec") != null ? WbaJs.number(input.get("expiresInSec")) : DEFAULT_EXPIRES_SEC);

        Map<String, String> working = normalizeHeaders(input.get("headers"));
        Map<String, Object> emitted = new LinkedHashMap<>();

        List<Comp> components = new ArrayList<>();
        List<String> derived = new ArrayList<>();
        if (input.get("components") != null) {
            for (Object c : JsVal.list(input.get("components"))) derived.add((String) c);
        } else {
            derived.addAll(List.of("@authority", "@method", "@path"));
        }
        String url = (String) input.get("url");
        // by default a URL with a query string also covers @query (the verifier requires it)
        if (input.get("components") == null && HAS_QUERY.matcher(url).find()) derived.add("@query");
        if (!derived.contains("@authority")) throw new IllegalArgumentException("signRequest: the web-bot-auth profile requires @authority to be covered");
        for (String id : derived) {
            String lower = WbaJs.lower(id);
            if (!lower.startsWith("@")) throw new IllegalArgumentException("signRequest: components must be derived components, got \"" + id + "\" (use coverHeaders for headers)");
            components.add(new Comp(lower, "\"" + lower + "\"", null));
        }

        String signatureAgent = null;
        if (def(input, "agentDirectoryUrl")) {
            boolean hasKey = def(input, "agentDirectoryKey");
            if (hasKey && !(input.get("agentDirectoryKey") instanceof String)) throw new IllegalArgumentException("signRequest: agentDirectoryKey must be a string");
            String key = hasKey ? (String) input.get("agentDirectoryKey") : null;
            String agentUrl = (String) input.get("agentDirectoryUrl");
            signatureAgent = !hasKey ? sfString(agentUrl) : key + "=" + sfString(agentUrl);
            working.put("signature-agent", signatureAgent);
            emitted.put(SIGNATURE_AGENT_HEADER, signatureAgent);
            components.add(!hasKey ? new Comp("signature-agent", "\"signature-agent\"", null) : new Comp("signature-agent", "\"signature-agent\";key=" + sfString(key), key));
        } else if (def(input, "agentDirectoryKey")) {
            throw new IllegalArgumentException("signRequest: agentDirectoryKey requires agentDirectoryUrl");
        }

        if (input.get("coverHeaders") != null) {
            List<Object> names = new ArrayList<>();
            if (input.get("coverHeaders") instanceof String) ((String) input.get("coverHeaders")).codePoints().forEach(cp -> names.add(new String(Character.toChars(cp))));
            else names.addAll(JsVal.list(input.get("coverHeaders")));
            for (Object n : names) {
                String name = (String) n;
                String lower = WbaJs.lower(name);
                if (!working.containsKey(lower)) throw new IllegalArgumentException("signRequest: covered header \"" + name + "\" is not present in headers");
                boolean have = false;
                for (Comp c : components) if (c.id.equals(lower)) { have = true; break; }
                if (!have) components.add(new Comp(lower, "\"" + lower + "\"", null));
            }
        }

        Ctx ctx = buildContext((String) input.get("method"), url, working);

        // The parameter order follows the examples in the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag.
        List<String> raws = new ArrayList<>();
        for (Comp c : components) raws.add(c.raw);
        String paramsRaw = "(" + String.join(" ", raws) + ");created=" + WbaJs.numStr(created) + ";keyid=" + sfString((String) input.get("keyid"))
            + ";alg=" + sfString(WEB_BOT_AUTH_ALG) + ";expires=" + WbaJs.numStr(expires);
        if (def(input, "nonce")) paramsRaw += ";nonce=" + sfString((String) input.get("nonce"));
        paramsRaw += ";tag=" + sfString(WEB_BOT_AUTH_TAG);

        String base = buildSignatureBase(components, paramsRaw, ctx);
        byte[] sig = edKey(input.get("key")).sign(Json.utf8(base));

        String signatureInput = label + "=" + paramsRaw;
        String signature = label + "=:" + WbaJs.b64(sig) + ":";
        emitted.put("Signature-Input", signatureInput);
        emitted.put("Signature", signature);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("signatureInput", signatureInput);
        out.put("signature", signature);
        if (signatureAgent != null) out.put("signatureAgent", signatureAgent);
        List<Object> covered = new ArrayList<>();
        for (Comp c : components) covered.add(c.id);
        out.put("covered", covered);
        out.put("headers", emitted);
        return out;
    }

    // ---- verifySignedRequest ----

    private static String xFromResolved(Object k) {
        if (k == null) return null;
        if (k instanceof byte[]) return ((byte[]) k).length == 32 ? Keys.b64u((byte[]) k) : null;
        if (k instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) k;
            if (m.get("x") instanceof String && "Ed25519".equals(m.get("crv")) && "OKP".equals(m.get("kty"))) return (String) m.get("x");
        }
        return null;
    }

    private static String resolvePublicKeyX(String keyid, Map<String, Object> opts, double now, double skew) throws Exception {
        if (opts.get("resolveKey") != null) return xFromResolved(((KeyResolver) opts.get("resolveKey")).resolve(keyid));
        if (opts.get("jwks") != null) {
            Map<String, Object> match = null;
            for (Object j : JsVal.list(get(opts.get("jwks"), "keys"))) if (j instanceof Map && keyid.equals(((Map<?, ?>) j).get("kid"))) { match = JsVal.map(j); break; }
            if (match == null) return null;
            // A published validity window is enforced; a bound that is present but not a finite number cannot be checked, so the key resolves to nothing.
            for (String b : new String[] {"nbf", "exp"}) {
                if (match.containsKey(b)) {
                    Double d = JsVal.num(match.get(b));
                    if (d == null || Double.isNaN(d) || Double.isInfinite(d)) return null;
                }
            }
            if (match.containsKey("nbf") && !(Double.isFinite(now) && Double.isFinite(skew) && now + skew >= WbaJs.number(match.get("nbf")))) return null;
            if (match.containsKey("exp") && !(Double.isFinite(now) && Double.isFinite(skew) && now - skew <= WbaJs.number(match.get("exp")))) return null;
            return xFromResolved(match);
        }
        return null;
    }

    private static boolean ed25519VerifyX(String x, byte[] message, byte[] sig) {
        try {
            if (sig.length != 64) return false;
            byte[] pk = Pca.decodeB64uStrict(x, 32);
            return pk != null && Jose.verifyEd25519Strict(pk, message, sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Map<String, Object> invalid(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("valid", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }

    private static Json.Num num(double d) { return new Json.Num(WbaJs.numStr(d)); }

    /**
     * Verify the HTTP Message Signature of {@code req} ({method, url, headers}). {@code opts}: resolveKey ({@link KeyResolver}, takes precedence) or
     * jwks (a key directory), now (epoch seconds), clockSkewSec (0), maxAgeSec, requireExpires (default true), requiredTag (default web-bot-auth;
     * null = not enforced), label, requiredComponents (default {@code @authority @method @path}, plus {@code @query} when the URL has a query),
     * maxLifetimeSec (default 300; Infinity disables), replayCache ({@link ReplayCache}). Returns {valid, reason?, label?, keyid?, covered?, created?,
     * expires?, tag?, nonce?}; never throws.
     */
    public static Map<String, Object> verifySignedRequest(Map<String, Object> req, Map<String, Object> opts) {
        try {
            if (opts.get("resolveKey") == null && opts.get("jwks") == null) return invalid("verifySignedRequest: provide resolveKey or jwks");
            Map<String, String> headers = normalizeHeaders(req.get("headers"));
            String sigInputHeader = headers.get("signature-input");
            String sigHeader = headers.get("signature");
            if (sigInputHeader == null || sigHeader == null) return invalid("missing Signature-Input or Signature header");

            List<SigInput> inputs = parseSignatureInput(sigInputHeader);
            Map<String, byte[]> sigs = parseSignature(sigHeader);
            Object requiredTag = def(opts, "requiredTag") ? opts.get("requiredTag") : WEB_BOT_AUTH_TAG;

            SigInput chosen = null;
            if (def(opts, "label")) { for (SigInput e : inputs) if (e.label.equals(opts.get("label"))) { chosen = e; break; } }
            else if (requiredTag != null) {
                for (SigInput e : inputs) if (Objects.equals(e.params.get("tag"), requiredTag)) { chosen = e; break; }
                if (chosen == null && !inputs.isEmpty()) chosen = inputs.get(0);
            } else if (!inputs.isEmpty()) chosen = inputs.get(0);
            if (chosen == null) return invalid("no matching signature in Signature-Input");

            byte[] sigBytes = sigs.get(chosen.label);
            if (sigBytes == null) return invalid("no Signature entry for label \"" + chosen.label + "\"");

            String tag = chosen.params.get("tag") instanceof String ? (String) chosen.params.get("tag") : null;
            if (requiredTag != null && !Objects.equals(tag, requiredTag)) {
                return invalid("tag \"" + (tag == null ? "undefined" : tag) + "\" does not match required \"" + WbaJs.anyStr(requiredTag) + "\"");
            }

            // web-bot-auth requires @authority to be covered; @method and @path too, so a signature for one request cannot be replayed on another
            // method or path of the same host.
            Set<String> covered = new HashSet<>();
            for (Comp c : chosen.components) covered.add(c.id);
            List<Object> required = opts.get("requiredComponents") != null ? JsVal.list(opts.get("requiredComponents")) : new ArrayList<>(List.of("@authority", "@method", "@path"));
            for (Object id : required) if (!covered.contains(id)) return invalid(WbaJs.anyStr(id) + " is not a covered component");
            if (!def(opts, "requiredComponents")) {
                String url = (String) req.get("url");
                int q = url.indexOf('?');
                if (q >= 0 && !url.substring(q + 1).split("#", -1)[0].isEmpty() && !covered.contains("@query")) return invalid("@query is not a covered component");
            }

            Object alg = chosen.params.get("alg");
            if (alg != null && !WEB_BOT_AUTH_ALG.equals(alg)) return invalid("unsupported alg \"" + WbaJs.str(alg) + "\"");

            // Freshness.
            double now = opts.get("now") != null ? WbaJs.number(opts.get("now")) : (double) (System.currentTimeMillis() / 1000);
            double skew = opts.get("clockSkewSec") != null ? WbaJs.number(opts.get("clockSkewSec")) : 0;
            Double created = chosen.params.get("created") instanceof Double ? (Double) chosen.params.get("created") : null;
            Double expires = chosen.params.get("expires") instanceof Double ? (Double) chosen.params.get("expires") : null;
            if (expires == null && !Boolean.FALSE.equals(opts.get("requireExpires"))) return invalid("missing expires parameter");
            if (expires != null && !(Double.isFinite(now) && Double.isFinite(skew) && Double.isFinite(expires) && now <= expires + skew)) return invalid("signature has expired");
            if (created != null && !(Double.isFinite(now) && Double.isFinite(skew) && Double.isFinite(created) && created <= now + skew)) return invalid("signature created-time is in the future");
            if (opts.get("maxAgeSec") != null && created != null && !(Double.isFinite(now) && Double.isFinite(skew) && now - created <= WbaJs.number(opts.get("maxAgeSec")) + skew)) return invalid("signature is older than maxAgeSec");
            double maxLifetime = opts.get("maxLifetimeSec") != null ? WbaJs.number(opts.get("maxLifetimeSec")) : 300;
            if (!Double.isNaN(maxLifetime) && !Double.isInfinite(maxLifetime)) {
                if (created == null) return invalid("missing created parameter (needed to bound the signature lifetime)");
                if (expires != null && !(expires - created <= maxLifetime)) return invalid("signature lifetime exceeds maxLifetimeSec");
            }

            String keyid = chosen.params.get("keyid") instanceof String ? (String) chosen.params.get("keyid") : null;
            if (keyid == null) return invalid("missing keyid parameter");
            String x = resolvePublicKeyX(keyid, opts, now, skew);
            if (x == null) return invalid("could not resolve key \"" + keyid + "\"");

            Ctx ctx = buildContext((String) req.get("method"), (String) req.get("url"), headers);
            String base = buildSignatureBase(chosen.components, chosen.paramsRaw, ctx);
            if (!ed25519VerifyX(x, Json.utf8(base), sigBytes)) return invalid("signature does not verify under the resolved key");

            String nonce = chosen.params.get("nonce") instanceof String ? (String) chosen.params.get("nonce") : null;
            if (opts.get("replayCache") != null) {
                boolean finite = !Double.isNaN(maxLifetime) && !Double.isInfinite(maxLifetime);
                double until = expires != null ? expires : created != null ? created + (finite ? maxLifetime : 3600) : now + 3600;
                String key = keyid + "|" + (nonce != null ? nonce : Keys.b64u(sigBytes));
                if (!((ReplayCache) opts.get("replayCache")).claim(key, until + skew, now)) return invalid("replayed signature");
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("valid", Boolean.TRUE);
            out.put("label", chosen.label);
            out.put("keyid", keyid);
            List<Object> cov = new ArrayList<>();
            for (Comp c : chosen.components) cov.add(c.id);
            out.put("covered", cov);
            if (created != null) out.put("created", num(created));
            if (expires != null) out.put("expires", num(expires));
            if (tag != null) out.put("tag", tag);
            if (nonce != null) out.put("nonce", nonce);
            return out;
        } catch (Exception e) {
            return invalid("verification failed (fail closed): " + e.getMessage());
        }
    }

    // ---- key directory (JWKS) + handler ----

    private static byte[] pub(Object o) {
        if (o instanceof byte[]) return (byte[]) o;
        if (o instanceof String) return Keys.unb64u((String) o);
        throw new IllegalArgumentException("publicKey must be bytes or a b64u string");
    }

    /** The JWKS for a list of {publicKey (bytes or b64u), keyid?, use?, nbf?, exp?}: {keys: [{kty, crv, x, kid, use?, nbf?, exp?}]}. */
    public static Map<String, Object> buildKeyDirectory(List<Map<String, Object>> keys) {
        List<Object> list = new ArrayList<>();
        for (Map<String, Object> k : keys) {
            byte[] pk = pub(k.get("publicKey"));
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("kty", "OKP");
            e.put("crv", "Ed25519");
            e.put("x", Keys.b64u(pk));
            e.put("kid", k.get("keyid") != null ? k.get("keyid") : jwkThumbprint(pk));
            if (def(k, "use")) e.put("use", k.get("use"));
            if (def(k, "nbf")) e.put("nbf", k.get("nbf"));
            if (def(k, "exp")) e.put("exp", k.get("exp"));
            list.add(e);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keys", list);
        return out;
    }

    /** Resolve a public key JWK from a directory by {@code kid} (null when absent). */
    public static Map<String, Object> resolveFromDirectory(Map<String, Object> directory, String keyid) {
        for (Object j : JsVal.list(directory.get("keys"))) if (j instanceof Map && keyid.equals(((Map<?, ?>) j).get("kid"))) return JsVal.map(j);
        return null;
    }

    /**
     * A framework-agnostic handler for the well-known directory path: returns {status, headers, body} (200 JSON) when the path (before any
     * {@code ?}) is {@link #WELL_KNOWN_DIRECTORY_PATH}, otherwise null so a caller can fall through.
     */
    public static Function<String, Map<String, Object>> directoryHandler(List<Map<String, Object>> keys) {
        String body = JsVal.stringify(buildKeyDirectory(keys));
        return pathname -> {
            int q = pathname.indexOf('?');
            String path = q >= 0 ? pathname.substring(0, q) : pathname;
            if (!path.equals(WELL_KNOWN_DIRECTORY_PATH)) return null;
            Map<String, Object> headers = new LinkedHashMap<>();
            headers.put("content-type", DIRECTORY_CONTENT_TYPE);
            headers.put("cache-control", "max-age=86400");
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", new Json.Num("200"));
            out.put("headers", headers);
            out.put("body", body);
            return out;
        };
    }

    // ---- PCA proof binding ----

    /** The {@code PCA-Action} header carrying a PCActn (base64url of the canonical wire form). */
    public static Map<String, Object> proofHeaders(Object pcactn) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put(PCA_HEADER, Keys.b64u(Json.canonicalize(pcactn).getBytes(StandardCharsets.UTF_8)));
        return h;
    }

    /** Reverse {@link #proofHeaders}: the {@code PCA-Action} header value to the PCActn. Throws IllegalArgumentException when the value is not a strict encoding of one. */
    public static Map<String, Object> decodeProofHeader(String value) {
        String text = Pca.decodePcaHeader(value);
        if (text == null) throw new IllegalArgumentException("PCA-Action is not strict unpadded base64url of UTF-8 text");
        if (Pca.artifactTooLarge(text)) throw new IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON);
        Object v = Json.parse(text);
        if (!(v instanceof Map)) throw new IllegalArgumentException("decodePCActn: not an object");
        return JsVal.map(v);
    }

    /**
     * Sign a request AND bind it to a PCActn: the PCActn goes in the canonical {@code PCA-Action} header and that header is a covered component, so
     * the single request is bot-verifiable and carries tamper-evident proof of authority. {@code input} is the {@link #signRequest} input plus
     * {@code pcactn}. Returns the sign result with the proof header merged into {@code headers}, plus {@code proofHeader}.
     */
    public static Map<String, Object> signRequestWithProof(Map<String, Object> input) {
        if (!def(input, "pcactn")) throw new IllegalArgumentException("signRequestWithProof: pcactn is required");
        Map<String, Object> proof = proofHeaders(input.get("pcactn"));
        Map<String, Object> headers = new LinkedHashMap<>();
        if (input.get("headers") instanceof Map) headers.putAll(JsVal.map(input.get("headers")));
        headers.putAll(proof);
        List<Object> cover = new ArrayList<>();
        if (input.get("coverHeaders") != null) cover.addAll(JsVal.list(input.get("coverHeaders")));
        cover.add(PCA_PROOF_COMPONENT);
        Map<String, Object> rest = new LinkedHashMap<>(input);
        rest.remove("pcactn");
        rest.put("headers", headers);
        rest.put("coverHeaders", cover);
        Map<String, Object> result = signRequest(rest);
        Map<String, Object> merged = new LinkedHashMap<>(JsVal.map(result.get("headers")));
        merged.putAll(proof);
        result.put("headers", merged);
        result.put("proofHeader", proof);
        return result;
    }

    /**
     * Verify the HTTP Message Signature AND extract the proof: requires {@code PCA-Action} to be a covered component (else fail closed), decodes the
     * PCActn from it, and, when {@code opts.expectedPCActn} is given, checks the carried proof equals it by canonical digest. The returned
     * {@code pcactn} is bound to the verified signature.
     */
    public static Map<String, Object> verifySignedRequestWithProof(Map<String, Object> req, Map<String, Object> opts) {
        Map<String, Object> base = verifySignedRequest(req, opts);
        if (!Boolean.TRUE.equals(base.get("valid"))) return base;
        Object cov = base.get("covered");
        if (!(cov instanceof List) || !((List<?>) cov).contains(PCA_PROOF_COMPONENT)) return invalid("the " + PCA_HEADER + " proof header is not covered by the signature");
        String headerValue;
        try {
            headerValue = normalizeHeaders(req.get("headers")).get(PCA_PROOF_COMPONENT);
        } catch (RuntimeException e) {
            return invalid("verification failed (fail closed): " + e.getMessage());
        }
        if (headerValue == null) return invalid("missing " + PCA_HEADER + " header");
        Map<String, Object> pcactn;
        try {
            pcactn = decodeProofHeader(headerValue);
        } catch (RuntimeException e) {
            return invalid("invalid PCActn in " + PCA_HEADER + ": " + e.getMessage());
        }
        if (opts.get("expectedPCActn") != null && !Pca.hashCanonical(pcactn).equals(Pca.hashCanonical(opts.get("expectedPCActn")))) {
            return invalid("carried PCActn does not match the expected proof");
        }
        Map<String, Object> out = new LinkedHashMap<>(base);
        out.put("pcactn", pcactn);
        return out;
    }
}
