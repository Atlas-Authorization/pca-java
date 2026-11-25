package net.atlasauth.pca.sandbox;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Egress admission for non-WASM tools: the one outbound request an authorized operation maps to, matched exactly (host, port,
 * method, path, query, body hash). The proxy server itself (sockets, TLS tunnelling) is a runtime concern and not part of this port.
 */
public final class Egress {
    private Egress() {}

    private static final Pattern HOST_RE = Pattern.compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*");
    private static final Pattern METHOD_RE = Pattern.compile("[A-Z]+");
    private static final Pattern BAD_PATH = Pattern.compile("[?#\\\\]|%2e|%2f|%5c|(^|/)\\.\\.?(/|\\z)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENCODED_PATH = Pattern.compile("%2e|%2f|%5c|\\\\", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONNECT_RE = Pattern.compile("([a-z0-9.-]+|\\[[0-9a-f:]+\\]):(\\d{1,5})", Pattern.CASE_INSENSITIVE);
    private static final Pattern V4_TAIL = Pattern.compile("(.*:)(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
    private static final Pattern GROUP = Pattern.compile("[0-9a-f]{1,4}");

    // Node's net.isIPv4 / net.isIPv6 grammar.
    private static final String V4SEG = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
    private static final String V4 = "(?:" + V4SEG + "\\.){3}" + V4SEG;
    private static final String V6SEG = "(?:[0-9a-fA-F]{1,4})";
    private static final Pattern IPV4 = Pattern.compile(V4);
    private static final Pattern IPV6 = Pattern.compile("(?:"
        + "(?:" + V6SEG + ":){7}(?:" + V6SEG + "|:)|"
        + "(?:" + V6SEG + ":){6}(?:" + V4 + "|:" + V6SEG + "|:)|"
        + "(?:" + V6SEG + ":){5}(?::" + V4 + "|(?::" + V6SEG + "){1,2}|:)|"
        + "(?:" + V6SEG + ":){4}(?:(?::" + V6SEG + "){0,1}:" + V4 + "|(?::" + V6SEG + "){1,3}|:)|"
        + "(?:" + V6SEG + ":){3}(?:(?::" + V6SEG + "){0,2}:" + V4 + "|(?::" + V6SEG + "){1,4}|:)|"
        + "(?:" + V6SEG + ":){2}(?:(?::" + V6SEG + "){0,3}:" + V4 + "|(?::" + V6SEG + "){1,5}|:)|"
        + "(?:" + V6SEG + ":){1}(?:(?::" + V6SEG + "){0,4}:" + V4 + "|(?::" + V6SEG + "){1,6}|:)|"
        + "(?::(?:(?::" + V6SEG + "){0,5}:" + V4 + "|(?::" + V6SEG + "){1,7}|:))"
        + ")(?:%[0-9a-zA-Z.:-]{1,})?");

    static boolean isIPv4(String s) { return IPV4.matcher(s).matches(); }

    static boolean isIPv6(String s) { return IPV6.matcher(s).matches(); }

    private static boolean privateV4(int a, int b) {
        return a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a >= 224;
    }

    private static List<String> part(String h) { return h.isEmpty() ? List.of() : java.util.Arrays.asList(h.split(":", -1)); }

    /** The eight 16-bit groups of an IPv6 literal (any spelling Node accepts: compressed or expanded, a dotted v4 tail, any case), or null; a zone id is not parsed. */
    private static int[] ipv6Groups(String ip) {
        if (!isIPv6(ip) || ip.indexOf('%') >= 0) return null;
        String s = ip.toLowerCase(Locale.ROOT);
        Matcher t = V4_TAIL.matcher(s);
        if (t.matches()) {
            s = t.group(1) + Integer.toHexString((Integer.parseInt(t.group(2)) << 8) | Integer.parseInt(t.group(3))) + ":"
                + Integer.toHexString((Integer.parseInt(t.group(4)) << 8) | Integer.parseInt(t.group(5)));
        }
        String[] halves = s.split("::", -1);
        if (halves.length > 2) return null;
        List<String> head = part(halves[0]), rest = halves.length > 1 ? part(halves[1]) : List.of();
        int fill = 8 - head.size() - rest.size();
        if (halves.length == 1 ? fill != 0 : fill < 1) return null;
        List<String> groups = new ArrayList<>(head);
        for (int i = 0; halves.length > 1 && i < fill; i++) groups.add("0");
        groups.addAll(rest);
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) {
            if (!GROUP.matcher(groups.get(i)).matches()) return null;
            g[i] = Integer.parseInt(groups.get(i), 16);
        }
        return g;
    }

    /**
     * Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not its
     * spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address follows its
     * embedded IPv4 address; a zoned address ({@code %id}) is link-scoped, so private. Anything that is not an IP literal (or not a string)
     * counts as private.
     */
    public static boolean isPrivateAddress(Object ipArg) {
        if (!(ipArg instanceof String)) return true;
        String ip = (String) ipArg;
        if (isIPv4(ip)) {
            String[] p = ip.split("\\.");
            return privateV4(Integer.parseInt(p[0]), Integer.parseInt(p[1]));
        }
        int[] g = ipv6Groups(ip);
        if (g == null) return true;
        boolean zero80 = g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0;
        boolean nat64 = g[0] == 0x64 && g[1] == 0xff9b && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0;
        if ((zero80 && (g[5] == 0 || g[5] == 0xffff)) || nat64) return privateV4(g[6] >> 8, g[6] & 0xff);
        return g[0] < 0x2000 || g[0] >= 0x4000;
    }

    private static String sha256b64u(byte[] b) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class Admission {
        String opId, verb, resource;
        Object params;
        String method, scheme, host, path, bodySha256;
        boolean hasBodySha256, pathPrefix, tunnel;
        int port;
        Object query;
        long uses;
        double expiresAt;
    }

    /** The set of admitted requests: one authorized operation, one request template. */
    public static final class EgressPolicy {
        private final List<Admission> admissions = new ArrayList<>();
        private final DoubleSupplier now;

        public EgressPolicy(DoubleSupplier now) { this.now = now != null ? now : () -> (double) System.currentTimeMillis(); }

        /**
         * Admit the request that {@code operation} maps to. Throws unless {@code result} allows exactly {@code operation} and the
         * template is well formed. {@code uses} (default 1) and {@code expiresAt} (default never) are JSON numbers or null.
         */
        public void admit(Authorize.AuthorizeResult result, Authorize.Operation operation, Function<Authorize.Operation, Map<String, Object>> toRequest, Object uses, Object expiresAt) {
            if (!Authorize.isAuthorizedFor(result, operation)) throw new IllegalArgumentException("not_authorized: result does not allow exactly this operation");
            Map<String, Object> t = toRequest.apply(operation);
            if (t == null) throw new IllegalArgumentException("no_egress_for_operation");
            Object host = t.get("host");
            if (!(host instanceof String)) throw new IllegalArgumentException("bad_template_host");
            String h = (String) host;
            if (!(isIPv4(h) || isIPv6(h) || HOST_RE.matcher(h).matches()) || !h.equals(h.toLowerCase(Locale.ROOT))) throw new IllegalArgumentException("bad_template_host");
            Object scheme = t.get("scheme");
            if (!"http".equals(scheme) && !"https".equals(scheme)) throw new IllegalArgumentException("bad_template_scheme");
            Object portV = t.get("port");
            if (portV == null) portV = Long.valueOf("http".equals(scheme) ? 80 : 443);
            Double pd = JsVal.num(portV);
            if (pd == null || pd.isNaN() || pd.isInfinite() || pd != Math.rint(pd) || pd < 1 || pd > 65535) throw new IllegalArgumentException("bad_template_port");
            Object method = t.get("method");
            if (!(method instanceof String) || !METHOD_RE.matcher((String) method).matches()) throw new IllegalArgumentException("bad_template_method");
            Object path = t.get("path");
            if (!(path instanceof String)) throw new JsVal.TypeError("path is not a string");
            String ps = (String) path;
            if (!ps.startsWith("/") || BAD_PATH.matcher(ps).find()) throw new IllegalArgumentException("bad_template_path");
            Double ud = JsVal.num(uses == null ? Long.valueOf(1) : uses);
            if (ud == null || ud.isNaN() || ud.isInfinite() || ud != Math.rint(ud) || ud < 1) throw new IllegalArgumentException("bad_uses");
            Admission a = new Admission();
            a.opId = result.operation != null ? result.operation.id : "";
            a.verb = operation.verb;
            a.resource = operation.resource;
            a.params = operation.params;
            a.method = (String) method;
            a.scheme = (String) scheme;
            a.host = h;
            a.port = (int) (double) pd;
            a.path = ps;
            a.pathPrefix = JsVal.truthy(t.get("path_prefix"));
            a.query = t.get("query") == null ? "" : t.get("query");
            a.hasBodySha256 = t.containsKey("body_sha256");
            a.bodySha256 = t.get("body_sha256") instanceof String ? (String) t.get("body_sha256") : null;
            a.tunnel = Boolean.TRUE.equals(t.get("tunnel"));
            a.uses = (long) (double) ud;
            Double ex = expiresAt == null ? null : JsVal.num(expiresAt);
            a.expiresAt = ex == null ? Double.POSITIVE_INFINITY : ex;
            admissions.add(a);
        }

        /**
         * Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason. Returns
         * {@code {allow:true, op_id, admission:{verb, resource, params_digest}}} or {@code {allow:false, reason}}.
         */
        public Map<String, Object> claim(Object method, Object url, byte[] bodyIn) {
            if (!(method instanceof String)) throw new JsVal.TypeError("method is not a string");
            String m = (String) method;
            Target parsed = parseTarget(m, url instanceof String ? (String) url : JsVal.str(url));
            if (parsed.reason != null) return deny(parsed.reason);
            byte[] body = bodyIn == null ? new byte[0] : bodyIn;
            String why = "no_admission";
            for (Admission a : admissions) {
                if (parsed.connect != a.tunnel) continue;
                if (!a.method.equals(m.toUpperCase(Locale.ROOT)) && !parsed.connect) continue;
                if (!parsed.scheme.equals(a.scheme) && !parsed.connect) continue;
                if (!parsed.host.equals(a.host) || parsed.port != a.port) continue;
                if (!parsed.connect) {
                    boolean pathOk;
                    if (a.pathPrefix) pathOk = parsed.path.equals(a.path) || parsed.path.startsWith(a.path.endsWith("/") ? a.path : a.path + "/");
                    else pathOk = parsed.path.equals(a.path);
                    if (!pathOk) continue;
                    if (!parsed.query.equals(a.query)) { why = "query_mismatch"; continue; }
                    if (body.length > 0 && (!a.hasBodySha256 || !sha256b64u(body).equals(a.bodySha256))) { why = "body_mismatch"; continue; }
                    if (body.length == 0 && a.hasBodySha256 && !sha256b64u(body).equals(a.bodySha256)) { why = "body_mismatch"; continue; }
                }
                double t = now.getAsDouble();
                if (a.uses < 1 || !(Double.isFinite(t) && t < a.expiresAt)) { why = "spent"; continue; } // reported only when the request would otherwise have matched
                a.uses -= 1;
                Map<String, Object> adm = new LinkedHashMap<>();
                adm.put("verb", a.verb);
                adm.put("resource", a.resource);
                adm.put("params_digest", Pca.hashCanonical(a.params));
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("allow", Boolean.TRUE);
                out.put("op_id", a.opId);
                out.put("admission", adm);
                return out;
            }
            return deny(why);
        }

        private static Map<String, Object> deny(String reason) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("allow", Boolean.FALSE);
            out.put("reason", reason);
            return out;
        }
    }

    private static final class Target {
        String reason;
        boolean connect;
        String scheme, host, path, query;
        int port;
        static Target refuse(String r) { Target t = new Target(); t.reason = r; return t; }
    }

    private static Target parseTarget(String method, String url) {
        Target t = new Target();
        if (method.toUpperCase(Locale.ROOT).equals("CONNECT")) {
            Matcher m = CONNECT_RE.matcher(url);
            if (!m.matches()) return Target.refuse("bad_connect_target");
            t.connect = true;
            t.scheme = "https";
            String h = m.group(1);
            if (h.startsWith("[")) h = h.substring(1);
            if (h.endsWith("]")) h = h.substring(0, h.length() - 1);
            t.host = h.toLowerCase(Locale.ROOT);
            t.port = Integer.parseInt(m.group(2));
            t.path = "";
            t.query = "";
            return t;
        }
        EgressUrl.Parsed u = EgressUrl.parse(url);
        if (u == null) return Target.refuse("not_absolute_url");
        if ((!u.scheme.equals("http") && !u.scheme.equals("https")) || u.credentials || u.hash) return Target.refuse("bad_url");
        // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
        if (ENCODED_PATH.matcher(u.path).find()) return Target.refuse("encoded_path");
        t.connect = false;
        t.scheme = u.scheme;
        t.host = u.host;
        t.port = u.port >= 0 ? u.port : (u.scheme.equals("http") ? 80 : 443);
        t.path = u.path;
        t.query = u.query;
        return t;
    }
}
