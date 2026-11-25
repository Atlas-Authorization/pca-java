package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The slice of the WHATWG URL parser and serializer the QRNG HTTP source needs: special-scheme URLs (http, https, ftp, ws, wss) with
 * userinfo, host, port, dot-segment resolution, percent-encoding sets, a form-urlencoded query ({@code searchParams.set}) and a fragment.
 * Any other scheme parses as an opaque URL with an empty host (so the transport check refuses it).
 * shortcut: IPv6 literals are lower-cased but not compressed and numeric IPv4 shorthand is not normalised (127.1 stays 127.1, which the
 * loopback check then refuses: fail closed); upgrade when a caller needs those spellings.
 */
final class WhatwgUrl {
    private final String scheme;
    private final boolean special;
    private String username = "", password = "", host = "";
    private int port = -1;
    private String path = "";
    private String query;     // raw, without '?', null when absent
    private String fragment;  // without '#', null when absent

    private WhatwgUrl(String scheme, boolean special) { this.scheme = scheme; this.special = special; }

    private static int defaultPort(String s) {
        switch (s) { case "http": case "ws": return 80; case "https": case "wss": return 443; case "ftp": return 21; default: return -1; }
    }

    /** Parses an absolute URL; throws IllegalArgumentException("Invalid URL") when it is not one. */
    static WhatwgUrl parse(String input) {
        String s = input;
        int b = 0, e = s.length();
        while (b < e && s.charAt(b) <= 0x20) b++;
        while (e > b && s.charAt(e - 1) <= 0x20) e--;
        s = s.substring(b, e).replace("\t", "").replace("\n", "").replace("\r", "");
        int colon = s.indexOf(':');
        if (colon < 1 || !isAlpha(s.charAt(0))) throw bad();
        for (int i = 1; i < colon; i++) {
            char c = s.charAt(i);
            if (!(isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) throw bad();
        }
        String scheme = s.substring(0, colon).toLowerCase(Locale.ROOT);
        String rest = s.substring(colon + 1);
        boolean special = defaultPort(scheme) >= 0;
        WhatwgUrl u = new WhatwgUrl(scheme, special);
        if (!special) { u.path = rest; return u; }

        int h = rest.indexOf('#');
        if (h >= 0) { u.fragment = encode(rest.substring(h + 1), FRAGMENT); rest = rest.substring(0, h); }
        int q = rest.indexOf('?');
        if (q >= 0) { u.query = encode(rest.substring(q + 1), QUERY_SPECIAL); rest = rest.substring(0, q); }
        int i = 0;
        while (i < rest.length() && (rest.charAt(i) == '/' || rest.charAt(i) == '\\')) i++;
        rest = rest.substring(i);
        int slash = 0;
        while (slash < rest.length() && rest.charAt(slash) != '/' && rest.charAt(slash) != '\\') slash++;
        String authority = rest.substring(0, slash);
        String rawPath = rest.substring(slash);

        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            String ui = authority.substring(0, at);
            authority = authority.substring(at + 1);
            int pc = ui.indexOf(':');
            u.username = encode(pc < 0 ? ui : ui.substring(0, pc), USERINFO);
            u.password = pc < 0 ? "" : encode(ui.substring(pc + 1), USERINFO);
        }
        String hostText = authority, portText = null;
        int pcol = authority.lastIndexOf(':');
        if (pcol >= 0 && authority.indexOf(']', pcol) < 0) { hostText = authority.substring(0, pcol); portText = authority.substring(pcol + 1); }
        u.host = parseHost(hostText);
        if (portText != null && !portText.isEmpty()) {
            for (int k = 0; k < portText.length(); k++) if (portText.charAt(k) < '0' || portText.charAt(k) > '9') throw bad();
            if (portText.length() > 5) throw bad();
            int p = Integer.parseInt(portText);
            if (p > 65535) throw bad();
            u.port = p == defaultPort(scheme) ? -1 : p;
        }
        u.path = normalizePath(rawPath);
        return u;
    }

    private static IllegalArgumentException bad() { return new IllegalArgumentException("Invalid URL"); }
    private static boolean isAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

    private static String parseHost(String text) {
        if (text.startsWith("[")) {
            if (!text.endsWith("]") || text.length() < 4) throw bad();
            String inner = text.substring(1, text.length() - 1).toLowerCase(Locale.ROOT);
            for (int i = 0; i < inner.length(); i++) {
                char c = inner.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':' || c == '.')) throw bad();
            }
            return "[" + inner + "]";
        }
        String h = new String(percentDecode(text), StandardCharsets.UTF_8);
        boolean ascii = true;
        for (int i = 0; i < h.length(); i++) if (h.charAt(i) > 0x7f) ascii = false;
        if (!ascii) {
            try { h = java.net.IDN.toASCII(h, java.net.IDN.ALLOW_UNASSIGNED); } catch (IllegalArgumentException ex) { throw bad(); }
        }
        h = h.toLowerCase(Locale.ROOT);
        if (h.isEmpty()) throw bad();
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (c <= 0x20 || c == 0x7f || "#%/:<>?@[\\]^|".indexOf(c) >= 0) throw bad();
        }
        return h;
    }

    private static String normalizePath(String raw) {
        String p = raw.replace('\\', '/');
        List<String> out = new ArrayList<>();
        String[] segs = p.isEmpty() ? new String[0] : p.substring(1).split("/", -1);
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            boolean last = i == segs.length - 1;
            String l = seg.toLowerCase(Locale.ROOT);
            boolean dot2 = l.equals("..") || l.equals(".%2e") || l.equals("%2e.") || l.equals("%2e%2e");
            boolean dot1 = l.equals(".") || l.equals("%2e");
            if (dot2) { if (!out.isEmpty()) out.remove(out.size() - 1); if (last) out.add(""); }
            else if (dot1) { if (last) out.add(""); }
            else out.add(encode(seg, PATH));
        }
        return "/" + String.join("/", out);
    }

    // ---- percent-encode sets (a predicate over the byte value) ----
    private interface Set { boolean has(int b); }
    private static final Set FRAGMENT = b -> b <= 0x20 || b > 0x7e || b == '"' || b == '<' || b == '>' || b == '`';
    private static final Set QUERY_SPECIAL = b -> b <= 0x20 || b > 0x7e || b == '"' || b == '#' || b == '<' || b == '>' || b == '\'';
    private static final Set PATH = b -> b <= 0x20 || b > 0x7e || b == '"' || b == '#' || b == '<' || b == '>' || b == '?' || b == '`' || b == '{' || b == '}';
    private static final Set USERINFO = b -> PATH.has(b) || b == '/' || b == ':' || b == ';' || b == '=' || b == '@' || (b >= '[' && b <= '^') || b == '|';

    private static String encode(String s, Set set) {
        StringBuilder sb = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            int b = x & 0xff;
            if (set.has(b)) sb.append('%').append(HEX.charAt(b >> 4)).append(HEX.charAt(b & 15));
            else sb.append((char) b);
        }
        return sb.toString();
    }

    private static final String HEX = "0123456789ABCDEF";

    private static byte[] percentDecode(String s) {
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < in.length; i++) {
            int c = in[i] & 0xff;
            if (c == '%' && i + 2 < in.length && hexv(in[i + 1]) >= 0 && hexv(in[i + 2]) >= 0) { out.write(hexv(in[i + 1]) * 16 + hexv(in[i + 2])); i += 2; }
            else out.write(c);
        }
        return out.toByteArray();
    }

    private static int hexv(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // ---- accessors ----
    String protocol() { return scheme + ":"; }
    String username() { return username; }
    String password() { return password; }
    boolean isOpaque() { return !special; }
    /** The host without a port (IPv6 keeps its brackets). */
    String hostname() { return host; }
    /** The host plus a non-default port. */
    String hostWithPort() { return port < 0 ? host : host + ":" + port; }

    /** {@code searchParams.set(name, value)}: replaces the first pair with that name in place, drops later ones, else appends. */
    void setParam(String name, String value) {
        List<String[]> pairs = new ArrayList<>();
        if (query != null) {
            for (String part : query.split("&", -1)) {
                if (part.isEmpty()) continue;
                int eq = part.indexOf('=');
                String n = eq < 0 ? part : part.substring(0, eq), v = eq < 0 ? "" : part.substring(eq + 1);
                pairs.add(new String[] {formDecode(n), formDecode(v)});
            }
        }
        boolean found = false;
        List<String[]> next = new ArrayList<>();
        for (String[] p : pairs) {
            if (p[0].equals(name)) { if (!found) { found = true; next.add(new String[] {name, value}); } }
            else next.add(p);
        }
        if (!found) next.add(new String[] {name, value});
        StringBuilder sb = new StringBuilder();
        for (String[] p : next) { if (sb.length() > 0) sb.append('&'); sb.append(formEncode(p[0])).append('=').append(formEncode(p[1])); }
        query = sb.toString();
    }

    private static String formDecode(String s) { return new String(percentDecode(s.replace('+', ' ')), StandardCharsets.UTF_8); }

    private static String formEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            int b = x & 0xff;
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_') sb.append((char) b);
            else if (b == ' ') sb.append('+');
            else sb.append('%').append(HEX.charAt(b >> 4)).append(HEX.charAt(b & 15));
        }
        return sb.toString();
    }

    /** The serialized URL ({@code URL.href}). */
    String href() {
        if (!special) return scheme + ":" + path;
        StringBuilder sb = new StringBuilder(scheme).append("://");
        if (!username.isEmpty() || !password.isEmpty()) {
            sb.append(username);
            if (!password.isEmpty()) sb.append(':').append(password);
            sb.append('@');
        }
        sb.append(hostWithPort()).append(path);
        if (query != null) sb.append('?').append(query);
        if (fragment != null) sb.append('#').append(fragment);
        return sb.toString();
    }
}
