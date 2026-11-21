package net.atlasauth.pca.oauth;

import net.atlasauth.pca.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The part of the WHATWG URL parser the OAuth ports read (new URL(s): protocol, origin, pathname, search) for absolute URLs without
 * a base. Special schemes (http, https, ftp, ws, wss) get the full authority, host (domain, IPv4, IPv6), port and path handling;
 * file and non-special schemes only validate the scheme (and a non-special authority's host characters).
 * Domain-to-ASCII is UTS 46 through {@link HostIdna}.
 */
public final class WhatwgUrl {
    /** e.g. "https:". */
    public final String protocol;
    /** Serialized host ("" for file and non-special schemes). */
    public final String host;
    /** Port digits, "" when absent or the scheme default. */
    public final String port;
    public final String pathname;
    /** "" or "?" + query. */
    public final String search;
    private final boolean special;

    private WhatwgUrl(String protocol, String host, String port, String pathname, String search, boolean special) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.pathname = pathname;
        this.search = search;
        this.special = special;
    }

    /** scheme://host[:port] for a special scheme (not file); "null" otherwise. */
    public String origin() { return special ? protocol + "//" + host + (port.isEmpty() ? "" : ":" + port) : "null"; }

    private static int defaultPort(String scheme) {
        switch (scheme) {
            case "http": case "ws": return 80;
            case "https": case "wss": return 443;
            case "ftp": return 21;
            default: return -1;
        }
    }

    private static boolean isAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
    private static boolean isDigit(char c) { return c >= '0' && c <= '9'; }

    /** The parsed URL, or null where new URL() would throw. */
    public static WhatwgUrl parse(String input) {
        int a = 0, b = input.length();
        while (a < b && input.charAt(a) <= 0x20) a++;
        while (b > a && input.charAt(b - 1) <= 0x20) b--;
        StringBuilder cleaned = new StringBuilder();
        for (int i = a; i < b; i++) {
            char c = input.charAt(i);
            if (c != '\t' && c != '\n' && c != '\r') cleaned.append(c);
        }
        String s = cleaned.toString();
        if (s.isEmpty() || !isAlpha(s.charAt(0))) return null;
        int i = 1;
        while (i < s.length() && (isAlpha(s.charAt(i)) || isDigit(s.charAt(i)) || s.charAt(i) == '+' || s.charAt(i) == '-' || s.charAt(i) == '.')) i++;
        if (i >= s.length() || s.charAt(i) != ':') return null;
        String scheme = s.substring(0, i).toLowerCase(Locale.ROOT);
        String rest = s.substring(i + 1);
        String proto = scheme + ":";
        if (scheme.equals("file")) return new WhatwgUrl(proto, "", "", "", "", false);
        int dport = defaultPort(scheme);
        if (dport < 0) { // non-special: only an authority's host characters can fail
            if (rest.startsWith("//")) {
                int e = rest.length();
                for (int k = 2; k < rest.length(); k++) { char c = rest.charAt(k); if (c == '/' || c == '?' || c == '#') { e = k; break; } }
                String auth = rest.substring(2, e);
                String hp = auth.substring(auth.lastIndexOf('@') + 1);
                String h = hp.startsWith("[") ? hp : hp.contains(":") ? hp.substring(0, hp.indexOf(':')) : hp;
                if (!h.startsWith("[")) for (int k = 0; k < h.length(); k++) if (forbiddenHost(h.charAt(k))) return null;
            }
            return new WhatwgUrl(proto, "", "", "", "", false);
        }
        int p = 0;
        while (p < rest.length() && (rest.charAt(p) == '/' || rest.charAt(p) == '\\')) p++;
        int e = rest.length();
        for (int k = p; k < rest.length(); k++) { char c = rest.charAt(k); if (c == '/' || c == '\\' || c == '?' || c == '#') { e = k; break; } }
        String authority = rest.substring(p, e);
        int at = authority.lastIndexOf('@');
        String hostport = authority;
        if (at >= 0) {
            hostport = authority.substring(at + 1);
            if (hostport.isEmpty()) return null;
        }
        String hostStr, portStr = "";
        if (hostport.startsWith("[")) {
            int close = hostport.indexOf(']');
            if (close < 0) return null;
            hostStr = hostport.substring(0, close + 1);
            String after = hostport.substring(close + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') return null;
                portStr = after.substring(1);
            }
        } else {
            int colon = hostport.indexOf(':');
            hostStr = colon < 0 ? hostport : hostport.substring(0, colon);
            if (colon >= 0) portStr = hostport.substring(colon + 1);
        }
        String port = "";
        if (!portStr.isEmpty()) {
            for (int k = 0; k < portStr.length(); k++) if (!isDigit(portStr.charAt(k))) return null;
            BigInteger pv = new BigInteger(portStr);
            if (pv.compareTo(BigInteger.valueOf(65535)) > 0) return null;
            port = pv.intValue() == dport ? "" : pv.toString();
        }
        if (hostStr.isEmpty()) return null;
        String host = parseHost(hostStr);
        if (host == null) return null;

        String tail = rest.substring(e);
        int hash = tail.indexOf('#');
        if (hash >= 0) tail = tail.substring(0, hash);
        String pathStr = tail, query = null;
        int q = tail.indexOf('?');
        if (q >= 0) { pathStr = tail.substring(0, q); query = tail.substring(q + 1); }
        String path = parsePath(pathStr);
        String search = query == null || query.isEmpty() ? "" : "?" + encode(query, true);
        return new WhatwgUrl(proto, host, port, path, search, true);
    }

    private static boolean isDoubleDot(String s) {
        String l = s.toLowerCase(Locale.ROOT);
        return l.equals("..") || l.equals(".%2e") || l.equals("%2e.") || l.equals("%2e%2e");
    }

    private static boolean isSingleDot(String s) {
        String l = s.toLowerCase(Locale.ROOT);
        return l.equals(".") || l.equals("%2e");
    }

    private static String parsePath(String pathStr) {
        String t = pathStr;
        if (!t.isEmpty() && (t.charAt(0) == '/' || t.charAt(0) == '\\')) t = t.substring(1);
        List<String> segs = new ArrayList<>();
        int start = 0;
        while (true) {
            int end = t.length();
            boolean more = false;
            for (int k = start; k < t.length(); k++) { char c = t.charAt(k); if (c == '/' || c == '\\') { end = k; more = true; break; } }
            String seg = t.substring(start, end);
            if (isDoubleDot(seg)) {
                if (!segs.isEmpty()) segs.remove(segs.size() - 1);
                if (!more) segs.add("");
            } else if (isSingleDot(seg)) {
                if (!more) segs.add("");
            } else {
                segs.add(encode(seg, false));
            }
            if (!more) break;
            start = end + 1;
        }
        return "/" + String.join("/", segs);
    }

    /** Percent-encode with the path (query=false) or special-query (query=true) set; a lone surrogate becomes U+FFFD. */
    private static String encode(String s, boolean query) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
            boolean enc;
            if (cp > 0x7e) enc = true;
            else if (cp <= 0x20 || cp == 0x7f || cp == '"' || cp == '#' || cp == '<' || cp == '>') enc = true;
            else if (query) enc = cp == '\'';
            else enc = cp == '?' || cp == '`' || cp == '{' || cp == '}';
            if (!enc) { sb.append((char) cp); continue; }
            for (byte by : Json.utf8(new String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", by & 0xff));
        }
        return sb.toString();
    }

    private static boolean forbiddenHost(char c) {
        return c <= 0x20 || c == 0x7f || c == '#' || c == '/' || c == ':' || c == '<' || c == '>' || c == '?' || c == '@' || c == '[' || c == '\\' || c == ']' || c == '^' || c == '|';
    }

    private static boolean forbiddenDomain(char c) { return forbiddenHost(c) || c == '%'; }

    private static String parseHost(String h) {
        if (h.startsWith("[")) {
            if (!h.endsWith("]")) return null;
            int[] pieces = parseIpv6(h.substring(1, h.length() - 1));
            return pieces == null ? null : "[" + serializeIpv6(pieces) + "]";
        }
        String domain = percentDecode(h);
        String ad;
        if (HostIdna.needsProcessing(domain)) {
            ad = HostIdna.toAscii(domain);
            if (ad == null) return null;
        } else ad = domain.toLowerCase(Locale.ROOT);
        if (ad.isEmpty()) return null;
        for (int i = 0; i < ad.length(); i++) if (forbiddenDomain(ad.charAt(i))) return null;
        if (endsInNumber(ad)) return parseIpv4(ad);
        return ad;
    }

    private static String percentDecode(String s) {
        byte[] in = Json.utf8(s);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < in.length; i++) {
            if (in[i] == '%' && i + 2 < in.length && hex(in[i + 1]) >= 0 && hex(in[i + 2]) >= 0) {
                out.write(hex(in[i + 1]) * 16 + hex(in[i + 2]));
                i += 2;
            } else out.write(in[i]);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static int hex(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // ---- IPv4 ----

    private static BigInteger parseIpv4Number(String in) {
        if (in.isEmpty()) return null;
        int radix = 10;
        String t = in;
        if (t.length() >= 2 && (t.startsWith("0x") || t.startsWith("0X"))) { t = t.substring(2); radix = 16; }
        else if (t.length() >= 2 && t.charAt(0) == '0') { t = t.substring(1); radix = 8; }
        if (t.isEmpty()) return BigInteger.ZERO;
        for (int i = 0; i < t.length(); i++) {
            int d = hex(t.charAt(i));
            if (d < 0 || d >= radix) return null;
        }
        return new BigInteger(t, radix);
    }

    private static boolean endsInNumber(String s) {
        List<String> parts = new ArrayList<>(List.of(s.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty()) {
            if (parts.size() == 1) return false;
            parts.remove(parts.size() - 1);
        }
        String last = parts.get(parts.size() - 1);
        if (!last.isEmpty()) {
            boolean digits = true;
            for (int i = 0; i < last.length(); i++) if (!isDigit(last.charAt(i))) { digits = false; break; }
            if (digits) return true;
        }
        return parseIpv4Number(last) != null;
    }

    private static String parseIpv4(String s) {
        List<String> parts = new ArrayList<>(List.of(s.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty() && parts.size() > 1) parts.remove(parts.size() - 1);
        if (parts.size() > 4) return null;
        List<BigInteger> nums = new ArrayList<>();
        for (String p : parts) {
            BigInteger n = parseIpv4Number(p);
            if (n == null) return null;
            nums.add(n);
        }
        for (int i = 0; i < nums.size() - 1; i++) if (nums.get(i).compareTo(BigInteger.valueOf(255)) > 0) return null;
        BigInteger last = nums.get(nums.size() - 1);
        if (last.compareTo(BigInteger.valueOf(256).pow(5 - nums.size())) >= 0) return null;
        BigInteger ip = last;
        for (int i = 0; i < nums.size() - 1; i++) ip = ip.add(nums.get(i).multiply(BigInteger.valueOf(256).pow(3 - i)));
        long v = ip.longValue();
        return ((v >> 24) & 0xff) + "." + ((v >> 16) & 0xff) + "." + ((v >> 8) & 0xff) + "." + (v & 0xff);
    }

    // ---- IPv6 ----

    private static int[] parseIpv6(String in) {
        int[] pieces = new int[8];
        int idx = 0, compress = -1, p = 0, n = in.length();
        if (p < n && in.charAt(p) == ':') {
            if (!(p + 1 < n && in.charAt(p + 1) == ':')) return null;
            p += 2;
            idx++;
            compress = idx;
        }
        while (p < n) {
            if (idx == 8) return null;
            if (in.charAt(p) == ':') {
                if (compress != -1) return null;
                p++;
                idx++;
                compress = idx;
                continue;
            }
            int value = 0, len = 0;
            while (len < 4 && p < n && hex(in.charAt(p)) >= 0) { value = value * 16 + hex(in.charAt(p)); p++; len++; }
            if (p < n && in.charAt(p) == '.') {
                if (len == 0) return null;
                p -= len;
                if (idx > 6) return null;
                int seen = 0;
                while (p < n) {
                    int v4 = -1;
                    if (seen > 0) {
                        if (in.charAt(p) == '.' && seen < 4) p++;
                        else return null;
                    }
                    if (p >= n || !isDigit(in.charAt(p))) return null;
                    while (p < n && isDigit(in.charAt(p))) {
                        int num = in.charAt(p) - '0';
                        if (v4 == -1) v4 = num;
                        else if (v4 == 0) return null;
                        else v4 = v4 * 10 + num;
                        if (v4 > 255) return null;
                        p++;
                    }
                    pieces[idx] = pieces[idx] * 0x100 + v4;
                    seen++;
                    if (seen == 2 || seen == 4) idx++;
                }
                if (seen != 4) return null;
                break;
            } else if (p < n && in.charAt(p) == ':') {
                p++;
                if (p >= n) return null;
            } else if (p < n) return null;
            pieces[idx] = value;
            idx++;
        }
        if (compress != -1) {
            int swaps = idx - compress;
            idx = 7;
            while (idx != 0 && swaps > 0) {
                int t = pieces[compress + swaps - 1];
                pieces[compress + swaps - 1] = pieces[idx];
                pieces[idx] = t;
                idx--;
                swaps--;
            }
        } else if (idx != 8) return null;
        return pieces;
    }

    private static String serializeIpv6(int[] a) {
        int best = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (a[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && a[j] == 0) j++;
            if (j - i > bestLen) { best = i; bestLen = j - i; }
            i = j;
        }
        if (bestLen < 2) best = -1;
        StringBuilder sb = new StringBuilder();
        boolean ignore0 = false;
        for (int i = 0; i < 8; i++) {
            if (ignore0 && a[i] == 0) continue;
            ignore0 = false;
            if (best == i) {
                sb.append(i == 0 ? "::" : ":");
                ignore0 = true;
                continue;
            }
            sb.append(Integer.toHexString(a[i]));
            if (i != 7) sb.append(':');
        }
        return sb.toString();
    }
}
