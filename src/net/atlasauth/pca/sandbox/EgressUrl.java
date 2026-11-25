package net.atlasauth.pca.sandbox;

import net.atlasauth.pca.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The part of the WHATWG URL parser the egress target check needs: scheme, credentials, host, port, path and query of an absolute
 * URL. Hosts must be ASCII (a non-ASCII host is refused: fail closed). Returns null for a URL the parser rejects.
 */
final class EgressUrl {
    private EgressUrl() {}

    static final class Parsed {
        String scheme;
        boolean credentials;
        boolean hash;
        String host = "";
        int port = -1;
        String path = "/";
        String query = "";
    }

    private static int defaultPort(String scheme) {
        switch (scheme) {
            case "http": case "ws": return 80;
            case "https": case "wss": return 443;
            case "ftp": return 21;
            default: return -1;
        }
    }

    static Parsed parse(String input) {
        int b = 0, e = input.length();
        while (b < e && input.charAt(b) <= 0x20) b++;
        while (e > b && input.charAt(e - 1) <= 0x20) e--;
        StringBuilder sb = new StringBuilder();
        for (int i = b; i < e; i++) {
            char c = input.charAt(i);
            if (c != '\t' && c != '\n' && c != '\r') sb.append(c);
        }
        String s = sb.toString();
        int colon = -1;
        if (!s.isEmpty() && isAlpha(s.charAt(0))) {
            for (int i = 1; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == ':') { colon = i; break; }
                if (!(isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) return null;
            }
        }
        if (colon < 0) return null;
        Parsed p = new Parsed();
        p.scheme = s.substring(0, colon).toLowerCase(Locale.ROOT);
        String rest = s.substring(colon + 1);
        boolean special = defaultPort(p.scheme) >= 0 || p.scheme.equals("file");
        if (!special) {
            int h = rest.indexOf('#');
            p.hash = h >= 0 && h + 1 < rest.length();
            return p; // an opaque or hierarchical non-special URL: the caller refuses its scheme
        }
        if (p.scheme.equals("file")) return p;
        int i = 0;
        while (i < rest.length() && (rest.charAt(i) == '/' || rest.charAt(i) == '\\')) i++;
        int end = i;
        while (end < rest.length() && "/\\?#".indexOf(rest.charAt(end)) < 0) end++;
        String authority = rest.substring(i, end);
        String tail = rest.substring(end);
        String hostport = authority;
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = authority.substring(0, at);
            int c = userinfo.indexOf(':');
            String user = c < 0 ? userinfo : userinfo.substring(0, c);
            String pass = c < 0 ? "" : userinfo.substring(c + 1);
            p.credentials = !user.isEmpty() || !pass.isEmpty();
            hostport = authority.substring(at + 1);
            if (hostport.isEmpty()) return null;
        }
        String hostText;
        String portText = "";
        if (hostport.startsWith("[")) {
            int close = hostport.indexOf(']');
            if (close < 0) return null;
            hostText = hostport.substring(0, close + 1);
            String after = hostport.substring(close + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') return null;
                portText = after.substring(1);
            }
        } else {
            int c = hostport.indexOf(':');
            hostText = c < 0 ? hostport : hostport.substring(0, c);
            if (c >= 0) portText = hostport.substring(c + 1);
        }
        if (hostText.isEmpty()) return null;
        if (!portText.isEmpty()) {
            for (int k = 0; k < portText.length(); k++) if (portText.charAt(k) < '0' || portText.charAt(k) > '9') return null;
            BigInteger n = new BigInteger(portText);
            if (n.compareTo(BigInteger.valueOf(65535)) > 0) return null;
            int v = n.intValue();
            p.port = v == defaultPort(p.scheme) ? -1 : v;
        }
        String host = hostText.startsWith("[") ? ipv6Host(hostText.substring(1, hostText.length() - 1)) : domainHost(hostText);
        if (host == null) return null;
        p.host = host;

        int hashAt = tail.indexOf('#');
        String beforeHash = hashAt < 0 ? tail : tail.substring(0, hashAt);
        p.hash = hashAt >= 0 && hashAt + 1 < tail.length();
        int q = beforeHash.indexOf('?');
        String pathPart = q < 0 ? beforeHash : beforeHash.substring(0, q);
        p.query = q < 0 ? "" : encode(beforeHash.substring(q + 1), true);
        p.path = path(pathPart);
        return p;
    }

    private static boolean isAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

    // ---- path and query -------------------------------------------------------------------------------------------------

    private static String path(String raw) {
        if (raw.isEmpty()) return "/";
        String[] parts = raw.replace('\\', '/').substring(1).split("/", -1);
        List<String> stack = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) {
            String seg = parts[i];
            String l = seg.toLowerCase(Locale.ROOT);
            boolean last = i == parts.length - 1;
            if (l.equals("..") || l.equals(".%2e") || l.equals("%2e.") || l.equals("%2e%2e")) {
                if (!stack.isEmpty()) stack.remove(stack.size() - 1);
                if (last) stack.add("");
            } else if (l.equals(".") || l.equals("%2e")) {
                if (last) stack.add("");
            } else stack.add(encode(seg, false));
        }
        return "/" + String.join("/", stack);
    }

    /** Percent-encode with the path (or special-query) encode set: C0 controls, space, ", #, <, >, DEL and non-ASCII (UTF-8); path adds ? ^ ` { }; query adds '. */
    private static String encode(String s, boolean query) {
        StringBuilder out = new StringBuilder();
        for (byte raw : Json.utf8(s)) {
            int c = raw & 0xff;
            boolean enc = c <= 0x20 || c >= 0x7f || c == '"' || c == '#' || c == '<' || c == '>'
                || (query ? c == '\'' : (c == '?' || c == '^' || c == '`' || c == '{' || c == '}'));
            if (enc) out.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            else out.append((char) c);
        }
        return out.toString();
    }

    // ---- hosts ----------------------------------------------------------------------------------------------------------

    private static String domainHost(String text) {
        byte[] src = Json.utf8(text);
        StringBuilder d = new StringBuilder();
        for (int i = 0; i < src.length; i++) {
            int c = src[i] & 0xff;
            if (c == '%' && i + 2 < src.length && hex(src[i + 1] & 0xff) >= 0 && hex(src[i + 2] & 0xff) >= 0) {
                c = hex(src[i + 1] & 0xff) * 16 + hex(src[i + 2] & 0xff);
                i += 2;
            }
            if (c >= 0x80) return null; // non-ASCII host: not ported, refused
            d.append((char) c);
        }
        String domain = d.toString().toLowerCase(Locale.ROOT);
        if (domain.isEmpty()) return null;
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            if (c <= 0x1f || c == 0x7f || " #%/:<>?@[\\]^|".indexOf(c) >= 0) return null;
        }
        if (endsInNumber(domain)) return ipv4Host(domain);
        return domain;
    }

    private static int hex(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static boolean endsInNumber(String domain) {
        List<String> parts = new ArrayList<>(List.of(domain.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty()) {
            if (parts.size() == 1) return false;
            parts.remove(parts.size() - 1);
        }
        String last = parts.get(parts.size() - 1);
        if (!last.isEmpty() && last.chars().allMatch(c -> c >= '0' && c <= '9')) return true;
        if (last.length() >= 2 && last.charAt(0) == '0' && (last.charAt(1) == 'x' || last.charAt(1) == 'X')) {
            for (int i = 2; i < last.length(); i++) if (hex(last.charAt(i)) < 0) return false;
            return true;
        }
        return false;
    }

    private static BigInteger ipv4Number(String in) {
        if (in.isEmpty()) return null;
        int radix = 10;
        String s = in;
        if (s.length() >= 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')) { s = s.substring(2); radix = 16; }
        else if (s.length() >= 2 && s.charAt(0) == '0') { s = s.substring(1); radix = 8; }
        if (s.isEmpty()) return BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int h = hex(s.charAt(i));
            if (h < 0 || h >= radix) return null;
        }
        return new BigInteger(s, radix);
    }

    private static String ipv4Host(String domain) {
        List<String> parts = new ArrayList<>(List.of(domain.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty() && parts.size() > 1) parts.remove(parts.size() - 1);
        if (parts.size() > 4) return null;
        List<BigInteger> nums = new ArrayList<>();
        for (String p : parts) {
            BigInteger n = ipv4Number(p);
            if (n == null) return null;
            nums.add(n);
        }
        for (int i = 0; i < nums.size() - 1; i++) if (nums.get(i).compareTo(BigInteger.valueOf(255)) > 0) return null;
        BigInteger last = nums.get(nums.size() - 1);
        if (last.compareTo(BigInteger.valueOf(256).pow(5 - nums.size())) >= 0) return null;
        BigInteger ip = last;
        for (int i = 0; i < nums.size() - 1; i++) ip = ip.add(nums.get(i).multiply(BigInteger.valueOf(256).pow(3 - i)));
        long v = ip.longValueExact();
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    /** Parse the text between the brackets and serialize it in the compressed lowercase form; null when invalid. */
    private static String ipv6Host(String in) {
        int[] a = new int[8];
        int piece = 0;
        int compress = -1;
        int p = 0;
        int n = in.length();
        if (n > 0 && in.charAt(0) == ':') {
            if (n < 2 || in.charAt(1) != ':') return null;
            p += 2;
            piece++;
            compress = piece;
        }
        while (p < n) {
            if (piece == 8) return null;
            if (in.charAt(p) == ':') {
                if (compress != -1) return null;
                p++;
                piece++;
                compress = piece;
                continue;
            }
            int value = 0, length = 0;
            while (length < 4 && p < n && hex(in.charAt(p)) >= 0) {
                value = value * 16 + hex(in.charAt(p));
                p++;
                length++;
            }
            if (p < n && in.charAt(p) == '.') {
                if (length == 0) return null;
                p -= length;
                if (piece > 6) return null;
                int seen = 0;
                while (p < n) {
                    int v4 = -1;
                    if (seen > 0) {
                        if (in.charAt(p) == '.' && seen < 4) p++;
                        else return null;
                    }
                    if (p >= n || in.charAt(p) < '0' || in.charAt(p) > '9') return null;
                    while (p < n && in.charAt(p) >= '0' && in.charAt(p) <= '9') {
                        int d = in.charAt(p) - '0';
                        if (v4 == -1) v4 = d;
                        else if (v4 == 0) return null;
                        else v4 = v4 * 10 + d;
                        if (v4 > 255) return null;
                        p++;
                    }
                    a[piece] = a[piece] * 0x100 + v4;
                    seen++;
                    if (seen == 2 || seen == 4) piece++;
                }
                if (seen != 4) return null;
                break;
            } else if (p < n && in.charAt(p) == ':') {
                p++;
                if (p >= n) return null;
            } else if (p < n) return null;
            a[piece] = value;
            piece++;
        }
        if (compress != -1) {
            int swaps = piece - compress;
            piece = 7;
            while (piece != 0 && swaps > 0) {
                int t = a[compress + swaps - 1];
                a[compress + swaps - 1] = a[piece];
                a[piece] = t;
                piece--;
                swaps--;
            }
        } else if (piece != 8) return null;
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (a[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && a[j] == 0) j++;
            if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        if (bestLen < 2) bestStart = -1;
        StringBuilder out = new StringBuilder();
        boolean ignore0 = false;
        for (int i = 0; i < 8; i++) {
            if (ignore0 && a[i] == 0) continue;
            ignore0 = false;
            if (bestStart == i) {
                out.append(i == 0 ? "::" : ":");
                ignore0 = true;
                continue;
            }
            out.append(Integer.toHexString(a[i]));
            if (i != 7) out.append(':');
        }
        return out.toString();
    }
}
