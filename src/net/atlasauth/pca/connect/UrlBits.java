package net.atlasauth.pca.connect;

import java.util.Locale;

/**
 * The URL members the WHATWG parser port does not expose (credentials and fragment), read from the raw text with the same
 * pre-processing (trim C0/space, drop tab and newlines). Only emptiness matters to the callers: {@code u.username !== '' || u.password !== ''}
 * and {@code u.hash !== ''}.
 */
public final class UrlBits {
    private UrlBits() {}

    private static String clean(String input) {
        int a = 0, b = input.length();
        while (a < b && input.charAt(a) <= 0x20) a++;
        while (b > a && input.charAt(b - 1) <= 0x20) b--;
        StringBuilder sb = new StringBuilder();
        for (int i = a; i < b; i++) {
            char c = input.charAt(i);
            if (c != '\t' && c != '\n' && c != '\r') sb.append(c);
        }
        return sb.toString();
    }

    /** True when {@code new URL(input).hash} is not the empty string (a '#' followed by at least one character). */
    public static boolean hasFragment(String input) {
        String s = clean(input);
        int h = s.indexOf('#');
        return h >= 0 && h + 1 < s.length();
    }

    private static boolean special(String s) {
        int c = s.indexOf(':');
        if (c < 0) return false;
        switch (s.substring(0, c).toLowerCase(Locale.ROOT)) {
            case "http": case "https": case "ftp": case "ws": case "wss": return true;
            default: return false;
        }
    }

    /** True when the URL carries a non-empty username or password. */
    public static boolean hasCredentials(String input) {
        String s = clean(input);
        int c = s.indexOf(':');
        if (c < 0) return false;
        String rest = s.substring(c + 1);
        boolean sp = special(s);
        int p = 0;
        if (sp) while (p < rest.length() && (rest.charAt(p) == '/' || rest.charAt(p) == '\\')) p++;
        else if (rest.startsWith("//")) p = 2;
        else return false;
        int e = rest.length();
        for (int k = p; k < rest.length(); k++) {
            char ch = rest.charAt(k);
            if (ch == '/' || ch == '?' || ch == '#' || (sp && ch == '\\')) { e = k; break; }
        }
        String authority = rest.substring(p, e);
        int at = authority.lastIndexOf('@');
        if (at < 0) return false;
        String userinfo = authority.substring(0, at);
        return !(userinfo.isEmpty() || userinfo.equals(":"));
    }
}
