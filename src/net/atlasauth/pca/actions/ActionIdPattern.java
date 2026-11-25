package net.atlasauth.pca.actions;

import java.util.Map;
import java.util.regex.Pattern;

/** The restricted resource id grammar: matching and (decidable) containment between two patterns. A pattern is {@code "*"}, {@code {exact}} or {@code {prefix, class, len}}. */
public final class ActionIdPattern {
    private ActionIdPattern() {}

    private static final String DIGITS = "0123456789", HEXLC = DIGITS + "abcdef", LOWER = "abcdefghijklmnopqrstuvwxyz", UPPER = LOWER.toUpperCase(java.util.Locale.ROOT);
    private static final String ALNUM = DIGITS + LOWER + UPPER;
    private static final Pattern UUID_RE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final int MAX_ID_LEN = 128;

    /** The character set of an id class (digits, hex, alnum, slug, uuid, any_safe). */
    public static String idClassChars(String c) {
        switch (c) {
            case "digits": return DIGITS;
            case "hex": return HEXLC;
            case "alnum": return ALNUM;
            case "slug": return DIGITS + LOWER + "-_";
            case "uuid": return HEXLC + "-";
            case "any_safe": return ALNUM + "._-:/";
            default: throw new IllegalArgumentException("unknown id class " + c);
        }
    }

    private static boolean inClass(String s, String c) {
        String set = idClassChars(c);
        for (int i = 0; i < s.length(); i++) if (set.indexOf(s.charAt(i)) < 0) return false;
        return true;
    }

    private static boolean isExact(Object p) { return p instanceof Map && ((Map<?, ?>) p).containsKey("exact"); }

    /** Does {@code id} (the id part of a resource, without the type) match the pattern? */
    public static boolean idMatches(Object p, String id) {
        if ("*".equals(p)) return !id.isEmpty() && id.length() <= MAX_ID_LEN && inClass(id, "any_safe");
        if (isExact(p)) return id.equals(J.get(p, "exact"));
        String prefix = (String) J.get(p, "prefix");
        if (!id.startsWith(prefix)) return false;
        String rest = id.substring(prefix.length());
        java.util.List<Object> len = J.a(J.get(p, "len"));
        if (rest.length() < J.num(len.get(0)) || rest.length() > J.num(len.get(1))) return false;
        String cls = (String) J.get(p, "class");
        if (cls.equals("uuid")) return UUID_RE.matcher(rest).matches();
        return inClass(rest, cls);
    }

    private static boolean classSubset(String a, String b) {
        String sa = idClassChars(a), sb = idClassChars(b);
        for (int i = 0; i < sa.length(); i++) if (sb.indexOf(sa.charAt(i)) < 0) return false;
        return true;
    }

    /** Is every id matched by {@code inner} also matched by {@code outer}? */
    public static boolean idPatternContains(Object outer, Object inner) {
        if ("*".equals(outer)) return true;
        if ("*".equals(inner)) return false;
        if (isExact(outer)) return isExact(inner) && J.get(inner, "exact").equals(J.get(outer, "exact"));
        if (isExact(inner)) return idMatches(outer, (String) J.get(inner, "exact"));
        String ip = (String) J.get(inner, "prefix"), op = (String) J.get(outer, "prefix");
        if (!ip.startsWith(op)) return false;
        String r = ip.substring(op.length());
        String oc = (String) J.get(outer, "class"), ic = (String) J.get(inner, "class");
        if (!inClass(r, oc)) return false;
        if (oc.equals("uuid")) return ic.equals("uuid") && r.isEmpty();
        if (!classSubset(ic, oc)) return false;
        java.util.List<Object> ol = J.a(J.get(outer, "len")), il = J.a(J.get(inner, "len"));
        return r.length() + J.num(il.get(0)) >= J.num(ol.get(0)) && r.length() + J.num(il.get(1)) <= J.num(ol.get(1));
    }
}
