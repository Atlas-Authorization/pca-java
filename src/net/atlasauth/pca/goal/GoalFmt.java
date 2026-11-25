package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Plain-text rendering of quantities, values and acts. An unknown currency is shown in raw minor units, never guessed. */
public final class GoalFmt {
    private GoalFmt() {}

    public static final Map<String, Integer> CCY_EXPONENT = Map.of("USD", 2, "EUR", 2, "GBP", 2, "CAD", 2, "AUD", 2, "CHF", 2, "JPY", 0, "KRW", 0);

    private static String pad(String s, int n) {
        StringBuilder b = new StringBuilder();
        for (int i = s.length(); i < n; i++) b.append('0');
        return b.append(s).toString();
    }

    /** {@code minor} is rendered as written (a JSON number lexeme or integer). */
    public static String fmtMoney(String ccy, Object minor) {
        Integer e = CCY_EXPONENT.get(ccy);
        String m = G.jsStr(minor);
        if (e == null) return ccy + " " + m + " (minor units)";
        if (e == 0) return ccy + " " + m;
        String s = pad(m, e + 1);
        return ccy + " " + s.substring(0, s.length() - e) + "." + s.substring(s.length() - e);
    }

    public static String fmtQuantity(Map<String, Object> q) {
        Map<String, Object> u = G.obj(q.get("u"), "unit");
        Object n = q.get("n");
        switch (G.kind(u)) {
            case "money": return fmtMoney((String) u.get("ccy"), n);
            case "count": return G.jsStr(n);
            case "duration": return G.jsStr(n) + "ms";
            case "instant": return "@" + G.jsStr(n);
            case "bytes": return G.jsStr(n) + "B";
            case "ratio": return G.jsStr(n) + "ppm";
            default: throw new IrError("unknown unit");
        }
    }

    public static String fmtValue(Map<String, Object> v) {
        String k = G.kind(v);
        if (k.equals("q")) return fmtQuantity(G.m(v.get("q")));
        if (k.equals("s")) return G.q((String) v.get("s"));
        List<String> xs = new ArrayList<>();
        for (Object i : G.arr(v.get("items"), "items")) xs.add(fmtValue(G.m(i)));
        return "{" + String.join(", ", xs) + "}";
    }

    public static String fmtAct(Map<String, Object> a) {
        Map<String, Object> params = G.m(a.get("params"));
        List<String> ks = new ArrayList<>(params.keySet());
        ks.sort(String::compareTo);
        List<String> ps = new ArrayList<>();
        for (String k : ks) ps.add(k + "=" + fmtValue(G.m(params.get(k))));
        return a.get("verb") + " on " + a.get("res") + (ps.isEmpty() ? "" : " (" + String.join(", ", ps) + ")");
    }
}
