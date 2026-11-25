package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.ActionsBridge;

/**
 * Migration shims between the old, disagreeing action vocabularies and the one action-def vocabulary. Old names stay accepted on INPUT
 * for one release; every conversion is total and fails closed.
 */
public final class ActionCompat {
    private ActionCompat() {}

    private static final List<String> BLAST_RADII = List.of("one", "bounded", "tenant", "global");
    private static final Map<String, Long> BLAST_PPM = Map.of("one", 50_000L, "bounded", 300_000L, "tenant", 700_000L, "global", 1_000_000L);
    private static final long PPM_MAX = 1_000_000L;
    private static final Pattern READ_RE = Pattern.compile("\\A(?:read|get|list|view|search|fetch|head)(?:_|\\z)");
    private static final Pattern DELETE_RE = Pattern.compile("(?:\\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\\z)");
    private static final Pattern SEND_RE = Pattern.compile("(?:\\A|_)(?:send|post|publish|notify|email|sms)(?:_|\\z)");

    /** Any old reversibility word to the canonical class (anything unknown is irreversible: fail closed). */
    public static String normalizeReversibility(Object x) {
        if ("reversible".equals(x) || "read".equals(x)) return "reversible";
        if ("rate_limited".equals(x) || "costly".equals(x)) return "rate_limited";
        return "irreversible";
    }

    /** The operations-side word for the revocation staleness table ({@code rate_limited} becomes {@code costly}). */
    public static String legacyOperationsClass(String r) { return "rate_limited".equals(r) ? "costly" : r; }

    public static String maxRevOf(String a, String b) { return ActionsBridge.revRank(a) >= ActionsBridge.revRank(b) ? a : b; }

    /** The schema {@code units} entry and the envelope unit tag from a def's unit (null for a money unit whose currency is a reference). */
    public static Map<String, Object> unitTagOf(Map<String, Object> u) {
        if (!"money".equals(u.get("kind"))) return J.obj("kind", u.get("kind"));
        if (!(u.get("ccy") instanceof String)) return null;
        Map<String, Object> m = J.obj("kind", "money", "currency", u.get("ccy"));
        if (u.containsKey("exp")) m.put("exponent", u.get("exp"));
        return m;
    }

    private static long ppmOf(double x) {
        double v = (Double.isNaN(x) || Double.isInfinite(x) ? 1 : x) * 1_000_000;
        double r = Math.floor(v);
        long rounded = (long) (v - r >= 0.5 ? r + 1 : r);
        return Math.min(PPM_MAX, Math.max(0, rounded));
    }

    /** The smallest radius whose default covers the float, and the integer ppm. */
    public static Map<String, Object> blastOfFloat(double x) {
        long ppm = ppmOf(x);
        String radius = "global";
        for (String r : BLAST_RADII) if (BLAST_PPM.get(r) >= ppm) { radius = r; break; }
        return J.obj("radius", radius, "ppm", J.n(ppm));
    }

    /** A legacy float kept EXACTLY: the largest radius whose default does not exceed it, with the ppm override carrying the exact value. */
    public static Map<String, Object> blastExactOfFloat(double x) {
        long ppm = ppmOf(x);
        String radius = "one";
        for (int i = BLAST_RADII.size() - 1; i >= 0; i--) if (BLAST_PPM.get(BLAST_RADII.get(i)) <= ppm) { radius = BLAST_RADII.get(i); break; }
        return J.obj("radius", radius, "ppm", J.n(ppm));
    }

    /**
     * Convert an old catalog entry ({@code connector, action, verb, reversibility, blastRadius, amountField?, resource?, description}).
     * Effects are inferred conservatively from the action name (an unknown write is {@code update}, never {@code read}); {@code opts}:
     * {@code {ccy?, exp?, maxAmount?}}. The result is {@code authored}.
     */
    public static Map<String, Object> fromCatalogSpec(Map<String, Object> s, Map<String, Object> o) {
        List<Object> effects = new ArrayList<>();
        Object amountField = s.get("amountField");
        String action = (String) s.get("action");
        if (amountField != null) effects.add("pay");
        if (READ_RE.matcher(action).find()) effects.add("read");
        if (DELETE_RE.matcher(action).find()) effects.add("delete");
        if (SEND_RE.matcher(action).find()) effects.add("send");
        if (effects.isEmpty()) effects.add("update");
        Map<String, Object> params = new LinkedHashMap<>();
        if (amountField != null) {
            Object max = o != null && o.get("maxAmount") != null ? o.get("maxAmount") : J.n(100_000_000_000L);
            Object ccy = o != null && o.get("ccy") != null ? o.get("ccy") : "USD";
            Object exp = o != null && o.get("exp") != null ? o.get("exp") : J.n(2);
            params.put((String) amountField, J.obj("type", "integer", "role", "money.amount", "min", J.n(0), "max", max, "unit", J.obj("kind", "money", "ccy", ccy, "exp", exp)));
            params.put("idempotency_key", J.obj("type", "string", "max_len", J.n(128)));
        }
        Map<String, Object> b = blastOfFloat(J.num(s.get("blastRadius")));
        Object resource = s.get("resource");
        boolean wildcard = resource == null || "*".equals(resource);
        String desc = (String) s.get("description");
        Map<String, Object> d = J.obj("v", J.n(1), "kind", "pca-action-def", "verb", s.get("verb"), "title", desc.length() > 120 ? desc.substring(0, 117) + "..." : desc, "description", desc,
            "effects", effects, "resource", J.obj("type", s.get("connector"), "id", wildcard ? (Object) "*" : J.obj("prefix", "", "class", "any_safe", "len", J.list(J.n(1), J.n(128))), "scope", wildcard ? "set" : "one"),
            "params", params, "reversibility", normalizeReversibility(s.get("reversibility")), "blast", J.obj("radius", b.get("radius"), "ppm", b.get("ppm")));
        if (amountField != null) d.put("idempotency", J.obj("mode", "key_param", "param", "idempotency_key"));
        d.put("review", J.obj("state", "authored"));
        return d;
    }

    public static List<Object> fromCatalog(List<?> specs, Map<String, Object> o) {
        List<Object> out = new ArrayList<>();
        for (Object s : specs) out.add(fromCatalogSpec(J.m(s), o));
        return out;
    }
}
