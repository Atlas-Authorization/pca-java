package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared helpers of the Intent Layer v2 rules (13-18): JavaScript value semantics over the {@link Json} tree, so every
 * rule judges numbers by their IEEE-754 binary64 value exactly like the TypeScript reference (packages/pca/src).
 *
 * <p>Verifier-held state (the {@code context.intent_v2} object, the W-B primitive inputs, plaintext params) is NORMALIZED
 * once on entry with {@link #normalize}: every {@link Json.Num} becomes the number {@code JSON.parse} would yield, spelled
 * as JavaScript prints it (integral values as plain digits, others as the shortest round-trip decimal; {@code -0} stays
 * {@code "-0"}). After that the strict canonicalizer and every numeric test agree with the reference on any lexical form
 * ({@code 1.0}, {@code 1e3}, {@code 950000.0}).
 */
public final class IntentJs {
    private IntentJs() {}

    static final double MAX_SAFE = 9007199254740991.0;

    // ---- values ----
    static boolean isObj(Object o) { return o instanceof Map; }
    static boolean isArr(Object o) { return o instanceof List; }
    static boolean isStr(Object o) { return o instanceof String; }
    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return (List<Object>) o; }
    /** Own member (JSON null counts as present, like a defined property). */
    static boolean own(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }
    /**
     * An optional member: ABSENT means {@code dflt}; a member that is present (JSON null included) is returned as is, so a
     * present null reaches the type check and fails closed (it is malformed, never a default).
     */
    static Object opt(Object o, String k, Object dflt) { return own(o, k) ? get(o, k) : dflt; }
    /** {@code o[k]} or null when absent (callers that need presence use {@link #own}). */
    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** The binary64 value of a JSON number (Num, Integer, Long, Double), else null (not a number). */
    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double) return ((Number) o).doubleValue();
        return null;
    }
    static boolean isNumber(Object o) { return num(o) != null; }
    static boolean isNegZero(double d) { return d == 0.0 && Double.doubleToRawLongBits(d) != 0L; }
    /** {@code Number.isSafeInteger} (accepts -0). */
    static boolean isSafeInteger(Object o) {
        Double d = num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE;
    }
    /** The reference {@code isInt}: a safe integer that is not -0. */
    static boolean isInt(Object o) { return isSafeInteger(o) && !isNegZero(num(o)); }
    /** The reference {@code isNonNeg}: {@link #isInt} and &gt;= 0. */
    static boolean isNonNeg(Object o) { return isInt(o) && num(o) >= 0; }
    /** Value of a safe integer (call after {@link #isSafeInteger}). */
    static long lng(Object o) { return (long) (double) num(o); }
    /** {@code Number.isFinite}. */
    static boolean isFinite(Object o) { Double d = num(o); return d != null && !Double.isNaN(d) && !Double.isInfinite(d); }
    /** JavaScript {@code String(n)} of a safe integer. */
    static Json.Num ofLong(long v) { return new Json.Num(Long.toString(v)); }

    /**
     * Equality of the lenient canonical JSON texts (the predicate DSL's {@code deepEq}) computed structurally: numbers by
     * binary64 value ({@code -0} prints as {@code 0}), strings by UTF-16 code units, objects by key set and member values,
     * arrays element-wise. A non-JSON value (or a non-finite number) never equals anything.
     */
    static boolean jsonEquals(Object a, Object b) {
        if (a == null || b == null) return a == null && b == null;
        if (a instanceof String || b instanceof String) return a.equals(b);
        if (a instanceof Boolean || b instanceof Boolean) return a.equals(b);
        Double x = num(a), y = num(b);
        if (x != null || y != null) return x != null && y != null && isFinite(a) && isFinite(b) && x.doubleValue() == y.doubleValue();
        if (a instanceof List && b instanceof List) {
            List<?> l = (List<?>) a, r = (List<?>) b;
            if (l.size() != r.size()) return false;
            for (int i = 0; i < l.size(); i++) if (!jsonEquals(l.get(i), r.get(i))) return false;
            return true;
        }
        if (a instanceof Map && b instanceof Map) {
            Map<?, ?> l = (Map<?, ?>) a, r = (Map<?, ?>) b;
            if (l.size() != r.size()) return false;
            for (Map.Entry<?, ?> e : l.entrySet()) if (!r.containsKey(e.getKey()) || !jsonEquals(e.getValue(), r.get(e.getKey()))) return false;
            return true;
        }
        return false;
    }

    // ---- strings ----
    /** UTF-8 byte length as {@code TextEncoder} counts it (a lone surrogate encodes as U+FFFD: 3 bytes). */
    static int u8len(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) n += 1;
            else if (c < 0x800) n += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { n += 4; i++; }
            else n += 3;
        }
        return n;
    }
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static boolean hasLoneSurrogate(String s) { return Json.hasLoneSurrogate(s); }
    public static int compareUtf8(String a, String b) { return Json.compareUtf8(a, b); }
    static List<String> sortedUtf8(java.util.Collection<String> keys) {
        List<String> out = new ArrayList<>(keys);
        out.sort(Json::compareUtf8);
        return out;
    }
    /** Canonical base64url of exactly 32 bytes (a "digest"). */
    static boolean b32(Object o) { return Pca.decodeB64uStrict(o, 32) != null; }
    /** Canonical base64url of any length. */
    static boolean b64any(Object o) { return Pca.decodeB64uStrict(o, -1) != null; }

    // ---- hashing ----
    static String canon(Object v) { return Json.canonicalizeStrict(v); }
    static byte[] canonBytes(Object v) { return utf8(Json.canonicalizeStrict(v)); }
    static String hashCanonical(Object v) { return Pca.hashCanonical(v); }
    /** {@code utf8(domain) || strictCanonical(body)}. */
    static byte[] message(String domain, Object body) { return Pca.concat(utf8(domain), canonBytes(body)); }
    /** {@code {d: domain, <slot>: value}} hashed (an artifact reference). */
    static String ref(String domain, String slot, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", domain);
        m.put(slot, value);
        return hashCanonical(m);
    }

    // ---- signatures ----
    /** Strict Ed25519 (rule 7) under a b64u key; a malformed key or signature is a failed signature. */
    static boolean verifyEd(Object pub, byte[] msg, Object sig) {
        return pub instanceof String && sig instanceof String && Pca.verifyB64u((String) pub, msg, (String) sig);
    }

    /** The reason token of a signature refused because this SDK's suite dispatch does not implement the artifact's suite. */
    public static final String UNSUPPORTED_SUITE = "unsupported_suite";

    /**
     * The suite capability rule (README "suite capability"): an absent {@code alg} is ed25519; a non-string {@code alg} is
     * malformed; an {@code alg} this SDK's suite dispatch does not implement fails with {@link #UNSUPPORTED_SUITE}. Null = ok.
     */
    static String suiteError(Object alg, boolean algPresent) {
        if (!algPresent) return null;
        if (!(alg instanceof String)) return "alg must be a string";
        return Pq.resolveSigAlg(alg, true) != null ? null : UNSUPPORTED_SUITE + ": '" + alg + "'";
    }

    /** The implemented suite an artifact names (absent = ed25519), or null. */
    static String suiteOf(Map<String, Object> artifact) {
        Pq.Suite s = Pq.resolveSigAlg(artifact.get("alg"), artifact.containsKey("alg"));
        return s == null ? null : s.alg;
    }

    /**
     * {@code bindSuiteFields(base, alg, pqPk)}: for a non-ed25519 suite the suite name and the PQ key are signed into the
     * body; for ed25519 (or an unknown suite) the body is unchanged.
     */
    static Map<String, Object> bindSuiteFields(Map<String, Object> base, Object alg, boolean algPresent, Object pqPk, boolean pqPresent) {
        Pq.Suite s = Pq.resolveSigAlg(alg, algPresent);
        if (s == null || s.alg.equals("ed25519")) return base;
        Map<String, Object> out = new LinkedHashMap<>(base);
        out.put("alg", s.alg);
        if (pqPresent) out.put("pq_pk", pqPk);
        return out;
    }

    /**
     * {@code verifyPinnedSuite}: ed25519 verifies under {@code identity}; a PQ / hybrid suite verifies only under a PQ key
     * the VERIFIER pins for {@code identity} ({@code pqPins}), never the artifact's own key alone. Never throws.
     */
    static boolean verifyPinnedSuite(Object alg, boolean algPresent, String identity, Object artifactPqPk, byte[] msg,
                                     Object sig, Object pqSig, Map<String, Object> pqPins) {
        try {
            Pq.Suite s = Pq.resolveSigAlg(alg, algPresent);
            if (s == null) return false;
            if (s.alg.equals("ed25519")) return verifyEd(identity, msg, sig);
            Pq.PinnedPq pq = Pq.resolvePqKey(identity, artifactPqPk, null, pqPins, null);
            if (pq == null) return false;
            return Pq.verifyLeafSuite(alg, algPresent, identity, pq, msg, sig, pqSig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    static Map<String, Object> pin(String identity, Object pqPk) {
        if (!(pqPk instanceof String)) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(identity, pqPk);
        return m;
    }

    // ---- JSON.parse semantics for verifier state ----
    /**
     * A deep copy of a JSON tree with every number spelled as JavaScript would print the value {@code JSON.parse} yields.
     * Maps keep their insertion order; non-JSON values are kept as they are. Depth is bounded by the tree itself (the
     * lenient parser caps nesting at 512).
     */
    @SuppressWarnings("unchecked")
    public static Object normalize(Object v) {
        if (v instanceof Json.Num) return normNum(((Json.Num) v).raw);
        if (v instanceof Double) return normDouble((Double) v, v.toString());
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), normalize(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(normalize(x));
            return out;
        }
        return v;
    }

    static Json.Num normNum(String raw) {
        double d;
        try { d = Double.parseDouble(raw); } catch (NumberFormatException e) { return new Json.Num(raw); }
        return normDouble(d, raw);
    }

    private static Json.Num normDouble(double d, String raw) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return new Json.Num(raw); // refused by every strict consumer
        if (isNegZero(d)) return new Json.Num("-0");
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new Json.Num(new BigDecimal(d).toPlainString());
        return new Json.Num(shortest(d));
    }

    /** The shortest decimal that round-trips to {@code d} (JavaScript's digits), printed without an exponent. */
    static String shortest(double d) {
        BigDecimal exact = new BigDecimal(d);
        for (int p = 1; p <= 17; p++) {
            BigDecimal r = exact.round(new MathContext(p, java.math.RoundingMode.HALF_EVEN));
            if (r.doubleValue() == d) return r.stripTrailingZeros().toPlainString();
        }
        return exact.toPlainString();
    }
}
