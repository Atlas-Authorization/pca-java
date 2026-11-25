package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Replays a TypeScript-reference differential oracle (test-data/&lt;module&gt;.json.gz: a header line, then one case per line,
 * each {fn, name, args, out}). {@code out} is the reference's JSON result; {"$throws": msg, code?} means the reference threw,
 * so the native must throw too (and carry the same code when the native exposes one). Bytes are {"$bytes": b64url}.
 * Objects compare by JSON value (numbers as JavaScript prints them), strings and codes exactly.
 */
public final class OracleCases {
    private OracleCases() {}

    /** One native call over the case's positional arguments. */
    public interface Fn { Object apply(List<?> args) throws Exception; }

    /** The cases of one fn; fails when the oracle has none (a renamed fn must not pass vacuously). */
    public static List<Map<String, Object>> of(String module, String fn) throws Exception {
        List<Map<String, Object>> out = BaseOracle.of(module, fn);
        assertFalse(out.isEmpty(), "no oracle cases for " + module + "/" + fn);
        return out;
    }

    private static final ThreadLocal<Double> CASE_CLOCK_MS = new ThreadLocal<>();

    /** The frozen clock (epoch ms) the case being replayed must run under, or null when the case does not depend on the clock. */
    public static Double caseClockMs() { return CASE_CLOCK_MS.get(); }

    /** Replay every case of {@code fn} through {@code f}; reports every divergent case at once. */
    public static void each(String module, String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cases = new ArrayList<>(of(module, fn));
        // the generated RSA DPoP cases replay through the same function table when present (DpopDiffTest.rsaCorpusIsPresent enforces presence)
        if (module.equals("ref-dpop") && java.nio.file.Files.exists(BaseOracle.corpusPath(BaseOracle.RSA))) cases.addAll(BaseOracle.of(BaseOracle.RSA, fn));
        for (Map<String, Object> c : cases) {
            // a case named in the corpus header's clockCases runs with the clock set to the header's clockMs (never skipped)
            CASE_CLOCK_MS.set(BaseOracle.isClockCase(module, (String) c.get("name")) ? Double.valueOf(BaseOracle.clockMs(module)) : null);
            String d;
            try { d = diff(c, c.get("out"), f); } finally { CASE_CLOCK_MS.remove(); }
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    @SuppressWarnings("unchecked")
    static String diff(Map<String, Object> c, Object want, Fn f) {
        Object got = null;
        Throwable err = null;
        try { got = f.apply((List<?>) c.get("args")); } catch (Throwable t) { err = t; }
        if (want instanceof Map && ((Map<String, Object>) want).containsKey("$throws")) {
            if (err == null && !(engineCrash(((Map<String, Object>) want).get("$throws")) && refusal(got))) return c.get("name") + "\n  want: throw " + want + "\n  got:  " + got;
            Object code = ((Map<String, Object>) want).get("code");
            String gotCode = err instanceof Coded ? ((Coded) err).code() : null;
            return code == null || gotCode == null || code.equals(gotCode) ? null : c.get("name") + "\n  want code: " + code + "\n  got code:  " + gotCode;
        }
        if (err != null) return c.get("name") + "\n  want: " + want + "\n  got:  THROWS " + err;
        Object norm = IntentJs.normalize(toJson(got));
        return IntentJs.jsonEquals(want, norm) ? null : c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + safe(norm);
    }

    /** A raw JavaScript engine failure text (the reference crashed on hostile input): the exact set of messages the replay rule names. */
    static final java.util.regex.Pattern ENGINE_CRASH = java.util.regex.Pattern.compile(
        "Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack");

    /** An engine-crash expectation passes iff the native refuses (throws, or returns its refusal); the message is never compared, never for a returned value. */
    static boolean engineCrash(Object msg) { return msg instanceof String && ENGINE_CRASH.matcher((String) msg).find(); }

    /** A returned refusal: no value, false, or a result that says it did not succeed or admit. */
    @SuppressWarnings("unchecked")
    static boolean refusal(Object got) {
        if (got == null || Boolean.FALSE.equals(got)) return true;
        if (got instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) got;
            for (String k : new String[] {"ok", "allow", "valid", "admit", "verified"}) if (Boolean.FALSE.equals(m.get(k))) return true;
            return m.containsKey("error") || m.containsKey("$err");
        }
        return false;
    }

    private static String safe(Object o) {
        try { return Json.canonicalize(o); } catch (RuntimeException e) { return String.valueOf(o); }
    }

    /** byte[] -> {"$bytes": b64url}; Number -> Json.Num; recursive over maps and lists. */
    @SuppressWarnings("unchecked")
    public static Object toJson(Object v) {
        if (v instanceof byte[]) { Map<String, Object> m = new LinkedHashMap<>(); m.put("$bytes", Keys.b64u((byte[]) v)); return m; }
        if (v instanceof Json.Num && ("NaN".equals(((Json.Num) v).raw) || "Infinity".equals(((Json.Num) v).raw) || "-Infinity".equals(((Json.Num) v).raw))) {
            Map<String, Object> m = new LinkedHashMap<>(); m.put("$num", ((Json.Num) v).raw); return m; // a non-finite number the native kept as spelled
        }
        if (v instanceof Integer || v instanceof Long || v instanceof Short) return new Json.Num(v.toString());
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) { Map<String, Object> m = new LinkedHashMap<>(); m.put("$num", Double.isNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity"); return m; } // the oracle's spelling of a non-finite number
            return v instanceof Float ? Double.valueOf(d) : v;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            // a bare Object member is the native's marker of a JavaScript undefined member: JSON omits it
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) if (e.getValue() == null || e.getValue().getClass() != Object.class) out.put(e.getKey(), toJson(e.getValue()));
            return out;
        }
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(toJson(x)); return out; }
        return v;
    }

    /** A native exception carrying the reference's stable error code. */
    public interface Coded { String code(); }

    /** JavaScript reads of a member on a non-object: null stays null, anything else has no members. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> js(Object o) { return o == null ? null : o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>(); }

    /** The JavaScript number value of a JSON number (null when not a number). */
    public static Double num(Object o) { return IntentJs.num(o); }
}
