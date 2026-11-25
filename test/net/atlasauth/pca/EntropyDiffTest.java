package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Replays every case of the reference oracle for the QRNG entropy module (HTTP source with an injected transport, SP 800-90B health
 * tests, HKDF mixing, secureSeed, the Ed25519 key helper): 562 cases, every fn dispatched, an unhandled fn fails the test. A reference
 * throw needs the native to throw (an argument a typed API cannot even receive counts as that refusal). Messages that start with "QRNG",
 * "HttpQrngSource", "mixEntropy" or "secureSeed" are compared exactly; JavaScript runtime texts are not.
 */
public class EntropyDiffTest {
    private static final Set<String> FNS = Set.of("constants", "repetitionCutoff", "proportionCutoff", "healthTestBytes", "parseAnuUint8", "parseHex",
        "parseBase64", "mixEntropy", "secureSeed", "generateKeyPairWithEntropy", "httpQrng", "nullQrng", "unavailableSource", "entropyError");
    private static final String[] EXACT = {"QRNG", "HttpQrngSource", "mixEntropy", "secureSeed"};

    private static final class Unrepresentable extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Unrepresentable(String m) { super(m); }
    }

    /** A rejection that is not an Error object (the reference's bare string). */
    private static final class StringReject extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final String text;
        StringReject(String t) { super(t); this.text = t; }
    }

    /** A transport failure with no message (the reference's non-Error throw: "unknown error"). */
    private static final class NoMessage extends RuntimeException {
        private static final long serialVersionUID = 1L;
        NoMessage() { super((String) null); }
    }

    /** An EntropyError carrying its code to the generic replay. */
    private static final class Coded extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;
        Coded(EntropyError e) { super(e.getMessage()); this.code = e.code(); }
        @Override public String code() { return code; }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Object dec(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : l(v)) out.add(dec(x)); return out; }
        if (!(v instanceof Map)) return v;
        Map<String, Object> mm = m(v);
        if (mm.size() == 1 && mm.get("$num") instanceof String) {
            String s = (String) mm.get("$num");
            return s.equals("NaN") ? Double.NaN : s.equals("Infinity") ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY;
        }
        if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) {
        if (o == null || o instanceof byte[]) return (byte[]) o;
        throw new Unrepresentable("not bytes");
    }

    private static String str(Object o) {
        if (o instanceof String) return (String) o;
        throw new Unrepresentable("not a string");
    }

    private static double dbl(Object o) {
        Double d = IntentJs.num(o);
        if (d == null) throw new Unrepresentable("not a number");
        return d;
    }

    /** An int the typed API can hold: an integral number that fits. */
    private static Integer integer(Object o) {
        if (o == null) return null;
        Double d = IntentJs.num(o);
        if (d == null || Double.isNaN(d) || Double.isInfinite(d) || d != Math.rint(d) || Math.abs(d) > Integer.MAX_VALUE) throw new Unrepresentable("not an int");
        return (int) (double) d;
    }

    /** For a positive-integer config field: anything the typed API cannot hold becomes -1, which the constructor refuses with the reference's message. */
    private static Integer posInt(Object o) {
        try { return integer(o); } catch (Unrepresentable e) { return -1; }
    }

    private static Object num(double d) {
        if (Double.isNaN(d)) return Map.of("$num", "NaN");
        if (Double.isInfinite(d)) return Map.of("$num", d > 0 ? "Infinity" : "-Infinity");
        return d;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // ---- the pure functions ----

    private static Object call(String fn, List<?> a) throws Exception {
        Object a0 = a.size() > 0 ? a.get(0) : null, a1 = a.size() > 1 ? a.get(1) : null, a2 = a.size() > 2 ? a.get(2) : null;
        try {
            switch (fn) {
                case "constants": {
                    Map<String, Object> o = new LinkedHashMap<>();
                    o.put("MAX_HKDF_OUTPUT", Entropy.MAX_HKDF_OUTPUT);
                    o.put("MIN_LOCAL_BYTES", Entropy.MIN_LOCAL_BYTES);
                    o.put("DEFAULT_SEED_BYTES", Entropy.DEFAULT_SEED_BYTES);
                    o.put("DEFAULT_MAX_QRNG_BYTES", Entropy.DEFAULT_MAX_QRNG_BYTES);
                    o.put("DEFAULT_TIMEOUT_MS", Entropy.DEFAULT_TIMEOUT_MS);
                    return o;
                }
                case "repetitionCutoff": return num(Entropy.repetitionCutoff(dbl(a0)));
                case "proportionCutoff": return num(Entropy.proportionCutoff(dbl(a0), dbl(a1)));
                case "healthTestBytes": {
                    if (a.size() > 1 && !(a1 instanceof Map)) throw new Unrepresentable("opts is not an object");
                    Map<String, Object> o = a1 == null ? Map.of() : m(a1);
                    Entropy.HealthVerdict v = Entropy.healthTestBytes(bytes(a0), o.containsKey("h") ? dbl(o.get("h")) : 8, o.containsKey("window") ? dbl(o.get("window")) : 512);
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("ok", v.ok());
                    if (!v.ok()) out.put("test", v.test());
                    return out;
                }
                case "parseAnuUint8": return Entropy.parseAnuUint8(a0);
                case "parseHex": return Entropy.parseHex(str(a0));
                case "parseBase64": // RegExp.test and atob read their argument as text
                    return Entropy.parseBase64(a0 instanceof String ? (String) a0 : a0 == null ? "null" : a0 instanceof Boolean ? a0.toString()
                        : AttestCommon.jsNumString(dbl(a0)));
                case "mixEntropy": {
                    Map<String, Object> o = a2 == null ? Map.of() : m(a2);
                    String ctx = null;
                    if (o.containsKey("context")) {
                        Object c = o.get("context");
                        if (c == null) throw new Unrepresentable("null context");   // the reference reads .length of null
                        ctx = c instanceof String ? (String) c : null;               // a number has no length: no context
                    }
                    return Entropy.mixEntropy(bytes(a0), bytes(a1), integer(o.get("length")), ctx);
                }
                case "nullQrng": case "unavailableSource": {
                    Entropy.QrngSource src = fn.equals("nullQrng") ? (a0 == null ? new Entropy.NullQrngSource() : new Entropy.NullQrngSource(str(a0))) : Entropy.unavailableSource((String) a0);
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("name", src.name());
                    try { src.fetch(integer(a1)); out.put("ok", true); } catch (Exception e) { out.put("$throws", e.getMessage()); }
                    return out;
                }
                case "entropyError": {
                    EntropyError e = new EntropyError(str(a0), str(a1));
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("name", e.getClass().getSimpleName());
                    out.put("code", e.code());
                    out.put("message", e.getMessage());
                    out.put("isError", e instanceof Throwable);
                    return out;
                }
                default: throw new AssertionError("unhandled fn " + fn);
            }
        } catch (EntropyError e) {
            throw new Coded(e);
        }
    }

    // ---- the structured cases: built from specs, compared as whole result maps ----

    private static String clsOf(Throwable e) {
        if (e instanceof EntropyError) return "EntropyError";
        if (e instanceof StringReject) return "string";
        return "Error";
    }

    private static Map<String, Object> errRec(Throwable e) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("cls", clsOf(e));
        r.put("message", e instanceof StringReject ? ((StringReject) e).text : e.getMessage());
        if (e instanceof EntropyError) r.put("code", ((EntropyError) e).code());
        return r;
    }

    private static Entropy.SecureSeedOptions seedOptions(Map<String, Object> o, List<Integer> reqs, List<Integer> locals, List<Object> errs) {
        Entropy.SecureSeedOptions so = new Entropy.SecureSeedOptions();
        so.length = integer(o.get("length"));
        so.localBytes = integer(o.get("localBytes"));
        so.quantumBytes = integer(o.get("quantumBytes"));
        so.context = o.get("context") == null ? null : str(o.get("context"));
        so.requireQuantum = Boolean.TRUE.equals(o.get("requireQuantum"));
        Object ht = o.get("healthTest");
        if (Boolean.FALSE.equals(ht)) so.healthTest = null;
        else if (ht instanceof Map) {
            Map<String, Object> hm = m(ht);
            so.healthTest = new Entropy.HealthTestOptions(hm.containsKey("h") ? dbl(hm.get("h")) : 8, hm.containsKey("window") ? dbl(hm.get("window")) : 512);
        }
        Object src = o.get("source");
        if (src instanceof Map) {
            Map<String, Object> sp = m(src);
            String name = sp.get("name") == null ? "test-src" : (String) sp.get("name");
            String kind = (String) sp.get("kind"), msg = (String) sp.get("message");
            so.source = new Entropy.QrngSource() {
                @Override public String name() { return name; }
                @Override public byte[] fetch(int n) {
                    reqs.add(n);
                    switch (kind) {
                        case "bytes": return (byte[]) sp.get("value");
                        case "reject": case "throwSync": throw new RuntimeException(msg);
                        case "rejectString": throw new StringReject(msg);
                        case "nonbytes": return null;
                        default: throw new AssertionError("bad source spec " + kind);
                    }
                }
            };
        }
        Object lo = o.get("local");
        if (lo instanceof Map) {
            Map<String, Object> lp = m(lo);
            so.randomBytesImpl = n -> {
                locals.add(n);
                switch ((String) lp.get("kind")) {
                    case "fixed": return (byte[]) lp.get("value");
                    case "throw": throw new RuntimeException((String) lp.get("message"));
                    default: return null;
                }
            };
        }
        String hook = o.get("hook") == null ? "none" : (String) o.get("hook");
        if (!hook.equals("none")) so.onQrngError = e -> { errs.add(errRec(e)); if (hook.equals("throw")) throw new RuntimeException("hook boom"); };
        return so;
    }

    private static Map<String, Object> runSeed(Map<String, Object> o, boolean keypair) throws Exception {
        List<Integer> reqs = new ArrayList<>(), locals = new ArrayList<>();
        List<Object> errs = new ArrayList<>();
        Map<String, Object> got = new LinkedHashMap<>();
        try {
            Entropy.SecureSeedOptions so = seedOptions(o, reqs, locals, errs);
            if (keypair) {
                Entropy.EntropyKeyPair kp = Entropy.generateKeyPairWithEntropy(so);
                got.put("publicKey", kp.publicKey());
                got.put("secretKeySha256", hex(MessageDigest.getInstance("SHA-256").digest(kp.secretKey())));
                got.put("usedQuantum", kp.usedQuantum());
            } else {
                Entropy.SecureSeedResult r = Entropy.secureSeed(so);
                got.put("seed", r.seed());
                got.put("usedQuantum", r.usedQuantum());
                got.put("quantumByteCount", r.quantumByteCount());
                got.put("source", r.source());
            }
        } catch (Unrepresentable e) {
            got.put("$throws", e.getMessage()); got.put("$unrep", true);
        } catch (RuntimeException e) {
            got.put("$throws", e.getMessage());
            if (e instanceof EntropyError) got.put("code", ((EntropyError) e).code());
        }
        got.put("qrngErrors", errs);
        got.put("localRequested", locals.isEmpty() ? null : locals.get(0));
        got.put("requests", reqs);
        return got;
    }

    private static Map<String, Object> runHttp(Map<String, Object> cfg, Object n, Map<String, Object> tr) throws Exception {
        List<Object> log = new ArrayList<>();
        Map<String, Object> got = new LinkedHashMap<>();
        HttpQrngSource src;
        HttpQrngSource.Config c = new HttpQrngSource.Config();
        c.url = cfg.get("url") instanceof String ? (String) cfg.get("url") : null;
        c.apiKey = (String) cfg.get("apiKey");
        c.apiKeyHeader = (String) cfg.get("apiKeyHeader");
        if (cfg.containsKey("format")) {
            String f = (String) cfg.get("format");
            c.format = f.equals("anu-uint8") ? HttpQrngSource.Format.ANU_UINT8 : f.equals("hex") ? HttpQrngSource.Format.HEX : HttpQrngSource.Format.BASE64;
        }
        if (cfg.containsKey("timeoutMs")) c.timeoutMs = posInt(cfg.get("timeoutMs"));
        if (cfg.containsKey("maxBytes")) c.maxBytes = posInt(cfg.get("maxBytes"));
        c.lengthParam = (String) cfg.get("lengthParam");
        if (cfg.get("extraParams") != null) { c.extraParams = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(cfg.get("extraParams")).entrySet()) c.extraParams.put(e.getKey(), (String) e.getValue()); }
        c.allowInsecureLoopback = Boolean.TRUE.equals(cfg.get("allowInsecureLoopback"));
        if (cfg.get("buildUrl") != null) { String suffix = (String) m(cfg.get("buildUrl")).get("suffix"); c.buildUrl = (base, k) -> base + "/" + k + suffix; }
        String kind = (String) tr.get("kind");
        if (!kind.equals("none")) {
            int status = tr.get("status") == null ? 200 : integer(tr.get("status"));
            boolean ok = tr.get("ok") != null ? Boolean.TRUE.equals(tr.get("ok")) : status >= 200 && status <= 299;
            c.transport = req -> {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("url", req.url());
                r.put("headers", new LinkedHashMap<>(req.headers()));
                r.put("redirect", req.redirect());
                r.put("signal", req.timeoutMs() > 0);
                log.add(r);
                switch (kind) {
                    case "throw": throw new RuntimeException((String) tr.get("message"));
                    case "throwString": throw new NoMessage();
                    case "hang": Thread.sleep(Long.MAX_VALUE); return null;
                    default: break;
                }
                return new HttpQrngSource.Response() {
                    @Override public boolean ok() { return ok; }
                    @Override public int status() { return status; }
                    @Override public Object json() {
                        if (kind.equals("jsonThrows")) throw new RuntimeException("bad json");
                        if (kind.equals("json")) return tr.get("body");
                        throw new IllegalStateException("json unused");
                    }
                    @Override public String text() {
                        if (kind.equals("textThrows")) throw new RuntimeException("read failed");
                        if (kind.equals("text")) return (String) tr.get("text");
                        throw new IllegalStateException("text unused");
                    }
                };
            };
        }
        try {
            src = new HttpQrngSource(c);
        } catch (IllegalArgumentException e) {
            got.put("$throws", e.getMessage());
            return got;
        }
        try {
            if (n == null) throw new Unrepresentable("null count");
            Integer count = integer(n);
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("name", src.name());
            ok.put("bytes", src.fetch(count));
            ok.put("requests", log);
            return ok;
        } catch (Exception e) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("$throws", e.getMessage());
            if (e instanceof Unrepresentable) out.put("$unrep", true);
            if (e instanceof EntropyError) out.put("code", ((EntropyError) e).code());
            out.put("name", src.name());
            out.put("requests", log);
            out.put("leaksKey", c.apiKey != null && !c.apiKey.isEmpty() && e.getMessage() != null && e.getMessage().contains(c.apiKey));
            return out;
        }
    }

    private static boolean exact(String msg) {
        for (String p : EXACT) if (msg.startsWith(p)) return true;
        return false;
    }

    /** Compares the whole result map; the reference's class names and JavaScript runtime texts are not part of the contract. */
    @SuppressWarnings("unchecked")
    private static String compare(Map<String, Object> c, Map<String, Object> got) {
        Map<String, Object> want = new LinkedHashMap<>(m(c.get("out")));
        want.remove("cls");
        if (want.get("code") instanceof String && ((String) want.get("code")).startsWith("ERR_")) want.remove("code");
        boolean unrep = got.remove("$unrep") != null;
        if (want.get("$throws") instanceof String && got.get("$throws") != null && (unrep || !exact((String) want.get("$throws")))) want.put("$throws", got.get("$throws"));
        if (got.get("$throws") instanceof String && (want.get("$throws") == null)) return c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  THROWS " + got.get("$throws");
        for (Object e : (List<Object>) (got.get("qrngErrors") instanceof List ? got.get("qrngErrors") : List.of())) {
            Map<String, Object> er = (Map<String, Object>) e;
            if (er.get("message") == null) er.put("message", "");
        }
        Object norm = IntentJs.normalize(OracleCases.toJson(got));
        return IntentJs.jsonEquals(want, norm) ? null : c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + Json.canonicalize(norm);
    }

    @Test void replayAllCases() throws Exception {
        List<Map<String, Object>> cases = BaseOracle.all("ref-entropy");
        assertEquals(562, cases.size());
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            String fn = (String) c.get("fn");
            assertTrue(FNS.contains(fn), "unhandled fn " + fn);
            List<?> args = (List<?>) dec(c.get("args"));
            String d;
            switch (fn) {
                case "secureSeed": case "generateKeyPairWithEntropy": d = compare(c, runSeed(m(args.get(0)), fn.equals("generateKeyPairWithEntropy"))); break;
                case "httpQrng": d = compare(c, runHttp(m(args.get(0)), args.get(1), m(args.get(2)))); break;
                case "nullQrng": case "unavailableSource": d = compare(c, m(call(fn, args))); break;
                default: d = OracleCases.diff(c, c.get("out"), unused -> call(fn, args));
            }
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /** The platform CSPRNG path and a failing source round-trip through secureSeed without any injection. */
    @Test void platformCsprngSeeds() {
        Entropy.SecureSeedResult a = Entropy.secureSeed(new Entropy.SecureSeedOptions()), b = Entropy.secureSeed(new Entropy.SecureSeedOptions());
        assertEquals(32, a.seed().length);
        assertTrue(!java.util.Arrays.equals(a.seed(), b.seed()));
        Entropy.SecureSeedOptions o = new Entropy.SecureSeedOptions();
        o.source = Entropy.unavailableSource(null);
        assertTrue(!Entropy.secureSeed(o).usedQuantum());
        o.requireQuantum = true;
        try { Entropy.secureSeed(o); throw new AssertionError("must refuse"); } catch (EntropyError e) { assertEquals("quantum_required", e.code()); }
    }
}
