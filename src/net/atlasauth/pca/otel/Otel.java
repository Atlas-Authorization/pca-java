package net.atlasauth.pca.otel;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.revoke.JsVal;

/**
 * OpenTelemetry instrumentation for Proof-Carrying Authority: wrap a verification guard so every decision emits a span
 * (decision / tier / risk / verb / resource) and two metrics. The telemetry types are tiny structural interfaces that an
 * OpenTelemetry Span / Tracer / Counter / Histogram / Meter adapts to in a line each, so this package has no dependency on
 * OpenTelemetry. It observes and never decides: with no tracer and no meter the wrapper returns the guard's result unchanged.
 * Guard results and verdicts are JSON trees (Map / List / String / Boolean / Json.Num / null).
 */
public final class Otel {
    private Otel() {}

    /** Minimal structural shape of an OpenTelemetry {@code Span}: only the methods this package touches. */
    public interface SpanLike {
        /** {@code v} is a String, a number or a Boolean. */
        void setAttribute(String k, Object v);
        /** {@code message} is null when the status carries none. */
        void setStatus(int code, String message);
        void recordException(Throwable e);
        void end();
    }

    public interface TracerLike { SpanLike startSpan(String name); }

    public interface CounterLike { void add(double n, Map<String, Object> attrs); }

    public interface HistogramLike { void record(double n, Map<String, Object> attrs); }

    public interface MeterLike {
        CounterLike createCounter(String name);
        HistogramLike createHistogram(String name);
    }

    /** OpenTelemetry {@code SpanStatusCode}: UNSET = 0, OK = 1, ERROR = 2, mirrored so the SDK is never imported. */
    public static final int STATUS_OK = 1;
    public static final int STATUS_ERROR = 2;

    private static final int MAX_TEXT = 256;

    // JavaScript whitespace (what \s matches), spelled out because the Java \s is ASCII only.
    private static final String WS = " \\t\\n\\u000B\\f\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    // \b before a word character, spelled out because the Java \b is Unicode-aware.
    private static final String WB = "(?<![A-Za-z0-9_])";
    private static final Pattern JWT = Pattern.compile(WB + "eyJ[\\w-]{5,}\\.[\\w-]{5,}\\.[\\w-]*");
    private static final Pattern AUTH_HEADER = Pattern.compile(WB + "(authorization[\"']?[" + WS + "]*[:=][" + WS + "]*)[^\\n\"']*", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCHEME = Pattern.compile(WB + "(Bearer|Basic|Token)[" + WS + "]+[\\w.~+/=-]{6,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*:\\/\\/)[^" + WS + "/@]*:[^" + WS + "/@]*@", Pattern.CASE_INSENSITIVE);
    private static final Pattern KEYED = Pattern.compile(WB + "((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)[\"']?[" + WS + "]*[:=][" + WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + WS + "\"'&,;]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern LONG_RUN = Pattern.compile("[A-Za-z0-9_-]{32,}");

    /**
     * Remove what looks like a credential from text bound for telemetry: JWTs, Bearer and Basic credentials, URL userinfo,
     * name=value pairs whose name is token, secret, password, key, signature, credential or authorization, and long unbroken
     * base64url or hex runs (32+ characters). The result is cut to 256 characters. A pattern list is a net, not a proof.
     */
    public static String redactSecrets(String text) {
        String t = text == null ? "null" : text;
        t = JWT.matcher(t).replaceAll("[redacted]");
        t = AUTH_HEADER.matcher(t).replaceAll("$1[redacted]");
        t = SCHEME.matcher(t).replaceAll("$1 [redacted]");
        t = URL_USERINFO.matcher(t).replaceAll("$1[redacted]@");
        Matcher m = KEYED.matcher(t);
        StringBuilder sb = new StringBuilder();
        int last = 0;
        while (m.find()) {
            String val = m.group(2);
            String q = val.charAt(0) == '"' || val.charAt(0) == '\'' ? val.substring(0, 1) : "";
            sb.append(t, last, m.start()).append(m.group(1)).append(q).append("[redacted]").append(q);
            last = m.end();
        }
        sb.append(t, last, t.length());
        t = sb.toString();
        t = LONG_RUN.matcher(t).replaceAll("[redacted]");
        return t.length() > MAX_TEXT ? t.substring(0, MAX_TEXT) + "..." : t;
    }

    private static Object g(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** {@code o?.[0]} over a JSON value: the first element of an array, the first character of a string, member "0" of an object. */
    private static Object first(Object o) {
        if (o instanceof List) return ((List<?>) o).isEmpty() ? null : ((List<?>) o).get(0);
        if (o instanceof String) return ((String) o).isEmpty() ? null : ((String) o).substring(0, 1);
        if (o instanceof Map) return ((Map<?, ?>) o).get("0");
        return null;
    }

    /** The first deny reason, if any (a string), used for the span's error message and the {@code pca.reason} attribute. */
    private static String firstReason(Object result) {
        Object r = first(g(g(result, "verdict"), "reasons"));
        return r instanceof String ? (String) r : null;
    }

    private static Double finite(Object v) {
        Double d = JsVal.num(v);
        return d != null && !d.isNaN() && !d.isInfinite() ? d : null;
    }

    /**
     * Map a guard result to OpenTelemetry span attributes. Fields the verdict lacks are omitted; {@code pca.reason} is added on deny
     * only; anything but an explicit {@code ok: true} is reported as a deny.
     */
    public static Map<String, Object> pcaSpanAttributes(Object result, Function<String, String> redact) {
        Function<String, String> rd = redact != null ? redact : Otel::redactSecrets;
        Map<String, Object> attrs = new LinkedHashMap<>();
        boolean ok = Boolean.TRUE.equals(g(result, "ok"));
        attrs.put("pca.decision", ok ? "allow" : "deny");
        Object status = g(result, "status");
        if (finite(status) != null) attrs.put("pca.status", status);
        Object verdict = g(result, "verdict");
        Object tier = g(g(verdict, "requiredThreshold"), "t");
        if (finite(tier) != null) attrs.put("pca.tier", tier);
        Object risk = g(verdict, "r");
        if (finite(risk) != null) attrs.put("pca.risk", risk);
        Object action = g(g(result, "pcactn"), "action");
        Object verb = g(action, "verb");
        if (verb instanceof String) attrs.put("pca.verb", rd.apply((String) verb));
        Object resource = g(action, "resource");
        if (resource instanceof String) attrs.put("pca.resource", rd.apply((String) resource));
        if (!ok) {
            String reason = firstReason(result);
            if (reason != null) attrs.put("pca.reason", rd.apply(reason));
        }
        return attrs;
    }

    /** The guard being observed: a request in, a result tree out (it may throw). */
    public interface Guard<Req> { Object apply(Req req) throws Exception; }

    /** Options for {@link #instrumentGuard}; leave tracer and meter null for a pure pass-through. */
    public static final class InstrumentGuardOptions {
        public TracerLike tracer;
        public MeterLike meter;
        public String spanName;
        /** Applied to every string that leaves in a span attribute, a status message or a recorded exception (default {@link #redactSecrets}). */
        public Function<String, String> redact;
    }

    /** A fresh error handed to {@code recordException}: the original may carry credentials in its message, cause or stack. */
    public static final class CleanError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String errorName;
        CleanError(String name, String message) {
            super(message, null, false, false); // no cause, no stack
            this.errorName = name;
        }
        /** The original exception's simple class name when it is a plain word of at most 64 characters, else "Error". */
        public String errorName() { return errorName; }
    }

    private static void safe(Runnable f) {
        try { f.run(); } catch (RuntimeException e) { /* the decision is the guard's, not the exporter's */ }
    }

    /**
     * Wrap a verification guard so each decision emits a span and metrics; the result is returned unchanged. A span named
     * {@code spanName} (default "pca.verify") is annotated with {@link #pcaSpanAttributes}, given OK status on allow and ERROR status
     * plus the first reason on deny, and always ended. When the guard throws, a redacted copy of the exception is recorded and the
     * original is re-thrown. A {@code pca.verifications} counter and a {@code pca.verify.risk} histogram are created once and fed per
     * decision. A tracer or meter that throws never changes what the guard decided.
     */
    public static <Req> Guard<Req> instrumentGuard(Guard<Req> guard, InstrumentGuardOptions opts) {
        final TracerLike tracer = opts == null ? null : opts.tracer;
        final MeterLike meter = opts == null ? null : opts.meter;
        final String spanName = opts == null || opts.spanName == null ? "pca.verify" : opts.spanName;
        final CounterLike counter = meter == null ? null : meter.createCounter("pca.verifications");
        final HistogramLike histogram = meter == null ? null : meter.createHistogram("pca.verify.risk");
        final Function<String, String> redact = opts == null || opts.redact == null ? Otel::redactSecrets : opts.redact;

        return req -> {
            final SpanLike[] span = new SpanLike[1];
            safe(() -> { if (tracer != null) span[0] = tracer.startSpan(spanName); });
            try {
                Object result = guard.apply(req);
                if (span[0] != null) {
                    final SpanLike sp = span[0];
                    safe(() -> {
                        for (Map.Entry<String, Object> e : pcaSpanAttributes(result, redact).entrySet()) sp.setAttribute(e.getKey(), e.getValue());
                        boolean ok = Boolean.TRUE.equals(g(result, "ok"));
                        String reason = ok ? null : firstReason(result);
                        if (ok) sp.setStatus(STATUS_OK, null);
                        else sp.setStatus(STATUS_ERROR, reason != null ? redact.apply(reason) : null);
                    });
                }
                final String decision = Boolean.TRUE.equals(g(result, "ok")) ? "allow" : "deny";
                safe(() -> {
                    if (counter != null) {
                        Map<String, Object> a = new LinkedHashMap<>();
                        a.put("decision", decision);
                        counter.add(1, a);
                    }
                });
                Double risk = finite(g(g(result, "verdict"), "r"));
                if (histogram != null && risk != null) {
                    safe(() -> {
                        Map<String, Object> a = new LinkedHashMap<>();
                        a.put("decision", decision);
                        histogram.record(risk, a);
                    });
                }
                return result;
            } catch (Exception e) {
                if (span[0] != null) {
                    final SpanLike sp = span[0];
                    safe(() -> {
                        String simple = e.getClass().getSimpleName();
                        String name = simple.matches("[A-Za-z0-9_]{1,64}") ? simple : "Error";
                        CleanError clean = new CleanError(name, redact.apply(e.getMessage() != null ? e.getMessage() : ""));
                        sp.recordException(clean);
                        sp.setStatus(STATUS_ERROR, clean.getMessage());
                    });
                }
                throw e;
            } finally {
                if (span[0] != null) safe(() -> span[0].end());
            }
        };
    }
}
