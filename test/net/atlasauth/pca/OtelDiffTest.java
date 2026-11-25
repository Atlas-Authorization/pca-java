package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.otel.Otel;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle over the OpenTelemetry attribute mapping, the secret redactor and the guard wrapper. */
class OtelDiffTest {
    private static final String MOD = "ref-otel";

    private static Function<String, String> mode(Object m) {
        if (m == null) return null;
        switch ((String) m) {
            case "identity": return s -> s;
            case "upper": return s -> s.toUpperCase(Locale.ROOT);
            case "brackets": return s -> "<" + s + ">";
            default: throw new IllegalArgumentException("mode " + m);
        }
    }

    private static Map<String, Object> ev(String ev) { Map<String, Object> m = new LinkedHashMap<>(); m.put("ev", ev); return m; }

    @Test void redactSecrets() throws Exception { OracleCases.each(MOD, "redactSecrets", a -> Otel.redactSecrets((String) a.get(0))); }

    @Test void pcaSpanAttributes() throws Exception { OracleCases.each(MOD, "pcaSpanAttributes", a -> Otel.pcaSpanAttributes(a.get(0), mode(a.get(1)))); }

    @SuppressWarnings("unchecked")
    @Test void instrumentScenario() throws Exception {
        OracleCases.each(MOD, "instrumentScenario", a -> {
            Map<String, Object> spec = (Map<String, Object>) a.get(0);
            List<Object> events = new ArrayList<>();
            String tm = spec.get("tracerMode") == null ? "ok" : (String) spec.get("tracerMode");
            String mm = spec.get("meterMode") == null ? "ok" : (String) spec.get("meterMode");
            Otel.SpanLike span = new Otel.SpanLike() {
                @Override public void setAttribute(String k, Object v) {
                    Map<String, Object> e = ev("setAttribute"); e.put("k", k); e.put("v", v); events.add(e);
                    if (tm.equals("attrThrows")) throw new RuntimeException("exporter boom");
                }
                @Override public void setStatus(int code, String message) {
                    Map<String, Object> e = ev("setStatus"); e.put("code", code); if (message != null) e.put("message", message); events.add(e);
                    if (tm.equals("statusThrows")) throw new RuntimeException("exporter boom");
                }
                @Override public void recordException(Throwable t) {
                    Map<String, Object> e = ev("recordException"); e.put("message", t.getMessage()); e.put("noStack", t.getStackTrace().length == 0); events.add(e);
                    if (tm.equals("recordThrows")) throw new RuntimeException("exporter boom");
                }
                @Override public void end() {
                    events.add(ev("end"));
                    if (tm.equals("endThrows")) throw new RuntimeException("exporter boom");
                }
            };
            Otel.TracerLike tracer = name -> {
                Map<String, Object> e = ev("startSpan"); e.put("name", name); events.add(e);
                if (tm.equals("startThrows")) throw new RuntimeException("exporter boom");
                return span;
            };
            Otel.MeterLike meter = new Otel.MeterLike() {
                @Override public Otel.CounterLike createCounter(String name) {
                    Map<String, Object> e = ev("createCounter"); e.put("name", name); events.add(e);
                    if (mm.equals("createThrows")) throw new RuntimeException("exporter boom");
                    return (v, attrs) -> {
                        Map<String, Object> x = ev("add"); x.put("v", v); x.put("a", attrs); events.add(x);
                        if (mm.equals("addThrows")) throw new RuntimeException("exporter boom");
                    };
                }
                @Override public Otel.HistogramLike createHistogram(String name) {
                    Map<String, Object> e = ev("createHistogram"); e.put("name", name); events.add(e);
                    return (v, attrs) -> {
                        Map<String, Object> x = ev("record"); x.put("v", v); x.put("a", attrs); events.add(x);
                        if (mm.equals("recordThrows")) throw new RuntimeException("exporter boom");
                    };
                }
            };
            Map<String, Object> g = (Map<String, Object>) spec.get("guard");
            Otel.Guard<String> guard = req -> {
                if (g.get("throws") != null) throw new RuntimeException((String) g.get("throws"));
                return g.get("result");
            };
            Otel.InstrumentGuardOptions o = new Otel.InstrumentGuardOptions();
            if (Boolean.TRUE.equals(spec.get("tracer"))) o.tracer = tracer;
            if (Boolean.TRUE.equals(spec.get("meter"))) o.meter = meter;
            o.spanName = (String) spec.get("spanName");
            o.redact = mode(spec.get("redact"));
            Map<String, Object> out = new LinkedHashMap<>();
            Otel.Guard<String> wrapped;
            try {
                wrapped = Otel.instrumentGuard(guard, o);
            } catch (RuntimeException e) {
                out.put("wrap", e.getMessage());
                out.put("events", events);
                return out;
            }
            Map<String, Object> outcome = new LinkedHashMap<>();
            try { outcome.put("result", wrapped.apply("req")); } catch (Exception e) { outcome = new LinkedHashMap<>(); outcome.put("threw", e.getMessage()); }
            out.put("outcome", outcome);
            out.put("events", events);
            return out;
        });
    }
}
