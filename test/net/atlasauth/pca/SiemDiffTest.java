package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.siem.JsFmt;
import net.atlasauth.pca.siem.Siem;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle over the SIEM event mapping, the credential scrubber and the sinks. */
class SiemDiffTest {
    private static final String MOD = "ref-siem";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> opts(List<?> a) { return a.size() > 1 ? (Map<String, Object>) a.get(1) : null; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> spec(List<?> a) { return (Map<String, Object>) a.get(0); }

    @Test void toOcsfEvent() throws Exception { OracleCases.each(MOD, "toOcsfEvent", a -> Siem.toOcsfEvent(a.get(0), opts(a))); }

    @Test void toCef() throws Exception { OracleCases.each(MOD, "toCef", a -> Siem.toCef(a.get(0), opts(a))); }

    @Test void toEcs() throws Exception { OracleCases.each(MOD, "toEcs", a -> Siem.toEcs(a.get(0), opts(a))); }

    @SuppressWarnings("unchecked")
    @Test void formatDecision() throws Exception {
        OracleCases.each(MOD, "formatDecision", a -> Siem.formatDecision(a.get(0), (String) a.get(1), (Map<String, Object>) a.get(2)).toMap());
    }

    @Test void scrubError() throws Exception { OracleCases.each(MOD, "scrubError", a -> Siem.scrubError((String) a.get(0))); }

    @SuppressWarnings("unchecked")
    @Test void httpSinkScenario() throws Exception {
        OracleCases.each(MOD, "httpSinkScenario", a -> {
            Map<String, Object> s = spec(a);
            String mode = (String) s.get("mode");
            String format = (String) s.get("format");
            List<Map<String, Object>> calls = Collections.synchronizedList(new ArrayList<>());
            Siem.HttpSinkOptions o = new Siem.HttpSinkOptions(format);
            if (s.get("headers") != null) {
                o.headers = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : ((Map<String, Object>) s.get("headers")).entrySet()) o.headers.put(e.getKey(), (String) e.getValue());
            }
            o.contentType = (String) s.get("contentType");
            o.name = (String) s.get("name");
            if (s.get("timeoutMs") != null) o.timeoutMs = JsVal.num(s.get("timeoutMs"));
            o.fetch = (url, init) -> {
                Map<String, Object> call = new LinkedHashMap<>();
                call.put("url", url);
                call.put("method", init.method);
                call.put("headers", new LinkedHashMap<String, Object>(init.headers));
                call.put("body", init.body);
                calls.add(call);
                if (mode.equals("ok")) return new Siem.FetchLikeResponse(true, 200, null);
                if (mode.startsWith("st:")) {
                    String[] p = mode.split(":", 3);
                    return new Siem.FetchLikeResponse(false, Integer.parseInt(p[1]), p.length > 2 ? p[2] : null);
                }
                if (mode.startsWith("throws:")) throw new RuntimeException(mode.substring(7));
                Thread.sleep(500); // hang: outlive the sink's timeout
                return new Siem.FetchLikeResponse(true, 200, null);
            };
            Siem.SiemSink sink = Siem.httpSink((String) s.get("url"), o);
            List<Siem.SiemEvent> events = new ArrayList<>();
            for (Object r : (List<Object>) s.get("events")) events.add(Siem.formatDecision(r, format, null));
            Map<String, Object> out = new LinkedHashMap<>();
            Siem.SinkResult res = sink.deliver(events);
            out.put("name", sink.name());
            out.put("format", sink.format());
            out.put("result", res.toMap());
            // the fetch runs on the sink's own thread: on a short timeout it may not have started yet when delivery gives up
            for (int i = 0; i < 200 && calls.isEmpty() && "hang".equals(mode); i++) Thread.sleep(10);
            if (!calls.isEmpty()) out.put("request", calls.get(0));
            return out;
        });
    }

    @SuppressWarnings("unchecked")
    @Test void consoleSinkScenario() throws Exception {
        OracleCases.each(MOD, "consoleSinkScenario", a -> {
            Map<String, Object> s = spec(a);
            List<Object> lines = new ArrayList<>();
            String throwsMsg = (String) s.get("throws");
            Siem.ConsoleSinkOptions o = new Siem.ConsoleSinkOptions();
            o.format = (String) s.get("format");
            o.name = (String) s.get("name");
            o.logger = l -> { if (throwsMsg != null) throw new RuntimeException(throwsMsg); lines.add(l); };
            Siem.SiemSink sink = Siem.consoleSink(o);
            List<Siem.SiemEvent> events = new ArrayList<>();
            for (Object r : (List<Object>) s.get("records")) events.add(Siem.formatDecision(r, sink.format(), null));
            Map<String, Object> out = new LinkedHashMap<>();
            Siem.SinkResult res = sink.deliver(events);
            out.put("name", sink.name());
            out.put("format", sink.format());
            out.put("result", res.toMap());
            out.put("lines", lines);
            return out;
        });
    }

    @SuppressWarnings("unchecked")
    @Test void exportScenario() throws Exception {
        OracleCases.each(MOD, "exportScenario", a -> {
            Map<String, Object> s = spec(a);
            String mode = (String) s.get("sinkMode");
            String format = (String) s.get("format");
            List<Object> errors = new ArrayList<>();
            List<Object> delivered = new ArrayList<>();
            Siem.SiemSink sink = new Siem.SiemSink() {
                @Override public String name() { return "s1"; }
                @Override public String format() { return format; }
                @Override public Siem.SinkResult deliver(List<Siem.SiemEvent> events) {
                    for (Siem.SiemEvent e : events) delivered.add(e.line);
                    if (mode.equals("ok")) return Siem.SinkResult.success();
                    if (mode.equals("fail")) return Siem.SinkResult.failure("collector said no token=abcdef123");
                    if (mode.equals("failNoError")) return new Siem.SinkResult(false, null);
                    throw new RuntimeException("deliver exploded Bearer abcdefghij");
                }
            };
            Siem.ExportOptions o = new Siem.ExportOptions();
            o.serialize = (Map<String, Object>) s.get("serialize");
            boolean cbThrows = mode.equals("throwsOnError") || Boolean.TRUE.equals(s.get("onErrorThrows"));
            o.onError = (err, name, count) -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("message", err.getMessage());
                m.put("sink", name);
                m.put("count", count);
                errors.add(m);
                if (cbThrows) throw new RuntimeException("cb");
            };
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", Siem.exportBatch((List<Object>) s.get("records"), sink, o).toMap());
            out.put("errors", errors);
            out.put("delivered", delivered);
            return out;
        });
    }

    @Test void jsNumberText() {
        assertEquals("0", JsFmt.num(-0.0));
        assertEquals("1e+21", JsFmt.num(1e21));
        assertEquals("100000000000000000000", JsFmt.num(1e20));
        assertEquals("1.5e-7", JsFmt.num(1.5e-7));
        assertEquals("0.000001", JsFmt.num(1e-6));
        assertEquals("0.1", JsFmt.num(0.1));
        assertEquals("-12.5", JsFmt.num(-12.5));
        assertEquals("1800000000000", JsFmt.num(1_800_000_000_000.0));
    }
}
