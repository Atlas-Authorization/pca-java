package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.dataflow.Dataflow;
import net.atlasauth.pca.dataflow.Dataflow.Capability;
import net.atlasauth.pca.dataflow.Detectors;
import net.atlasauth.pca.dataflow.TraceRules;
import org.junit.jupiter.api.Test;

class DataflowDiffTest {
    private static final String M = "ref-dataflow";

    // ---- spec plumbing (see the oracle header) ------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<String> strs(Object o) { return (List<String>) o; }

    /** A capability spec as the reference's tag() accepts it; anything else is refused. */
    private static Capability cap(Object spec) {
        if (!(spec instanceof Map)) throw new IllegalArgumentException("tag: a capability needs a set of sources and a boolean isTrusted");
        Map<String, Object> m = map(spec);
        if (!(m.get("sources") instanceof List) || !(m.get("isTrusted") instanceof Boolean)) throw new IllegalArgumentException("tag: a capability needs a set of sources and a boolean isTrusted");
        if (m.containsKey("readers") && !(m.get("readers") instanceof List)) throw new IllegalArgumentException("tag: readers must be a Set when given");
        return new Capability(strs(m.get("sources")), (Boolean) m.get("isTrusted"), m.containsKey("readers") ? strs(m.get("readers")) : null);
    }

    /** A value spec: {"$raw": v} is v itself (untagged); {"$t": v, cap} is tagged; anything else is itself. */
    private static Object val(Object spec) {
        if (spec instanceof Map && map(spec).containsKey("$raw")) {
            Object raw = map(spec).get("$raw");
            return raw == null ? new Object() : raw; // a null element would read as an explicit undefined
        }
        if (spec instanceof Map && map(spec).containsKey("$t")) return Dataflow.tag(map(spec).get("$t"), cap(map(spec).get("cap")));
        return spec;
    }

    private static Map<String, Object> capJson(Capability c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sources", new ArrayList<Object>(c.sources()));
        m.put("isTrusted", c.isTrusted());
        if (c.readers() != null) m.put("readers", new ArrayList<Object>(c.readers()));
        return m;
    }

    private static Map<String, Object> taggedJson(Object t) {
        Dataflow.Tagged<?> tg = (Dataflow.Tagged<?>) t;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", tg.value());
        m.put("cap", capJson(tg.cap()));
        return m;
    }

    private static Dataflow.Sink sink(Object spec) {
        if (!(spec instanceof Map)) return null;
        Map<String, Object> m = map(spec);
        String id = m.get("id") instanceof String ? (String) m.get("id") : null;
        Dataflow.FlowPolicy p = null;
        if (m.get("accepts") instanceof Map) {
            Map<String, Object> a = map(m.get("accepts"));
            p = new Dataflow.FlowPolicy(a.get("external") instanceof Boolean ? (Boolean) a.get("external") : null,
                a.get("requireTrusted") instanceof Boolean ? (Boolean) a.get("requireTrusted") : null,
                a.get("allowedSources") instanceof List ? strs(a.get("allowedSources")) : null,
                a.get("deniedSources") instanceof List ? strs(a.get("deniedSources")) : null);
        }
        return new Dataflow.Sink(id, p);
    }

    private static Map<String, Object> decisionJson(Dataflow.FlowDecision d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("outcome", d.outcome);
        if (d.reason != null) m.put("reason", d.reason);
        if (d.path != null) m.put("path", new ArrayList<Object>(d.path));
        return m;
    }

    private static Function<List<Object>, Object> combiner(String name) {
        switch (name) {
            case "count": return v -> new Json.Num(Integer.toString(v.size()));
            case "pair": return v -> v;
            case "first": return v -> v.get(0);
            default: return v -> { throw new IllegalStateException("combiner failed"); };
        }
    }

    // ---- data-flow ------------------------------------------------------------------------------------------------------------

    @Test void tag() throws Exception { OracleCases.each(M, "tag", a -> taggedJson(Dataflow.tag(a.get(0), cap(a.get(1))))); }

    @SuppressWarnings("unchecked")
    private static List<String> readers(Object opts) {
        return opts instanceof Map && map(opts).get("readers") instanceof List ? (List<String>) map(opts).get("readers") : null;
    }

    @Test void fromTrustedQuery() throws Exception { OracleCases.each(M, "fromTrustedQuery", a -> taggedJson(Dataflow.fromTrustedQuery(a.get(0), readers(a.get(1))))); }

    @Test void fromToolOutput() throws Exception { OracleCases.each(M, "fromToolOutput", a -> taggedJson(Dataflow.fromToolOutput((String) a.get(0), a.get(1), readers(a.get(2))))); }

    @Test void fromSource() throws Exception {
        OracleCases.each(M, "fromSource", a -> {
            Object t = a.get(2) instanceof Map ? map(a.get(2)).get("isTrusted") : null;
            return taggedJson(Dataflow.fromSource((String) a.get(0), a.get(1), Boolean.TRUE.equals(t), readers(a.get(2))));
        });
    }

    private static List<Capability> caps(Object o) {
        List<Capability> out = new ArrayList<>();
        for (Object c : (List<?>) o) {
            Map<String, Object> m = map(c);
            out.add(new Capability(strs(m.get("sources")), Boolean.TRUE.equals(m.get("isTrusted")), m.containsKey("readers") ? strs(m.get("readers")) : null));
        }
        return out;
    }

    @Test void unionSources() throws Exception { OracleCases.each(M, "unionSources", a -> new ArrayList<Object>(Dataflow.unionSources(caps(a.get(0))))); }

    @Test void combineCaps() throws Exception { OracleCases.each(M, "combineCaps", a -> capJson(Dataflow.combineCaps(caps(a.get(0))))); }

    @Test void derive() throws Exception {
        OracleCases.each(M, "derive", a -> {
            List<Object> ins = new ArrayList<>();
            for (Object s : (List<?>) a.get(0)) ins.add(val(s));
            return taggedJson(Dataflow.derive(ins, combiner((String) a.get(1))));
        });
    }

    @Test void classifyFlow() throws Exception { OracleCases.each(M, "classifyFlow", a -> decisionJson(Dataflow.classifyFlow(val(a.get(0)), sink(a.get(1))))); }

    @Test void canFlow() throws Exception {
        OracleCases.each(M, "canFlow", a -> {
            Dataflow.CanFlow c = Dataflow.canFlow(val(a.get(0)), sink(a.get(1)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", c.ok);
            if (c.reason != null) m.put("reason", c.reason);
            return m;
        });
    }

    @Test void checkAction() throws Exception {
        OracleCases.each(M, "checkAction", a -> {
            Map<String, Object> act = map(a.get(0));
            List<Object> args = new ArrayList<>();
            for (Object s : (List<?>) a.get(1)) {
                if (s == null) args.add(null);
                else if (s instanceof Map && Boolean.TRUE.equals(map(s).get("$hole"))) args.add(Dataflow.HOLE);
                else args.add(val(s));
            }
            Map<String, Object> g = map(a.get(2));
            Dataflow.FlowGovernor gov = action -> {
                if (Boolean.TRUE.equals(g.get("throws"))) throw new IllegalStateException("governor failed");
                return sink(g.get("sink"));
            };
            Map<String, Object> op = map(a.get(3));
            Double expected = op.containsKey("expectedArgs") ? JsValNum.of(op.get("expectedArgs")) : null;
            Dataflow.ActionDecision d = Dataflow.checkAction(new Dataflow.PcaStyleAction((String) act.get("verb"), (String) act.get("resource")), args, gov, expected);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", d.outcome);
            m.put("sink", d.sink);
            if (d.reason != null) m.put("reason", d.reason);
            if (d.arg != null) m.put("arg", new Json.Num(Integer.toString(d.arg)));
            if (d.path != null) m.put("path", new ArrayList<Object>(d.path));
            return m;
        });
    }

    /** The JavaScript number of a parsed JSON number. */
    private static final class JsValNum {
        static Double of(Object o) { return net.atlasauth.pca.revoke.JsVal.num(o); }
    }

    @Test void dualContext() throws Exception {
        OracleCases.each(M, "dualContext", a -> {
            Map<String, Object> spec = map(a.get(0));
            Function<Object, Object> plan;
            switch ((String) spec.get("plan")) {
                case "identity": plan = q -> q; break;
                case "wrap": plan = q -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("planned", q); return m; }; break;
                default: plan = q -> { throw new IllegalStateException("planner failed"); };
            }
            Function<Object, Object> quarantine;
            switch ((String) spec.get("quarantine")) {
                case "tagged_untrusted": quarantine = p -> Dataflow.fromToolOutput("quarantine", p, null); break;
                case "trusted": quarantine = p -> Dataflow.fromTrustedQuery(p, null); break;
                case "raw": quarantine = p -> new Object(); break;
                default: quarantine = p -> { throw new IllegalStateException("q failed"); };
            }
            Dataflow.DualResult<Object, Object> r = Dataflow.dualContext(val(spec.get("query")), plan, quarantine);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("plan", r.plan);
            m.put("result", taggedJson(r.result));
            return m;
        });
    }

    @Test void sinkPresets() throws Exception {
        OracleCases.each(M, "externalSendSink", a -> sinkJson(Dataflow.externalSendSink((String) a.get(0))));
        OracleCases.each(M, "sensitiveSink", a -> sinkJson(Dataflow.sensitiveSink((String) a.get(0))));
    }

    private static Map<String, Object> sinkJson(Dataflow.Sink s) {
        Map<String, Object> acc = new LinkedHashMap<>();
        if (s.accepts.external != null) acc.put("external", s.accepts.external);
        if (s.accepts.requireTrusted != null) acc.put("requireTrusted", s.accepts.requireTrusted);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", s.id);
        m.put("accepts", acc);
        return m;
    }

    @Test void levelOf() throws Exception { OracleCases.each(M, "levelOf", a -> Dataflow.levelOf(val(a.get(0)))); }

    @Test void consts() throws Exception {
        OracleCases.each(M, "consts", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("TRUSTED_QUERY", Dataflow.TRUSTED_QUERY);
            m.put("tool", Dataflow.toolProvenance("x"));
            m.put("tool2", Dataflow.toolProvenance(""));
            return m;
        });
    }

    // ---- trace rules ------------------------------------------------------------------------------------------------------------

    /** A refusal that carries the reference's stable error code. */
    private static final class CodedEx extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;

        CodedEx(TraceRules.TraceRuleError e) { super(e.getMessage(), e); this.code = e.code(); }

        @Override public String code() { return code; }
    }

    private interface Thunk { Object get() throws Exception; }

    private static Object guard(Thunk t) throws Exception {
        try { return t.get(); } catch (TraceRules.TraceRuleError e) { throw new CodedEx(e); }
    }

    @Test void parseTraceRule() throws Exception {
        OracleCases.each(M, "parseTraceRule", a -> guard(() -> a.size() > 2
            ? TraceRules.parseTraceRule((String) a.get(0), (String) a.get(1), a.get(2))
            : TraceRules.parseTraceRule((String) a.get(0), (String) a.get(1))));
    }

    @Test void parseInvariantRule() throws Exception {
        OracleCases.each(M, "parseInvariantRule", a -> guard(() -> TraceRules.parseInvariantRule((String) a.get(0), (String) a.get(1), a.get(2) instanceof Map ? map(a.get(2)) : null)));
    }

    @Test void compileTraceRules() throws Exception {
        OracleCases.each(M, "compileTraceRules", a -> guard(() -> TraceRules.compileTraceRules(a.get(0), map(a.get(1)))));
    }

    @SuppressWarnings("unchecked")
    @Test void lethalTrifecta() throws Exception {
        OracleCases.each(M, "lethalTrifecta", a -> TraceRules.lethalTrifecta(map(a.get(0)), (List<Object>) a.get(1), a.get(2) instanceof Map ? map(a.get(2)) : null));
    }

    @Test void traceConsts() throws Exception {
        OracleCases.each(M, "traceConsts", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("MAX_TRACE_CAVEATS", TraceRules.MAX_TRACE_CAVEATS);
            m.put("PRIVATE_READ_TRAITS", TraceRules.PRIVATE_READ_TRAITS);
            m.put("EXTERNAL_SEND_TRAITS", TraceRules.EXTERNAL_SEND_TRAITS);
            return m;
        });
    }

    // ---- detectors ----------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> ctx(Object o) {
        Map<String, Object> c = new LinkedHashMap<>(map(o));
        c.put("secretKey", Keys.unb64u((String) map(c.get("secretKey")).get("$bytes")));
        return c;
    }

    @Test void categoryId() throws Exception { OracleCases.each(M, "categoryId", a -> Detectors.categoryId(a.get(0))); }

    @Test void lakeraReceipt() throws Exception { OracleCases.each(M, "lakeraReceipt", a -> Detectors.lakeraReceipt(a.get(0), ctx(a.get(1)))); }

    @Test void promptSecurityReceipt() throws Exception { OracleCases.each(M, "promptSecurityReceipt", a -> Detectors.promptSecurityReceipt(a.get(0), ctx(a.get(1)))); }

    @Test void genericReceipt() throws Exception { OracleCases.each(M, "genericReceipt", a -> Detectors.genericReceipt(a.get(0), ctx(a.get(1)))); }
}
