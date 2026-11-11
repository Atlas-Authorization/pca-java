package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link ArgProvenance} (provenance by default): a differential test against the TS reference (oracle
 * tools/pca-audit/k05-oracles/argprov-oracle.mts -> test-data/k05-argprov.json.gz). Validators compare the EXACT reason
 * (or null), the decision every member, the recorder every receipt and bundle byte for byte (canonical JSON).
 *
 * <p>Comparison rules: a {@code {$throws}} out only requires a refusal (the Java request reader has no error-code channel:
 * the gate turns any throw into a fail-closed refusal). A decision whose reason is the reference's catch-all
 * {@code "evaluation error (fail closed): <message>"} compares the prefix only (Java names the exception class; the
 * outcome, code and every other member must still match). The recorder's clock is truncated by the harness (a Java
 * {@code LongSupplier} carries whole milliseconds; the reference truncates inside).
 */
public class K05ArgProvDiffTest {
    static final String EVAL_ERR = "evaluation error (fail closed): ";


    /** Parsed once per JVM (the mutation run executes this class once per mutant). */
    static List<Map<String, Object>> cases() throws Exception {
        return K05Oracle.all("k05-argprov");
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    static void report(String fn, int n, List<String> bad) { assertTrue(bad.isEmpty(), fn + ": " + bad.size() + "/" + n + " divergent case(s):\n" + String.join("\n", bad)); }
    static boolean isThrows(Object o) { return o instanceof Map && ((Map<?, ?>) o).containsKey("$throws"); }

    /** Every nested {@code {$throws}} becomes the marker the Java side emits for a refusal. */
    static Object marks(Object v) {
        if (isThrows(v)) return "$THROWS";
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(marks(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), marks(e.getValue()));
            return out;
        }
        return v;
    }
    static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }

    interface Fn { Object apply(List<?> a) throws Exception; }

    /** Generic: exact canonical JSON equality; a {@code {$throws}} out requires a throw. */
    void check(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of(fn);
        for (Map<String, Object> c : cs) {
            Object want = c.get("out");
            String w = isThrows(want) ? "THROWS" : canon(marks(want));
            String got;
            try { got = canon(f.apply(args(c))); } catch (Throwable t) { got = isThrows(want) ? "THROWS" : "THROWS " + t; }
            if (!w.equals(got)) bad.add(c.get("name") + "\n  want: " + w + "\n  got:  " + got);
        }
        report(fn, cs.size(), bad);
    }

    @Test void receiptWire() throws Exception { check("provReceiptWireError", a -> ArgProvenance.receiptWireError(a.get(0))); }
    @Test void mediatorPin() throws Exception { check("isProvMediatorPin", a -> ArgProvenance.isMediatorPin(a.get(0))); }
    @Test void actionInfo() throws Exception { check("provActionInfoError", a -> ArgProvenance.actionInfoError(a.get(0))); }
    @Test void readOnly() throws Exception { check("isReadOnlyAction", a -> ArgProvenance.isReadOnlyAction(a.get(0))); }
    @Test void envelope() throws Exception { check("provEnvelopeError", a -> ArgProvenance.envelopeError(a.get(0))); }
    @Test void tokens() throws Exception { check("occursAsToken", a -> ArgProvenance.occursAsToken((String) a.get(0), (String) a.get(1))); }
    @Test void leafTexts() throws Exception { check("provLeaves", a -> ArgProvenance.leaves(a.get(0))); }
    @Test void receiptRef() throws Exception { check("provReceiptRef", a -> ArgProvenance.receiptRef(a.get(0))); }

    @Test void actionDigest() throws Exception {
        check("provActionDigest", a -> {
            Map<String, Object> op = IntentJs.obj(a.get(0));
            return ArgProvenance.actionDigest((String) op.get("verb"), (String) op.get("resource"), op.get("params"));
        });
    }

    static ArgProvenance.Input input(Object a) {
        if (!(a instanceof Map)) return null;
        Map<String, Object> m = IntentJs.obj(a);
        ArgProvenance.Input in = new ArgProvenance.Input();
        in.bundle = m.get("bundle");
        in.operation = m.get("operation");
        in.mediators = m.get("mediators"); // absent stays absent (null): the reference denies a missing pin list
        in.action = m.get("action");
        in.principalPlan = Boolean.TRUE.equals(m.get("principalPlan"));
        in.principalControl = Boolean.TRUE.equals(m.get("principalControl"));
        in.observed = m.get("observed");
        return in;
    }

    @Test void decision() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of("decideArgProvenance");
        for (Map<String, Object> c : cs) {
            Map<String, Object> want = new LinkedHashMap<>(IntentJs.obj(c.get("out")));
            String got;
            try {
                Map<String, Object> g = ArgProvenance.decide(input(args(c).get(0))).toJson();
                if (want.get("reason") instanceof String && ((String) want.get("reason")).startsWith(EVAL_ERR)) {
                    want.put("reason", EVAL_ERR);
                    if (g.get("reason") instanceof String && ((String) g.get("reason")).startsWith(EVAL_ERR)) g.put("reason", EVAL_ERR);
                }
                got = canon(g);
            } catch (Throwable t) { got = "THROWS " + t; }
            String w = canon(want);
            if (!w.equals(got)) bad.add(c.get("name") + "\n  want: " + w + "\n  got:  " + got);
        }
        report("decideArgProvenance", cs.size(), bad);
    }

    static Authorize.Operation op(Object o) {
        Map<String, Object> m = IntentJs.obj(o);
        return new Authorize.Operation((String) m.get("verb"), (String) m.get("resource"), IntentJs.obj(m.get("params")));
    }

    /** The mediator side: one recorder, the spec's steps in order; a step that throws records the refusal marker. */
    @Test void recorder() throws Exception {
        check("recorder", a -> {
            Map<String, Object> spec = IntentJs.obj(a.get(0));
            List<Object> clock = new ArrayList<>((List<?>) spec.get("clock"));
            long[] last = {0};
            ArgProvenance.Recorder rec = new ArgProvenance.Recorder((String) spec.get("mediator"), (String) spec.get("kid"),
                Keys.ed25519(Keys.edFromSeed(Base64.getUrlDecoder().decode((String) spec.get("sk")))), (String) spec.get("session"),
                () -> clock.isEmpty() ? last[0] : (last[0] = IntentJs.lng(clock.remove(0))));
            List<Object> outs = new ArrayList<>();
            for (Object so : (List<?>) spec.get("steps")) {
                List<?> s = (List<?>) so;
                try {
                    switch ((String) s.get(0)) {
                        case "principal": outs.add(rec.principal((String) s.get(1))); break;
                        case "tool": outs.add(rec.tool((String) s.get(1), s.get(2))); break;
                        case "retrieval": outs.add(rec.retrieval((String) s.get(1), s.get(2))); break;
                        case "web": outs.add(rec.web((String) s.get(1), s.get(2))); break;
                        case "action": outs.add(rec.forAction(op(s.get(1)))); break;
                        case "direct": outs.add(ArgProvenance.principalDirect(rec, op(s.get(1)))); break;
                        default: throw new AssertionError("unknown step " + s.get(0));
                    }
                } catch (RuntimeException e) {
                    outs.add("$THROWS");
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("pin", rec.pin());
            out.put("outs", outs);
            return out;
        });
    }

    /** The request reader: header {@code PCA-Provenance}, else the body member {@code pca_provenance}. */
    @Test void requestBundle() throws Exception {
        check("defaultProvenanceBundle", a -> {
            Map<String, Object> r = IntentJs.obj(a.get(0));
            String body = (String) r.get("body");
            return ArgProvenance.requestBundle((String) r.get("header"), body == null ? null : body.getBytes(StandardCharsets.UTF_8));
        });
    }
}
