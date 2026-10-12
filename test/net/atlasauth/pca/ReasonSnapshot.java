package net.atlasauth.pca;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Characterization snapshot of every OBSERVABLE output of the verifier over the whole conformance corpus (core +
 * full adversarial): allow, the check map, the diagnostic {@code reason}, the strict-JSON rejection message and the
 * canonical forms. Conformance only pins allow/checks; this pins the rest so mutation testing sees diagnostics too.
 * Regenerate with {@code java -cp ... net.atlasauth.pca.ReasonSnapshot test-data/reasons.tsv.gz} (deterministic).
 */
public final class ReasonSnapshot {
    static final String DIR = "conformance/";

    static String esc(String s) {
        if (s == null) return "<null>";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') b.append("\\\\");
            else if (c == '\n') b.append("\\n");
            else if (c == '\t') b.append("\\t");
            else if (c == '\r') b.append("\\r");
            else if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> loadJson(String name) throws Exception {
        if (name.endsWith(".gz")) {
            try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of(DIR + name)))) {
                return (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DIR + name)));
    }

    /** One line per vector / primitive: key TAB value. */
    @SuppressWarnings("unchecked")
    static Map<String, String> compute(Map<String, Object> doc, String tag, int k, int step) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Object> vs = (List<Object>) doc.get("vectors");
        for (int i = k; i < vs.size(); i += step) {
            Map<String, Object> v = (Map<String, Object>) vs.get(i);
            Map<String, Object> ctx = (Map<String, Object>) v.get("context");
            List<String> allowed = null;
            if (ctx.get("allowed_suites") instanceof List) {
                allowed = new ArrayList<>();
                for (Object o : (List<Object>) ctx.get("allowed_suites")) allowed.add(String.valueOf(o));
            }
            String val;
            try {
                Pca.Verdict g = v.containsKey("pcactn_json")
                    ? Pca.verifyPcactnJson((String) v.get("pcactn_json"), (Map<String, Object>) v.get("grant"), Json.asLong(ctx.get("now")), (String) ctx.get("aud"), allowed)
                    : Pca.verifyPcactn(v.get("pcactn"), (Map<String, Object>) v.get("grant"), Json.asLong(ctx.get("now")), (String) ctx.get("aud"), allowed);
                val = g.allow + "|" + g.checks + "|" + esc(g.reason);
            } catch (Throwable t) { val = "THROW:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage()); }
            out.put(tag + ":v:" + v.get("name"), val);
        }
        Map<String, Object> prim = (Map<String, Object>) doc.get("primitives");
        if (k == 0 && prim != null) {
            int n = 0;
            if (prim.get("chain_pin") != null) for (Object x : (List<Object>) prim.get("chain_pin")) {
                Map<String, Object> cv = (Map<String, Object>) x;
                String why;
                try {
                    List<String> allowed = null;
                    if (cv.get("allowed_suites") instanceof List) {
                        allowed = new ArrayList<>();
                        for (Object o : (List<Object>) cv.get("allowed_suites")) allowed.add(String.valueOf(o));
                    }
                    why = Pca.verifyChain((List<Object>) cv.get("chain"), (String) cv.get("expected_root_issuer"), cv.get("expected_root_issuer") instanceof String,
                        allowed, (Map<String, Object>) cv.get("pq_pins"), (Map<String, Object>) cv.get("trusted_root"));
                } catch (Throwable t) { why = "THROW:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage()); }
                out.put(tag + ":cp:" + cv.get("name"), esc(why));
            }
            if (prim.get("json_parse") != null) for (Object x : (List<Object>) prim.get("json_parse")) {
                String in = (String) ((Map<String, Object>) x).get("input");
                String val;
                try {
                    Object parsed = Json.parse(in);
                    String c;
                    try { c = Json.canonicalizeStrict(parsed); } catch (RuntimeException e) { c = "CANON-ERR:" + e.getClass().getSimpleName() + ":" + esc(e.getMessage()); }
                    val = "ok|" + esc(c) + "|" + esc(Json.canonicalize(parsed));
                } catch (Throwable t) { val = "err|" + t.getClass().getSimpleName() + "|" + esc(t.getMessage()); }
                String lenient;
                try { lenient = esc(Json.canonicalize(Json.parseLenient(in))); } catch (Throwable t) { lenient = "ERR:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage()); }
                out.put(tag + ":jp:" + (n++) + ":" + esc(in.length() > 80 ? in.substring(0, 80) : in), val + "|len=" + lenient);
            }
            n = 0;
            if (prim.get("canonical") != null) for (Object x : (List<Object>) prim.get("canonical")) {
                Object value = ((Map<String, Object>) x).get("value");
                String val;
                try { val = Json.canonicalizeStrict(value) + "|" + Pca.hashStrict(value); } catch (Throwable t) { val = "ERR:" + esc(t.getMessage()); }
                String len;
                try { len = Json.canonicalize(value) + "|" + Pca.hashCanonical(value); } catch (Throwable t) { len = "ERR:" + esc(t.getMessage()); }
                out.put(tag + ":cn:" + (n++), esc(val) + "|" + esc(len));
            }
            n = 0;
            if (prim.get("b64u") != null) for (Object x : (List<Object>) prim.get("b64u")) {
                Map<String, Object> b = (Map<String, Object>) x;
                int len = b.containsKey("len") ? (int) Json.asLong(b.get("len")) : -1;
                byte[] r = Pca.decodeB64uStrict(b.get("input"), len);
                out.put(tag + ":b6:" + (n++), r == null ? "null" : Pca.b64(r));
            }
        }
        return out;
    }

    static List<Map<String, Object>> inputs;

    @SuppressWarnings("unchecked")
    static synchronized List<Map<String, Object>> inputs() throws Exception {
        if (inputs == null) {
            List<Map<String, Object>> l = new ArrayList<>();
            try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("../../tools/pca-audit/native-mutation/inputs.jsonl.gz")))) {
                for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n"))
                    if (!line.isEmpty()) l.add((Map<String, Object>) Json.parseLenient(line));
            }
            inputs = l;
        }
        return inputs;
    }

    /** Pinned outputs over tools/pca-audit/native-mutation/inputs.jsonl.gz (structural + parse fuzz), entries i % step == k. */
    @SuppressWarnings("unchecked")
    static Map<String, String> computeInputs(int k, int step) throws Exception {
        Map<String, String> out = new LinkedHashMap<>();
        List<Map<String, Object>> in = inputs();
        for (int i = k; i < in.size(); i += step) {
            Map<String, Object> c = in.get(i);
            String raw = (String) c.get("raw");
            String val;
            if ("verify".equals(c.get("kind"))) {
                try {
                    List<String> allowed = null;
                    if (c.get("allowed_suites") instanceof List) {
                        allowed = new ArrayList<>();
                        for (Object o : (List<Object>) c.get("allowed_suites")) allowed.add(String.valueOf(o));
                    }
                    Map<String, Object> grant = (Map<String, Object>) Json.parseLenient((String) c.get("grant"));
                    Pca.Verdict g = Pca.verifyPcactnJson(raw, grant, Json.asLong(c.get("now")), (String) c.get("aud"), allowed);
                    val = g.allow + "|" + g.checks + "|" + esc(g.reason);
                } catch (Throwable t) { val = "THROW:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage()); }
            } else {
                try {
                    Object parsed = Json.parse(raw);
                    String cs;
                    try { cs = Json.canonicalizeStrict(parsed); } catch (RuntimeException e) { cs = "CANON-ERR:" + esc(e.getMessage()); }
                    val = "ok|" + esc(cs);
                } catch (Throwable t) { val = "err|" + t.getClass().getSimpleName() + "|" + esc(t.getMessage()); }
                try { val += "|len=" + esc(Json.canonicalize(Json.parseLenient(raw))); } catch (Throwable t) { val += "|len=ERR:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage()); }
            }
            if (val.length() > 600) val = val.substring(0, 600) + "#" + val.hashCode();
            out.put("in:" + c.get("id"), val);
        }
        return out;
    }

    /**
     * Runs {@code c} on a thread with a 512 MiB stack, so the pinned outputs never depend on the JVM / PIT-minion stack size or
     * on instrumentation frames (a deep lenient re-parse that overflowed on one stack and not on another made the snapshot
     * flaky under mutation: equivalent mutants were reported KILLED by SnapshotTest.a00).
     */
    static <T> T onBigStack(java.util.concurrent.Callable<T> c) throws Exception {
        Object[] box = new Object[2];
        Thread t = new Thread(null, () -> { try { box[0] = c.call(); } catch (Throwable e) { box[1] = e; } }, "snapshot", 1L << 29);
        t.start();
        t.join();
        if (box[1] instanceof Exception) throw (Exception) box[1];
        if (box[1] instanceof Error) throw (Error) box[1];
        @SuppressWarnings("unchecked") T r = (T) box[0];
        return r;
    }

    public static void main(String[] a) throws Exception {
        onBigStack(() -> { write(a[0]); return null; });
    }

    static void write(String path) throws Exception {
        String[] a = {path};
        Map<String, String> all = new LinkedHashMap<>();
        all.putAll(computeInputs(0, 1));
        all.putAll(compute(loadJson("vectors.json"), "core", 0, 1));
        Map<String, Object> adv = loadJson("vectors-adversarial.json.gz");
        all.putAll(compute(adv, "adv", 0, 1));
        try (OutputStream os = new GZIPOutputStream(Files.newOutputStream(Path.of(a[0])))) {
            for (Map.Entry<String, String> e : all.entrySet())
                os.write((esc(e.getKey()) + "\t" + e.getValue() + "\n").getBytes(StandardCharsets.UTF_8));
        }
        System.out.println("wrote " + all.size() + " lines");
    }

    static synchronized Map<String, String> load() throws Exception {
        if (cache != null) return cache;
        Map<String, String> m = new java.util.HashMap<>();
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/reasons.tsv.gz")))) {
            for (String l : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                int t = l.indexOf('\t');
                if (t > 0) m.put(l.substring(0, t), l.substring(t + 1));
            }
        }
        return cache = m;
    }
    private static Map<String, String> cache;
}
