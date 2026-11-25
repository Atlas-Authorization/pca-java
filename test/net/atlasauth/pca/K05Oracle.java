package net.atlasauth.pca;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Loads a k05 oracle (test-data/k05-&lt;module&gt;.json.gz: a header line, then one case per line) line by line, optionally only
 * the cases of one fn, into a soft cache. The oracles are up to 170 MB of JSON: reading a whole file into one string, or
 * keeping every module's cases strongly reachable, ran the surefire fork (2 GB) out of heap.
 */
final class K05Oracle {
    private K05Oracle() {}

    private static final Map<String, SoftReference<List<Map<String, Object>>>> CACHE = new HashMap<>();

    /** Every case of the module (normalized like the k042 tests). */
    static List<Map<String, Object>> all(String module) throws Exception { return load(module, null); }

    /** The cases of one fn (empty when there are none). */
    static List<Map<String, Object>> of(String module, String fn) throws Exception { return load(module, fn); }

    @SuppressWarnings("unchecked")
    private static synchronized List<Map<String, Object>> load(String module, String fn) throws Exception {
        String key = module + "\u0000" + fn;
        SoftReference<List<Map<String, Object>>> r = CACHE.get(key);
        List<Map<String, Object>> out = r == null ? null : r.get();
        if (out != null) return out;
        out = new ArrayList<>();
        String head = fn == null ? "{\"fn\":" : "{\"fn\":" + Json.canonicalize(fn) + ",";
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new GZIPInputStream(Files.newInputStream(Path.of("test-data/" + module + ".json.gz"))), StandardCharsets.UTF_8))) {
            for (String line; (line = in.readLine()) != null; ) {
                if (!line.startsWith(head)) continue;
                if (line.endsWith(",")) line = line.substring(0, line.length() - 1);
                out.add((Map<String, Object>) IntentJs.normalize(Json.parseLenient(line)));
            }
        }
        if (out.isEmpty() && fn == null) throw new IllegalStateException("no cases in " + module);
        CACHE.put(key, new SoftReference<>(out));
        return out;
    }
}
