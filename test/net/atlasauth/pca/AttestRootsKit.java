package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;

/**
 * Replay helpers of the attestation-root corpora (ref-attest-maa, ref-attest-nvidia, ref-attest-nvidia-rim): the header line carries a
 * {@code blobs} table, every string over 400 characters in args and out is {"$blob": id}; {"$bytes": b64url} is bytes, {"$num"} a non-finite
 * double. A reference rejection whose reason is library text (OpenSSL "error:", a Node type error, an ASN.1 schema text, an OCSP library
 * text) is compared by presence only.
 */
final class AttestRootsKit {
    private AttestRootsKit() {}

    @SuppressWarnings("unchecked")
    static Map<String, Object> blobs(String module) throws Exception {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new GZIPInputStream(Files.newInputStream(BaseOracle.corpusPath(module))), StandardCharsets.UTF_8))) {
            String head = in.readLine();
            Object doc;
            try {
                doc = Json.parseLenient(head);
            } catch (RuntimeException e) {
                doc = Json.parseLenient(head + "]}"); // the header line ends inside the "cases" array
            }
            return (Map<String, Object>) ((Map<String, Object>) doc).get("blobs");
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> hydrated(Map<String, Object> c, Map<String, Object> blobs) {
        Map<String, Object> out = new LinkedHashMap<>(c);
        out.put("args", AttestVectors.hydrate(c.get("args"), blobs));
        out.put("out", AttestVectors.hydrate(c.get("out"), blobs));
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    static byte[] unb(String s) { return java.util.Base64.getUrlDecoder().decode(s); }

    /** {"$bytes"} as byte[] and {"$num"} as double, throughout a value. */
    @SuppressWarnings("unchecked")
    static Object dec(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(dec(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$bytes") instanceof String) return unb((String) map.get("$bytes"));
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    static boolean libText(Object r) {
        if (!(r instanceof String)) return false;
        String s = (String) r;
        return s.startsWith("error:") || s.startsWith("The first argument") || s.contains("error:0") || s.startsWith("OCSP response rejected:");
    }

    /** Where the reference text is library text and the native also gave a text, both become the same marker (presence only). */
    @SuppressWarnings("unchecked")
    static void libAlign(Object want, Object got) {
        if (want instanceof List && got instanceof List && ((List<?>) want).size() == ((List<?>) got).size()) {
            for (int i = 0; i < ((List<?>) want).size(); i++) libAlign(((List<Object>) want).get(i), ((List<Object>) got).get(i));
        } else if (want instanceof Map && got instanceof Map) {
            Map<String, Object> w = (Map<String, Object>) want, g = (Map<String, Object>) got;
            for (Map.Entry<String, Object> e : w.entrySet()) {
                if (!g.containsKey(e.getKey())) continue;
                if ((e.getKey().equals("reason") || e.getKey().equals("error")) && libText(e.getValue()) && g.get(e.getKey()) instanceof String && !((String) g.get(e.getKey())).isEmpty()) {
                    e.setValue("<lib>");
                    g.put(e.getKey(), "<lib>");
                } else libAlign(e.getValue(), g.get(e.getKey()));
            }
        }
    }

    /** One case: a reference throw requires a throw (or a {"$throws"} result); else the normalized JSON must equal. */
    @SuppressWarnings("unchecked")
    static String diff(Map<String, Object> c, OracleCases.Fn fn) {
        Object got = null;
        Throwable err = null;
        try { got = fn.apply((List<?>) c.get("args")); } catch (Throwable t) { err = t; }
        Object want = c.get("out");
        boolean wantThrow = want instanceof Map && ((Map<String, Object>) want).containsKey("$throws");
        boolean gotThrow = err != null || (got instanceof Map && ((Map<String, Object>) got).containsKey("$throws"));
        if (wantThrow) return gotThrow ? null : c.get("name") + "\n  want: throw\n  got:  " + got;
        if (err != null) return c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  THROWS " + err;
        Object norm = IntentJs.normalize(OracleCases.toJson(got));
        libAlign(want, norm);
        if (IntentJs.jsonEquals(want, norm)) return null;
        String g;
        try { g = Json.canonicalize(norm); } catch (RuntimeException e) { g = String.valueOf(norm); }
        String w = Json.canonicalize(want);
        return c.get("name") + "\n  want: " + (w.length() > 1500 ? w.substring(0, 1500) + "..." : w) + "\n  got:  " + (g.length() > 1500 ? g.substring(0, 1500) + "..." : g);
    }

    /** Replays every case of a corpus through the function table; asserts the case total, that every fn name is handled, and returns the number replayed. */
    static void replay(String module, int total, Map<String, OracleCases.Fn> f, Set<String> skipNames) throws Exception {
        Map<String, Object> blobs = blobs(module);
        List<Map<String, Object>> all = BaseOracle.of(module, null);
        assertEquals(total, all.size(), module + " case total");
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns, "every fn of the corpus is replayed");
        List<String> bad = new ArrayList<>();
        int replayed = 0, skipped = 0;
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(module, e.getKey())) {
                if (skipNames != null && skipNames.contains(c.get("name"))) { skipped++; continue; }
                replayed++;
                String d = diff(hydrated(c, blobs), e.getValue());
                if (d != null) bad.add(d);
            }
        }
        assertEquals(total, replayed + skipped, "every case was replayed or counted as skipped");
        assertEquals(skipNames == null ? 0 : skipNames.size(), skipped);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 30))));
    }
}
