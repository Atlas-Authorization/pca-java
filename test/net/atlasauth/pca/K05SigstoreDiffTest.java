package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Sigstore}: a differential test against the TS reference (oracle
 * tools/pca-audit/k05-oracles/sigstore-oracle.mts -> test-data/k05-sigstore.json.gz).
 *
 * <ul>
 *   <li>parseTrustedRoot: the summary (log key ids, validity, v2 names, chain lengths) or a refusal;
 *   <li>verifySigstoreBundleCore / verifySigstoreBundle: ok and the exact core / facts, or the exact refusal code. The detail
 *       is informative only: the reference's details embed JavaScript runtime messages ("fail closed: Unexpected token ...");
 *   <li>verifyRfc3161: the exact genTime (ms) or a refusal; dssePae: the exact bytes.
 * </ul>
 */
public class K05SigstoreDiffTest {
    static List<Map<String, Object>> all;
    static final Map<String, Sigstore.PinnedRoots> ROOTS = new HashMap<>();

    @SuppressWarnings("unchecked")
    static synchronized List<Map<String, Object>> cases() throws Exception {
        if (all != null) return all;
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k05-sigstore.json.gz")))) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            in.transferTo(b);
            all = (List<Map<String, Object>>) ((Map<String, Object>) Json.parseLenient(b.toString(StandardCharsets.UTF_8))).get("cases");
        }
        for (Map<String, Object> c : all) {
            if (!"parseTrustedRoot".equals(c.get("fn"))) continue;
            String id = ((String) c.get("name")).substring("parseTrustedRoot/".length());
            try { ROOTS.put(id, Sigstore.parseTrustedRoot(args(c).get(0))); } catch (RuntimeException e) { /* refused: no roots */ }
        }
        return all;
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    static Map<?, ?> map(Object o) { return o instanceof Map ? (Map<?, ?>) o : null; }
    static boolean throwsOut(Object out) { return map(out) != null && map(out).containsKey("$throws"); }
    /** The Java roots a {"$root": id} argument names (null when the Java parse refused that root). */
    static Sigstore.PinnedRoots root(Object ref) { return ROOTS.get((String) map(ref).get("$root")); }
    static void report(String fn, List<String> bad, boolean suspect) {
        if (suspect) {
            System.out.println(fn + ": " + bad.size() + " case(s) differ from the reference (@suspect, report only)\n" + String.join("\n", bad));
            return;
        }
        assertTrue(bad.isEmpty(), fn + ": " + bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }

    // ---- parseTrustedRoot ----

    static Object summaryLog(Sigstore.PinnedLog l) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("keyId", Base64.getEncoder().encodeToString(l.keyId));
        m.put("start", l.start);
        m.put("end", l.end == Long.MAX_VALUE ? null : l.end);
        m.put("v2", l.v2Name);
        return m;
    }
    static Object summaryCa(Sigstore.PinnedCa c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("chain", (long) c.chain.size());
        m.put("start", c.start);
        m.put("end", c.end == Long.MAX_VALUE ? null : c.end);
        return m;
    }
    static Object summary(Sigstore.PinnedRoots r) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<Object> tl = new ArrayList<>(), ct = new ArrayList<>(), ca = new ArrayList<>(), ts = new ArrayList<>();
        for (Sigstore.PinnedLog l : r.tlogs) tl.add(summaryLog(l));
        for (Sigstore.PinnedLog l : r.ctlogs) ct.add(summaryLog(l));
        for (Sigstore.PinnedCa c : r.cas) ca.add(summaryCa(c));
        for (Sigstore.PinnedCa c : r.tsas) ts.add(summaryCa(c));
        m.put("tlogs", tl);
        m.put("ctlogs", ct);
        m.put("cas", ca);
        m.put("tsas", ts);
        return m;
    }

    @Test void parseTrustedRoot() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("parseTrustedRoot")) {
            Object want = c.get("out");
            String got;
            Object sum = null;
            try { sum = summary(Sigstore.parseTrustedRoot(args(c).get(0))); got = Json.canonicalize(sum); } catch (RuntimeException e) { got = "THROWS " + e; }
            boolean same = throwsOut(want) ? got.startsWith("THROWS ") : sum != null && IntentJs.jsonEquals(want, sum);
            if (!same) bad.add(c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + got);
        }
        report("parseTrustedRoot", bad, false);
    }

    // ---- bundles ----

    static String show(Object v) {
        try { return Json.canonicalize(v); } catch (RuntimeException e) { return String.valueOf(v); }
    }

    /** "" when the Java result matches the reference's {ok, core|facts} / {ok: false, code} / {$throws}, else the difference. */
    static String compare(Object want, boolean ok, Map<String, Object> value, String code, String detail, String member) {
        String got = ok ? "ok " + show(value) : "refused " + code + " (" + detail + ")";
        Map<?, ?> w = map(want);
        if (throwsOut(want)) return ok ? "\n  want: refusal " + w.get("$throws") + "\n  got:  " + got : "";
        if (Boolean.TRUE.equals(w.get("ok"))) return ok && IntentJs.jsonEquals(w.get(member), value) ? "" : "\n  want: ok " + show(w.get(member)) + "\n  got:  " + got;
        return !ok && String.valueOf(w.get("code")).equals(code) ? "" : "\n  want: refused " + w.get("code") + " (" + w.get("detail") + ")\n  got:  " + got;
    }

    void core(String fn, boolean suspect) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(fn)) {
            String d;
            try {
                Sigstore.CoreResult r = Sigstore.verifySigstoreBundleCore(args(c).get(0), root(args(c).get(1)));
                d = compare(c.get("out"), r.ok, r.core, r.code, r.detail, "core");
            } catch (Throwable t) { d = "\n  THROWS " + t; } // the verifier never throws
            if (!d.isEmpty()) bad.add(c.get("name") + d);
        }
        report(fn, bad, suspect);
    }
    @Test void verifySigstoreBundleCore() throws Exception { core("verifySigstoreBundleCore", false); }

    @Test void verifySigstoreBundle() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("verifySigstoreBundle")) {
            String d;
            try {
                Sigstore.Result r = Sigstore.verifySigstoreBundle(args(c).get(0), root(args(c).get(1)));
                d = compare(c.get("out"), r.ok, r.facts, r.code, r.detail, "facts");
            } catch (Throwable t) { d = "\n  THROWS " + t; }
            if (!d.isEmpty()) bad.add(c.get("name") + d);
        }
        report("verifySigstoreBundle", bad, false);
    }

    // ---- RFC 3161 ----

    void rfc3161(String fn, boolean suspect) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(fn)) {
            List<?> a = args(c);
            Object want = c.get("out");
            String got;
            try {
                Sigstore.PinnedRoots r = root(a.get(2));
                if (r == null) throw new IllegalArgumentException("bad root ref");
                got = Long.toString(Sigstore.verifyRfc3161(Base64.getDecoder().decode((String) a.get(0)), Base64.getDecoder().decode((String) a.get(1)), r.tsas));
            } catch (RuntimeException e) { got = "THROWS " + e; }
            boolean same = throwsOut(want) ? got.startsWith("THROWS ") : IntentJs.isSafeInteger(want) && Long.toString(IntentJs.lng(want)).equals(got);
            if (!same) bad.add(c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + got);
        }
        report(fn, bad, suspect);
    }
    @Test void verifyRfc3161() throws Exception { rfc3161("verifyRfc3161", false); }

    @Test void dssePae() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("dssePae")) {
            List<?> a = args(c);
            String want = (String) map(c.get("out")).get("$bytes");
            String got = Base64.getUrlEncoder().withoutPadding().encodeToString(Sigstore.dssePae((String) a.get(0), Base64.getDecoder().decode((String) a.get(1))));
            if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report("dssePae", bad, false);
    }
}
