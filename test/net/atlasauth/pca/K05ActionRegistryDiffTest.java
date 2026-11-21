package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link ActionRegistry}: a differential test against the TS reference (oracle
 * tools/pca-audit/k05-oracles/actionregistry-oracle.mts -> test-data/k05-actionregistry.json.gz). Every validator case asserts
 * the EXACT reason (or null), every decision every member. {@code {$throws, code}} must throw an {@link Actions.ActionKitError}
 * with that code, {@code {$throws}} any refusal. A case carrying {@code textPrefix} (engine-specific message tails: JS
 * TypeError text, canonicalizer wording) requires the same decision with a message that starts with the prefix.
 */
public class K05ActionRegistryDiffTest {
    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = K05Oracle.of("k05-actionregistry", fn);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }

    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    static Map<String, Object> mapOrNull(Object o) { return o instanceof Map ? M(o) : null; }

    static Map<String, Object> thrown(RuntimeException e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("$throws", String.valueOf(e.getMessage()));
        if (e instanceof Actions.ActionKitError) m.put("code", ((Actions.ActionKitError) e).code);
        return m;
    }

    /** Every string that starts with the prefix becomes the prefix (both sides). */
    @SuppressWarnings("unchecked")
    static Object cut(Object v, String p) {
        if (v instanceof String) return ((String) v).startsWith(p) ? p : v;
        if (v instanceof Map) {
            Map<String, Object> o = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) o.put(e.getKey(), cut(e.getValue(), p));
            return o;
        }
        if (v instanceof List) {
            List<Object> o = new ArrayList<>();
            for (Object x : (List<Object>) v) o.add(cut(x, p));
            return o;
        }
        return v;
    }

    static boolean same(Object want, Object got, String prefix) {
        if (want instanceof Map && M(want).containsKey("$throws")) {
            if (!(got instanceof Map) || !M(got).containsKey("$throws")) return false;
            Object code = M(want).get("code");
            return code == null || code.equals(M(got).get("code"));
        }
        if (prefix != null) { want = cut(want, prefix); got = cut(got, prefix); }
        return Json.canonicalize(want).equals(Json.canonicalize(got));
    }

    interface Fn { Object apply(List<?> a); }

    static void check(String fn, Fn f) throws Exception { check(fn, f, c -> false); }

    interface Skip { boolean test(Map<String, Object> c); }

    static void check(String fn, Fn f, Skip skip) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(fn)) {
            if (skip.test(c)) continue;
            List<?> a = (List<?>) c.get("args");
            Object got;
            try { got = f.apply(a); } catch (RuntimeException e) { got = thrown(e); }
            Object want = c.get("out");
            if (!same(want, got, (String) c.get("textPrefix")))
                bad.add(c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + Json.canonicalize(got));
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 60))));
    }

    static boolean signed(Object o) { return !Boolean.FALSE.equals(o); }

    @Test void evolutionRecordError() throws Exception { check("evolutionRecordError", a -> ActionRegistry.evolutionRecordError(a.get(0), signed(a.get(1)))); }
    @Test void evolutionDiffDigest() throws Exception { check("evolutionDiffDigest", a -> ActionRegistry.evolutionDiffDigest(M(a.get(0)))); }
    @Test void verifyRegistrySig() throws Exception { check("verifyRegistrySig", a -> ActionRegistry.verifyRegistrySig((String) a.get(0), a.get(1), M(a.get(2)), a.get(3))); }
    @Test void verifyEvolutionRecord() throws Exception { check("verifyEvolutionRecord", a -> ActionRegistry.verifyEvolutionRecord(a.get(0), a.get(1))); }
    @Test void reapprovalValid() throws Exception { check("reapprovalValid", a -> ActionRegistry.reapprovalValid(a.get(0), a.get(1), a.get(2), a.get(3), a.get(4))); }
    @Test void actionPinError() throws Exception { check("actionPinError", a -> ActionRegistry.actionPinError(a.get(0))); }

    /** The native decision carries exactly the reference's members (ok, via | code, escalate, reason, needs_reapproval). */
    @Test void decidePin() throws Exception { check("decidePin", a -> ActionRegistry.decidePin(M(a.get(0)))); }

    @Test void compareVersions() throws Exception {
        check("compareVersions", a -> IntentJs.ofLong(Integer.signum(ActionRegistry.compareVersions((String) a.get(0), (String) a.get(1)))));
    }

    @Test void packShapeError() throws Exception { check("packShapeError", a -> ActionRegistry.packShapeError(a.get(0), signed(a.get(1)))); }

    @Test void packDefs() throws Exception {
        check("packDefs", a -> {
            List<Object> verbs = new ArrayList<>();
            for (Object d : ActionRegistry.packDefs(M(a.get(0)), mapOrNull(a.get(1)))) verbs.add(M(d).get("verb"));
            return verbs;
        });
    }

    @Test void verifyPack() throws Exception {
        check("verifyPack", a -> {
            Map<String, Object> r = ActionRegistry.verifyPack(a.get(0), a.get(1), mapOrNull(a.get(2)));
            if (!Boolean.TRUE.equals(r.get("ok"))) return r;
            List<Object> verbs = new ArrayList<>();
            for (Object d : (List<?>) r.get("defs")) verbs.add(M(d).get("verb"));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", Boolean.TRUE);
            m.put("digest", r.get("digest"));
            m.put("verbs", verbs);
            return m;
        });
    }

    /** Native trackers do not keep content (keepContent: false): ok / status / code compare, the reason only for bad_pack. */
    @Test void packTracker() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("packTracker")) {
            List<?> steps = (List<?>) ((List<?>) c.get("args")).get(0);
            List<?> want = (List<?>) c.get("out");
            String got;
            try {
                // the oracle's tracker pins ALLKEYS (reg-1 ed25519, reg-ml, reg-hy): the keys every honest pack in it verifies under
                ActionRegistry.PackTracker t = new ActionRegistry.PackTracker(trackerKeys());
                List<Object> out = new ArrayList<>();
                for (Object so : steps) {
                    List<?> st = (List<?>) so;
                    Map<String, Object> r = t.accept(st.get(0), mapOrNull(st.size() > 1 ? st.get(1) : null));
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("ok", r.get("ok"));
                    if (Boolean.TRUE.equals(r.get("ok"))) m.put("status", r.get("status"));
                    else { m.put("code", r.get("code")); if ("bad_pack".equals(r.get("code"))) m.put("reason", r.get("reason")); }
                    out.add(m);
                }
                got = Json.canonicalize(out);
            } catch (RuntimeException e) { got = "THROWS " + e; }
            List<Object> w = new ArrayList<>();
            for (Object o : want) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", M(o).get("ok"));
                if (Boolean.TRUE.equals(M(o).get("ok"))) m.put("status", M(o).get("status"));
                else { m.put("code", M(o).get("code")); if ("bad_pack".equals(M(o).get("code"))) m.put("reason", M(o).get("reason")); }
                w.add(m);
            }
            String ws = Json.canonicalize(w);
            if (!ws.equals(got)) bad.add(c.get("name") + "\n  want: " + ws + "\n  got:  " + got);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }

    /** ALLKEYS of the oracle, read back from its own verifyPack cases (the honest `p1` / `ml` / `hybrid` packs verify under it). */
    static Object trackerKeys() throws Exception {
        for (Map<String, Object> c : of("verifyPack")) if ("verifyPack/hybrid".equals(c.get("name"))) return ((List<?>) c.get("args")).get(1);
        throw new AssertionError("verifyPack/hybrid case missing (it carries the oracle's ALLKEYS)");
    }

    /**
     * Typed port: a grant that is not an object or a context that is not an array cannot reach the Java API; the reference denies it.
     */
    @Test void rule22Decide() throws Exception {
        check("rule22Decide", a -> {
            if (!(a.get(0) instanceof Map) || !(a.get(1) instanceof String) || !(a.get(2) instanceof Map) || !(a.get(3) instanceof List)) return "deny";
            @SuppressWarnings("unchecked") List<Object> ctx = (List<Object>) a.get(3);
            return ActionRegistry.rule22Decide(M(a.get(0)), (String) a.get(1), M(a.get(2)), ctx);
        });
    }

    @Test void verifyPackProof() throws Exception {
        check("verifyPackProof", a -> {
            if (!(a.get(2) instanceof String)) throw new IllegalArgumentException("typed port: digest is a string");
            return ActionRegistry.verifyPackProof(a.get(0), a.get(1), (String) a.get(2));
        });
    }
}
