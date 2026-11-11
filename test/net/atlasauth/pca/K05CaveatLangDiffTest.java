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
import java.util.function.Function;
import java.util.zip.GZIPInputStream;
import net.atlasauth.pca.servlet.PcaCore;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link CaveatLang} (the caveat language v2) and the K1 request headers ({@link PcaCore#presentedK1}):
 * a differential test against the TS reference (oracle tools/pca-audit/k05-oracles/caveatlang-oracle.mts ->
 * test-data/k05-caveatlang.json.gz). Validators compare the exact reason (or null); verdicts / results compare canonical JSON.
 *
 * <p>Not ported: {@code dischargeRequests} (the client-side discharge request builder has no Java twin; a verifier never
 * builds requests).
 */
public class K05CaveatLangDiffTest {

    static List<Map<String, Object>> cases() throws Exception {
        return K05Oracle.all("k05-caveatlang");
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static Object arg(Map<String, Object> c, int i) { List<?> a = (List<?>) c.get("args"); return i < a.size() ? a.get(i) : null; }
    static Map<String, Object> map(Object o) { return Ledger.map(o); }
    static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }

    interface Run { String apply(Map<String, Object> c) throws Exception; }

    /** Every case of {@code fn}: {@code want} renders the oracle output, {@code got} the Java result, compared exactly. */
    static void check(String fn, Function<Object, String> want, Run got) throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of(fn)) {
            String w = want.apply(c.get("out")), g;
            try { g = got.apply(c); } catch (Throwable t) { g = "THROWS " + t; }
            if (!w.equals(g)) bad.add(c.get("name") + "\n  want: " + w + "\n  got:  " + g);
            ran++;
        }
        assertTrue(ran > 0);
        assertTrue(bad.isEmpty(), bad.size() + "/" + ran + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(60, bad.size()))));
    }
    static void validator(String fn, Function<Object, String> v) throws Exception {
        check(fn, o -> String.valueOf(o), c -> String.valueOf(v.apply(arg(c, 0))));
    }

    @Test void spiffeIdError() throws Exception { validator("spiffeIdError", CaveatLang::spiffeIdError); }
    @Test void needsDischargeError() throws Exception { validator("needsDischargeError", CaveatLang::needsDischargeError); }
    @Test void dischargeShapeError() throws Exception { validator("dischargeShapeError", CaveatLang::dischargeShapeError); }
    @Test void narrowShapeError() throws Exception { validator("narrowShapeError", CaveatLang::narrowShapeError); }
    @Test void maxUsesError() throws Exception { validator("maxUsesError", CaveatLang::maxUsesError); }
    @Test void spiffeBoundError() throws Exception { validator("spiffeBoundError", CaveatLang::spiffeBoundError); }
    @Test void deriveError() throws Exception { validator("deriveError", CaveatLang::deriveError); }

    @Test void maxUsesSlotKey() throws Exception {
        check("maxUsesSlotKey", o -> (String) o, c -> CaveatLang.maxUsesSlotKey((String) arg(c, 0), (String) arg(c, 1), (int) IntentJs.lng(arg(c, 2))));
    }

    @Test void evaluateDerive() throws Exception {
        check("evaluateDerive", o -> String.valueOf(o), c -> {
            Map<String, Object> inp = map(arg(c, 1));
            // the typed claims parameter holds only objects; a non-object holder reads as absent, as a JS property read on it does
            Map<String, Map<String, Object>> claims = new LinkedHashMap<>();
            Map<String, Object> cl = map(inp.get("claims"));
            if (cl != null) for (Map.Entry<String, Object> e : cl.entrySet()) if (map(e.getValue()) != null) claims.put(e.getKey(), map(e.getValue()));
            return String.valueOf(CaveatLang.evaluateDerive(map(arg(c, 0)), IntentJs.lng(inp.get("now")), inp.get("action"), inp.get("history"), claims));
        });
    }

    @Test void verifyDischarge() throws Exception {
        check("verifyDischarge", K05CaveatLangDiffTest::canon, c -> {
            CaveatLang.DischargeVerdict v = CaveatLang.verifyDischarge(arg(c, 0), arg(c, 1), map(arg(c, 2)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", v.ok);
            if (v.ok) { m.put("digest", v.digest); m.put("claims", v.claims); } else m.put("reason", v.reason);
            return canon(m);
        });
    }

    @Test void verifyNarrow() throws Exception {
        check("verifyNarrow", K05CaveatLangDiffTest::canon, c -> {
            CaveatLang.NarrowVerdict v = CaveatLang.verifyNarrow(arg(c, 0), arg(c, 1), arg(c, 2), map(arg(c, 3)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", v.ok);
            if (v.ok) m.put("caveats", v.caveats); else m.put("reason", v.reason);
            return canon(m);
        });
    }

    static List<Object> bound(List<CaveatLang.BoundCaveat> bs) {
        if (bs == null) return null;
        List<Object> out = new ArrayList<>();
        for (CaveatLang.BoundCaveat b : bs) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("caveat", b.caveat);
            m.put("hop", IntentJs.ofLong(b.hop));
            m.put("cap_hash", b.capHash);
            out.add(m);
        }
        return out;
    }

    @Test void boundCaveats() throws Exception {
        check("boundCaveats", K05CaveatLangDiffTest::canon, c -> canon(bound(CaveatLang.boundCaveats(arg(c, 0), arg(c, 1)))));
    }

    @Test void evaluateK1() throws Exception {
        check("evaluateK1", K05CaveatLangDiffTest::canon, c -> {
            CaveatLang.K1Result r = CaveatLang.evaluateK1(arg(c, 0), arg(c, 1), map(arg(c, 2)), map(arg(c, 3)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", r.ok);
            m.put("failed", r.failed);
            m.put("reasons", r.reasons);
            m.put("plain", r.plain);
            m.put("bound", bound(r.bound));
            return canon(m);
        });
    }

    @Test void evaluateCaveatsK1() throws Exception {
        check("evaluateCaveatsK1", K05CaveatLangDiffTest::canon, c -> {
            Caveats.Result r = CaveatLang.evaluateCaveatsK1(arg(c, 0), arg(c, 1), map(arg(c, 2)), map(arg(c, 3)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", r.ok);
            m.put("failed", r.failed);
            return canon(m);
        });
    }

    @Test void presentedK1() throws Exception {
        check("presentedK1", K05CaveatLangDiffTest::canon, c -> {
            Map<String, String> h = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : map(arg(c, 0)).entrySet()) h.put(e.getKey(), (String) e.getValue());
            PcaCore.PresentedK1 p = PcaCore.presentedK1(h);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", p.ok);
            if (p.ok) m.put("value", p.value);
            return canon(m);
        });
    }
}
