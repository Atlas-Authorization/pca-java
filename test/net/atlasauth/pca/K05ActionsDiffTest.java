package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link Actions}: a differential test against the TS reference action kit (shared oracle
 * test-data/k05-actions.json.gz, 65k cases: validateDef and its sub-checks, id patterns, the strict JSON profile, profiles,
 * trait registries, closure / floor / floorDecision, normalize, defDigest, worstReversibility, impliedFromFacts, declProfile,
 * hintTraits, effective, reviewer pins, the signed confirmation, factsDigest, rule 22, the pack Merkle root and proof).
 *
 * <p>Comparison: every result as canonical JSON; a reference throw with a code must be an {@link Actions.ActionKitError} with that
 * code, without one any refusal; {@code cmp: "code"} (a message carrying the reference's own exception text) compares the
 * {@code <code>: } prefix only.
 */
public class K05ActionsDiffTest {
    // the oracle is 118 MB of JSON, one case per line: parse only the lines of the fn under test, and let the GC drop a list
    static final Map<String, SoftReference<List<Map<String, Object>>>> CACHE = new HashMap<>();

    @SuppressWarnings("unchecked")
    static synchronized List<Map<String, Object>> cases(String fn) throws Exception {
        SoftReference<List<Map<String, Object>>> r = CACHE.get(fn);
        List<Map<String, Object>> out = r == null ? null : r.get();
        if (out != null) return out;
        out = new ArrayList<>();
        String head = "{\"fn\":" + Json.canonicalize(fn) + ",";
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new GZIPInputStream(Files.newInputStream(Path.of("test-data/k05-actions.json.gz"))), StandardCharsets.UTF_8))) {
            for (String line; (line = in.readLine()) != null; ) {
                if (!line.startsWith(head)) continue;
                if (line.endsWith(",")) line = line.substring(0, line.length() - 1);
                out.add((Map<String, Object>) IntentJs.normalize(Json.parseLenient(line)));
            }
        }
        CACHE.put(fn, new SoftReference<>(out));
        return out;
    }

    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> A(Object o) { return (List<Object>) o; }
    @SuppressWarnings("unchecked") static List<String> S(Object o) { return (List<String>) o; }

    interface Fn { Object apply(List<Object> a) throws Exception; }

    static Object json(Object got) {
        if (got instanceof Actions.Profile) return ((Actions.Profile) got).toMap();
        if (got instanceof byte[]) { Map<String, Object> m = new LinkedHashMap<>(); m.put("$bytes", Pca.b64((byte[]) got)); return m; }
        return got;
    }

    static void run(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        int n = 0;
        for (Map<String, Object> c : cases(fn)) {
            n++;
            Object want = c.get("out");
            String wt = Json.canonicalize(want), gt;
            Object thrown = null, got = null;
            try { got = json(f.apply(A(c.get("args")))); } catch (Throwable t) { thrown = t; }
            if (want instanceof Map && M(want).containsKey("$throws")) {
                Object code = M(want).get("code");
                boolean ok = thrown != null && (code == null || (thrown instanceof Actions.ActionKitError && code.equals(((Actions.ActionKitError) thrown).code)));
                if (!ok) bad.add(c.get("name") + "\n  want: throw " + wt + "\n  got:  " + (thrown != null ? "THROWS " + thrown : Json.canonicalize(IntentJs.normalize(got))));
                continue;
            }
            gt = thrown != null ? "THROWS " + thrown : Json.canonicalize(IntentJs.normalize(got));
            boolean same;
            if ("code".equals(c.get("cmp")) && want instanceof String && got instanceof String && ((String) want).contains(": ")) {
                String w = (String) want;
                same = ((String) got).startsWith(w.substring(0, w.indexOf(": ") + 2));
            } else same = wt.equals(gt);
            if (!same) bad.add(c.get("name") + "\n  want: " + wt + "\n  got:  " + gt);
        }
        assertTrue(n > 0, "no oracle cases for " + fn);
        assertTrue(bad.isEmpty(), fn + ": " + bad.size() + " of " + n + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(60, bad.size()))));
    }

    static Actions.Registry reg(Object custom) { return custom == null ? Actions.CORE_REGISTRY : Actions.extendRegistry(Actions.CORE_REGISTRY, A(custom)); }
    static Map<String, Object> pins(Object p) { return p == null ? null : M(p); }

    // ---- validateDef and its sub-checks ----
    @Test void validateDef() throws Exception { run("validateDef", a -> Actions.validateDef(a.get(0))); }
    @Test void isRole() throws Exception { run("isRole", a -> Actions.isRole(a.get(0))); }
    @Test void isFormat() throws Exception { run("isFormat", a -> Actions.isFormat(a.get(0))); }
    @Test void isContextKey() throws Exception { run("isContextKey", a -> Actions.isContextKey(a.get(0))); }
    @Test void paramNameError() throws Exception { run("paramNameError", a -> Actions.paramNameError((String) a.get(0))); }
    @Test void jsonProfileError() throws Exception { run("jsonProfileError", a -> Actions.jsonProfileError(a.get(0), 0)); }
    @Test void idPatternError() throws Exception { run("idPatternError", a -> Actions.idPatternError(a.get(0))); }

    // ---- profiles, registries, closure, floors, floorDecision ----
    @Test void profileError() throws Exception { run("profileError", a -> Actions.profileError(a.get(0))); }
    @Test void registryError() throws Exception { run("registryError", a -> Actions.registryError(a.get(0), Boolean.TRUE.equals(a.get(1)))); }
    @Test void closure() throws Exception { run("closure", a -> Actions.closure(reg(a.get(0)), A(a.get(1)))); }
    @Test void floorOf() throws Exception { run("floorOf", a -> Actions.floorOf(reg(a.get(0)), A(a.get(1)))); }
    @Test void topTraits() throws Exception { run("topTraits", a -> Actions.topTraits(reg(a.get(0)))); }
    @Test void traitsDigest() throws Exception { run("traitsDigest", a -> Actions.traitsDigest(reg(a.get(0)))); }
    @Test void tablesDigest() throws Exception { run("tablesDigest", a -> Actions.tablesDigest()); }
    @Test void floorDecision() throws Exception { run("floorDecision", a -> Actions.floorDecision(M(a.get(0)), M(a.get(1)), Actions.Profile.fromMap(a.get(2)))); }

    // ---- worstReversibility / sensitivityFloor / impliedFromFacts ----
    @Test void worstReversibility() throws Exception { run("worstReversibility", a -> Actions.worstReversibility(a.get(0), M(a.get(1)))); }
    @Test void sensitivityFloor() throws Exception { run("sensitivityFloor", a -> Actions.sensitivityFloor(M(a.get(0)))); }
    @Test @SuppressWarnings("unchecked") void impliedFromFacts() throws Exception {
        run("impliedFromFacts", a -> {
            Map<String, Object> f = M(a.get(0));
            return Actions.impliedFromFacts(A(f.get("effects")), (List<Map<String, Object>>) (Object) A(f.get("params")), (String) f.get("scope"), (String) f.get("worstRev"));
        });
    }

    // ---- downstream of an accepted def ----
    @Test void normalize() throws Exception { run("normalize", a -> Actions.normalize(M(a.get(0)))); }
    @Test void defDigest() throws Exception { run("defDigest", a -> Actions.defDigest(M(a.get(0)))); }
    @Test void declProfile() throws Exception { run("declProfile", a -> Actions.declProfile(M(a.get(0)))); }
    @Test void hintTraits() throws Exception { run("hintTraits", a -> Actions.hintTraits(M(a.get(0)))); }
    @Test void effective() throws Exception { run("effective", a -> Actions.effective(M(a.get(0)), Actions.CORE_REGISTRY, pins(a.get(1)))); }

    // ---- reviewer pins, the review message, the signed confirmation ----
    @Test void reviewerPinsError() throws Exception { run("reviewerPinsError", a -> Actions.reviewerPinsError(a.get(0))); }
    @Test void reviewMessage() throws Exception { run("reviewMessage", a -> Actions.reviewMessage(M(a.get(0)))); }
    @Test void isConfirmed() throws Exception { run("isConfirmed", a -> Actions.isConfirmed(M(a.get(0)), Actions.CORE_REGISTRY, pins(a.get(1)))); }

    // ---- rule 22 and packs ----
    @Test void factsDigest() throws Exception { run("factsDigest", a -> Actions.factsDigest(M(a.get(0)))); }
    @Test void schemaVerbFloorError() throws Exception { run("schemaVerbFloorError", a -> Actions.verbFloorError(a.get(0), Actions.CORE_REGISTRY, pins(a.get(1)))); }
    @Test void schemaFloorError() throws Exception { run("schemaFloorError", a -> Actions.schemaFloorError(M(a.get(0)), pins(a.get(1)))); }
    @Test void packRoot() throws Exception { run("packRoot", a -> Actions.packRoot(S(a.get(0)))); }
    @Test void packProof() throws Exception { run("packProof", a -> Actions.packProof(S(a.get(0)), (String) a.get(1))); }

    // ---- the reference fixes of d36d91ac7, one each ----
    @Test void floorDecisionDeniesANonIntegerTier() {
        Map<String, Object> call = new LinkedHashMap<>(); call.put("context", new ArrayList<>());
        Object[][] tiers = {{IntentJs.ofLong(3), IntentJs.ofLong(3)}, {null, IntentJs.ofLong(2)}, {"3", IntentJs.ofLong(2)}, {new Json.Num("2.5"), IntentJs.ofLong(2)},
            {IntentJs.ofLong(3), new Json.Num("-1")}, {new Json.Num("-0"), IntentJs.ofLong(0)}, {IntentJs.ofLong(3), true}};
        for (int i = 0; i < tiers.length; i++) {
            Map<String, Object> g = new LinkedHashMap<>(); g.put("caveats", new ArrayList<>());
            if (tiers[i][0] != null) g.put("max_esc", tiers[i][0]);   // null = missing
            g.put("preauth_esc", tiers[i][1]);
            assertEquals(i == 0 ? "allow" : "deny", Actions.floorDecision(g, call, Actions.Profile.BOTTOM), "tiers #" + i);
        }
    }

    @Test void aReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed() throws Exception {
        List<Object> a = null;
        for (Map<String, Object> c : cases("isConfirmed")) if ("isConfirmed/read good".equals(c.get("name"))) a = A(c.get("args"));
        assertTrue(Actions.isConfirmed(M(a.get(0)), Actions.CORE_REGISTRY, pins(a.get(1))), "control");
        for (Object f : new Object[] {"missing", null, ""}) {
            Map<String, Object> d = M(IntentJs.normalize(Json.parseLenient(Json.canonicalize(a.get(0)))));
            Map<String, Object> att = M(M(d.get("review")).get("attestation"));
            if ("missing".equals(f)) att.remove("final_traits"); else att.put("final_traits", f);
            assertFalse(Actions.isConfirmed(d, Actions.CORE_REGISTRY, pins(a.get(1))), "final_traits " + f);
        }
    }

    @Test void aNullMaxItemsImpliesBulk() {
        for (Object mi : new Object[] {"missing", null, IntentJs.ofLong(10)}) {
            Map<String, Object> p = new LinkedHashMap<>(); p.put("type", "array");
            if (!"missing".equals(mi)) p.put("max_items", mi);
            List<String> t = Actions.impliedFromFacts(List.of("create"), List.of(p), null, "reversible");
            assertEquals(!(mi instanceof Json.Num), t.contains("pca.bulk"), "max_items " + mi);
        }
    }
}
