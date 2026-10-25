package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills for {@link IntentV2}: a differential test against the TS reference {@code decideIntentV2}
 * (oracle tools/pca-audit/java-mutate/k042-intentv2-oracle.mts -> test-data/k042-intentv2-cases.json.gz). Every case
 * asserts the EXACT check list (name, ok, reason in order) and the canonical env. A thrown-internal-error reason is
 * compared up to its language-neutral prefix "&lt;check&gt; error (fail closed): ".
 */
public class K042IntentV2DiffTest {
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-intentv2-cases.json.gz")))) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            in.transferTo(b);
            Map<String, Object> doc = (Map<String, Object>) Json.parseLenient(b.toString(StandardCharsets.UTF_8));
            return (List<Map<String, Object>>) (List<?>) doc.get("cases");
        }
    }

    /** The actual result rendered like the oracle (one line per check, then the env). */
    static String render(IntentV2.Decision d, List<?> want) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.checks.size(); i++) {
            IntentV2.Check c = d.checks.get(i);
            String r = c.reason;
            Object w = i < want.size() ? want.get(i) : null;
            if (r != null && w instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) w).get("prefix"))) {
                int k = r.indexOf("(fail closed): ");
                if (k >= 0) r = r.substring(0, k + "(fail closed): ".length());
            }
            sb.append(c.name).append('|').append(c.ok).append('|').append(r).append('\n');
        }
        sb.append("env ").append(Json.canonicalize(d.env));
        return sb.toString();
    }
    static String renderWant(Map<String, Object> cs) {
        StringBuilder sb = new StringBuilder();
        for (Object o : (List<?>) cs.get("checks")) {
            Map<?, ?> c = (Map<?, ?>) o;
            sb.append(c.get("name")).append('|').append(c.get("ok")).append('|').append(c.get("reason")).append('\n');
        }
        sb.append("env ").append(cs.get("env"));
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    static IntentV2.Decision run(Map<String, Object> cs) {
        Map<String, Object> p = (Map<String, Object>) Json.parseLenient((String) cs.get("p"));
        Map<String, Object> grant = (Map<String, Object>) Json.parseLenient((String) cs.get("grant"));
        IntentV2.Context ctx = cs.containsKey("ctx") ? IntentV2.Context.fromJsonText((String) cs.get("ctx")) : null;
        if (cs.containsKey("wp")) ctx = ctx.withParams(Json.parseLenient((String) cs.get("wp")));
        return IntentV2.decide(p, grant, ctx, Json.asLong(cs.get("now")));
    }
    @SuppressWarnings("unchecked")
    static boolean active(Map<String, Object> cs) {
        Map<String, Object> p = (Map<String, Object>) Json.parseLenient((String) cs.get("p"));
        IntentV2.Context ctx = cs.containsKey("ctx") ? IntentV2.Context.fromJsonText((String) cs.get("ctx")) : null;
        if (cs.containsKey("wp")) ctx = ctx.withParams(Json.parseLenient((String) cs.get("wp")));
        return IntentV2.active(p, ctx);
    }

    static List<Map<String, Object>> ALL;
    static synchronized List<Map<String, Object>> all() throws Exception { if (ALL == null) ALL = cases(); return ALL; }

    /** Every case whose name starts with one of {@code prefixes} matches the reference (checks, env, active). */
    static void group(String... prefixes) throws Exception {
        List<String> bad = new ArrayList<>();
        int n = 0;
        for (Map<String, Object> c : all()) {
            String name = (String) c.get("name");
            boolean in = false;
            for (String pf : prefixes) if (name.startsWith(pf)) in = true;
            if (!in) continue;
            n++;
            String want = renderWant(c) + "\nactive " + c.get("active");
            String got;
            try { got = render(run(c), (List<?>) c.get("checks")) + "\nactive " + active(c); } catch (Throwable t) { got = "THROWS " + t; }
            if (!want.equals(got)) bad.add(name + "\n  want: " + want.replace("\n", "\n        ") + "\n  got:  " + got.replace("\n", "\n        "));
        }
        assertTrue(n > 0, "no case for " + String.join(",", prefixes));
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }

    static final String[] GROUPS = {"vec/", "ctx-absent/", "ctx-not-object/", "ctx-empty/", "ctx/", "clock/", "schema/", "root/", "session/", "chain2/", "chain1/",
        "rev/", "acc/", "acc-un/", "acc-verb/", "acc-key/", "seq/", "layers/", "map/", "wb16/", "wb17/", "wb18/", "wb-combo/", "json/", "with-params/"};

    @Test void everyCaseIsInAGroup() throws Exception {
        assertTrue(all().size() > 800, "oracle cases: " + all().size());
        for (Map<String, Object> c : all()) {
            boolean in = false;
            for (String g : GROUPS) if (((String) c.get("name")).startsWith(g)) in = true;
            assertTrue(in, "ungrouped case " + c.get("name"));
        }
    }
    @Test void vectors() throws Exception { group("vec/"); }
    @Test void contextAbsentOrNotAnObject() throws Exception { group("ctx-absent/", "ctx-not-object/", "ctx-empty/"); }
    @Test void contextMembers() throws Exception { group("ctx/"); }
    @Test void clock() throws Exception { group("clock/"); }
    @Test void schema() throws Exception { group("schema/"); }
    @Test void sessionRootAndBinding() throws Exception { group("root/", "session/"); }
    @Test void deltaChain() throws Exception { group("chain2/", "chain1/"); }
    @Test void revocation() throws Exception { group("rev/"); }
    @Test void accumulators() throws Exception { group("acc/", "acc-un/", "acc-verb/", "acc-key/"); }
    @Test void sequencedReceipts() throws Exception { group("seq/"); }
    @Test void layers() throws Exception { group("layers/"); }
    @Test void map() throws Exception { group("map/"); }
    @Test void worldFacts() throws Exception { group("wb16/"); }
    @Test void provenance() throws Exception { group("wb17/"); }
    @Test void classes() throws Exception { group("wb18/", "wb-combo/"); }
    @Test void jsonNumbersAndWithParams() throws Exception { group("json/", "with-params/"); }
}
