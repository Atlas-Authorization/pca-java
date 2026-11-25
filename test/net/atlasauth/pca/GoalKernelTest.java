package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import net.atlasauth.pca.goal.GoalCodec;
import net.atlasauth.pca.goal.GoalCompiler;
import net.atlasauth.pca.goal.GoalKernel;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Replay of the proved goal kernel (GoalKernel over the Dafny translation in src/dafny-goal). (1) the kernel tape corpus
 * (the goal-kernel corpus in test-data, from the reference's extracted JavaScript kernel on the goal conformance vectors): every op's
 * output tape must be identical; (2) the typed front door on the goal conformance vectors when the layout has them.
 * Without the translation the kernel tests are skipped, unless PCA_GOAL_KERNEL_REQUIRE=1 (CI after extraction), where they fail.
 */
class GoalKernelTest {
    private static final String M = "ref-goal-kernel";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static void needKernel() {
        if (GoalKernel.available()) return;
        if ("1".equals(System.getenv("PCA_GOAL_KERNEL_REQUIRE"))) fail("PCA_GOAL_KERNEL_REQUIRE=1 but the extracted goal kernel is missing");
        Assumptions.assumeTrue(false, "extracted goal kernel not present (src/dafny-goal)");
    }

    private static List<Object> tape(String s) {
        List<Object> t = GoalKernel.tapeFromText(s);
        assertEquals(s, GoalKernel.tapeToText(t), "tape text round trip");
        return t;
    }

    @Test void tapeText() throws Exception {
        List<Map<String, Object>> cases = OracleCases.of(M, "kernel");
        assertTrue(cases.size() > 150);
        for (Map<String, Object> c : cases) { tape((String) l(c.get("args")).get(0)); tape((String) l(c.get("args")).get(1)); }
        assertEquals("k5 i-3 s s68.1f600", GoalKernel.tapeToText(GoalKernel.tapeFromText("k5 i-3 s s68.1f600")));
        assertEquals("h😀", l(GoalKernel.tapeFromText("s68.1f600").get(0)).get(1));
    }

    @Test void kernelTapes() throws Exception {
        needKernel();
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, "kernel")) {
            List<Object> args = l(c.get("args"));
            Map<String, Object> want = m(c.get("out"));
            List<Object> g = tape((String) args.get(0)), o = tape((String) args.get(1));
            for (String op : new String[] {"typecheck", "compile", "render"}) {
                String got = GoalKernel.tapeToText(GoalKernel.call(op, g, o, null, null));
                if (!got.equals(want.get(op))) bad.add(c.get("name") + " " + op);
            }
            List<Object> probes = l(args.get(2)), outs = l(want.get("probes"));
            assertEquals(probes.size(), outs.size());
            for (int i = 0; i < probes.size(); i++) {
                List<Object> p = l(probes.get(i)), w = l(outs.get(i));
                List<Object> a = tape((String) p.get(0)), h = tape((String) p.get(1));
                if (!GoalKernel.tapeToText(GoalKernel.call("decideg", g, o, a, h)).equals(w.get(0))) bad.add(c.get("name") + "#" + i + " decideg");
                if (!GoalKernel.tapeToText(GoalKernel.call("decidep", g, o, a, h)).equals(w.get(1))) bad.add(c.get("name") + "#" + i + " decidep");
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent tape(s): " + bad.subList(0, Math.min(25, bad.size())));
    }

    /** The typed front door's renderTape is the kernel's: same tape as the corpus render of every case's goal. */
    @Test void compilerRenderTapeReplaysCorpus() throws Exception {
        needKernel();
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, "kernel")) {
            List<Object> g = tape((String) l(c.get("args")).get(0));
            Map<String, Object> goal;
            try { goal = GoalCodec.decodeGoal(g); } catch (RuntimeException e) { continue; }  // a malformed goal tape has no typed goal
            if (!GoalKernel.tapeToText(GoalCodec.encodeGoal(goal)).equals(GoalKernel.tapeToText(g))) continue;  // not canonical: the typed goal cannot reproduce the input tape
            if (!GoalKernel.tapeToText(GoalCompiler.renderTape(goal)).equals(((String) m(c.get("out")).get("render")).replaceFirst("^i0 ?", ""))) bad.add((String) c.get("name"));  // the corpus render carries the kernel's status token (i0), renderTape returns the card only
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent render(s): " + bad.subList(0, Math.min(25, bad.size())));
    }

    /** A string token of a million characters crosses the bridge and the proved code without a stack overflow. */
    @Test void hugeStringDoesNotOverflow() {
        needKernel();
        List<Object> big = new ArrayList<>();
        big.add(new ArrayList<Object>(List.of("s", "a".repeat(1 << 20))));
        for (String op : new String[] {"typecheck", "compile", "render"}) {
            List<Object> out = GoalKernel.call(op, big, new ArrayList<>(), null, null);
            assertEquals("i", l(out.get(0)).get(0), op);
        }
    }

    @Test void malformedIsRefused() {
        needKernel();
        List<Object> bad = GoalKernel.tapeFromText("i7");
        assertEquals("i9", GoalKernel.tapeToText(GoalKernel.call("typecheck", bad, new ArrayList<>(), null, null)));
        assertThrows(IllegalArgumentException.class, () -> GoalKernel.call("nope", bad, bad, null, null));
        assertThrows(RuntimeException.class, () -> GoalKernel.call("typecheck", GoalKernel.tapeFromText("k9007199254740992"), bad, null, null));
    }

    @Test void typedFrontDoorOnConformanceVectors() throws Exception {
        needKernel();
        Path dir;
        try { dir = GoalRunner.locate(); } catch (RuntimeException e) { Assumptions.assumeTrue(false, "goal conformance vectors not in this layout"); return; }
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) { files = s.filter(p -> p.toString().endsWith(".json") && !p.getFileName().toString().equals("index.json")).sorted().toList(); }
        List<String> bad = new ArrayList<>();
        for (Path f : files) {
            Map<String, Object> v = m(Json.parseLenient(Files.readString(f, StandardCharsets.UTF_8)));
            if ("fn".equals(v.get("kind"))) continue;
            Map<String, Object> goal = m(v.get("goal")), ont = m(v.get("ontology")), comp = m(v.get("compile"));
            String id = (String) v.get("id");
            if (!GoalKernel.typecheck(goal, ont).equals(comp.get("reasons"))) bad.add(id + ": reasons");
            Map<String, Object> r = GoalKernel.compileGoal(goal, ont);
            String pd = Boolean.TRUE.equals(r.get("ok")) ? GoalCompiler.policyDigest(m(r.get("policy"))) : null;
            if (!Objects.equals(pd, v.get("policy_digest"))) bad.add(id + ": policy_digest");
            if (!GoalKernel.tapeToText(GoalKernel.renderTape(goal)).equals(GoalKernel.tapeToText(GoalCodec.encodeGoal(GoalCodec.decodeGoal(GoalKernel.renderTape(goal)))))) bad.add(id + ": render");
            if (!Boolean.TRUE.equals(comp.get("ok"))) continue;
            List<Object> probes = l(v.get("probes"));
            for (int i = 0; i < probes.size(); i++) {
                Map<String, Object> p = m(probes.get(i)), exp = m(p.get("expect"));
                Map<String, Object> d = GoalKernel.decidePolicy(goal, ont, m(p.get("action")), m(p.get("history")));
                String dec = Boolean.TRUE.equals(d.get("ok")) ? (String) d.get("decision") : "deny";
                Object wit = Boolean.TRUE.equals(d.get("ok")) ? d.get("witness") : null;
                if (!dec.equals(exp.get("decision")) || !G0.same(wit, exp.get("witness"))) bad.add(id + "#" + i + ": " + dec + " " + wit);
                if (Boolean.TRUE.equals(d.get("ok"))) {
                    // the policy is the lowering of Strip(goal) (grants that depend on a hole dropped, holes emptied): it decides exactly as the stripped goal,
                    // and is never more permissive than the goal itself; a goal without holes strips to itself
                    int pr = rank(dec);
                    if (pr != rank(GoalKernel.decideGoal(strip(goal), ont, m(p.get("action")), m(p.get("history"))))) bad.add(id + "#" + i + ": decidePolicy != decideGoal(strip)");
                    if (pr > rank(GoalKernel.decideGoal(goal, ont, m(p.get("action")), m(p.get("history"))))) bad.add(id + "#" + i + ": decidePolicy more permissive than decideGoal");
                }
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergence(s): " + bad.subList(0, Math.min(25, bad.size())));
    }

    private static int rank(String d) { return "allow".equals(d) ? 2 : "escalate".equals(d) ? 1 : 0; }

    /** StripGrants: drop every grant whose gid a hole depends on (a global hole drops all), holes := []. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> strip(Map<String, Object> goal) {
        List<Object> holes = l(goal.get("holes"));
        Map<String, Object> out = new java.util.LinkedHashMap<>(goal);
        List<Object> kept = new java.util.ArrayList<>();
        for (Object g : l(goal.get("grants"))) {
            boolean dep = false;
            for (Object h : holes) { Map<String, Object> hm = m(h); if (Boolean.TRUE.equals(hm.get("global")) || l(hm.get("affects")).contains(m(g).get("gid"))) dep = true; }
            if (!dep) kept.add(g);
        }
        out.put("grants", kept);
        out.put("holes", new java.util.ArrayList<Object>());
        return out;
    }

    @Test void provedKernelPlugsIntoReview() {
        needKernel();
        assertTrue(GoalKernel.provedKernel().canDecide());
    }

    /** Witness equality by value ({gid, bids} maps from two sources). */
    private static final class G0 {
        static boolean same(Object a, Object b) {
            if (a == null || b == null) return a == b;
            Map<String, Object> x = m(a), y = m(b);
            return Objects.equals(x.get("gid"), y.get("gid")) && Objects.equals(new ArrayList<>(l(x.get("bids"))), new ArrayList<>(l(y.get("bids"))));
        }
    }
}
