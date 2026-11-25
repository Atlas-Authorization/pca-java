package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link GoalRunner}: small corpora built from real vectors (copied, then tampered) so every
 * disagreement kind is reported with its exact text and in order, the index checks, the probe count, the runner's CLI output
 * (at most 20 disagreement lines, a non-zero exit as an exception) and the vector directory lookup.
 */
public class GoalRunnerKillTest {
    static final Path SRC = GoalRunner.locate();
    static final String NL = System.lineSeparator();

    static String real(String name) throws Exception { return Files.readString(SRC.resolve(name + ".json"), StandardCharsets.UTF_8); }

    static String swap(String s, String from, String to) {
        assertTrue(s.contains(from), "fixture text missing: " + from);
        return s.replace(from, to);
    }

    static Path dir(String index, String... files) throws Exception {
        Path d = Files.createTempDirectory("goal-runner-kill");
        if (index != null) Files.writeString(d.resolve("index.json"), index, StandardCharsets.UTF_8);
        for (int i = 0; i < files.length; i += 2) Files.writeString(d.resolve(files[i]), files[i + 1], StandardCharsets.UTF_8);
        return d;
    }

    static final String FN = "fn-meet-deny-ok", W = "w-w23-19", ILL = "calendar-ill-035";

    static Path good() throws Exception {
        return dir("{\"cases\":[\"" + ILL + "\",\"" + FN + "\",\"" + W + "\"]}",
            FN + ".json", real(FN), W + ".json", real(W), ILL + ".json", real(ILL), "note.txt", "not a vector");
    }

    /** Five vectors, each wrong in a different way (written in reverse name order). */
    static Path bad() throws Exception {
        String fnBad = swap(real(FN), "\"expect\":\"deny\"", "\"expect\":\"allow\"");
        String w = swap(real(W), "\"id\":\"" + W + "\"", "\"id\":\"b\"");
        w = swap(w, "\"goal_digest\":\"JGBF", "\"goal_digest\":\"XGBF");
        w = swap(w, "\"policy_digest\":\"rw6I", "\"policy_digest\":\"Xw6I");
        w = swap(w, "\"expect\":{\"decision\":\"allow\",\"witness\":{\"gid\":\"g1\",\"bids\":[]}}", "\"expect\":{\"decision\":\"deny\",\"witness\":null}");
        String ill = swap(real(ILL), "\"id\":\"" + ILL + "\"", "\"id\":\"d\"");
        ill = swap(ill, "\"policy_digest\":null", "\"policy_digest\":\"X\""); // never compared: the goal does not compile
        return dir("{\"cases\":[\"a-fn\",\"b-goal\",\"c-err\",\"d-ill\",\"zz\"]}",
            "e-fn.json", swap(fnBad, "\"id\":\"" + FN + "\"", "\"id\":\"e\""),
            "d-ill.json", ill,
            "c-err.json", "{\"id\":\"c\",\"kind\":\"w\",\"goal\":1,\"ontology\":{},\"goal_digest\":\"x\"}",
            "b-goal.json", w,
            "a-fn.json", swap(fnBad, "\"id\":\"" + FN + "\"", "\"id\":\"a\""));
    }

    static final List<String> BAD = Arrays.asList("index: missing file zz", "a", "b:goal_digest", "b:policy_digest", "b#0");

    static void badExpect(List<String> got) {
        assertEquals(7, got.size(), String.valueOf(got));
        assertEquals(BAD, got.subList(0, 5));
        assertTrue(got.get(5).startsWith("c:error java.lang."), got.get(5));
        assertEquals("e", got.get(6));
    }

    @Test
    void goodCorpus() throws Exception {
        GoalRunner.Result r = GoalRunner.run(good());
        assertEquals(3, r.vectors);
        assertEquals(2, r.probes);
        assertEquals(List.of(), r.disagreements);
        assertEquals("java: 3 vectors, 2 probes, 0 disagreements", r.toString());
        assertThrows(UnsupportedOperationException.class, () -> r.disagreements.add("x"));
    }

    @Test
    void everyDisagreementKind() throws Exception {
        GoalRunner.Result r = GoalRunner.run(bad());
        assertEquals(5, r.vectors);
        assertEquals(2, r.probes);
        badExpect(r.disagreements);
        assertEquals("java: 5 vectors, 2 probes, 7 disagreements", r.toString());
    }

    @Test
    void indexChecks() throws Exception {
        String fn = real(FN);
        assertEquals(List.of("index: lists 2 cases, directory has 1"),
            GoalRunner.run(dir("{\"cases\":[\"" + FN + "\",\"x\"]}", FN + ".json", fn)).disagreements);
        assertEquals(List.of("index: lists 0 cases, directory has 1"), GoalRunner.run(dir("{\"cases\":[]}", FN + ".json", fn)).disagreements);
        assertEquals(List.of("index: lists -1 cases, directory has 1"), GoalRunner.run(dir("{}", FN + ".json", fn)).disagreements);
        assertEquals(List.of("index: missing file x"), GoalRunner.run(dir("{\"cases\":[\"x\"]}", FN + ".json", fn)).disagreements);
        GoalRunner.Result empty = GoalRunner.run(dir("{\"cases\":[]}"));
        assertEquals(0, empty.vectors);
        assertEquals(List.of("no vectors"), empty.disagreements);
    }

    static String out(String[] args, boolean throwsExpected) throws Exception {
        PrintStream old = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
        try {
            if (throwsExpected) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> GoalRunner.main(args));
                assertTrue(e.getMessage().endsWith(" goal vector disagreements"), e.getMessage());
            } else GoalRunner.main(args);
        } finally {
            System.setOut(old);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    @Test
    void mainPrintsAndFails() throws Exception {
        assertEquals("java: 3 vectors, 2 probes, 0 disagreements" + NL, out(new String[] {good().toString()}, false));
        String o = out(new String[] {bad().toString()}, true);
        String[] lines = o.split(NL);
        assertEquals(8, lines.length, o);
        assertEquals("java: 5 vectors, 2 probes, 7 disagreements", lines[0]);
        List<String> shown = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            assertTrue(lines[i].startsWith("   "), lines[i]);
            shown.add(lines[i].substring(3));
        }
        badExpect(shown);
    }

    @Test
    void mainShowsAtMostTwenty() throws Exception {
        String fnBad = swap(real(FN), "\"expect\":\"deny\"", "\"expect\":\"allow\"");
        List<String> files = new ArrayList<>();
        StringBuilder idx = new StringBuilder("{\"cases\":[");
        for (int i = 0; i < 22; i++) {
            String id = String.format("f%02d", i);
            files.add(id + ".json");
            files.add(swap(fnBad, "\"id\":\"" + FN + "\"", "\"id\":\"" + id + "\""));
            idx.append(i == 0 ? "" : ",").append('"').append(id).append('"');
        }
        Path d = dir(idx.append("]}").toString(), files.toArray(new String[0]));
        String[] lines = out(new String[] {d.toString()}, true).split(NL);
        assertEquals(21, lines.length);
        assertEquals("java: 22 vectors, 0 probes, 22 disagreements", lines[0]);
        for (int i = 0; i < 20; i++) assertEquals(String.format("   f%02d", i), lines[i + 1]);
    }

    @Test
    void mainWithoutArgumentsReplaysTheCorpus() throws Exception {
        String o = out(new String[0], false);
        assertTrue(o.startsWith("java: ") && o.endsWith(" probes, 0 disagreements" + NL), o);
    }

    @Test
    void locateTriesBothLayouts() throws Exception {
        Path empty = Files.createTempDirectory("goal-runner-locate");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> GoalRunner.locate(empty));
        assertEquals("goal vectors not found (no index.json under ../../packages/pca-conformance/vectors/goal or conformance/goal)", e.getMessage());
        Path vendored = empty.resolve("conformance/goal");
        Files.createDirectories(vendored);
        Files.writeString(vendored.resolve("index.json"), "{}");
        assertEquals(vendored, GoalRunner.locate(empty));
        // a directory named index.json is not the index
        Path other = Files.createTempDirectory("goal-runner-locate2");
        Files.createDirectories(other.resolve("conformance/goal/index.json"));
        assertThrows(IllegalStateException.class, () -> GoalRunner.locate(other));
        assertEquals(Path.of("../../packages/pca-conformance/vectors/goal"), GoalRunner.locate());
    }
}
