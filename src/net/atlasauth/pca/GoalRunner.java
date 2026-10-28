package net.atlasauth.pca;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Replays the shared goal vectors (index.json plus one JSON file per case): goal digest, lowered policy digest, the
 * decision and witness of every probe, and the helper-function vectors. A missing corpus is an error, never a skip.
 */
public final class GoalRunner {
    private GoalRunner() {}

    /** Outcome of a corpus run; {@code disagreements} is empty when every vector agrees. */
    public static final class Result {
        public final int vectors;
        public final int probes;
        public final List<String> disagreements;

        Result(int vectors, int probes, List<String> disagreements) {
            this.vectors = vectors;
            this.probes = probes;
            this.disagreements = Collections.unmodifiableList(disagreements);
        }

        @Override public String toString() { return "java: " + vectors + " vectors, " + probes + " probes, " + disagreements.size() + " disagreements"; }
    }

    /** The vector directory: the monorepo layout, else the vendored layout of a standalone checkout. */
    public static Path locate() {
        for (String c : new String[] {"../../packages/pca-conformance/vectors/goal", "conformance/goal"}) {
            Path p = Path.of(c);
            if (Files.isRegularFile(p.resolve("index.json"))) return p;
        }
        throw new IllegalStateException("goal vectors not found (no index.json under ../../packages/pca-conformance/vectors/goal or conformance/goal)");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> read(Path f) throws IOException {
        return (Map<String, Object>) Json.parseLenient(Files.readString(f));
    }

    @SuppressWarnings("unchecked")
    public static Result run(Path dir) throws IOException {
        Map<String, Object> index = read(dir.resolve("index.json"));
        List<String> names = new ArrayList<>();
        try (Stream<Path> st = Files.list(dir)) {
            st.forEach(p -> {
                String n = p.getFileName().toString();
                if (n.endsWith(".json") && !n.equals("index.json")) names.add(n);
            });
        }
        Collections.sort(names);
        List<String> bad = new ArrayList<>();
        // every case the index lists must be present, and nothing unlisted may ride along
        List<Object> listed = (List<Object>) index.get("cases");
        if (listed == null || listed.size() != names.size()) bad.add("index: lists " + (listed == null ? -1 : listed.size()) + " cases, directory has " + names.size());
        else for (Object c : listed) if (!names.contains(c + ".json")) bad.add("index: missing file " + c);
        int probes = 0;
        for (String n : names) {
            Map<String, Object> v = read(dir.resolve(n));
            String id = (String) v.get("id");
            try {
                if ("fn".equals(v.get("kind"))) {
                    Object got = GoalSemantics.runFn((String) v.get("fn"), v.get("input"));
                    if (!GoalSemantics.canon(got).equals(GoalSemantics.canon(v.get("expect")))) bad.add(id);
                    continue;
                }
                Map<String, Object> goal = (Map<String, Object>) v.get("goal"), ont = (Map<String, Object>) v.get("ontology");
                if (!GoalSemantics.goalDigest(goal).equals(v.get("goal_digest"))) bad.add(id + ":goal_digest");
                Map<String, Object> compile = (Map<String, Object>) v.get("compile");
                if (!Boolean.TRUE.equals(compile.get("ok"))) continue;
                if (!GoalSemantics.policyDigest(ont, goal).equals(v.get("policy_digest"))) bad.add(id + ":policy_digest");
                List<Object> ps = (List<Object>) v.get("probes");
                for (int i = 0; i < ps.size(); i++) {
                    probes++;
                    Map<String, Object> p = (Map<String, Object>) ps.get(i);
                    Map<String, Object> got = GoalSemantics.decide(goal, ont, (Map<String, Object>) p.get("action"), (Map<String, Object>) p.get("history"));
                    if (!GoalSemantics.canon(got).equals(GoalSemantics.canon(p.get("expect")))) bad.add(id + "#" + i);
                }
            } catch (RuntimeException e) { // a vector the runner cannot evaluate is a disagreement, not a crash of the run
                bad.add(id + ":error " + e);
            }
        }
        if (names.isEmpty()) bad.add("no vectors");
        return new Result(names.size(), probes, bad);
    }

    public static void main(String[] args) throws IOException {
        Result r = run(args.length > 0 ? Path.of(args[0]) : locate());
        System.out.println(r);
        for (int i = 0; i < r.disagreements.size() && i < 20; i++) System.out.println("   " + r.disagreements.get(i));
        if (!r.disagreements.isEmpty()) System.exit(1);
    }
}
