package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.policyci.ActionLintRules;
import net.atlasauth.pca.policyci.Authoring;
import net.atlasauth.pca.policyci.Cli;
import net.atlasauth.pca.policyci.Normalize;
import net.atlasauth.pca.policyci.PolicyCi;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the policy-safety CI gate (see the oracle header for the case shapes). */
class PolicyCiDiffTest {
    private static final String MODULE = "ref-policy-ci";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static Map<String, Object> opts(List<?> a, int i) { return a.size() > i ? m(a.get(i)) : null; }

    @Test void normalizePolicyInput() throws Exception { OracleCases.each(MODULE, "normalizePolicyInput", a -> Normalize.normalizePolicyInput(a.get(0))); }
    @Test void normalizeChain() throws Exception { OracleCases.each(MODULE, "normalizeChain", a -> Normalize.normalizeChain((List<?>) a.get(0))); }
    @Test void isCapability() throws Exception { OracleCases.each(MODULE, "isCapability", a -> Normalize.isCapability(a.get(0))); }
    @Test void isEnvelope() throws Exception { OracleCases.each(MODULE, "isEnvelope", a -> Normalize.isEnvelope(a.get(0))); }

    @Test void lintPolicy() throws Exception { OracleCases.each(MODULE, "lintPolicy", a -> PolicyCi.lintPolicy(a.get(0), opts(a, 1))); }
    @Test void lintChain() throws Exception { OracleCases.each(MODULE, "lintChain", a -> PolicyCi.lintChain((List<?>) a.get(0), opts(a, 1))); }
    @Test void lint() throws Exception { OracleCases.each(MODULE, "lint", a -> PolicyCi.lint(a.get(0), opts(a, 1))); }

    @Test void lintPolicies() throws Exception {
        OracleCases.each(MODULE, "lintPolicies", a -> {
            List<Map<String, Object>> items = new ArrayList<>();
            for (Object i : l(a.get(0))) items.add(m(i));
            return PolicyCi.lintPolicies(items, opts(a, 1));
        });
    }

    @Test void summarize() throws Exception { OracleCases.each(MODULE, "summarize", a -> PolicyCi.summarize(l(a.get(0)), opts(a, 1))); }

    @Test void checkLintRulesPin() throws Exception {
        OracleCases.each(MODULE, "checkLintRulesPin", a -> a.size() > 1 ? PolicyCi.checkLintRulesPin((String) a.get(0), (String) a.get(1)) : PolicyCi.checkLintRulesPin((String) a.get(0)));
    }

    @Test void toAnalyzerPolicy() throws Exception { OracleCases.each(MODULE, "toAnalyzerPolicy", a -> Authoring.toAnalyzerPolicy(a.get(0))); }

    @Test void diffCommand() throws Exception {
        OracleCases.each(MODULE, "diffCommand", a -> Authoring.diffCommand(a.get(0), a.get(1), a.size() > 2 ? m(a.get(2)) : new LinkedHashMap<>()));
    }

    /** Only the input refusals are recorded: they never reach the analyzer's test runner or coverage engine. */
    @Test void testCommand() throws Exception { OracleCases.each(MODULE, "testCommand", a -> Authoring.testCommand(a.get(0), a.get(1), new LinkedHashMap<>(), null)); }
    @Test void coverageCommand() throws Exception { OracleCases.each(MODULE, "coverageCommand", a -> Authoring.coverageCommand(a.get(0), a.get(1), new LinkedHashMap<>(), null)); }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    @Test void parseArgs() throws Exception { OracleCases.each(MODULE, "parseArgs", a -> Cli.parseArgs(strings(a.get(0)))); }

    /** A file name the reference could create on its platform but Windows cannot (a colon, a quote, ...): stored under a private-use stand-in, restored in the output. */
    private static String onDisk(String name) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return name;
        StringBuilder b = new StringBuilder();
        for (char c : name.toCharArray()) b.append("<>:\"|?*\\".indexOf(c) >= 0 ? (char) (0xE000 + c) : c);
        return b.toString();
    }

    private static String fromDisk(String s) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return s;
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) b.append(c >= 0xE000 && c < 0xE100 ? (char) (c - 0xE000) : c);
        return b.toString();
    }

    @Test void run() throws Exception {
        OracleCases.each(MODULE, "run", a -> {
            Map<String, Object> in = m(a.get(0));
            Map<String, Object> files = m(in.get("files"));
            Path dir = Files.createTempDirectory("pcaci");
            String prefix = dir.toString() + "/";
            try {
                for (Map.Entry<String, Object> e : files.entrySet()) Files.write(dir.resolve(onDisk(e.getKey())), ((String) e.getValue()).getBytes(StandardCharsets.UTF_8));
                List<String> argv = new ArrayList<>();
                for (String t : strings(in.get("argv"))) argv.add(files.containsKey(t) ? prefix + onDisk(t) : t);
                List<Object> lines = new ArrayList<>();
                int code = Cli.run(argv, s -> lines.add(fromDisk(s.replace(prefix, ""))));
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("code", code);
                out.put("lines", lines);
                return out;
            } finally {
                try (var st = Files.walk(dir)) { st.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
            }
        });
    }

    @Test void digestOfTheRuleList() {
        assertEquals(24, ActionLintRules.LINT_RULES.length);
        assertEquals(43, ActionLintRules.lintRulesDigest().length());
        assertTrue((Boolean) PolicyCi.checkLintRulesPin(" " + ActionLintRules.lintRulesDigest() + "\n").get("ok"));
    }
}
