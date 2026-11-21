package net.atlasauth.pca.policyci;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import net.atlasauth.pca.Json;

/**
 * The command line of the policy-safety gate.
 *
 * <pre>
 * pca-policy-ci &lt;files...&gt; [--max-severity error|warn|info] [--format text|github] [--quiet] [--schema file] [--lint-rules-pin file]
 * pca-policy-ci diff &lt;old.json&gt; &lt;new.json&gt; [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
 * pca-policy-ci test &lt;policy.json&gt; &lt;tests.json&gt; [--require-digest]
 * pca-policy-ci coverage &lt;policy.json&gt; &lt;traffic-or-tests.json&gt; [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]
 * </pre>
 *
 * Each file is a JSON policy (envelope, grant, compiled policy, {@code {predicates, caveats}}) or a JSON array treated as a delegation
 * chain. Exits non-zero when a finding reaches {@code --max-severity} (default {@code error}); 2 is unusable input.
 */
public final class Cli {
    private Cli() {}

    private static final List<String> SEVERITIES = List.of("error", "warn", "info");

    private static boolean isSeverity(String x) { return SEVERITIES.contains(x); }

    /** Parse the gate's own arguments: {@code {args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}}} or {@code {error}}. */
    public static Map<String, Object> parseArgs(List<String> argv) {
        List<Object> files = new ArrayList<>();
        String maxSeverity = "error", format = "text", schema = null, lintRulesPin = null;
        boolean quiet = false, help = false;
        String sevMsg = "--max-severity expects one of " + String.join("|", SEVERITIES);

        for (int i = 0; i < argv.size(); i++) {
            String a = argv.get(i);
            if (a == null) continue;
            if (a.equals("--help") || a.equals("-h")) {
                help = true;
            } else if (a.equals("--quiet") || a.equals("-q")) {
                quiet = true;
            } else if (a.equals("--lint-rules-pin")) {
                String v = ++i < argv.size() ? argv.get(i) : null;
                if (v == null || v.startsWith("-")) return Js.obj("error", "--lint-rules-pin expects a file");
                lintRulesPin = v;
            } else if (a.equals("--max-severity")) {
                String v = ++i < argv.size() ? argv.get(i) : null;
                if (v == null || !isSeverity(v)) return Js.obj("error", sevMsg);
                maxSeverity = v;
            } else if (a.startsWith("--max-severity=")) {
                String v = a.substring("--max-severity=".length());
                if (!isSeverity(v)) return Js.obj("error", sevMsg);
                maxSeverity = v;
            } else if (a.equals("--schema")) {
                String v = ++i < argv.size() ? argv.get(i) : null;
                if (v == null) return Js.obj("error", "--schema expects a file");
                schema = v;
            } else if (a.startsWith("--schema=")) {
                schema = a.substring("--schema=".length());
            } else if (a.equals("--format")) {
                String v = ++i < argv.size() ? argv.get(i) : null;
                if (!"text".equals(v) && !"github".equals(v)) return Js.obj("error", "--format expects 'text' or 'github'");
                format = v;
            } else if (a.startsWith("--format=")) {
                String v = a.substring("--format=".length());
                if (!v.equals("text") && !v.equals("github")) return Js.obj("error", "--format expects 'text' or 'github'");
                format = v;
            } else if (a.startsWith("-")) {
                return Js.obj("error", "unknown option '" + a + "'");
            } else {
                files.add(a);
            }
        }
        Map<String, Object> args = Js.obj("files", files, "maxSeverity", maxSeverity, "format", format, "quiet", quiet, "help", help);
        if (schema != null) args.put("schema", schema);
        if (lintRulesPin != null) args.put("lintRulesPin", lintRulesPin);
        return Js.obj("args", args);
    }

    private static final String HELP = "pca-policy-ci — statically catch unsafe PCA policies before they ship.\n\n"
        + "Usage:\n"
        + "  pca-policy-ci <files...> [options]\n"
        + "  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]\n"
        + "  pca-policy-ci test <policy.json> <tests.json> [--require-digest]\n"
        + "  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]\n\n"
        + "Options:\n"
        + "  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)\n"
        + "  --format <text|github>            Output format (default: text; 'github' = workflow annotations)\n"
        + "  --schema <file>                   Also check each policy against this signed action schema (JSON)\n"
        + "  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>\n"
        + "  --quiet, -q                       Only print findings and the summary line\n"
        + "  --help, -h                        Show this help\n\n"
        + "Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array\n"
        + "treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.";

    /** The usage text. */
    public static String help() { return HELP; }

    private static String message(Throwable e) { return e instanceof StackOverflowError ? "Maximum call stack size exceeded" : String.valueOf(e.getMessage()); }

    private static Object[] readJson(String file) {
        try {
            String text = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8);
            return new Object[] { true, Json.parseLenient(text) };
        } catch (java.io.IOException | RuntimeException | StackOverflowError e) {
            return new Object[] { false, file + ": " + message(e) };
        }
    }

    private static List<Object> lintFile(String file, boolean hasSchema, Object schema, Rules.SchemaValidator validator) {
        String text;
        try {
            text = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8);
        } catch (java.io.IOException | RuntimeException e) {
            return finding("cannot read file: " + message(e));
        }
        Object doc;
        try {
            doc = Json.parseLenient(text);
        } catch (RuntimeException | StackOverflowError e) {
            return finding("invalid JSON: " + message(e));
        }
        Map<String, Object> opts = new LinkedHashMap<>();
        if (hasSchema) opts.put("schema", schema);
        return PolicyCi.lint(doc, opts, validator);
    }

    private static List<Object> finding(String message) {
        List<Object> out = new ArrayList<>();
        out.add(Js.obj("rule", "malformed-policy", "severity", "error", "message", message));
        return out;
    }

    private static String ghLevel(String sev) { return sev.equals("error") ? "error" : sev.equals("warn") ? "warning" : "notice"; }

    private static String textTag(String sev) { return sev.equals("error") ? "ERROR" : sev.equals("warn") ? "WARN " : "INFO "; }

    @SuppressWarnings("unchecked")
    private static void printText(List<Object> results, boolean quiet, Consumer<String> write) {
        for (Object r : results) {
            if (!quiet) write.accept("\n" + Js.get(r, "label") + ":");
            List<Object> findings = (List<Object>) Js.get(r, "findings");
            if (findings.isEmpty()) {
                if (!quiet) write.accept("  (clean)");
                continue;
            }
            for (Object f : findings) {
                Object where = Js.get(f, "where");
                String loc = where != null ? " [" + Js.str(where) + "]" : "";
                write.accept("  " + textTag((String) Js.get(f, "severity")) + " " + Js.get(f, "rule") + loc + ": " + Js.get(f, "message"));
            }
        }
    }

    private static String escapeGh(String s) { return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"); }

    /** Workflow-command property values must also escape {@code :} and {@code ,}, or a file name can add properties or end the command. */
    private static String escapeGhProp(String s) { return escapeGh(s).replace(":", "%3A").replace(",", "%2C"); }

    @SuppressWarnings("unchecked")
    private static void printGithub(List<Object> results, Consumer<String> write) {
        for (Object r : results) {
            for (Object f : (List<Object>) Js.get(r, "findings")) {
                String props = "file=" + escapeGhProp((String) Js.get(r, "label")) + ",title=" + escapeGhProp((String) Js.get(f, "rule"));
                Object where = Js.get(f, "where");
                String loc = where != null ? Js.str(where) + ": " : "";
                write.accept("::" + ghLevel((String) Js.get(f, "severity")) + " " + props + "::" + escapeGh(loc + Js.get(f, "message")));
            }
        }
    }

    private static final java.util.regex.Pattern DECIMAL = java.util.regex.Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?");

    /** {@code Number(v)} of a trimmed non-empty flag value when it is finite, else null (JavaScript's grammar, including 0x / 0o / 0b). */
    private static Double flagNum(Map<String, Object> flags, String k) {
        Object v = flags.get(k);
        if (!(v instanceof String)) return null;
        String s = Js.trim((String) v);
        if (s.isEmpty()) return null;
        double d;
        try {
            if (s.length() > 2 && s.charAt(0) == '0' && "xXoObB".indexOf(s.charAt(1)) >= 0) {
                int radix = "xX".indexOf(s.charAt(1)) >= 0 ? 16 : "oO".indexOf(s.charAt(1)) >= 0 ? 8 : 2;
                d = new java.math.BigInteger(s.substring(2), radix).doubleValue();
                if (s.charAt(2) == '-' || s.charAt(2) == '+') return null;
            } else if (DECIMAL.matcher(s).matches()) {
                d = Double.parseDouble(s);
            } else {
                return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return Double.isNaN(d) || Double.isInfinite(d) ? null : d;
    }

    private static Object numJson(double d) { return new Json.Num(net.atlasauth.pca.AttestCommon.jsNumString(d)); }

    /** {@code diff}, {@code test} and {@code coverage}: two files and flags. Unknown or malformed flags are a usage error (exit 2). */
    @SuppressWarnings("unchecked")
    private static int runAuthoring(String cmd, List<String> rest, Consumer<String> write, Authoring.Backend backend) {
        List<String> files = new ArrayList<>();
        Map<String, Object> flags = new LinkedHashMap<>();
        Set<String> valued = Set.of("--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors");
        Set<String> bools = Set.of("--allow-widen", "--integer", "--require-digest");
        for (int i = 0; i < rest.size(); i++) {
            String a = rest.get(i);
            if (valued.contains(a)) {
                if (++i >= rest.size()) { write.accept(a + " expects a value"); return 2; }
                flags.put(a, rest.get(i));
            } else if (bools.contains(a)) {
                flags.put(a, Boolean.TRUE);
            } else if (a.startsWith("-")) {
                write.accept("unknown option '" + a + "'");
                return 2;
            } else {
                files.add(a);
            }
        }
        for (Map.Entry<String, Object> e : flags.entrySet()) {
            String k = e.getKey();
            if (valued.contains(k) && !k.equals("--verb") && !k.equals("--amount-field") && flagNum(flags, k) == null) {
                write.accept(k + " expects a number, got '" + e.getValue() + "'");
                return 2;
            }
        }
        if (files.size() != 2) {
            write.accept("error: " + cmd + " takes exactly two files");
            write.accept(HELP);
            return 2;
        }
        Object[] a = readJson(files.get(0));
        if (!(Boolean) a[0]) { write.accept((String) a[1]); return 2; }
        Object[] b = readJson(files.get(1));
        if (!(Boolean) b[0]) { write.accept((String) b[1]); return 2; }
        Map<String, Object> r;
        if (cmd.equals("diff")) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("allowWiden", flags.containsKey("--allow-widen"));
            if (flags.get("--verb") instanceof String) o.put("verb", flags.get("--verb"));
            if (flags.get("--amount-field") instanceof String) o.put("amountField", flags.get("--amount-field"));
            o.put("integer", flags.containsKey("--integer"));
            if (flagNum(flags, "--window-secs") != null) o.put("windowSecs", numJson(flagNum(flags, "--window-secs")));
            if (flagNum(flags, "--max-exposure-increase") != null) o.put("maxExposureIncrease", numJson(flagNum(flags, "--max-exposure-increase")));
            r = Authoring.diffCommand(a[1], b[1], o);
        } else if (cmd.equals("test")) {
            r = Authoring.testCommand(a[1], b[1], Js.obj("requireDigest", flags.containsKey("--require-digest")), backend);
        } else {
            Map<String, Object> o = new LinkedHashMap<>();
            if (flagNum(flags, "--min-clauses") != null) o.put("minClauses", numJson(flagNum(flags, "--min-clauses")));
            if (flagNum(flags, "--min-boundaries") != null) o.put("minBoundaries", numJson(flagNum(flags, "--min-boundaries")));
            if (flagNum(flags, "--min-mutation") != null) o.put("minMutation", numJson(flagNum(flags, "--min-mutation")));
            if (flagNum(flags, "--max-survivors") != null) o.put("maxSurvivors", numJson(flagNum(flags, "--max-survivors")));
            r = Authoring.coverageCommand(a[1], b[1], o, backend);
        }
        for (Object l : (List<Object>) r.get("lines")) write.accept((String) l);
        return (int) Math.round(Js.num(r.get("exitCode")));
    }

    /** Run the CLI; {@code write} receives each output line. Returns the process exit code. */
    public static int run(List<String> argv, Consumer<String> write) { return run(argv, write, PolicyCi.ANALYZER_SCHEMA_VALIDATOR, Authoring.ANALYZER_BACKEND); }

    /**
     * {@code validator} checks policies against {@code --schema}; {@code backend} runs {@code test} and {@code coverage}. Either may be
     * null when that analyzer part is not available: the command then refuses (a rule that cannot run is a finding; a missing backend
     * is exit code 2).
     */
    @SuppressWarnings("unchecked")
    public static int run(List<String> argv, Consumer<String> write, Rules.SchemaValidator validator, Authoring.Backend backend) {
        if (!argv.isEmpty() && (argv.get(0).equals("diff") || argv.get(0).equals("test") || argv.get(0).equals("coverage"))) {
            return runAuthoring(argv.get(0), argv.subList(1, argv.size()), write, backend != null ? backend : Authoring.ANALYZER_BACKEND);
        }
        Map<String, Object> parsed = parseArgs(argv);
        if (parsed.containsKey("error")) {
            write.accept((String) parsed.get("error"));
            write.accept(HELP);
            return 2;
        }
        Map<String, Object> args = (Map<String, Object>) parsed.get("args");
        List<Object> files = (List<Object>) args.get("files");
        if (Boolean.TRUE.equals(args.get("help"))) {
            write.accept(HELP);
            return 0;
        }
        boolean pinFailed = false;
        if (args.get("lintRulesPin") != null) {
            Map<String, Object> r;
            try {
                r = PolicyCi.checkLintRulesPin(new String(Files.readAllBytes(Paths.get((String) args.get("lintRulesPin"))), StandardCharsets.UTF_8));
            } catch (java.io.IOException | RuntimeException e) {
                r = Js.obj("ok", false, "message", "cannot read the lint rules pin: " + message(e));
            }
            write.accept((Boolean.TRUE.equals(r.get("ok")) ? "PASS" : "FAIL") + " — " + r.get("message"));
            pinFailed = !Boolean.TRUE.equals(r.get("ok"));
            if (files.isEmpty()) return pinFailed ? 1 : 0;
        }
        if (files.isEmpty()) {
            write.accept("error: no policy files given");
            write.accept(HELP);
            return 2;
        }

        boolean hasSchema = false;
        Object schema = null;
        if (args.get("schema") != null) {
            Object[] s = readJson((String) args.get("schema"));
            if (!(Boolean) s[0]) { write.accept((String) s[1]); return 2; }
            hasSchema = true;
            schema = s[1];
        }
        Rules.SchemaValidator v = validator != null ? validator : PolicyCi.ANALYZER_SCHEMA_VALIDATOR;
        List<Object> results = new ArrayList<>();
        for (Object file : files) results.add(Js.obj("label", file, "findings", lintFile((String) file, hasSchema, schema, v)));
        Map<String, Object> summary = PolicyCi.summarize(results, Js.obj("maxSeverity", args.get("maxSeverity")));

        if ("github".equals(args.get("format"))) printGithub(results, write);
        else printText(results, Boolean.TRUE.equals(args.get("quiet")), write);

        if (summary.get("reason") != null) write.accept("error: " + summary.get("reason"));
        Map<String, Object> c = (Map<String, Object>) summary.get("counts");
        write.accept("\n" + (Boolean.TRUE.equals(summary.get("ok")) ? "PASS" : "FAIL") + " — " + Js.str(c.get("error")) + " error(s), " + Js.str(c.get("warn")) + " warning(s), " + Js.str(c.get("info"))
            + " info across " + results.size() + " policy/policies (fail threshold: " + summary.get("maxSeverity") + ")");
        int code = (int) Math.round(Js.num(summary.get("exitCode")));
        return pinFailed ? Math.max(1, code) : code;
    }
}
