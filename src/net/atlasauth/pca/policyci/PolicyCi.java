package net.atlasauth.pca.policyci;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * A CI gate that STATICALLY catches unsafe PCA policies before they ship. It drives the static analyzer (reachability, totality,
 * delegation-safety subsumption, numeric satisfiability) over an envelope, a minted grant, a compiled policy or a delegation chain and
 * reports findings {@code {rule, severity, message, where?}}. Rules (each toggleable): over-broad-grant, privilege-escalation,
 * redundant-caveat, dangerous-reachability, missing-safety-floor, and schema-mismatch when a schema is given.
 *
 * <p>Sound by construction: a hard error is only ever emitted from a proven analyzer verdict; anything undecidable fails safe to a
 * warning or note. A rule that throws is a finding (internal-error), never a crash and never silence.
 *
 * <p>Options are JSON-shaped maps: {@code rules}, {@code maxCombinations}, {@code schema}, {@code schemaOptions}, and for the summary
 * {@code maxSeverity}.
 */
public final class PolicyCi {
    private PolicyCi() {}

    /** Verb substrings treated as dangerous (case-insensitive {@code includes} match). */
    public static final List<String> DEFAULT_DANGEROUS_VERBS = List.of("delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant",
        "revoke", "deploy", "shutdown", "rotate");

    /** Severity ordering used for thresholds; higher is more severe. Keys in the reference's order. */
    public static final Map<String, Integer> SEVERITY_RANK = new LinkedHashMap<>();
    static {
        SEVERITY_RANK.put("info", 1);
        SEVERITY_RANK.put("warn", 2);
        SEVERITY_RANK.put("error", 3);
    }

    /** The schema check used when no analyzer schema validator is available: it refuses, so the rule reports internal-error. */
    public static final Rules.SchemaValidator NO_SCHEMA_VALIDATOR = (policy, schema, options) -> {
        throw new UnsupportedOperationException("schema validation is not available");
    };

    /** The analyzer's schema check ({@code validatePolicyAgainstSchema}): the default of every entry point that takes no validator. */
    public static final Rules.SchemaValidator ANALYZER_SCHEMA_VALIDATOR =
        (policy, schema, options) -> net.atlasauth.pca.analyzer.Validate.validatePolicyAgainstSchema(policy, schema, options);

    private static List<Object> guarded(String rule, Supplier<List<Object>> run) {
        try {
            return run.get();
        } catch (RuntimeException | StackOverflowError e) {
            List<Object> out = new ArrayList<>();
            out.add(Js.obj("rule", "internal-error", "severity", "error", "message", "rule " + rule + " could not run: " + (e instanceof StackOverflowError ? "Maximum call stack size exceeded" : String.valueOf(e.getMessage()))));
            return out;
        }
    }

    // ---- resolved config ----

    private static final class Resolved {
        boolean overBroad, privilegeEscalation, redundantCaveat, dangerousReach, safetyFloor, requireExpiry, requireScopeGate;
        List<String> overBroadVerbs, reachVerbs;
        List<?> targets;
    }

    private static boolean truthy(Object v) {
        if (v == null || Boolean.FALSE.equals(v)) return false;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = Js.num(v);
        return d == null || !(d == 0 || d.isNaN());
    }

    @SuppressWarnings("unchecked")
    private static List<String> verbList(Object cfg, String key) {
        Object dv = cfg instanceof Map ? ((Map<?, ?>) cfg).get(key) : null;
        return truthy(dv) ? (List<String>) dv : DEFAULT_DANGEROUS_VERBS;
    }

    private static Resolved resolveRules(Object rules) {
        Object r = rules == null ? Map.of() : rules;
        Object ob = Js.get(r, "overBroadGrant"), dr = Js.get(r, "dangerousReachability"), sf = Js.get(r, "missingSafetyFloor");
        Resolved c = new Resolved();
        c.overBroad = !Boolean.FALSE.equals(ob);
        c.overBroadVerbs = verbList(ob, "dangerousVerbs");
        c.privilegeEscalation = !Boolean.FALSE.equals(Js.get(r, "privilegeEscalation"));
        c.redundantCaveat = !Boolean.FALSE.equals(Js.get(r, "redundantCaveat"));
        c.dangerousReach = !Boolean.FALSE.equals(dr);
        c.reachVerbs = verbList(dr, "dangerousVerbs");
        Object t = dr instanceof Map ? ((Map<?, ?>) dr).get("targets") : null;
        c.targets = truthy(t) ? (List<?>) t : List.of();
        c.safetyFloor = !Boolean.FALSE.equals(sf);
        c.requireExpiry = !(sf instanceof Map) || !Boolean.FALSE.equals(((Map<?, ?>) sf).get("requireExpiry"));
        c.requireScopeGate = !(sf instanceof Map) || !Boolean.FALSE.equals(((Map<?, ?>) sf).get("requireScopeGate"));
        return c;
    }

    private static Map<String, Object> analyzerOpts(Map<String, Object> opts) {
        Map<String, Object> ao = new LinkedHashMap<>();
        if (opts != null && opts.containsKey("maxCombinations")) ao.put("maxCombinations", opts.get("maxCombinations"));
        return ao;
    }

    // ---- lintPolicy / lintChain / lint ----

    /** Lint a single PCA policy (an envelope, a minted grant, a compiled policy or a bare {@code {predicates, caveats?}}); empty = clean. */
    public static List<Object> lintPolicy(Object input, Map<String, Object> opts) { return lintPolicy(input, opts, ANALYZER_SCHEMA_VALIDATOR); }

    @SuppressWarnings("unchecked")
    public static List<Object> lintPolicy(Object input, Map<String, Object> opts, Rules.SchemaValidator validator) {
        Map<String, Object> norm = Normalize.normalizePolicyInput(input);
        if (!Boolean.TRUE.equals(norm.get("ok"))) {
            List<Object> out = new ArrayList<>();
            out.add(Js.obj("rule", "malformed-policy", "severity", "error", "message", norm.get("reason")));
            return out;
        }
        Resolved cfg = resolveRules(opts == null ? null : opts.get("rules"));
        Map<String, Object> ao = analyzerOpts(opts);
        Map<String, Object> policy = (Map<String, Object>) norm.get("policy");
        List<Object> out = new ArrayList<>();
        if (cfg.overBroad) out.addAll(guarded("over-broad-grant", () -> Rules.ruleOverBroadGrant(policy, cfg.overBroadVerbs, ao)));
        if (cfg.redundantCaveat) out.addAll(guarded("redundant-caveat", () -> Rules.ruleRedundantCaveat(policy)));
        if (cfg.dangerousReach) out.addAll(guarded("dangerous-reachability", () -> Rules.ruleDangerousReachability(policy, cfg.reachVerbs, cfg.targets, ao)));
        if (cfg.safetyFloor) out.addAll(guarded("missing-safety-floor", () -> Rules.ruleMissingSafetyFloor(policy, cfg.requireExpiry, cfg.requireScopeGate, cfg.overBroadVerbs)));
        if (opts != null && opts.containsKey("schema")) {
            Object so = opts.get("schemaOptions");
            out.addAll(guarded("schema-mismatch", () -> Rules.ruleSchemaMismatch(policy, opts.get("schema"), so instanceof Map ? (Map<String, Object>) so : null, validator)));
        }
        return out;
    }

    /**
     * Lint a delegation chain (root to leaf): grants or already-effective {@code {predicates, caveats}} hops. Runs the privilege-escalation
     * check across every consecutive pair, then the single-policy rules on the acting leaf's effective authority.
     */
    public static List<Object> lintChain(List<?> chain, Map<String, Object> opts) {
        Map<String, Object> norm = Normalize.normalizeChain(chain);
        if (!Boolean.TRUE.equals(norm.get("ok"))) {
            List<Object> out = new ArrayList<>();
            out.add(Js.obj("rule", "malformed-policy", "severity", "error", "message", norm.get("reason")));
            return out;
        }
        Resolved cfg = resolveRules(opts == null ? null : opts.get("rules"));
        Map<String, Object> ao = analyzerOpts(opts);
        @SuppressWarnings("unchecked") List<Object> hops = (List<Object>) norm.get("hops");
        List<Object> out = new ArrayList<>();
        if (cfg.privilegeEscalation) out.addAll(guarded("privilege-escalation", () -> Rules.rulePrivilegeEscalation(hops, ao)));

        if (!hops.isEmpty()) {
            @SuppressWarnings("unchecked") Map<String, Object> leaf = (Map<String, Object>) hops.get(hops.size() - 1);
            if (cfg.overBroad) out.addAll(guarded("over-broad-grant", () -> Rules.ruleOverBroadGrant(leaf, cfg.overBroadVerbs, ao)));
            if (cfg.redundantCaveat) out.addAll(guarded("redundant-caveat", () -> Rules.ruleRedundantCaveat(leaf)));
            if (cfg.dangerousReach) out.addAll(guarded("dangerous-reachability", () -> Rules.ruleDangerousReachability(leaf, cfg.reachVerbs, cfg.targets, ao)));
            if (cfg.safetyFloor) out.addAll(guarded("missing-safety-floor", () -> Rules.ruleMissingSafetyFloor(leaf, cfg.requireExpiry, cfg.requireScopeGate, cfg.overBroadVerbs)));
        }
        return out;
    }

    /** Dispatch: a list input is a delegation chain, anything else a single policy. */
    public static List<Object> lint(Object input, Map<String, Object> opts) { return lint(input, opts, ANALYZER_SCHEMA_VALIDATOR); }

    public static List<Object> lint(Object input, Map<String, Object> opts, Rules.SchemaValidator validator) {
        return input instanceof List ? lintChain((List<?>) input, opts) : lintPolicy(input, opts, validator);
    }

    // ---- lintPolicies + summary ----

    /** Lint a list of labeled policies ({@code {label?, policy}}) or chains and roll the findings into a summary. */
    public static Map<String, Object> lintPolicies(List<Map<String, Object>> items, Map<String, Object> opts) { return lintPolicies(items, opts, ANALYZER_SCHEMA_VALIDATOR); }

    public static Map<String, Object> lintPolicies(List<Map<String, Object>> items, Map<String, Object> opts, Rules.SchemaValidator validator) {
        List<Object> results = new ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            Map<String, Object> item = items.get(i);
            Object label = item.get("label");
            results.add(Js.obj("label", label != null ? label : "policy[" + i + "]", "findings", lint(item.get("policy"), opts, validator)));
        }
        return summarize(results, opts);
    }

    /** Roll labeled findings into counts and an exit-code mapping ({@code error} gives non-zero); nothing linted never reports success. */
    public static Map<String, Object> summarize(List<Object> results, Map<String, Object> opts) {
        Object ms = opts == null ? null : opts.get("maxSeverity");
        Object maxSeverity = ms == null ? "error" : ms;
        String msKey = Js.str(maxSeverity); // hasOwnProperty / the rank lookup coerce the key to a string: ["error"] reads as "error"
        if (!SEVERITY_RANK.containsKey(msKey)) {
            throw new IllegalArgumentException("summarize: maxSeverity must be one of " + String.join(", ", SEVERITY_RANK.keySet()));
        }
        Map<String, Object> counts = Js.obj("error", Js.n(0), "warn", Js.n(0), "info", Js.n(0));
        if (results == null || results.isEmpty()) {
            return Js.obj("results", new ArrayList<Object>(), "counts", counts, "maxSeverity", maxSeverity, "ok", false, "exitCode", Js.n(2), "reason", "no policies were linted");
        }
        long[] n = new long[3]; // error, warn, info
        int failing = 0;
        int threshold = SEVERITY_RANK.get(msKey);
        for (Object r : results) {
            for (Object fo : (List<?>) Js.get(r, "findings")) {
                Object sv = Js.get(fo, "severity");
                String sev = sv instanceof String && SEVERITY_RANK.containsKey(sv) ? (String) sv : "error";
                if (sev.equals("error")) n[0]++; else if (sev.equals("warn")) n[1]++; else n[2]++;
                if (SEVERITY_RANK.get(sev) >= threshold) failing++;
            }
        }
        counts = Js.obj("error", Js.n(n[0]), "warn", Js.n(n[1]), "info", Js.n(n[2]));
        boolean ok = failing == 0;
        return Js.obj("results", results, "counts", counts, "maxSeverity", maxSeverity, "ok", ok, "exitCode", Js.n(ok ? 0 : 1));
    }

    // ---- pinned lint rule list ----

    private static final Pattern DIGEST = Pattern.compile("[A-Za-z0-9_-]{43}");

    /**
     * Enforce the pinned digest of the action-kit lint rule list: {@code pinText} is the pin file's content (one digest, surrounding
     * whitespace ignored). Returns {@code {ok, message}}; an empty or malformed pin fails.
     */
    public static Map<String, Object> checkLintRulesPin(String pinText) { return checkLintRulesPin(pinText, ActionLintRules.lintRulesDigest()); }

    public static Map<String, Object> checkLintRulesPin(String pinText, String actual) {
        String pinned = Js.trim(pinText);
        if (!DIGEST.matcher(pinned).matches()) return Js.obj("ok", false, "message", "the lint rules pin is not a digest (expected 43 base64url characters)");
        return pinned.equals(actual)
            ? Js.obj("ok", true, "message", "lint rules digest " + actual + " matches the pin")
            : Js.obj("ok", false, "message", "lint rules digest " + actual + " differs from the pin " + pinned + ": the rule list changed; review it and update the pin");
    }
}
