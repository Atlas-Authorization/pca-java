package net.atlasauth.pca.actions;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.policyci.ActionLintRules;

/**
 * The 24 stable lint rules (14 errors LD-001..014, 10 warnings LW-001..010), SARIF output and the rule-list digest. Pure: defs in,
 * findings out, deterministic order. A def that does not pass validation is reported as LD-000 and not linted further. The rule list
 * and its digest are those of {@link ActionLintRules} (one copy).
 */
public final class ActionLint {
    private ActionLint() {}

    public static final String LINT_RULES_DIGEST_DOMAIN = ActionLintRules.LINT_RULES_DIGEST_DOMAIN;
    public static final String[] STRUCTURE_RULE = {"LD-000", "error", "the def is not well formed and cannot be loaded"};
    public static final String[] NOTE_RULE = {"LN-001", "note", "an informational note from the loader"};

    /** The digest a policy gate pins: the ordered (id, severity, title) list. */
    public static String lintRulesDigest() { return ActionLintRules.lintRulesDigest(); }

    private static final Pattern DESTROY_RE = Pattern.compile("^(?:delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(?:_|\\z)");
    private static final Pattern SEND_RE = Pattern.compile("^(?:send|email|notify|sms|message|post_to|broadcast|invite)(?:_|\\z)");
    private static final Pattern EXPORT_RE = Pattern.compile("^(?:export|download|dump|backup|extract)(?:_|\\z)");
    private static final String[][] NAME_GROUPS = {{"create_", "new_", "add_", "make_"}, {"delete_", "remove_", "destroy_"}};
    private static final List<String> OWN_RULES = List.of("money_has_currency", "money_amount_bounded", "pay_has_idempotency");

    private static String lastSeg(String verb) { int i = verb.lastIndexOf('.'); return i < 0 ? verb : verb.substring(i + 1); }

    private static List<String> bindingKeys(Map<String, Object> d) {
        List<String> out = new ArrayList<>();
        Object b = d.get("bindings");
        if (b == null) return out;
        if (J.get(b, "mcp") != null) out.add("mcp:" + J.get(J.get(b, "mcp"), "tool"));
        if (J.get(b, "openapi") != null) out.add("openapi:" + J.get(J.get(b, "openapi"), "operationId"));
        if (J.get(b, "http") != null) out.add("http:" + ((String) J.get(J.get(b, "http"), "method")).toUpperCase(java.util.Locale.ROOT) + " " + J.get(J.get(b, "http"), "path"));
        if (J.get(b, "graphql") != null) out.add("graphql:" + J.get(J.get(b, "graphql"), "op") + "." + J.get(J.get(b, "graphql"), "field"));
        if (J.get(b, "grpc") != null) out.add("grpc:" + J.get(J.get(b, "grpc"), "service") + "/" + J.get(J.get(b, "grpc"), "method"));
        if (J.get(b, "asyncapi") != null) out.add("asyncapi:" + J.get(J.get(b, "asyncapi"), "op") + " " + J.get(J.get(b, "asyncapi"), "channel"));
        return out;
    }

    private static List<String> vocabularyIssues(Object x, Actions.Registry reg) {
        List<String> out = new ArrayList<>();
        if (!(x instanceof Map)) return out;
        Object effects = J.get(x, "effects");
        if (effects instanceof List) for (Object e : J.a(effects)) if (!ActionsBridge.effects().contains(e)) out.add("unknown effect '" + J.jsStr(e) + "'");
        Object params = J.get(x, "params");
        if (params instanceof Map) {
            for (Map.Entry<String, Object> e : J.m(params).entrySet()) {
                Object q = e.getValue();
                if (!(q instanceof Map)) continue;
                if (J.m(q).containsKey("role") && !ActionsBridge.isRole(J.m(q).get("role"))) out.add(e.getKey() + ": unknown role '" + J.jsStr(J.m(q).get("role")) + "'");
                if (J.m(q).containsKey("format") && !ActionsBridge.isFormat(J.m(q).get("format"))) out.add(e.getKey() + ": unknown format '" + J.jsStr(J.m(q).get("format")) + "'");
            }
        }
        Object ctx = J.get(x, "context");
        if (ctx instanceof List) for (Object c : J.a(ctx)) if (!ActionsBridge.isContextKey(c)) out.add("unknown context key '" + J.jsStr(c) + "' (known: " + String.join(", ", ActionsBridge.contextKeys()) + ", session_taint_max:<level>)");
        Object tr = J.get(x, "traits");
        if (tr instanceof List) for (Object t : J.a(tr)) if (t instanceof String && !reg.traits.containsKey(t)) out.add("unknown trait '" + t + "'");
        return out;
    }

    private static String severityOf(String rule) {
        if (rule.equals(STRUCTURE_RULE[0])) return "error";
        for (String[] r : ActionLintRules.LINT_RULES) if (r[0].equals(rule)) return r[1];
        throw new IllegalArgumentException("unknown rule " + rule);
    }

    private static void add(List<Map<String, Object>> out, String rule, String verb, String message, String param) {
        Map<String, Object> f = J.obj("rule", rule, "severity", severityOf(rule));
        if (verb != null) f.put("verb", verb);
        if (param != null) f.put("param", param);
        f.put("message", message);
        out.add(f);
    }

    private static List<String> params(Map<String, Object> np, List<String> names, Predicate<Map<String, Object>> pred) {
        List<String> out = new ArrayList<>();
        for (String k : names) if (pred.test(J.m(np.get(k)))) out.add(k);
        return out;
    }

    private static List<?> tags(Map<String, Object> q) { return q.get("tags") instanceof List ? J.a(q.get("tags")) : List.of(); }

    private static boolean roleStarts(Map<String, Object> q, String pfx) { return q.get("role") instanceof String && ((String) q.get("role")).startsWith(pfx); }

    private static boolean isReadOnly(Object effects) {
        if (!(effects instanceof List) || ((List<?>) effects).isEmpty()) return false;
        for (Object e : (List<?>) effects) if (!"read".equals(e)) return false;
        return true;
    }

    private static int u8(String s) { return Json.utf8(s).length; }

    private static String groupOf(String[] grp, String verb) { for (String p : grp) if (lastSeg(verb).startsWith(p)) return p; return null; }

    /**
     * Lint a pack's defs (raw values, so a malformed one is still reported). {@code opts}: {customTraits?, stability?, ns?}; {@code attestationVerified}
     * is the registry layer's signature check (null: an attestation needs a {@code sig} member to count). Findings are sorted by verb, rule, param, message.
     */
    @SuppressWarnings("unchecked")
    public static List<Object> lintDefs(List<?> raw, Map<String, Object> opts, Predicate<Map<String, Object>> attestationVerified) {
        List<Map<String, Object>> out = new ArrayList<>();
        Actions.Registry reg = Actions.CORE_REGISTRY;
        Object custom = opts == null ? null : opts.get("customTraits");
        if (custom instanceof List && !((List<?>) custom).isEmpty()) {
            try { reg = Actions.extendRegistry(Actions.CORE_REGISTRY, (List<Object>) custom); }
            catch (RuntimeException e) { add(out, "LD-007", null, "invalid custom traits: " + e.getMessage(), null); }
        }
        List<Map<String, Object>> defs = new ArrayList<>();
        for (Object x : raw) {
            String verb = x instanceof Map && J.m(x).get("verb") instanceof String ? (String) J.m(x).get("verb") : null;
            List<String> vocab = vocabularyIssues(x, reg);
            if (!vocab.isEmpty()) { for (String v : vocab) add(out, "LD-007", verb, v, null); continue; }
            String bad = Actions.validateDef(x);
            if (bad != null) { add(out, STRUCTURE_RULE[0], verb, bad, null); continue; }
            defs.add(J.m(x));
        }
        Map<String, Map<String, Object>> byVerb = new HashMap<>();
        Map<String, String> names = new HashMap<>();
        for (Map<String, Object> d : defs) {
            if (byVerb.containsKey(d.get("verb"))) add(out, "LD-009", (String) d.get("verb"), "verb '" + d.get("verb") + "' is defined twice", null);
            byVerb.put((String) d.get("verb"), d);
        }
        for (Map<String, Object> d : defs) {
            List<Object> ns = new ArrayList<>();
            ns.add(d.get("verb"));
            if (d.get("aliases") instanceof List) ns.addAll(J.a(d.get("aliases")));
            for (Object n : ns) {
                String owner = names.get(n);
                if (owner != null && !owner.equals(d.get("verb"))) add(out, "LD-009", (String) d.get("verb"), "'" + n + "' is also a name of '" + owner + "'", null);
                else if (!names.containsKey(n)) names.put((String) n, (String) d.get("verb"));
            }
        }
        Map<String, String> bound = new HashMap<>();
        for (Map<String, Object> d : defs) {
            for (String k : bindingKeys(d)) {
                String owner = bound.get(k);
                if (owner != null && !owner.equals(d.get("verb"))) add(out, "LD-014", (String) d.get("verb"), "binding " + k + " is also bound by '" + owner + "'", null);
                else bound.put(k, (String) d.get("verb"));
            }
        }
        for (String[] grp : NAME_GROUPS) {
            Map<String, Integer> used = new LinkedHashMap<>();
            for (Map<String, Object> d : defs) { String g = groupOf(grp, (String) d.get("verb")); if (g != null) used.merge(g, 1, Integer::sum); }
            if (used.size() > 1) {
                List<Map.Entry<String, Integer>> es = new ArrayList<>(used.entrySet());
                es.sort((a, b) -> !a.getValue().equals(b.getValue()) ? Integer.compare(b.getValue(), a.getValue()) : a.getKey().compareTo(b.getKey()));
                String win = es.get(0).getKey();
                for (Map<String, Object> d : defs) { String g = groupOf(grp, (String) d.get("verb")); if (g != null && !g.equals(win)) add(out, "LW-008", (String) d.get("verb"), "uses '" + g + "' where its siblings use '" + win + "'", null); }
            }
        }
        String fileNs = opts == null ? null : (String) opts.get("ns");
        if (fileNs != null) for (Map<String, Object> d : defs) {
            String first = ((String) d.get("verb")).split("\\.", -1)[0];
            if (!first.equals(fileNs)) add(out, "LW-008", (String) d.get("verb"), "verb namespace '" + first + "' differs from the file namespace '" + fileNs + "'", null);
        }

        for (Map<String, Object> d : defs) lintOne(out, d, J.m(Actions.normalize(d)), reg, byVerb, opts, attestationVerified);

        out.sort((a, b) -> {
            int c = cmp((String) a.get("verb"), (String) b.get("verb"));
            if (c == 0) c = cmp((String) a.get("rule"), (String) b.get("rule"));
            if (c == 0) c = cmp((String) a.get("param"), (String) b.get("param"));
            if (c == 0) c = cmp((String) a.get("message"), (String) b.get("message"));
            return c;
        });
        return new ArrayList<Object>(out);
    }

    private static int cmp(String a, String b) { return (a == null ? "" : a).compareTo(b == null ? "" : b); }

    private static void lintOne(List<Map<String, Object>> out, Map<String, Object> d, Map<String, Object> n, Actions.Registry reg, Map<String, Map<String, Object>> byVerb,
                                Map<String, Object> opts, Predicate<Map<String, Object>> att) {
        String verb = (String) d.get("verb");
        Map<String, Object> np = J.m(n.get("params"));
        List<String> pn = new ArrayList<>(new TreeSet<>(np.keySet()));
        Map<String, Object> eff = ActionEffective.effective(d, reg, att);
        Map<String, Object> hint = J.m(eff.get("hint"));
        Set<Object> tset = new HashSet<>(J.a(hint.get("traits"))), cl = new HashSet<>(J.a(hint.get("closure")));
        List<Object> effects = J.a(d.get("effects"));
        String last = lastSeg(verb);
        Map<String, Object> idem = J.m(n.get("idempotency"));

        if (DESTROY_RE.matcher(last).find() && !effects.contains("delete")) add(out, "LD-001", verb, "the verb says '" + last + "' but effects do not include delete", null);
        for (String k : params(np, pn, q -> "money.amount".equals(q.get("role")) || "money.fee".equals(q.get("role")))) {
            Object u = J.m(np.get(k)).get("unit");
            if (u == null || !"money".equals(J.get(u, "kind"))) add(out, "LD-002", verb, "a money parameter needs a unit of kind money with a currency", k);
            else if (!(J.get(u, "ccy") instanceof String)) {
                String from = (String) J.get(J.get(u, "ccy"), "from");
                Object c = np.get(from);
                if (c == null || !"money.currency".equals(J.get(c, "role")) || !"iso_currency".equals(J.get(c, "format"))) add(out, "LD-002", verb, "the currency parameter '" + from + "' needs role money.currency and format iso_currency", k);
            }
        }
        for (String k : params(np, pn, q -> "money.currency".equals(q.get("role")))) if (!"iso_currency".equals(J.m(np.get(k)).get("format"))) add(out, "LD-002", verb, "a currency parameter needs the iso_currency format", k);
        for (String k : params(np, pn, q -> "integer".equals(q.get("type")) || "duration".equals(q.get("type")))) {
            Map<String, Object> q = J.m(np.get(k));
            if (roleStarts(q, "id.")) continue;
            if ("count.limit".equals(q.get("role")) && q.get("max") != null) continue;
            if (q.get("min") == null || q.get("max") == null) add(out, "LD-003", verb, "a numeric parameter needs both min and max (has " + (q.get("min") == null ? "no min" : "min") + ", " + (q.get("max") == null ? "no max" : "max") + ")", k);
        }
        if ((effects.contains("pay") || tset.contains("pca.money_moving")) && "none".equals(idem.get("mode"))) add(out, "LD-004", verb, "a money-moving action needs idempotency key_param or natural", null);
        List<String> pii = params(np, pn, q -> tags(q).contains("pii") || roleStarts(q, "contact.") || roleStarts(q, "person."));
        if (!pii.isEmpty()) {
            TreeSet<String> expected = new TreeSet<>();
            if (d.get("side_effects") instanceof List) for (Object s : J.a(d.get("side_effects"))) { Object k = J.get(s, "kind"); if ("send".equals(k) || "export".equals(k)) expected.add((String) k); }
            if (SEND_RE.matcher(last).find()) expected.add("send");
            if (EXPORT_RE.matcher(last).find()) expected.add("export");
            for (String e : expected) if (!effects.contains(e)) add(out, "LD-005", verb, "personal data can " + (e.equals("send") ? "be sent" : "be exported") + " (" + String.join(", ", pii) + ") but effects do not include " + e, null);
        }
        for (Object c : J.a(eff.get("clamps"))) add(out, "LD-006", verb, "declared " + ("rev".equals(J.get(c, "field")) ? "reversibility" : "blast") + " " + J.jsStr(J.get(c, "declared")) + " is below the floor " + J.jsStr(J.get(c, "floor")), null);
        Map<String, Object> res = J.m(n.get("resource"));
        if ("*".equals(res.get("id")) && "one".equals(res.get("scope"))) add(out, "LD-008", verb, "resource id '*' with scope one names every resource at once", null);
        if (!isReadOnly(effects) && ActionUndo.mayBeReversible(d)) {
            Object comp = d.get("compensates");
            if (comp == null) add(out, "LD-010", verb, "a write declared reversible must name its compensating action (compensates)", null);
            else if (!byVerb.containsKey(comp)) add(out, "LD-010", verb, "compensates '" + comp + "', which is not in the pack", null);
            else {
                Map<String, Object> s = ActionUndo.compensationShape(d, byVerb.get(comp));
                if (!Boolean.TRUE.equals(s.get("ok"))) add(out, "LD-010", verb, "compensates '" + comp + "', which cannot undo it: " + s.get("reason"), null);
            }
        }
        Map<String, Object> review = J.m(d.get("review"));
        if ("confirmed".equals(review.get("state"))) {
            Object a = review.get("attestation");
            if (a == null) add(out, "LD-011", verb, "confirmed without an attestation", null);
            else if (!Actions.defDigest(d).equals(J.get(a, "def_digest"))) add(out, "LD-011", verb, "the attestation covers a different digest of this def", null);
            else if (!Actions.traitsDigest(reg).equals(J.get(a, "traits_digest"))) add(out, "LD-011", verb, "the attestation was made against a different trait registry", null);
            else if (att != null ? !att.test(d) : !J.has(a, "sig")) add(out, "LD-011", verb, "the attestation is not signed by a pinned reviewer", null);
        }
        Set<Object> dismissed = new HashSet<>();
        if ("confirmed".equals(review.get("state")) && J.get(review.get("attestation"), "dismissed") instanceof List) for (Object x : J.a(J.get(review.get("attestation"), "dismissed"))) dismissed.add(J.get(x, "trait"));
        Object prov = review.get("provenance");
        if (prov != null && J.get(prov, "union") instanceof List) for (Object t : J.a(J.get(prov, "union"))) if (!cl.contains(t) && !dismissed.contains(t)) add(out, "LD-011", verb, "the union-added trait " + t + " was removed without a signed dismissal", null);
        for (String r : ActionEffective.prulesViolations(d, strs(J.m(hint.get("eff")).get("prules")))) if (!OWN_RULES.contains(r)) add(out, "LD-012", verb, "structural rule " + r + " is required by the action's traits and violated", null);
        if (isReadOnly(effects)) {
            boolean enforced = d.get("context") instanceof List && J.a(d.get("context")).contains("sandbox_attested");
            for (String k : params(np, pn, q -> "code.command".equals(q.get("role")) || "query.sql".equals(q.get("role")))) if (!enforced) add(out, "LD-013", verb, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k);
            for (String k : params(np, pn, q -> tags(q).contains("credential"))) add(out, "LD-013", verb, "a read-only action handles a credential", k);
        }

        Object desc = d.get("description");
        if (desc == null) add(out, "LW-001", verb, "description is missing", null);
        else if (u8((String) desc) > 400) add(out, "LW-001", verb, "description is longer than 400 bytes", null);
        String title = (String) d.get("title");
        String first = firstWord(title).toLowerCase(java.util.Locale.ROOT);
        boolean sEnd = first.length() >= 2 && first.endsWith("s") && first.charAt(first.length() - 2) != 's';
        if (first.endsWith("ing") || first.endsWith("ed") || (sEnd && !(first.endsWith("us") || first.endsWith("is"))) || List.of("a", "an", "the").contains(first)) add(out, "LW-001", verb, "title '" + title + "' is not imperative", null);
        for (String k : params(np, pn, q -> "string".equals(q.get("type")) && q.get("max_len") == null && q.get("values") == null)) add(out, "LW-002", verb, "a string parameter without max_len (the default is 1024; say it)", k);
        if (cl.contains("pca.external_communication")) {
            for (String k : params(np, pn, q -> "string".equals(q.get("type")) && q.get("values") == null && q.get("format") == null && (q.get("role") == null || roleStarts(q, "text.")) && !tags(q).contains("free_text_outbound"))) {
                if (k.equals(idem.get("param"))) continue;
                add(out, "LW-003", verb, "free text flows into an outbound action without tags: [free_text_outbound]", k);
            }
        }
        String stability = opts == null ? null : (String) opts.get("stability");
        if ("stable".equals(stability) && ("unreviewed".equals(review.get("state")) || "suggested".equals(review.get("state")))) add(out, "LW-004", verb, "a " + review.get("state") + " def in a stable pack", null);
        Object dis = review.get("attestation") == null ? null : J.get(review.get("attestation"), "dismissed");
        if (dis instanceof List) for (Object x : J.a(dis)) if (J.jsTrim((String) J.get(x, "reason")).length() < 5) add(out, "LW-005", verb, "dismissed trait " + J.get(x, "trait") + " has no reason", null);
        for (String k : params(np, pn, q -> "array".equals(q.get("type")) && q.get("max_items") == null)) add(out, "LW-006", verb, "an array parameter without max_items", k);
        for (String k : params(np, pn, q -> "critical".equals(ActionsBridge.effectiveParamSensitivity(q)) && q.get("provenance_min") == null)) add(out, "LW-007", verb, "a critical parameter without provenance_min", k);
        boolean exNone = !(d.get("examples") instanceof List) || J.a(d.get("examples")).isEmpty();
        if ((tset.contains("pca.money_moving") || tset.contains("pca.destructive") || tset.contains("pca.privilege_change")) && exNone) add(out, "LW-009", verb, "no example for a money-moving, destructive or privilege-changing action", null);
        if (d.get("since") == null) add(out, "LW-010", verb, "since is missing", null);
    }

    private static List<String> strs(Object xs) { List<String> l = new ArrayList<>(); for (Object x : J.a(xs)) l.add((String) x); return l; }

    /** The first whitespace-separated token of a title ({@code title.split(/\s+/)[0]}: empty when the title starts with white space). */
    private static String firstWord(String t) {
        int i = 0;
        while (i < t.length() && !J.jsSpace(t.charAt(i))) i++;
        return t.substring(0, i);
    }

    /** Does the run fail? Errors always; warnings under {@code strict}. */
    public static boolean lintFails(List<?> fs, boolean strict) {
        for (Object f : fs) { Object s = J.get(f, "severity"); if ("error".equals(s) || (strict && "warning".equals(s))) return true; }
        return false;
    }

    private static String padEnd(String s, int n) { StringBuilder b = new StringBuilder(s); while (b.length() < n) b.append(' '); return b.toString(); }

    /** Plain text, one line per finding. */
    public static String lintText(List<?> fs) {
        if (fs.isEmpty()) return "0 errors, 0 warnings";
        int e = 0, w = 0;
        for (Object f : fs) { Object s = J.get(f, "severity"); if ("error".equals(s)) e++; else if ("warning".equals(s)) w++; }
        List<String> lines = new ArrayList<>();
        for (Object f : fs) {
            Object file = J.get(f, "file"), verb = J.get(f, "verb"), param = J.get(f, "param");
            boolean hasFile = file != null && !"".equals(file), hasVerb = verb != null && !"".equals(verb), hasParam = param != null && !"".equals(param);
            String loc = hasFile ? J.jsStr(file) + (J.get(f, "line") != null ? ":" + J.jsStr(J.get(f, "line")) + ":" + (J.get(f, "column") != null ? J.jsStr(J.get(f, "column")) : "1") : "") + ": " : "";
            lines.add(padEnd(J.jsStr(J.get(f, "severity")), 7) + " " + J.jsStr(J.get(f, "rule")) + "  " + loc + (hasVerb ? J.jsStr(verb) : "") + (hasParam ? " [" + J.jsStr(param) + "]" : "")
                + (hasVerb || hasParam ? ": " : "") + J.jsStr(J.get(f, "message")));
        }
        int notes = fs.size() - e - w;
        return String.join("\n", lines) + "\n" + e + " error" + (e == 1 ? "" : "s") + ", " + w + " warning" + (w == 1 ? "" : "s") + (notes > 0 ? ", " + notes + " note" + (notes == 1 ? "" : "s") : "");
    }

    private static String level(String s) { return "error".equals(s) ? "error" : "warning".equals(s) ? "warning" : "note"; }

    /** SARIF 2.1.0 so findings appear as pull request annotations. {@code tool}: {name?, version?}. */
    public static Map<String, Object> toSarif(List<?> fs, Map<String, Object> tool) {
        List<String[]> rules = new ArrayList<>();
        rules.add(STRUCTURE_RULE);
        rules.add(NOTE_RULE);
        rules.addAll(Arrays.asList(ActionLintRules.LINT_RULES));
        List<Object> rs = new ArrayList<>();
        for (String[] r : rules) rs.add(J.obj("id", r[0], "shortDescription", J.obj("text", r[2]), "defaultConfiguration", J.obj("level", level(r[1]))));
        Object name = tool == null ? null : tool.get("name"), version = tool == null ? null : tool.get("version");
        Map<String, Object> driver = J.obj("name", name != null ? name : "pca actions lint");
        if (version != null && !"".equals(version)) driver.put("version", version);
        driver.put("rules", rs);
        List<Object> results = new ArrayList<>();
        for (Object f : fs) {
            Object file = J.get(f, "file"), verb = J.get(f, "verb"), param = J.get(f, "param");
            boolean hasFile = file != null && !"".equals(file), hasVerb = verb != null && !"".equals(verb);
            Map<String, Object> loc = new LinkedHashMap<>();
            if (hasFile) {
                Map<String, Object> pl = J.obj("artifactLocation", J.obj("uri", file));
                if (J.get(f, "line") != null) pl.put("region", J.obj("startLine", J.get(f, "line"), "startColumn", J.get(f, "column") != null ? J.get(f, "column") : J.n(1)));
                loc.put("physicalLocation", pl);
            }
            if (hasVerb) loc.put("logicalLocations", J.list(J.obj("name", verb, "kind", "member")));
            String text = (hasVerb ? J.jsStr(verb) + (param != null && !"".equals(param) ? " [" + J.jsStr(param) + "]" : "") + ": " : "") + J.jsStr(J.get(f, "message"));
            results.add(J.obj("ruleId", J.get(f, "rule"), "level", level((String) J.get(f, "severity")), "message", J.obj("text", text), "locations", J.list(loc)));
        }
        return J.obj("$schema", "https://json.schemastore.org/sarif-2.1.0.json", "version", "2.1.0", "runs", J.list(J.obj("tool", J.obj("driver", driver), "results", results)));
    }
}
