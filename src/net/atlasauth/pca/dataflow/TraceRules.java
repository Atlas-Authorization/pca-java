package net.atlasauth.pca.dataflow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.CaveatLang;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Trace rules: Invariant-style "never B after A" guardrails compiled into K1 {@code derive} caveats the verifier already
 * enforces over its own signed action history. A caveat only removes authority, so a compiled rule is a restriction by
 * construction. Compilation is fail-strict: anything the target cannot express exactly is a {@link TraceRuleError}.
 * Rules, selectors, verb tables and edges are JSON trees (Maps / Lists), as on the wire.
 */
public final class TraceRules {
    private TraceRules() {}

    public static final int MAX_TRACE_CAVEATS = 64;
    private static final int B_CHUNK = 8;
    private static final long WINDOW_MAX = CaveatLang.DERIVE_MAX_WINDOW_MS;

    public static final List<String> PRIVATE_READ_TRAITS = List.of("pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data");
    public static final List<String> EXTERNAL_SEND_TRAITS = List.of("pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure");

    /** A refusal to compile; {@link #code()} is the stable reason (id, syntax, duration, window, selector, unknown_tool, ...). */
    public static final class TraceRuleError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String code;

        public TraceRuleError(String code, String message) { super(message); this.code = code; }

        public String code() { return code; }
    }

    private static final String WS = " \\t\\n\\u000B\\f\\r\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF";
    private static final String DOT = "[^\\n\\r\\u2028\\u2029]";
    private static final Pattern RULE_ID_RE = Pattern.compile("[a-z][a-z0-9_]{0,39}");
    private static final Pattern VERB_RE = Pattern.compile("[A-Za-z0-9_.:/-]{1,256}");
    private static final Pattern DURATION_RE = Pattern.compile("([1-9][0-9]{0,9})(ms|s|m|h|d)");
    private static final Pattern RULE_RE = Pattern.compile("^[" + WS + "]*never[" + WS + "]+(" + DOT + "+?)[" + WS + "]+after[" + WS + "]+(" + DOT + "+?)[" + WS + "]+within[" + WS + "]+([^" + WS + "]+)[" + WS + "]*\\z");
    private static final Pattern HEAD_RE = Pattern.compile("^raise[" + WS + "]+(?:\"([^\"]*)\"|'([^']*)')[" + WS + "]+if:\\z");
    private static final Pattern FLOW_RE = Pattern.compile("^\\(([A-Za-z0-9_]+):[" + WS + "]*(ToolCall|ToolOutput|Message)\\)[" + WS + "]*->[" + WS + "]*\\(([A-Za-z0-9_]+):[" + WS + "]*(ToolCall|ToolOutput|Message)\\)\\z");
    private static final Pattern IS_TOOL_RE = Pattern.compile("^([A-Za-z0-9_]+)[" + WS + "]+is[" + WS + "]+tool:([A-Za-z0-9_.:/-]+)(\\(" + DOT + "*\\))?\\z");

    private static TraceRuleError err(String code, String m) { return new TraceRuleError(code, m); }

    private static boolean isWs(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }

    private static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && isWs(s.charAt(a))) a++;
        while (b > a && isWs(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    private static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    private static long duration(String t) {
        Matcher m = DURATION_RE.matcher(t);
        if (!m.matches()) throw err("duration", "'" + t + "' is not a duration like 10m, 2h or 7d");
        long unit;
        switch (m.group(2)) {
            case "ms": unit = 1; break;
            case "s": unit = 1000; break;
            case "m": unit = 60_000; break;
            case "h": unit = 3_600_000; break;
            default: unit = 86_400_000; break;
        }
        long ms = Long.parseLong(m.group(1)) * unit;
        if (ms > WINDOW_MAX) throw err("window", "a window of " + t + " exceeds the 30-day history the verifier keeps");
        return ms;
    }

    private static Map<String, Object> selector(String text, boolean neverSide) {
        List<Object> tools = new ArrayList<>(), traits = new ArrayList<>(), resources = new ArrayList<>();
        boolean any = false;
        for (String raw : text.split(",", -1)) {
            String a = trim(raw);
            if (a.equals("any")) any = true;
            else if (a.startsWith("tool:") && VERB_RE.matcher(a.substring(5)).matches()) tools.add(a.substring(5));
            else if (a.startsWith("trait:") && VERB_RE.matcher(a.substring(6)).matches()) traits.add(a.substring(6));
            else if (a.startsWith("resource:") && a.length() > 9 && a.length() <= 9 + 256) {
                if (neverSide) throw err("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)");
                resources.add(a.substring(9));
            } else throw err("selector", "'" + a + "' is not tool:<verb>, trait:<id>, resource:<prefix> or any");
        }
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("tools", tools);
        s.put("traits", traits);
        s.put("resources", resources);
        s.put("any", any);
        return s;
    }

    private static void checkId(String id) {
        if (!RULE_ID_RE.matcher(id).matches()) throw err("id", "rule id '" + id + "' must match ^[a-z][a-z0-9_]{0,39}$");
    }

    /** Parse {@code never <B> after <A> within <duration>}. Throws {@link TraceRuleError}. */
    public static Map<String, Object> parseTraceRule(String id, String text) { return parseTraceRuleImpl(id, text, false, null); }

    /** As {@link #parseTraceRule(String, String)} with a reason (a JSON null reason is carried as a null member). */
    public static Map<String, Object> parseTraceRule(String id, String text, Object reason) { return parseTraceRuleImpl(id, text, true, reason); }

    private static Map<String, Object> parseTraceRuleImpl(String id, String text, boolean hasReason, Object reason) {
        checkId(id);
        Matcher m = RULE_RE.matcher(text);
        if (!m.find()) throw err("syntax", "expected 'never <selector> after <selector> within <duration>', got '" + text + "'");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id);
        out.put("never", selector(m.group(1), true));
        out.put("after", selector(m.group(2), false));
        out.put("within_ms", n(duration(m.group(3))));
        if (hasReason) out.put("reason", reason);
        return out;
    }

    /**
     * Import the Invariant subset {@code raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)} plus {@code x is tool:<name>}
     * lines. {@code o.horizon} (a duration) is required; {@code o.dropUnsupported === true} turns an unsupported condition into a
     * listed removal (a weaker raise condition: strictly more refusals). Returns {rule, dropped}.
     */
    public static Map<String, Object> parseInvariantRule(String id, String text, Map<String, Object> o) {
        checkId(id);
        Object horizon = o == null ? null : o.get("horizon");
        if (!(horizon instanceof String)) throw err("horizon", "an Invariant rule has no window: pass the horizon explicitly");
        long withinMs = duration((String) horizon);
        List<String> lines = new ArrayList<>();
        for (String l : text.split("\n", -1)) {
            String t = trim(l);
            if (t.length() > 0 && !t.startsWith("#")) lines.add(t);
        }
        Matcher head = HEAD_RE.matcher(lines.isEmpty() ? "" : lines.get(0));
        if (!head.find()) throw err("syntax", "the first line must be raise \"<message>\" if:");
        Matcher flow = FLOW_RE.matcher(lines.size() < 2 ? "" : lines.get(1));
        if (!flow.find()) throw err("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)");
        String a = flow.group(1), ta = flow.group(2), b = flow.group(3), tb = flow.group(4);
        if (ta.equals("Message") || !tb.equals("ToolCall")) throw err("unsupported", "only a tool call or tool output followed by a tool call can be compiled");
        if (a.equals(b)) throw err("syntax", "the two events need distinct names");
        Map<String, List<Object>> tools = new LinkedHashMap<>();
        tools.put(a, new ArrayList<>());
        tools.put(b, new ArrayList<>());
        List<Object> dropped = new ArrayList<>();
        boolean drop = o != null && Boolean.TRUE.equals(o.get("dropUnsupported"));
        for (String l : lines.subList(Math.min(2, lines.size()), lines.size())) {
            Matcher m = IS_TOOL_RE.matcher(l);
            boolean hit = m.find();
            if (hit && tools.containsKey(m.group(1)) && m.group(3) == null) {
                tools.get(m.group(1)).add(m.group(2));
                continue;
            }
            if (drop) {
                // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
                if (hit && tools.containsKey(m.group(1))) tools.get(m.group(1)).add(m.group(2));
                dropped.add(l);
                continue;
            }
            throw err("unsupported", "'" + l + "' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead");
        }
        for (String v : new String[] {a, b}) {
            if (tools.get(v).size() > 1) throw err("unsatisfiable", "'" + v + "' is constrained to two different tools, so the rule can never fire");
        }
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("id", id);
        rule.put("never", sel(tools.get(b)));
        rule.put("after", sel(tools.get(a)));
        rule.put("within_ms", n(withinMs));
        rule.put("reason", head.group(1) != null ? head.group(1) : head.group(2) != null ? head.group(2) : "");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rule", rule);
        out.put("dropped", dropped);
        return out;
    }

    private static Map<String, Object> sel(List<Object> tools) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("tools", new ArrayList<>(tools));
        s.put("traits", new ArrayList<>());
        s.put("resources", new ArrayList<>());
        s.put("any", tools.isEmpty());
        return s;
    }

    // ---- compile ------------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o, String what) {
        if (!(o instanceof List)) throw new IllegalArgumentException("TypeError: " + what + " is not iterable");
        return (List<Object>) o;
    }

    private static List<String> expand(Map<?, ?> s, Map<?, ?> table, String what) {
        List<String> verbs = new ArrayList<>();
        for (Object k : table.keySet()) verbs.add((String) k);
        Collections.sort(verbs);
        Set<String> out = new LinkedHashSet<>();
        if (JsVal.truthy(s.get("any"))) out.addAll(verbs);
        for (Object t : list(s.get("tools"), "tools")) {
            if (!(t instanceof String) || !table.containsKey(t)) throw err("unknown_tool", what + ": tool '" + JsVal.str(t) + "' is not an action in the verb table");
            out.add((String) t);
        }
        for (Object tr : list(s.get("traits"), "traits")) {
            List<String> hit = new ArrayList<>();
            for (String v : verbs) if (list(JsVal.member(table.get(v), "traits"), "traits").contains(tr)) hit.add(v);
            if (hit.isEmpty()) throw err("empty_selector", what + ": trait '" + JsVal.str(tr) + "' matches no action");
            out.addAll(hit);
        }
        List<String> r = new ArrayList<>(out);
        Collections.sort(r);
        return r;
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Lower rules to K1 derive caveats over the verifier's history. Returns {caveats, edges, digest}; throws {@link TraceRuleError}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> compileTraceRules(Object rules, Map<String, Object> table) {
        List<Object> caveats = new ArrayList<>(), edges = new ArrayList<>();
        Set<Object> ids = new LinkedHashSet<>();
        for (Object ro : list(rules, "rules")) {
            Map<?, ?> r = (Map<?, ?>) ro;
            // `RULE_ID_RE.test(r.id)` coerces: a missing id reads as the text "undefined", which is a valid id
            String id = r.containsKey("id") ? JsVal.str(r.get("id")) : "undefined";
            Object idKey = r.containsKey("id") ? r.get("id") : "<missing>";
            if (!RULE_ID_RE.matcher(id).matches() || ids.contains(idKey)) throw err("id", "rule id '" + id + "' is malformed or repeated");
            ids.add(idKey);
            Object w = r.get("within_ms");
            if (!(JsVal.isSafeInteger(w) && JsVal.num(w) >= 1 && JsVal.num(w) <= WINDOW_MAX)) throw err("window", "rule '" + id + "': within_ms must be 1..30 days");
            Map<?, ?> never = (Map<?, ?>) r.get("never"), after = (Map<?, ?>) r.get("after");
            if (list(never.get("resources"), "resources").size() > 0) throw err("resource_on_effect", "rule '" + id + "': a resource selector cannot name the later action");
            List<String> bs = expand(never, table, "rule '" + id + "' never");
            List<Map<String, Object>> as = new ArrayList<>();
            for (String v : expand(after, table, "rule '" + id + "' after")) as.add(obj("verb", v));
            Set<String> prefixes = new LinkedHashSet<>();
            for (Object p : list(after.get("resources"), "resources")) prefixes.add((String) p);
            List<String> ps = new ArrayList<>(prefixes);
            Collections.sort(ps);
            for (String p : ps) as.add(obj("resource_prefix", p));
            if (bs.isEmpty() || as.isEmpty()) throw err("empty_selector", "rule '" + id + "': a side matches nothing");
            int cnt = 0;
            for (Map<String, Object> a : as) {
                for (int i = 0; i < bs.size(); i += B_CHUNK) {
                    List<Object> orArgs = new ArrayList<>();
                    for (String v : bs.subList(i, Math.min(i + B_CHUNK, bs.size()))) orArgs.add(obj("op", "eq", "a", obj("ref", "verb"), "b", obj("const", v)));
                    Map<String, Object> isB = obj("op", "or", "args", orArgs);
                    Map<String, Object> seen = obj("name", "seen", "kind", "count", "window_ms", w);
                    seen.putAll(a);
                    Map<String, Object> c = obj(
                        "type", "derive",
                        "id", "trace." + id + "." + (cnt++),
                        "defs", new ArrayList<Object>(Arrays.asList(seen, obj("name", "verb", "kind", "action", "field", "verb"), obj("name", "is_b", "kind", "expr", "expr", isB))),
                        "check", obj("op", "not", "arg", obj("op", "and", "args", new ArrayList<Object>(Arrays.asList(
                            obj("op", "gt", "a", obj("ref", "seen"), "b", obj("const", n(0))), obj("ref", "is_b"))))));
                    String e = CaveatLang.deriveError(c);
                    if (e != null) throw err("internal", "rule '" + id + "' compiled to an invalid caveat: " + e);
                    caveats.add(c);
                    if (caveats.size() > MAX_TRACE_CAVEATS) throw err("too_large", "more than " + MAX_TRACE_CAVEATS + " caveats: split the rule set or narrow the selectors");
                }
                for (String v : bs) {
                    edges.add(obj("rule", id, "from", a.containsKey("verb") ? obj("tool", a.get("verb")) : obj("resource", a.get("resource_prefix")), "to", v, "within_ms", w));
                }
            }
        }
        return obj("caveats", caveats, "edges", edges, "digest", Pca.hashCanonical(obj("d", "atlas-pca/trace-rules/v1", "caveats", caveats)));
    }

    // ---- lethal trifecta lint -----------------------------------------------------------------------------------------------

    private static boolean has(Object def, List<?> traits) {
        for (Object t : list(JsVal.member(def, "traits"), "traits")) if (traits.contains(t)) return true;
        return false;
    }

    private static boolean readOnly(Object def) {
        Object ef = JsVal.opt(def, "effects");
        List<Object> effects = ef == null ? new ArrayList<>() : list(ef, "effects");
        if (effects.isEmpty()) return false;
        for (Object e : effects) if (!"read".equals(e)) return false;
        return true;
    }

    /**
     * The lethal trifecta: private data, untrusted content and a way out in one action set. A send is cut off when every untrusted
     * read, or every private read, has an edge rule to it. A lint: it reports, it does not enforce. {@code o} = {untrusted?,
     * untrusted_traits?}; a null {@code o} throws, as JavaScript does reading a member of null.
     */
    public static Map<String, Object> lethalTrifecta(Map<String, Object> table, List<Object> edges, Map<String, Object> o) {
        List<String> verbs = new ArrayList<>();
        for (String k : table.keySet()) verbs.add(k);
        Collections.sort(verbs);
        Object untrustedO = o.get("untrusted"), untrustedTraitsO = o.get("untrusted_traits");
        List<Object> untrustedL = untrustedO == null ? new ArrayList<>() : list(untrustedO, "untrusted");
        List<Object> untrustedTraits = untrustedTraitsO == null ? new ArrayList<>() : list(untrustedTraitsO, "untrusted_traits");
        List<Object> priv = new ArrayList<>(), untrusted = new ArrayList<>(), sends = new ArrayList<>();
        for (String v : verbs) {
            Object def = table.get(v);
            if (has(def, PRIVATE_READ_TRAITS)) priv.add(v);
            if (untrustedL.contains(v) || has(def, untrustedTraits) || (readOnly(def) && list(JsVal.member(def, "traits"), "traits").contains("pca.network_egress"))) untrusted.add(v);
            if (has(def, EXTERNAL_SEND_TRAITS) && !readOnly(def)) sends.add(v);
        }
        List<Object> findings = new ArrayList<>();
        if (!priv.isEmpty() && !untrusted.isEmpty() && !sends.isEmpty()) {
            for (Object s : sends) {
                List<Object> fu = new ArrayList<>(), fp = new ArrayList<>();
                for (Object u : untrusted) if (!ruled(edges, u, s)) fu.add(u);
                for (Object p : priv) if (!ruled(edges, p, s)) fp.add(p);
                if (!fu.isEmpty() && !fp.isEmpty()) findings.add(obj("send", s, "from_untrusted", fu, "from_private", fp));
            }
        }
        return obj("private_reads", priv, "untrusted_reads", untrusted, "sends", sends, "findings", findings);
    }

    private static boolean ruled(List<Object> edges, Object from, Object to) {
        for (Object eo : list(edges, "edges")) {
            Object f = JsVal.member(eo, "from");
            if (f instanceof Map && ((Map<?, ?>) f).containsKey("tool") && from.equals(((Map<?, ?>) f).get("tool")) && to.equals(((Map<?, ?>) eo).get("to"))) return true;
        }
        return false;
    }
}
