package net.atlasauth.pca.mcp;

import java.net.http.HttpRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.A2a;
import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.Agent;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.a2a.A2aPca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The Model Context Protocol adapter for Proof-Carrying Authority: wrap a tool handler so every call carries a fresh PCActn, derive a site
 * action schema from the tools an MCP server lists and check a tool call against it, attach the proof to a client transport request, and the
 * client half of MCP authorization step-up. Values are parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null).
 *
 * <p>This does not authorize: it attaches a proof-carrying action; the resource server's verifier decides. A bypassed wrapper just means
 * the action lacks a valid PCActn and fails server-side.
 *
 * <p>Differences from the TypeScript package, by design: the Java {@link Agent} builds the proof and carries its own audience, so there is no
 * local dry-run fast-fail, no per-call audience override and no provenance recorder here; {@link #withPca} turns a refused build
 * (the agent throws) into an MCP error result. The optional action-kit importer ({@code importActionDefsFromMcp}) is not ported (it needs an
 * optional experimental package); the v1 draft below is.
 */
public final class Mcp {
    private Mcp() {}

    /** The header a proof travels in. */
    public static final String PCA_ACTION_HEADER = Agent.HEADER;
    /** Key under which a tool result carries the encoded PCActn in its {@code _meta}. */
    public static final String RESULT_META_KEY = "x-pca-action";

    // ---------------------------------------------------------------------------------------------------------- handlers

    /** An MCP tool handler: {@code (args, extra) -> result} where the result is an MCP tool result map ({@code content}, optional {@code isError}). */
    @FunctionalInterface
    public interface ToolHandler { Map<String, Object> call(Map<String, Object> args, Object extra) throws Exception; }

    /** Which PCA action a tool is: the catalog {@code verb}, the resource (fixed, or derived from the args), and the optional proof receiver. */
    public static final class GuardToolSpec {
        public String verb;
        public String resource;
        public Function<Map<String, Object>, String> resourceOf;
        /** Receives the PCActn so the proof can be forwarded (for example as a request header) to the resource server. */
        public BiConsumer<Map<String, Object>, Map<String, Object>> onProof;
    }

    /** The tool error {@link #withPca} returns when the proof cannot be built: a text content item and {@code isError: true}. */
    public static Map<String, Object> deniedResult(String text) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("type", "text");
        item.put("text", text);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("content", new ArrayList<Object>(List.of(item)));
        r.put("isError", Boolean.TRUE);
        return r;
    }

    /**
     * Wrap a tool handler so each call builds a PCActn before the original handler runs. When the agent refuses to build the proof (it throws
     * IllegalArgumentException or IllegalStateException) the wrapper returns an MCP error result instead of throwing, so the model sees it.
     */
    public static ToolHandler withPca(Agent agent, GuardToolSpec spec, ToolHandler handler) {
        return (args, extra) -> {
            Map<String, Object> pca;
            try {
                String resource = spec.resourceOf != null ? spec.resourceOf.apply(args) : spec.resource;
                pca = agent.act(spec.verb, resource, args);
            } catch (IllegalArgumentException | IllegalStateException e) {
                return deniedResult(e.getMessage() == null ? "denied" : e.getMessage());
            }
            if (spec.onProof != null) spec.onProof.accept(pca, args);
            return handler.call(args, extra);
        };
    }

    /**
     * Attach the encoded PCActn into a result's {@code _meta} so a downstream gateway or resource server can read the proof off the tool
     * result. Additive: existing {@code content}, {@code isError} and {@code _meta} members are kept. {@code pca}: an object with {@code encoded}.
     */
    public static Map<String, Object> guardToolResult(Object pca, Object result) {
        Object encoded = pca instanceof Map ? ((Map<?, ?>) pca).get("encoded") : null;
        boolean hasEncoded = pca instanceof Map && ((Map<?, ?>) pca).containsKey("encoded");
        if (pca == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'encoded')");
        if (result == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading '_meta')");
        Object prev = result instanceof Map ? ((Map<?, ?>) result).get("_meta") : null;
        Map<String, Object> meta = JsVal.truthy(prev) && (prev instanceof Map || prev instanceof List) ? A2aPca.spread(prev) : new LinkedHashMap<String, Object>();
        if (hasEncoded) meta.put(RESULT_META_KEY, encoded);
        else meta.remove(RESULT_META_KEY); // assigning undefined replaces an earlier value and is not serialised
        Map<String, Object> out = A2aPca.spread(result);
        out.put("_meta", meta);
        return out;
    }

    /** {@link #guardToolResult(Object, Object)} for a proof already encoded as its header value. */
    public static Map<String, Object> guardToolResult(String encoded, Map<String, Object> result) {
        Map<String, Object> pca = new LinkedHashMap<>();
        pca.put("encoded", encoded);
        return guardToolResult(pca, result);
    }

    /** The request headers a proof travels in: {@code {PCA-Action: base64url(UTF-8 of the encoded PCActn JSON)}} (the provenance header is not produced here). */
    public static Map<String, String> pcaHeaders(String encoded) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put(PCA_ACTION_HEADER, net.atlasauth.pca.Keys.b64u(Json.utf8(encoded)));
        return h;
    }

    // ---------------------------------------------------------------------------------------------------------- client transport

    /** Which PCA action an MCP tool call is: {@code {verb, resource}}; null = send the call without a proof. */
    @FunctionalInterface
    public interface ToolActionMap { String[] map(String tool, Map<String, Object> args); }

    /** The {@code tools/call} a JSON-RPC body carries: {@code {name, arguments}} (arguments an object, {@code {}} when absent or not an object), else null. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toolCallOf(Object body) {
        if (!(body instanceof String)) return null;
        Object msg;
        try { msg = Json.parseLenient((String) body); } catch (RuntimeException e) { return null; }
        if (!(msg instanceof Map) || !"tools/call".equals(((Map<String, Object>) msg).get("method"))) return null;
        Object params = ((Map<String, Object>) msg).get("params");
        Object name = params instanceof Map ? ((Map<String, Object>) params).get("name") : null;
        Object args = params instanceof Map ? ((Map<String, Object>) params).get("arguments") : null;
        if (!(name instanceof String)) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", name);
        out.put("arguments", args instanceof Map ? args : new LinkedHashMap<String, Object>());
        return out;
    }

    /**
     * The agent side of an MCP server that requires a PCActn per tool call: for a JSON-RPC {@code tools/call} body, build a fresh proof for that call
     * (verb and resource from {@code toolAction}, the arguments committed by digest, a new counter) and add it as the {@code PCA-Action} header.
     * Every other request is returned unchanged. It decides nothing: the server's verifier does.
     */
    @SuppressWarnings("unchecked")
    public static HttpRequest.Builder withProof(Agent agent, ToolActionMap toolAction, HttpRequest.Builder request, String body) {
        Map<String, Object> call = toolCallOf(body);
        if (call == null) return request;
        String[] act = toolAction.map((String) call.get("name"), (Map<String, Object>) call.get("arguments"));
        if (act == null) return request;
        return Agent.attach(request, agent.act(act[0], act[1], (Map<String, Object>) call.get("arguments")));
    }

    // ---------------------------------------------------------------------------------------------------------- site action schema

    /** Anything that lists tools like an MCP client or server ({@code tools/list}): the result map carries {@code tools}. */
    @FunctionalInterface
    public interface ToolLister { Map<String, Object> listTools(); }

    /**
     * Draft an action schema from an MCP tool list. {@code site}: {@code site}, {@code aud}, {@code version}, optional {@code verbPrefix}.
     * Every write verb is drafted {@code irreversible} (the fail-closed default); the result is {@code {schema, todo}}.
     */
    public static Map<String, Object> draftActionSchemaFromMcp(List<Object> tools, Map<String, Object> site) { return McpDraft.draft(tools, site); }

    /** As {@link #draftActionSchemaFromMcp(List, Map)}, listing the tools from a client or server first. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> draftActionSchemaFromMcp(ToolLister source, Map<String, Object> site) {
        return McpDraft.draft((List<Object>) source.listTools().get("tools"), site);
    }

    private static final Pattern INT_KEY = Pattern.compile("0|[1-9][0-9]{0,8}");

    /** {@code Object.entries(o)} order: array-index keys ascending, then the others in insertion order. */
    private static List<Map.Entry<String, Object>> entries(Object o) {
        List<Map.Entry<String, Object>> out = new ArrayList<>();
        if (o == null) throw new IllegalStateException("TypeError: cannot convert undefined or null to object");
        List<String> keys = McpDraft.keysOf(o);
        List<String> ints = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : keys) (INT_KEY.matcher(k).matches() ? ints : rest).add(k);
        ints.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        for (String k : ints) out.add(new java.util.AbstractMap.SimpleEntry<>(k, McpDraft.valueOf(o, k)));
        for (String k : rest) out.add(new java.util.AbstractMap.SimpleEntry<>(k, McpDraft.valueOf(o, k)));
        return out;
    }

    /** {@code JSON.parse(JSON.stringify(v))} for parsed JSON: a deep copy where -0 becomes 0. */
    @SuppressWarnings("unchecked")
    private static Object copy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), copy(e.getValue()));
            return out;
        }
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(copy(x)); return out; }
        if (v instanceof Json.Num && "-0".equals(((Json.Num) v).raw)) return new Json.Num("0");
        return v;
    }

    /**
     * Record the developer's decisions on a draft (a new object). {@code d}: {@code verbs} (per verb {@code reversibility} and {@code params}: a partial
     * declaration per parameter path), optional {@code units}. A decision about a verb or parameter the draft does not have throws: the schema is
     * closed, so a typo must not silently publish a looser schema.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> applySchemaDecisions(Object draft, Map<String, Object> d) {
        Map<String, Object> out = (Map<String, Object>) copy(draft);
        if (JsVal.truthy(d.get("units"))) {
            Object u = out.get("units");
            Map<String, Object> merged = A2aPca.spread(u == null ? new LinkedHashMap<String, Object>() : u);
            merged.putAll(A2aPca.spread(d.get("units")));
            out.put("units", merged);
        }
        Object verbs = out.get("verbs");
        for (Map.Entry<String, Object> e : entries(d.get("verbs"))) {
            String verb = e.getKey();
            Object dv = e.getValue();
            if (!(verbs instanceof List)) throw new IllegalStateException("TypeError: out.verbs.find is not a function");
            Map<String, Object> v = null;
            for (Object x : (List<Object>) verbs) {
                if (x == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'verb')");
                if (x instanceof Map && verb.equals(((Map<String, Object>) x).get("verb"))) { v = (Map<String, Object>) x; break; }
            }
            if (v == null) throw new IllegalArgumentException("applySchemaDecisions: the draft has no verb '" + verb + "'");
            if (dv == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'reversibility')");
            Object rev = dv instanceof Map ? ((Map<String, Object>) dv).get("reversibility") : null;
            if (JsVal.truthy(rev)) v.put("reversibility", rev);
            Object dp = dv instanceof Map ? ((Map<String, Object>) dv).get("params") : null;
            for (Map.Entry<String, Object> pe : entries(dp == null ? new LinkedHashMap<String, Object>() : dp)) {
                Object params = v.get("params");
                Object p = params instanceof Map ? ((Map<String, Object>) params).get(pe.getKey()) : null;
                if (!JsVal.truthy(p)) throw new IllegalArgumentException("applySchemaDecisions: verb '" + verb + "' has no parameter '" + pe.getKey() + "'");
                if (p instanceof Map) ((Map<String, Object>) p).putAll(A2aPca.spread(pe.getValue()));
            }
        }
        return out;
    }

    /** The first verb entry that maps a tool ({@code mcp.tool}), or null. A verbs member that is not an array throws, as the reference does. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> entryOfTool(Object schema, Object toolName) {
        Object verbs = schema instanceof Map ? ((Map<String, Object>) schema).get("verbs") : null;
        if (schema == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'verbs')");
        if (!(verbs instanceof List)) throw new IllegalStateException("TypeError: schema.verbs.find is not a function");
        for (Object v : (List<Object>) verbs) {
            if (v == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'mcp')");
            Object mcp = v instanceof Map ? ((Map<String, Object>) v).get("mcp") : null;
            Object tool = mcp instanceof Map ? ((Map<String, Object>) mcp).get("tool") : null;
            if (tool != null && tool.equals(toolName)) return v instanceof Map ? (Map<String, Object>) v : null;
        }
        return null;
    }

    /** The schema verb an MCP tool maps to (by {@code mcp.tool}), or null. */
    public static String verbOfTool(Object schema, Object toolName) {
        Map<String, Object> e = entryOfTool(schema, toolName);
        return e != null && e.get("verb") instanceof String ? (String) e.get("verb") : null;
    }

    /** Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb): {@code {ok:true, verb}} or {@code {ok:false, code, path?, reason}}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> conformToolCall(Object schema, String toolName, Object args) {
        String verb = verbOfTool(schema, toolName);
        Map<String, Object> out = new LinkedHashMap<>();
        if (verb == null) {
            out.put("ok", false);
            out.put("code", "unknown_verb");
            out.put("reason", "MCP tool '" + toolName + "' is not declared by the site schema");
            return out;
        }
        ActionSchema.Conform c = ActionSchema.conform(schema, verb, args);
        if (c.ok) {
            out.put("ok", true);
            for (Object v : (List<Object>) ((Map<String, Object>) schema).get("verbs")) {
                if (v instanceof Map && verb.equals(((Map<String, Object>) v).get("verb"))) { out.put("verb", v); break; }
            }
            return out;
        }
        out.put("ok", false);
        out.put("code", c.code);
        if (c.path != null) out.put("path", c.path);
        out.put("reason", c.reason);
        return out;
    }

    // ---------------------------------------------------------------------------------------------------------- authorization step-up (client)

    private static final String JS_WS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    private static final Pattern NEED_PARAM = Pattern.compile("(?:^|[" + JS_WS + ",])pca_need=\"([^\"\\\\]*)\"");

    /** The need a {@code pca_need} auth-param carries, decoded ({@code {ok:true, need}} or {@code {ok:false, code}}); null when the header names none. */
    public static Map<String, Object> pcaNeedFromChallenge(Object header) {
        if (!(header instanceof String)) return null;
        Matcher m = NEED_PARAM.matcher((String) header);
        if (!m.find()) return null;
        A2a.Decoded d = A2a.decodeNeed(m.group(1));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", d.need != null);
        if (d.need != null) out.put("need", d.need); else out.put("code", d.code);
        return out;
    }

    /** Parse the value of a {@code WWW-Authenticate} header into its challenges ({@code scheme} lower-cased; {@code params} names lower-cased, quoted values unescaped, a repeated name keeps its first value). Never throws. */
    public static List<Map<String, Object>> parseChallenges(Object headerO) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!(headerO instanceof String)) return out;
        String h = (String) headerO;
        int n = h.length();
        int[] pos = {0};
        Map<String, Object> cur = null;
        skipWs(h, pos);
        while (pos[0] < n) {
            String name = token(h, pos);
            if (name.isEmpty()) { pos[0]++; continue; } // a stray quote or equals sign: skip it
            while (pos[0] < n && (h.charAt(pos[0]) == ' ' || h.charAt(pos[0]) == '\t')) pos[0]++;
            if (pos[0] < n && h.charAt(pos[0]) == '=') {
                pos[0]++;
                while (pos[0] < n && (h.charAt(pos[0]) == ' ' || h.charAt(pos[0]) == '\t')) pos[0]++;
                StringBuilder val = new StringBuilder();
                if (pos[0] < n && h.charAt(pos[0]) == '"') {
                    pos[0]++;
                    while (pos[0] < n && h.charAt(pos[0]) != '"') {
                        if (h.charAt(pos[0]) == '\\' && pos[0] + 1 < n) pos[0]++;
                        val.append(h.charAt(pos[0]));
                        pos[0]++;
                    }
                    pos[0]++; // closing quote
                } else val.append(token(h, pos));
                String key = name.toLowerCase(java.util.Locale.ROOT);
                // the reference stores params in a plain object: names it already inherits are never (re)written
                @SuppressWarnings("unchecked") Map<String, Object> params = cur == null ? null : (Map<String, Object>) cur.get("params");
                if (cur != null && !params.containsKey(key) && !key.equals("constructor") && !key.equals("__proto__")) params.put(key, val.toString());
            } else {
                cur = new LinkedHashMap<>();
                cur.put("scheme", name.toLowerCase(java.util.Locale.ROOT));
                cur.put("params", new LinkedHashMap<String, Object>());
                out.add(cur);
            }
            skipWs(h, pos);
        }
        return out;
    }

    private static void skipWs(String h, int[] pos) {
        while (pos[0] < h.length() && (h.charAt(pos[0]) == ' ' || h.charAt(pos[0]) == '\t' || h.charAt(pos[0]) == ',')) pos[0]++;
    }

    private static String token(String h, int[] pos) {
        int s = pos[0];
        while (pos[0] < h.length() && " \t,=\"".indexOf(h.charAt(pos[0])) < 0) pos[0]++;
        return h.substring(s, pos[0]);
    }

    private static List<String> splitScopes(Object s) {
        List<String> out = new ArrayList<>();
        if (!(s instanceof String)) return out;
        for (String x : ((String) s).split(" ", -1)) if (!x.isEmpty()) out.add(x);
        return out;
    }

    /**
     * What to do with a response. Only {@code 403} with {@code error="insufficient_scope"} on a Bearer challenge is a step-up. The new scope list is the UNION of
     * what was requested before and what the challenge names, sorted; with {@code pcaAware} a valid {@code pca_need} hands the typed requirement to the approval
     * flow and still carries the scope union as the fallback; a union that adds nothing (and no usable need) gives up instead of looping. The attempt counter
     * bounds every path. {@code state}: {@code requested} (scopes), {@code attempts}, optional {@code maxAttempts} (default 3) and {@code pcaAware}.
     * Result: {@code {action:"scope", scopes, attempts}}, {@code {action:"pca", need, fallbackScopes, attempts}} or {@code {action:"give_up", reason}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> planStepUp(Object status, Object wwwAuthenticate, Map<String, Object> state) {
        double max = state.get("maxAttempts") != null ? numOf(state.get("maxAttempts")) : 3;
        Map<String, Object> bearer = null;
        Double st = JsVal.num(status);
        if (st != null && st == 403.0) for (Map<String, Object> c : parseChallenges(wwwAuthenticate)) if ("bearer".equals(c.get("scheme"))) { bearer = c; break; }
        Map<String, Object> bparams = bearer == null ? null : (Map<String, Object>) bearer.get("params");
        if (bearer == null || !"insufficient_scope".equals(bparams.get("error"))) return giveUp("not_insufficient_scope");
        double attemptsIn = numOf(state.get("attempts"));
        if (!(Double.isFinite(attemptsIn) && attemptsIn < max)) return giveUp("retry_limit");
        List<Object> requested = (List<Object>) state.get("requested");
        Set<Object> had = new LinkedHashSet<>(requested);
        Set<String> u = new LinkedHashSet<>();
        for (Object r : requested) u.add(String.valueOf(r));
        u.addAll(splitScopes(bparams.get("scope")));
        List<String> union = new ArrayList<>(u);
        java.util.Collections.sort(union);
        double attempts = attemptsIn + 1;
        if (Boolean.TRUE.equals(state.get("pcaAware"))) {
            Map<String, Object> r = wwwAuthenticate instanceof String ? pcaNeedFromChallenge(wwwAuthenticate) : null;
            if (r != null && Boolean.TRUE.equals(r.get("ok"))) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("action", "pca");
                out.put("need", r.get("need"));
                out.put("fallbackScopes", new ArrayList<Object>(union));
                out.put("attempts", McpDraft.num(attempts));
                return out; // a missing or malformed pca_need is not an error: it falls through to the stock behaviour below
            }
        }
        boolean allHad = true;
        for (String s : union) if (!had.contains(s)) { allHad = false; break; }
        if (allHad) return giveUp("no_new_scope");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("action", "scope");
        out.put("scopes", new ArrayList<Object>(union));
        out.put("attempts", McpDraft.num(attempts));
        return out;
    }

    private static double numOf(Object o) { Double d = JsVal.num(o); return d == null ? Double.NaN : d; }

    private static Map<String, Object> giveUp(String reason) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("action", "give_up");
        out.put("reason", reason);
        return out;
    }

    /** The reason a present-but-unusable {@code pca_need} was ignored (for client logs), or null. */
    public static String pcaNeedProblem(Object wwwAuthenticate) {
        Map<String, Object> r = pcaNeedFromChallenge(wwwAuthenticate);
        return r != null && Boolean.FALSE.equals(r.get("ok")) ? (String) r.get("code") : null;
    }

    /**
     * RFC 9207 section 2.4 as tabulated in the MCP authorization specification: compare a present {@code iss} with the recorded issuer by plain string comparison
     * (no case folding, default-port elision, trailing-slash or percent-encoding normalization); reject an absent {@code iss} only when the server advertised
     * {@code authorization_response_iss_parameter_supported: true}. Without a recorded issuer nothing can be checked and the response is refused.
     * {@code a}: {@code recordedIssuer}, {@code issParameterSupported}, {@code iss} (absent or null differ: null never equals the recorded issuer).
     */
    public static Map<String, Object> checkAuthorizationResponseIss(Map<String, Object> a) {
        Map<String, Object> out = new LinkedHashMap<>();
        Object rec = a.get("recordedIssuer");
        if (!(rec instanceof String) || ((String) rec).isEmpty()) return iss(false, "no_recorded_issuer");
        if (!a.containsKey("iss")) return Boolean.TRUE.equals(a.get("issParameterSupported")) ? iss(false, "iss_missing") : iss(true, null);
        return rec.equals(a.get("iss")) ? iss(true, null) : iss(false, "iss_mismatch");
    }

    private static Map<String, Object> iss(boolean proceed, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("proceed", proceed);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    // ---------------------------------------------------------------------------------------------------------- conformance matrix (client side of step-up)

    public static final List<String> MCP_CLIENT_REVISIONS = List.of("2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft");

    private static Map<String, Object> row(String id, String requirement, String section, String a, String b, String c, String d, String e) {
        Map<String, Object> levels = new LinkedHashMap<>();
        String[] v = {a, b, c, d, e};
        for (int i = 0; i < MCP_CLIENT_REVISIONS.size(); i++) levels.put(MCP_CLIENT_REVISIONS.get(i), v[i]);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", id);
        r.put("requirement", requirement);
        r.put("levels", levels);
        r.put("section", section);
        return r;
    }

    /** The MCP authorization conformance matrix for the client side of step-up: one row per requirement, the level per specification revision. */
    public static List<Map<String, Object>> mcpAuthClientRows() {
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(row("parse-www-authenticate", "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "Protected Resource Metadata Discovery Requirements", "n/a", "MUST", "MUST", "MUST", "MUST"));
        rows.add(row("step-up-on-insufficient-scope", "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "Step-Up Authorization Flow", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"));
        rows.add(row("scope-union", "The new scope set is the union of the previously requested set and the challenge scopes.", "Step-Up Authorization Flow, step 2", "n/a", "n/a", "n/a", "SHOULD", "SHOULD"));
        rows.add(row("retry-limit", "Retry no more than a few times and track upgrade attempts per resource and operation.", "Step-Up Authorization Flow, step 4", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"));
        rows.add(row("iss-validation-table", "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "Authorization Response Validation", "n/a", "n/a", "n/a", "MUST", "MUST"));
        rows.add(row("pca-need-ignored-by-stock-client", "A client that does not know pca_need behaves exactly as without it.", "RFC 9110 section 11.2 (unknown auth-params are ignored)", "EXT", "EXT", "EXT", "EXT", "EXT"));
        return rows;
    }
}
