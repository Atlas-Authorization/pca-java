package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * {@code authorize}: the full authorization pipeline for a resource server or tool guard (0.5, additive).
 *
 * <p>{@link Pca#verifyPcactn} answers "is this a validly signed PCActn for this audience". {@link #authorize} answers
 * "may THIS operation run now", in the same order as the TypeScript {@code authorize()}:
 * <ol>
 *   <li>configuration: {@code audience}, {@code resolveGrant}, {@code stateStore} and {@code isRevoked} are REQUIRED,
 *       and the call must name the {@link Operation} it will execute (verb, resource, params). A missing one denies
 *       with its name; nothing is ever downgraded to "not enforced".</li>
 *   <li>the core checks ({@link Pca#verifyPcactn}), then {@code revocation} ({@code isRevoked}), then
 *       {@code zk_compliance} (a carried proof cannot be verified here: fail closed).</li>
 *   <li>{@code operation}: the signed {@code action.verb} / {@code action.resource} equal the operation's, and the signed
 *       {@code action.params_digest} opens to exactly the operation's params. Those params are what the predicates and
 *       caveats read, so a $400 operation is judged as $400 even when the agent signed $50.</li>
 *   <li>{@code grant_ref}, {@code params_digest}, {@code plan_root_authorized} ({@code plan("single-step")} or a
 *       context plan), {@code attestation} (a grant whose {@code agent_binding} pins the agent needs an attestation
 *       verifier this SDK does not have: fail closed), {@code reversibility} (when the context names a class).</li>
 *   <li>policy: the envelope predicates (default deny), the envelope caveats and the ROOT caveats outside the envelope
 *       ({@code policy}), and the caveats delegation hops appended ({@code delegated_caveats}). {@code predicates} and
 *       {@code tool_schema} caveats are enforced against the operation; unknown caveat types fail closed.</li>
 *   <li>replay (check {@code replay}): only when everything above passes, the counter is consumed through {@link StateStore#claim}, one atomic
 *       compare-and-set per action (key {@link #stateKey}). A replayed or older counter denies.</li>
 * </ol>
 *
 * <p>Not ported from the TypeScript policy VM: the risk score, trust budget and threshold step-up. Never throws: any
 * internal error is a denial.
 */
public final class Authorize {
    private Authorize() {}

    public static final String ENVELOPE_CAVEAT = "envelope";
    /** The only plan mode: accept a one-node plan whose node is exactly the operation. */
    public static final String SINGLE_STEP = "single-step";

    /**
     * The checks that must be {@code pass} (not merely "not failed"): the TypeScript {@code DEFAULT_REQUIRED_CHECKS} plus
     * the operation binding and the policy. {@code require} can add names, never remove these.
     */
    public static final List<String> DEFAULT_REQUIRED_CHECKS = List.of("counter_format", "replay", "revocation",
        "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy");

    /** A failing one of these is an authentication failure (401), everything else is insufficient authority (403). */
    static final List<String> AUTHN_CHECKS = List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound",
        "leaf_signature", "malformed", "grant_ref");

    /** {@code (pcactn, grant) -> revoked?}: only {@code Boolean.FALSE} passes (null, true, or an exception denies). */
    @FunctionalInterface
    public interface RevocationCheck {
        Boolean isRevoked(Map<String, Object> pcactn, Map<String, Object> grant);
    }

    /** The operation the handler / tool WILL execute, from the server's own routing and parsed input, never from the PCActn. */
    public static final class Operation {
        public final String verb;
        public final String resource;
        /** A JSON object: a {@link Json} tree or plain Java values (Map, List, String, Boolean, numbers, null). */
        public final Map<String, ?> params;

        public Operation(String verb, String resource, Map<String, ?> params) {
            this.verb = verb;
            this.resource = resource;
            this.params = params;
        }

        public static Operation of(String verb, String resource, Map<String, ?> params) { return new Operation(verb, resource, params); }
    }

    /** The operation an allowing decision is bound to. {@code id} is the digest of the presented PCActn. */
    public static final class AuthorizedOperation {
        public final String verb;
        public final String resource;
        public final String paramsDigest;
        public final String id;

        AuthorizedOperation(String verb, String resource, String paramsDigest, String id) {
            this.verb = verb;
            this.resource = resource;
            this.paramsDigest = paramsDigest;
            this.id = id;
        }
    }

    /**
     * Outcome of {@link #authorize}. {@code allow} is the one thing a caller must branch on. {@code status} is 200, 401
     * (no / undecodable / unauthenticated proof) or 403. {@code checks} maps each check to {@code pass}, {@code fail} or
     * {@code not-enforced}; {@code reason} is the decisive one (an {@code operation} failure first; null on allow).
     * {@code missing} names absent configuration components (the call was refused before any verification).
     */
    public static final class AuthorizeResult {
        public final boolean allow;
        public final int status;
        public final Map<String, String> checks;
        public final List<String> reasons;
        public final String reason;
        public final AuthorizedOperation operation;
        public final Map<String, Object> pcactn;
        public final Pca.Verdict verdict;
        public final List<String> missing;

        AuthorizeResult(boolean allow, int status, Map<String, String> checks, List<String> reasons, String reason,
                        AuthorizedOperation operation, Map<String, Object> pcactn, Pca.Verdict verdict, List<String> missing) {
            this.allow = allow;
            this.status = status;
            this.checks = Collections.unmodifiableMap(checks);
            this.reasons = Collections.unmodifiableList(reasons);
            this.reason = reason;
            this.operation = operation;
            this.pcactn = pcactn;
            this.verdict = verdict;
            this.missing = missing == null ? null : Collections.unmodifiableList(missing);
        }

        /** The names of the failing checks, in check order. */
        public List<String> failed() {
            List<String> out = new ArrayList<>();
            for (Map.Entry<String, String> e : checks.entrySet()) if ("fail".equals(e.getValue())) out.add(e.getKey());
            return out;
        }
    }

    /** The inputs of {@link #authorize} (fluent setters). */
    public static final class Input {
        Operation operation;
        String audience;
        Function<String, Map<String, Object>> resolveGrant;
        StateStore stateStore;
        RevocationCheck isRevoked;
        Long now;
        String plan;
        Function<Map<String, Object>, Map<String, Object>> context;
        Pca.IntentPolicy intentPolicy;
        Function<Map<String, Object>, IntentV2.Context> intentV2;
        List<String> allowedSuites;
        List<String> require = List.of();

        /** What the handler / tool will execute (required). */
        public Input operation(Operation op) { this.operation = op; return this; }
        /** This resource server's id: the PCActn's signed {@code aud} must equal it (required). */
        public Input audience(String audience) { this.audience = audience; return this; }
        /** {@code grant_ref -> grant | null} from your own store (required). */
        public Input resolveGrant(Function<String, Map<String, Object>> resolveGrant) { this.resolveGrant = resolveGrant; return this; }
        /** The replay store (required): {@link MemoryStateStore}, {@link PcaJdbcStateStore}, or your database. */
        public Input stateStore(StateStore stateStore) { this.stateStore = stateStore; return this; }
        /** The revocation check (required): only {@code false} passes. */
        public Input isRevoked(RevocationCheck isRevoked) { this.isRevoked = isRevoked; return this; }
        /** Epoch milliseconds (default: the wall clock). */
        public Input now(long now) { this.now = now; return this; }
        /**
         * {@code "single-step"}: accept a one-node plan whose node is exactly this operation. Otherwise (null) the
         * {@link #context} must return the principal-authorized {@code plan} with {@code plan_authorized: true}.
         */
        public Input plan(String plan) { this.plan = plan; return this; }
        /**
         * {@code pcactn -> map | null} with optional {@code plan}, {@code plan_authorized}, {@code subject}, {@code env},
         * {@code blast_radius}, {@code recent_action_times}, {@code reversibility_class} (the server's authoritative
         * class; the agent may only declare a stricter one).
         */
        public Input context(Function<Map<String, Object>, Map<String, Object>> context) { this.context = context; return this; }
        /** Forwarded to {@link Pca#verifyPcactn}. */
        public Input intentPolicy(Pca.IntentPolicy intentPolicy) { this.intentPolicy = intentPolicy; return this; }
        /** Forwarded to {@link Pca#verifyPcactn}; its {@code params} default to the operation's. */
        public Input intentV2(IntentV2.Context intentV2) { this.intentV2 = intentV2 == null ? null : p -> intentV2; return this; }
        /** As above, computed per PCActn (an exception denies with {@code intent_v2}). */
        public Input intentV2(Function<Map<String, Object>, IntentV2.Context> intentV2) { this.intentV2 = intentV2; return this; }
        /** Forwarded to {@link Pca#verifyPcactn} (null = no suite policy). */
        public Input allowedSuites(List<String> allowedSuites) { this.allowedSuites = allowedSuites; return this; }
        /** Extra check names that must pass (the defaults always apply). */
        public Input require(List<String> require) { this.require = require == null ? List.of() : require; return this; }
        public Input require(String... require) { return require(Arrays.asList(require)); }
    }

    // ---- the store key -----------------------------------------------------------------------------------------------

    /** The store key of a holder's counter stream (the TypeScript {@code pcaStateKey} default scope). */
    public static String stateKey(String grantId, String leafHolder) { return grantId + ":" + leafHolder; }

    // ---- the envelope ------------------------------------------------------------------------------------------------

    private static String validateRiskPolicy(Object p) {
        if (!(p instanceof Map)) return "risk_policy must be an object";
        Map<?, ?> m = (Map<?, ?>) p;
        if (!(m.get("weights") instanceof Map)) return "risk_policy.weights missing";
        Map<?, ?> w = (Map<?, ?>) m.get("weights");
        for (String k : new String[] {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}) {
            Double v = Caveats.fin(w.get(k));
            if (v == null || v < 0) return "risk_policy.weights." + k + " must be finite and >= 0";
        }
        Map<String, Double> vals = new LinkedHashMap<>();
        for (String k : new String[] {"theta1", "theta2", "kappa", "lambda", "rho", "bMax"}) {
            Double v = Caveats.fin(m.get(k));
            if (v == null) return "risk_policy." + k + " must be finite";
            vals.put(k, v);
        }
        if (vals.get("theta1") < 0 || vals.get("theta2") < vals.get("theta1")) return "risk_policy requires 0 <= theta1 <= theta2";
        if (vals.get("kappa") <= 0) return "risk_policy.kappa must be > 0";
        if (vals.get("lambda") < 0 || vals.get("rho") < 0 || vals.get("bMax") < 0) return "risk_policy lambda/rho/bMax must be >= 0";
        return null;
    }

    /** The grant's policy envelope: its FIRST {@code envelope} caveat without {@code type}, or null when absent or malformed. */
    public static Map<String, Object> readEnvelope(Object grant) {
        try {
            Object cs = grant instanceof Map ? ((Map<?, ?>) grant).get("caveats") : null;
            if (!(cs instanceof List)) return null;
            Map<?, ?> cv = null;
            for (Object c : (List<?>) cs) {
                if (c instanceof Map && ENVELOPE_CAVEAT.equals(((Map<?, ?>) c).get("type"))) { cv = (Map<?, ?>) c; break; }
            }
            if (cv == null) return null;
            Map<String, Object> e = new LinkedHashMap<>();
            for (Map.Entry<?, ?> en : cv.entrySet()) if (!"type".equals(en.getKey())) e.put((String) en.getKey(), en.getValue());
            if (!(e.get("goal_commit") instanceof String)) return null;
            if (!(e.get("predicates") instanceof List) || !(e.get("caveats") instanceof List)) return null;
            if (!(e.get("agent_binding") instanceof Map) && !(e.get("agent_binding") instanceof List)) return null;
            if (validateRiskPolicy(e.get("risk_policy")) != null) return null;
            return e;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    /** Every root caveat except the first {@code envelope} one (TypeScript {@code rootCaveats}); a non-list is returned as is. */
    public static Object rootCaveats(Object grant) { return Caveats.rootCaveats(grant); }

    /** TypeScript {@code requiresAttestation}: any agent pin in {@code agent_binding} requires a bound attestation. */
    static boolean requiresAttestation(Object binding) {
        Map<?, ?> b = binding instanceof Map ? (Map<?, ?>) binding : Map.of();
        boolean hasMin = b.containsKey("min_measurement") && !"".equals(b.get("min_measurement"));
        return nonEmpty(b.get("model_allowlist")) || hasMin
            || (b.get("operator") instanceof String && !((String) b.get("operator")).isEmpty())
            || nonEmpty(b.get("weights_allowlist")) || nonEmpty(b.get("system_prompt_allowlist"))
            || nonEmpty(b.get("tool_manifest_allowlist")) || Boolean.TRUE.equals(b.get("require_hardware"))
            || Boolean.TRUE.equals(b.get("require_measured_weights"));
    }

    private static boolean nonEmpty(Object x) { return x instanceof List && !((List<?>) x).isEmpty(); }

    // ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) --------------------------------------

    public static final int MAX_SCHEMA_DEPTH = 8;
    public static final int MAX_SCHEMA_NODES = 256;
    public static final int MAX_OBJECT_PROPS = 64;
    public static final int MAX_ENUM_VALUES = 256;
    public static final int DEFAULT_MAX_ARRAY_ITEMS = 256;
    public static final int ABSOLUTE_MAX_ARRAY_ITEMS = 4096;
    public static final int DEFAULT_MAX_STRING_LEN = 65_536;
    public static final int ABSOLUTE_MAX_STRING_LEN = 1_048_576;
    public static final int MAX_VALUE_NODES = 10_000;

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9_]{1,64}");
    private static final Map<String, List<String>> SPEC_KEYS = Map.of(
        "string", List.of("type", "enum", "const", "minLength", "maxLength", "prefix"),
        "number", List.of("type", "enum", "const", "min", "max"),
        "integer", List.of("type", "enum", "const", "min", "max"),
        "boolean", List.of("type", "enum", "const"),
        "object", List.of("type", "props", "required"),
        "array", List.of("type", "items", "minItems", "maxItems"));

    /** The verdict of {@link #evaluateToolSchema}: {@code reason} is null when {@code ok}. */
    public static final class ToolSchemaResult {
        public final boolean ok;
        public final String reason;
        ToolSchemaResult(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
        @Override public String toString() { return "ToolSchemaResult{ok=" + ok + ", reason=" + reason + "}"; }
    }

    private static boolean isInt(Object x) {
        Double f = Caveats.fin(x);
        return f != null && f == Math.rint(f);
    }

    private static boolean nonNegInt(Object x, int mx) {
        Double f = Caveats.fin(x);
        return f != null && f == Math.rint(f) && f >= 0 && f <= mx;
    }

    private static boolean onlyKeys(Map<?, ?> o, List<String> allowed) {
        for (Object k : o.keySet()) if (!allowed.contains(k)) return false;
        return true;
    }

    /** JavaScript {@code ===} on the scalars a schema can hold (numbers compare as doubles; a bool is never a number). */
    private static boolean jsEq(Object a, Object b) {
        Double fa = Caveats.fin(a), fb = Caveats.fin(b);
        if (fa != null || fb != null) return fa != null && fb != null && fa.doubleValue() == fb.doubleValue();
        if (a instanceof Boolean || b instanceof Boolean) return a instanceof Boolean && a.equals(b);
        if (a instanceof String && b instanceof String) return a.equals(b);
        return false;
    }

    /** Validate a {@code tool_schema} argument schema (closed; shape, depth, node count, bounds). Null when valid. */
    public static String validateArgSchema(Object schema) {
        if (!(schema instanceof Map)) return "schema must be an object";
        Map<?, ?> s = (Map<?, ?>) schema;
        if (!onlyKeys(s, List.of("props", "required"))) return "unknown schema key";
        return objectSchemaError(s.get("props"), s.containsKey("required"), s.get("required"), 1, new int[1]);
    }

    private static String objectSchemaError(Object props, boolean hasRequired, Object required, int depth, int[] nodes) {
        if (depth > MAX_SCHEMA_DEPTH) return "schema too deep";
        if (++nodes[0] > MAX_SCHEMA_NODES) return "schema too large";
        if (!(props instanceof Map)) return "props must be an object";
        Map<?, ?> pm = (Map<?, ?>) props;
        if (pm.size() > MAX_OBJECT_PROPS) return "too many props";
        for (Map.Entry<?, ?> en : pm.entrySet()) {
            String n = (String) en.getKey();
            if (!SAFE_NAME.matcher(n).matches()) return "invalid property name '" + head(n, 32) + "'";
            String e = specError(en.getValue(), depth + 1, nodes);
            if (e != null) return n + ": " + e;
        }
        if (hasRequired) {
            if (!(required instanceof List) || ((List<?>) required).size() > MAX_OBJECT_PROPS) return "required must be a short array";
            for (Object r : (List<?>) required) if (!(r instanceof String) || !pm.containsKey(r)) return "required names an undeclared property";
        }
        return null;
    }

    private static String specError(Object specO, int depth, int[] nodes) {
        if (depth > MAX_SCHEMA_DEPTH) return "schema too deep";
        if (++nodes[0] > MAX_SCHEMA_NODES) return "schema too large";
        if (!(specO instanceof Map) || !(((Map<?, ?>) specO).get("type") instanceof String)
                || !SPEC_KEYS.containsKey(((Map<?, ?>) specO).get("type"))) return "unknown type";
        Map<?, ?> spec = (Map<?, ?>) specO;
        String t = (String) spec.get("type");
        if (!onlyKeys(spec, SPEC_KEYS.get(t))) return "unknown spec key";
        if (t.equals("object")) {
            nodes[0]--; // counted once by objectSchemaError
            return objectSchemaError(spec.get("props"), spec.containsKey("required"), spec.get("required"), depth, nodes);
        }
        if (t.equals("array")) {
            if (spec.containsKey("minItems") && !nonNegInt(spec.get("minItems"), ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad minItems";
            if (spec.containsKey("maxItems") && !nonNegInt(spec.get("maxItems"), ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad maxItems";
            if (spec.containsKey("minItems") && spec.containsKey("maxItems")
                    && Caveats.fin(spec.get("minItems")) > Caveats.fin(spec.get("maxItems"))) return "minItems > maxItems";
            return specError(spec.get("items"), depth + 1, nodes);
        }
        if (spec.containsKey("const") && !scalarOk(t, spec.get("const"))) return "bad const";
        if (spec.containsKey("enum")) {
            Object en = spec.get("enum");
            if (!(en instanceof List) || ((List<?>) en).isEmpty() || ((List<?>) en).size() > MAX_ENUM_VALUES) return "bad enum";
            for (Object x : (List<?>) en) if (!scalarOk(t, x)) return "bad enum";
        }
        if (t.equals("string")) {
            if (spec.containsKey("minLength") && !nonNegInt(spec.get("minLength"), ABSOLUTE_MAX_STRING_LEN)) return "bad minLength";
            if (spec.containsKey("maxLength") && !nonNegInt(spec.get("maxLength"), ABSOLUTE_MAX_STRING_LEN)) return "bad maxLength";
            if (spec.containsKey("minLength") && spec.containsKey("maxLength")
                    && Caveats.fin(spec.get("minLength")) > Caveats.fin(spec.get("maxLength"))) return "minLength > maxLength";
            if (spec.containsKey("prefix") && (!(spec.get("prefix") instanceof String) || ((String) spec.get("prefix")).length() > 512))
                return "bad prefix";
        } else if (t.equals("number") || t.equals("integer")) {
            if (spec.containsKey("min") && Caveats.fin(spec.get("min")) == null) return "bad min";
            if (spec.containsKey("max") && Caveats.fin(spec.get("max")) == null) return "bad max";
            if (spec.containsKey("min") && spec.containsKey("max") && Caveats.fin(spec.get("min")) > Caveats.fin(spec.get("max")))
                return "min > max";
        }
        return null;
    }

    private static boolean scalarOk(String t, Object v) {
        if (t.equals("string")) return v instanceof String && ((String) v).length() <= 1024;
        if (t.equals("boolean")) return v instanceof Boolean;
        return Caveats.fin(v) != null && (t.equals("number") || isInt(v));
    }

    /** The first {@code n} UTF-16 code units of {@code s}. */
    private static String head(String s, int n) { return s.length() <= n ? s : s.substring(0, n); }

    /** {@code JSON.stringify} of a property name, cut to 48 UTF-16 code units plus an ellipsis. */
    private static String show(String k) {
        String s = k.length() > 48 ? k.substring(0, 48) + "…" : k;
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    boolean lone = (Character.isHighSurrogate(c) && !(i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))))
                        || (Character.isLowSurrogate(c) && !(i > 0 && Character.isHighSurrogate(s.charAt(i - 1))));
                    if (c < 0x20 || lone) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String checkValue(Map<?, ?> spec, Object v, String path, int depth, int[] budget) {
        if (depth > MAX_SCHEMA_DEPTH + 1) return path + ": too deep";
        if (++budget[0] > MAX_VALUE_NODES) return path + ": too many values";
        Object t = spec.get("type");
        if ("object".equals(t)) {
            if (!(v instanceof Map)) return path + ": expected object";
            return checkObject((Map<?, ?>) spec.get("props"), spec.get("required"), (Map<?, ?>) v, path, depth, budget);
        }
        if ("array".equals(t)) {
            if (!(v instanceof List)) return path + ": expected array";
            List<?> l = (List<?>) v;
            double mx = Math.min(spec.containsKey("maxItems") ? Caveats.fin(spec.get("maxItems")) : DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS);
            if (l.size() > mx) return path + ": exceeds maxItems";
            if (spec.containsKey("minItems") && l.size() < Caveats.fin(spec.get("minItems"))) return path + ": below minItems";
            for (int i = 0; i < l.size(); i++) {
                String e = checkValue((Map<?, ?>) spec.get("items"), l.get(i), path + "[" + i + "]", depth + 1, budget);
                if (e != null) return e;
            }
            return null;
        }
        if ("string".equals(t)) {
            if (!(v instanceof String)) return path + ": wrong type (expected string)";
            int n = ((String) v).length();
            double mx = Math.min(spec.containsKey("maxLength") ? Caveats.fin(spec.get("maxLength")) : DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN);
            if (n > mx) return path + ": exceeds maxLength";
            if (spec.containsKey("minLength") && n < Caveats.fin(spec.get("minLength"))) return path + ": below minLength";
            if (spec.containsKey("prefix") && !((String) v).startsWith((String) spec.get("prefix"))) return path + ": violates prefix";
        } else if ("number".equals(t) || "integer".equals(t)) {
            Double f = Caveats.fin(v);
            if (f == null || ("integer".equals(t) && f != Math.rint(f))) return path + ": wrong type (expected " + t + ")";
            if (spec.containsKey("min") && f < Caveats.fin(spec.get("min"))) return path + ": below min";
            if (spec.containsKey("max") && f > Caveats.fin(spec.get("max"))) return path + ": above max";
        } else if ("boolean".equals(t)) {
            if (!(v instanceof Boolean)) return path + ": wrong type (expected boolean)";
        } else {
            return path + ": unknown type";
        }
        if (spec.containsKey("const") && !jsEq(spec.get("const"), v)) return path + ": violates const";
        if (spec.containsKey("enum")) {
            boolean any = false;
            for (Object e : (List<?>) spec.get("enum")) if (jsEq(e, v)) { any = true; break; }
            if (!any) return path + ": violates enum";
        }
        return null;
    }

    private static String checkObject(Map<?, ?> props, Object required, Map<?, ?> obj, String path, int depth, int[] budget) {
        for (Object k : obj.keySet()) if (!props.containsKey(k)) return path + ": unexpected argument " + show((String) k);
        if (required instanceof List) {
            for (Object r : (List<?>) required) if (!obj.containsKey(r)) return path + ": missing required argument '" + r + "'";
        }
        for (Map.Entry<?, ?> en : obj.entrySet()) {
            String e = checkValue((Map<?, ?>) props.get(en.getKey()), en.getValue(), path + "." + en.getKey(), depth + 1, budget);
            if (e != null) return e;
        }
        return null;
    }

    /** A tool call for {@link #evaluateToolSchema}: {@code {tool, args, tool_signature_digest?}}. */
    public static Map<String, Object> toolCall(String tool, Map<String, ?> args, String toolSignatureDigest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("tool", tool);
        m.put("args", args);
        if (toolSignatureDigest != null) m.put("tool_signature_digest", toolSignatureDigest);
        return m;
    }

    /**
     * Evaluate a tool call {@code {tool, args, tool_signature_digest?}} against a {@code tool_schema} caveat. Same rules
     * as the TypeScript {@code evaluateToolSchema}. Never throws.
     */
    public static ToolSchemaResult evaluateToolSchema(Object caveat, Object call) {
        try {
            if (!(caveat instanceof Map) || !"tool_schema".equals(((Map<?, ?>) caveat).get("type"))
                    || !(((Map<?, ?>) caveat).get("tool") instanceof String) || ((String) ((Map<?, ?>) caveat).get("tool")).isEmpty())
                return new ToolSchemaResult(false, "malformed tool_schema caveat");
            Map<?, ?> cv = (Map<?, ?>) caveat;
            String verr = validateArgSchema(cv.get("schema"));
            if (verr != null) return new ToolSchemaResult(false, "malformed tool_schema caveat: " + verr);
            if (!Pca.hashCanonical(cv.get("schema")).equals(cv.get("schema_digest"))) return new ToolSchemaResult(false, "schema digest mismatch");
            Map<String, Object> binding = new LinkedHashMap<>();
            binding.put("tool", cv.get("tool"));
            binding.put("signature_digest", IntentRevocation.jsText(cv.get("signature_digest"), cv.containsKey("signature_digest")));
            binding.put("schema", cv.get("schema"));
            if (!Pca.hashCanonical(binding).equals(cv.get("binding_digest"))) return new ToolSchemaResult(false, "binding digest mismatch");
            if (!(call instanceof Map) || !(((Map<?, ?>) call).get("tool") instanceof String) || !(((Map<?, ?>) call).get("args") instanceof Map))
                return new ToolSchemaResult(false, "malformed call");
            Map<?, ?> c = (Map<?, ?>) call;
            if (!c.get("tool").equals(cv.get("tool"))) return new ToolSchemaResult(false, "tool " + show((String) c.get("tool")) + " not authorized");
            if (c.containsKey("tool_signature_digest") && !java.util.Objects.equals(c.get("tool_signature_digest"), cv.get("signature_digest")))
                return new ToolSchemaResult(false, "signed tool_binding differs from the authorized tool signature");
            Map<?, ?> schema = (Map<?, ?>) cv.get("schema");
            String e = checkObject((Map<?, ?>) schema.get("props"), schema.get("required"), (Map<?, ?>) c.get("args"), "args", 1, new int[1]);
            return e != null ? new ToolSchemaResult(false, e) : new ToolSchemaResult(true, null);
        } catch (RuntimeException | StackOverflowError ex) {
            return new ToolSchemaResult(false, "evaluation error (fail closed)");
        }
    }

    // ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) ---------------------------------------------

    private static boolean agentCaveatSatisfied(Object cv, Map<String, Object> ctx, Map<String, Object> actionCtx, Map<String, Object> toolCall) {
        try {
            if (!(cv instanceof Map) || ctx == null) return false;
            Object t = ((Map<?, ?>) cv).get("type");
            if ("tool_schema".equals(t)) return evaluateToolSchema(cv, toolCall).ok;
            if ("predicates".equals(t)) {
                Object allow = ((Map<?, ?>) cv).get("allow");
                if (actionCtx == null || !(allow instanceof List)) return false;
                for (Object p : (List<?>) allow) if (Predicates.predicateMatches(p, actionCtx)) return true;
                return false;
            }
            // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
            return Caveats.evaluateCaveats(List.of(cv), ctx).ok;
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        }
    }

    /**
     * Evaluate caveats with the agent-native evaluator: the stock types of {@link Caveats#evaluateCaveats}, plus
     * {@code predicates} ({@code allow}: the action must match one predicate; needs {@code actionCtx} =
     * {@code {action: {...}, subject?, env?}}) and {@code tool_schema} (needs {@code toolCall}, see {@link #toolCall}).
     * {@code ctx} is the stock context ({@code now}, {@code action}, {@code blast_radius}, ...). Unknown types fail
     * closed. Never throws.
     */
    public static Caveats.Result evaluateAgentCaveats(Object caveats, Map<String, Object> ctx, Map<String, Object> actionCtx,
                                                      Map<String, Object> toolCall) {
        try {
            return SafeRegex.withBudget(() -> {
                List<String> failed = new ArrayList<>();
                if (!(caveats instanceof List)) {
                    failed.add("<malformed caveats>");
                    return new Caveats.Result(false, failed);
                }
                Map<String, Object> a = actionCtx == null ? new LinkedHashMap<>() : actionCtx;
                Map<String, Object> tc = toolCall == null ? new LinkedHashMap<>() : toolCall;
                for (Object cv : (List<?>) caveats) {
                    if (ctx == null) throw new IllegalArgumentException("ctx");
                    if (!agentCaveatSatisfied(cv, new LinkedHashMap<>(ctx), a, tc)) {
                        Object t = cv instanceof Map ? ((Map<?, ?>) cv).get("type") : null;
                        failed.add(t instanceof String ? (String) t : "<malformed>");
                    }
                }
                return new Caveats.Result(failed.isEmpty(), failed);
            });
        } catch (RuntimeException | StackOverflowError e) {
            return new Caveats.Result(false, new ArrayList<>(List.of("<evaluation error>")));
        }
    }

    // ---- authorize -----------------------------------------------------------------------------------------------------

    private static int classRank(Object c) {
        if (!(c instanceof String)) return 2;
        switch ((String) c) {
            case "reversible": return 0;
            case "rate_limited": case "costly": return 1;
            default: return 2;
        }
    }

    private static AuthorizeResult refuse(int status, String check, String reason, List<String> missing, Map<String, Object> p) {
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put(check, "fail");
        return new AuthorizeResult(false, status, checks, new ArrayList<>(List.of(reason)), reason, null, p, null, missing);
    }

    /** Names of the required components that are absent (empty = complete), in the order {@code authorize} reports them. */
    public static List<String> missingAuthorizeComponents(String audience, Object resolveGrant, Object stateStore, Object isRevoked) {
        List<String> missing = new ArrayList<>();
        if (audience == null || audience.isEmpty()) missing.add("audience");
        if (resolveGrant == null) missing.add("resolveGrant");
        if (stateStore == null) missing.add("stateStore");
        if (isRevoked == null) missing.add("isRevoked");
        return missing;
    }

    private static boolean validOperation(Operation op) {
        return op != null && op.verb != null && !op.verb.isEmpty() && op.resource != null && !op.resource.isEmpty() && op.params != null;
    }

    private static String decisive(Map<String, String> checks, List<String> reasons) {
        List<String> names = new ArrayList<>(checks.keySet());
        names.sort((x, y) -> Integer.compare(x.equals("operation") ? 0 : 1, y.equals("operation") ? 0 : 1)); // stable
        for (String n : names) {
            if (!"fail".equals(checks.get(n))) continue;
            for (String r : reasons) if (r.startsWith(n + ":")) return r;
        }
        return reasons.isEmpty() ? "denied" : reasons.get(0);
    }

    /** The operation params as a private strict JSON tree (canonical round trip); Java numbers become JSON numbers. */
    static Map<String, Object> copyParams(Map<String, ?> params) {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) Json.parse(Json.canonicalize(toTree(params, 0)));
        return m;
    }

    private static Object toTree(Object v, int depth) {
        if (depth > Json.MAX_LENIENT_DEPTH) throw new IllegalArgumentException("params nested too deep");
        if (v == null || v instanceof String || v instanceof Boolean || v instanceof Json.Num) return v;
        if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte || v instanceof BigInteger)
            return new Json.Num(v.toString());
        if (v instanceof BigDecimal) return new Json.Num(((BigDecimal) v).toString());
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (!Double.isFinite(d)) throw new IllegalArgumentException("params: non-finite number");
            return new Json.Num(Double.toString(d));
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!(e.getKey() instanceof String)) throw new IllegalArgumentException("params: non-string key");
                out.put((String) e.getKey(), toTree(e.getValue(), depth + 1));
            }
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(toTree(x, depth + 1));
            return out;
        }
        throw new IllegalArgumentException("params: unsupported type " + v.getClass().getSimpleName());
    }

    /** A parsed PCActn, or null with {@code err[0]} = "absent" / "undecodable". */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> coerce(Object pcactn, String[] err) {
        if (pcactn instanceof Map) return (Map<String, Object>) pcactn;
        String text = null;
        if (pcactn instanceof String) text = (String) pcactn;
        else if (pcactn instanceof byte[]) {
            byte[] b = (byte[]) pcactn;
            if (b.length > Pca.MAX_ARTIFACT_BYTES) { err[0] = "undecodable"; return null; }
            try {
                text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
            } catch (CharacterCodingException e) { err[0] = "undecodable"; return null; }
        } else {
            err[0] = pcactn == null ? "absent" : "undecodable";
            return null;
        }
        if (Pca.artifactTooLarge(text)) { err[0] = "undecodable"; return null; }
        Object obj;
        try { obj = Json.parse(text); } catch (RuntimeException e) { err[0] = "undecodable"; return null; }
        if (obj instanceof Map) return (Map<String, Object>) obj;
        err[0] = "undecodable";
        return null;
    }

    /**
     * Authorize ONE operation (see the class doc for the pipeline). {@code pcactn} is the presented PCActn: a parsed
     * object ({@link Json#parse} tree), or its JSON text / UTF-8 bytes (strict profile). Never throws.
     */
    public static AuthorizeResult authorize(Object pcactn, Input in) {
        try {
            return run(pcactn, in == null ? new Input() : in);
        } catch (RuntimeException | StackOverflowError e) { // never throw: an internal error denies
            return refuse(403, "authorize", "authorize: error (fail closed): " + e.getClass().getSimpleName(), null, null);
        }
    }

    @SuppressWarnings("unchecked")
    private static AuthorizeResult run(Object pcactn, Input in) {
        List<String> missing = missingAuthorizeComponents(in.audience, in.resolveGrant, in.stateStore, in.isRevoked);
        if (in.plan != null && !SINGLE_STEP.equals(in.plan)) missing.add("plan (only 'single-step' or null)");
        if (!missing.isEmpty())
            return refuse(403, "authorize_config", "authorize_config: missing required component(s): " + String.join(", ", missing)
                + " (fail closed)", missing, null);
        if (!validOperation(in.operation))
            return refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)", null, null);
        // a private copy: the params that are verified cannot change under the verifier
        String opVerb = in.operation.verb, opResource = in.operation.resource;
        Map<String, Object> opParams = copyParams(in.operation.params);

        String[] err = new String[1];
        Map<String, Object> p = coerce(pcactn, err);
        if (p == null)
            return refuse(401, "wire", "absent".equals(err[0]) ? "wire: no PCActn presented" : "wire: PCActn could not be decoded", null, null);
        Object grantRefO = p.get("grant_ref");
        if (!(grantRefO instanceof String)) return refuse(401, "malformed", "malformed: grant_ref is not a string", null, p);
        String grantRef = (String) grantRefO;
        Map<String, Object> grant;
        try {
            grant = in.resolveGrant.apply(grantRef);
        } catch (RuntimeException e) {
            return refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", null, p);
        }
        if (grant == null) return refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", null, p);

        long now = in.now != null ? in.now : System.currentTimeMillis();
        Map<String, Object> ctx = new LinkedHashMap<>();
        if (in.context != null) {
            Map<String, Object> c;
            try {
                c = in.context.apply(p);
            } catch (RuntimeException e) {
                return refuse(403, "context", "context: the context callback failed (fail closed)", null, p);
            }
            if (c != null) ctx = c;
        }

        IntentV2.Context v2 = null;
        if (in.intentV2 != null) {
            try {
                v2 = in.intentV2.apply(p);
            } catch (RuntimeException e) {
                return refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", null, p);
            }
        }
        if (v2 != null && v2.wellFormed && v2.get("params") == null) v2 = v2.withParams(opParams);

        // ---- 1. the core checks
        Pca.Verdict core = Pca.verifyPcactn(p, grant, now, in.audience, in.allowedSuites, in.intentPolicy, v2);
        if (Boolean.FALSE.equals(core.checks.get("wire"))) {
            String r = core.reason == null || core.reason.isEmpty() ? "wire: malformed PCActn" : core.reason;
            Map<String, String> wc = new LinkedHashMap<>();
            wc.put("wire", "fail");
            wc.put("malformed", "fail");
            return new AuthorizeResult(false, 401, wc, new ArrayList<>(List.of(r)), r, null, p, core, null);
        }
        Map<String, String> checks = new LinkedHashMap<>();
        for (Map.Entry<String, Boolean> e : core.checks.entrySet()) checks.put(e.getKey(), e.getValue() ? "pass" : "fail");
        List<String> reasons = new ArrayList<>();
        if (!core.allow && core.reason != null && !core.reason.isEmpty()) reasons.add(core.reason);

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        Boolean revoked;
        try {
            revoked = in.isRevoked.isRevoked(p, grant);
        } catch (RuntimeException e) {
            revoked = null;
        }
        if (Boolean.FALSE.equals(revoked)) checks.put("revocation", "pass");
        else fail(checks, reasons, "revocation", Boolean.TRUE.equals(revoked) ? "the grant is revoked" : "the revocation check failed (fail closed)");
        if (p.containsKey("zk_compliance"))
            fail(checks, reasons, "zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)");

        Map<String, Object> action = p.get("action") instanceof Map ? (Map<String, Object>) p.get("action") : new LinkedHashMap<>();
        Object signedDigest = action.get("params_digest");
        String opDigest = Pca.paramsDigest(opParams);

        // ---- 3. the operation binding
        if (!opVerb.equals(action.get("verb")) || !opResource.equals(action.get("resource"))) {
            fail(checks, reasons, "operation", "the proof is for " + IntentRevocation.jsText(action.get("verb"), action.containsKey("verb"))
                + " on " + IntentRevocation.jsText(action.get("resource"), action.containsKey("resource"))
                + ", but this operation is " + opVerb + " on " + opResource);
        } else if (!opDigest.equals(signedDigest)) {
            fail(checks, reasons, "operation", "the proof's params_digest does not match the params of this " + opVerb + " operation");
        } else {
            checks.put("operation", "pass");
        }

        // ---- 4. grant_ref, params, plan, attestation, reversibility
        if (grantRef.equals(grant.get("id"))) checks.put("grant_ref", "pass");
        else fail(checks, reasons, "grant_ref", "does not reference the supplied grant");
        if (opDigest.equals(signedDigest)) checks.put("params_digest", "pass");
        else fail(checks, reasons, "params_digest", "supplied params do not hash to action.params_digest");

        Map<String, Object> pl = p.get("plan") instanceof Map ? (Map<String, Object>) p.get("plan") : new LinkedHashMap<>();
        Object nodeId = pl.get("node_id");
        Object planNodes = ctx.get("plan");
        Object planAuthorized = ctx.get("plan_authorized");
        if (SINGLE_STEP.equals(in.plan) && planNodes == null) {
            Map<String, Object> node = new LinkedHashMap<>();
            node.put("id", IntentRevocation.jsText(nodeId, pl.containsKey("node_id")));
            node.put("verb", opVerb);
            node.put("resource", opResource);
            node.put("params_digest", opDigest);
            node.put("reversibility_class", action.get("reversibility_class"));
            planNodes = List.of(node);
            planAuthorized = Boolean.TRUE;
        }
        if (planNodes != null) {
            String known;
            try {
                List<Object> leaves = new ArrayList<>();
                for (Object n : (List<Object>) planNodes) {
                    Map<String, Object> nm = (Map<String, Object>) n;
                    leaves.add(Pca.planLeaf(nm.get("id"), nm, Pca.conditionsDigest(nm.get("pre"), nm.get("post"))));
                }
                known = Pca.merkleRoot(leaves);
            } catch (RuntimeException e) {
                known = null;
            }
            if (known == null || !known.equals(pl.get("root"))) fail(checks, reasons, "plan_root_authorized", "known plan does not match plan.root");
            else if (!Boolean.TRUE.equals(planAuthorized))
                fail(checks, reasons, "plan_root_authorized", "the plan root has not been authorized by the principal");
            else checks.put("plan_root_authorized", "pass");
        } else {
            checks.put("plan_root_authorized", "not-enforced");
        }

        Map<String, Object> env = readEnvelope(grant);
        if (requiresAttestation(env != null ? env.get("agent_binding") : null))
            fail(checks, reasons, "attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED "
                + "(no attestation verifier in this SDK: fail closed)");

        Object declared = action.get("reversibility_class");
        Object effective = declared;
        Object serverClass = ctx.get("reversibility_class");
        if (serverClass != null) {
            int dr = classRank(declared), sr = classRank(serverClass);
            if (dr < sr) fail(checks, reasons, "reversibility", "declared class '" + IntentRevocation.jsText(declared, action.containsKey("reversibility_class"))
                + "' is less restrictive than the authoritative '" + IntentRevocation.jsText(serverClass, true) + "'");
            else checks.put("reversibility", "pass");
            effective = dr > sr ? declared : serverClass;
        }

        // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
        List<Object> chain = p.get("cap_chain") instanceof List ? (List<Object>) p.get("cap_chain") : new ArrayList<>();
        int depth = Math.max(0, chain.size() - 1);
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("verb", action.get("verb"));
        inner.put("resource", action.get("resource"));
        inner.put("params", opParams);
        if (effective != null) inner.put("reversibility_class", effective);
        Map<String, Object> actionCtx = new LinkedHashMap<>();
        actionCtx.put("action", inner);
        if (ctx.get("subject") != null) actionCtx.put("subject", ctx.get("subject"));
        Object predEnv = v2Env(p, grant, v2, now, ctx.get("env"));
        if (predEnv != null) actionCtx.put("env", predEnv);
        Map<String, Object> toolCall = new LinkedHashMap<>();
        toolCall.put("tool", inner.get("verb") instanceof String ? inner.get("verb") : "");
        toolCall.put("args", opParams);
        if (p.get("tool_binding") instanceof String) toolCall.put("tool_signature_digest", p.get("tool_binding"));
        Object revClass = effective;
        if (revClass == null && nodeId instanceof String && planNodes instanceof List) {
            for (Object n : (List<?>) planNodes) {
                if (n instanceof Map && nodeId.equals(((Map<?, ?>) n).get("id"))) { revClass = ((Map<?, ?>) n).get("reversibility_class"); break; }
            }
        }
        Map<String, Object> cctx = new LinkedHashMap<>();
        cctx.put("now", now);
        cctx.put("action", inner);
        cctx.put("delegation_depth", depth);
        if (ctx.get("blast_radius") != null) cctx.put("blast_radius", ctx.get("blast_radius"));
        if (revClass != null) cctx.put("reversibility_class", revClass);
        if (ctx.get("recent_action_times") != null) cctx.put("recent_action_times", ctx.get("recent_action_times"));

        if (!chain.isEmpty()) {
            Map<String, Object> leaf = chain.get(chain.size() - 1) instanceof Map ? (Map<String, Object>) chain.get(chain.size() - 1) : new LinkedHashMap<>();
            List<Object> gcs = grant.get("caveats") instanceof List ? (List<Object>) grant.get("caveats") : new ArrayList<>();
            Object extra = null;
            if (leaf.get("caveats") instanceof List) {
                List<Object> lcs = (List<Object>) leaf.get("caveats");
                extra = gcs.size() >= lcs.size() ? new ArrayList<>() : new ArrayList<>(lcs.subList(gcs.size(), lcs.size()));
            }
            Caveats.Result r = evaluateAgentCaveats(extra, cctx, actionCtx, toolCall);
            if (r.ok) checks.put("delegated_caveats", "pass");
            else fail(checks, reasons, "delegated_caveats", "delegation caveat(s) not satisfied: " + String.join(", ", r.failed));
        }

        List<String> policyWhy;
        try {
            policyWhy = SafeRegex.withBudget(() -> {
                List<String> why = new ArrayList<>();
                if (env == null) return new ArrayList<>(List.of("grant carries no valid envelope"));
                Object preds = env.get("predicates");
                String denial = Predicates.denialReason(preds, actionCtx);
                if (denial != null) why.add(denial);
                Caveats.Result r = evaluateAgentCaveats(env.get("caveats"), cctx, actionCtx, toolCall);
                if (!r.ok) why.add("caveat(s) not satisfied: " + String.join(", ", r.failed));
                r = evaluateAgentCaveats(rootCaveats(grant), cctx, actionCtx, toolCall);
                if (!r.ok) why.add("root caveat(s) not satisfied: " + String.join(", ", r.failed));
                return why;
            });
        } catch (RuntimeException | StackOverflowError e) {
            policyWhy = List.of("policy evaluation error (fail closed)");
        }
        if (!policyWhy.isEmpty()) {
            checks.put("policy", "fail");
            for (String w : policyWhy) reasons.add("policy: " + w);
        } else {
            checks.put("policy", "pass");
        }

        // ---- required checks (default-deny), then the replay counter. `replay` passes tentatively; a refused claim flips it.
        checks.put("replay", "pass");
        List<String> required = new ArrayList<>(DEFAULT_REQUIRED_CHECKS);
        for (String n : in.require) if (n != null) required.add(n.equals("counter") ? "replay" : n); // `counter` is the old name of `replay`
        for (String name : required) {
            String st = checks.get(name);
            if (!"pass".equals(st) && !"fail".equals(st)) {
                checks.put(name, "fail");
                reasons.add(name + ": required check is " + (st == null ? "absent" : st)
                    + " (default-deny: not enforced by this resource server)");
            }
        }

        if (checks.containsValue("fail")) return deny(checks, reasons, p, core);

        Object holder = !chain.isEmpty() && chain.get(chain.size() - 1) instanceof Map ? ((Map<?, ?>) chain.get(chain.size() - 1)).get("holder") : null;
        long counter = Json.asLong(p.get("counter"));
        if (!(holder instanceof String) || !(grant.get("id") instanceof String)) {
            fail(checks, reasons, "replay", "no counter stream for this proof (fail closed)");
            return deny(checks, reasons, p, core);
        }
        StateStore.ClaimResult claimed;
        try {
            claimed = in.stateStore.claim(stateKey((String) grant.get("id"), (String) holder), counter);
        } catch (RuntimeException e) {
            claimed = null;
        }
        if (claimed == null || !claimed.ok) {
            if (claimed == null) fail(checks, reasons, "replay", "the replay store failed (fail closed)");
            else if (claimed.lastCounter != null) fail(checks, reasons, "replay", counter + " is not greater than last seen " + claimed.lastCounter + " (replay)");
            else fail(checks, reasons, "replay", counter + " was already claimed (replay)");
            return deny(checks, reasons, p, core);
        }
        return new AuthorizeResult(true, 200, checks, reasons, null,
            new AuthorizedOperation(opVerb, opResource, (String) signedDigest, Pca.hashCanonical(p)), p, core, null);
    }

    private static void fail(Map<String, String> checks, List<String> reasons, String name, String why) {
        checks.put(name, "fail");
        reasons.add(name + ": " + why);
    }

    private static AuthorizeResult deny(Map<String, String> checks, List<String> reasons, Map<String, Object> p, Pca.Verdict core) {
        boolean authn = false;
        for (String c : AUTHN_CHECKS) if ("fail".equals(checks.get(c))) authn = true;
        return new AuthorizeResult(false, authn ? 401 : 403, checks, reasons, decisive(checks, reasons), null, p, core, null);
    }

    /** The predicate {@code env}: the host's, with the verifier-computed Intent Layer v2 members (TypeScript {@code v2Env}). */
    private static Object v2Env(Map<String, Object> p, Map<String, Object> grant, IntentV2.Context v2, long now, Object env) {
        if (!p.containsKey("intent_session")) return env;
        Map<String, Object> rest = env instanceof Map ? new LinkedHashMap<>((Map<String, Object>) env) : new LinkedHashMap<>();
        for (String k : new String[] {"acc", "mon", "canon", "world", "prov", "class"}) rest.remove(k);
        for (Map.Entry<String, Object> e : IntentV2.decide(p, grant, v2, now).env.entrySet())
            if (e.getValue() != null) rest.put(e.getKey(), e.getValue());
        return rest;
    }

    /**
     * True only if {@code result} allowed exactly this operation (verb, resource, params digest). Call it where the side
     * effect runs, with the values it is about to use. Never throws.
     */
    public static boolean isAuthorizedFor(AuthorizeResult result, Operation operation) {
        try {
            AuthorizedOperation b = result != null && result.allow ? result.operation : null;
            if (b == null || !validOperation(operation)) return false;
            return b.verb.equals(operation.verb) && b.resource.equals(operation.resource)
                && b.paramsDigest.equals(Pca.paramsDigest(copyParams(operation.params)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The {@code authorize} components a guard adds on top of its audience / grant resolver: the opt-in of
     * {@code PcaFilter} (and the Spring interceptor). {@code plan} defaults to {@code "single-step"}.
     */
    public static final class Options {
        public final StateStore stateStore;
        public final RevocationCheck isRevoked;
        public final String plan;
        public final Function<Map<String, Object>, Map<String, Object>> context;
        public final List<String> require;

        public Options(StateStore stateStore, RevocationCheck isRevoked) {
            this(stateStore, isRevoked, SINGLE_STEP, null, List.of());
        }

        public Options(StateStore stateStore, RevocationCheck isRevoked, String plan,
                       Function<Map<String, Object>, Map<String, Object>> context, List<String> require) {
            this.stateStore = stateStore;
            this.isRevoked = isRevoked;
            this.plan = plan;
            this.context = context;
            this.require = require == null ? List.of() : List.copyOf(require);
        }

        /** Run {@link #authorize} with these options. */
        public AuthorizeResult run(Object pcactn, Operation operation, String audience, Function<String, Map<String, Object>> resolveGrant, long now) {
            return authorize(pcactn, new Input().operation(operation).audience(audience).resolveGrant(resolveGrant)
                .stateStore(stateStore).isRevoked(isRevoked).now(now).plan(plan).context(context).require(require));
        }
    }
}
