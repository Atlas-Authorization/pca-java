package net.atlasauth.pca;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * PROVENANCE BY DEFAULT (0.5): an agent cannot be steered by injected content into choosing who, where or how much.
 *
 * <p>A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees bytes enter the model's context and holds a key the
 * model cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
 * ({@code principal}), a tool result ({@code tool}), a retrieved document ({@code retrieval}), a fetched page ({@code web}), and
 * finally the action the model chose ({@code action}, bound to the exact operation). The verifier re-derives every label from that
 * chain ({@link #decide}). A receipt that does not verify under a pinned mediator key, a chain with a gap, or no chain at all leaves
 * every value at {@code agent} (the top of the lattice {@code trusted < first_party < tool < web < agent}).
 *
 * <p>An action is SENSITIVE unless its definition says it only reads (effects exactly {@code read}, traits within
 * {@link #READ_SAFE_TRAITS}); an unknown action is sensitive. A sensitive action whose choice or any sink argument does not derive
 * from the principal is {@code escalate} (only a principal-signed escalation answer admits it); a forged or malformed chain is
 * {@code deny}. {@link Authorize#authorize} runs this gate by default (check {@code provenance_flow}); the only opt-out is the
 * grant envelope's signed member {@code provenance: {mode: "insecure_off"}}.
 *
 * <p>Token boundaries ({@link #occursAsToken}) are computed on UTF-16 code units, exactly as the reference. Everything here is
 * total: malformed input fails closed and nothing throws except the {@link Recorder} on a misuse by its own caller.
 */
public final class ArgProvenance {
    private ArgProvenance() {}

    public static final String RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\0";
    public static final String RECEIPT_REF_DOMAIN = "atlas-pca/prov-receipt-ref/v1";
    public static final String ACTION_DOMAIN = "atlas-pca/prov-action/v1";
    /** Request header carrying a bundle (base64url of its JSON). */
    public static final String HEADER = "PCA-Provenance";
    /** JSON body member carrying a bundle (when the header is absent). */
    public static final String BODY_MEMBER = "pca_provenance";
    public static final int MAX_RECEIPTS = 256;
    /** Largest principal message a bundle may carry (UTF-8 bytes). */
    public static final int MAX_CONTENT_BYTES = 65_536;
    /** Leaves examined per parameter; a larger value keeps the context label. */
    public static final int MAX_LEAVES = 4096;
    static final int MAX_DEPTH = 32;
    /** Mediator pins a grant envelope may name. */
    public static final int MAX_ENVELOPE_MEDIATORS = 16;

    public static final List<String> ORIGINS = List.of("principal", "tool", "retrieval", "web", "action");
    /** The label lattice, lowest first. */
    public static final List<String> LEVELS = List.of("trusted", "first_party", "tool", "web", "agent");
    static final List<String> FLOORS = List.of("first_party", "tool", "agent");
    /** Traits a read-only action may carry and still be non-sensitive. */
    public static final List<String> READ_SAFE_TRAITS = List.of("pca.financial_data_read", "pca.pii_access", "pca.regulated_data");

    static final String OUTCOME_PASS = "pass", OUTCOME_ESCALATE = "escalate", OUTCOME_DENY = "deny";
    private static final Pattern CONTENT_KEY = Pattern.compile("0|[1-9][0-9]{0,8}");

    static int rank(String level) { return LEVELS.indexOf(level); }
    static String join(String a, String b) { return rank(a) >= rank(b) ? a : b; }
    /** The level a segment of each origin carries; {@code action} (and anything unknown) is the top. */
    static String originLevel(Object origin) {
        if ("principal".equals(origin)) return "trusted";
        if ("tool".equals(origin) || "retrieval".equals(origin)) return "tool";
        if ("web".equals(origin)) return "web";
        return "agent";
    }

    private static boolean isOne(Object v) { return IntentJs.isInt(v) && IntentJs.lng(v) == 1L; }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    // ---- digests --------------------------------------------------------------------------------------------------------

    /** The digest an {@code action} receipt binds: the exact operation (verb, resource, params). Throws on a non-canonical value. */
    public static String actionDigest(String verb, String resource, Object params) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", ACTION_DOMAIN);
        m.put("verb", verb);
        m.put("resource", resource);
        m.put("params", params);
        return Pca.hashCanonical(m);
    }

    /** Content address of a receipt (signature included). */
    public static String receiptRef(Object receipt) { return IntentArtifacts.artifactRef(RECEIPT_REF_DOMAIN, "r", receipt); }

    // ---- wire -----------------------------------------------------------------------------------------------------------

    /** Is {@code k} a well-formed mediator pin {@code {mediator, kid, pk, pq_pk?}}? */
    public static boolean isMediatorPin(Object k) {
        if (!(k instanceof Map)) return false;
        Map<String, Object> m = obj(k);
        return IntentArtifacts.closedMembers(m, List.of("mediator", "kid", "pk"), List.of("pq_pk"), "pin") == null
            && IntentArtifacts.isBoundedString(m.get("mediator"), 256) && IntentArtifacts.isBoundedString(m.get("kid"), 64)
            && IntentArtifacts.isDigest(m.get("pk")) && IntentArtifacts.pinPqOk(m);
    }

    /** Wire validation of one receipt; null = well-formed. */
    public static String receiptWireError(Object r) {
        if (!(r instanceof Map)) return "a receipt must be an object";
        Map<String, Object> m = obj(r);
        String c = IntentArtifacts.closedMembers(m, List.of("v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at", "sig"),
            IntentArtifacts.SUITE_MEMBERS, "receipt");
        if (c != null) return c;
        if (!isOne(m.get("v")) || !"pca-prov".equals(m.get("kind"))) return "a receipt must be {v: 1, kind: \"pca-prov\"}";
        if (!IntentArtifacts.isBoundedString(m.get("mediator"), 256)) return "'mediator' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.isBoundedString(m.get("kid"), 64)) return "'kid' must be a non-empty string (<= 64 bytes)";
        if (!IntentArtifacts.isDigest(m.get("session"))) return "'session' must be canonical base64url (32 bytes)";
        if (!IntentJs.isNonNeg(m.get("seq"))) return "'seq' must be a non-negative safe integer";
        if (m.get("prev") != null && !IntentArtifacts.isDigest(m.get("prev"))) return "'prev' must be null or canonical base64url (32 bytes)";
        if (!ORIGINS.contains(m.get("origin"))) return "'origin' must be one of " + String.join(", ", ORIGINS);
        if (!IntentArtifacts.isBoundedString(m.get("source"), 256)) return "'source' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.isDigest(m.get("content_digest"))) return "'content_digest' must be canonical base64url (32 bytes)";
        if (!IntentJs.isNonNeg(m.get("issued_at"))) return "'issued_at' must be a non-negative safe integer";
        if (!(m.get("sig") instanceof String)) return "'sig' must be a string";
        return IntentArtifacts.artifactSuiteError(m);
    }

    /** Validate action facts {@code {effects?, traits?, params?}}; null = well-formed. */
    public static String actionInfoError(Object a) {
        if (!(a instanceof Map)) return "action info must be an object";
        Map<String, Object> m = obj(a);
        String c = IntentArtifacts.closedMembers(m, List.of(), List.of("effects", "traits", "params"), "action info");
        if (c != null) return c;
        for (String k : new String[] {"effects", "traits"}) {
            if (!m.containsKey(k)) continue;
            Object v = m.get(k);
            boolean ok = v instanceof List && ((List<?>) v).size() <= 64;
            if (ok) for (Object x : (List<?>) v) ok &= IntentArtifacts.isBoundedString(x, 128);
            if (!ok) return "action info '" + k + "' must be a list of strings";
        }
        if (m.containsKey("params")) {
            if (!(m.get("params") instanceof Map)) return "action info 'params' must be an object";
            Map<String, Object> ps = obj(m.get("params"));
            for (String k : Decision.jsKeys(ps))
                if (!IntentArtifacts.isBoundedString(k, 128) || !FLOORS.contains(ps.get(k))) return "action info param '" + k + "' must map to first_party | tool | agent";
        }
        return null;
    }

    /** Is an action with these facts non-sensitive (it only reads)? Null (unknown) facts are sensitive. */
    public static boolean isReadOnlyAction(Object a) {
        if (!(a instanceof Map)) return false;
        Object effects = obj(a).get("effects");
        if (!(effects instanceof List) || ((List<?>) effects).isEmpty()) return false;
        for (Object e : (List<?>) effects) if (!"read".equals(e)) return false;
        Object traits = obj(a).get("traits");
        if (traits == null) return true;
        if (!(traits instanceof List)) return false;
        for (Object t : (List<?>) traits) if (!READ_SAFE_TRAITS.contains(t)) return false;
        return true;
    }

    /** The grant envelope member {@code provenance}: {@code {mode?: "enforce" | "insecure_off", mediators?: Pin[] (<= 16)}}; null = well-formed. */
    public static String envelopeError(Object p) {
        if (!(p instanceof Map)) return "provenance must be an object";
        Map<String, Object> m = obj(p);
        String c = IntentArtifacts.closedMembers(m, List.of(), List.of("mode", "mediators"), "provenance");
        if (c != null) return c;
        if (m.containsKey("mode") && !"enforce".equals(m.get("mode")) && !"insecure_off".equals(m.get("mode"))) return "provenance.mode must be 'enforce' or 'insecure_off'";
        if (m.containsKey("mediators")) {
            Object ms = m.get("mediators");
            boolean ok = ms instanceof List && ((List<?>) ms).size() <= MAX_ENVELOPE_MEDIATORS;
            if (ok) for (Object x : (List<?>) ms) ok &= isMediatorPin(x);
            if (!ok) return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}";
        }
        return null;
    }

    // ---- tokens and leaves ----------------------------------------------------------------------------------------------

    /** Word characters for token boundaries: ASCII letters, digits, {@code _}, and every non-ASCII code unit (fewer matches: fail closed). */
    static boolean isWord(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80; }

    /**
     * Does {@code needle} occur in {@code text} as a whole token? An occurrence counts when the code unit before it is not a word
     * character (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, on UTF-16 code
     * units (Java strings are UTF-16, as the reference's); no normalization. An empty needle never occurs.
     */
    public static boolean occursAsToken(String text, String needle) {
        if (text == null || needle == null || needle.isEmpty()) return false;
        boolean headWord = isWord(needle.charAt(0));
        boolean tailWord = isWord(needle.charAt(needle.length() - 1));
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
            boolean okB = !headWord || i == 0 || !isWord(text.charAt(i - 1));
            int end = i + needle.length();
            boolean okA = !tailWord || end == text.length() || !isWord(text.charAt(end));
            if (okB && okA) return true;
        }
        return false;
    }

    /**
     * The text of every leaf of a JSON value: strings as they are, object keys (in {@code Object.keys} order) followed by their
     * values, other scalars in strict canonical form ({@code true}, {@code null}, {@code 120}, {@code 1.5}). Null when deeper than
     * 32 levels, larger than {@link #MAX_LEAVES} leaves, or not canonical (a lone surrogate is kept: strings are never canonicalized).
     */
    public static List<String> leaves(Object v) {
        List<String> out = new ArrayList<>();
        return walk(v, 0, out) ? out : null;
    }

    private static boolean walk(Object x, int depth, List<String> out) {
        if (depth > MAX_DEPTH || out.size() > MAX_LEAVES) return false;
        if (x instanceof String) out.add((String) x);
        else if (x instanceof List) {
            for (Object y : (List<?>) x) if (!walk(y, depth + 1, out)) return false;
        } else if (x instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) x;
            for (String k : Decision.jsKeys(m)) {
                out.add(k);
                if (!walk(m.get(k), depth + 1, out)) return false;
            }
        } else {
            try {
                out.add(Json.canonicalizeStrict(IntentJs.normalize(x)));
            } catch (RuntimeException e) {
                return false;
            }
        }
        return out.size() <= MAX_LEAVES;
    }

    private static List<String> sortU(java.util.Collection<String> xs) { return IntentJs.sortedUtf8(new LinkedHashSet<>(xs)); }

    // ---- the decision ---------------------------------------------------------------------------------------------------

    /** The inputs of {@link #decide}. {@code bundle} null = none; {@code action} null = unknown action (sensitive). */
    public static final class Input {
        public Object bundle;
        /** {@code {verb, resource, params}}. */
        public Object operation;
        /** The pinned mediator keys (a list of {@code {mediator, kid, pk, pq_pk?}}). */
        public Object mediators = List.of();
        public Object action;
        /** The principal authorized this exact operation (a node of an executable, principal-authorized registry plan). */
        public boolean principalPlan;
        /** The principal committed to this step (an admitted workflow step): the CHOICE is trusted, the values are not. */
        public boolean principalControl;
        /** Untrusted content THIS server saw reach the agent's context: a list of {@code {origin: tool|retrieval|web, source}}. */
        public Object observed;
    }

    /** The decision: {@code outcome} is {@code pass}, {@code escalate} or {@code deny}; {@code code} and {@code reason} are null on a pass. */
    public static final class Result {
        public final String outcome, code, reason;
        public final boolean sensitive, verified;
        /** The label of the action choice. */
        public final String control;
        /** The label of every top-level parameter. */
        public final Map<String, String> labels;
        /** Sink parameters whose label is above their floor (UTF-8 order). */
        public final List<String> tainted;
        /** {@code origin:source} of the untrusted content, plus {@code unlabelled} without a verified chain (UTF-8 order). */
        public final List<String> path;

        Result(String outcome, String code, String reason, Base b) {
            this.outcome = outcome;
            this.code = code;
            this.reason = reason;
            this.sensitive = b.sensitive;
            this.verified = b.verified;
            this.control = b.control;
            this.labels = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(b.labels));
            this.tainted = List.copyOf(b.tainted);
            this.path = List.copyOf(b.path);
        }

        /** The JSON form (the vector file's {@code expect} shape). */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            if (code != null) m.put("code", code);
            if (reason != null) m.put("reason", reason);
            m.put("sensitive", sensitive);
            m.put("verified", verified);
            m.put("control", control);
            m.put("labels", new LinkedHashMap<String, Object>(labels));
            m.put("tainted", new ArrayList<Object>(tainted));
            m.put("path", new ArrayList<Object>(path));
            return m;
        }
    }

    /** What is known so far: a deny keeps every member computed before the failing step. */
    private static final class Base {
        boolean sensitive = true, verified = false;
        String control = "agent";
        Map<String, String> labels = new LinkedHashMap<>();
        List<String> tainted = new ArrayList<>(), path = new ArrayList<>();
        Result deny(String code, String reason) { return new Result(OUTCOME_DENY, code, reason, this); }
    }

    private static final class Chain {
        boolean verified;
        String context = "agent";
        List<String> path = new ArrayList<>(List.of("unlabelled"));
        List<String> principalTexts = new ArrayList<>();
        String code, reason;
        static Chain bad(String code, String reason) { Chain c = new Chain(); c.code = code; c.reason = reason; return c; }
    }

    private static boolean operationOk(Object op) {
        if (!(op instanceof Map)) return false;
        Map<String, Object> m = obj(op);
        return IntentArtifacts.isBoundedString(m.get("verb"), 256) && m.get("resource") instanceof String && m.get("params") instanceof Map;
    }

    @SuppressWarnings("unchecked")
    private static Chain verifyChain(Object bundle, Map<String, Object> op, List<Object> pins) {
        if (bundle == null) return new Chain();
        if (!(bundle instanceof Map)) return Chain.bad("malformed_bundle", "the bundle must be an object");
        Map<String, Object> b = obj(bundle);
        String c = IntentArtifacts.closedMembers(b, List.of("v", "kind", "receipts"), List.of("contents"), "bundle");
        if (c != null) return Chain.bad("malformed_bundle", c);
        if (!isOne(b.get("v")) || !"pca-provenance".equals(b.get("kind"))) return Chain.bad("malformed_bundle", "the bundle must be {v: 1, kind: \"pca-provenance\"}");
        Object rs0 = b.get("receipts");
        if (!(rs0 instanceof List) || ((List<?>) rs0).isEmpty() || ((List<?>) rs0).size() > MAX_RECEIPTS)
            return Chain.bad("malformed_bundle", "the bundle must hold 1.." + MAX_RECEIPTS + " receipts");
        List<Object> rs = (List<Object>) rs0;
        for (int i = 0; i < rs.size(); i++) {
            String e = receiptWireError(rs.get(i));
            if (e != null) return Chain.bad("malformed_bundle", "receipt " + i + ": " + e);
        }
        Object contents0 = b.containsKey("contents") ? b.get("contents") : new LinkedHashMap<String, Object>();
        if (!(contents0 instanceof Map)) return Chain.bad("malformed_bundle", "'contents' must be an object");
        Map<String, Object> contents = obj(contents0);
        Map<String, Object> first = obj(rs.get(0));
        for (int i = 0; i < rs.size(); i++) {
            Map<String, Object> r = obj(rs.get(i));
            if (IntentJs.lng(r.get("seq")) != i) return Chain.bad("broken_chain", "receipt " + i + " has seq " + IntentRevocation.jsText(r.get("seq"), true));
            if (!r.get("session").equals(first.get("session")) || !r.get("mediator").equals(first.get("mediator")) || !r.get("kid").equals(first.get("kid")))
                return Chain.bad("broken_chain", "receipt " + i + " belongs to another session or mediator");
            boolean linked = i == 0 ? r.get("prev") == null : receiptRef(rs.get(i - 1)).equals(r.get("prev"));
            if (!linked) return Chain.bad("broken_chain", "receipt " + i + " does not link to its predecessor");
            if (i > 0 && IntentJs.lng(r.get("issued_at")) < IntentJs.lng(obj(rs.get(i - 1)).get("issued_at")))
                return Chain.bad("broken_chain", "receipt " + i + " is older than its predecessor");
        }
        Map<String, Object> last = obj(rs.get(rs.size() - 1));
        if (!"action".equals(last.get("origin")) || !last.get("source").equals(op.get("verb"))
            || !last.get("content_digest").equals(actionDigest((String) op.get("verb"), (String) op.get("resource"), op.get("params"))))
            return Chain.bad("unbound_action", "the last receipt is not the action receipt of this operation");
        for (String k : Decision.jsKeys(contents)) {
            Map<String, Object> r = null;
            if (CONTENT_KEY.matcher(k).matches()) {
                int idx = Integer.parseInt(k);
                if (idx < rs.size()) r = obj(rs.get(idx));
            }
            if (r == null || !"principal".equals(r.get("origin"))) return Chain.bad("malformed_bundle", "contents '" + k + "' does not name a principal receipt");
            Object text = contents.get(k);
            if (!(text instanceof String) || IntentJs.u8len((String) text) > MAX_CONTENT_BYTES)
                return Chain.bad("malformed_bundle", "contents '" + k + "' must be a string of at most " + MAX_CONTENT_BYTES + " bytes");
            String d;
            try {
                d = Pca.hashCanonical(text);
            } catch (RuntimeException e) {
                return Chain.bad("content_mismatch", "contents '" + k + "' is not canonical text");
            }
            if (!d.equals(r.get("content_digest"))) return Chain.bad("content_mismatch", "contents '" + k + "' does not hash to its receipt");
        }
        Map<String, Object> pin = null;
        for (Object p : pins) {
            Map<String, Object> pm = obj(p);
            if (pm.get("mediator").equals(first.get("mediator")) && pm.get("kid").equals(first.get("kid"))) { pin = pm; break; }
        }
        // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
        if (pin == null) return new Chain();
        for (int i = 0; i < rs.size(); i++)
            if (!IntentArtifacts.verifyArtifactSig(RECEIPT_DOMAIN, obj(rs.get(i)), pin.get("pk"), pin.get("pq_pk")))
                return Chain.bad("bad_signature", "receipt " + i + " does not verify under the pinned mediator key");
        Chain ch = new Chain();
        ch.verified = true;
        ch.path = new ArrayList<>();
        int before = 0;
        String context = "trusted";
        for (int i = 0; i < rs.size() - 1; i++) {
            Map<String, Object> r = obj(rs.get(i));
            if ("action".equals(r.get("origin"))) continue;
            before++;
            context = join(context, originLevel(r.get("origin")));
            if (!"principal".equals(r.get("origin"))) ch.path.add(r.get("origin") + ":" + r.get("source"));
        }
        if (before == 0) {
            context = "agent";
            ch.path.add("unlabelled");
        }
        ch.context = context;
        ch.path = sortU(ch.path);
        for (String k : Decision.jsKeys(contents)) ch.principalTexts.add((String) contents.get(k));
        return ch;
    }

    /**
     * The provenance decision for one operation. Steps, first failure wins:
     * <ol start="0">
     *   <li>inputs: pins, operation and action facts well-formed, else {@code deny} ({@code malformed_config} /
     *       {@code malformed_operation} / {@code malformed_action});</li>
     *   <li>the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing
     *       {@code issued_at}), the last receipt is the {@code action} receipt of this operation, every principal content hashes to
     *       its receipt, every signature verifies under the pinned (mediator, kid). A failure is {@code deny}; an unpinned mediator
     *       is ignored (no trust);</li>
     *   <li>server observations join into the context (raise only);</li>
     *   <li>control = {@code trusted} with {@code principalPlan} or {@code principalControl}, else the context;</li>
     *   <li>each top-level parameter: {@code trusted} with {@code principalPlan}; else the join over its leaves, where a leaf is
     *       {@code trusted} when the context is or it occurs as a token in a verified principal content;</li>
     *   <li>floors: the action's {@code params[p]}, else {@code first_party} for a sensitive action and {@code agent} otherwise;</li>
     *   <li>a sensitive action whose control is not {@code trusted}, or any tainted parameter, is {@code escalate}.</li>
     * </ol>
     * Never throws.
     */
    @SuppressWarnings("unchecked")
    public static Result decide(Input in) {
        Base base = new Base();
        try {
            if (in == null) return base.deny("malformed_config", "input must be an object");
            boolean pinsOk = in.mediators instanceof List;
            if (pinsOk) for (Object p : (List<?>) in.mediators) pinsOk &= isMediatorPin(p);
            if (!pinsOk) return base.deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}");
            if (!operationOk(in.operation)) return base.deny("malformed_operation", "the operation needs a verb, a resource and a params object");
            if (in.action != null) {
                String e = actionInfoError(in.action);
                if (e != null) return base.deny("malformed_action", e);
            }
            Object obs = in.observed == null ? List.of() : in.observed;
            boolean obsOk = obs instanceof List;
            if (obsOk) for (Object o : (List<?>) obs) {
                Object origin = o instanceof Map ? obj(o).get("origin") : null;
                obsOk &= ("tool".equals(origin) || "retrieval".equals(origin) || "web".equals(origin)) && IntentArtifacts.isBoundedString(obj(o).get("source"), 256);
            }
            if (!obsOk) return base.deny("malformed_config", "observations must be a list of {origin, source}");
            Map<String, Object> op = obj(in.operation);
            String verb = (String) op.get("verb");
            boolean sensitive = !isReadOnlyAction(in.action);
            base.sensitive = sensitive;
            Chain ch = verifyChain(in.bundle, op, (List<Object>) in.mediators);
            if (ch.code != null) return base.deny(ch.code, ch.reason);
            base.verified = ch.verified;
            String context = ch.context;
            List<String> path = new ArrayList<>(ch.path);
            for (Object o : (List<?>) obs) {
                context = join(context, originLevel(obj(o).get("origin")));
                path.add(obj(o).get("origin") + ":" + obj(o).get("source"));
            }
            base.path = sortU(path);
            boolean plan = in.principalPlan;
            String control = plan || in.principalControl ? "trusted" : context;
            base.control = control;
            Map<String, Object> params = obj(op.get("params"));
            Map<String, String> labels = new LinkedHashMap<>();
            for (String p : IntentJs.sortedUtf8(params.keySet())) {
                if (plan) {
                    labels.put(p, "trusted");
                    continue;
                }
                List<String> ls = leaves(params.get(p));
                if (ls == null) {
                    labels.put(p, context);
                    continue;
                }
                String l = "trusted";
                for (String leaf : ls) {
                    // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                    boolean typed = "trusted".equals(context);
                    for (int i = 0; !typed && i < ch.principalTexts.size(); i++) typed = occursAsToken(ch.principalTexts.get(i), leaf);
                    l = join(l, typed ? "trusted" : context);
                }
                labels.put(p, l);
            }
            base.labels = labels;
            Object floorsO = in.action instanceof Map ? obj(in.action).get("params") : null;
            Map<String, Object> floors = floorsO instanceof Map ? obj(floorsO) : new LinkedHashMap<>();
            List<String> tainted = new ArrayList<>();
            for (Map.Entry<String, String> e : labels.entrySet()) {
                String f = floors.containsKey(e.getKey()) ? (String) floors.get(e.getKey()) : sensitive ? "first_party" : "agent";
                if (rank(e.getValue()) > rank(f)) tainted.add(e.getKey());
            }
            base.tainted = sortU(tainted);
            // no segment origin maps to first_party, so a control label is trusted or untrusted
            boolean badControl = sensitive && !"trusted".equals(control);
            if (!badControl && base.tainted.isEmpty()) return new Result(OUTCOME_PASS, null, null, base);
            String where = base.path.isEmpty() ? "" : " [" + String.join(", ", base.path) + "]";
            String code = badControl && !base.tainted.isEmpty() ? "untrusted_control_and_args" : badControl ? "untrusted_control" : "untrusted_args";
            List<String> parts = new ArrayList<>();
            if (badControl) parts.add("the choice of " + verb + " derives from untrusted content");
            if (!base.tainted.isEmpty()) parts.add(String.join(", ", base.tainted) + (base.tainted.size() == 1 ? " derives" : " derive") + " from untrusted content");
            return new Result(OUTCOME_ESCALATE, code, String.join("; ", parts) + where + ": the principal must confirm (prompt-injection path)", base);
        } catch (RuntimeException | StackOverflowError e) {
            return base.deny("malformed_config", "evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    // ---- the request side -----------------------------------------------------------------------------------------------

    /**
     * The bundle a request presents: header {@code PCA-Provenance} (strict unpadded base64url of the JSON, strict UTF-8, strict
     * JSON), else the JSON body member {@code pca_provenance}. Null when neither is present or the body is not readable JSON.
     * Throws {@link IllegalArgumentException} when the header is present but does not decode or parse (the gate then fails closed).
     */
    public static Object requestBundle(String header, byte[] body) {
        if (header != null && !header.isEmpty()) {
            String text = Pca.decodePcaHeader(header);
            if (text == null) throw new IllegalArgumentException("the PCA-Provenance header is not canonical base64url of UTF-8");
            return Json.parse(text);
        }
        if (body == null || body.length == 0) return null;
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            Object env = Json.parse(text);
            return env instanceof Map ? obj(env).get(BODY_MEMBER) : null;
        } catch (CharacterCodingException | RuntimeException e) {
            return null; // an unparsable body carries no bundle
        }
    }

    /**
     * The bundle presented with ONE call: either the bundle itself ({@link #bundle}; null = explicitly none) or the request it is
     * read from ({@link #request}: header, else body member). An explicit bundle wins over the gate's {@code bundle} function, which
     * wins over the request.
     */
    public static final class Presented {
        final boolean explicit;
        final Object bundle;
        final String header;
        final byte[] body;
        private Presented(boolean explicit, Object bundle, String header, byte[] body) { this.explicit = explicit; this.bundle = bundle; this.header = header; this.body = body; }
        /** The bundle for this call ({@link Recorder#forAction}); null means "no bundle" (unlabelled), never "read the request". */
        public static Presented bundle(Object bundle) { return new Presented(true, bundle, null, null); }
        /** Read the bundle from the request: the raw {@code PCA-Provenance} header value (may be null) and body bytes (may be null). */
        public static Presented request(String header, byte[] body) { return new Presented(false, null, header, body == null ? null : body.clone()); }
    }

    /** Untrusted content THIS server saw reach the agent's context in this session (raise only), e.g. a gateway's own log. */
    @FunctionalInterface
    public interface Observed {
        /** {@code session} is the bundle's session id, or null. Returns a list of {@code {origin, source}} (null: none). */
        List<?> observed(Map<String, Object> pcactn, Authorize.Operation operation, String session);
    }

    /**
     * The gate's configuration ({@link Authorize.Input#provenanceGate}, {@link Authorize.Options#withProvenance}). Every member is
     * optional; the gate runs without any (then no chain verifies and a sensitive action escalates).
     */
    public static final class Options {
        List<Object> mediators = List.of();
        Function<Authorize.Operation, Map<String, Object>> actions;
        Observed observed;
        BiFunction<Map<String, Object>, Authorize.Operation, Object> bundle;

        /** Pinned mediator keys {@code {mediator, kid, pk, pq_pk?}} (the agent harness, gateway or MCP client that labels segments); the grant envelope may add more. */
        public Options mediators(List<?> mediators) { this.mediators = mediators == null ? List.of() : List.copyOf(mediators); return this; }
        /** The facts {@code {effects?, traits?, params?}} of the action about to run, from YOUR action definitions; null = unknown (sensitive). */
        public Options actions(Function<Authorize.Operation, Map<String, Object>> actions) { this.actions = actions; return this; }
        public Options observed(Observed observed) { this.observed = observed; return this; }
        /** Supply the bundle per call {@code (pcactn, operation) -> bundle} instead of reading the request (an exception: unreadable, fail closed). */
        public Options bundle(BiFunction<Map<String, Object>, Authorize.Operation, Object> bundle) { this.bundle = bundle; return this; }
    }

    // ---- the mediator side ----------------------------------------------------------------------------------------------

    /**
     * The mediator side: one recorder per agent session. It must run where the bytes enter the model's context (the harness that
     * builds the prompt, a gateway, an MCP client), with a key the model cannot reach. The verifier pins {@link #pin()} (or the
     * principal names it in the grant envelope's {@code provenance.mediators}). Thread-safe.
     */
    public static final class Recorder {
        private final String mediator, kid, session;
        private final Keys.SuiteKey key;
        private final LongSupplier now;
        private final Map<String, Object> pin;
        private final List<Map<String, Object>> chain = new ArrayList<>();
        private final Map<String, Object> contents = new LinkedHashMap<>();

        /**
         * @param key     the mediator key (Ed25519, or a hybrid suite with its Ed25519 half); a pure post-quantum key has no pin {@code pk}
         * @param session canonical base64url of 32 bytes, or null for a random one
         * @param now     the clock (null: the wall clock)
         */
        public Recorder(String mediator, String kid, Keys.SuiteKey key, String session, LongSupplier now) {
            if (!IntentArtifacts.isBoundedString(mediator, 256) || !IntentArtifacts.isBoundedString(kid, 64))
                throw new IllegalArgumentException("Recorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required");
            if (key == null || key.ed == null) throw new IllegalArgumentException("Recorder: an Ed25519 (or hybrid) mediator key is required");
            String s = session;
            if (s == null) {
                byte[] b = new byte[32];
                new SecureRandom().nextBytes(b);
                s = Pca.b64(b);
            }
            if (!IntentArtifacts.isDigest(s)) throw new IllegalArgumentException("Recorder: session must be canonical base64url of 32 bytes");
            this.mediator = mediator;
            this.kid = kid;
            this.key = key;
            this.session = s;
            this.now = now == null ? System::currentTimeMillis : now;
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("mediator", mediator);
            p.put("kid", kid);
            p.put("pk", key.ed.id());
            if (key.pqPk() != null) p.put("pq_pk", key.pqPk());
            this.pin = java.util.Collections.unmodifiableMap(p);
        }

        /** A recorder with a fresh random Ed25519 key and session (pin {@link #pin()}). */
        public static Recorder create(String mediator, String kid) { return new Recorder(mediator, kid, Keys.ed25519(Keys.edGenerate()), null, null); }

        public String session() { return session; }
        /** The pin a verifier (or the principal's grant envelope) must carry for this recorder. */
        public Map<String, Object> pin() { return pin; }

        /** The principal's own message (TRUSTED). */
        public synchronized Map<String, Object> principal(String text) { return segment("principal", "user", text); }
        /** A tool result (UNTRUSTED). Non-string output is recorded as its canonical JSON text. */
        public synchronized Map<String, Object> tool(String name, Object output) { return segment("tool", name, output); }
        /** A retrieved document (UNTRUSTED). */
        public synchronized Map<String, Object> retrieval(String source, Object content) { return segment("retrieval", source, content); }
        /** A fetched web page or HTTP response (UNTRUSTED). */
        public synchronized Map<String, Object> web(String url, Object content) { return segment("web", url, content); }

        /** Record the chosen action and return the bundle to present with it ({@code PCA-Provenance} header or {@code pca_provenance}). */
        public synchronized Map<String, Object> forAction(Authorize.Operation op) {
            if (chain.size() >= MAX_RECEIPTS)
                throw new IllegalStateException("provenance: the session holds " + MAX_RECEIPTS + " receipts; start a new session with the principal's message");
            Map<String, Object> params = Authorize.copyParams(op.params);
            append("action", op.verb, actionDigest(op.verb, op.resource, params));
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("v", 1L);
            b.put("kind", "pca-provenance");
            b.put("receipts", new ArrayList<Object>(chain));
            if (!contents.isEmpty()) b.put("contents", new LinkedHashMap<>(contents));
            return b;
        }

        /** Every receipt so far. */
        public synchronized List<Map<String, Object>> receipts() { return List.copyOf(chain); }

        private Map<String, Object> segment(String origin, String source, Object content) {
            String text = textOf(content);
            Map<String, Object> r = append(origin, source, Pca.hashCanonical(text));
            if ("principal".equals(origin) && IntentJs.u8len(text) <= MAX_CONTENT_BYTES) contents.put(String.valueOf(chain.size() - 1), text);
            return r;
        }

        private Map<String, Object> append(String origin, String source, String digest) {
            Map<String, Object> prev = chain.isEmpty() ? null : chain.get(chain.size() - 1);
            long issued = Math.max(prev == null ? 0L : IntentJs.lng(prev.get("issued_at")), now.getAsLong());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("v", 1L);
            body.put("kind", "pca-prov");
            body.put("mediator", mediator);
            body.put("kid", kid);
            body.put("session", session);
            body.put("seq", (long) chain.size());
            body.put("prev", prev == null ? null : receiptRef(prev));
            body.put("origin", origin);
            body.put("source", clip(source == null ? "" : source));
            body.put("content_digest", digest);
            body.put("issued_at", issued);
            Map<String, Object> r = Issue.signArtifact(RECEIPT_DOMAIN, body, key);
            chain.add(r);
            return r;
        }
    }

    static String textOf(Object c) {
        if (c instanceof String) return (String) c;
        try {
            return Json.canonicalize(c);
        } catch (RuntimeException e) {
            return String.valueOf(c);
        }
    }

    /** A source label of at most 256 UTF-8 bytes ({@code -} when empty); a cut never splits a surrogate pair. */
    static String clip(String s) {
        while (IntentJs.u8len(s) > 256) {
            int n = Math.max(1, s.length() / 2);
            if (n > 1 && Character.isLowSurrogate(s.charAt(n))) n--;
            s = s.substring(0, n);
        }
        return s.isEmpty() ? "-" : s;
    }

    /**
     * The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
     * input, no model in between): one principal segment holding the operation's canonical JSON, then the action. Under a pinned
     * {@code recorder} key the operation's choice and values are trusted.
     */
    public static Map<String, Object> principalDirect(Recorder recorder, Authorize.Operation op) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", op.verb);
        m.put("resource", op.resource);
        m.put("params", Authorize.copyParams(op.params));
        recorder.principal(Json.canonicalizeStrict(m));
        return recorder.forAction(op);
    }

    /** The bundle's session id when it names one (for {@link Observed}). */
    static String bundleSession(Object bundle) {
        Object rs = bundle instanceof Map ? obj(bundle).get("receipts") : null;
        Object r0 = rs instanceof List && !((List<?>) rs).isEmpty() ? ((List<?>) rs).get(0) : null;
        Object s = r0 instanceof Map ? obj(r0).get("session") : null;
        return s instanceof String ? (String) s : null;
    }
}
