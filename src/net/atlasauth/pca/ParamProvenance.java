package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Rule 17: per-parameter provenance, label receipts and flow rules (packages/pca/src/param-provenance.ts
 * {@code decideParamProvenance}, label-receipts.ts, the taint lattice of taint.ts: trusted 0 &lt; first_party 1 &lt; tool 2
 * &lt; web 3 &lt; agent 4; the join is the highest rank; tainted = rank &gt;= 2). Outcome {@code pass}, {@code question} or
 * {@code deny}; first failure wins; never throws.
 */
public final class ParamProvenance {
    private ParamProvenance() {}

    public static final String LABELS_DOMAIN = "atlas-pca/labels/v1\0";
    public static final String LABELS_REF_DOMAIN = "atlas-pca/labels-ref/v1";
    public static final String LABEL_REF_PREFIX = "pca-labels:";
    public static final String PUBLIC_CLASS = "public";
    public static final int MAX_LABEL_FIELDS = 64;
    public static final int MAX_PROV_PATHS = 32;
    public static final int MAX_PROV_REFS = 8;
    public static final int MAX_COMMITTED_LABELS = 16;
    static final Pattern PROV_PATH_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}");
    private static final Set<String> PROTO_NAMES = Set.of("__proto__", "constructor", "prototype");
    static final List<String> TAINT_LEVELS = List.of("trusted", "first_party", "tool", "web", "agent");
    private static final List<String> MODES = List.of("allow", "question", "question_typed", "deny");
    private static final int TAINTED_RANK = 2;

    /** The rule-17 verdict. {@code labels}: classified path -> level; {@code classes}: path -> sorted class list; {@code env}: nested labels. */
    public static final class ProvResult {
        public final String outcome;
        public final String reason;
        public final String friction;
        public final Map<String, Object> labels;
        public final Map<String, Object> classes;
        public final Map<String, Object> env;
        ProvResult(String outcome, String reason, String friction, Map<String, Object> labels, Map<String, Object> classes, Map<String, Object> env) {
            this.outcome = outcome; this.reason = reason; this.friction = friction; this.labels = labels; this.classes = classes; this.env = env;
        }
    }

    static boolean isTaintLevel(Object k) { return k instanceof String && TAINT_LEVELS.contains(k); }
    static int rank(Object level) { return isTaintLevel(level) ? TAINT_LEVELS.indexOf(level) : 4; }
    static boolean isProvPath(String k) { return PROV_PATH_RE.matcher(k).matches() && !PROTO_NAMES.contains(k.substring("action.params.".length())); }

    // ---- label receipts ----
    static String validateLabelsWire(Object lo) {
        if (!(lo instanceof Map)) return "label receipt must be an object";
        Map<String, Object> l = IntentJs.obj(lo);
        String m = IntentArtifacts.closedMembers(l, List.of("v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"), IntentArtifacts.SUITE_MEMBERS, "labels");
        if (m != null) return m;
        if (!OracleFacts.isOne(l.get("v")) || !"pca-labels".equals(l.get("kind"))) return "label receipt must be {v: 1, kind: \"pca-labels\"}";
        if (!IntentArtifacts.isBoundedString(l.get("site"), 256)) return "'labels.site' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.isDigest(l.get("session"))) return "'labels.session' must be canonical base64url (32 bytes)";
        if (!IntentArtifacts.isDigest(l.get("response_digest"))) return "'labels.response_digest' must be canonical base64url (32 bytes)";
        if (!(l.get("fields") instanceof Map)) return "'labels.fields' must be an object";
        Map<String, Object> fields = IntentJs.obj(l.get("fields"));
        if (fields.isEmpty() || fields.size() > MAX_LABEL_FIELDS) return "'labels.fields' must hold 1.." + MAX_LABEL_FIELDS + " fields";
        for (Map.Entry<String, Object> e : fields.entrySet()) {
            String k = e.getKey();
            Object f = e.getValue();
            if (!IntentArtifacts.isBoundedString(k, 256)) return "label field paths must be non-empty strings (<= 256 bytes)";
            if (!(f instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(f), List.of("class", "value_digest"), List.of(), "object") != null)
                return "label field '" + k + "' must be exactly {class, value_digest}";
            Object cls = IntentJs.get(f, "class");
            if (!(cls instanceof String) || ((String) cls).length() > 128 || !IntentArtifacts.DATA_CLASS_RE.matcher((String) cls).matches()) return "label field '" + k + "': invalid data class";
            if (!IntentArtifacts.isDigest(IntentJs.get(f, "value_digest"))) return "label field '" + k + "': value_digest must be canonical base64url (32 bytes)";
        }
        if (!IntentJs.isInt(l.get("issued_at")) || IntentJs.num(l.get("issued_at")) < 0) return "'labels.issued_at' must be a non-negative safe integer";
        if (!IntentArtifacts.isBoundedString(l.get("kid"), 64)) return "'labels.kid' must be a non-empty string (<= 64 bytes)";
        if (!(l.get("sig") instanceof String)) return "'labels.sig' must be a string";
        return null;
    }

    public static String labelsRef(Map<String, Object> l) { return IntentArtifacts.artifactRef(LABELS_REF_DOMAIN, "l", l); }

    static String verifyLabels(Object l, List<?> keys) {
        String w = validateLabelsWire(l);
        if (w != null) return w;
        Map<String, Object> r = IntentJs.obj(l);
        String se = IntentArtifacts.artifactSuiteError(r);
        if (se != null) return "signature suite: " + se;
        Map<?, ?> key = null;
        for (Object k : keys) if (r.get("site").equals(IntentJs.get(k, "site")) && r.get("kid").equals(IntentJs.get(k, "kid"))) { key = (Map<?, ?>) k; break; }
        if (key == null) return "no pinned label key for site '" + r.get("site") + "' kid '" + r.get("kid") + "'";
        return IntentArtifacts.verifyArtifactSig(LABELS_DOMAIN, r, key.get("pk"), key.get("pq_pk")) ? null : "bad label receipt signature";
    }

    /** The most specific flow pattern for {@code cls}: itself, else the longest {@code p.*} prefix, else {@code *}. */
    static String flowRuleFor(Map<String, Object> rules, String cls) {
        if (rules.containsKey(cls)) return cls;
        String best = null;
        for (String p : rules.keySet()) {
            if (!p.endsWith(".*")) continue;
            String prefix = p.substring(0, p.length() - 1);
            if (cls.startsWith(prefix) && (best == null || p.length() > best.length())) best = p;
        }
        if (best != null) return best;
        return rules.containsKey("*") ? "*" : null;
    }

    static boolean flowAllowed(Map<String, Object> rules, String cls, String origin, String aud) {
        if (aud.equals(origin) || cls.equals(PUBLIC_CLASS)) return true;
        String p = flowRuleFor(rules, cls);
        if (p == null) return false;
        Object sinks = rules.get(p);
        return sinks instanceof List && ((List<?>) sinks).contains(aud);
    }

    static String validateFlowRules(Object rules) {
        if (!(rules instanceof Map)) return "flows must be an object";
        for (Map.Entry<String, Object> e : IntentJs.obj(rules).entrySet()) {
            String p = e.getKey();
            String base = p.equals("*") ? "x" : p.endsWith(".*") ? p.substring(0, p.length() - 2) : p;
            if (!IntentArtifacts.DATA_CLASS_RE.matcher(base).matches()) return "flow pattern '" + p + "' is not a class, a 'prefix.*' or '*'";
            if (!(e.getValue() instanceof List)) return "flow pattern '" + p + "' needs a list of audiences";
            for (Object s : (List<?>) e.getValue()) if (!IntentArtifacts.isBoundedString(s, 256)) return "flow pattern '" + p + "' needs a list of audiences";
        }
        return null;
    }

    // ---- policy and wire ----
    static String validateProvenancePolicy(Object po) {
        if (!(po instanceof Map) || !(IntentJs.get(po, "params") instanceof Map)) return "provenance policy needs a params map";
        Map<String, Object> p = IntentJs.obj(po);
        String cm = IntentArtifacts.closedMembers(p, List.of("params"), List.of("registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"), "policy");
        if (cm != null) return cm;
        for (Map.Entry<String, Object> e : IntentJs.obj(p.get("params")).entrySet()) {
            if (!IntentArtifacts.isParamPath(e.getKey())) return "policy param '" + e.getKey() + "' is not an action.params path";
            if (!"material".equals(e.getValue()) && !"critical".equals(e.getValue())) return "policy param '" + e.getKey() + "': sensitivity must be material or critical";
        }
        if (p.containsKey("registry")) {
            if (!(p.get("registry") instanceof Map)) return "registry must be an object";
            for (Map.Entry<String, Object> e : IntentJs.obj(p.get("registry")).entrySet())
                if (!IntentArtifacts.isBoundedString(e.getKey(), 256) || !isTaintLevel(e.getValue())) return "registry entry '" + e.getKey() + "' must map to a taint level";
        }
        if (p.containsKey("label_keys")) {
            if (!(p.get("label_keys") instanceof List)) return "label_keys must be a list";
            for (Object k : (List<?>) p.get("label_keys"))
                if (!(k instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(k), List.of("site", "kid", "pk"), List.of("pq_pk"), "label_key") != null
                    || !IntentArtifacts.isBoundedString(IntentJs.get(k, "site"), 256) || !IntentArtifacts.isBoundedString(IntentJs.get(k, "kid"), 64)
                    || !IntentArtifacts.isDigest(IntentJs.get(k, "pk")) || !IntentArtifacts.pinPqOk(k)) return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk";
        }
        if (p.containsKey("critical_max") && !isTaintLevel(p.get("critical_max"))) return "critical_max must be a taint level";
        if (p.containsKey("material_tainted") && !isMode(p.get("material_tainted"))) return "material_tainted must be allow | question | question_typed | deny";
        if (p.containsKey("critical_tainted") && ("allow".equals(p.get("critical_tainted")) || !isMode(p.get("critical_tainted"))))
            return "critical_tainted must be question | question_typed | deny";
        if (p.containsKey("flows")) {
            String e = validateFlowRules(p.get("flows"));
            if (e != null) return e;
        }
        return null;
    }

    static String validateProvWire(Object prov) {
        if (!(prov instanceof Map)) return "'prov' must be an object";
        Map<String, Object> m = IntentJs.obj(prov);
        if (m.size() > MAX_PROV_PATHS) return "'prov' holds more than " + MAX_PROV_PATHS + " paths";
        for (Map.Entry<String, Object> e : m.entrySet()) {
            String k = e.getKey();
            if (!isProvPath(k)) return "'prov' key '" + k + "' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)";
            Object refs = e.getValue();
            if (!(refs instanceof List) || ((List<?>) refs).isEmpty() || ((List<?>) refs).size() > MAX_PROV_REFS) return "'prov." + k + "' must hold 1.." + MAX_PROV_REFS + " refs";
            for (Object r : (List<?>) refs) if (!IntentArtifacts.isBoundedString(r, 256)) return "'prov." + k + "' refs must be non-empty strings (<= 256 bytes)";
        }
        return null;
    }

    /** {@code pca-labels:<digest>#<field>} split at the FIRST {@code #}: {receipt, field}, or null. */
    static String[] parseLabelRef(String ref) {
        if (!ref.startsWith(LABEL_REF_PREFIX)) return null;
        String rest = ref.substring(LABEL_REF_PREFIX.length());
        int i = rest.indexOf('#');
        if (i < 0) return null;
        String receipt = rest.substring(0, i), field = rest.substring(i + 1);
        return IntentArtifacts.isDigest(receipt) && !field.isEmpty() ? new String[] {receipt, field} : null;
    }

    private static List<String> sorted(Set<String> keys) {
        List<String> l = new ArrayList<>(keys);
        l.sort(Json::compareUtf8);
        return l;
    }

    /** The {@code primitives.intent_provenance} entry point: normalizes {@code input}, then {@link #decide(Map)}. */
    public static ProvResult decide(Object input) {
        try {
            return decide(IntentJs.obj(IntentJs.normalize(input)));
        } catch (RuntimeException e) {
            return new ProvResult("deny", "provenance: evaluation error (fail closed): " + e.getClass().getSimpleName(), null,
                new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>());
        }
    }

    /** Rule 17 over an already normalized input {@code {aud, session, action, prov?, committed_labels?, labels?, policy}}. */
    static ProvResult decide(Map<String, Object> input) {
        Map<String, Object> labels = new LinkedHashMap<>();
        Map<String, Object> classes = new LinkedHashMap<>();
        try {
            Object policyO = input.get("policy");
            String pe = validateProvenancePolicy(policyO);
            if (pe != null) return deny(labels, classes, "policy misconfigured (fail closed): " + pe);
            Map<String, Object> policy = IntentJs.obj(policyO);
            Object prov = IntentJs.opt(input, "prov", new LinkedHashMap<String, Object>());
            String we = validateProvWire(prov);
            if (we != null) return deny(labels, classes, we);
            Object committed = IntentJs.opt(input, "committed_labels", List.of());
            if (!(committed instanceof List) || ((List<?>) committed).size() > MAX_COMMITTED_LABELS)
                return deny(labels, classes, "committed labels must be a list of at most " + MAX_COMMITTED_LABELS + " digests");
            Set<String> committedSet = new LinkedHashSet<>();
            for (Object d : (List<?>) committed) {
                if (!IntentArtifacts.isDigest(d) || !committedSet.add((String) d)) return deny(labels, classes, "committed labels must be distinct canonical 32-byte digests");
            }
            Object action = input.get("action");
            if (!(action instanceof Map)) return deny(labels, classes, "action must be an object");
            if (!(IntentJs.opt(action, "params", Map.of()) instanceof Map)) return deny(labels, classes, "action.params must be an object");
            Object params = IntentArtifacts.actionParams(action);
            if (!(IntentJs.opt(input, "labels", List.of()) instanceof List)) return deny(labels, classes, "labels must be an array");
            Map<String, Object> provMap = IntentJs.obj(prov);
            List<String> paths = sorted(provMap.keySet());
            for (String p : paths) if (!IntentArtifacts.resolveParamPath(params, p).found) return deny(labels, classes, "prov names '" + p + "', a parameter the action does not carry");
            for (String a : paths) for (String b : paths) if (!a.equals(b) && b.startsWith(a + ".")) return deny(labels, classes, "prov paths '" + a + "' and '" + b + "' overlap");

            Map<String, Map<String, Object>> receipts = new HashMap<>();
            for (Object r : IntentArtifacts.iterable(IntentJs.opt(input, "labels", List.of()))) {
                try {
                    if (validateLabelsWire(r) == null) receipts.put(labelsRef(IntentJs.obj(r)), IntentJs.obj(r));
                } catch (RuntimeException e) { /* no reference */ }
            }
            Object regO = IntentJs.opt(policy, "registry", Map.of());
            Map<?, ?> reg = (Map<?, ?>) regO;
            Object keysO = IntentJs.opt(policy, "label_keys", List.of());
            // `aud` is whatever the input carries (TS never casts it): a non-string never equals a site and never passes a flow
            // rule (label-receipts.ts flowAllowed), and the refusal prints it as JavaScript would
            Object audO = input.get("aud");
            String aud = audO instanceof String ? (String) audO : null;
            Map<String, List<String[]>> origins = new LinkedHashMap<>();

            for (String p : paths) {
                Object value = IntentArtifacts.resolveParamPath(params, p).value;
                int join = -1;
                for (Object refO : (List<?>) provMap.get(p)) {
                    String ref = (String) refO;
                    int r;
                    if (!ref.startsWith(LABEL_REF_PREFIX)) {
                        r = reg.containsKey(ref) && isTaintLevel(reg.get(ref)) ? rank(reg.get(ref)) : 4;
                        join = Math.max(join, r);
                        continue;
                    }
                    String[] lr = parseLabelRef(ref);
                    if (lr == null) return deny(labels, classes, "malformed label ref on '" + p + "'");
                    if (!committedSet.contains(lr[0])) return deny(labels, classes, "label ref on '" + p + "' names a receipt the PCActn does not commit");
                    Map<String, Object> rc = receipts.get(lr[0]);
                    if (rc == null) return deny(labels, classes, "label receipt for '" + p + "' was not supplied");
                    String ve = verifyLabels(rc, (List<?>) keysO);
                    if (ve != null) return deny(labels, classes, "label receipt for '" + p + "': " + ve);
                    if (!rc.get("session").equals(input.get("session"))) return deny(labels, classes, "label receipt for '" + p + "' is bound to another session");
                    Map<String, Object> fields = IntentJs.obj(rc.get("fields"));
                    if (!fields.containsKey(lr[1])) return deny(labels, classes, "label receipt for '" + p + "' has no field '" + lr[1] + "'");
                    Map<String, Object> field = IntentJs.obj(fields.get(lr[1]));
                    boolean match;
                    try { match = IntentJs.hashCanonical(value).equals(field.get("value_digest")); } catch (RuntimeException e) { match = false; }
                    r = match ? (rc.get("site").equals(aud) ? 1 : 2) : 4;
                    join = Math.max(join, r);
                    origins.computeIfAbsent(p, k -> new ArrayList<>()).add(new String[] {(String) field.get("class"), (String) rc.get("site")});
                }
                labels.put(p, TAINT_LEVELS.get(join < 0 ? 4 : join));
            }
            Map<String, Object> sens = IntentJs.obj(policy.get("params"));
            for (String p : sorted(sens.keySet())) {
                if (labels.containsKey(p)) continue;
                if (IntentArtifacts.resolveParamPath(params, p).found) labels.put(p, "agent");
            }
            Object flowsO = IntentJs.opt(policy, "flows", Map.of());
            for (String p : sorted(origins.keySet())) {
                TreeSet<String> cs = new TreeSet<>(Json::compareUtf8);
                for (String[] o : origins.get(p)) cs.add(o[0]);
                classes.put(p, new ArrayList<Object>(cs));
                for (String[] o : origins.get(p))
                    if (aud == null || !flowAllowed(IntentJs.obj(flowsO), o[0], o[1], aud))
                        return deny(labels, classes, "flow: class '" + o[0] + "' from '" + o[1] + "' may not reach '" + IntentRevocation.jsText(audO, input.containsKey("aud")) + "' (parameter '" + p + "')");
            }
            int capRank = rank(IntentJs.opt(policy, "critical_max", "agent"));
            List<String> labelled = sorted(labels.keySet());
            for (String p : labelled) {
                if ("critical".equals(sens.get(p)) && rank(labels.get(p)) > capRank)
                    return deny(labels, classes, "critical parameter '" + p + "' has provenance '" + labels.get(p) + "', above the policy maximum '" + policy.get("critical_max") + "'");
            }
            boolean question = false, typed = false;
            for (String p : labelled) {
                Object s = sens.containsKey(p) ? sens.get(p) : null;
                if (s == null || rank(labels.get(p)) < TAINTED_RANK) continue;
                Object mode = "critical".equals(s)
                    ? IntentJs.opt(policy, "critical_tainted", "question_typed")
                    : IntentJs.opt(policy, "material_tainted", "question");
                if ("deny".equals(mode)) return deny(labels, classes, "tainted " + s + " parameter '" + p + "' (provenance '" + labels.get(p) + "') is denied by policy");
                if ("question".equals(mode) || "question_typed".equals(mode)) question = true;
                if ("question_typed".equals(mode)) typed = true;
            }
            Map<String, Object> env = new LinkedHashMap<>();
            for (String p : labelled) if (!IntentArtifacts.setNested(env, p, labels.get(p))) return deny(labels, classes, "provenance paths overlap at '" + p + "'");
            return question
                ? new ProvResult("question", "provenance: a tainted value needs the principal (lazy question)", typed ? "typed" : "tap", labels, classes, env)
                : new ProvResult("pass", null, null, labels, classes, env);
        } catch (RuntimeException e) {
            return deny(labels, classes, "evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /** The read-cell verdict (V14): {@code outcome} allow / question / deny, the optional fields to minimise, the uncovered ones. */
    public static final class ReadPurposeResult {
        public final String outcome;
        public final List<String> minimise;
        public final List<String> uncovered;
        ReadPurposeResult(String outcome, List<String> minimise, List<String> uncovered) { this.outcome = outcome; this.minimise = minimise; this.uncovered = uncovered; }
    }

    private static boolean classCovered(List<?> patterns, String cls) {
        if (cls.equals(PUBLIC_CLASS)) return true;
        for (Object p : patterns) {
            String s = (String) p;
            if (s.equals("*") || s.equals(cls) || (s.endsWith(".*") && cls.startsWith(s.substring(0, s.length() - 1)))) return true;
        }
        return false;
    }

    /**
     * Read cell decision (V14; {@code primitives.intent_read_purpose}, label-receipts.ts {@code decideReadPurpose}) over
     * {@code {fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?}}: a field is covered
     * when its class is {@code public} or matches a pattern of the OWN member {@code coverage[purpose]} (a class, {@code p.*},
     * {@code *}); an uncovered optional field is minimised, any other uncovered field makes the read {@code on_uncovered}
     * (default {@code question}). Both lists de-duplicated and sorted in UTF-8 byte order. Malformed input (JSON null anywhere
     * included) is deny with empty lists. Never throws.
     */
    public static ReadPurposeResult decideReadPurpose(Object input) {
        ReadPurposeResult malformed = new ReadPurposeResult("deny", List.of(), List.of());
        try {
            Object n = IntentJs.normalize(input);
            if (!(n instanceof Map)) return malformed;
            Map<String, Object> in = IntentJs.obj(n);
            Object fields = in.get("fields"), purpose = in.get("purpose"), coverage = in.get("coverage");
            Object onUncovered = in.containsKey("on_uncovered") ? in.get("on_uncovered") : "question";
            if (!(fields instanceof List) || !(purpose instanceof String) || !(coverage instanceof Map) || !("question".equals(onUncovered) || "deny".equals(onUncovered))) return malformed;
            for (Object pats : ((Map<?, ?>) coverage).values()) {
                if (!(pats instanceof List)) return malformed;
                for (Object x : (List<?>) pats) if (!(x instanceof String)) return malformed;
            }
            for (Object f : (List<?>) fields) {
                if (!(f instanceof Map) || !(IntentJs.get(f, "path") instanceof String) || !(IntentJs.get(f, "class") instanceof String)
                    || (IntentJs.own(f, "optional") && !(IntentJs.get(f, "optional") instanceof Boolean))) return malformed;
            }
            List<?> patterns = ((Map<?, ?>) coverage).containsKey(purpose) ? (List<?>) ((Map<?, ?>) coverage).get(purpose) : List.of();
            Set<String> minimise = new java.util.HashSet<>(), uncovered = new java.util.HashSet<>();
            for (Object f : (List<?>) fields) {
                if (classCovered(patterns, (String) IntentJs.get(f, "class"))) continue;
                (Boolean.TRUE.equals(IntentJs.get(f, "optional")) ? minimise : uncovered).add((String) IntentJs.get(f, "path"));
            }
            return new ReadPurposeResult(uncovered.isEmpty() ? "allow" : (String) onUncovered, sorted(minimise), sorted(uncovered));
        } catch (RuntimeException e) {
            return malformed;
        }
    }

    private static ProvResult deny(Map<String, Object> labels, Map<String, Object> classes, String reason) {
        return new ProvResult("deny", "provenance: " + reason, null, labels, classes, new LinkedHashMap<>());
    }

    /** A tainted-value mode (a JSON null is none: {@code List.of().contains(null)} would throw). */
    static boolean isMode(Object m) { return m instanceof String && MODES.contains(m); }
}
