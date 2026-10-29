package net.atlasauth.pca;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the
 * principal's plan authorization.
 *
 * <pre>
 *   draft --validate--&gt; validated --commit--&gt; committed --authorize--&gt; authorized
 *     \_____________________|_______________________|______revoke_______|--&gt; revoked
 * </pre>
 *
 * <ul>
 *   <li>{@code draft}: the nodes are recorded; the root is computed from them (never taken from the caller).</li>
 *   <li>{@code validated}: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed
 *       the server's own {@link Validator}.</li>
 *   <li>{@code committed}: the root is fixed. A committed plan is NOT executable: it still needs the principal.</li>
 *   <li>{@code authorized}: the principal approved this root for this grant, optionally until {@code expiresAt}.</li>
 *   <li>{@code revoked}: terminal; every later action against the root is denied.</li>
 * </ul>
 *
 * <p>"Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is {@code authorized}, the
 * approval has not expired, and its stored nodes still hash to the root. {@link #check} adds the per-action staleness rules a
 * server applies immediately before execution: the node exists and the operation's verb, resource and params still match what
 * the principal approved.
 *
 * <p>Wire formats are unchanged: the registry only feeds {@code plan} / {@code plan_authorized} into the authorize context
 * ({@link Authorize.Input#plans}) and names the state on a denial (the {@code plan_state} check). Nodes are JSON objects
 * {@code {id, verb, resource, params_digest?, reversibility_class?, pre?, post?}}. Every transition is ONE atomic
 * {@link AtomicKv#update}, so concurrent callers (threads, processes sharing a {@link PcaJdbcAtomicKv}) can never both win one.
 */
public final class PlanRegistry {
    public static final String DRAFT = "draft";
    public static final String VALIDATED = "validated";
    public static final String COMMITTED = "committed";
    public static final String AUTHORIZED = "authorized";
    public static final String REVOKED = "revoked";
    /** The state reported for a root the registry does not know. */
    public static final String UNKNOWN = "unknown";

    /** The server's own validation, run by {@link #validate} after the structural checks. Return null to accept, else the reason. A throw refuses. */
    @FunctionalInterface
    public interface Validator {
        String validate(PlanRecord record) throws Exception;
    }

    // ---- results ----------------------------------------------------------------------------------------------------

    /** A plan record: an immutable JSON-shaped object {@code {grantRef, root, nodes, state, createdAt, ...}}. */
    public static final class PlanRecord {
        private final Map<String, Object> tree;

        private PlanRecord(Map<String, Object> tree) { this.tree = Collections.unmodifiableMap(tree); }

        /** From the JSON object a store persisted; null unless it has a string {@code root} and a list {@code nodes}. */
        @SuppressWarnings("unchecked")
        public static PlanRecord of(Object tree) {
            if (!(tree instanceof Map)) return null;
            Map<String, Object> m = (Map<String, Object>) tree;
            if (!(m.get("root") instanceof String) || !(m.get("nodes") instanceof List) || !(m.get("state") instanceof String)) return null;
            return new PlanRecord(new LinkedHashMap<>(m));
        }

        public Map<String, Object> toMap() { return new LinkedHashMap<>(tree); }

        PlanRecord with(String key, Object value) {
            Map<String, Object> m = new LinkedHashMap<>(tree);
            m.put(key, value);
            return new PlanRecord(m);
        }

        public String grantRef() { return (String) tree.get("grantRef"); }
        public String root() { return (String) tree.get("root"); }
        public String state() { return (String) tree.get("state"); }
        /** The plan nodes (a copy). */
        @SuppressWarnings("unchecked")
        public List<Object> nodes() { return (List<Object>) deepCopy(tree.get("nodes")); }
        public Long createdAt() { return instant("createdAt"); }
        public Long validatedAt() { return instant("validatedAt"); }
        public Long committedAt() { return instant("committedAt"); }
        public Long authorizedAt() { return instant("authorizedAt"); }
        public Long revokedAt() { return instant("revokedAt"); }
        /** The principal's approval {@code {by, expiresAt?}} (a copy), or null. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> approval() { return tree.get("approval") instanceof Map ? (Map<String, Object>) deepCopy(tree.get("approval")) : null; }
        public String revokedReason() { Object v = tree.get("revokedReason"); return v instanceof String ? (String) v : null; }

        private Long instant(String k) {
            Double d = IntentJs.num(tree.get(k));
            return d == null || Double.isNaN(d) || Double.isInfinite(d) ? null : Long.valueOf((long) (double) d);
        }

        @Override public String toString() { return "PlanRecord" + tree; }
    }

    /** The result of a lifecycle transition: {@code ok} with the new record, or not ok with the current {@code state} and a {@code reason}. */
    public static final class PlanTransition {
        public final boolean ok;
        public final PlanRecord record;
        public final String state;
        public final String reason;

        private PlanTransition(boolean ok, PlanRecord record, String state, String reason) {
            this.ok = ok; this.record = record; this.state = state; this.reason = reason;
        }

        static PlanTransition ok(PlanRecord r) { return new PlanTransition(true, r, null, null); }
        static PlanTransition no(String state, String reason) { return new PlanTransition(false, null, state, reason); }

        /** The reference's JSON shape. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (ok) m.put("record", record.toMap());
            else {
                m.put("state", state);
                m.put("reason", reason);
            }
            return m;
        }
    }

    /** A plan's state at the moment of use. */
    public static final class PlanStatus {
        public final String state;
        public final boolean executable;
        /** Why it is not executable (null when executable). */
        public final String reason;
        public final PlanRecord record;

        PlanStatus(String state, boolean executable, String reason, PlanRecord record) {
            this.state = state; this.executable = executable; this.reason = reason; this.record = record;
        }

        PlanStatus notExecutable(String why) { return new PlanStatus(state, false, why, record); }

        /** The reference's JSON shape. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("state", state);
            m.put("executable", executable);
            if (reason != null) m.put("reason", reason);
            if (record != null) m.put("record", record.toMap());
            return m;
        }
    }

    /** The verifier context for an action against a root: the stored plan, {@code planAuthorized} = executable now, and the status. */
    public static final class PlanContext {
        public final List<Object> plan;
        public final boolean planAuthorized;
        public final PlanStatus status;

        PlanContext(List<Object> plan, boolean planAuthorized, PlanStatus status) {
            this.plan = plan; this.planAuthorized = planAuthorized; this.status = status;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("plan", plan);
            m.put("planAuthorized", planAuthorized);
            m.put("status", status.toMap());
            return m;
        }
    }

    // ---- the registry -----------------------------------------------------------------------------------------------

    private final AtomicKv kv;
    private final String prefix;
    private final LongSupplier clock;
    private final Validator validator;

    /** A registry over a fresh in-memory store (one process), the wall clock and no validator. */
    public PlanRegistry() { this(new MemoryAtomicKv(), "pca-plan:", System::currentTimeMillis, null); }

    /** A registry over {@code kv} (use {@link PcaJdbcAtomicKv} for a durable, shared one). {@code validator} and {@code clock} may be null. */
    public PlanRegistry(AtomicKv kv, String prefix, LongSupplier clock, Validator validator) {
        if (kv == null) throw new IllegalArgumentException("kv");
        this.kv = kv;
        this.prefix = prefix == null ? "pca-plan:" : prefix;
        this.clock = clock == null ? System::currentTimeMillis : clock;
        this.validator = validator;
    }

    /** JavaScript {@code encodeURIComponent}: the key scope of a grant reference. */
    static String encodeUriComponent(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%21", "!").replace("%27", "'")
            .replace("%28", "(").replace("%29", ")").replace("%7E", "~");
    }

    private String key(String grantRef, String root) { return prefix + encodeUriComponent(grantRef) + ":" + root; }

    /** A deep copy of a JSON tree. */
    static Object deepCopy(Object v) { return Json.parseLenient(Json.canonicalize(v)); }

    private static String rootOf(List<Object> nodes) {
        if (nodes.isEmpty()) throw new IllegalArgumentException("merkleRoot: empty leaf set");
        List<Object> leaves = new ArrayList<>();
        for (Object n : nodes) {
            @SuppressWarnings("unchecked")
            Map<String, Object> nm = (Map<String, Object>) n;
            leaves.add(Pca.planLeaf(nm.get("id"), nm, Pca.conditionsDigest(nm.get("pre"), nm.get("post"))));
        }
        return Pca.merkleRoot(leaves);
    }

    /** Structural validity of a plan's nodes (the reason, or null when valid). */
    private static String structuralProblem(List<Object> nodes) {
        if (nodes.isEmpty()) return "a plan needs at least one node";
        Set<String> ids = new HashSet<>();
        for (Object o : nodes) {
            Map<?, ?> n = o instanceof Map ? (Map<?, ?>) o : null;
            if (n == null || !(n.get("id") instanceof String) || ((String) n.get("id")).isEmpty()) return "every node needs an id";
            String id = (String) n.get("id");
            if (!ids.add(id)) return "duplicate node id '" + id + "'";
            if (!(n.get("verb") instanceof String) || ((String) n.get("verb")).isEmpty() || !(n.get("resource") instanceof String) || ((String) n.get("resource")).isEmpty())
                return "node '" + id + "' needs a verb and a resource";
            if (n.containsKey("reversibility_class")) {
                Object rc = n.get("reversibility_class");
                boolean known = "reversible".equals(rc) || "rate_limited".equals(rc) || "costly".equals(rc) || "irreversible".equals(rc);
                if (!known) return "node '" + id + "' has an unknown reversibility class '" + IntentRevocation.jsText(rc, true) + "'";
            }
        }
        return null;
    }

    /** A private copy of the nodes and their root; throws when the plan has no root. */
    private static Object[] prepare(List<?> nodes) {
        @SuppressWarnings("unchecked")
        List<Object> copy = (List<Object>) deepCopy(nodes);
        return new Object[] {copy, rootOf(copy)};
    }

    public PlanRecord get(String grantRef, String root) {
        return PlanRecord.of(kv.get(key(grantRef, root)));
    }

    /** Atomically move {@code from} -> the next record (computed from the current one). */
    private PlanTransition move(String grantRef, String root, Set<String> from, String to, java.util.function.UnaryOperator<PlanRecord> next) {
        PlanTransition[] out = {PlanTransition.no(UNKNOWN, "plan " + root + " is unknown for this grant")};
        kv.update(key(grantRef, root), prev -> {
            PlanRecord cur = PlanRecord.of(prev);
            if (cur == null) {
                out[0] = PlanTransition.no(UNKNOWN, "plan " + root + " is unknown for this grant");
                return null;
            }
            if (!from.contains(cur.state())) {
                out[0] = PlanTransition.no(cur.state(), "plan " + root + " is " + cur.state() + ": cannot " + to);
                return null;
            }
            PlanRecord rec = next.apply(cur);
            out[0] = PlanTransition.ok(rec);
            return rec.toMap();
        });
        return out[0];
    }

    /** Record a draft plan for a grant. The root is computed from {@code nodes}. Re-drafting an existing root is refused. */
    public PlanTransition draft(String grantRef, List<?> nodes) {
        if (grantRef == null || grantRef.isEmpty()) return PlanTransition.no(UNKNOWN, "a plan needs a grant");
        // structural problems are reported by validate (a draft can be inspected first); an unhashable plan has no root
        Object[] prep;
        try {
            prep = prepare(nodes);
        } catch (RuntimeException e) {
            return PlanTransition.no(UNKNOWN, "the plan cannot be committed: " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
        final Object copy = prep[0];
        final String root = (String) prep[1];
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("grantRef", grantRef);
        m.put("root", root);
        m.put("nodes", copy);
        m.put("state", DRAFT);
        m.put("createdAt", IntentJs.ofLong(clock.getAsLong()));
        PlanRecord rec = PlanRecord.of(m);
        PlanTransition[] out = {PlanTransition.ok(rec)};
        kv.update(key(grantRef, root), prev -> {
            PlanRecord cur = PlanRecord.of(prev);
            if (cur != null) {
                out[0] = PlanTransition.no(cur.state(), "plan " + root + " already exists (" + cur.state() + ")");
                return null;
            }
            out[0] = PlanTransition.ok(rec);
            return rec.toMap();
        });
        return out[0];
    }

    /** draft -> validated (structural checks, then the server's validator). */
    public PlanTransition validate(String grantRef, String root) {
        PlanRecord cur = get(grantRef, root);
        if (cur == null) return PlanTransition.no(UNKNOWN, "plan " + root + " is unknown for this grant");
        if (!DRAFT.equals(cur.state())) return PlanTransition.no(cur.state(), "plan " + root + " is " + cur.state() + ": cannot validate");
        List<Object> nodes = cur.nodes();
        String problem = structuralProblem(nodes);
        if (problem == null) {
            try {
                if (!rootOf(nodes).equals(root)) problem = "the stored nodes no longer hash to the root";
            } catch (RuntimeException e) {
                problem = "the stored nodes no longer hash to the root";
            }
        }
        if (problem != null) return PlanTransition.no(cur.state(), "plan " + root + " is invalid: " + problem);
        if (validator != null) {
            String why;
            try {
                why = validator.validate(cur);
            } catch (Exception e) {
                why = "validator error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage());
            }
            if (why != null) return PlanTransition.no(cur.state(), "plan " + root + " is invalid: " + why);
        }
        return move(grantRef, root, Set.of(DRAFT), "validate", r -> r.with("state", VALIDATED).with("validatedAt", IntentJs.ofLong(clock.getAsLong())));
    }

    /** validated -> committed: the root is fixed; it still needs the principal's authorization to execute. */
    public PlanTransition commit(String grantRef, String root) {
        return move(grantRef, root, Set.of(VALIDATED), "commit", r -> r.with("state", COMMITTED).with("committedAt", IntentJs.ofLong(clock.getAsLong())));
    }

    /**
     * committed -> authorized: the principal's approval (call it only after verifying the principal's consent).
     * {@code approval} is a JSON object {@code {by, expiresAt?}}: {@code by} names who approved (non-empty string), the
     * optional {@code expiresAt} (epoch ms) is when the approval lapses (absent: until revoked).
     */
    public PlanTransition authorize(String grantRef, String root, Map<String, Object> approval) {
        if (approval == null || !(approval.get("by") instanceof String) || ((String) approval.get("by")).isEmpty())
            return PlanTransition.no(stateOf(grantRef, root), "an approval names who approved (`by`)");
        if (approval.containsKey("expiresAt") && !IntentJs.isFinite(approval.get("expiresAt")))
            return PlanTransition.no(stateOf(grantRef, root), "approval.expiresAt must be a time (epoch ms)");
        Object copy = deepCopy(approval);
        return move(grantRef, root, Set.of(COMMITTED), "authorize", r -> r.with("state", AUTHORIZED).with("authorizedAt", IntentJs.ofLong(clock.getAsLong())).with("approval", copy));
    }

    /** {@link #authorize(String, String, Map)} for an approval by {@code by} that lapses at {@code expiresAt} (epoch ms; null: never). */
    public PlanTransition authorize(String grantRef, String root, String by, Long expiresAt) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("by", by);
        if (expiresAt != null) a.put("expiresAt", IntentJs.ofLong(expiresAt));
        return authorize(grantRef, root, a);
    }

    /** Any state except revoked -> revoked (terminal). */
    public PlanTransition revoke(String grantRef, String root, String reason) {
        return move(grantRef, root, Set.of(DRAFT, VALIDATED, COMMITTED, AUTHORIZED), "revoke",
            r -> r.with("state", REVOKED).with("revokedAt", IntentJs.ofLong(clock.getAsLong())).with("revokedReason", reason == null ? "" : reason));
    }

    private String stateOf(String grantRef, String root) {
        PlanRecord r = get(grantRef, root);
        return r == null ? UNKNOWN : r.state();
    }

    /** The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). */
    public PlanStatus status(String grantRef, String root) { return status(grantRef, root, clock.getAsLong()); }

    public PlanStatus status(String grantRef, String root, long now) {
        PlanRecord record = get(grantRef, root);
        if (record == null) return new PlanStatus(UNKNOWN, false, "plan " + root + " is unknown for this grant", null);
        String state = record.state();
        if (!AUTHORIZED.equals(state)) {
            String why = COMMITTED.equals(state) ? "committed but not authorized by the principal"
                : REVOKED.equals(state) ? "revoked (" + (record.revokedReason() != null ? record.revokedReason() : "no reason given") + ")"
                : state + ", not authorized";
            return new PlanStatus(state, false, "plan " + root + " is " + why, record);
        }
        Map<String, Object> approval = record.approval();
        if (approval != null && approval.containsKey("expiresAt")) {
            Double exp = IntentJs.num(approval.get("expiresAt"));
            if (exp == null || !(now < exp))
                return new PlanStatus(state, false, "plan " + root + ": the principal's approval expired at " + (exp == null ? IntentRevocation.jsText(approval.get("expiresAt"), true) : RevocationStaleness.jsNum(exp)), record);
        }
        String actual;
        try {
            actual = rootOf(record.nodes());
        } catch (RuntimeException e) {
            actual = null;
        }
        if (!root.equals(actual)) return new PlanStatus(state, false, "plan " + root + ": the stored nodes no longer hash to the root", record);
        return new PlanStatus(state, true, null, record);
    }

    /** {@link #status} plus the per-action staleness rules; run it immediately before execution. */
    public PlanStatus check(String grantRef, String root, String nodeId, Authorize.Operation operation, Long now) {
        PlanStatus s = status(grantRef, root, now != null ? now : clock.getAsLong());
        if (!s.executable || s.record == null) return s;
        if (nodeId == null && operation == null) return s;
        List<Object> nodes = s.record.nodes();
        Map<?, ?> node = null;
        if (nodeId != null) {
            for (Object n : nodes) if (n instanceof Map && nodeId.equals(((Map<?, ?>) n).get("id"))) { node = (Map<?, ?>) n; break; }
            if (node == null) return s.notExecutable("plan " + root + " has no node '" + nodeId + "'");
        }
        if (operation != null) {
            String digest;
            try {
                digest = Pca.paramsDigest(operation.params == null ? null : Authorize.copyParams(operation.params));
            } catch (RuntimeException e) {
                return s.notExecutable("plan " + root + ": the operation's params cannot be hashed");
            }
            List<Object> candidates = node != null ? List.of(node) : nodes;
            boolean same = false;
            for (Object c : candidates) {
                Map<?, ?> n = (Map<?, ?>) c;
                Object pd = n.get("params_digest") != null ? n.get("params_digest") : Pca.paramsDigest(null);
                if (java.util.Objects.equals(n.get("verb"), operation.verb) && java.util.Objects.equals(n.get("resource"), operation.resource) && digest.equals(pd)) {
                    same = true;
                    break;
                }
            }
            if (!same) return s.notExecutable("plan " + root + ": the operation (" + operation.verb + " on " + operation.resource + " with these params) is not what the principal approved");
        }
        return s;
    }

    /** For {@code isPlanAuthorized}-style options: true only when executable now. Never throws. */
    public boolean isPlanAuthorized(String grantRef, String planRoot) {
        try {
            return status(grantRef, planRoot).executable;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The verifier context for an action against {@code root}; null: the root is unknown. */
    public PlanContext context(String grantRef, String root, Long now) {
        PlanStatus s = status(grantRef, root, now != null ? now : clock.getAsLong());
        if (s.record == null) return null;
        return new PlanContext(s.record.nodes(), s.executable, s);
    }
}
