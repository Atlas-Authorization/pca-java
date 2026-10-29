package net.atlasauth.pca;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The durable record of one authorized operation (T3), keyed by the operation id ({@code AuthorizedOperation.id}, the digest
 * of the presented PCActn). It is an immutable JSON-shaped object: {@link #toMap()} is exactly what a store persists, and
 * {@link #of(Object)} reads it back. Members: {@code id}, {@code state}, {@code verb}, {@code resource}, {@code params_digest},
 * {@code reversibility}, {@code startedAt}, then optionally {@code executingAt}, {@code finishedAt}, {@code result},
 * {@code error} (instants are epoch milliseconds).
 */
public final class OperationRecord {
    /** Claimed for execution, the function not started yet (re-check running), or the process crashed before starting it. */
    public static final String PENDING = "pending";
    /** The function has been started: the side effect is running, or the process crashed during or after it. */
    public static final String EXECUTING = "executing";
    /** The side effect completed; {@link #result()} is what the function returned. */
    public static final String COMMITTED = "committed";
    /** The function threw; {@link #error()} is its message. Not re-run. */
    public static final String FAILED = "failed";
    /** The pre-execution re-check refused: the function never ran. */
    public static final String ABORTED = "aborted";
    /** Found {@code executing} after the pending timeout: the outcome is unknown and must be reconciled, never silently re-run. */
    public static final String UNCERTAIN = "uncertain";

    private final Map<String, Object> tree;

    private OperationRecord(Map<String, Object> tree) { this.tree = Collections.unmodifiableMap(tree); }

    /** A new {@code pending} record. */
    public static OperationRecord pending(String id, String verb, String resource, String paramsDigest, String reversibility, long startedAt) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("state", PENDING);
        m.put("verb", verb);
        m.put("resource", resource);
        m.put("params_digest", paramsDigest);
        m.put("reversibility", reversibility);
        m.put("startedAt", IntentJs.ofLong(startedAt));
        return new OperationRecord(m);
    }

    /** From the JSON object a store persisted: null unless {@code id} and {@code state} are strings. */
    @SuppressWarnings("unchecked")
    public static OperationRecord of(Object tree) {
        if (!(tree instanceof Map)) return null;
        Map<String, Object> m = (Map<String, Object>) tree;
        if (!(m.get("id") instanceof String) || !(m.get("state") instanceof String)) return null;
        return new OperationRecord(new LinkedHashMap<>(m));
    }

    /** A copy of the JSON object (safe to modify). */
    public Map<String, Object> toMap() { return new LinkedHashMap<>(tree); }

    /** A copy with {@code key} set (a number must be a {@link Json.Num}; see {@link IntentJs#ofLong}). */
    public OperationRecord with(String key, Object value) {
        Map<String, Object> m = new LinkedHashMap<>(tree);
        m.put(key, value);
        return new OperationRecord(m);
    }

    /** A copy moved to {@code state}, with the optional members set (a null value leaves the member as it is). */
    public OperationRecord moved(String state, Long executingAt, Long finishedAt, String error) {
        OperationRecord r = with("state", state);
        if (executingAt != null) r = r.with("executingAt", IntentJs.ofLong(executingAt));
        if (finishedAt != null) r = r.with("finishedAt", IntentJs.ofLong(finishedAt));
        if (error != null) r = r.with("error", error);
        return r;
    }

    public String id() { return (String) tree.get("id"); }
    public String state() { return (String) tree.get("state"); }
    public String verb() { return str("verb"); }
    public String resource() { return str("resource"); }
    public String paramsDigest() { return str("params_digest"); }
    public String reversibility() { return str("reversibility"); }
    public String error() { return str("error"); }
    /** True when a {@code result} member is present (a JSON null result counts). */
    public boolean hasResult() { return tree.containsKey("result"); }
    public Object result() { return tree.get("result"); }
    /** When the record was created (epoch ms); 0 if the stored value is not a number. */
    public long startedAt() { Long v = instant("startedAt"); return v == null ? 0L : v; }
    /** When the function was started (epoch ms); null if never. */
    public Long executingAt() { return instant("executingAt"); }
    /** When it reached its final state (epoch ms); null if not yet. */
    public Long finishedAt() { return instant("finishedAt"); }

    private String str(String k) { Object v = tree.get(k); return v instanceof String ? (String) v : null; }

    private Long instant(String k) {
        Double d = IntentJs.num(tree.get(k));
        return d == null || Double.isNaN(d) || Double.isInfinite(d) ? null : Long.valueOf((long) (double) d);
    }

    @Override public String toString() { return "OperationRecord" + tree; }
}
