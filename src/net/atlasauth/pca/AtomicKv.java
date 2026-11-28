package net.atlasauth.pca;

import java.util.function.UnaryOperator;

/**
 * An atomic key/value seam for the operation record store and the plan registry (0.5). Values are JSON trees ({@link Json}
 * nodes: Map, List, String, Boolean, {@link Json.Num}, or {@link #JSON_NULL}); a key holds at most one value, and a Java {@code null} means absent.
 *
 * <p>{@link #update} MUST be atomic across every process and node that shares the store: a read-modify-write that two callers
 * cannot interleave (a compare-and-set loop, a row lock inside a transaction, a Redis script). A call that cannot decide MUST
 * throw an unchecked exception; the caller then refuses or reports the outcome as unknown. {@link MemoryAtomicKv} is the
 * in-process reference, {@link PcaJdbcAtomicKv} the durable one.
 */
public interface AtomicKv {
    /**
     * A stored JSON {@code null}: a value that is present and null, as the reference's stores keep it. It is distinct from an absent key
     * (which reads as Java null), so a record that is present but not a valid record is told apart from a missing one. Store it with
     * {@link #set}; it comes back from {@link #get} and as the {@code current} of {@link #update}.
     */
    Object JSON_NULL = new Object() { @Override public String toString() { return "null"; } };

    /** The value of {@code key}, or null when absent. */
    Object get(String key);

    /** Unconditionally store {@code value} under {@code key}. */
    void set(String key, Object value);

    /**
     * Atomically replace the value of {@code key} with {@code fn(current)}, where {@code current} is null when the key is
     * absent. {@code fn} may be called more than once (a retried compare-and-set), so it must be free of side effects other
     * than recording its own result. If {@code fn} returns null nothing changes. Returns the value stored afterwards (null: none).
     */
    Object update(String key, UnaryOperator<Object> fn);

    /** Every key in the store, sorted. A store that cannot list its keys throws UnsupportedOperationException (the default). */
    default java.util.List<String> keys() { throw new UnsupportedOperationException("this AtomicKv cannot list its keys"); }
}
