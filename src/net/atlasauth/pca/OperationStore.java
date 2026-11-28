package net.atlasauth.pca;

import java.util.List;

/**
 * Durable, shared storage for {@link OperationRecord}s. Both methods that change state MUST be atomic across every process
 * and node that shares the store (a unique-key insert and a conditional {@code UPDATE ... WHERE state = ?}, a Redis script,
 * {@link AtomicKv#update}). A call that cannot decide MUST throw an unchecked exception; the executor then refuses or reports
 * the outcome as unknown. {@link MemoryOperationStore} is the in-process reference; {@link AtomicKvOperationStore} runs over any
 * {@link AtomicKv} such as {@link PcaJdbcAtomicKv}.
 */
public interface OperationStore {
    /** Atomically insert {@code record} if no record with its id exists (returns null); otherwise return the existing record unchanged. */
    OperationRecord create(OperationRecord record);

    /** The record, or null. */
    OperationRecord get(String id);

    /** Atomically replace the record with {@code next} only if its current state is {@code from}. Returns whether it did. */
    boolean transition(String id, String from, OperationRecord next);

    /** True when {@link #listOpen} works (otherwise recover a known id with {@code Operations.recoverOperation}). */
    default boolean supportsListOpen() { return false; }

    /** Records still open, in state {@code pending} or {@code executing}. */
    default List<OperationRecord> listOpen() { throw new UnsupportedOperationException("this store has no listOpen"); }

    /** True when the records live in this process only (a crash loses them: tests and single-process tools). */
    default boolean processLocal() { return false; }
}
