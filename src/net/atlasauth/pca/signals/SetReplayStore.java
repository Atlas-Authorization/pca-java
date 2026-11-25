package net.atlasauth.pca.signals;

/**
 * A durable jti replay store for received SETs. addIfAbsent MUST be atomic: of N concurrent calls with the same jti exactly one
 * returns true. An entry may be dropped once nowSec &gt;= expiresAtSec. Back it with a shared store (SQL unique key, Redis SET NX EX)
 * when more than one process receives SETs; check yours with {@link Signals#runSetReplayStoreConformance}.
 */
public interface SetReplayStore {
    boolean addIfAbsent(String jti, double expiresAtSec, double nowSec);
}
