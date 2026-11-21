package net.atlasauth.pca;

import org.junit.jupiter.api.Test;

/** PCA 0.5 mutation kills for {@link StoreConformance}: a store that raises inside the in-flight retry race, and a transition that stores the wrong state. */
public class K05R5G5StoreTest {
    @Test void aRaiseDuringTheInFlightRetryRaceIsReportedAsSuch() {
        K05StoreConformanceKillTest.stateFault(5, "fail retry-after-timeout: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom", 2, 1, 2, (h, p, c, r) -> {
            if (p.equals("retry") && c == 3) throw new IllegalStateException("boom");
            return r.get();
        });
    }

    @Test void aTransitionThatStoresTheWrongStateIsNotStored() {
        K05StoreConformanceKillTest.opFault(0, "fail semantics: the transition was not stored", 2, 1, 2, new K05StoreConformanceKillTest.OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, K05StoreConformanceKillTest.sem(id) && next.executingAt() != null ? next.with("state", "pending") : next);
            }
        });
    }
}
