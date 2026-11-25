package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback. */
class BaseOracleClockTest {
    @Test void headerClockIsRead() {
        assertEquals(1_700_000_000_000d, BaseOracle.clockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"clockMs\":1700000000000,\"cases\":["));
    }

    @Test void missingHeaderClockFallsBack() {
        assertEquals(BaseOracle.FALLBACK_CLOCK_MS, BaseOracle.clockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"cases\":["));
        assertEquals(BaseOracle.FALLBACK_CLOCK_MS, BaseOracle.clockOfHeader(null));
    }

    @Test void headerClockCasesAreRead() {
        java.util.Set<String> cc = BaseOracle.clockCasesOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"clockMs\":1700000000000,\"clockCases\":[\"f/a\",\"f/b\"],\"cases\":[");
        assertEquals(java.util.Set.of("f/a", "f/b"), cc);
        assertEquals(java.util.Set.of(), BaseOracle.clockCasesOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"cases\":["));
        assertEquals(java.util.Set.of(), BaseOracle.clockCasesOfHeader(null));
    }
}
