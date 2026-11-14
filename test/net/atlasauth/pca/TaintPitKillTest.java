package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Taint: the lattice ranks, what the registry may record, the graph fallback for an unknown level, and the policy bound. */
class TaintPitKillTest {
    static Map<String, Object> prov(Object refs) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("trusted_refs", refs);
        return p;
    }

    @Test void rankOfKindIsTheLatticePositionAndAnUnknownKindIsTheWorst() {
        String[] levels = {"trusted", "first_party", "tool", "web", "agent"};
        for (int i = 0; i < levels.length; i++) assertEquals(i, Taint.rankOfKind(levels[i]), levels[i]);
        assertEquals(4, Taint.rankOfKind("bogus"));
        assertEquals(4, Taint.rankOfKind(null));
        assertEquals(4, Taint.rankOfKind(7));
    }

    @Test void theInMemoryRegistryRecordsOnlyANonEmptyDigestAtAKnownLevel() {
        Taint.InMemoryRegistry r = new Taint.InMemoryRegistry();
        assertTrue(r.record(null, "trusted") == r);
        r.record("", "trusted").record("d", "bogus").record("e", null).record("ok", "web");
        assertNull(r.lookup(null));
        assertNull(r.lookup(""));
        assertNull(r.lookup("d"));
        assertNull(r.lookup("e"));
        assertEquals("web", r.lookup("ok"));
    }

    @Test void aLevelTheServerDoesNotKnowIsNotAVouchingAndFallsBackToTheGraph() {
        Taint.Registry odd = d -> "bogus";
        assertEquals(1, Taint.compute(prov(List.of("n")), new Taint.Context(odd, n -> true)).rank, "the graph vouches first party");
        assertEquals(4, Taint.compute(prov(List.of("n")), new Taint.Context(odd, n -> false)).rank);
        assertEquals(4, Taint.compute(prov(List.of("n")), new Taint.Context(odd, null)).rank, "no graph at all");
        Taint.Registry known = d -> "tool";
        assertEquals(2, Taint.compute(prov(List.of("n")), new Taint.Context(known, n -> true)).rank, "a vouched level wins over the graph");
        assertEquals(4, Taint.compute(prov(List.of("n")), new Taint.Context(d -> null, n -> { throw new IllegalStateException("x"); })).rank);
    }

    @Test void trustedRefsIsReadByValueEvenWhenTheMapDeniesTheKey() {
        Map<String, Object> p = new HashMap<String, Object>() {
            @Override public boolean containsKey(Object k) { return false; }
        };
        p.put("trusted_refs", List.of("t"));
        Taint.Result r = Taint.compute(p, new Taint.Context(d -> "trusted", null));
        assertTrue(r.valid);
        assertEquals(0, r.rank);
    }

    @Test void theGateRoundsTheBoundDownToAWholeRank() {
        Taint.Context agent = new Taint.Context(d -> "agent", null);
        Taint.Context web = new Taint.Context(d -> "web", null);
        Map<String, Object> p = prov(List.of("x"));
        assertEquals("information-flow taint 1 exceeds policy max 0.8", Taint.gate(p, agent, 0.8));
        assertEquals("information-flow taint 1 exceeds policy max 0.99", Taint.gate(p, agent, 0.99));
        assertNull(Taint.gate(p, agent, 1.0));
        assertNull(Taint.gate(p, agent, 5.0));
        assertNull(Taint.gate(p, web, 0.75));
        assertEquals("information-flow taint 0.75 exceeds policy max 0.74", Taint.gate(p, web, 0.74));
        assertEquals("information-flow taint 0.75 exceeds policy max 0", Taint.gate(p, web, 0));
        assertNull(Taint.gate(p, new Taint.Context(d -> "trusted", null), 0));
        String mis = "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)";
        assertEquals(mis, Taint.gate(p, web, -0.1));
        assertEquals(mis, Taint.gate(p, web, Double.NaN));
        assertEquals("taint: provenance is absent or malformed", Taint.gate(null, web, 0.5));
        assertEquals("taint: no trusted-input registry", Taint.gate(p, null, -1));
    }
}
