package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The information-flow taint gate (enforce.taint): server-side re-classification, fail-closed lineage, the policy bound. */
class TaintTest {
    static Map<String, Object> prov(Object refs) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("causal_hash", "");
        p.put("taint_level", 0L);
        if (refs != null) p.put("trusted_refs", refs);
        return p;
    }

    static Taint.Context ctx() {
        Taint.InMemoryRegistry reg = new Taint.InMemoryRegistry().record("t", "trusted").record("f", "first_party").record("tool1", "tool").record("w", "web");
        reg.record("", "trusted").record("x", "bogus").record(null, "trusted");
        return new Taint.Context(reg, ref -> ref.equals("graph-node"));
    }

    @Test void theLatticeRanksTheLineageByItsWorstRef() {
        Taint.Context c = ctx();
        assertEquals(0, Taint.compute(prov(List.of("t")), c).rank);
        assertEquals(1, Taint.compute(prov(List.of("t", "f")), c).rank);
        assertEquals(2, Taint.compute(prov(List.of("f", "tool1")), c).rank);
        assertEquals(3, Taint.compute(prov(List.of("tool1", "w", "t")), c).rank);
        assertEquals(4, Taint.compute(prov(List.of("t", "unknown")), c).rank); // an unverifiable ref is the agent label
        assertEquals(1, Taint.compute(prov(List.of("graph-node")), c).rank); // the server's own resource graph vouches first party
        assertEquals(4, Taint.compute(prov(List.of("x")), c).rank); // an unknown level is not a vouching
        assertEquals(0.75, Taint.compute(prov(List.of("w")), c).taint(), 1e-12);
        assertTrue(Taint.compute(prov(List.of("t")), c).valid);
        // the empty lineage and an absent trusted_refs are the worst case (no verifiable trusted input), still valid
        for (Object refs : new Object[] {List.of(), null}) {
            Taint.Result r = Taint.compute(prov(refs), c);
            assertTrue(r.valid);
            assertEquals(4, r.rank);
            assertEquals(1.0, r.taint(), 1e-12);
        }
        // a throwing graph is the worst case for that ref
        Taint.Context throwing = new Taint.Context(ref -> null, ref -> { throw new IllegalStateException("x"); });
        assertEquals(4, Taint.compute(prov(List.of("a")), throwing).rank);
    }

    @Test void malformedProvenanceFailsClosed() {
        Taint.Context c = ctx();
        Taint.Result noReg = Taint.compute(prov(List.of("t")), new Taint.Context(null, null));
        assertFalse(noReg.valid);
        assertEquals("taint: no trusted-input registry", noReg.reason);
        assertEquals("taint: no trusted-input registry", Taint.compute(prov(List.of("t")), null).reason);
        for (Object bad : new Object[] {null, "x", List.of()}) assertEquals("taint: provenance is absent or malformed", Taint.compute(bad, c).reason);
        assertEquals("taint: trusted_refs must be an array", Taint.compute(prov("t"), c).reason);
        Map<String, Object> nul = prov(null);
        nul.put("trusted_refs", null);
        assertEquals("taint: trusted_refs must be an array", Taint.compute(nul, c).reason);
        assertEquals("taint: trusted_refs must be non-empty strings", Taint.compute(prov(List.of("t", "")), c).reason);
        assertEquals("taint: trusted_refs must be non-empty strings", Taint.compute(prov(java.util.Arrays.asList("t", null)), c).reason);
        assertEquals("taint: trusted_refs must be non-empty strings", Taint.compute(prov(List.of("t", 5L)), c).reason);
        Taint.Result thrown = Taint.compute(prov(List.of("t")), new Taint.Context(ref -> { throw new IllegalStateException("boom"); }, null));
        assertFalse(thrown.valid);
        assertEquals(4, thrown.rank);
        assertEquals("taint: evaluation error (fail closed): boom", thrown.reason);
    }

    @Test void theGateBoundsTheTaint() {
        Taint.Context c = ctx();
        assertNull(Taint.gate(prov(List.of("t")), c, 0));
        assertNull(Taint.gate(prov(List.of("f")), c, 0.25));
        assertEquals("information-flow taint 0.25 exceeds policy max 0.2", Taint.gate(prov(List.of("f")), c, 0.2));
        assertNull(Taint.gate(prov(List.of("w")), c, 0.8));
        assertEquals("information-flow taint 1 exceeds policy max 0.99", Taint.gate(prov(List.of("unknown")), c, 0.99));
        assertNull(Taint.gate(prov(List.of("unknown")), c, 1));
        assertEquals("taint: trusted_refs must be an array", Taint.gate(prov("t"), c, 1));
        // the invalid lineage is reported before a misconfigured bound; a negative or NaN bound is misconfigured
        assertEquals("taint: no trusted-input registry", Taint.gate(prov(List.of("t")), null, -1));
        String mis = "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)";
        assertEquals(mis, Taint.gate(prov(List.of("t")), c, -0.5));
        assertEquals(mis, Taint.gate(prov(List.of("t")), c, Double.NaN));
    }

    @Test void theAuthorizeGateRecordsTaintGate() {
        Map<String, Object> clean = K05ParityAuditTest.agentSigned("provenance", prov(List.of("t")));
        Authorize.AuthorizeResult ok = Authorize.authorize(clean, AuthorizeK05KillTest.input(Map.of("amount", 50L)).enforceTaint(ctx(), 0.25));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("taint_gate"));
        Map<String, Object> dirty = K05ParityAuditTest.agentSigned("provenance", prov(List.of("t", "unknown")));
        Authorize.AuthorizeResult no = Authorize.authorize(dirty, AuthorizeK05KillTest.input(Map.of("amount", 50L)).enforceTaint(ctx(), 0.25));
        assertFalse(no.allow);
        assertEquals("fail", no.checks.get("taint_gate"));
        assertTrue(no.reasons.contains("taint_gate: information-flow taint 1 exceeds policy max 0.25"), no.reasons.toString());
        assertNull(Authorize.authorize(K05ParityAuditTest.agentSigned("provenance", prov(List.of("unknown"))), AuthorizeK05KillTest.input(Map.of("amount", 50L))).checks.get("taint_gate"));
    }
}
