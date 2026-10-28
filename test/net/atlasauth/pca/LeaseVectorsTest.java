package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The lease corpus (lease-vectors.json). A missing file FAILS. */
public class LeaseVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("lease-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static List<String> strs(Object o) { List<String> out = new ArrayList<>(); for (Object x : l(o)) out.add((String) x); return out; }

    @Test void scenarios() {
        assertTrue(l(DOC.get("scenarios")).size() >= 10);
        for (Object sx : l(DOC.get("scenarios"))) {
            Map<String, Object> s = m(sx);
            Lease.Policy policy = new Lease.Policy(List.of((String) DOC.get("authority")));
            if (s.containsKey("policy")) {
                Map<String, Object> p = m(s.get("policy"));
                if (p.containsKey("minApprovals")) policy.minApprovals = Json.asLong(p.get("minApprovals"));
                if (p.containsKey("eligibleApprovers")) policy.eligibleApprovers = strs(p.get("eligibleApprovers"));
                if (p.containsKey("freshJustification")) policy.freshJustification = (Boolean) p.get("freshJustification");
            }
            Lease.Registry reg = new Lease.Registry(policy);
            for (Object stx : l(s.get("steps"))) {
                Map<String, Object> st = m(stx), e = m(st.get("expect"));
                String op = (String) st.get("op"), label = s.get("name") + ": " + op;
                if (op.equals("accept")) {
                    Lease.Accept got = reg.accept(l(DOC.get("records")).get((int) Json.asLong(st.get("record"))), st.containsKey("chain") ? strs(st.get("chain")) : List.of());
                    assertEquals(e.get("ok"), got.code == null, label + ": ok");
                    if (got.code == null) { assertEquals(e.get("replaced"), got.replaced, label + ": replaced"); assertEquals(Json.asLong(e.get("seq")), got.seq, label + ": seq"); }
                    else assertEquals(e.get("code"), got.code, label + ": code");
                } else if (op.equals("revoke")) {
                    Lease.Revoke got = reg.revoke(l(DOC.get("revocations")).get((int) Json.asLong(st.get("revocation"))));
                    assertEquals(e.get("ok"), got.code == null, label + ": ok");
                    if (got.code == null) assertEquals(Json.asLong(e.get("revoked")), (long) got.revoked, label + ": revoked");
                    else assertEquals(e.get("code"), got.code, label + ": code");
                } else {
                    assertEquals("check", op, label);
                    Lease.Decision got = reg.check(l(DOC.get("records")).get((int) Json.asLong(st.get("record"))), st.get("now"));
                    assertEquals(e.get("decision"), got.decision, label + ": decision");
                    assertEquals(e.get("code"), got.code, label + ": code");
                    assertEquals(e.get("lease_id"), got.leaseId, label + ": lease_id");
                    if (e.containsKey("expires_at")) assertEquals(Json.asLong(e.get("expires_at")), (long) got.expiresAt, label + ": expires_at");
                    else assertNull(got.expiresAt, label + ": expires_at");
                }
            }
        }
    }

    @Test void pathUnder() {
        assertTrue(Lease.pathUnder("db/prod/ro", "db/prod"));
        assertFalse(Lease.pathUnder("db/production", "db/prod"));
    }

    @Test void totalOnHostileInput() {
        Lease.Registry reg = new Lease.Registry(new Lease.Policy(List.of()));
        for (Object x : new Object[] {null, "x", 1, List.of(), Map.of()}) {
            assertFalse(Lease.verify(x));
            assertFalse(Lease.verifyRevocation(x));
            assertEquals("bad_record", reg.accept(x, List.of()).code);
            assertEquals("bad_input", reg.check(x, "now").code);
        }
    }
}
