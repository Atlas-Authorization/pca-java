package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** contracts-vectors.json: validate, check, advance, verify and the durable enforcer, every row and step. */
public class ContractsVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("contracts-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void validateRows() {
        List<Object> rows = l(DOC.get("validate"));
        assertTrue(rows.size() >= 21, "validate rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            assertEquals(l(m(r.get("expect")).get("problems")), new ArrayList<Object>(Contracts.validateContract(r.get("contract"))), (String) r.get("name"));
        }
    }

    @Test void checkRows() {
        List<Object> rows = l(DOC.get("check"));
        assertTrue(rows.size() >= 11, "check rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            Map<String, Object> got = Contracts.checkContract(r.get("action"), r.get("contract"), r.get("state"));
            assertEquals(Json.canonicalize(r.get("expect")), Json.canonicalize(got), (String) r.get("name"));
        }
    }

    @Test void advanceRows() {
        List<Object> rows = l(DOC.get("advance"));
        assertTrue(rows.size() >= 7, "advance rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Object contract = r.get("contract");
            Object state = Prohibitions.emptyState(r.get("genesis_now"));
            String genesisDigest = Prohibitions.stateDigest(state);
            int i = 0;
            for (Object sx : l(r.get("steps"))) {
                Map<String, Object> st = m(sx);
                Map<String, Object> exp = m(st.get("expect"));
                Map<String, Object> o = st.containsKey("options") ? m(st.get("options")) : new LinkedHashMap<>();
                String label = name + " step " + i++;
                // the "stale digest of genesis" option is the digest of the state the sequence started from
                String digest = Boolean.TRUE.equals(o.get("stale_digest_of_genesis")) ? genesisDigest : null;
                Map<String, Object> res = Contracts.advanceContract(state, st.get("action"), contract, o.get("now"), o.get("expectedSeq"), digest);
                assertEquals(exp.get("ok"), res.get("ok"), label + ": ok");
                assertEquals(exp.get("decidedBy"), res.get("decidedBy"), label + ": decidedBy");
                assertEquals(l(exp.get("violated")), new ArrayList<Object>(l(res.get("violated"))), label + ": violated");
                assertEquals(l(exp.get("reasons")), new ArrayList<Object>(l(res.get("reasons"))), label + ": reasons");
                if (Boolean.TRUE.equals(res.get("ok"))) state = res.get("next");
                Map<String, Object> cur = m(state);
                assertEquals(Prohibitions.dv(exp.get("seq")), Prohibitions.dv(cur.get("seq")), label + ": seq");
                assertEquals(Json.canonicalize(exp.get("deadlines")), Json.canonicalize(cur.containsKey("deadlines") ? cur.get("deadlines") : new LinkedHashMap<>()), label + ": deadlines");
                List<String> latched = new ArrayList<>(m(cur.get("latched")).keySet());
                Collections.sort(latched);
                List<String> want = new ArrayList<>();
                for (Object k : l(exp.get("latched"))) want.add((String) k);
                Collections.sort(want);
                assertEquals(want, latched, label + ": latched");
                assertEquals(exp.get("state_digest"), Prohibitions.stateDigest(state), label + ": state digest");
            }
        }
    }

    @Test void verifyRows() {
        List<Object> rows = l(DOC.get("verify"));
        assertTrue(rows.size() >= 7, "verify rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String why = Contracts.verifyContract(r.get("contract"), r.get("principal") instanceof String ? (String) r.get("principal") : null);
            Map<String, Object> exp = m(r.get("expect"));
            assertEquals(exp.get("ok"), why == null, r.get("name") + " (" + why + ")");
            if (!Boolean.TRUE.equals(exp.get("ok"))) assertEquals(exp.get("reason"), why, (String) r.get("name"));
        }
    }

    @Test void enforcerRows() {
        List<Object> rows = l(DOC.get("enforcer"));
        assertTrue(rows.size() >= 9, "enforcer rows: " + rows.size());
        Map<String, Object> head = m(rows.get(0));
        Object contract = head.get("contract");
        String principal = (String) head.get("principal");
        double clock = Prohibitions.dv(head.get("clock"));
        int ran = 0;
        for (Object x : rows.subList(1, rows.size())) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> opts = r.containsKey("options") ? m(r.get("options")) : new LinkedHashMap<>();
            MemoryAtomicKv kv = new MemoryAtomicKv();
            double[] wall = {clock};
            boolean latch = !Boolean.FALSE.equals(opts.get("latchOnViolation"));
            ContractEnforcer en = ContractEnforcer.open(kv, contract, principal, "k", () -> wall[0], latch);
            if (r.containsKey("stored_document")) kv.set("k", r.get("stored_document"));
            int i = 0;
            for (Object sx : l(r.get("steps"))) {
                Map<String, Object> st = m(sx);
                Map<String, Object> exp = m(st.get("expect"));
                String label = name + " step " + i++;
                String op = (String) st.get("op");
                if (st.containsKey("wall")) wall[0] = Prohibitions.dv(st.get("wall"));
                if (op.equals("check") || op.equals("peek")) {
                    ContractEnforcer.Result res = op.equals("check") ? en.check(st.get("action"), !Boolean.FALSE.equals(st.get("permitted"))) : en.peek(st.get("action"));
                    assertEquals(exp.get("allow"), res.allow, label + ": allow");
                    assertEquals(exp.get("reason"), res.reason, label + ": reason");
                    assertEquals(l(exp.get("violated")), res.violated, label + ": violated");
                    assertEquals(l(exp.get("reasons")), res.reasons, label + ": reasons");
                    assertEquals((long) Prohibitions.dv(exp.get("seq")), res.seq, label + ": seq");
                } else if (op.equals("state")) {
                    Map<String, Object> got = en.state();
                    assertEquals(Prohibitions.dv(exp.get("seq")), Prohibitions.dv(m(got.get("state")).get("seq")), label + ": seq");
                    assertEquals(Prohibitions.dv(exp.get("now")), Prohibitions.dv(m(got.get("state")).get("now")), label + ": now");
                    assertEquals(exp.get("latched"), got.get("latched"), label + ": latched");
                    assertEquals(exp.get("state_digest"), Prohibitions.stateDigest(got.get("state")), label + ": state digest");
                } else {
                    assertEquals("reset", op, label);
                    assertEquals(exp.get("cleared"), en.reset((String) st.get("sig")), label + ": cleared");
                }
                ran++;
            }
        }
        assertTrue(ran >= 20, "enforcer steps: " + ran);
    }
}
