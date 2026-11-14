package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The A2A binding corpus (a2a-vectors.json). A missing file FAILS. */
public class A2aVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("a2a-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static List<String> strs(Object o) { List<String> out = new ArrayList<>(); for (Object x : l(o)) out.add((String) x); return out; }

    @Test void needs() {
        assertTrue(l(DOC.get("need")).size() >= 20);
        for (Object x : l(DOC.get("need"))) {
            Map<String, Object> c = m(x);
            Object input = c.get("input") instanceof Json.Num ? ((Json.Num) c.get("input")).raw : c.get("input");
            A2a.Decoded d = A2a.decodeNeed(input);
            Map<String, Object> e = m(c.get("expect"));
            assertEquals(e.get("ok"), d.code == null, c.get("name") + ": ok");
            if (d.code == null) assertEquals(e.get("digest"), A2a.needDigest(d.need), c.get("name") + ": digest");
            else assertEquals(e.get("code"), d.code, c.get("name") + ": code");
        }
    }

    @Test void push() {
        Map<String, Object> p = m(DOC.get("push"));
        for (Object x : l(p.get("tokens"))) { Map<String, Object> t = m(x); assertEquals(t.get("token"), A2a.pushToken((String) t.get("task_id"), strs(t.get("chain_ids")), t.get("salt"))); }
        for (Object s : l(p.get("weak_salts"))) assertNull(A2a.pushToken("t", List.of("a"), s));
        for (Object x : l(p.get("checks"))) {
            Map<String, Object> c = m(x), e = m(c.get("expected")), d = m(c.get("delivered")), exp = m(c.get("expect"));
            String got = A2a.checkPush((String) e.get("task_id"), strs(e.get("chain_ids")), (String) e.get("salt"), d.get("token"), d.get("payload"));
            assertEquals(exp.get("ok"), got == null, c.get("name") + ": ok");
            if (got != null) assertEquals(exp.get("reason"), got, c.get("name") + ": reason");
        }
    }

    @Test void chains() {
        for (Object x : l(DOC.get("chains"))) {
            Map<String, Object> c = m(x), exp = m(c.get("expect"));
            List<List<String>> chains = new ArrayList<>();
            for (Object y : l(c.get("chains"))) chains.add(strs(y));
            Object[] got = A2a.checkChainExtension(chains);
            assertEquals(exp.get("ok"), got == null, c.get("name") + ": ok");
            if (got != null) {
                assertEquals(exp.get("reason"), got[1], c.get("name") + ": reason");
                assertEquals(Json.asLong(exp.get("failedHop")), ((Integer) got[0]).longValue(), c.get("name") + ": hop");
            }
        }
    }

    @Test void resume() {
        for (Object x : l(DOC.get("resume"))) {
            Map<String, Object> c = m(x);
            Map<String, Object> pa = c.get("proof_action") == null ? null : m(c.get("proof_action"));
            String got = A2a.resumeGate((String) c.get("state"), c.get("need_encoded"), c.get("answer_need_digest"), pa == null ? null : (String) pa.get("verb"), pa == null ? null : (String) pa.get("resource"));
            assertEquals(c.get("expect"), got, (String) c.get("name"));
        }
    }

    @Test void receipts() {
        Map<String, Object> r = m(DOC.get("receipts"));
        String signer = (String) r.get("signer");
        List<Object> recs = l(r.get("records"));
        for (Object x : l(r.get("verify"))) { Map<String, Object> v = m(x); assertEquals(v.get("ok"), A2a.verifyReceipt(recs.get((int) Json.asLong(v.get("record"))), signer), "verify " + v.get("record")); }
        for (Object x : l(r.get("digests"))) { Map<String, Object> d = m(x); assertEquals(d.get("digest"), A2a.receiptDigest(recs.get((int) Json.asLong(d.get("record"))))); }
        for (Object x : l(r.get("scenarios"))) {
            Map<String, Object> s = m(x), exp = m(s.get("expect"));
            List<Object> list = new ArrayList<>();
            for (Object i : l(s.get("indices"))) list.add(recs.get((int) Json.asLong(i)));
            A2a.ReceiptChain got = A2a.checkReceiptChain(list, signer, (String) s.get("task_id"), strs(s.get("chain_ids")));
            String name = (String) s.get("name");
            assertEquals(exp.get("ok"), got.code == null, name + ": ok");
            if (got.code == null) { assertEquals(exp.get("terminal"), got.terminal, name); assertEquals(exp.get("last_state"), got.lastState, name); }
            else { assertEquals(exp.get("code"), got.code, name); if (exp.containsKey("at")) assertEquals(Json.asLong(exp.get("at")), (long) got.at, name + ": at"); }
            assertEquals(s.get("may_trigger_next"), A2a.mayTriggerNext(list, signer, (String) s.get("task_id"), strs(s.get("chain_ids"))), name + ": may");
        }
    }
}
