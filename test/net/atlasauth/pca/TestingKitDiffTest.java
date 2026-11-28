package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.testing.TestingKit;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the testing kit (constants, route mapping, fake verifier, tamper, state store). */
class TestingKitDiffTest {
    private static final String MODULE = "ref-testing";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    private static TestingKit.FakeVerifyOptions opts(Object o) {
        Map<String, Object> src = m(o);
        TestingKit.FakeVerifyOptions r = new TestingKit.FakeVerifyOptions();
        if (src.containsKey("audience")) r.audience((String) src.get("audience"));
        if (src.get("now") != null) r.now(Long.parseLong(src.get("now").toString()));
        if (src.get("grant") != null) r.grant(m(src.get("grant")));
        return r;
    }

    @Test void consts() throws Exception {
        OracleCases.each(MODULE, "consts", a -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("aud", TestingKit.ADAPTER_ACCEPTANCE_AUDIENCE);
            out.put("expected", TestingKit.adapterAcceptanceExpected());
            return out;
        });
    }

    @Test void acceptanceOperation() throws Exception { OracleCases.each(MODULE, "acceptanceOperation", a -> TestingKit.acceptanceOperation(m(a.get(0)))); }
    @Test void fakeVerify() throws Exception { OracleCases.each(MODULE, "fakeVerifyAllow", a -> TestingKit.fakeVerify(a.get(0), opts(a.get(1))).allow()); }
    @Test void expectVerifies() throws Exception { OracleCases.each(MODULE, "expectVerifies", a -> TestingKit.expectVerifies(a.get(0), opts(a.get(1))).allow()); }
    @Test void expectDenied() throws Exception { OracleCases.each(MODULE, "expectDenied", a -> TestingKit.expectDenied(a.get(0), opts(a.get(1))).allow()); }

    @Test void tamper() throws Exception {
        OracleCases.each(MODULE, "tamper", a -> {
            Map<String, Object> mut = m(a.get(1));
            return TestingKit.tamper((String) a.get(0), rec -> {
                String op = (String) mut.get("op");
                if (op.equals("none")) return;
                List<Object> path = l(mut.get("path"));
                Object cur = rec;
                for (int i = 0; i < path.size() - 1; i++) cur = m(cur).get((String) path.get(i));
                Map<String, Object> holder = m(cur); // a missing parent is a null here: the reference throws, so does this
                String last = (String) path.get(path.size() - 1);
                if (op.equals("set")) holder.put(last, mut.get("value"));
                else holder.remove(last);
            });
        });
    }

    @Test void memoryStateStore() throws Exception {
        OracleCases.each(MODULE, "memorySession", a -> {
            TestingKit.MemoryStateStore s = TestingKit.memoryStateStore();
            List<Object> out = new java.util.ArrayList<>();
            for (Object op : l(a.get(0))) {
                List<Object> o = l(op);
                if (o.get(0).equals("put")) s.put((String) o.get(1), m(o.get(2)));
                else out.add(s.get((String) o.get(1)));
            }
            return out;
        });
    }

    /** A real agent built with the defaults verifies, a tampered one does not, and a PQ-free round trip needs no grant. */
    @Test void roundTrip() {
        net.atlasauth.pca.Facade.Handle a = TestingKit.testAgent(null);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("amount", new Json.Num("42"));
        TestingKit.Made made = TestingKit.makePCActn(a, "stripe.refund", "charge:ch_1", params, null, null);
        org.junit.jupiter.api.Assertions.assertTrue(TestingKit.expectVerifies(made.pcactn(), null).allow());
        String bad = TestingKit.tamper(made.encoded(), rec -> m(rec.get("action")).put("verb", "stripe.payout"));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> TestingKit.expectVerifies(Json.parse(bad), null));
        org.junit.jupiter.api.Assertions.assertFalse(TestingKit.expectDenied(Json.parse(bad), null).allow());
    }
}
