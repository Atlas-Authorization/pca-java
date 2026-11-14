package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The intent-state corpus (intent-state-vectors.json, format pca-intent-state-vectors / 1): accumulator and monitor
 * declarations, selection and values, pre-states, reservation receipts, sequencer key sets (IntentAcc) and the session-history
 * functions (IntentHistory: windows, keys, pre-state, post, monitor folds). Every case asserts the reference output exactly
 * (compared as canonical JSON); every function of the file has a runner, and a function without one fails.
 */
public class IntentStateVectorsTest {
    static List<Map<String, Object>> CASES;

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void load() {
        Map<String, Object> doc = Track3Vectors.load("intent-state-vectors.json");
        assertEquals("pca-intent-state-vectors", doc.get("format"));
        assertEquals(1L, Json.asLong(doc.get("ver")));
        CASES = new ArrayList<>();
        for (Object o : (List<Object>) doc.get("cases")) CASES.add((Map<String, Object>) o);
        assertTrue(CASES.size() >= 3000, "corpus too small: " + CASES.size());
    }

    @SuppressWarnings("unchecked")
    static List<Object> args(Map<String, Object> c) { return (List<Object>) c.get("args"); }
    static Map<String, Object> m(Object o) { return IntentJs.obj(o); }
    static String s(Object o) { return (String) o; }
    static double d(Object o) { return IntentJs.num(o); }
    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) { return o instanceof List ? (List<Object>) o : new ArrayList<>(); }

    static Object toJson(Object o) {
        if (o instanceof Long || o instanceof Integer) return new Json.Num(o.toString());
        if (o instanceof IntentAcc.AccValue) {
            IntentAcc.AccValue v = (IntentAcc.AccValue) o;
            Map<String, Object> r = new LinkedHashMap<>();
            if (v.reason != null) {
                r.put("ok", false);
                r.put("reason", v.reason);
                if (v.val != 0 || v.key != null) r.put("leaked", v.val + "/" + v.key);
            } else {
                r.put("ok", true);
                r.put("val", new Json.Num(Long.toString(v.val)));
                r.put("key", v.key);
            }
            return r;
        }
        return o;
    }

    static final Set<String> RUN = new LinkedHashSet<>();

    /** Runs every case of {@code fn}; each must equal the reference output. */
    static void run(String fn, Function<List<Object>, Object> f) {
        RUN.add(fn);
        List<String> bad = new ArrayList<>();
        int n = 0;
        for (Map<String, Object> c : CASES) {
            if (!fn.equals(c.get("fn"))) continue;
            n++;
            Object got;
            try {
                got = f.apply(args(c));
            } catch (RuntimeException e) {
                got = "THREW " + e;
            }
            String want = Json.canonicalize(c.get("out"));
            String g = Json.canonicalize(toJson(got));
            if (!want.equals(g)) bad.add(c.get("name") + "\n    want " + want + "\n    got  " + g);
        }
        assertTrue(n > 0, "no cases for " + fn);
        assertTrue(bad.isEmpty(), bad.size() + "/" + n + " " + fn + " cases differ from the reference:\n  " + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 30))));
    }

    static Object throwsOr(Object v) {
        if (v != null) return v;
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("throws", true);
        return t;
    }

    @Test void declarations() {
        run("accumulatorDeclError", a -> IntentAcc.accumulatorDeclError(a.get(0)));
        run("monitorDeclError", a -> IntentAcc.monitorDeclError(a.get(0)));
        run("monitorStates", a -> IntentAcc.monitorStates(m(a.get(0))));
        run("trackedKeySetError", a -> IntentAcc.trackedKeySetError(a.get(0)));
    }

    @Test void preStateValues() {
        run("preStateError", a -> IntentAcc.preStateError(a.get(0), a.get(1)));
        run("preValue", a -> IntentAcc.preValue(a.get(0), m(a.get(1))));
        run("combineAcc", a -> IntentAcc.combineAcc(a.get(0), m(a.get(1)), new IntentAcc.AccValue(null, IntentJs.lng(IntentJs.get(a.get(2), "val")), (String) IntentJs.get(a.get(2), "key"))));
    }

    @Test void selectionAndValues() {
        run("accSelects", a -> IntentAcc.accSelects(m(a.get(0)), s(a.get(1)), a.get(2)));
        run("accValueOf", a -> IntentAcc.accValueOf(m(a.get(0)), s(a.get(1)), m(a.get(2)), a.get(3)));
    }

    @Test void receiptsAndKeySets() {
        run("receiptArithmeticOk", a -> IntentAcc.receiptArithmeticOk(a.get(0), m(a.get(1)), IntentJs.lng(a.get(2))));
        run("pcactnReservationDigest", a -> IntentAcc.pcactnReservationDigest(m(a.get(0))));
        run("receiptShapeError", a -> IntentAcc.receiptShapeError(a.get(0)));
        run("keySetShapeError", a -> IntentAcc.keySetShapeError(a.get(0)));
        run("verifyKeySet", a -> IntentAcc.verifyKeySet(a.get(0), s(a.get(1)), a.get(2), (Boolean) a.get(3)));
        run("verifyReceiptSignature", a -> a.get(0) instanceof Map ? IntentAcc.verifyReceiptSignature(m(a.get(0)), s(a.get(1)), a.get(2) == null ? null : m(a.get(2))) : false);
        run("verifyReceiptAgainstHolder", a -> IntentAcc.verifyReceiptAgainstHolder(m(a.get(0)), m(a.get(1)), a.get(2), d(a.get(3)), d(a.get(4)), d(a.get(5)), a.get(6)));
    }

    @Test void sessionHistory() {
        run("inWindow", a -> IntentHistory.inWindow(m(a.get(0)), a.get(1), a.get(2)));
        run("accKeyOf", a -> IntentHistory.accKeyOf(m(a.get(0)), m(a.get(1))));
        run("accPreState", a -> {
            Map<String, Object> cand = m(a.get(2));
            return throwsOr(IntentHistory.accPreState(m(a.get(0)), list(a.get(1)), m(cand.get("params")), cand.get("t"), a.get(3)));
        });
        run("accPost", a -> {
            Map<String, Object> cand = m(a.get(2));
            return throwsOr(IntentHistory.accPost(m(a.get(0)), list(a.get(1)), s(cand.get("verb")), m(cand.get("params")), cand.get("t"), a.get(3)));
        });
        run("monitorStep", a -> IntentHistory.monitorStep(m(a.get(0)), s(a.get(1)), m(a.get(2))));
        run("monitorState", a -> IntentHistory.monitorState(m(a.get(0)), list(a.get(1))));
    }

    /** Every function of the corpus has a runner above: a new function without one fails here. */
    @Test void everyCorpusFunctionIsRun() {
        declarations(); preStateValues(); selectionAndValues(); receiptsAndKeySets(); sessionHistory();
        Set<String> seen = new LinkedHashSet<>();
        for (Map<String, Object> c : CASES) seen.add((String) c.get("fn"));
        for (String fn : seen) assertTrue(RUN.contains(fn), "no runner for corpus function " + fn);
        for (String fn : RUN) assertTrue(seen.contains(fn), "corpus has no case for " + fn);
    }
}
