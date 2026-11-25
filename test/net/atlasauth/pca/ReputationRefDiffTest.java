package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The reputation input validator and the fail-closed edges of the score against the reference corpus (ref-reputation, 85 cases);
 * reasons compare exactly. The scoring, the coverage price and the signed coverage quote are replayed by CoreSweepDiffTest, the
 * settlement evidence by CoreResearchDiffTest. An input that is not an object reads as an input without a subject, as in the reference.
 */
class ReputationRefDiffTest {
    static final String MODULE = "ref-reputation";
    static final int TOTAL = 85;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** The corpus spelling of a non-finite number, {"$num": text}, as that double (throughout a value). */
    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("validateReputationInput", x -> Reputation.validateReputationInput(m(nums(x.get(0)))));
        f.put("reputation", x -> Reputation.reputation(m(nums(x.get(0)))));
        f.put("constants", x -> Issue.obj("MAX_REPUTATION_RECORDS", Reputation.MAX_REPUTATION_RECORDS, "COVERAGE_QUOTE_DOMAIN", Reputation.COVERAGE_QUOTE_DOMAIN));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    /** The record cap is not in the corpus (it would be megabytes): one record over it is refused, exactly at it is not. */
    @Test void recordCap() {
        List<Object> events = new ArrayList<>();
        Map<String, Object> ev = Issue.obj("agent", "a", "outcome", "auto");
        for (int i = 0; i < Reputation.MAX_REPUTATION_RECORDS; i++) events.add(ev);
        assertEquals(null, Reputation.validateReputationInput(Issue.obj("subject", "s", "events", events)));
        events.add(ev);
        assertEquals("too many records", Reputation.validateReputationInput(Issue.obj("subject", "s", "events", events)));
        assertEquals(List.of("invalid input: too many records"), Reputation.reputation(Issue.obj("subject", "s", "disputes", events)).get("factors"));
    }
}
