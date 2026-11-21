package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalCrc;
import net.atlasauth.pca.goal.GoalDrift;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal drift monitor and the conformal risk control numerics. */
class GoalDriftDiffTest {
    private static final String M = "ref-goal-drift";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Object copy(Object o) {
        if (o instanceof Map) { Map<String, Object> r = new LinkedHashMap<>(); for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) r.put((String) e.getKey(), copy(e.getValue())); return r; }
        if (o instanceof List) { List<Object> r = new ArrayList<>(); for (Object x : (List<?>) o) r.add(copy(x)); return r; }
        return o;
    }

    private static byte[] key(Object b64) {
        String s = (String) b64;
        return s.isEmpty() ? new byte[0] : Keys.unb64u(s);
    }

    @Test void flow() throws Exception {
        OracleCases.each(M, "flow", a -> {
            Map<String, Object> goal = m(a.get(0)), opts = m(a.get(1));
            GoalDrift.Monitor mon = new GoalDrift.Monitor(goal, opts);
            Map<String, Object> last = null;
            List<Object> out = new ArrayList<>();
            for (Object so : l(a.get(2))) {
                Map<String, Object> s = m(so);
                switch ((String) s.get("op")) {
                    case "observe": out.add(mon.observe(m(s.get("act")), s.get("t"))); break;
                    case "state": out.add(copy(mon.state())); break;
                    case "seal": last = m(copy(mon.seal(key(s.get("key"))))); out.add(copy(last)); break;
                    case "restoreLast": {
                        Map<String, Object> sealed = m(copy(last));
                        String mode = (String) s.get("mode");
                        if (mode.equals("state")) {
                            Map<String, Object> st = new LinkedHashMap<>(m(sealed.get("state")));
                            st.put("strikes", new Json.Num("0"));
                            sealed.put("state", st);
                        }
                        if (mode.equals("mac")) { String mac = (String) sealed.get("mac"); sealed.put("mac", (mac.charAt(0) == '0' ? "1" : "0") + mac.substring(1)); }
                        if (mode.equals("badmac")) sealed.put("mac", "zz");
                        mon = GoalDrift.Monitor.restore(goal, sealed, key(s.get("key")), opts);
                        out.add(copy(mon.state()));
                        break;
                    }
                    default: {
                        Map<String, Object> r = GoalDrift.guardedDecide(goal, m(s.get("ont")), mon, m(s.get("case")), s.get("t"));
                        out.add(copy(r));
                    }
                }
            }
            return out;
        });
    }

    @Test void applyDrift() throws Exception { OracleCases.each(M, "applyDrift", a -> GoalDrift.applyDrift((String) a.get(0), m(a.get(1)))); }
    @Test void alphaOf() throws Exception { OracleCases.each(M, "alphaOf", a -> GoalCrc.alphaOf(Double.parseDouble(a.get(0).toString()))); }

    @Test void calibrate() throws Exception {
        OracleCases.each(M, "calibrate", a -> {
            String gate = (String) a.get(2);
            double cap = gate.equals("none") ? 0 : Double.parseDouble(gate.substring(2)) / 1e5;
            return GoalCrc.calibrate(l(a.get(0)), m(a.get(1)), gate.equals("none") ? null : (k, n) -> GoalCrc.cpUpper95(k, n) <= cap);
        });
    }

    @Test void assertMonotone() throws Exception { OracleCases.each(M, "assertMonotone", a -> { GoalCrc.assertMonotone(l(a.get(0))); return null; }); }
    @Test void cpUpper95() throws Exception { OracleCases.each(M, "cpUpper95", a -> GoalCrc.cpUpper95(Long.parseLong(a.get(0).toString()), Long.parseLong(a.get(1).toString()))); }

    @Test void renderReportMarkdown() throws Exception {
        OracleCases.each(M, "renderReportMarkdown", a -> GoalCrc.renderReportMarkdown(l(a.get(0)), (String) m(a.get(1)).get("source"), (String) m(a.get(1)).get("modelSet")));
    }
}
