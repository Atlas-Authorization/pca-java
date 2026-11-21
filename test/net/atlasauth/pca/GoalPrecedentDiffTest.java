package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalExamples;
import net.atlasauth.pca.goal.GoalPrecedent;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal precedent log (scripted flows over signed escalation answers). */
class GoalPrecedentDiffTest {
    private static final String M = "ref-goal-precedent";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Map<String, Object> entryOut(Map<String, Object> r, boolean withCell) {
        if (!Boolean.TRUE.equals(r.get("ok"))) return r;
        Map<String, Object> e = m(r.get("entry"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("digest", e.get("digest"));
        if (withCell) out.put("cell", e.get("cell"));
        out.put("seq", e.get("seq"));
        return out;
    }

    @Test void flow() throws Exception {
        OracleCases.each(M, "flow", a -> {
            Map<String, Object> goal = m(a.get(0)), ont = m(a.get(1)), grant = m(a.get(2));
            GoalPrecedent.Log log = new GoalPrecedent.Log(l(a.get(3)));
            GoalExamples.Space space = GoalExamples.buildSpace(List.of(goal), new ArrayList<>());
            List<Object> out = new ArrayList<>();
            for (Object so : l(a.get(4))) {
                Map<String, Object> s = m(so);
                String op = (String) s.get("op");
                long now = s.get("now") == null ? 0 : Long.parseLong(s.get("now").toString());
                switch (op) {
                    case "append": out.add(entryOut(log.append(m(s.get("answer")), m(s.get("answered")), grant, space, now), true)); break;
                    case "revoke": out.add(entryOut(log.revoke(m(s.get("rev"))), false)); break;
                    case "verifyChain": out.add(log.verifyChain(space)); break;
                    case "lookup": {
                        Map<String, Object> h = log.lookup((String) s.get("policyDigest"), space, m(s.get("case")), now);
                        out.add(h == null ? null : G(h));
                        break;
                    }
                    case "authorize": {
                        Map<String, Object> r = GoalPrecedent.authorizeWithPrecedents(goal, ont, (String) s.get("policyDigest"), log, m(s.get("case")), now);
                        Map<String, Object> o2 = new LinkedHashMap<>();
                        o2.put("decision", r.get("decision"));
                        o2.put("via", r.get("via"));
                        if (r.get("precedent") != null) o2.put("digest", m(r.get("precedent")).get("digest"));
                        out.add(o2);
                        break;
                    }
                    case "tamper": {
                        Map<String, Object> e = log.entries().get(Integer.parseInt(s.get("index").toString()));
                        if (Boolean.TRUE.equals(s.get("del"))) e.remove((String) s.get("key")); else e.put((String) s.get("key"), s.get("value"));
                        out.add(true);
                        break;
                    }
                    default: out.add(log.head());
                }
            }
            return out;
        });
    }

    private static Map<String, Object> G(Map<String, Object> h) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("decision", h.get("decision"));
        out.put("digest", m(h.get("entry")).get("digest"));
        return out;
    }

    @Test void ceilingsOf() throws Exception { OracleCases.each(M, "ceilingsOf", a -> GoalPrecedent.ceilingsOf(m(a.get(0)))); }

    @Test void answerBodyFor() throws Exception {
        OracleCases.each(M, "answerBodyFor", a -> {
            Map<String, Object> o = m(a.get(1));
            return GoalPrecedent.answerBodyFor(m(a.get(0)), (String) o.get("principal"), (String) o.get("decision"), o.get("iat"), o.get("expires_at"), (String) o.get("nonce"));
        });
    }

    @Test void signRevocation() throws Exception { OracleCases.each(M, "signRevocationSeed", a -> GoalPrecedent.signRevocation(m(a.get(0)), Keys.unb64u((String) a.get(1)))); }
}
