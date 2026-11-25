package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.research.Console;
import net.atlasauth.pca.research.Dlp;
import net.atlasauth.pca.research.Immune;
import net.atlasauth.pca.research.PolicySim;
import net.atlasauth.pca.research.ReputationEvidence;
import net.atlasauth.pca.research.Session;
import org.junit.jupiter.api.Test;

/** The research-tier pure modules (session, console with the immune read side, DLP, policy simulation, reputation evidence) against the reference. */
public class CoreResearchDiffTest {
    static final String MODULE = "ref-core-research-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Keys.EdKey ed(Object label) { return Keys.edFromSeed(CoreStoresDiffTest.seed("research/" + label)); }

    static double d(Object o) { return StoreJs.dbl(o); }

    @Test void evaluateDlp() throws Exception { OracleCases.each(MODULE, "evaluateDlp", a -> Dlp.evaluateDlp(m(a.get(0)), m(a.get(1)))); }

    @Test void defaultDlpPolicy() throws Exception { OracleCases.each(MODULE, "defaultDlpPolicy", a -> Dlp.defaultDlpPolicy(m(a.get(0)))); }

    @Test void immune() throws Exception {
        OracleCases.each(MODULE, "assess", a -> Immune.assess(a.get(0)));
        OracleCases.each(MODULE, "validateImmuneState", a -> Immune.validateImmuneState(a.get(0)));
        OracleCases.each(MODULE, "observe", a -> Immune.observe(m(a.get(0)), m(a.get(1))));
        OracleCases.each(MODULE, "updateBaseline", a -> Immune.updateBaseline(m(a.get(0)), d(a.get(1))));
        OracleCases.each(MODULE, "baselineStd", a -> StoreJs.num(Immune.baselineStd(m(a.get(0)))));
    }

    @Test void console() throws Exception {
        OracleCases.each(MODULE, "buildConsole", a -> Console.buildConsole(l(a.get(0))));
        OracleCases.each(MODULE, "anomalies", a -> Console.anomalies(Console.buildConsole(l(a.get(0)))));
        OracleCases.each(MODULE, "eventFromPCActn", a -> Console.eventFromPCActn(m(a.get(0)), (String) a.get(1), a.get(2) == null ? null : d(a.get(2))));
        OracleCases.each(MODULE, "freezeAgent", a -> Console.freezeAgent(m(a.get(0)), a.get(1)));
        OracleCases.each(MODULE, "unfreezeAgent", a -> Console.unfreezeAgent(m(a.get(0)), a.get(1)));
        OracleCases.each(MODULE, "isFrozen", a -> Console.isFrozen(a.get(0), a.get(1)));
    }

    static Facade.Handle agentOf(Object specO) {
        Map<String, Object> s = m(specO);
        Facade.AgentOptions o = new Facade.AgentOptions(Keys.ed25519(ed(s.get("principal"))), (String) s.get("goal"), m(s.get("permissions")))
            .holder(Keys.ed25519(ed(s.get("holder")))).goalSalt((String) s.get("goalSalt")).now((long) d(s.get("now")));
        return Agent.fromPrincipal(o);
    }

    static String goalOf(Facade.Handle h) {
        Map<String, Object> env = Authorize.readEnvelope(h.grant);
        return env != null && env.get("goal_commit") instanceof String ? (String) env.get("goal_commit") : "";
    }

    @Test void session() throws Exception {
        OracleCases.each(MODULE, "session", a -> {
            Map<String, Facade.Handle> ags = new HashMap<>();
            Map<String, Session> sess = new HashMap<>();
            List<Object> out = new ArrayList<>();
            for (Object oo : (List<?>) a.get(0)) {
                List<?> op = (List<?>) oo;
                try {
                    Object v = null;
                    switch ((String) op.get(0)) {
                        case "agent": { Facade.Handle h = agentOf(op.get(2)); ags.put((String) op.get(1), h); v = h.holder.ed.id(); break; }
                        case "start": { Session s = Session.startSession(need(ags, op.get(2))); sess.put((String) op.get(1), s); v = s.goalCommit; break; }
                        case "mk": {
                            List<Facade.Handle> ms = new ArrayList<>();
                            for (Object n : (List<?>) op.get(2)) ms.add(need(ags, n));
                            String goal = op.get(3) != null ? (String) op.get(3) : ms.isEmpty() ? "" : goalOf(ms.get(0));
                            Session s = new Session(ms.isEmpty() ? null : ms.get(0), ms, goal);
                            sess.put((String) op.get(1), s);
                            v = s.goalCommit;
                            break;
                        }
                        case "add": {
                            Keys.SuiteKey child = op.get(3) == null ? null : Keys.ed25519(ed(op.get(3)));
                            List<Object> cav = op.get(4) == null ? null : jsIterable(op.get(4));
                            Session.Added r = Session.addMember(need(sess, op.get(2)), child, cav);
                            sess.put((String) op.get(1), r.session);
                            v = r.member.holder.ed.id();
                            break;
                        }
                        case "agents": v = new ArrayList<Object>(Session.sessionAgents(need(sess, op.get(1)))); break;
                        case "depth": v = Session.sessionDepth(need(sess, op.get(1))); break;
                        case "shares": v = Session.sharesGoal(need(sess, op.get(1))); break;
                        case "goal": v = need(sess, op.get(1)).goalCommit; break;
                        case "console": v = Session.sessionConsole(need(sess, op.get(1)), (List<?>) op.get(2)); break;
                        default: throw new IllegalStateException("op");
                    }
                    out.add(v);
                } catch (Throwable t) {
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("$err", "Error");
                    out.add(e);
                }
            }
            return out;
        });
    }

    /** What the reference's spread of a caveats argument yields: a list as is, a string as its code points. */
    @SuppressWarnings("unchecked")
    static List<Object> jsIterable(Object o) {
        if (o instanceof List) return (List<Object>) o;
        List<Object> out = new ArrayList<>();
        if (o instanceof String) ((String) o).codePoints().forEach(cp -> out.add(new String(Character.toChars(cp))));
        else throw new IllegalArgumentException("not iterable");
        return out;
    }

    static <T> T need(Map<String, T> m, Object k) {
        T v = m.get((String) k);
        if (v == null) throw new IllegalStateException("unknown " + k);
        return v;
    }

    static Facade.CompiledPolicy compile(Object specO) {
        Map<String, Object> s = m(specO);
        return Facade.compilePolicy(m(s.get("permissions")), m(s.get("limits")), null, (String) s.get("budgetModel"), m(s.get("riskPolicy")), (long) d(s.get("now")));
    }

    @Test void policySim() throws Exception {
        OracleCases.each(MODULE, "simulate", a -> {
            List<Map<String, Object>> acts = new ArrayList<>();
            for (Object x : l(a.get(1))) acts.add(m(x));
            return PolicySim.simulate(compile(a.get(0)), acts, null, a.get(2) == null ? 0 : d(a.get(2)));
        });
        OracleCases.each(MODULE, "lintPolicy", a -> PolicySim.lintPolicy(compile(a.get(0)), null));
    }

    @Test void reputationEvidence() throws Exception {
        OracleCases.each(MODULE, "disputesFromSettlements", a -> {
            String guardian = "@g".equals(a.get(1)) ? Keys.ed25519(ed("guardian")).ed.id() : (String) a.get(1);
            Map<String, Object> subjects = m(a.get(2));
            Map<String, Object> pin = a.get(3) == null ? null : m(a.get(3));
            return ReputationEvidence.disputesFromSettlements(l(a.get(0)), guardian, id -> subjects.get(id) instanceof String ? (String) subjects.get(id) : null, pin);
        });
    }

    @Test void sessionAndFreezeBasics() {
        assertTrue(Console.isFrozen(null, "a"), "a malformed set fails closed");
        Map<String, Object> s = Console.freezeAgent(Console.emptyFreeze(), "b");
        s = Console.freezeAgent(s, "a");
        assertEquals(List.of("a", "b"), s.get("frozen"));
        assertTrue(Console.isFrozen(s, "a"));
        assertEquals(List.of("b"), Console.unfreezeAgent(s, "a").get("frozen"));
    }
}
