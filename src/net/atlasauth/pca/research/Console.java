package net.atlasauth.pca.research;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Pca;

/**
 * The principal's live agent console, data layer: projects a stream of activity events into a per-agent view with a threat read (see
 * {@link Immune}) and models the kill switch. Pure and offline: a projection over records you feed it. The "freeze" is a local kill-switch
 * set a client or gateway consults before dispatching; authoritative revocation is the transparency ledger's revocation epoch.
 *
 * <p>An event is {@code {at, agent, verb, resource, outcome: auto|step_up|deny|executed, r?, taint?, digest?, goalCommit?}}.
 */
public final class Console {
    private Console() {}

    /** An activity event from a proof-carrying action and the verifier's outcome; {@code at} may be null (then the action's {@code iat}). */
    public static Map<String, Object> eventFromPCActn(Map<String, Object> p, String outcome, Double at) {
        if (!(p.get("cap_chain") instanceof List)) throw new IllegalArgumentException("eventFromPCActn: cap_chain must be a list");
        List<?> chain = (List<?>) p.get("cap_chain");
        Map<String, Object> leaf = chain.isEmpty() ? null : Js.map(chain.get(chain.size() - 1));
        Map<String, Object> action = Js.map(p.get("action"));
        if (action == null) throw new IllegalArgumentException("eventFromPCActn: action must be an object");
        Map<String, Object> e = Js.obj();
        if (at != null) e.put("at", Js.n(at)); else if (p.containsKey("iat")) e.put("at", p.get("iat"));
        e.put("agent", leaf != null && leaf.get("holder") != null ? leaf.get("holder") : "unknown");
        if (action.containsKey("verb")) e.put("verb", action.get("verb"));
        if (action.containsKey("resource")) e.put("resource", action.get("resource"));
        e.put("outcome", outcome);
        Map<String, Object> rc = Js.map(p.get("risk_claim"));
        if (rc != null && rc.containsKey("r")) e.put("r", rc.get("r"));
        Map<String, Object> pv = Js.map(p.get("provenance"));
        if (pv != null && pv.containsKey("taint_level")) e.put("taint", pv.get("taint_level"));
        e.put("digest", Pca.hashCanonical(p));
        return e;
    }

    private static boolean usable(Object o) {
        Map<String, Object> e = Js.map(o);
        return e != null && Js.isFinite(e.get("at")) && e.get("agent") instanceof String && !((String) e.get("agent")).isEmpty();
    }

    private static Map<String, Object> total(long actions, long autos, long stepUps, long denies, long executed) {
        Map<String, Object> t = Js.obj();
        t.put("actions", Js.n(actions));
        t.put("autos", Js.n(autos));
        t.put("stepUps", Js.n(stepUps));
        t.put("denies", Js.n(denies));
        t.put("executed", Js.n(executed));
        return t;
    }

    /**
     * Project events into the console view {@code {agents, totals, window: {from, to}, dropped}}, agents most threatened first (then most
     * recently seen). An event with no finite time or no agent id cannot be placed in a timeline or attributed: it is counted in
     * {@code dropped}, not guessed. A risk that is present but not a number is refused (throws) rather than summed as text.
     */
    public static Map<String, Object> buildConsole(List<?> all) {
        List<Map<String, Object>> events = new ArrayList<>();
        for (Object o : all) if (usable(o)) events.add(Js.map(o));
        long dropped = all.size() - events.size();
        Map<String, List<Map<String, Object>>> byAgent = new LinkedHashMap<>();
        for (Map<String, Object> e : events) byAgent.computeIfAbsent((String) e.get("agent"), k -> new ArrayList<>()).add(e);

        List<Map<String, Object>> agents = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> en : byAgent.entrySet()) {
            List<Map<String, Object>> sorted = new ArrayList<>(en.getValue());
            sorted.sort((a, b) -> { double d = Js.d(a.get("at")) - Js.d(b.get("at")); return d == 0 || Double.isNaN(d) ? 0 : d < 0 ? -1 : 1; });
            Map<String, Object> immune = Immune.initialState();
            long autos = 0, stepUps = 0, denies = 0, executed = 0;
            double totalRisk = 0;
            for (Map<String, Object> e : sorted) {
                Object ro = e.get("r");
                if (ro != null && !Js.isNum(ro)) throw new IllegalArgumentException("buildConsole: r must be a number");
                double r = ro == null ? 0 : Js.d(ro);
                totalRisk += r;
                Object outcome = e.get("outcome");
                if ("auto".equals(outcome)) autos++;
                else if ("step_up".equals(outcome)) stepUps++;
                else if ("deny".equals(outcome)) denies++;
                else if ("executed".equals(outcome)) executed++;
                Map<String, Object> obs = Js.obj();
                obs.put("r", Js.n(r));
                obs.put("at", e.get("at"));
                obs.put("stepUp", "step_up".equals(outcome));
                obs.put("denied", "deny".equals(outcome));
                immune = Immune.observe(immune, obs);
            }
            Map<String, Object> a = Js.obj();
            a.put("agent", en.getKey());
            a.put("actions", Js.n((long) sorted.size()));
            a.put("autos", Js.n(autos));
            a.put("stepUps", Js.n(stepUps));
            a.put("denies", Js.n(denies));
            a.put("executed", Js.n(executed));
            a.put("totalRisk", Js.n(totalRisk));
            a.put("firstSeen", sorted.get(0).get("at"));
            a.put("lastSeen", sorted.get(sorted.size() - 1).get("at"));
            a.put("threat", Immune.assess(immune));
            agents.add(a);
        }
        agents.sort((x, y) -> {
            double d = Js.d(Js.map(y.get("threat")).get("score")) - Js.d(Js.map(x.get("threat")).get("score"));
            if (d != 0 && !Double.isNaN(d)) return d < 0 ? -1 : 1;
            double l = Js.d(y.get("lastSeen")) - Js.d(x.get("lastSeen"));
            return l == 0 || Double.isNaN(l) ? 0 : l < 0 ? -1 : 1;
        });

        long ta = 0, tau = 0, ts = 0, td = 0, te = 0;
        for (Map<String, Object> a : agents) {
            ta += (long) Js.d(a.get("actions"));
            tau += (long) Js.d(a.get("autos"));
            ts += (long) Js.d(a.get("stepUps"));
            td += (long) Js.d(a.get("denies"));
            te += (long) Js.d(a.get("executed"));
        }
        double from = 0, to = 0;
        if (!events.isEmpty()) {
            from = Double.POSITIVE_INFINITY;
            to = Double.NEGATIVE_INFINITY;
            for (Map<String, Object> e : events) { from = Math.min(from, Js.d(e.get("at"))); to = Math.max(to, Js.d(e.get("at"))); }
        }
        Map<String, Object> window = Js.obj();
        window.put("from", Js.n(from));
        window.put("to", Js.n(to));
        Map<String, Object> view = Js.obj();
        view.put("agents", new ArrayList<Object>(agents));
        view.put("totals", total(ta, tau, ts, td, te));
        view.put("window", window);
        view.put("dropped", Js.n(dropped));
        return view;
    }

    /** The agents whose current threat read is not calm (the console's "anomalies" panel). */
    public static List<Object> anomalies(Map<String, Object> view) {
        List<Object> out = new ArrayList<>();
        for (Object a : (List<?>) view.get("agents")) if (!"calm".equals(Js.map(Js.map(a).get("threat")).get("level"))) out.add(a);
        return out;
    }

    // ---- freeze (the kill switch) -----------------------------------------------------------------------------------------

    /** The empty freeze set {@code {frozen: []}}. */
    public static Map<String, Object> emptyFreeze() {
        Map<String, Object> s = Js.obj();
        s.put("frozen", new ArrayList<Object>());
        return s;
    }

    private static List<?> frozen(Map<String, Object> set) {
        if (set == null || !(set.get("frozen") instanceof List)) throw new IllegalArgumentException("freeze set must be {frozen: [...]}");
        return (List<?>) set.get("frozen");
    }

    /** Freeze an agent: the set with the id added (sorted); the same set when it is already frozen. */
    public static Map<String, Object> freezeAgent(Map<String, Object> set, Object agent) {
        if (!(agent instanceof String) || ((String) agent).isEmpty()) throw new IllegalArgumentException("freezeAgent: agent must be a non-empty string");
        if (set == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'frozen')");
        Object f = set.get("frozen");
        List<Object> next = new ArrayList<>();
        if (f instanceof String) { // the reference calls .includes on whatever is there: a string tests a substring and spreads into its characters
            if (((String) f).contains((String) agent)) return set;
            ((String) f).codePoints().forEach(cp -> next.add(new String(Character.toChars(cp))));
        } else if (f instanceof List) {
            if (((List<?>) f).contains(agent)) return set;
            next.addAll((List<?>) f);
        } else throw new IllegalArgumentException("freeze set must be {frozen: [...]}");
        next.add(agent);
        next.sort((a, b) -> Js.str(a).compareTo(Js.str(b))); // Array.prototype.sort compares the elements as strings, and keeps them as they are
        Map<String, Object> s = Js.obj();
        s.put("frozen", next);
        return s;
    }

    /** The set without the agent. */
    public static Map<String, Object> unfreezeAgent(Map<String, Object> set, Object agent) {
        List<Object> next = new ArrayList<>();
        for (Object o : frozen(set)) if (!(o == null ? agent == null : o.equals(agent))) next.add(o);
        Map<String, Object> s = Js.obj();
        s.put("frozen", next);
        return s;
    }

    /** Whether an agent is frozen. Fails closed: an agent with no usable id, or a malformed set, counts as frozen. */
    public static boolean isFrozen(Object set, Object agent) {
        if (!(agent instanceof String) || ((String) agent).isEmpty() || !(set instanceof Map) || !(((Map<?, ?>) set).get("frozen") instanceof List)) return true;
        return ((List<?>) ((Map<?, ?>) set).get("frozen")).contains(agent);
    }
}
