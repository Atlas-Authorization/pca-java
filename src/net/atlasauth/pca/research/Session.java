package net.atlasauth.pca.research;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Keys;

/**
 * A multi-agent session, the delegation-tree "team" view: a root agent plus the sub-agents it delegates to all share ONE signed goal; the
 * session groups them so a principal sees the whole team under a goal and the console can be scoped to it. Pure.
 */
public final class Session {
    /** Deepest delegation chain a session accepts. */
    public static final int SESSION_MAX_DEPTH = 32;

    public final Facade.Handle root;
    /** Root first, then each added sub-agent, in delegation order. */
    public final List<Facade.Handle> members;
    /** The shared signed goal commitment (from the root grant), "" when the grant carries none. */
    public final String goalCommit;

    public Session(Facade.Handle root, List<Facade.Handle> members, String goalCommit) {
        this.root = root;
        this.members = new ArrayList<>(members);
        this.goalCommit = goalCommit;
    }

    /** What {@link #addMember} returns: the grown session and the new member. */
    public static final class Added {
        public final Session session;
        public final Facade.Handle member;
        Added(Session session, Facade.Handle member) { this.session = session; this.member = member; }
    }

    private static String goalOf(Facade.Handle h) {
        Map<String, Object> env = Authorize.readEnvelope(h.grant);
        return env != null && env.get("goal_commit") instanceof String ? (String) env.get("goal_commit") : "";
    }

    /** Start a session from a root agent. */
    public static Session startSession(Facade.Handle root) {
        List<Facade.Handle> m = new ArrayList<>();
        m.add(root);
        return new Session(root, m, goalOf(root));
    }

    /**
     * Add a sub-agent: one attenuated delegation hop under the session's current leaf. {@code child} (the sub-agent's key) and
     * {@code addedCaveats} may be null. Throws past {@link #SESSION_MAX_DEPTH} hops.
     */
    public static Added addMember(Session session, Keys.SuiteKey child, List<Object> addedCaveats) {
        if (session.members.size() > SESSION_MAX_DEPTH) throw new IllegalArgumentException("addMember: a session is limited to " + SESSION_MAX_DEPTH + " delegation hops");
        Facade.Handle parent = session.members.get(session.members.size() - 1);
        Facade.Handle member = parent.subAgent(child, addedCaveats);
        List<Facade.Handle> next = new ArrayList<>(session.members);
        next.add(member);
        return new Added(new Session(session.root, next, session.goalCommit), member);
    }

    /** The holder ids (b64u public keys) of every agent in the session. */
    public static List<String> sessionAgents(Session session) {
        List<String> out = new ArrayList<>();
        for (Facade.Handle m : session.members) out.add(m.holder.ed.id());
        return out;
    }

    /** A console view scoped to just this session's agents. */
    public static Map<String, Object> sessionConsole(Session session, List<?> events) {
        Set<String> ids = new HashSet<>(sessionAgents(session));
        List<Object> mine = new ArrayList<>();
        for (Object e : events) {
            if (e == null) throw new IllegalArgumentException("sessionConsole: an event must not be null");
            Map<String, Object> m = Js.map(e);
            if (m != null && m.get("agent") instanceof String && ids.contains(m.get("agent"))) mine.add(e);
        }
        return Console.buildConsole(mine);
    }

    /**
     * True iff every member shares the root's goal commitment (a well-formed team). A root without a readable envelope has no goal commitment
     * (""), and members that all lack one do not "share a goal": false.
     */
    public static boolean sharesGoal(Session session) {
        if (session.goalCommit.isEmpty()) return false;
        for (Facade.Handle m : session.members) if (!goalOf(m).equals(session.goalCommit)) return false;
        return true;
    }

    /** Depth of the delegation tree (0 = root only). */
    public static int sessionDepth(Session session) { return session.members.size() - 1; }
}
