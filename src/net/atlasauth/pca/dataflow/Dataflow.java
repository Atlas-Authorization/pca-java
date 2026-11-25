package net.atlasauth.pca.dataflow;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.AttestCommon;

/**
 * The capability-tagged, positive data-flow model (CaMeL style): every value carries the provenance it was derived from and the
 * sinks it may reach; an interpreter decides each flow from the tags alone. Pure and deterministic. Non-exfiltration is
 * provable GIVEN CORRECT TAGGING AT THE BOUNDARIES: tag the genuine user query with {@link #fromTrustedQuery} and everything a
 * tool or document returns with {@link #fromToolOutput}; mis-tagged input voids the proof.
 */
public final class Dataflow {
    private Dataflow() {}

    /** The genuine, trusted user query: the one source control flow may derive from. */
    public static final String TRUSTED_QUERY = "trusted-query";

    /** Marker for a hole in a tagged-argument list (an argument nobody tagged); a null element is an explicit "undefined". */
    public static final Object HOLE = new Object() { @Override public String toString() { return "<hole>"; } };

    /** Provenance tag for the output of a named tool. Always untrusted. */
    public static String toolProvenance(String name) { return "tool:" + name; }

    // ---- capability + tagged value -----------------------------------------------------------------------------------------

    /** The data-flow label of a value: its lineage, whether every source is trusted, and an optional sink allow-list. */
    public static final class Capability {
        private final Set<String> sources;
        private final boolean trusted;
        private final Set<String> readers;

        /** {@code readers} null = unrestricted by the value (the sink's own policy still applies). */
        public Capability(Collection<String> sources, boolean isTrusted, Collection<String> readers) {
            if (sources == null) throw new IllegalArgumentException("a capability needs a set of sources");
            this.sources = Collections.unmodifiableSet(new LinkedHashSet<>(sources));
            this.trusted = isTrusted;
            this.readers = readers == null ? null : Collections.unmodifiableSet(new LinkedHashSet<>(readers));
        }

        /** The provenance tags, in insertion order. Immutable. */
        public Set<String> sources() { return sources; }
        public boolean isTrusted() { return trusted; }
        /** The sink allow-list in insertion order, or null. Immutable. */
        public Set<String> readers() { return readers; }
    }

    /** A value carrying its data-flow capability. Only this class's factories make one, so a look-alike is never a tagged value. */
    public static final class Tagged<T> {
        private final T value;
        private final Capability cap;
        private Tagged(T value, Capability cap) { this.value = value; this.cap = cap; }
        public T value() { return value; }
        public Capability cap() { return cap; }
    }

    /** True only for a value created by {@link #tag}, the {@code from*} constructors or {@link #derive}. */
    public static boolean isTagged(Object x) { return x instanceof Tagged; }

    /** Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors). Throws on a contradictory capability. */
    public static <T> Tagged<T> tag(T value, Capability cap) {
        if (cap == null) throw new IllegalArgumentException("tag: a capability needs a set of sources and a boolean isTrusted");
        if (cap.isTrusted()) {
            if (cap.sources().isEmpty()) throw new IllegalArgumentException("tag: a trusted capability needs at least one source");
            for (String src : cap.sources()) {
                if (src != null && src.startsWith("tool:")) throw new IllegalArgumentException("tag: tool output can never be trusted");
            }
        }
        return new Tagged<>(value, new Capability(cap.sources(), cap.isTrusted(), cap.readers()));
    }

    /** Tag a value as the genuine, trusted user query (a BOUNDARY assertion). */
    public static <T> Tagged<T> fromTrustedQuery(T value, Collection<String> readers) {
        return tag(value, new Capability(Collections.singleton(TRUSTED_QUERY), true, readers));
    }

    /** Tag the output of a named tool. ALWAYS untrusted. */
    public static <T> Tagged<T> fromToolOutput(String name, T value, Collection<String> readers) {
        return tag(value, new Capability(Collections.singleton(toolProvenance(name)), false, readers));
    }

    /** Tag a value from an arbitrary source; untrusted unless the caller explicitly vouches for it. */
    public static <T> Tagged<T> fromSource(String source, T value, boolean isTrusted, Collection<String> readers) {
        return tag(value, new Capability(Collections.singleton(source), isTrusted, readers));
    }

    // ---- capability algebra ------------------------------------------------------------------------------------------------

    /** Union of the provenance sources of several capabilities (insertion order). */
    public static Set<String> unionSources(List<Capability> caps) {
        Set<String> out = new LinkedHashSet<>();
        for (Capability c : caps) out.addAll(c.sources());
        return Collections.unmodifiableSet(out);
    }

    /**
     * Combine capabilities: sources = union, isTrusted = AND over the inputs (none = untrusted, fail closed), readers = the
     * intersection of the inputs that restrict readers.
     */
    public static Capability combineCaps(List<Capability> caps) {
        Set<String> sources = unionSources(caps);
        boolean trusted = !caps.isEmpty();
        for (Capability c : caps) if (!c.isTrusted()) { trusted = false; break; }
        Set<String> readers = null;
        for (Capability c : caps) {
            if (c.readers() == null) continue;
            if (readers == null) readers = new LinkedHashSet<>(c.readers());
            else {
                Set<String> next = new LinkedHashSet<>();
                for (String id : readers) if (c.readers().contains(id)) next.add(id);
                readers = next;
            }
        }
        return new Capability(sources, trusted, readers);
    }

    /**
     * Derive a new tagged value from existing ones: the capability is {@link #combineCaps} over the inputs, so provenance
     * propagates and trust can only be lost. Every input must be a tagged value made by this class.
     */
    public static <T> Tagged<T> derive(List<?> inputs, Function<List<Object>, T> combine) {
        if (inputs == null) throw new IllegalArgumentException("derive: every input must be a tagged value made by this module");
        for (Object t : inputs) if (!isTagged(t)) throw new IllegalArgumentException("derive: every input must be a tagged value made by this module");
        List<Object> values = new ArrayList<>();
        List<Capability> caps = new ArrayList<>();
        for (Object t : inputs) { values.add(((Tagged<?>) t).value()); caps.add(((Tagged<?>) t).cap()); }
        T value = combine.apply(values);
        return new Tagged<>(value, combineCaps(caps));
    }

    // ---- sinks + the policy interpreter ------------------------------------------------------------------------------------

    public static final String ALLOW = "allow";
    public static final String STEP_UP = "step_up";
    public static final String DENY = "deny";

    /** What a sink accepts; every member optional (null = not set). */
    public static final class FlowPolicy {
        public final Boolean external;
        public final Boolean requireTrusted;
        public final Set<String> allowedSources;
        public final Set<String> deniedSources;

        public FlowPolicy(Boolean external, Boolean requireTrusted, Collection<String> allowedSources, Collection<String> deniedSources) {
            this.external = external;
            this.requireTrusted = requireTrusted;
            this.allowedSources = allowedSources == null ? null : new LinkedHashSet<>(allowedSources);
            this.deniedSources = deniedSources == null ? null : new LinkedHashSet<>(deniedSources);
        }
    }

    /** A place a value leaves the trusted interior. An invalid sink (null id / empty id / null policy) is refused, never allowed. */
    public static final class Sink {
        public final String id;
        public final FlowPolicy accepts;

        public Sink(String id, FlowPolicy accepts) { this.id = id; this.accepts = accepts; }
    }

    /** The decision for one value-to-sink flow. {@code reason} / {@code path} are null when absent. */
    public static final class FlowDecision {
        public final String outcome;
        public final String reason;
        public final List<String> path;

        FlowDecision(String outcome, String reason, List<String> path) { this.outcome = outcome; this.reason = reason; this.path = path; }
    }

    private static List<String> sortedSources(Capability cap) {
        List<String> l = new ArrayList<>(cap.sources());
        Collections.sort(l);
        return l;
    }

    private static String joinSorted(Collection<String> c) {
        List<String> l = new ArrayList<>(c);
        Collections.sort(l);
        return String.join(", ", l);
    }

    /**
     * Classify one value-to-sink flow from the value's tags and the sink's declared policy, in order: the value's reader
     * allow-list, the sink's denied sources, its allow-list, the external-sink exfiltration rule, the trust requirement.
     * A value that is not a tagged value of this class, or an invalid sink, is a denial.
     */
    public static FlowDecision classifyFlow(Object value, Sink sink) {
        if (!isTagged(value)) return new FlowDecision(DENY, "value carries no provenance tag made by this module (fail closed)", new ArrayList<>());
        Capability cap = ((Tagged<?>) value).cap();
        if (sink == null || sink.id == null || sink.id.isEmpty() || sink.accepts == null) {
            return new FlowDecision(DENY, "the sink is not a valid sink (fail closed)", sortedSources(cap));
        }
        FlowPolicy p = sink.accepts;

        if (cap.readers() != null && !cap.readers().contains(sink.id)) {
            String list = joinSorted(cap.readers());
            return new FlowDecision(DENY, "value's readers capability [" + (list.isEmpty() ? "∅" : list) + "] does not include sink '" + sink.id + "'", sortedSources(cap));
        }
        if (p.deniedSources != null) {
            List<String> bad = new ArrayList<>();
            for (String s : sortedSources(cap)) if (p.deniedSources.contains(s)) bad.add(s);
            if (!bad.isEmpty()) return new FlowDecision(DENY, "provenance [" + String.join(", ", bad) + "] is forbidden at sink '" + sink.id + "'", bad);
        }
        if (p.allowedSources != null) {
            List<String> bad = new ArrayList<>();
            for (String s : sortedSources(cap)) if (!p.allowedSources.contains(s)) bad.add(s);
            if (!bad.isEmpty()) return new FlowDecision(DENY, "provenance [" + String.join(", ", bad) + "] is not in the allow-list of sink '" + sink.id + "'", bad);
        }
        if (Boolean.TRUE.equals(p.external) && !cap.isTrusted()) {
            return new FlowDecision(DENY, "untrusted value (provenance [" + String.join(", ", sortedSources(cap)) + "]) may not flow to external-send sink '"
                + sink.id + "' — exfiltration / prompt-injection path", sortedSources(cap));
        }
        if (Boolean.TRUE.equals(p.requireTrusted) && !cap.isTrusted()) {
            return new FlowDecision(STEP_UP, "sink '" + sink.id + "' requires trusted provenance; value provenance [" + String.join(", ", sortedSources(cap))
                + "] is untrusted — needs human review", sortedSources(cap));
        }
        return new FlowDecision(ALLOW, null, null);
    }

    /** The boolean view of {@link #classifyFlow}: ok only for a clean {@code allow} (a step-up is not ok without a human). */
    public static final class CanFlow {
        public final boolean ok;
        public final String reason;

        CanFlow(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
    }

    public static CanFlow canFlow(Object value, Sink sink) {
        FlowDecision d = classifyFlow(value, sink);
        return new CanFlow(ALLOW.equals(d.outcome), d.reason);
    }

    // ---- action gate --------------------------------------------------------------------------------------------------------

    /** The verb and resource of a PCActn's {@code action}. */
    public static final class PcaStyleAction {
        public final String verb;
        public final String resource;

        public PcaStyleAction(String verb, String resource) { this.verb = verb; this.resource = resource; }
    }

    /** Resolves which sink an action dispatches to. May throw: the action is then refused. */
    public interface FlowGovernor { Sink sinkFor(PcaStyleAction action) throws Exception; }

    /** The decision for one action; {@code reason}, {@code arg} (an argument index) and {@code path} are null when absent. */
    public static final class ActionDecision {
        public final String outcome;
        public final String sink;
        public final String reason;
        public final Integer arg;
        public final List<String> path;

        ActionDecision(String outcome, String sink, String reason, Integer arg, List<String> path) {
            this.outcome = outcome; this.sink = sink; this.reason = reason; this.arg = arg; this.path = path;
        }
    }

    private static int severity(String outcome) { return ALLOW.equals(outcome) ? 0 : STEP_UP.equals(outcome) ? 1 : 2; }

    /**
     * Gate a PCA action by data flow: every tagged argument is checked against the sink the action dispatches to and the worst
     * outcome wins (deny over step_up over allow). {@code taggedArgs}: a null element is an explicit undefined (skipped), {@link
     * #HOLE} an argument nobody tagged (a denial). {@code expectedArgs} (null = unknown) makes a count mismatch a refusal.
     */
    public static ActionDecision checkAction(PcaStyleAction action, List<?> taggedArgs, FlowGovernor policy, Double expectedArgs) {
        Sink sink;
        try {
            sink = policy.sinkFor(action);
        } catch (Exception e) {
            return new ActionDecision(DENY, "(unresolved)", "the sink for this action could not be resolved (fail closed)", null, null);
        }
        if (sink == null || sink.id == null || sink.id.isEmpty()) {
            return new ActionDecision(DENY, "(unresolved)", "the sink for this action is not a valid sink (fail closed)", null, null);
        }
        if (taggedArgs == null) return new ActionDecision(DENY, sink.id, "the tagged arguments are not a list (fail closed)", null, null);
        if (expectedArgs != null && taggedArgs.size() != expectedArgs) {
            return new ActionDecision(DENY, sink.id, "expected " + AttestCommon.jsNumString(expectedArgs) + " tagged argument(s), got " + taggedArgs.size() + " (fail closed)", null, null);
        }
        ActionDecision worst = new ActionDecision(ALLOW, sink.id, null, null, null);
        for (int i = 0; i < taggedArgs.size(); i++) {
            Object arg = taggedArgs.get(i);
            if (arg == null) continue;
            if (arg == HOLE) return new ActionDecision(DENY, sink.id, "an argument was not tagged (fail closed)", i, null);
            FlowDecision d = classifyFlow(arg, sink);
            if (severity(d.outcome) > severity(worst.outcome)) worst = new ActionDecision(d.outcome, sink.id, d.reason, i, d.path);
        }
        return worst;
    }

    // ---- dual-context --------------------------------------------------------------------------------------------------------

    /** The result of {@link #dualContext}: the plan and the capability-tagged quarantined result. */
    public static final class DualResult<P, R> {
        public final P plan;
        public final Tagged<R> result;

        DualResult(P plan, Tagged<R> result) { this.plan = plan; this.result = result; }
    }

    /**
     * Run the dual-LLM separation: a PRIVILEGED planner that sees only the trusted query value, and a QUARANTINED handler that
     * processes untrusted content and returns only a capability-tagged result. Throws when the query is not a trusted tagged
     * value, or the handler returns something that is not tagged.
     */
    @SuppressWarnings("unchecked")
    public static <Q, P, R> DualResult<P, R> dualContext(Object query, Function<Q, P> plan, Function<P, Object> quarantine) {
        if (!isTagged(query)) throw new IllegalArgumentException("dualContext: the query must be a tagged value made by this module");
        Tagged<Q> q = (Tagged<Q>) query;
        if (!q.cap().isTrusted()) {
            throw new IllegalStateException("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [" + String.join(", ", sortedSources(q.cap())) + "]");
        }
        P p = plan.apply(q.value());
        Object result = quarantine.apply(p);
        if (!isTagged(result)) throw new IllegalArgumentException("dualContext: the quarantined handler must return a tagged value made by this module");
        return new DualResult<>(p, (Tagged<R>) result);
    }

    // ---- presets + the verifier's lattice ----------------------------------------------------------------------------------

    /** An external-send sink: exfiltrating, so untrusted values hard-deny. */
    public static Sink externalSendSink(String id) { return new Sink(id, new FlowPolicy(Boolean.TRUE, null, null, null)); }

    /** A sensitive internal sink: untrusted values step up for human review. */
    public static Sink sensitiveSink(String id) { return new Sink(id, new FlowPolicy(null, Boolean.TRUE, null, null)); }

    /** A tagged value's label in the verifier's provenance lattice: {@code trusted}, {@code tool} (every source a tool) or {@code agent}. */
    public static String levelOf(Object value) {
        if (!isTagged(value)) return "agent";
        Capability cap = ((Tagged<?>) value).cap();
        if (cap.isTrusted()) return "trusted";
        if (cap.sources().isEmpty()) return "agent";
        for (String s : cap.sources()) if (s == null || !s.startsWith("tool:")) return "agent";
        return "tool";
    }
}
