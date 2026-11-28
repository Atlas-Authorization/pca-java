package net.atlasauth.pca.ai;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.Agent;
import net.atlasauth.pca.Facade;

/**
 * Builds the proof for one tool call. Implementations refuse by throwing {@link PcaDenied}; any other exception is also treated as a
 * refusal by {@link ToolGuard} (the tool never runs). {@link #tool} / {@link #principal} feed the provenance recorder, when there is one.
 */
public interface Prover {
    Proof prove(String verb, String resource, Map<String, Object> params);

    /** Record what a tool returned: it re-enters the model's context, so it is untrusted from here on. */
    default void tool(String name, Object output) {}

    /** Record a document handed to the model: retrieved content is untrusted (it can carry an injected instruction). */
    default void retrieval(String source, Object content) {}

    /** Record a principal (user) message. */
    default void principal(String text) {}

    /** The facade handle as a prover: a failed local dry-run refuses (advisory pre-check, the server still decides), and tool results are recorded. */
    static Prover of(Facade.Handle h) {
        return new Prover() {
            @Override public Proof prove(String verb, String resource, Map<String, Object> params) {
                Facade.ActResult r;
                try {
                    r = h.act(verb, resource, params, null);
                } catch (RuntimeException e) {
                    throw new PcaDenied(String.valueOf(e.getMessage()), verb, resource, e);
                }
                if (!r.dryRun.allowed) throw new PcaDenied(r.dryRun.reason == null ? "denied" : r.dryRun.reason, verb, resource);
                return new Proof(r.pcactn, r.encoded, r.headers);
            }
            @Override public void tool(String name, Object output) { h.provenance.tool(name, output); }
            @Override public void retrieval(String source, Object content) { h.provenance.retrieval(source, content); }
            @Override public void principal(String text) { h.provenance.principal(text); }
        };
    }

    /** A plain agent as a prover (no local dry-run and no provenance: the agent builds the proof, the server decides). */
    static Prover of(Agent a) {
        return (verb, resource, params) -> {
            Map<String, Object> p;
            try {
                p = a.act(verb, resource, params);
            } catch (RuntimeException e) {
                throw new PcaDenied(String.valueOf(e.getMessage()), verb, resource, e);
            }
            String enc = Agent.header(p);
            Map<String, String> h = new LinkedHashMap<>();
            h.put(Agent.HEADER, enc);
            return new Proof(p, enc, h);
        };
    }
}
