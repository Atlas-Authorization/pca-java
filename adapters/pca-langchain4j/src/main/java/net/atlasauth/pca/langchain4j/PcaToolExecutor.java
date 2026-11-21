package net.atlasauth.pca.langchain4j;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.service.tool.ToolExecutor;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Proof;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;

/**
 * Wraps a LangChain4j {@link ToolExecutor} (which is what a {@code @Tool} method becomes): every execution is mapped to a PCA action, a proof
 * is built, and the real tool runs only under it. A refusal throws {@link PcaDenied} (or, with {@code deniedAsText}, returns the refusal as the
 * tool result so the model sees it); the delegate never runs. The resource server's verifier still decides.
 */
public final class PcaToolExecutor implements ToolExecutor {
    /** Receives the proof for the call about to run. */
    @FunctionalInterface
    public interface ProofSink { void accept(Proof proof, ToolExecutionRequest request); }

    private final ToolExecutor delegate;
    private final Prover prover;
    private final ToolGuard.ToolMapping mapping;
    private final ProofSink onProof;
    private final boolean deniedAsText;

    public PcaToolExecutor(ToolExecutor delegate, Prover prover, ToolGuard.ToolMapping mapping, ProofSink onProof, boolean deniedAsText) {
        if (delegate == null || prover == null || mapping == null) throw new IllegalArgumentException("PcaToolExecutor: delegate, prover and mapping are required");
        this.delegate = delegate;
        this.prover = prover;
        this.mapping = mapping;
        this.onProof = onProof;
        this.deniedAsText = deniedAsText;
    }

    @Override public String execute(ToolExecutionRequest request, Object memoryId) {
        try {
            return ToolGuard.runJson(prover, mapping, request.name(), request.arguments(), (args, proof) -> {
                if (onProof != null) onProof.accept(proof, request);
                return delegate.execute(request, memoryId);
            });
        } catch (PcaDenied d) {
            if (deniedAsText) return "denied: " + d.getMessage();
            throw d;
        }
    }

    /** Guard every executor of a tool map (the shape {@code AiServices.builder(...).tools(Map)} takes). */
    public static Map<ToolSpecification, ToolExecutor> wrapAll(Map<ToolSpecification, ToolExecutor> tools, Prover prover, ToolGuard.ToolMapping mapping,
                                                              ProofSink onProof, boolean deniedAsText) {
        Map<ToolSpecification, ToolExecutor> out = new LinkedHashMap<>();
        for (Map.Entry<ToolSpecification, ToolExecutor> e : tools.entrySet()) out.put(e.getKey(), new PcaToolExecutor(e.getValue(), prover, mapping, onProof, deniedAsText));
        return out;
    }
}
