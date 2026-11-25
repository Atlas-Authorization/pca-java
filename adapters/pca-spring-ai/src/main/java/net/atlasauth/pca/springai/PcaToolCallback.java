package net.atlasauth.pca.springai;

import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.execution.ToolExecutionException;
import org.springframework.ai.tool.metadata.ToolMetadata;

/**
 * Decorates a Spring AI {@link ToolCallback}: every call is mapped to a PCA action and a proof is built first; the real tool runs only
 * under that proof. A refusal (unmapped tool, denied proof, malformed arguments) throws {@link ToolExecutionException} wrapping
 * {@link PcaDenied}, and the delegate never runs. The proof reaches the tool through {@code onProof} (forward it as the
 * {@code PCA-Action} header to the resource server); the resource server's verifier still decides.
 */
public final class PcaToolCallback implements ToolCallback {
    /** Receives the proof for the call about to run. */
    @FunctionalInterface
    public interface ProofSink { void accept(net.atlasauth.pca.ai.Proof proof, String toolName, String toolInput); }

    private final ToolCallback delegate;
    private final Prover prover;
    private final ToolGuard.ToolMapping mapping;
    private final ProofSink onProof;

    public PcaToolCallback(ToolCallback delegate, Prover prover, ToolGuard.ToolMapping mapping, ProofSink onProof) {
        if (delegate == null || prover == null || mapping == null) throw new IllegalArgumentException("PcaToolCallback: delegate, prover and mapping are required");
        this.delegate = delegate;
        this.prover = prover;
        this.mapping = mapping;
        this.onProof = onProof;
    }

    @Override public ToolDefinition getToolDefinition() { return delegate.getToolDefinition(); }

    @Override public ToolMetadata getToolMetadata() { return delegate.getToolMetadata(); }

    @Override public String call(String toolInput) { return guarded(toolInput, () -> delegate.call(toolInput)); }

    @Override public String call(String toolInput, ToolContext toolContext) { return guarded(toolInput, () -> delegate.call(toolInput, toolContext)); }

    private String guarded(String toolInput, java.util.function.Supplier<String> run) {
        String name = delegate.getToolDefinition().name();
        try {
            return ToolGuard.runJson(prover, mapping, name, toolInput, (args, proof) -> {
                if (onProof != null) onProof.accept(proof, name, toolInput);
                return run.get();
            });
        } catch (PcaDenied d) {
            throw new ToolExecutionException(delegate.getToolDefinition(), d);
        }
    }
}
