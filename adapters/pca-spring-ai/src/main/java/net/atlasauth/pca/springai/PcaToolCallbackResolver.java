package net.atlasauth.pca.springai;

import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;

/** Wraps every callback a {@link ToolCallbackResolver} resolves in a {@link PcaToolCallback}, so tools found by name are guarded too. */
public final class PcaToolCallbackResolver implements ToolCallbackResolver {
    private final ToolCallbackResolver delegate;
    private final Prover prover;
    private final ToolGuard.ToolMapping mapping;
    private final PcaToolCallback.ProofSink onProof;

    public PcaToolCallbackResolver(ToolCallbackResolver delegate, Prover prover, ToolGuard.ToolMapping mapping, PcaToolCallback.ProofSink onProof) {
        if (delegate == null) throw new IllegalArgumentException("PcaToolCallbackResolver: delegate is required");
        this.delegate = delegate;
        this.prover = prover;
        this.mapping = mapping;
        this.onProof = onProof;
    }

    @Override public ToolCallback resolve(String toolName) {
        ToolCallback cb = delegate.resolve(toolName);
        return cb == null ? null : new PcaToolCallback(cb, prover, mapping, onProof);
    }
}
