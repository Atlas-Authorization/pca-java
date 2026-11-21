package net.atlasauth.pca;

/**
 * {@link Decide#deriveDecideInput} was called without {@code ctx.grant} (the verifier's own stored grant). The grant is never
 * defaulted from the artifact. An {@link IllegalArgumentException}, so existing callers that catch it keep working.
 */
public final class DecideInputGrantRequired extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    /** The machine-readable code, {@code grant_required}. */
    public final String code = "grant_required";

    public DecideInputGrantRequired() {
        super("deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant");
    }
}
