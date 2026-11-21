package net.atlasauth.pca.openaiagents;

import java.util.Map;

/** A guarded tool (or guardrail) refused: the proof is missing, malformed, failed verification, is bound to another tool, or the policy / replay / revocation / configuration refused it. */
public final class PcaToolDenied extends RuntimeException {
    private static final long serialVersionUID = 1L;
    /** The PCA verb the proof claimed (or the configured verb / "(tool)" when unknown). */
    public final String verb;
    /** missing, malformed, verify, binding, policy, replay, revoked or config. */
    public final String kind;
    /** The per-check verdicts when the denial was a verification failure, else null. */
    public final transient Map<String, String> checks;

    public PcaToolDenied(String message, String verb, String kind, Map<String, String> checks) {
        super("PCA tool denied (" + kind + ") for " + verb + ": " + message);
        this.verb = verb;
        this.kind = kind;
        this.checks = checks;
    }

    public PcaToolDenied(String message, String verb, String kind) { this(message, verb, kind, null); }
}
