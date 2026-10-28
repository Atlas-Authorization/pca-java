package net.atlasauth.pca;

/** A refusal raised by the attestation readers and verifiers; the message is the reason text (reference wording). */
public final class AttestException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AttestException(String message) { super(message); }
}
