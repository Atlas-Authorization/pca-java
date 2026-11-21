package net.atlasauth.pca.ap2;

/** Every failure raised while parsing or verifying an AP2 mandate carries a human-readable reason (the message). */
public class Ap2Error extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public Ap2Error(String message) { super(message); }
}
