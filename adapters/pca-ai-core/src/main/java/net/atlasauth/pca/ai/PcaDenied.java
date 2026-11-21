package net.atlasauth.pca.ai;

/** A tool call was refused before it ran: no proof could be built, the local pre-check denied it, or the tool is not mapped. Fail closed. */
public final class PcaDenied extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public final String verb;
    public final String resource;

    public PcaDenied(String reason, String verb, String resource) {
        super(reason);
        this.verb = verb;
        this.resource = resource;
    }

    public PcaDenied(String reason, String verb, String resource, Throwable cause) {
        super(reason, cause);
        this.verb = verb;
        this.resource = resource;
    }
}
