package net.atlasauth.pca.agent;

/** Why an agent call failed. {@code code} is one of {@code no_plan}, {@code unknown_node}, {@code no_secret}, {@code network}, {@code bad_response}, {@code build_failed}. */
public final class PcaAgentError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;
    private final Integer httpStatus;

    public PcaAgentError(String code, String message) { this(code, message, null); }

    public PcaAgentError(String code, String message, Integer httpStatus) {
        super(message);
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public String code() { return code; }

    /** The HTTP status that went with the failure, or null. */
    public Integer httpStatus() { return httpStatus; }
}
