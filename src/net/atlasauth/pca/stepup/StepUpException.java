package net.atlasauth.pca.stepup;

/** Base of every step-up client error (unchecked). */
public class StepUpException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public StepUpException(String message) { super(message); }
    public StepUpException(String message, Throwable cause) { super(message, cause); }

    /** No principal key is stored on this device. */
    public static final class NoDeviceKey extends StepUpException {
        private static final long serialVersionUID = 1L;
        public NoDeviceKey() { super("No principal device key is stored."); }
    }

    /** The secret is not a base64url 32-byte Ed25519 seed. */
    public static final class InvalidSecret extends StepUpException {
        private static final long serialVersionUID = 1L;
        public InvalidSecret(String message) { super(message); }
    }

    /** The step-up's threshold message is not canonical base64url. */
    public static final class InvalidThresholdMessage extends StepUpException {
        private static final long serialVersionUID = 1L;
        public InvalidThresholdMessage() { super("The step-up's threshold message is not canonical base64url."); }
    }

    /** The server refused the signature (403): this key is not the grant's principal. */
    public static final class PrincipalMismatch extends StepUpException {
        private static final long serialVersionUID = 1L;
        public PrincipalMismatch(String message) { super(message); }
    }

    /** The server answered with an error status. */
    public static final class ApiError extends StepUpException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public ApiError(int status, String message) { super(message); this.status = status; }
    }

    /** The request failed on the network, or the answer was unreadable. */
    public static final class TransportError extends StepUpException {
        private static final long serialVersionUID = 1L;
        public TransportError(String message) { super(message); }
        public TransportError(String message, Throwable cause) { super(message, cause); }
    }
}
