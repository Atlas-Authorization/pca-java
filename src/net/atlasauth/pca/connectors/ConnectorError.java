package net.atlasauth.pca.connectors;

import java.util.List;

/** Base class for every runtime refusal the connector catalog raises. */
public class ConnectorError extends RuntimeException {
    private final String name;

    public ConnectorError(String message) { this("ConnectorError", message); }

    ConnectorError(String name, String message) {
        super(message);
        this.name = name;
    }

    /** The reference's error class name (ConnectorError, ManifestValidationError, UnknownProviderError). */
    public String errorName() { return name; }

    /** A manifest failed structural validation; {@link #issues} lists every problem found. */
    public static final class ManifestValidationError extends ConnectorError {
        public final List<String> issues;
        public ManifestValidationError(List<String> issues) {
            super("ManifestValidationError", "invalid provider manifest: " + String.join("; ", issues));
            this.issues = List.copyOf(issues);
        }
    }

    /** No manifest is registered for the requested provider id. */
    public static final class UnknownProviderError extends ConnectorError {
        public final String providerId;
        public UnknownProviderError(String providerId) {
            super("UnknownProviderError", "no connector registered for provider '" + providerId + "'");
            this.providerId = providerId;
        }
    }
}
