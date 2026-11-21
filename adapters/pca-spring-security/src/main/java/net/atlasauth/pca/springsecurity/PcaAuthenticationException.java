package net.atlasauth.pca.springsecurity;

import org.springframework.security.core.AuthenticationException;

import net.atlasauth.pca.servlet.PcaResult;

/** A refused PCActn. Carries the {@link PcaResult} that decides the 401/403 answer. */
public final class PcaAuthenticationException extends AuthenticationException {
    private static final long serialVersionUID = 1L;
    private final transient PcaResult result;

    public PcaAuthenticationException(PcaResult result) {
        super(result.detail());
        this.result = result;
    }

    public PcaResult result() { return result; }
}
