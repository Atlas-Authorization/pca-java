package net.atlasauth.pca.springsecurity;

import java.util.Map;

import org.springframework.security.core.AuthenticatedPrincipal;

import net.atlasauth.pca.servlet.PcaResult;

/** The principal of a verified PCActn: the grant it acts under ({@code grant_ref}) and the full {@link PcaResult}. */
public final class PcaPrincipal implements AuthenticatedPrincipal {
    private final PcaResult result;

    PcaPrincipal(PcaResult result) { this.result = result; }

    /** The grant the action runs under; the Spring Security principal name. */
    @Override
    public String getName() {
        Object p = result.pcactn();
        Object ref = p instanceof Map<?, ?> m ? m.get("grant_ref") : null;
        return ref == null ? "" : String.valueOf(ref);
    }

    public PcaResult result() { return result; }

    @Override public String toString() { return getName(); }
}
