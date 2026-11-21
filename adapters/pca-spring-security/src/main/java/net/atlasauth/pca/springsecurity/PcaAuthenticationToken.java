package net.atlasauth.pca.springsecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * A PCActn as a Spring Security {@code Authentication}. The unauthenticated form carries the request to verify; the
 * authenticated form is only ever built by {@link PcaAuthenticationProvider} from an allowed {@link PcaResult}.
 *
 * <p>Authorities come from the operation the proof was bound to by {@code Authorize.authorize} (never from the request):
 * {@code PCA_<verb>} and {@code PCA_<verb>:<resource>}, so {@code hasAuthority('PCA_payments.send')} works in
 * {@code @PreAuthorize} and in request matchers.
 */
public final class PcaAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;

    /** Authority prefix. */
    public static final String PREFIX = "PCA_";

    /** The authority granted for an operation verb. */
    public static String verbAuthority(String verb) { return PREFIX + verb; }

    /** The authority granted for an operation verb on one resource. */
    public static String verbAuthority(String verb, String resource) { return PREFIX + verb + ':' + resource; }

    private final transient HttpServletRequest request;
    private final transient PcaResult result;

    /** The request to verify (not yet authenticated). */
    public PcaAuthenticationToken(HttpServletRequest request) {
        super(null);
        this.request = request;
        this.result = null;
        super.setAuthenticated(false);
    }

    PcaAuthenticationToken(PcaResult result, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.request = null;
        this.result = result;
        super.setAuthenticated(true);
    }

    /** The authenticated token for an allowed result; fail closed (throws) on anything else. */
    static PcaAuthenticationToken authenticated(PcaResult result) {
        if (result == null || !result.allowed()) throw new IllegalArgumentException("only an allowed PCA result authenticates");
        List<GrantedAuthority> authorities = new ArrayList<>();
        Authorize.AuthorizedOperation op = result.authorization() == null ? null : result.authorization().operation;
        if (op != null && op.verb != null) {
            authorities.add(new SimpleGrantedAuthority(verbAuthority(op.verb)));
            if (op.resource != null) authorities.add(new SimpleGrantedAuthority(verbAuthority(op.verb, op.resource)));
        }
        return new PcaAuthenticationToken(result, authorities);
    }

    /** The request awaiting verification, or null on an authenticated token. */
    public HttpServletRequest request() { return request; }

    /** The verified outcome, or null on an unauthenticated token. */
    public PcaResult result() { return result; }

    @Override public Object getPrincipal() { return result == null ? null : new PcaPrincipal(result); }

    @Override public Object getCredentials() { return null; }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) throw new IllegalArgumentException("a PCA token is authenticated only by PcaAuthenticationProvider");
        super.setAuthenticated(false);
    }
}
