package net.atlasauth.pca.springsecurity;

import org.springframework.security.core.Authentication;

/**
 * Method-security helper. Register it as a bean named {@code pca} and write
 * {@code @PreAuthorize("@pca.hasVerb(authentication, 'payments.send')")}. True only for a PCA-authenticated token whose bound
 * operation has that verb (and resource); anything else, including a different kind of login, is false.
 * {@code hasAuthority('PCA_payments.send')} is equivalent for the verb form.
 */
public class PcaMethodSecurity {
    public boolean hasVerb(Authentication authentication, String verb) {
        return verb != null && has(authentication, PcaAuthenticationToken.verbAuthority(verb));
    }

    public boolean hasVerbOn(Authentication authentication, String verb, String resource) {
        return verb != null && resource != null && has(authentication, PcaAuthenticationToken.verbAuthority(verb, resource));
    }

    private static boolean has(Authentication a, String authority) {
        if (!(a instanceof PcaAuthenticationToken t) || !t.isAuthenticated()) return false;
        return t.getAuthorities().stream().anyMatch(g -> authority.equals(g.getAuthority()));
    }
}
