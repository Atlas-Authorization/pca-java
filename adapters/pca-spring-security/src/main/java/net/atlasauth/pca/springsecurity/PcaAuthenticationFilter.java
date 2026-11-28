package net.atlasauth.pca.springsecurity;

import net.atlasauth.pca.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * Runs every matched request through the {@link AuthenticationManager} as a {@link PcaAuthenticationToken}. On allow the
 * verified token becomes the request's {@code SecurityContext} (not saved to a session) and the {@link PcaResult} is set as the
 * {@code "pca"} request attribute; on refusal the chain stops and the answer is the same as {@code PcaInterceptor}'s: the
 * result's status ({@code 401}/{@code 403}), {@code WWW-Authenticate} challenge and JSON body. Requests the matcher does not
 * match pass through untouched (they are then decided by the rest of the chain).
 */
public final class PcaAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager manager;
    private final RequestMatcher matcher;
    private final SecurityContextHolderStrategy strategy = SecurityContextHolder.getContextHolderStrategy();

    public PcaAuthenticationFilter(AuthenticationManager manager, RequestMatcher matcher) {
        this.manager = java.util.Objects.requireNonNull(manager, "manager");
        this.matcher = matcher == null ? AnyRequestMatcher.INSTANCE : matcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!matcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        Authentication authenticated;
        try {
            authenticated = manager.authenticate(new PcaAuthenticationToken(request));
        } catch (PcaAuthenticationException e) {
            strategy.clearContext();
            refuse(response, e.result());
            return;
        } catch (AuthenticationException e) { // any other refusal from the manager: fail closed
            strategy.clearContext();
            response.reset();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "PCA realm=\"pca\"");
            return;
        }
        if (!(authenticated instanceof PcaAuthenticationToken t) || !t.isAuthenticated() || t.result() == null) {
            strategy.clearContext(); // an unexpected manager answer is never an allow
            response.reset();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "PCA realm=\"pca\"");
            return;
        }
        SecurityContext context = strategy.createEmptyContext();
        context.setAuthentication(t);
        strategy.setContext(context);
        request.setAttribute(PcaCore.ATTRIBUTE, t.result());
        chain.doFilter(request, response);
    }

    private static void refuse(HttpServletResponse response, PcaResult result) throws IOException {
        response.reset();
        response.setStatus(result.status());
        response.setHeader("WWW-Authenticate", result.wwwAuthenticate());
        response.setContentType("application/json;charset=UTF-8");
        byte[] out = Json.utf8(result.httpBody());
        response.setContentLength(out.length);
        response.getOutputStream().write(out);
    }
}
