package net.atlasauth.pca.jaxrs;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.ws.rs.NameBinding;

/**
 * Name-binding annotation: put it on a resource class or method to run {@link PcaContainerRequestFilter} for it. Resources
 * without it are not guarded.
 */
@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface PcaProtected {
}
