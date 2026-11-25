package net.atlasauth.pca.idjag;

/** The single-use check of an ID-JAG's jti: return {@code Boolean.TRUE} for a fresh one; anything else (or a throw) refuses the grant. */
@FunctionalInterface
public interface JtiStore {
    Object consume(String jti, double expSec) throws Exception;
}
