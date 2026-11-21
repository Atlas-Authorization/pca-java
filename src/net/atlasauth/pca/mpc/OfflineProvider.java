package net.atlasauth.pca.mpc;

import java.math.BigInteger;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.AuthTriple;
import net.atlasauth.pca.mpc.Spdz.MacContext;

/** A source of the SPDZ offline phase: the MAC key, authenticated triples and authenticated input sharings. */
public interface OfflineProvider {
    int n();
    MacContext macContext();
    AuthTriple genAuthTriple();
    /** Authenticated sharing of {@code value} contributed by party {@code owner}. */
    AuthSV authInput(BigInteger value, int owner);
}
