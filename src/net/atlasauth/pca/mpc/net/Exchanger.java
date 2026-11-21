package net.atlasauth.pca.mpc.net;

import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.IntFunction;

/** One un-echoed all-to-all round among the parties; a throw inside {@code parse} aborts the run naming that peer. */
public interface Exchanger {
    /** Send {@code mine(peer)} to every peer, collect theirs and validate each with {@code parse}; {@code timeoutMs} null means the mesh default. */
    <T> Map<Integer, T> exchange(String rd, IntFunction<Object> mine, BiFunction<Integer, Object, T> parse, Long timeoutMs);

    default <T> Map<Integer, T> exchange(String rd, IntFunction<Object> mine, BiFunction<Integer, Object, T> parse) {
        return exchange(rd, mine, parse, null);
    }

    /** A malformed-data abort naming peer {@code p}; callers {@code throw} the result. */
    RuntimeException bad(int p, String what);
}
