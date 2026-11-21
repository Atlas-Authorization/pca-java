package net.atlasauth.pca;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * L4 information-flow taint (the reference's {@code taint.ts}): the agent's declared {@code provenance.trusted_refs} are re-classified from facts the
 * SERVER holds (a trusted-input registry it populated, or its own resource graph); a ref it cannot vouch for is the worst label, so a claim can never
 * forge low taint. The lattice is {@code trusted < first_party < tool < web < agent} (rank 0..4, taint = rank / 4); an empty lineage is the worst
 * case. Pure and total: malformed provenance and any internal error fail closed to taint 1.
 */
public final class Taint {
    private Taint() {}

    public static final String[] LEVELS = {"trusted", "first_party", "tool", "web", "agent"};
    private static final int MAX_RANK = 4;

    static int rankOfKind(Object kind) {
        for (int i = 0; i < LEVELS.length; i++) if (LEVELS[i].equals(kind)) return i;
        return MAX_RANK; // an unknown kind is the worst rank (never undefined / NaN)
    }

    /** What the SERVER vouches for a content digest: a level name, or null for none. An unknown level is not a vouching. */
    @FunctionalInterface
    public interface Registry {
        String lookup(String digest);
    }

    /** The server-held context: the trusted-input registry and an optional resource graph (a ref naming one of its nodes is first party). */
    public static final class Context {
        final Registry registry;
        final Predicate<String> resourceGraphHasNode;

        public Context(Registry registry, Predicate<String> resourceGraphHasNode) {
            this.registry = registry;
            this.resourceGraphHasNode = resourceGraphHasNode;
        }
    }

    /** An in-memory registry the server fills from its own evidence (nothing an agent sends reaches it). */
    public static final class InMemoryRegistry implements Registry {
        private final Map<String, String> m = new HashMap<>();

        /** Records that {@code digest} is an input the server verified at {@code level}; an empty digest or unknown level records nothing. */
        public InMemoryRegistry record(String digest, String level) {
            if (digest != null && !digest.isEmpty() && java.util.Arrays.asList(LEVELS).contains(level)) m.put(digest, level);
            return this;
        }

        @Override public String lookup(String digest) { return m.get(digest); }
    }

    /** The outcome of {@link #compute}: {@code rank} 0..4 (taint = rank / 4), or invalid with the fail-closed reason (rank 4). */
    public static final class Result {
        public final boolean valid;
        public final int rank;
        public final String reason;

        Result(boolean valid, int rank, String reason) { this.valid = valid; this.rank = rank; this.reason = reason; }

        public double taint() { return rank / 4.0; }
    }

    private static Result invalid(String reason) { return new Result(false, MAX_RANK, reason); }

    /** The information-flow taint of a PCActn's {@code provenance}. Never throws. */
    public static Result compute(Object provenance, Context ctx) {
        try {
            if (ctx == null || ctx.registry == null) return invalid("taint: no trusted-input registry");
            if (!(provenance instanceof Map)) return invalid("taint: provenance is absent or malformed");
            Object raw = ((Map<?, ?>) provenance).get("trusted_refs");
            if (raw == null && !((Map<?, ?>) provenance).containsKey("trusted_refs")) return new Result(true, MAX_RANK, null); // empty lineage: worst
            if (!(raw instanceof List)) return invalid("taint: trusted_refs must be an array");
            List<?> refs = (List<?>) raw;
            for (Object r : refs) if (!(r instanceof String) || ((String) r).isEmpty()) return invalid("taint: trusted_refs must be non-empty strings");
            if (refs.isEmpty()) return new Result(true, MAX_RANK, null);
            int rank = 0;
            for (Object r : refs) {
                String ref = (String) r;
                String vouched = ctx.registry.lookup(ref);
                int cls;
                if (vouched != null && java.util.Arrays.asList(LEVELS).contains(vouched)) cls = rankOfKind(vouched);
                else {
                    boolean graph = false;
                    try {
                        graph = ctx.resourceGraphHasNode != null && ctx.resourceGraphHasNode.test(ref);
                    } catch (RuntimeException e) {
                        graph = false;
                    }
                    cls = graph ? 1 : MAX_RANK;
                }
                rank = Math.max(rank, cls);
            }
            return new Result(true, rank, null);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return invalid("taint: evaluation error (fail closed): " + e.getMessage());
        }
    }

    /** The enforce.taint gate: null when it passes, else the failure reason. */
    public static String gate(Object provenance, Context ctx, double maxTaint) {
        try {
            Result t = compute(provenance, ctx);
            int allowed = -1;
            for (int r = 0; r <= MAX_RANK; r++) if (r / 4.0 <= maxTaint) allowed = r;
            if (!t.valid) return t.reason != null ? t.reason : "provenance lineage is not server-verifiable (fail closed)";
            if (!(maxTaint >= 0)) return "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)";
            if (t.rank > allowed) return "information-flow taint " + AttestCommon.jsNumString(t.taint()) + " exceeds policy max " + AttestCommon.jsNumString(maxTaint);
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "taint gate error (fail closed): " + e.getMessage();
        }
    }
}
