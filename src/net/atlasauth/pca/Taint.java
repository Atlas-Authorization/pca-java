package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    // ---- the label lattice, the label registry, classification and the labelled result (the reference's full taint surface) -----------------

    private static final Object UNDEF = new Object();

    private static int levelIndex(Object kind) {
        if (!(kind instanceof String)) return -1;
        for (int i = 0; i < LEVELS.length; i++) if (LEVELS[i].equals(kind)) return i;
        return -1;
    }

    private static Object kindOf(Object label) { return label instanceof Map ? ((Map<?, ?>) label).get("kind") : null; }

    /** The most-trusted label, the identity of {@link #joinLabel}. */
    public static Map<String, Object> bottom() { return Issue.obj("kind", "trusted"); }

    /** The least-trusted label (fail closed / worst case). */
    public static Map<String, Object> top() { return Issue.obj("kind", "agent"); }

    /** True only for the five level names (an own-member test: {@code constructor}, {@code toString} are not levels). */
    public static boolean isTaintLevel(Object kind) { return levelIndex(kind) >= 0; }

    /** The rank of a label; an unknown, missing or non-string kind is the WORST rank 4. */
    public static int labelRank(Object label) {
        int i = levelIndex(kindOf(label));
        return i < 0 ? MAX_RANK : i;
    }

    /** Normalized taint of a label in [0, 1]: rank / 4. */
    public static double taintValue(Object label) { return labelRank(label) / 4.0; }

    private static Object labelId(Object l) {
        if (l == null) throw new IllegalArgumentException("Cannot convert undefined or null to object");
        return l instanceof Map && ((Map<?, ?>) l).containsKey("id") ? ((Map<?, ?>) l).get("id") : UNDEF;
    }

    private static boolean sameId(Object a, Object b) {
        if (a == UNDEF || b == UNDEF || a == null || b == null) return a == b;
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        return a.equals(b);
    }

    /**
     * The least upper bound of two labels: the higher rank wins and keeps its label as is; equal ranks keep the {@code id} only when both agree,
     * else the bare {@code {kind}}. A null label throws when both ranks tie (as the reference does), otherwise it is the worst rank.
     */
    public static Object joinLabel(Object a, Object b) {
        int ra = labelRank(a), rb = labelRank(b);
        if (ra > rb) return a;
        if (rb > ra) return b;
        if (sameId(labelId(a), labelId(b))) return a;
        Map<String, Object> out = new LinkedHashMap<>();
        if (a instanceof Map && ((Map<?, ?>) a).containsKey("kind")) out.put("kind", ((Map<?, ?>) a).get("kind"));
        return out;
    }

    /** The join over a list; the EMPTY lineage is the worst label (no verifiable trusted input is not "trusted"). */
    public static Object joinLabels(List<?> labels) {
        if (labels.isEmpty()) return top();
        Object acc = labels.get(0);
        for (int i = 1; i < labels.size(); i++) acc = joinLabel(acc, labels.get(i));
        return acc;
    }

    /** What the SERVER vouches for a content digest: a label map, or null for none. A lookup may throw: the caller then fails closed. */
    @FunctionalInterface
    public interface TrustedInputRegistry {
        Object lookup(String digest);
    }

    /** The registry that vouches for nothing. */
    public static final TrustedInputRegistry EMPTY_REGISTRY = d -> null;

    /** The server-held context of the labelled API: the registry (null = none) and an optional resource graph (a ref naming a node is first party). */
    public static final class LabelContext {
        final TrustedInputRegistry registry;
        final Predicate<String> resourceGraphHasNode;

        public LabelContext(TrustedInputRegistry registry, Predicate<String> resourceGraphHasNode) {
            this.registry = registry;
            this.resourceGraphHasNode = resourceGraphHasNode;
        }
    }

    /** An in-memory registry of labels the server fills from its own evidence. */
    public static final class InMemoryTrustedInputRegistry implements TrustedInputRegistry {
        private final Map<String, Map<String, Object>> m = new HashMap<>();

        /** Records that {@code digest} is an input the server verified at {@code label}; an empty or non-string digest, or a label whose kind is not a level, records nothing. */
        public InMemoryTrustedInputRegistry record(Object digest, Object label) {
            if (digest instanceof String && !((String) digest).isEmpty() && isTaintLevel(kindOf(label))) {
                Map<String, Object> copy = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : ((Map<?, ?>) label).entrySet()) copy.put((String) e.getKey(), e.getValue());
                m.put((String) digest, copy);
            }
            return this;
        }

        public InMemoryTrustedInputRegistry recordTrusted(Object digest) { return record(digest, Issue.obj("kind", "trusted")); }

        public InMemoryTrustedInputRegistry recordFirstParty(Object digest) { return record(digest, Issue.obj("kind", "first_party")); }

        public InMemoryTrustedInputRegistry recordTool(Object digest, Object id) { return record(digest, Issue.obj("kind", "tool", "id", id)); }

        public InMemoryTrustedInputRegistry recordWeb(Object digest) { return record(digest, Issue.obj("kind", "web")); }

        @Override public Object lookup(String digest) {
            Map<String, Object> l = m.get(digest);
            return l == null ? null : new LinkedHashMap<>(l);
        }

        public int size() { return m.size(); }
    }

    /**
     * Independently classifies ONE declared ref; the agent's own label is never read: a non-string or empty ref is {@code agent}; a registry hit
     * with a level kind is that (registered) label; a resource-graph node is {@code first_party}; else {@code agent} (carrying the ref as id when it
     * is at most 128 characters). A throwing registry throws; a null registry throws for a real ref.
     */
    public static Object classifyRef(Object ref, LabelContext ctx) {
        if (!(ref instanceof String) || ((String) ref).isEmpty()) return top();
        if (ctx.registry == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'lookup')");
        Object vouched = ctx.registry.lookup((String) ref);
        if (Zk.truthy(vouched) && isTaintLevel(kindOf(vouched))) return vouched;
        try {
            if (ctx.resourceGraphHasNode != null && ctx.resourceGraphHasNode.test((String) ref)) return Issue.obj("kind", "first_party");
        } catch (RuntimeException e) {
            // fall through to the worst case
        }
        return ((String) ref).length() <= 128 ? Issue.obj("kind", "agent", "id", ref) : top();
    }

    /** A label rebuilt as {@code {kind[, id]}}: the id only when the label has one of its own. */
    private static Map<String, Object> rebuilt(Object l) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", kindOf(l));
        if (l instanceof Map && ((Map<?, ?>) l).containsKey("id")) out.put("id", ((Map<?, ?>) l).get("id"));
        return out;
    }

    private static Map<String, Object> invalidResult(String reason) {
        return Issue.obj("taint", 1L, "label", top(), "refs", new ArrayList<Object>(), "valid", false, "reason", reason);
    }

    /**
     * The information-flow taint of a PCActn's {@code provenance} with per-ref labels: {@code {taint, label, refs: [{ref, label}], valid, reason?}}.
     * {@code taint} is the rank of the join of the independently classified refs over 4; an empty lineage is 1; every fault is
     * {@code {taint: 1, valid: false}} with a reason. Never throws.
     */
    public static Map<String, Object> computeTaint(Object provenance, LabelContext ctx) {
        if (ctx == null || ctx.registry == null) return invalidResult("taint: no trusted-input registry");
        if (!(provenance instanceof Map)) return invalidResult("taint: provenance is absent or malformed");
        Map<?, ?> p = (Map<?, ?>) provenance;
        List<?> list = new ArrayList<Object>();
        if (p.containsKey("trusted_refs")) {
            Object raw = p.get("trusted_refs");
            if (!(raw instanceof List)) return invalidResult("taint: trusted_refs must be an array");
            for (Object r : (List<?>) raw) if (!(r instanceof String) || ((String) r).isEmpty()) return invalidResult("taint: trusted_refs must be non-empty strings");
            list = (List<?>) raw;
        }
        try {
            List<Object> refs = new ArrayList<>(), labels = new ArrayList<>();
            for (Object r : list) {
                String ref = (String) r;
                Object v = ctx.registry.lookup(ref);
                Object label;
                if (Zk.truthy(v) && isTaintLevel(kindOf(v))) label = rebuilt(v);
                else {
                    boolean hit = false;
                    try {
                        hit = ctx.resourceGraphHasNode != null && ctx.resourceGraphHasNode.test(ref);
                    } catch (RuntimeException e) {
                        hit = false;
                    }
                    label = hit ? (Object) Issue.obj("kind", "first_party") : ref.length() <= 128 ? (Object) Issue.obj("kind", "agent", "id", ref) : top();
                }
                refs.add(Issue.obj("ref", ref, "label", label));
                labels.add(label);
            }
            Object joined = joinLabels(labels);
            return Issue.obj("taint", taintValue(joined), "label", joined, "refs", refs, "valid", true);
        } catch (RuntimeException e) {
            return invalidResult("taint: evaluation error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }
}
