package net.atlasauth.pca.actions.importers;

import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Actions.ActionKitError;

/** The bounds every importer enforces before it believes a byte of foreign input: size, depth, node count and reference expansion. */
public final class ImportLimits {
    public final long maxBytes, maxOps, maxJsonDepth, maxNodes, maxRefNodes, maxRefDepth;

    public ImportLimits(long maxBytes, long maxOps, long maxJsonDepth, long maxNodes, long maxRefNodes, long maxRefDepth) {
        this.maxBytes = maxBytes; this.maxOps = maxOps; this.maxJsonDepth = maxJsonDepth; this.maxNodes = maxNodes; this.maxRefNodes = maxRefNodes; this.maxRefDepth = maxRefDepth;
    }

    public static final ImportLimits DEFAULT = new ImportLimits(64L * 1024 * 1024, 20_000, 64, 6_000_000, 20_000, 8);
    /** Ceilings no caller may raise past: a caller-supplied limit is clamped to these. */
    public static final ImportLimits HARD = new ImportLimits(256L * 1024 * 1024, 50_000, 128, 20_000_000, 200_000, 16);

    private static final List<String> KEYS = List.of("max_bytes", "max_ops", "max_json_depth", "max_nodes", "max_ref_nodes", "max_ref_depth");

    private long of(int i) {
        switch (i) { case 0: return maxBytes; case 1: return maxOps; case 2: return maxJsonDepth; case 3: return maxNodes; case 4: return maxRefNodes; default: return maxRefDepth; }
    }

    /** Defaults, overridden member by member (clamped to the hard ceilings); a member that is not a positive safe integer is refused. */
    public static ImportLimits resolve(Object over) {
        long[] out = new long[6];
        for (int i = 0; i < 6; i++) {
            out[i] = DEFAULT.of(i);
            if (!(over instanceof Map) || !((Map<?, ?>) over).containsKey(KEYS.get(i))) continue;
            Object v = ((Map<?, ?>) over).get(KEYS.get(i));
            if (!Jx.isSafe(v) || Jx.num(v) < 1) throw new ActionKitError("bad_limit", "limit " + KEYS.get(i) + " must be a positive safe integer");
            out[i] = Math.min((long) (double) Jx.num(v), HARD.of(i));
        }
        return new ImportLimits(out[0], out[1], out[2], out[3], out[4], out[5]);
    }

    /** Size check of a text source (UTF-8 bytes). */
    public void textSizeCheck(String text) {
        if ((long) text.length() * 3 > maxBytes && Jx.u8(text) > maxBytes) throw new ActionKitError("import_limit", "the source is larger than " + maxBytes + " bytes");
    }

    /**
     * Walk a parsed source iteratively and refuse it when it is not plain JSON data, or is deeper or larger than the limits.
     * Returns the node count.
     */
    public long checkParsed(Object root) {
        long nodes = 0, bytes = 0;
        ArrayDeque<Object[]> stack = new ArrayDeque<>();
        stack.push(new Object[] {root, 0});
        while (!stack.isEmpty()) {
            Object[] top = stack.pop();
            Object v = top[0];
            int d = (Integer) top[1];
            if (++nodes > maxNodes) throw new ActionKitError("import_limit", "the source has more than " + maxNodes + " nodes");
            if (d > maxJsonDepth) throw new ActionKitError("import_limit", "the source nests deeper than " + maxJsonDepth);
            if (v == null || v instanceof Boolean) bytes += 4;
            else if (v instanceof String) bytes += ((String) v).length();
            else if (v instanceof List) {
                List<?> l = (List<?>) v;
                bytes += 2 + l.size();
                for (Object x : l) stack.push(new Object[] {x, d + 1});
            } else if (v instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                    bytes += ((String) e.getKey()).length() + 4;
                    stack.push(new Object[] {e.getValue(), d + 1});
                }
            } else {
                Double n = Jx.num(v);
                if (n == null) throw new ActionKitError("bad_source", "the source holds a " + v.getClass().getSimpleName());
                if (n.isNaN() || n.isInfinite()) throw new ActionKitError("bad_source", "the source holds a non-finite number");
                bytes += 8;
            }
            if (bytes > maxBytes) throw new ActionKitError("import_limit", "the source is larger than " + maxBytes + " bytes");
        }
        return nodes;
    }
}
