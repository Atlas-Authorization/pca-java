package net.atlasauth.pca.ai;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiFunction;
import net.atlasauth.pca.Json;

/** The shared guard behind every AI-stack adapter: map the tool call to an action, build the proof, run the tool under it. Deny fails closed. */
public final class ToolGuard {
    private ToolGuard() {}

    /** Which PCA action a tool call is. */
    public record Action(String verb, String resource) {}

    /** Map a tool call to an action; null declines (the call is then refused: there is no proof to carry). */
    @FunctionalInterface
    public interface ToolMapping { Action map(String tool, Map<String, Object> args); }

    /** The tool body, run only with a proof in hand. */
    @FunctionalInterface
    public interface Body<R> { R run(Map<String, Object> args, Proof proof) throws Exception; }

    /** Parse a tool call's JSON arguments (null, empty or whitespace: {@code {}}). Anything but a JSON object is refused. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseArguments(String raw) {
        if (raw == null || raw.trim().isEmpty()) return new LinkedHashMap<>();
        Object v;
        try {
            v = Json.parse(raw.trim());
        } catch (RuntimeException e) {
            throw new PcaDenied("tool arguments are not valid JSON: " + e.getMessage(), null, null, e);
        }
        if (!(v instanceof Map)) throw new PcaDenied("tool arguments must be a JSON object", null, null);
        return (Map<String, Object>) v;
    }

    /**
     * Run {@code body} for the call {@code name(args)}. Throws {@link PcaDenied} when the mapping declines, the proof cannot be built or the
     * local pre-check denies; the body never runs then. The body's result is recorded as untrusted tool output.
     */
    public static <R> R run(Prover prover, ToolMapping map, String name, Map<String, Object> args, Body<R> body) {
        Action a = map.map(name, args);
        if (a == null) throw new PcaDenied("no PCActn for unmapped tool \"" + name + "\" (the mapping declined)", null, null);
        Proof proof;
        try {
            proof = prover.prove(a.verb(), a.resource(), args);
        } catch (PcaDenied d) {
            throw d;
        } catch (RuntimeException e) {
            throw new PcaDenied("proof could not be built: " + e.getMessage(), a.verb(), a.resource(), e);
        }
        R out;
        try {
            out = body.run(args, proof);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        prover.tool(name, out);
        return out;
    }

    /** {@link #run} for JSON-string arguments (what model tool calls carry) and a String result. */
    public static String runJson(Prover prover, ToolMapping map, String name, String argsJson, BiFunction<Map<String, Object>, Proof, String> body) {
        return run(prover, map, name, parseArguments(argsJson), (a, p) -> body.apply(a, p));
    }

    /** A tool result as the string a model turn carries (canonical JSON; a null result carries the proof instead, as the TypeScript adapters do). */
    public static String content(Object result, Proof proof) {
        if (result == null) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pca", proof.encoded);
            return Json.canonicalize(m);
        }
        return Json.canonicalize(result);
    }
}
