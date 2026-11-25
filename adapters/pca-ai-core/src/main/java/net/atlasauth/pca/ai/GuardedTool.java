package net.atlasauth.pca.ai;

import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * A framework-free tool wrapper: any tool that is a name plus a {@code call(input)} (the shape LlamaIndex, and most agent frameworks without a Java SDK,
 * give a function tool) is wrapped so every call first builds a PCActn through the {@link Prover}, then runs the original tool, whose result is recorded as
 * untrusted. The wrapped tool is the same tool: metadata is untouched and only {@code call} is guarded. Refusals throw {@link PcaDenied} and the tool
 * never runs. This does not authorize: the proof is handed on ({@link Spec#onProof}) and the resource server's verifier decides.
 */
public final class GuardedTool {
    private GuardedTool() {}

    /** The structural shape of a function tool. */
    public interface Tool {
        String name();
        Object call(Map<String, Object> input) throws Exception;
    }

    /** The action a tool call is: a catalog verb and a fixed or argument-derived resource, and where the proof goes. */
    public static final class Spec {
        final String verb;
        final Function<Map<String, Object>, String> resource;
        BiConsumer<Proof, Map<String, Object>> onProof;

        private Spec(String verb, Function<Map<String, Object>, String> resource) {
            if (verb == null || verb.isEmpty()) throw new IllegalArgumentException("verb is required");
            if (resource == null) throw new IllegalArgumentException("resource is required");
            this.verb = verb;
            this.resource = resource;
        }

        public static Spec of(String verb, String resource) { return new Spec(verb, a -> resource); }

        public static Spec of(String verb, Function<Map<String, Object>, String> resource) { return new Spec(verb, resource); }

        /** Receive the proof (e.g. to forward its headers to the resource server) before the tool runs. */
        public Spec onProof(BiConsumer<Proof, Map<String, Object>> onProof) { this.onProof = onProof; return this; }
    }

    /** The same tool with {@code call} guarded: the name is the original's. */
    public static Tool withPCA(Prover prover, Spec spec, Tool tool) {
        if (prover == null || spec == null || tool == null) throw new IllegalArgumentException("prover, spec and tool are required");
        return new Tool() {
            @Override public String name() { return tool.name(); }
            @Override public Object call(Map<String, Object> input) {
                // a resource function that throws is a refusal: no resource, no proof
                return ToolGuard.run(prover, (n, a) -> {
                    String resource;
                    try { resource = spec.resource.apply(a); } catch (RuntimeException e) { throw new PcaDenied("resource could not be derived: " + e.getMessage(), spec.verb, null, e); }
                    return new ToolGuard.Action(spec.verb, resource);
                }, tool.name(), input, (a, proof) -> {
                    if (spec.onProof != null) spec.onProof.accept(proof, a);
                    return tool.call(a);
                });
            }
        };
    }
}
