package net.atlasauth.pca.anthropic;

import com.anthropic.core.JsonValue;
import com.anthropic.models.messages.ContentBlock;
import com.anthropic.models.messages.ToolResultBlockParam;
import com.anthropic.models.messages.ToolUseBlock;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;

/**
 * Helpers for the official {@code com.anthropic:anthropic-java} SDK: map a {@code tool_use} block to a PCA action, run your handler under the
 * proof, and return the {@code tool_result} block for the next turn. This does NOT authorize: the resource server's verifier decides.
 * As in the TypeScript adapter, a refusal (unmapped tool, denied proof, no handler, a handler error) comes back as an {@code is_error}
 * tool result so the model sees it; the handler never runs when the proof is refused.
 */
public final class AnthropicPca {
    private AnthropicPca() {}

    /** The {@code tool_use} blocks of a response's content, in order. */
    public static List<ToolUseBlock> extractToolUses(List<ContentBlock> content) {
        List<ToolUseBlock> out = new ArrayList<>();
        if (content != null) for (ContentBlock b : content) if (b.isToolUse()) out.add(b.asToolUse());
        return out;
    }

    /** A tool_use input as the plain JSON value the core signs over (an input that is not an object is refused by the caller). */
    public static Object plain(JsonValue v) {
        if (v == null) return null;
        // the visitor, not asNumber()/asArray()/asObject(): JsonValue extends JsonField<Nothing>, which Java sees as a raw type
        // (every Optional comes back as Optional<Object>); every method is implemented, so no Kotlin interface default is relied on
        return v.accept(new JsonValue.Visitor<Object>() {
            @Override public Object visitNull() { return null; }
            @Override public Object visitMissing() { return null; }
            @Override public Object visitBoolean(boolean b) { return b; }
            @Override public Object visitNumber(Number n) { return number(n); }
            @Override public Object visitString(String s) { return s; }
            @Override public Object visitArray(List<? extends JsonValue> values) {
                List<Object> out = new ArrayList<>();
                for (JsonValue x : values) out.add(plain(x));
                return out;
            }
            @Override public Object visitObject(Map<String, ? extends JsonValue> values) {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<String, ? extends JsonValue> e : values.entrySet()) out.put(e.getKey(), plain(e.getValue()));
                return out;
            }
            @Override public Object visitDefault() { throw new PcaDenied("unsupported value in the tool input", null, null); }
        });
    }

    private static Object number(Number n) {
        if (n instanceof Integer || n instanceof Long || n instanceof Short || n instanceof Byte) return n.longValue();
        BigDecimal d = new BigDecimal(n.toString());
        if (d.stripTrailingZeros().scale() <= 0 && d.abs().compareTo(BigDecimal.valueOf(9007199254740991L)) <= 0) return d.longValue();
        return n.doubleValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> inputOf(ToolUseBlock block) {
        Object in = plain(block._input());
        if (!(in instanceof Map)) throw new PcaDenied("tool input must be a JSON object", null, null);
        return (Map<String, Object>) in;
    }

    private static ToolResultBlockParam result(String id, String content, boolean error) {
        ToolResultBlockParam.Builder b = ToolResultBlockParam.builder().toolUseId(id).content(content);
        if (error) b.isError(true);
        return b.build();
    }

    /** Handle one tool_use block (see the class comment for the refusal rules). Never throws for a refusal. */
    public static ToolResultBlockParam handleToolUse(Prover prover, ToolGuard.ToolMapping map, ToolUseBlock block, Map<String, ToolGuard.Body<Object>> handlers) {
        String name = block.name();
        ToolGuard.Body<Object> handler = handlers.get(name);
        try {
            Map<String, Object> input = inputOf(block);
            if (map.map(name, input) == null) return result(block.id(), "No proof-carrying authority is mapped for tool \"" + name + "\".", true);
            if (handler == null) return result(block.id(), "No handler registered for tool \"" + name + "\".", true);
            String content = ToolGuard.run(prover, map, name, input, (a, proof) -> ToolGuard.content(handler.run(a, proof), proof));
            return result(block.id(), content, false);
        } catch (PcaDenied d) {
            return result(block.id(), String.valueOf(d.getMessage()), true);
        } catch (RuntimeException e) {
            String msg = String.valueOf(e.getMessage());
            prover.tool(name, msg); // a tool's error text reaches the model too: untrusted
            return result(block.id(), msg, true);
        }
    }

    /** Handle every tool_use block of a turn, in order; each gets its own result. */
    public static List<ToolResultBlockParam> handleToolUses(Prover prover, ToolGuard.ToolMapping map, List<ToolUseBlock> blocks, Map<String, ToolGuard.Body<Object>> handlers) {
        List<ToolResultBlockParam> out = new ArrayList<>();
        for (ToolUseBlock b : blocks) out.add(handleToolUse(prover, map, b, handlers));
        return out;
    }
}
