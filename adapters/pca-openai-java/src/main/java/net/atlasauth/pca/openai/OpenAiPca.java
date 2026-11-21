package net.atlasauth.pca.openai;

import com.openai.models.chat.completions.ChatCompletionMessageFunctionToolCall;
import com.openai.models.chat.completions.ChatCompletionMessageToolCall;
import com.openai.models.chat.completions.ChatCompletionToolMessageParam;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;

/**
 * Helpers for the official {@code com.openai:openai-java} SDK: turn a model's function tool call into a PCA action, run your handler under the
 * proof, and hand back the {@code tool} message for the next model turn. This does NOT authorize: it attaches a proof-carrying action and the
 * resource server's verifier decides. Deny fails closed: an unmapped tool, a custom (non-function) tool call, malformed arguments, or a refused
 * proof throw {@link PcaDenied} and the handler never runs.
 */
public final class OpenAiPca {
    private OpenAiPca() {}

    /** The tool name of a function tool call; a custom tool call is refused (there is no argument object to bind a proof to). */
    public static ChatCompletionMessageFunctionToolCall functionCall(ChatCompletionMessageToolCall call) {
        if (call == null || !call.isFunction()) throw new PcaDenied("only function tool calls can carry a PCActn (a custom tool call is refused)", null, null);
        return call.asFunction();
    }

    /**
     * Dispatch one tool call: map it, build the proof, run {@code handlers.get(name)} under it, and return the {@code tool} message. A tool with no
     * handler returns the proof itself as the content (as the TypeScript adapter does). The result is recorded as untrusted tool output.
     */
    public static ChatCompletionToolMessageParam dispatchToolCall(Prover prover, ToolGuard.ToolMapping map, ChatCompletionMessageToolCall call,
                                                                   Map<String, ToolGuard.Body<Object>> handlers) {
        ChatCompletionMessageFunctionToolCall fc = functionCall(call);
        String name = fc.function().name();
        Map<String, Object> args = ToolGuard.parseArguments(fc.function().arguments());
        String[] content = new String[1];
        ToolGuard.run(prover, map, name, args, (a, proof) -> {
            ToolGuard.Body<Object> h = handlers.get(name);
            Object result = h == null ? null : h.run(a, proof);
            content[0] = ToolGuard.content(result, proof);
            return content[0];
        });
        return ChatCompletionToolMessageParam.builder().toolCallId(fc.id()).content(content[0]).build();
    }

    /** Dispatch every tool call of a turn in order; the first refusal stops the turn (nothing after it runs). */
    public static List<ChatCompletionToolMessageParam> dispatchToolCalls(Prover prover, ToolGuard.ToolMapping map, List<ChatCompletionMessageToolCall> calls,
                                                                         Map<String, ToolGuard.Body<Object>> handlers) {
        List<ChatCompletionToolMessageParam> out = new ArrayList<>();
        for (ChatCompletionMessageToolCall c : calls) out.add(dispatchToolCall(prover, map, c, handlers));
        return out;
    }
}
