package net.atlasauth.pca.openai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.openai.models.chat.completions.ChatCompletionMessageFunctionToolCall;
import com.openai.models.chat.completions.ChatCompletionMessageToolCall;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Proof;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;
import org.junit.jupiter.api.Test;

public class OpenAiPcaTest {
    static Prover prover(List<String> deny) {
        return (verb, resource, params) -> {
            if (deny.contains(verb)) throw new PcaDenied("denied", verb, resource);
            return new Proof(new LinkedHashMap<>(), "enc", Map.of("PCA-Action", "enc"));
        };
    }

    static final ToolGuard.ToolMapping MAP = (n, a) -> "refund".equals(n) ? new ToolGuard.Action("stripe.refund", "charge:" + a.get("id")) : null;

    static ChatCompletionMessageToolCall call(String id, String name, String args) {
        return ChatCompletionMessageToolCall.ofFunction(ChatCompletionMessageFunctionToolCall.builder().id(id)
            .function(ChatCompletionMessageFunctionToolCall.Function.builder().name(name).arguments(args).build()).build());
    }

    @Test void dispatchRunsTheHandlerUnderTheProofAndBuildsTheToolMessage() {
        Map<String, ToolGuard.Body<Object>> handlers = Map.of("refund", (a, p) -> Map.of("ok", true, "proof", p.encoded));
        var msg = OpenAiPca.dispatchToolCall(prover(List.of()), MAP, call("call_1", "refund", "{\"id\":\"c9\"}"), handlers);
        assertEquals("call_1", msg.toolCallId());
        assertEquals("{\"ok\":true,\"proof\":\"enc\"}", msg.content().asText());
    }

    @Test void aToolWithoutAHandlerReturnsTheProof() {
        var msg = OpenAiPca.dispatchToolCall(prover(List.of()), MAP, call("c", "refund", ""), Map.of());
        assertEquals("{\"pca\":\"enc\"}", msg.content().asText());
    }

    @Test void refusalsNeverRunTheHandler() {
        AtomicInteger ran = new AtomicInteger();
        Map<String, ToolGuard.Body<Object>> handlers = new LinkedHashMap<>();
        handlers.put("refund", (a, p) -> { ran.incrementAndGet(); return "x"; });
        handlers.put("shell", (a, p) -> { ran.incrementAndGet(); return "x"; });
        assertThrows(PcaDenied.class, () -> OpenAiPca.dispatchToolCall(prover(List.of("stripe.refund")), MAP, call("c", "refund", "{}"), handlers));
        assertThrows(PcaDenied.class, () -> OpenAiPca.dispatchToolCall(prover(List.of()), MAP, call("c", "shell", "{}"), handlers));
        assertThrows(PcaDenied.class, () -> OpenAiPca.dispatchToolCall(prover(List.of()), MAP, call("c", "refund", "[1]"), handlers));
        assertEquals(0, ran.get());
    }

    @Test void aRefusalStopsTheRestOfTheTurn() {
        AtomicInteger ran = new AtomicInteger();
        Map<String, ToolGuard.Body<Object>> handlers = Map.of("refund", (a, p) -> { ran.incrementAndGet(); return "x"; });
        List<ChatCompletionMessageToolCall> calls = new ArrayList<>(List.of(call("1", "refund", "{}"), call("2", "shell", "{}"), call("3", "refund", "{}")));
        assertThrows(PcaDenied.class, () -> OpenAiPca.dispatchToolCalls(prover(List.of()), MAP, calls, handlers));
        assertEquals(1, ran.get());
    }
}
