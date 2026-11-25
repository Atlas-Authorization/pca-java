package net.atlasauth.pca.anthropic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anthropic.core.JsonValue;
import com.anthropic.models.messages.ContentBlock;
import com.anthropic.models.messages.ToolResultBlockParam;
import com.anthropic.models.messages.ToolUseBlock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.ai.PcaDenied;
import net.atlasauth.pca.ai.Proof;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.ai.ToolGuard;
import org.junit.jupiter.api.Test;

public class AnthropicPcaTest {
    static Prover prover(List<String> deny) {
        return (verb, resource, params) -> {
            if (deny.contains(verb)) throw new PcaDenied("denied by policy", verb, resource);
            return new Proof(new LinkedHashMap<>(), "enc", Map.of("PCA-Action", "enc"));
        };
    }

    static final ToolGuard.ToolMapping MAP = (n, a) -> "refund".equals(n) ? new ToolGuard.Action("stripe.refund", "charge:" + a.get("id")) : null;

    static ToolUseBlock use(String id, String name, Object input) {
        return ToolUseBlock.builder().id(id).name(name).input(JsonValue.from(input)).build();
    }

    static String text(ToolResultBlockParam r) { return r.content().get().asString(); }

    @Test void runsTheHandlerUnderTheProof() {
        Map<String, ToolGuard.Body<Object>> handlers = Map.of("refund", (a, p) -> Map.of("id", a.get("id"), "n", a.get("n"), "proof", p.encoded));
        ToolResultBlockParam r = AnthropicPca.handleToolUse(prover(List.of()), MAP, use("tu_1", "refund", Map.of("id", "c9", "n", 5)), handlers);
        assertEquals("tu_1", r.toolUseId());
        assertEquals("{\"id\":\"c9\",\"n\":5,\"proof\":\"enc\"}", text(r));
        assertTrue(r.isError().isEmpty());
    }

    @Test void refusalsComeBackAsErrorResultsAndNeverRun() {
        AtomicInteger ran = new AtomicInteger();
        Map<String, ToolGuard.Body<Object>> handlers = new LinkedHashMap<>();
        handlers.put("refund", (a, p) -> { ran.incrementAndGet(); return "x"; });
        handlers.put("shell", (a, p) -> { ran.incrementAndGet(); return "x"; });
        ToolResultBlockParam denied = AnthropicPca.handleToolUse(prover(List.of("stripe.refund")), MAP, use("1", "refund", Map.of("id", "c")), handlers);
        ToolResultBlockParam unmapped = AnthropicPca.handleToolUse(prover(List.of()), MAP, use("2", "shell", Map.of()), handlers);
        ToolResultBlockParam nohandler = AnthropicPca.handleToolUse(prover(List.of()), MAP, use("3", "refund", Map.of("id", "c")), Map.of());
        ToolResultBlockParam notObject = AnthropicPca.handleToolUse(prover(List.of()), MAP, use("4", "refund", List.of(1)), handlers);
        for (ToolResultBlockParam r : List.of(denied, unmapped, nohandler, notObject)) assertEquals(true, r.isError().get());
        assertEquals("denied by policy", text(denied));
        assertEquals(0, ran.get());
    }

    @Test void aHandlerErrorIsAnErrorResult() {
        Map<String, ToolGuard.Body<Object>> handlers = Map.of("refund", (a, p) -> { throw new IllegalArgumentException("card declined"); });
        ToolResultBlockParam r = AnthropicPca.handleToolUse(prover(List.of()), MAP, use("1", "refund", Map.of("id", "c")), handlers);
        assertEquals("card declined", text(r));
        assertEquals(true, r.isError().get());
    }

    @Test void plainConvertsNumbersToTheSignedProfile() {
        Object v = AnthropicPca.plain(JsonValue.from(Map.of("a", 2.0, "b", 1.5, "c", 7, "d", List.of(true, "s"))));
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) v;
        assertEquals(2L, m.get("a"));
        assertEquals(1.5, m.get("b"));
        assertEquals(7L, m.get("c"));
        assertEquals(List.of(true, "s"), m.get("d"));
    }

    @Test void extractsToolUseBlocks() {
        List<ContentBlock> content = List.of(ContentBlock.ofToolUse(use("1", "refund", Map.of())));
        assertEquals(1, AnthropicPca.extractToolUses(content).size());
    }
}
