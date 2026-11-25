package net.atlasauth.pca.springai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.execution.ToolExecutionException;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;

public class SpringAiAdapterTest {
    static final class FakeProver implements Prover {
        final List<String> deny = new ArrayList<>(), retrieved = new ArrayList<>(), tools = new ArrayList<>();
        @Override public Proof prove(String verb, String resource, Map<String, Object> params) {
            if (deny.contains(verb)) throw new PcaDenied("denied", verb, resource);
            return new Proof(new LinkedHashMap<>(), "enc", Map.of("PCA-Action", "enc"));
        }
        @Override public void tool(String name, Object output) { tools.add(name); }
        @Override public void retrieval(String source, Object content) { retrieved.add(source); }
    }

    static final class Echo implements ToolCallback {
        final AtomicInteger calls = new AtomicInteger();
        final String name;
        Echo(String name) { this.name = name; }
        @Override public ToolDefinition getToolDefinition() { return ToolDefinition.builder().name(name).description("d").inputSchema("{}").build(); }
        @Override public String call(String in) { calls.incrementAndGet(); return "ran:" + in; }
    }

    static final ToolGuard.ToolMapping MAP = (n, a) -> "refund".equals(n) ? new ToolGuard.Action("stripe.refund", "charge:1") : null;

    @Test void runsUnderTheProofAndHandsItToTheSink() {
        Echo e = new Echo("refund");
        List<String> seen = new ArrayList<>();
        PcaToolCallback cb = new PcaToolCallback(e, new FakeProver(), MAP, (p, n, in) -> seen.add(p.encoded + "/" + n));
        assertEquals("ran:{\"id\":\"1\"}", cb.call("{\"id\":\"1\"}"));
        assertEquals(List.of("enc/refund"), seen);
        assertEquals("refund", cb.getToolDefinition().name());
    }

    @Test void aDeniedCallThrowsToolExecutionAndNeverRuns() {
        Echo e = new Echo("refund");
        FakeProver p = new FakeProver();
        p.deny.add("stripe.refund");
        ToolExecutionException x = assertThrows(ToolExecutionException.class, () -> new PcaToolCallback(e, p, MAP, null).call("{}"));
        assertInstanceOf(PcaDenied.class, x.getCause());
        assertEquals(0, e.calls.get());
    }

    @Test void anUnmappedToolIsRefused() {
        Echo e = new Echo("shell");
        assertThrows(ToolExecutionException.class, () -> new PcaToolCallback(e, new FakeProver(), MAP, null).call("{}"));
        assertEquals(0, e.calls.get());
    }

    @Test void theResolverWrapsWhatItResolves() {
        Echo e = new Echo("refund");
        ToolCallbackResolver inner = n -> "refund".equals(n) ? e : null;
        PcaToolCallbackResolver r = new PcaToolCallbackResolver(inner, new FakeProver(), MAP, null);
        assertNull(r.resolve("nope"));
        assertInstanceOf(PcaToolCallback.class, r.resolve("refund"));
    }

    private static Document doc(String id, String object) {
        Map<String, Object> acl = new LinkedHashMap<>();
        acl.put("relation", "can_view");
        acl.put("object", object);
        Map<String, Object> md = new LinkedHashMap<>();
        md.put("acl", acl);
        return Document.builder().id(id).text("text " + id).metadata(md).build();
    }

    @Test void theRetrieverDropsWhatThePrincipalMayNotSeeAndFailsClosed() {
        List<Document> all = List.of(doc("a", "document:a"), doc("b", "document:b"), Document.builder().id("c").text("no acl").build());
        List<Object> policy = List.of(Map.of("verb", "can_view", "resource", "document:a"));
        FakeProver p = new FakeProver();
        PcaDocumentRetriever r = new PcaDocumentRetriever(q -> all, "user:alice", policy, p);
        List<Document> got = r.retrieve(new Query("anything"));
        assertEquals(List.of("a"), got.stream().map(Document::getId).toList());
        assertEquals(List.of("a"), p.retrieved);
        assertEquals(List.of("b", "c"), r.lastDecision().get("droppedIds"));
        // no usable policy: nothing is admitted
        assertTrue(new PcaDocumentRetriever(q -> all, "user:alice", null, null).retrieve(new Query("x")).isEmpty());
        assertSame(null, new PcaDocumentRetriever(q -> all, "u", policy, null).lastDecision());
    }
}
