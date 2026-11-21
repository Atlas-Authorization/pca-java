package net.atlasauth.pca.langchain4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.service.tool.ToolExecutor;
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

public class LangChain4jAdapterTest {
    static final class FakeProver implements Prover {
        final List<String> deny = new ArrayList<>(), retrieved = new ArrayList<>();
        @Override public Proof prove(String verb, String resource, Map<String, Object> params) {
            if (deny.contains(verb)) throw new PcaDenied("denied", verb, resource);
            return new Proof(new LinkedHashMap<>(), "enc", Map.of("PCA-Action", "enc"));
        }
        @Override public void retrieval(String source, Object content) { retrieved.add(source); }
    }

    static final ToolGuard.ToolMapping MAP = (n, a) -> "refund".equals(n) ? new ToolGuard.Action("stripe.refund", "charge:1") : null;

    static ToolExecutionRequest req(String name, String args) { return ToolExecutionRequest.builder().id("1").name(name).arguments(args).build(); }

    @Test void runsUnderTheProof() {
        List<String> seen = new ArrayList<>();
        ToolExecutor inner = (r, m) -> "ran:" + r.arguments();
        PcaToolExecutor x = new PcaToolExecutor(inner, new FakeProver(), MAP, (p, r) -> seen.add(p.encoded + "/" + r.name()), false);
        assertEquals("ran:{\"a\":1}", x.execute(req("refund", "{\"a\":1}"), "m"));
        assertEquals(List.of("enc/refund"), seen);
    }

    @Test void deniedOrUnmappedNeverRunsTheTool() {
        AtomicInteger ran = new AtomicInteger();
        ToolExecutor inner = (r, m) -> { ran.incrementAndGet(); return "x"; };
        FakeProver p = new FakeProver();
        p.deny.add("stripe.refund");
        assertThrows(PcaDenied.class, () -> new PcaToolExecutor(inner, p, MAP, null, false).execute(req("refund", "{}"), null));
        assertThrows(PcaDenied.class, () -> new PcaToolExecutor(inner, new FakeProver(), MAP, null, false).execute(req("shell", "{}"), null));
        assertTrue(new PcaToolExecutor(inner, p, MAP, null, true).execute(req("refund", "{}"), null).startsWith("denied: "));
        assertEquals(0, ran.get());
    }

    private static Content content(String id, String acl) {
        Metadata m = new Metadata().put("id", id);
        if (acl != null) m.put("acl", acl);
        return Content.from(TextSegment.from("text " + id, m));
    }

    @Test void theRetrieverKeepsOnlyAuthorizedContentAndFailsClosed() {
        List<Content> all = List.of(content("a", "can_view:document:a"), content("b", "can_view:document:b"), content("c", null),
            content("d", "x:y, can_view:document:a"));
        List<Object> policy = List.of(Map.of("verb", "can_view", "resource", "document:a"));
        FakeProver p = new FakeProver();
        PcaContentRetriever r = new PcaContentRetriever(q -> all, "user:alice", policy, p);
        List<Content> got = r.retrieve(Query.from("q"));
        assertEquals(List.of("a", "d"), got.stream().map(c -> c.textSegment().metadata().getString("id")).toList());
        assertEquals(List.of("a", "d"), p.retrieved);
        assertEquals(List.of("b", "c"), r.lastDecision().get("droppedIds"));
        assertTrue(new PcaContentRetriever(q -> all, "user:alice", "not a policy", null).retrieve(Query.from("q")).isEmpty());
    }
}
