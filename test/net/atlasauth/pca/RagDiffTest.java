package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.rag.Rag;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the retrieval filter through the native port. */
public class RagDiffTest {
    private static final String M = "ref-rag";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void aclsFromMetadata() throws Exception { OracleCases.each(M, "aclsFromMetadata", a -> Rag.aclsFromMetadata(a.get(0), a.get(1))); }

    @Test void compilePolicy() throws Exception { OracleCases.each(M, "compilePolicy", a -> Rag.compilePolicy(a.get(0))); }

    @Test void principalFromPCActn() throws Exception { OracleCases.each(M, "principalFromPCActn", a -> Rag.principalFromPCActn(a.get(0), m(a.get(1)))); }

    @Test void filterDocuments() throws Exception {
        OracleCases.each(M, "filterDocuments", a -> {
            Rag.Result<Object> r = Rag.filterDocuments(a.get(0), a.get(1) instanceof List ? l(a.get(1)) : null, a.get(2));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("documents", r.documents);
            out.put("decision", r.decision);
            return out;
        });
    }

    @Test void adminGroupClosureAdmitsAndOthersDrop() {
        Map<String, Object> pred = Map.of("verb", "can_view", "where", List.of(Map.of("field", "subject.group", "op", "eq", "value", "g1")));
        Map<String, Object> doc = Map.of("id", "d", "acl", Map.of("relation", "can_view", "object", "document:d"));
        Map<String, Object> ok = Map.of("id", "u", "attributes", Map.of("group", "g1"));
        assertEquals(List.of("d"), Rag.filterDocuments(ok, List.of(doc), List.of(pred)).decision.get("allowedIds"));
        assertEquals(List.of("d"), Rag.filterDocuments(Map.of("id", "u", "attributes", Map.of("group", "g2")), List.of(doc), List.of(pred)).decision.get("droppedIds"));
    }

    @Test void withPcaFilterFiltersBeforeTheModelAndRecordsRetrieval() throws Exception {
        Map<String, Object> pred = Map.of("verb", "can_view", "where", List.of(Map.of("field", "subject.group", "op", "eq", "value", "g1")));
        Map<String, Object> a = Map.of("id", "a", "acl", Map.of("relation", "can_view", "object", "document:a"));
        Map<String, Object> b = Map.of("id", "b");
        ArgProvenance.Recorder rec = ArgProvenance.Recorder.create("m", "k1");
        Rag.FilteredRetriever<Object> fr = Rag.withPcaFilter((q, k) -> List.of(a, b), Map.of("id", "u", "attributes", Map.of("group", "g1")), List.of(pred),
            (d, i) -> ((Map<?, ?>) d).get("id"), d -> Rag.aclsFromMetadata(((Map<?, ?>) d).get("acl"), ((Map<?, ?>) d).get("tags")), rec);
        assertEquals(null, fr.lastDecision());
        assertEquals(List.of(a), fr.retrieve("q", null));
        assertEquals(List.of("a"), fr.lastDecision().get("allowedIds"));
        assertEquals(List.of("b"), fr.lastDecision().get("droppedIds"));
        assertEquals(1, rec.receipts().size(), "only the admitted document is recorded as untrusted retrieval content");
        // a retriever that returns nothing admits nothing; a broken policy admits nothing
        assertEquals(List.of(), Rag.withPcaFilter((q, k) -> null, "u", List.of(pred)).retrieve("q", 3));
        assertEquals(List.of(), Rag.withPcaFilter((q, k) -> List.of(a), "u", "no policy").retrieve("q", null));
    }
}
