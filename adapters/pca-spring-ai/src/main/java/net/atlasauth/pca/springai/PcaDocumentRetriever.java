package net.atlasauth.pca.springai;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.rag.Rag;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.retrieval.search.DocumentRetriever;

/**
 * PCA-scoped RAG: a {@link DocumentRetriever} whose results are filtered to what the principal may see BEFORE they reach the model.
 * A document is admitted only when a permit predicate matches one of its ACL entries ({@code metadata.acl}: {@code {relation, object}} or a list,
 * and/or {@code metadata.tags}: {@code relation:object} strings) and no deny matches; anything unknown is dropped. See {@link Rag}.
 * Admitted documents are recorded as untrusted retrieval content when the prover has a recorder.
 */
public final class PcaDocumentRetriever implements DocumentRetriever {
    private final DocumentRetriever delegate;
    private final Object principal;
    private final Map<String, Object> compiled;
    private final Prover prover;
    private volatile Map<String, Object> last;

    /** {@code principal}: an id String or a {@code {id, attributes?, env?}} map; {@code policy}: anything {@link Rag#compilePolicy} takes. {@code prover} may be null. */
    public PcaDocumentRetriever(DocumentRetriever delegate, Object principal, Object policy, Prover prover) {
        if (delegate == null) throw new IllegalArgumentException("PcaDocumentRetriever: delegate is required");
        this.delegate = delegate;
        this.principal = principal;
        this.compiled = Rag.compilePolicy(policy);
        this.prover = prover;
    }

    @Override public List<Document> retrieve(Query query) {
        List<Document> docs = delegate.retrieve(query);
        Rag.Result<Document> r = Rag.filter(principal, docs == null ? new ArrayList<Document>() : docs, compiled,
            (d, i) -> d.getId(),
            d -> Rag.aclsFromMetadata(d.getMetadata().get("acl"), d.getMetadata().get("tags")));
        last = r.decision;
        if (prover != null) for (Document d : r.documents) prover.retrieval(d.getId(), d.getText());
        return r.documents;
    }

    /** The decision of the most recent retrieval (the proof trace), or null. */
    public Map<String, Object> lastDecision() { return last; }
}
