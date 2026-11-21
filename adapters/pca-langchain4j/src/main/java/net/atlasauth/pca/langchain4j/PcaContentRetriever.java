package net.atlasauth.pca.langchain4j;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.ai.Prover;
import net.atlasauth.pca.rag.Rag;

/**
 * PCA-scoped RAG: a {@link ContentRetriever} whose results are filtered to what the principal may see BEFORE they reach the model (fail closed;
 * see {@link Rag}). LangChain4j metadata holds scalars only, so by default the ACL is read from the segment metadata keys {@code acl} and
 * {@code tags}: {@code relation:object} strings, comma separated (the split at the first colon, so an object id may contain colons). The id is
 * metadata {@code id}, else {@code source}, else positional. Pass {@code getAcls} / {@code getId} for another layout.
 */
public final class PcaContentRetriever implements ContentRetriever {
    private final ContentRetriever delegate;
    private final Object principal;
    private final Map<String, Object> compiled;
    private final Prover prover;
    private final Function<Content, Object> getAcls;
    private final Function<Content, String> getId;
    private volatile Map<String, Object> last;

    public PcaContentRetriever(ContentRetriever delegate, Object principal, Object policy, Prover prover,
                               Function<Content, Object> getAcls, Function<Content, String> getId) {
        if (delegate == null) throw new IllegalArgumentException("PcaContentRetriever: delegate is required");
        this.delegate = delegate;
        this.principal = principal;
        this.compiled = Rag.compilePolicy(policy);
        this.prover = prover;
        this.getAcls = getAcls != null ? getAcls : PcaContentRetriever::defaultAcls;
        this.getId = getId != null ? getId : PcaContentRetriever::defaultId;
    }

    public PcaContentRetriever(ContentRetriever delegate, Object principal, Object policy, Prover prover) { this(delegate, principal, policy, prover, null, null); }

    static Object defaultAcls(Content c) {
        Metadata m = c.textSegment().metadata();
        List<Object> tags = new ArrayList<>();
        for (String key : new String[] {"acl", "tags"}) {
            String v = m.getString(key);
            if (v == null) continue;
            for (String t : v.split(",")) tags.add(t.trim());
        }
        return Rag.aclsFromMetadata(null, tags);
    }

    static String defaultId(Content c) {
        Metadata m = c.textSegment().metadata();
        String id = m.getString("id");
        return id != null ? id : m.getString("source");
    }

    @Override public List<Content> retrieve(Query query) {
        List<Content> found = delegate.retrieve(query);
        Rag.Result<Content> r = Rag.filter(principal, found == null ? new ArrayList<Content>() : found, compiled, (c, i) -> getId.apply(c), getAcls);
        last = r.decision;
        if (prover != null) for (Content c : r.documents) prover.retrieval(String.valueOf(getId.apply(c)), c.textSegment().text());
        return r.documents;
    }

    /** The decision of the most recent retrieval (the proof trace), or null. */
    public Map<String, Object> lastDecision() { return last; }
}
