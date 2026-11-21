package net.atlasauth.pca.rag;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.policybridge.OpenFga;
import net.atlasauth.pca.policybridge.PolicyBridge;

/**
 * FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the
 * TypeScript pca-rag package).
 *
 * <p>FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation,
 * resource = object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy
 * translation, an evaluator error) drops the document. Every decision is recorded ({@link Result#decision}), with a content
 * digest of the whole decision set.
 *
 * <p>JSON values are the core's: Map, List, String, Boolean, numbers. A principal is a String id or a Map {@code {id, attributes?, env?}}.
 * A policy is a List of predicates, a Map {@code {openfga: {model, tuples}}}, a Map {@code {predicates, denies?, report?}} or an
 * already-compiled policy ({@link #compilePolicy}).
 */
public final class Rag {
    private Rag() {}

    /** The admitted documents (candidate order) and the decision record (the proof trace). */
    public static final class Result<D> {
        public final List<D> documents;
        public final Map<String, Object> decision;
        Result(List<D> documents, Map<String, Object> decision) { this.documents = documents; this.decision = decision; }
    }

    // ---- helpers --------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static boolean nonEmptyString(Object o) { return o instanceof String && !((String) o).isEmpty(); }

    // ---- documents and ACLs ---------------------------------------------------------------------------------------------

    private static boolean isDocAcl(Object v) {
        Map<String, Object> m = map(v);
        return m != null && nonEmptyString(m.get("relation")) && nonEmptyString(m.get("object"));
    }

    private static List<Object> aclArray(Object acl) {
        List<Object> out = new ArrayList<>();
        if (acl instanceof List) { for (Object a : (List<?>) acl) if (isDocAcl(a)) out.add(a); }
        else if (isDocAcl(acl)) out.add(acl);
        return out;
    }

    /** A {@code relation:object} tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons. */
    private static Map<String, Object> tagToAcl(Object tag) {
        if (!(tag instanceof String)) return null;
        String t = (String) tag;
        int i = t.indexOf(':');
        if (i <= 0 || i >= t.length() - 1) return null;
        return obj("relation", t.substring(0, i), "object", t.substring(i + 1));
    }

    /** ACL entries from freeform {@code acl} (one entry or a list) and {@code tags} ({@code relation:object} strings) metadata. */
    public static List<Object> aclsFromMetadata(Object acl, Object tags) {
        List<Object> out = aclArray(acl);
        if (tags instanceof List) {
            for (Object t : (List<?>) tags) {
                Map<String, Object> a = tagToAcl(t);
                if (a != null) out.add(a);
            }
        }
        return out;
    }

    // ---- principal ------------------------------------------------------------------------------------------------------

    /**
     * The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with {@code opts.id}).
     * Throws on a PCActn with no capability chain, rather than producing an empty principal. {@code opts}: {id?, attributes?, env?}, may be null.
     */
    public static Map<String, Object> principalFromPCActn(Object pcactn, Map<String, Object> opts) {
        Map<String, Object> p = map(pcactn);
        Object chain = p == null ? null : p.get("cap_chain");
        Object holder = null;
        if (chain instanceof List && !((List<?>) chain).isEmpty()) {
            List<?> c = (List<?>) chain;
            Map<String, Object> leaf = map(c.get(c.size() - 1));
            holder = leaf == null ? null : leaf.get("holder");
        }
        if (!nonEmptyString(holder)) throw new IllegalArgumentException("principalFromPCActn: PCActn has no leaf capability holder");
        Map<String, Object> out = new LinkedHashMap<>();
        Object id = opts == null ? null : opts.get("id");
        out.put("id", id != null ? id : holder);
        if (opts != null && opts.containsKey("attributes")) out.put("attributes", opts.get("attributes"));
        if (opts != null && opts.containsKey("env")) out.put("env", opts.get("env"));
        return out;
    }

    private static Map<String, Object> toPrincipal(Object p) {
        if (p instanceof String) return obj("id", p);
        if (p instanceof Map) return map(p);
        if (p instanceof List) return new LinkedHashMap<>(); // a JavaScript array is an object with no id
        return null;
    }

    // ---- policy compilation ---------------------------------------------------------------------------------------------

    private static Map<String, Object> incomplete(String reason) {
        return obj("predicates", new ArrayList<Object>(), "denies", new ArrayList<Object>(), "incomplete", Boolean.TRUE, "incompleteReason", reason);
    }

    /**
     * Compile any policy into {@code {predicates, denies, incomplete, incompleteReason?, report?}} (an already-compiled policy passes through).
     * A value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> compilePolicy(Object policy) {
        if (!(policy instanceof Map) && !(policy instanceof List)) return incomplete("no usable policy was supplied (fail closed)");
        if (policy instanceof List) return obj("predicates", policy, "denies", new ArrayList<Object>(), "incomplete", Boolean.FALSE);
        Map<String, Object> p = map(policy);
        if (p.get("incomplete") instanceof Boolean) return p;
        if (!p.containsKey("openfga") && !(p.get("predicates") instanceof List)) {
            return incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)");
        }
        if (p.containsKey("openfga")) {
            Map<String, Object> fga = map(p.get("openfga"));
            if (fga == null && !(p.get("openfga") instanceof List)) return incomplete("the OpenFGA policy has no model (fail closed)");
            Map<String, Object> f = fga != null ? fga : new LinkedHashMap<String, Object>(); // an array has no model or tuples
            Map<String, Object> br = f.containsKey("tuples") ? OpenFga.openfgaToPca(f.get("model"), f.get("tuples")) : OpenFga.openfgaToPca(f.get("model"));
            Map<String, Object> report = map(br.get("report"));
            return obj("predicates", br.get("predicates"), "denies", br.get("denies"), "report", report, "incomplete", hasErrors(report));
        }
        List<Object> denies = p.get("denies") instanceof List ? (List<Object>) p.get("denies") : new ArrayList<Object>();
        Map<String, Object> out = obj("predicates", p.get("predicates"), "denies", denies);
        if (p.containsKey("report")) {
            Map<String, Object> report = map(p.get("report"));
            if (report == null || report.get("errors") == null) throw new IllegalArgumentException("compilePolicy: report.errors is required"); // the reference reads report.errors.length
            out.put("report", report);
            out.put("incomplete", lengthPositive(report.get("errors")));
        } else out.put("incomplete", Boolean.FALSE);
        return out;
    }

    /** JavaScript {@code x.length > 0} for a JSON value that is not null. */
    private static boolean lengthPositive(Object x) {
        if (x instanceof List) return !((List<?>) x).isEmpty();
        if (x instanceof String) return !((String) x).isEmpty();
        if (x instanceof Map) { Object n = ((Map<?, ?>) x).get("length"); return n instanceof net.atlasauth.pca.Json.Num && Double.parseDouble(((net.atlasauth.pca.Json.Num) n).raw) > 0; }
        return false;
    }

    private static boolean hasErrors(Map<String, Object> report) {
        return report != null && report.get("errors") instanceof List && !((List<?>) report.get("errors")).isEmpty();
    }

    // ---- the filter -----------------------------------------------------------------------------------------------------

    private static Map<String, Object> decideDocument(String id, List<Object> acls, Map<String, Object> principal, Map<String, Object> compiled) {
        if (Boolean.TRUE.equals(compiled.get("incomplete"))) {
            Object why = compiled.get("incompleteReason");
            return obj("id", id, "allowed", Boolean.FALSE, "reason", why instanceof String ? why : "policy translation incomplete (fail closed)");
        }
        Object pid = principal.get("id");
        if (!nonEmptyString(pid)) return obj("id", id, "allowed", Boolean.FALSE, "reason", "no principal identity (fail closed)");
        if (acls.isEmpty()) return obj("id", id, "allowed", Boolean.FALSE, "reason", "no decidable ACL metadata (fail closed)");
        String last = "no relation grants access (fail closed)";
        Map<String, Object> pol = obj("predicates", compiled.get("predicates"), "denies", compiled.get("denies"));
        for (Object a : acls) {
            Map<String, Object> acl = map(a);
            Map<String, Object> res;
            try {
                res = PolicyBridge.decide(pol, context(principal, acl));
            } catch (RuntimeException | StackOverflowError e) {
                last = "evaluator error (fail closed)";
                continue;
            }
            if (Boolean.TRUE.equals(res.get("allowed"))) {
                Map<String, Object> d = obj("id", id, "allowed", Boolean.TRUE, "via", acl,
                    "reason", "granted: " + pid + " has " + acl.get("relation") + " on " + acl.get("object"));
                if (res.get("matched") != null) d.put("matched", res.get("matched"));
                return d;
            }
            if (res.get("reason") instanceof String) last = (String) res.get("reason");
        }
        return obj("id", id, "allowed", Boolean.FALSE, "reason", last);
    }

    /** The evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id. */
    private static Map<String, Object> context(Map<String, Object> principal, Map<String, Object> acl) {
        Map<String, Object> subject = new LinkedHashMap<>();
        Object attrs = principal.get("attributes");
        if (attrs instanceof Map) subject.putAll(map(attrs));
        else if (attrs instanceof List) { int i = 0; for (Object v : (List<?>) attrs) subject.put(String.valueOf(i++), v); } // object spread of an array
        else if (attrs instanceof String) { String s = (String) attrs; for (int i = 0; i < s.length(); i++) subject.put(String.valueOf(i), String.valueOf(s.charAt(i))); }
        subject.put("id", principal.get("id"));
        Map<String, Object> ctx = obj("action", obj("verb", acl.get("relation"), "resource", acl.get("object")), "subject", subject);
        if (principal.containsKey("env")) ctx.put("env", principal.get("env"));
        return ctx;
    }

    /**
     * The generic filter. {@code id} and {@code acls} read a candidate's id (null or empty: positional {@code doc#i}) and its ACL
     * entries (anything that is not a list or entry yields none); either throwing marks the document unreadable and drops it.
     */
    public static <D> Result<D> filter(Object principalInput, List<D> candidates, Object policy,
                                       BiFunction<D, Integer, Object> id, java.util.function.Function<D, Object> acls) {
        Map<String, Object> principal = toPrincipal(principalInput);
        if (principal == null) principal = obj("id", "");
        Map<String, Object> compiled = compilePolicy(policy);
        List<D> list = candidates != null ? candidates : new ArrayList<D>();
        List<D> documents = new ArrayList<>();
        List<Object> decisions = new ArrayList<>(), allowedIds = new ArrayList<>(), droppedIds = new ArrayList<>(), allowedIndexes = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int i = 0; i < list.size(); i++) {
            D doc = list.get(i);
            Object rawId;
            List<Object> docAcls;
            try {
                rawId = id.apply(doc, i);
                docAcls = aclArray(acls.apply(doc));
            } catch (RuntimeException e) {
                String fid = "doc#" + i; // metadata that cannot even be read is unknown: fail closed
                decisions.add(obj("id", fid, "allowed", Boolean.FALSE, "reason", "unreadable document metadata (fail closed)"));
                droppedIds.add(fid);
                continue;
            }
            String docId = nonEmptyString(rawId) ? (String) rawId : "doc#" + i;
            if (seen.contains(docId)) docId = docId + "#dup" + i; // two candidates with one id must stay distinguishable
            seen.add(docId);
            Map<String, Object> d = decideDocument(docId, docAcls, principal, compiled);
            decisions.add(d);
            if (Boolean.TRUE.equals(d.get("allowed"))) {
                documents.add(doc);
                allowedIds.add(docId);
                allowedIndexes.add((long) i);
            } else droppedIds.add(docId);
        }
        Object pid = principal.get("id");
        Map<String, Object> base = obj("principal", pid instanceof String ? pid : "", "considered", (long) list.size(), "allowedIds", allowedIds,
            "allowedIndexes", allowedIndexes, "droppedIds", droppedIds, "policyIncomplete", Boolean.TRUE.equals(compiled.get("incomplete")));
        Map<String, Object> hashed = obj("v", 1L, "kind", "pca-rag/filter");
        hashed.putAll(base);
        Map<String, Object> decision = new LinkedHashMap<>(base);
        decision.put("decisions", decisions);
        decision.put("digest", Pca.hashCanonical(hashed));
        if (compiled.get("report") != null) decision.put("report", compiled.get("report"));
        return new Result<>(documents, decision);
    }

    /** Filter JSON documents ({@code {id, acl?, tags?}} maps) with the default readers. A null document is unreadable (dropped). */
    public static Result<Object> filterDocuments(Object principal, List<Object> candidates, Object policy) {
        return filter(principal, candidates, policy,
            (d, i) -> ((Map<?, ?>) nn(d)).get("id") ,
            d -> aclsFromMetadata(((Map<?, ?>) nn(d)).get("acl"), ((Map<?, ?>) nn(d)).get("tags")));
    }

    private static Object nn(Object d) {
        if (d == null) throw new IllegalArgumentException("null document");
        return d instanceof Map ? d : new LinkedHashMap<Object, Object>();
    }

    /** A generic retriever: candidate documents for a query ({@code k} null = the retriever's own default). */
    @FunctionalInterface
    public interface Retriever<D> {
        List<D> retrieve(String query, Integer k) throws Exception;
    }

    /** A retriever whose every result set was filtered to what the principal may see; {@link #lastDecision} is the audit record of the last call. */
    public static final class FilteredRetriever<D> {
        private final Retriever<D> inner;
        private final Object principal;
        private final Map<String, Object> compiled;
        private final BiFunction<D, Integer, Object> id;
        private final java.util.function.Function<D, Object> acls;
        private final net.atlasauth.pca.ArgProvenance.Recorder recorder;
        private volatile Map<String, Object> last;

        FilteredRetriever(Retriever<D> inner, Object principal, Map<String, Object> compiled, BiFunction<D, Integer, Object> id,
                          java.util.function.Function<D, Object> acls, net.atlasauth.pca.ArgProvenance.Recorder recorder) {
            this.inner = inner; this.principal = principal; this.compiled = compiled; this.id = id; this.acls = acls; this.recorder = recorder;
        }

        /** Retrieve, then keep only what the principal may see BEFORE it reaches the model; admitted documents are recorded as untrusted retrieval content. */
        public List<D> retrieve(String query, Integer k) throws Exception {
            List<D> docs = inner.retrieve(query, k);
            Result<D> res = filter(principal, docs == null ? new ArrayList<D>() : docs, compiled, id, acls);
            last = res.decision;
            if (recorder != null) {
                for (int i = 0; i < res.documents.size(); i++) {
                    D doc = res.documents.get(i);
                    String src;
                    try {
                        Object s = id.apply(doc, i);
                        src = s instanceof String ? (String) s : s == null ? "doc#" + i : String.valueOf(s);
                    } catch (RuntimeException e) {
                        src = "doc#" + i;
                    }
                    recorder.retrieval(src, doc);
                }
            }
            return res.documents;
        }

        /** The decision record of the last {@link #retrieve}, or null before the first. */
        public Map<String, Object> lastDecision() { return last; }
    }

    /**
     * Wrap a retriever so every result set is filtered to what {@code principal} may see before it reaches the model. The policy is compiled
     * once. {@code id} / {@code acls} read a document's id and ACL entries (as in {@link #filter}); {@code recorder} (nullable) is the agent
     * session's provenance recorder.
     */
    public static <D> FilteredRetriever<D> withPcaFilter(Retriever<D> retriever, Object principal, Object policy, BiFunction<D, Integer, Object> id,
                                                         java.util.function.Function<D, Object> acls, net.atlasauth.pca.ArgProvenance.Recorder recorder) {
        return new FilteredRetriever<>(retriever, principal, compilePolicy(policy), id, acls, recorder);
    }

    /** {@link #withPcaFilter} over JSON documents ({@code {id, acl?, tags?}} maps) with the default readers. */
    public static FilteredRetriever<Object> withPcaFilter(Retriever<Object> retriever, Object principal, Object policy) {
        return withPcaFilter(retriever, principal, policy, (d, i) -> ((Map<?, ?>) nn(d)).get("id"),
            d -> aclsFromMetadata(((Map<?, ?>) nn(d)).get("acl"), ((Map<?, ?>) nn(d)).get("tags")), null);
    }
}
