package net.atlasauth.pca;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * An agent that acts under a grant: it owns the leaf signing key, the capability chain and the monotonic counter, stamps a fresh
 * nonce on every action, and encodes the PCActn the way the native middleware expects ({@code PCA-Action} header, unpadded
 * base64url of the JSON). No TypeScript process is needed.
 *
 * <pre>{@code
 * Keys.SuiteKey me = Keys.ed25519(Keys.edGenerate());
 * Agent agent = Agent.create(me, "ins_123", grant, null);          // chain defaults to [grant]
 * Map<String,Object> pcactn = agent.act("pay", "invoice/7", Issue.obj("amount", 1200L));
 * HttpRequest req = agent.attach(HttpRequest.newBuilder(URI.create(url)), pcactn).POST(...).build();
 * }</pre>
 *
 * <p>Not thread-safe: counters are handed out in order, so use one Agent per thread or synchronize around {@code act}.
 */
public final class Agent {
    public static final String HEADER = "PCA-Action";

    public final Keys.SuiteKey signer;
    public final String aud;
    public final Map<String, Object> grant;
    public final List<Object> chain;
    private long counter;
    private Issue.Plan plan;
    private long ttlMs = Issue.DEFAULT_TTL_MS;
    private LongSupplier clock = System::currentTimeMillis;
    private boolean nonces = true;

    private Agent(Keys.SuiteKey signer, String aud, Map<String, Object> grant, List<Object> chain, long counter) {
        this.signer = signer;
        this.aud = aud;
        this.grant = grant;
        this.chain = chain;
        this.counter = counter;
    }

    /** {@code chain} is the capability chain starting at the grant; null means {@code [grant]}. */
    public static Agent create(Keys.SuiteKey signer, String aud, Map<String, Object> grant, List<Object> chain) {
        if (aud == null || aud.isEmpty()) throw new IllegalArgumentException("Agent: aud (the resource server / instance id) is required");
        List<Object> c = new ArrayList<Object>();
        if (chain != null) c.addAll(chain); else c.add(grant);
        return new Agent(signer, aud, grant, c, 0L);
    }

    public Agent ttlMs(long ms) { this.ttlMs = ms; return this; }
    public Agent clock(LongSupplier c) { this.clock = c; return this; }
    public Agent nonces(boolean on) { this.nonces = on; return this; }
    /** The last counter used; the next action uses {@code counter() + 1}. */
    public long counter() { return counter; }
    public Agent counter(long last) { this.counter = last; return this; }

    /** Commit a plan locally; the returned root is what a server must echo if the plan is registered with it. */
    public Issue.Plan commitPlan(List<Map<String, Object>> nodes) {
        plan = Issue.commitPlan(nodes);
        return plan;
    }

    private Map<String, Object> build(Issue.Plan p, String nodeId, Map<String, Object> params, Map<String, Object> slots) {
        Issue.ActSpec s = new Issue.ActSpec();
        s.grant = grant;
        s.chain = chain;
        s.plan = p;
        s.nodeId = nodeId;
        s.params = params;
        s.counter = counter + 1;
        s.signer = signer;
        s.aud = aud;
        s.iat = clock.getAsLong();
        s.ttlMs = ttlMs;
        if (nonces) s.nonce = Issue.randomB64u(16);
        if (slots != null) {
            if (slots.get("nonce") != null) s.nonce = (String) slots.get("nonce");
            s.caution = slots.get("caution");
            s.rationaleCommitment = (String) slots.get("rationale_commitment");
            s.toolBinding = (String) slots.get("tool_binding");
            s.prohibitionEvidence = slots.get("prohibition_evidence");
            s.progressStep = map(slots.get("progress_step"));
            s.intent = map(slots.get("intent"));
            s.intentSession = map(slots.get("intent_session"));
            s.freshAt = map(slots.get("fresh_at"));
            s.provenance = map(slots.get("provenance"));
            s.attestation = map(slots.get("attestation"));
            s.freshness = map(slots.get("freshness"));
            s.riskClaim = map(slots.get("risk_claim"));
        }
        Map<String, Object> out = Issue.buildPCActn(s);
        counter = s.counter; // monotonic: a counter is never reused, even if the call later fails
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** Act on node {@code nodeId} of the committed plan. {@code slots} carries the optional signed members (caution, intent, fresh_at, ...). */
    public Map<String, Object> actNode(String nodeId, Map<String, Object> params, Map<String, Object> slots) {
        if (plan == null) throw new IllegalStateException("commitPlan() first");
        return build(plan, nodeId, params, slots);
    }

    public Map<String, Object> actNode(String nodeId, Map<String, Object> params) { return actNode(nodeId, params, null); }

    /**
     * Act on one verb and resource with an ad-hoc single-node plan. Use {@link #commitPlan} and {@link #actNode} when the
     * server requires the plan to be registered first.
     */
    public Map<String, Object> act(String verb, String resource, Map<String, Object> params, Map<String, Object> slots) {
        Map<String, Object> node = Issue.obj("id", "n" + (counter + 1), "verb", verb, "resource", resource, "params_digest", Pca.paramsDigest(params));
        List<Map<String, Object>> nodes = new ArrayList<>();
        nodes.add(node);
        return build(Issue.commitPlan(nodes), (String) node.get("id"), params, slots);
    }

    public Map<String, Object> act(String verb, String resource, Map<String, Object> params) { return act(verb, resource, params, null); }

    /**
     * Delegate a narrower authority to a sub-agent. The child hop is signed by this agent; the returned Agent signs with
     * {@code child} (its counter starts at 0) over the extended chain.
     */
    public Agent delegate(Keys.SuiteKey child, List<Object> addedCaveats) {
        if (child.ed == null) throw new IllegalArgumentException("a delegate holder needs an Ed25519 identity");
        Map<String, Object> leaf = Pca.asMap(chain.get(chain.size() - 1));
        Map<String, Object> hop = Issue.delegate(leaf, child.ed.id(), addedCaveats, signer, child.pqPk());
        List<Object> c = new ArrayList<>(chain);
        c.add(hop);
        Agent a = new Agent(child, aud, grant, c, 0L);
        a.ttlMs = ttlMs;
        a.clock = clock;
        a.nonces = nonces;
        return a;
    }

    /** The header value for a PCActn. */
    public static String header(Map<String, Object> pcactn) { return Issue.header(pcactn); }

    /** Add the {@code PCA-Action} header to a request. */
    public static HttpRequest.Builder attach(HttpRequest.Builder b, Map<String, Object> pcactn) { return b.header(HEADER, header(pcactn)); }

    /** Send a request with the PCActn attached. */
    public static HttpResponse<String> send(HttpClient c, HttpRequest.Builder b, Map<String, Object> pcactn) throws java.io.IOException, InterruptedException {
        return c.send(attach(b, pcactn).build(), HttpResponse.BodyHandlers.ofString());
    }

    /** The JSON body {@code {"pcactn": ...}} that the Atlas {@code POST /v1/pca/actions} endpoint takes. */
    public static String actionsBody(Map<String, Object> pcactn) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pcactn", pcactn);
        return Json.canonicalize(m);
    }
}
