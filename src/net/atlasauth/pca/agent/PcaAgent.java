package net.atlasauth.pca.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Ledger;
import net.atlasauth.pca.Pca;

/**
 * The HTTP agent client of an Atlas-style resource server (a port of the reference {@code pca-agent}): commits a plan, builds and sends one signed
 * PCActn per action, follows a step-up and checks the ledger receipt of every allow. {@link #createAgent} builds a client; an {@link AgentClient}
 * is not thread-safe (counters are handed out in order): one client per thread.
 */
public final class PcaAgent {
    private PcaAgent() {}

    /** The HTTP seam: one request in, the status and the (possibly non-JSON) body out. Tests inject a double; the default is a plain HttpURLConnection. */
    @FunctionalInterface
    public interface FetchLike {
        FetchResponse fetch(String method, String url, Map<String, String> headers, String body) throws IOException;
    }

    public static final class FetchResponse {
        public final int status;
        public final String body;
        public FetchResponse(int status, String body) { this.status = status; this.body = body; }
    }

    /** The trust budget a verdict reports: {@code B}, {@code tau} and the time it was {@code asOf}. */
    public static final class TrustBudget {
        public final double b, tau, asOf;
        public TrustBudget(double b, double tau, double asOf) { this.b = b; this.tau = tau; this.asOf = asOf; }
    }

    /** The server's reply to an action; {@code raw} is the whole parsed verdict object (allow, checks, reason, budget, ...). */
    public static final class Verdict {
        public final boolean allow;
        public final Map<String, Object> raw;
        public final TrustBudget budget;
        public Verdict(boolean allow, Map<String, Object> raw, TrustBudget budget) { this.allow = allow; this.raw = raw; this.budget = budget; }
    }

    /** A ledger receipt. {@code salt}, when the server discloses it, lets the client check the entry commits to THIS action. */
    public static final class Receipt {
        public final Map<String, Object> raw;
        public Receipt(Map<String, Object> raw) { this.raw = raw; }
        public String root() { return raw.get("root") instanceof String ? (String) raw.get("root") : null; }
        public String commit() { return raw.get("commit") instanceof String ? (String) raw.get("commit") : null; }
        public String salt() { return raw.get("salt") instanceof String ? (String) raw.get("salt") : null; }
        public Object inclusionProof() { return raw.get("inclusion_proof"); }
    }

    /** The decided step-up: {@code status} is {@code approved}, {@code denied}, {@code expired} or {@code timeout}; {@code raw} carries the server's answer. */
    public static final class StepUpOutcome {
        public final String status;
        public final Map<String, Object> raw;
        public final Integer httpStatus;

        StepUpOutcome(String status, Map<String, Object> raw, Integer httpStatus) { this.status = status; this.raw = raw; this.httpStatus = httpStatus; }

        /** The PCActn an approved step-up carries, or null. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> pcactn() { return raw.get("pcactn") instanceof Map ? (Map<String, Object>) raw.get("pcactn") : null; }
    }

    /** The outcome of {@link AgentClient#act}: exactly one of the four subclasses ({@link #status()} names it). Never an exception for a server-side failure. */
    public abstract static class ActResult {
        public abstract String status();

        public static final class Allowed extends ActResult {
            public final Verdict verdict;
            public final Receipt receipt;
            public final Map<String, Object> pcactn;
            Allowed(Verdict verdict, Receipt receipt, Map<String, Object> pcactn) { this.verdict = verdict; this.receipt = receipt; this.pcactn = pcactn; }
            @Override public String status() { return "allowed"; }
        }

        public static final class Denied extends ActResult {
            public final Verdict verdict;
            public final int httpStatus;
            public final Map<String, Object> pcactn;
            Denied(Verdict verdict, int httpStatus, Map<String, Object> pcactn) { this.verdict = verdict; this.httpStatus = httpStatus; this.pcactn = pcactn; }
            @Override public String status() { return "denied"; }
        }

        public static final class StepUp extends ActResult {
            public final String stepupId;
            public final double requiredT;
            public final Map<String, Object> pcactn;
            StepUp(String stepupId, double requiredT, Map<String, Object> pcactn) { this.stepupId = stepupId; this.requiredT = requiredT; this.pcactn = pcactn; }
            @Override public String status() { return "step_up"; }
        }

        public static final class Error extends ActResult {
            public final PcaAgentError error;
            Error(PcaAgentError error) { this.error = error; }
            @Override public String status() { return "error"; }
        }
    }

    /** Optional signed slots of wire v2 (all signed into the PCActn when present; absent = current behaviour). */
    public static final class ActSlots {
        /** Uncertainty attestation in [0,1]; monotone (the verifier takes max with its own risk). */
        public Object caution;
        public String rationaleCommitment;
        public Map<String, Object> progressStep;
        public Object prohibitionEvidence;
        /** The b64u(32) digest of the tool signature you will dispatch to. */
        public String toolBinding;
        /** Overrides the generated nonce. */
        public String nonce;
    }

    public static final class CreateAgentOptions {
        public final Map<String, Object> grant;
        /** Capability chain starting at the grant; null: {@code [grant]}. */
        public List<Object> chain;
        /** The leaf holder's signing key. Null only for a sub-agent client you do not drive. */
        public Keys.SuiteKey agentKey;
        /** b64u public key of the agent (informational). */
        public String agentPublic;
        public final String rsBaseUrl;
        /** REQUIRED. The audience the PCActns are FOR (wire v2 {@code aud}): the Atlas instance id, or the id the resource server passes as its audience. */
        public final String audience;
        /** Lifetime stamped into each PCActn ({@code exp = iat + ttlMs}); null = the issuer default (20 min). */
        public Long ttlMs;
        public LongSupplier now = System::currentTimeMillis;
        /** Stamp a fresh random per-action {@code nonce}. */
        public boolean nonce = true;
        public FetchLike fetch;
        /** Verify the ledger inclusion proof of every receipt before reporting allowed (an allow whose receipt does not verify is an error). */
        public boolean verifyReceipts = true;
        /** The last counter used; the first act() uses counter + 1. */
        public long counter;
        public TrustBudget budget;
        /** The session's provenance recorder: every act appends the action receipt and sends the bundle as {@code pca_provenance}. */
        public ArgProvenance.Recorder provenance;

        public CreateAgentOptions(Map<String, Object> grant, String rsBaseUrl, String audience) {
            this.grant = grant;
            this.rsBaseUrl = rsBaseUrl;
            this.audience = audience;
        }
    }

    private static final FetchLike DEFAULT_FETCH = (method, url, headers, body) -> {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        try {
            c.setRequestMethod(method);
            c.setInstanceFollowRedirects(false); // a redirect is a non-2xx answer, never followed to another host
            c.setConnectTimeout(15_000);
            c.setReadTimeout(60_000);
            for (Map.Entry<String, String> e : headers.entrySet()) c.setRequestProperty(e.getKey(), e.getValue());
            if (body != null) {
                c.setDoOutput(true);
                try (OutputStream out = c.getOutputStream()) { out.write(body.getBytes(StandardCharsets.UTF_8)); }
            }
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            if (in != null) try (InputStream i = in) { i.transferTo(buf); }
            return new FetchResponse(status, new String(buf.toByteArray(), StandardCharsets.UTF_8));
        } finally {
            c.disconnect();
        }
    };

    /** Build the HTTP agent client. Throws {@link PcaAgentError} ({@code build_failed}) when the audience or the base URL is unusable. */
    public static AgentClient createAgent(CreateAgentOptions opts) {
        if (opts.audience == null || opts.audience.isEmpty()) {
            throw new PcaAgentError("build_failed", "createAgent: `audience` is required (the resource-server / Atlas instance id PCActns are for)");
        }
        boolean ok;
        try {
            URI u = new URI(opts.rsBaseUrl);
            ok = u.isAbsolute() && ("https".equals(u.getScheme()) || "http".equals(u.getScheme())) && u.getHost() != null && !u.getHost().isEmpty();
        } catch (URISyntaxException | NullPointerException e) {
            ok = false;
        }
        if (!ok) throw new PcaAgentError("build_failed", "createAgent: `rsBaseUrl` must be an absolute http(s) URL");
        return new AgentClient(opts, opts.rsBaseUrl.replaceAll("/+$", ""), opts.fetch != null ? opts.fetch : DEFAULT_FETCH);
    }

    /** The agent client of one grant (or sub-agent chain). */
    public static final class AgentClient {
        private final CreateAgentOptions opts;
        private final String base;
        private final FetchLike doFetch;
        public final Map<String, Object> grant;
        public final List<Object> chain;
        public final String agentPublic;
        private long counter;
        private TrustBudget budget;
        private String planRoot;
        private List<Map<String, Object>> plan;

        AgentClient(CreateAgentOptions opts, String base, FetchLike doFetch) {
            this.opts = opts;
            this.base = base;
            this.doFetch = doFetch;
            this.grant = opts.grant;
            List<Object> c = new ArrayList<>();
            if (opts.chain != null) c.addAll(opts.chain); else c.add(opts.grant);
            this.chain = Collections.unmodifiableList(c);
            this.agentPublic = opts.agentPublic;
            this.counter = opts.counter;
            this.budget = opts.budget;
        }

        /** The last counter used. */
        public long counter() { return counter; }

        /** The latest trust budget a verdict reported (or the one given at creation), or null. */
        public TrustBudget budget() { return budget; }

        /** The committed plan root, or null before {@link #commitPlan}. */
        public String planRoot() { return planRoot; }

        private static final class Reply {
            final int status;
            final Map<String, Object> json;
            Reply(int status, Map<String, Object> json) { this.status = status; this.json = json; }
        }

        @SuppressWarnings("unchecked")
        private Reply call(String method, String path, Object body) throws IOException {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("content-type", "application/json");
            headers.put("accept", "application/json");
            FetchResponse res = doFetch.fetch(method, base + path, headers, body == null ? null : Json.stringify(body));
            Object parsed;
            try {
                parsed = Json.parseLenient(res.body);
            } catch (RuntimeException e) {
                parsed = null; // a non-JSON body is an empty object
            }
            return new Reply(res.status, parsed instanceof Map ? (Map<String, Object>) parsed : new LinkedHashMap<String, Object>());
        }

        /** Commit the plan locally and with the server; the server must echo the same root. Returns the root. */
        public String commitPlan(List<Map<String, Object>> nodes) {
            String local = Issue.commitPlan(nodes).root;
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("grant_ref", grant.get("id"));
            body.put("nodes", nodes);
            Reply res;
            try {
                res = call("POST", "/v1/pca/plans", body);
            } catch (IOException e) {
                throw new PcaAgentError("network", e.getMessage() != null ? e.getMessage() : "plan commit failed");
            }
            if (res.status < 200 || res.status >= 300) throw new PcaAgentError("bad_response", "plan commit failed (" + res.status + ")", res.status);
            // The server must echo the root it committed: a missing root cannot be told apart from a server that stored another plan.
            Object remote = res.json.get("plan_root");
            if (!(remote instanceof String) || !remote.equals(local)) {
                throw new PcaAgentError("bad_response", "server plan_root is missing or differs from the locally computed root", res.status);
            }
            List<Map<String, Object>> copy = new ArrayList<>();
            for (Map<String, Object> n : nodes) copy.add(new LinkedHashMap<>(n));
            plan = copy;
            planRoot = local;
            return local;
        }

        private static ActResult.Error err(String code, String msg, Integer status) { return new ActResult.Error(new PcaAgentError(code, msg, status)); }

        private static Double num(Object v) {
            if (v instanceof Json.Num) {
                try {
                    double d = Double.parseDouble(((Json.Num) v).raw);
                    return Double.isFinite(d) ? d : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            if (v instanceof Number) {
                double d = ((Number) v).doubleValue();
                return Double.isFinite(d) ? d : null;
            }
            return null;
        }

        private static TrustBudget budgetOf(Object v) {
            if (!(v instanceof Map)) return null;
            Map<?, ?> m = (Map<?, ?>) v;
            Double b = num(m.get("B")), t = num(m.get("tau")), a = num(m.get("asOf"));
            return b == null || t == null || a == null ? null : new TrustBudget(b, t, a);
        }

        private static boolean receiptBinds(Receipt r, Map<String, Object> pcactn) {
            try {
                String salt = r.salt();
                if (salt == null) return false;
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("salt", salt);
                entry.put("pcactn_digest", Pca.hashCanonical(pcactn));
                return Pca.hashCanonical(entry).equals(r.commit());
            } catch (RuntimeException e) {
                return false;
            }
        }

        private static Object firstPresent(Object... xs) {
            for (Object x : xs) if (x != null) return x;
            return null;
        }

        /** Act on {@code nodeId} of the committed plan. Never throws for a server-side failure: every outcome is an {@link ActResult}. */
        @SuppressWarnings("unchecked")
        public ActResult act(String nodeId, Map<String, Object> params, ActSlots slots) {
            if (plan == null) return err("no_plan", "commitPlan() first", null);
            Keys.SuiteKey key = opts.agentKey;
            if (key == null) return err("no_secret", "no agentKey for this client", null);
            Map<String, Object> node = null;
            for (Map<String, Object> n : plan) if (nodeId.equals(n.get("id"))) { node = n; break; }
            if (node == null) return err("unknown_node", "unknown plan node " + nodeId, null);
            long next = counter + 1;
            Map<String, Object> pcactn;
            try {
                Issue.ActSpec s = new Issue.ActSpec();
                s.grant = grant;
                s.chain = chain;
                s.plan = Issue.commitPlan(plan);
                s.nodeId = nodeId;
                s.counter = next;
                s.signer = key;
                s.aud = opts.audience;
                s.params = params;
                s.iat = opts.now.getAsLong();
                s.ttlMs = opts.ttlMs;
                s.nonce = slots != null && slots.nonce != null ? slots.nonce : opts.nonce ? Issue.randomB64u(16) : null;
                if (slots != null) {
                    s.caution = slots.caution;
                    s.rationaleCommitment = slots.rationaleCommitment;
                    s.progressStep = slots.progressStep;
                    s.prohibitionEvidence = slots.prohibitionEvidence;
                    s.toolBinding = slots.toolBinding;
                }
                pcactn = Issue.buildPCActn(s);
            } catch (RuntimeException e) {
                return err("build_failed", e.getMessage() != null ? e.getMessage() : "build failed", null);
            }
            counter = next; // monotonic: never reuse a counter, even if the call fails
            Map<String, Object> provenance;
            try {
                provenance = opts.provenance == null ? null
                    : opts.provenance.forAction(new Authorize.Operation((String) node.get("verb"), (String) node.get("resource"), params != null ? params : new LinkedHashMap<String, Object>()));
            } catch (RuntimeException e) {
                return err("build_failed", e.getMessage() != null ? e.getMessage() : "provenance failed", null);
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("pcactn", pcactn);
            if (provenance != null) body.put("pca_provenance", provenance);
            Reply res;
            try {
                res = call("POST", "/v1/pca/actions", body);
            } catch (IOException e) {
                return err("network", e.getMessage() != null ? e.getMessage() : "network error", null);
            }
            Map<String, Object> j = res.json;
            if (res.status == 202 || "step_up_required".equals(j.get("status")) || Boolean.TRUE.equals(j.get("step_up_required"))) {
                Object id = firstPresent(j.get("stepup_id"), j.get("stepupId"), j.get("id"));
                Double t = num(firstPresent(j.get("required_t"), j.get("requiredT"), j.get("t")));
                if (!(id instanceof String)) return err("bad_response", "step-up response missing stepup_id", res.status);
                return new ActResult.StepUp((String) id, t != null ? t : 2.0, pcactn);
            }
            Object rawVerdict = j.get("verdict");
            Map<String, Object> vmap;
            if (rawVerdict instanceof Map) vmap = (Map<String, Object>) rawVerdict;
            else {
                vmap = new LinkedHashMap<>();
                vmap.put("allow", Boolean.TRUE.equals(j.get("allow")));
            }
            // Allow only on an explicit boolean true from every place the server states it: a truthy string or a contradiction is a deny.
            boolean allowed = res.status >= 200 && res.status < 300 && Boolean.TRUE.equals(vmap.get("allow")) && (!j.containsKey("allow") || Boolean.TRUE.equals(j.get("allow")));
            TrustBudget b = budgetOf(vmap.get("budget"));
            if (b != null) budget = b;
            Verdict verdict = new Verdict(Boolean.TRUE.equals(vmap.get("allow")), vmap, b);
            if (allowed) {
                if (!(j.get("receipt") instanceof Map)) return err("bad_response", "allow without receipt", res.status);
                Receipt receipt = new Receipt((Map<String, Object>) j.get("receipt"));
                if (opts.verifyReceipts) {
                    if (!verifyReceipt(receipt)) return err("bad_response", "allow receipt inclusion proof does not verify", res.status);
                    if (receipt.salt() != null && !receiptBinds(receipt, pcactn)) return err("bad_response", "allow receipt does not commit to this action", res.status);
                }
                return new ActResult.Allowed(verdict, receipt, pcactn);
            }
            return new ActResult.Denied(verdict, res.status, pcactn);
        }

        public ActResult act(String nodeId) { return act(nodeId, null, null); }

        public ActResult act(String nodeId, Map<String, Object> params) { return act(nodeId, params, null); }

        /** {@code encodeURIComponent}: URLEncoder, then the characters JavaScript leaves alone. */
        private static String encodeComponent(String s) {
            return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(").replace("%29", ")").replace("%7E", "~");
        }

        /** Poll a step-up until it is decided or {@code timeoutMs} passes. Only a 2xx answer can approve. */
        public StepUpOutcome awaitStepUp(String stepupId, long pollMs, long timeoutMs) {
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (true) {
                Reply res;
                try {
                    // Long poll (the server answers as soon as the step-up is decided, at most 25 s); servers without it ignore `wait`.
                    long wait = Math.min(25L, Math.floorDiv(deadline - System.currentTimeMillis(), 1000L));
                    res = call("GET", "/v1/pca/stepups/" + encodeComponent(stepupId) + (wait > 0 ? "?wait=" + wait : ""), null);
                } catch (IOException e) {
                    throw new PcaAgentError("network", e.getMessage() != null ? e.getMessage() : "network error");
                }
                Object s = res.json.get("status");
                // Only a 2xx answer can approve; a non-2xx answer that says "approved" is not an approval.
                boolean ok = res.status >= 200 && res.status < 300;
                if (ok && ("approved".equals(s) || "denied".equals(s) || "expired".equals(s))) return new StepUpOutcome((String) s, res.json, null);
                // 4xx other than 429 is final (unknown or foreign step-up): stop polling, never approve.
                if (res.status >= 400 && res.status < 500 && res.status != 429) return new StepUpOutcome("denied", new LinkedHashMap<String, Object>(), res.status);
                if (System.currentTimeMillis() + pollMs > deadline) return new StepUpOutcome("timeout", new LinkedHashMap<String, Object>(), null);
                try {
                    Thread.sleep(pollMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new PcaAgentError("network", "interrupted");
                }
            }
        }

        public StepUpOutcome awaitStepUp(String stepupId) { return awaitStepUp(stepupId, 1000L, 5 * 60_000L); }

        /** A sub-agent over the chain extended by one hop to {@code toPublic}; it signs with {@code agentKey} and its counter starts at 0. */
        @SuppressWarnings("unchecked")
        public AgentClient delegate(String toPublic, List<Object> addedCaveats, Keys.SuiteKey agentKey) {
            Keys.SuiteKey own = opts.agentKey;
            if (own == null) throw new PcaAgentError("no_secret", "cannot delegate without agentKey");
            Map<String, Object> child = Issue.delegate((Map<String, Object>) chain.get(chain.size() - 1), toPublic, addedCaveats != null ? addedCaveats : new ArrayList<Object>(), own, null);
            CreateAgentOptions o = new CreateAgentOptions(grant, base, opts.audience);
            List<Object> c = new ArrayList<>(chain);
            c.add(child);
            o.chain = c;
            o.agentKey = agentKey;
            o.agentPublic = toPublic;
            o.ttlMs = opts.ttlMs;
            o.now = opts.now;
            o.nonce = opts.nonce;
            o.fetch = doFetch;
            o.verifyReceipts = opts.verifyReceipts;
            o.counter = 0L;
            o.provenance = opts.provenance; // a sub-agent works in the same context session
            return new AgentClient(o, base, doFetch);
        }

        /** True when the receipt's inclusion proof verifies against its root. */
        public boolean verifyReceipt(Receipt r) {
            String root = r.root(), commit = r.commit();
            if (root == null || commit == null) return false;
            try {
                return Ledger.verifyLedgerInclusion(root, r.inclusionProof(), commit);
            } catch (RuntimeException e) {
                return false;
            }
        }
    }
}
