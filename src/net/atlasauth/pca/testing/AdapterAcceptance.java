package net.atlasauth.pca.testing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.StateStore;

/**
 * Shared acceptance matrix for resource-server adapters (the servlet filter, an interceptor, your own): every adapter runs the SAME
 * scenarios through its own request / response plumbing with the {@code operation} option (the {@code authorize} pipeline) and must produce
 * {@link #EXPECTED} exactly.
 *
 * <p>The routes: {@code POST /payments} executes {@code payments.send}, {@code POST /refunds} executes {@code payments.refund}, both on
 * resource {@code payments} with the JSON body as params. The grant permits both verbs up to $100 per call; the operation mapping reads the
 * request's method and URL, so the adapter must pass them through.
 *
 * <p>Scenarios (each on a fresh adapter unless noted): {@code over_limit_predicate} (a validly signed $400 payment under a
 * {@code where amount <= 100} grant), {@code over_limit_max_spend} (the same under a {@code max_spend} caveat), {@code body_differs} (a proof
 * signed for $50, the body says $400), {@code other_operation} (a proof for {@code payments.send} presented to {@code POST /refunds}),
 * {@code escalate_unanswered} (a payment the grant's {@code tighten} escalates, no principal answer: refused, never allowed),
 * {@code missing_revocation} / {@code missing_store} (no revocation check / no state store), then {@code valid_first} and
 * {@code replay_second} (same adapter: a $50 payment runs once, the same request again is refused). Every refusal must happen before the
 * handler runs; an allowed call must carry the bound operation.
 */
public final class AdapterAcceptance {
    private AdapterAcceptance() {}

    public static final String AUDIENCE = TestingKit.ADAPTER_ACCEPTANCE_AUDIENCE;

    /** One request as the adapter's framework would receive it. */
    public static final class Request {
        public final String method = "POST";
        /** Path only ({@code /payments}); adapters that need an absolute URL prefix an origin. */
        public final String path;
        public final Map<String, String> headers;
        public final Map<String, Object> body;

        Request(String path, Map<String, String> headers, Map<String, Object> body) {
            this.path = path;
            this.headers = Collections.unmodifiableMap(headers);
            this.body = body;
        }
    }

    /** What the harness observed for one request. */
    public static final class Observation {
        public final int status;
        public final boolean handlerRan;
        /** The authorization the adapter attached for the handler (allowed calls only), or null. */
        public final Authorize.AuthorizeResult authorization;

        public Observation(int status, boolean handlerRan, Authorize.AuthorizeResult authorization) {
            this.status = status;
            this.handlerRan = handlerRan;
            this.authorization = authorization;
        }
    }

    /** One row of the matrix: status, whether the handler ran, and whether an attached operation matches what ran. */
    public static final class Outcome {
        public final int status;
        public final boolean handlerRan;
        public final boolean bound;

        public Outcome(int status, boolean handlerRan, boolean bound) { this.status = status; this.handlerRan = handlerRan; this.bound = bound; }

        @Override public boolean equals(Object o) {
            return o instanceof Outcome && ((Outcome) o).status == status && ((Outcome) o).handlerRan == handlerRan && ((Outcome) o).bound == bound;
        }

        @Override public int hashCode() { return Objects.hash(status, handlerRan, bound); }

        @Override public String toString() { return "{status=" + status + ", handlerRan=" + handlerRan + ", bound=" + bound + "}"; }
    }

    /**
     * The options an adapter must pass to the authorize pipeline UNCHANGED: audience, grant resolver, replay / budget state store,
     * revocation check (a null store or check is the "missing" scenario: the pipeline must refuse), single-step plan mode, server-side
     * risk and the pinned provenance mediator. {@link #options()} builds the guard options; {@link #operation} maps a request to the operation.
     */
    public static final class Setup {
        public final String audience = AUDIENCE;
        public final Function<String, Map<String, Object>> resolveGrant;
        public final StateStore stateStore;
        public final Authorize.RevocationCheck isRevoked;

        Setup(Function<String, Map<String, Object>> resolveGrant, StateStore stateStore, Authorize.RevocationCheck isRevoked) {
            this.resolveGrant = resolveGrant;
            this.stateStore = stateStore;
            this.isRevoked = isRevoked;
        }

        /** "Spend = risk": a call is priced at amount / 100 of the blast radius. */
        private static Map<String, Object> risk(Authorize.Operation o) {
            double amount = 1;
            Object a = o == null || o.params == null ? null : o.params.get("amount");
            if (a instanceof Number) amount = ((Number) a).doubleValue();
            else if (a instanceof Json.Num) amount = Double.parseDouble(((Json.Num) a).raw);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("blastRadius", Math.min(1, amount / 100));
            m.put("semanticDistance", 0L);
            m.put("reversibility", 0L);
            m.put("taint", 0L);
            m.put("confidence", 1L);
            return m;
        }

        public Authorize.Options options() {
            return new Authorize.Options(stateStore, isRevoked, Authorize.SINGLE_STEP, null, null)
                .withRisk((op, grant, pcactn) -> risk(op))
                .withProvenance(new ArgProvenance.Options().mediators(List.of(PIN)));
        }

        /** The server's mapping from request to operation: route table on method + path, the JSON body as params; null for anything else. */
        public Authorize.Operation operation(String method, String path, Object body) { return acceptanceOperation(method, path, body); }
    }

    /** The harness the adapter provides: build the adapter ONCE from the setup, return a function that sends one request through it. */
    @FunctionalInterface
    public interface Harness {
        Function<Request, Observation> build(Setup setup);
    }

    private static Map<String, Outcome> expected() {
        Map<String, Outcome> m = new LinkedHashMap<>();
        for (String k : new String[] {"over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store"})
            m.put(k, new Outcome(403, false, false));
        m.put("valid_first", new Outcome(200, true, true));
        m.put("replay_second", new Outcome(403, false, false));
        return Collections.unmodifiableMap(m);
    }

    public static final Map<String, Outcome> EXPECTED = expected();

    /** The route mapping: {@code {verb, resource, params}} for {@code POST /payments} and {@code POST /refunds} with an object body, else null. */
    public static Authorize.Operation acceptanceOperation(String method, String path, Object body) {
        String key = (method == null ? "" : method.toUpperCase(java.util.Locale.ROOT)) + " " + (path == null ? "" : path);
        String verb;
        if (key.equals("POST /payments")) verb = "payments.send";
        else if (key.equals("POST /refunds")) verb = "payments.refund";
        else return null;
        if (!(body instanceof Map)) return null;
        @SuppressWarnings("unchecked") Map<String, Object> params = (Map<String, Object>) body;
        return new Authorize.Operation(verb, "payments", params);
    }

    // provenance by default: the agent presents a principal-direct bundle from a recorder the server pins (the matrix is about limits,
    // binding, replay and configuration, not prompt injection), sent in the PCA-Provenance header like a real agent's
    private static final Keys.SuiteKey PROV_KEY;
    static {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 3);
        PROV_KEY = Keys.ed25519(Keys.edFromSeed(seed));
    }

    private static ArgProvenance.Recorder recorder() { return new ArgProvenance.Recorder("adapter-acceptance", "k1", PROV_KEY, null, null); }

    private static final Map<String, Object> PIN = recorder().pin();

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** A grant, its holder and a request factory; {@link #setup} builds fresh options over it. */
    private static final class Fixture {
        final Map<String, Object> grant;
        final Keys.SuiteKey holder;
        long counter;

        Fixture(String limit) {
            Keys.SuiteKey principal = Keys.ed25519(Keys.edGenerate());
            holder = Keys.ed25519(Keys.edGenerate());
            List<Object> verbs = new ArrayList<>(List.of("payments.send", "payments.refund"));
            List<Object> where = new ArrayList<>();
            if (limit.equals("predicate") || limit.equals("escalate")) where.add(obj("field", "action.params.amount", "op", "lte", "value", 100L));
            Map<String, Object> envelope = obj(
                "predicates", new ArrayList<Object>(List.of(obj("verb", verbs, "resource", "payments", "where", where))),
                "caveats", new ArrayList<Object>(),
                "agent_binding", obj());
            // `escalate`: a payment over 50 asks the principal (decision escalate); with no answer it is refused
            if (limit.equals("escalate"))
                envelope.put("tighten", new ArrayList<Object>(List.of(obj("id", "big_payment", "when", obj("field", "action.params.amount", "op", "gt", "value", 50L), "signal", "escalate"))));
            // "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
            envelope.put("risk_policy", obj("weights", obj("alpha", 0L, "beta", 0L, "gamma", 1L, "delta", 0L, "epsilon", 0L, "zeta", 0L),
                "theta1", 1L, "theta2", 1L, "kappa", 100L, "lambda", 0L, "rho", new Json.Num("0.5"), "bMax", 1_000_000L));
            Map<String, Object> minted = Issue.mintGrant(principal, holder.ed.id(), null, envelope, "pay invoices", null).grant;
            if (limit.equals("max_spend")) {
                // max_spend as a ROOT caveat (outside the envelope): enforced like a delegated one
                @SuppressWarnings("unchecked") List<Object> cv = new ArrayList<>((List<Object>) minted.get("caveats"));
                cv.add(obj("type", "max_spend", "usd", 100L));
                grant = Issue.mintRoot(principal, holder.ed.id(), null, cv);
            } else {
                grant = minted;
            }
        }

        Request request(String verb, long signedAmount, String sentPath, long sentAmount) {
            Map<String, Object> params = obj("payee", "acme", "amount", signedAmount);
            Map<String, Object> node = obj("id", "n1", "verb", verb, "resource", "payments", "params_digest", Pca.paramsDigest(params), "reversibility_class", "irreversible");
            Issue.ActSpec spec = new Issue.ActSpec();
            spec.grant = grant;
            spec.chain = new ArrayList<Object>(List.of(grant));
            spec.plan = Issue.commitPlan(new ArrayList<>(List.of(node)));
            spec.nodeId = "n1";
            spec.params = params;
            spec.counter = ++counter;
            spec.signer = holder;
            spec.aud = AUDIENCE;
            Map<String, Object> pcactn = Issue.buildPCActn(spec);
            Map<String, Object> provenance = ArgProvenance.principalDirect(recorder(), new Authorize.Operation(verb, "payments", params));
            Map<String, String> headers = new LinkedHashMap<>(Issue.headers(pcactn, null, null, null, null, provenance));
            headers.put("content-type", "application/json");
            return new Request(sentPath, headers, obj("payee", "acme", "amount", sentAmount));
        }

        Setup setup(boolean withRevocation, boolean withStore) {
            return new Setup(ref -> ref.equals(grant.get("id")) ? grant : null, withStore ? new MemoryStateStore() : null, withRevocation ? (p, g) -> Boolean.FALSE : null);
        }
    }

    /** Run the matrix through {@code harness}; compare the result with {@link #EXPECTED} (map equality). */
    public static Map<String, Outcome> run(Harness harness) {
        Map<String, Outcome> out = new LinkedHashMap<>();
        class Runner {
            Outcome settle(Request req, Observation o) {
                Authorize.Operation ran = acceptanceOperation(req.method, req.path, req.body);
                boolean bound = o.authorization != null && ran != null && Authorize.isAuthorizedFor(o.authorization, ran);
                return new Outcome(o.status, o.handlerRan, bound);
            }

            void once(String name, Fixture f, Request req, boolean withRevocation, boolean withStore) {
                out.put(name, settle(req, harness.build(f.setup(withRevocation, withStore)).apply(req)));
            }
        }
        Runner r = new Runner();
        Fixture pred = new Fixture("predicate");
        r.once("over_limit_predicate", pred, pred.request("payments.send", 400, "/payments", 400), true, true);
        Fixture spend = new Fixture("max_spend");
        r.once("over_limit_max_spend", spend, spend.request("payments.send", 400, "/payments", 400), true, true);
        r.once("body_differs", pred, pred.request("payments.send", 50, "/payments", 400), true, true);
        r.once("other_operation", pred, pred.request("payments.send", 50, "/refunds", 50), true, true);
        Fixture esc = new Fixture("escalate");
        r.once("escalate_unanswered", esc, esc.request("payments.send", 70, "/payments", 70), true, true);
        r.once("missing_revocation", pred, pred.request("payments.send", 50, "/payments", 50), false, true);
        r.once("missing_store", pred, pred.request("payments.send", 50, "/payments", 50), true, false);

        Function<Request, Observation> send = harness.build(pred.setup(true, true));
        Request valid = pred.request("payments.send", 50, "/payments", 50);
        out.put("valid_first", r.settle(valid, send.apply(valid)));
        out.put("replay_second", r.settle(valid, send.apply(valid)));
        return out;
    }
}
