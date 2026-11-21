package net.atlasauth.pca.connect;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.connect.Proxy.ProxyFetch;
import net.atlasauth.pca.connect.Proxy.ProxyRequest;
import net.atlasauth.pca.connect.Proxy.ProxyResponse;
import net.atlasauth.pca.connect.Refresh.ProviderConfig;
import net.atlasauth.pca.connect.Refresh.VaultFetch;
import net.atlasauth.pca.connect.VaultError.BearerReleaseDisabledError;
import net.atlasauth.pca.connect.VaultError.ExpiredNoRefreshError;
import net.atlasauth.pca.connect.VaultError.NotAuthorizedError;
import net.atlasauth.pca.connect.VaultError.ProxyFailedError;
import net.atlasauth.pca.connect.VaultError.RequestMismatchError;
import net.atlasauth.pca.connect.VaultError.ScopeExceededError;
import net.atlasauth.pca.connect.VaultError.StoreError;
import net.atlasauth.pca.connect.VaultError.UnconfirmedActionError;
import net.atlasauth.pca.connect.VaultError.UnknownActionError;
import net.atlasauth.pca.connect.VaultError.UnknownConnectionError;
import net.atlasauth.pca.oauth.JsVal;

/**
 * An outbound connection/token vault for PCA agents. It holds an agent's third-party OAuth tokens and releases a FRESH access token only when
 * a verified Proof-Carrying Action proves least-privilege authority over the requested provider + scopes, or (proxy mode) makes the outbound
 * call itself so the agent never holds the credential. PCActns are parsed JSON trees (Json.parse); calls are synchronous.
 */
public final class TokenVault {
    /** The pinned definition of one action: where the scopes a credential may carry come from. */
    public static final class VaultAction {
        /** The verb a PCActn must carry for this action. */
        public String verb;
        /** Digest of the definition this mapping was written for (informational). */
        public String defDigest;
        /** True iff the definition carries a valid signed confirmation. Unconfirmed: nothing is released. */
        public boolean confirmed;
        public String provider;
        /** The minimum scopes the action needs (release is exactly these, and they must be inside the grant and the stored connection). */
        public List<String> scopesMin = new ArrayList<>();
        /** Proxy mode: map the outbound request back to the action's parameters ({@link Proxy#httpExtractor}); null when none. */
        public Function<ProxyRequest, Map<String, Object>> extract;
    }

    @FunctionalInterface public interface Actions { VaultAction resolve(String verb) throws Exception; }

    /** Revocation source: true refuses the action; a throw refuses it too (fail closed). */
    @FunctionalInterface public interface IsRevoked { boolean test(Map<String, Object> pcActn) throws Exception; }

    public static final class Receipts {
        public Keys.EdKey secretKey;
        /** Receives every signed receipt; null = none. A failing sink never fails the call. */
        public Consumer<Map<String, Object>> sink;
    }

    /** Vault options; unset members keep the reference defaults. */
    public static final class Options {
        public ConnectionStore store;
        public Map<String, ProviderConfig> providers = new LinkedHashMap<>();
        public VaultFetch fetch;
        /** Clock, epoch ms. */
        public LongSupplier now = System::currentTimeMillis;
        /** This vault's resource-server id, compared to each PCActn's signed aud. Null accepts any audience. A connection's own audience overrides it. */
        public String audience;
        /** Verifier-side issuer to pq_pk pins (b64u). */
        public Map<String, String> pqPins;
        /** The Merkle plan roots the principal authorized; required unless {@link #insecureSkipPlanRootCheck}. */
        public List<String> authorizedPlanRoots;
        public boolean insecureSkipPlanRootCheck;
        public double expiryLeewayMs = 30_000;
        public String defaultConnectionId = "default";
        public boolean requireActionBinding = true;
        public BiFunction<String, String, String> resourceFor = (provider, connectionId) -> "oauth:" + provider;
        /** The action.verb a PCActn must carry; null skips the verb check. */
        public String useVerb = "use_connection";
        public double defaultTokenLifetimeMs = 300_000;
        /** One-time-use store for presented actions (a captured action cannot be replayed to the vault). */
        public StateStore replay;
        public IsRevoked isRevoked;
        /** Production profile (default on): requires an encrypting store, replay, isRevoked and an audience. */
        public boolean strict = true;
        public Actions actions;
        /** DOCUMENTED INSECURE opt-in: without it getConnectionToken throws bearer_release_disabled. */
        public boolean insecureBearerRelease;
        public ProxyFetch proxyFetch;
        public List<String> proxyHeaders = Proxy.DEFAULT_PROXY_HEADERS;
        public long maxProxyResponseBytes = 4L * 1024 * 1024;
        public Receipts receipts;
    }

    public static final class ConnectionToken {
        public String provider, connectionId, accessToken;
        public List<String> scopes;
        public double expiresAt;
        /** True when the token was just refreshed at the provider. */
        public boolean refreshed;

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("provider", provider);
            m.put("connectionId", connectionId);
            m.put("accessToken", accessToken);
            m.put("scopes", new ArrayList<Object>(scopes));
            m.put("expiresAt", net.atlasauth.pca.revoke.JsVal.numOf(expiresAt));
            m.put("refreshed", refreshed);
            return m;
        }
    }

    public static final class GetConnectionTokenArgs {
        public String provider;
        public String connectionId;
        /** Null = default to the connection's bound authority scopes (or the action's scopes_min). */
        public List<String> scopes;
        public GetConnectionTokenArgs() {}
        public GetConnectionTokenArgs(String provider, String connectionId, List<String> scopes) { this.provider = provider; this.connectionId = connectionId; this.scopes = scopes; }
    }

    public static final class ProxyCallArgs {
        public String provider;
        public String connectionId;
        /** Optional: scopes the call asks for (checked against the action's scopes_min, never more); default the action's own. */
        public List<String> scopes;
        public ProxyCallArgs() {}
        public ProxyCallArgs(String provider, String connectionId) { this.provider = provider; this.connectionId = connectionId; }
        public ProxyCallArgs(String provider, String connectionId, List<String> scopes) { this(provider, connectionId); this.scopes = scopes; }
    }

    public static final class ProxyResult {
        public ProxyResponse response;
        /** Present when the vault was constructed with receipts, else null. */
        public Map<String, Object> receipt;
    }

    public static final class PutConnectionArgs {
        public String agentId, provider, connectionId, accessToken, refreshToken;
        public double expiresAt;
        public List<String> scopes;
        /** The binding: principal, optional scopes (default: {@link #scopes}) and optional audience. */
        public String principal;
        public List<String> authorityScopes;
        public String audience;
    }

    private final ConnectionStore store;
    private final Map<String, ProviderConfig> providers;
    private final VaultFetch fetchImpl;
    private final LongSupplier now;
    private final String audience;
    private final double expiryLeewayMs;
    private final Map<String, Object> pqPins;
    private final List<String> authorizedPlanRoots;
    private final boolean insecureSkipPlanRootCheck;
    private final String defaultConnectionId;
    private final boolean requireActionBinding;
    private final BiFunction<String, String, String> resourceFor;
    private final String useVerb;
    private final double defaultTokenLifetimeMs;
    private final StateStore replay;
    private final IsRevoked isRevoked;
    private final Actions actions;
    private final boolean insecureBearerRelease;
    private final ProxyFetch proxyFetch;
    private final List<String> proxyHeaders;
    private final long maxProxyResponseBytes;
    private final Receipts receipts;
    /** In-flight refreshes by connection, so two callers never spend one single-use refresh token twice. */
    private final Map<String, CompletableFuture<Refresh.Refreshed>> inflight = new ConcurrentHashMap<>();

    public TokenVault(Options o) {
        if (o.strict) {
            List<String> missing = new ArrayList<>();
            if (o.store == null || !o.store.encrypted()) missing.add("an encrypting store");
            if (o.replay == null) missing.add("replay");
            if (o.isRevoked == null) missing.add("isRevoked");
            if (o.audience == null || o.audience.isEmpty()) missing.add("audience");
            if (!missing.isEmpty()) throw new IllegalArgumentException("TokenVault strict mode requires " + String.join(", ", missing));
        } else if (o.store == null) {
            throw new IllegalArgumentException("TokenVault requires a store");
        }
        this.actions = o.actions;
        this.insecureBearerRelease = o.insecureBearerRelease;
        this.proxyFetch = o.proxyFetch;
        List<String> ph = new ArrayList<>();
        for (String h : o.proxyHeaders) ph.add(h.toLowerCase(Locale.ROOT));
        this.proxyHeaders = ph;
        this.maxProxyResponseBytes = o.maxProxyResponseBytes;
        this.receipts = o.receipts;
        this.replay = o.replay;
        this.isRevoked = o.isRevoked;
        this.store = o.store;
        this.providers = o.providers;
        this.fetchImpl = o.fetch;
        this.now = o.now;
        this.audience = o.audience;
        Map<String, Object> pins = null;
        if (o.pqPins != null) pins = new LinkedHashMap<String, Object>(o.pqPins);
        this.pqPins = pins;
        this.authorizedPlanRoots = o.authorizedPlanRoots;
        this.insecureSkipPlanRootCheck = o.insecureSkipPlanRootCheck;
        this.expiryLeewayMs = o.expiryLeewayMs;
        this.defaultConnectionId = o.defaultConnectionId;
        this.requireActionBinding = o.requireActionBinding;
        this.resourceFor = o.resourceFor;
        this.useVerb = o.useVerb;
        this.defaultTokenLifetimeMs = o.defaultTokenLifetimeMs;
    }

    private static void nonEmpty(String k, String v) {
        if (v == null || v.isEmpty()) throw new IllegalArgumentException("putConnection: " + k + " must be a non-empty string");
    }

    /** Store (or replace) an agent's connection. The authority descriptor binds which capability may use it. */
    public StoredConnection putConnection(PutConnectionArgs args) {
        String connectionId = args.connectionId != null ? args.connectionId : defaultConnectionId;
        nonEmpty("agentId", args.agentId);
        nonEmpty("provider", args.provider);
        nonEmpty("connectionId", connectionId);
        nonEmpty("accessToken", args.accessToken);
        nonEmpty("principal", args.principal);
        if (Double.isNaN(args.expiresAt) || Double.isInfinite(args.expiresAt)) throw new IllegalArgumentException("putConnection: expiresAt must be a finite number");
        if (args.refreshToken != null && args.refreshToken.isEmpty()) throw new IllegalArgumentException("putConnection: refreshToken must be a non-empty string when given");
        if (args.scopes == null) throw new IllegalArgumentException("putConnection: scopes must be a list of strings");
        StoredConnection c = new StoredConnection();
        c.agentId = args.agentId;
        c.provider = args.provider;
        c.connectionId = connectionId;
        c.accessToken = args.accessToken;
        c.expiresAt = args.expiresAt;
        c.scopes = new ArrayList<>(args.scopes);
        c.authority.provider = args.provider;
        c.authority.principal = args.principal;
        c.authority.scopes = new ArrayList<>(args.authorityScopes != null ? args.authorityScopes : args.scopes);
        c.authority.audience = args.audience;
        c.createdAt = now.getAsLong();
        c.useCount = 0;
        c.refreshToken = args.refreshToken;
        storeSet(c);
        return c;
    }

    /**
     * Resolve a FRESH access token iff (a) {@code pcActn} verifies against the connection's bound principal and (b) the capability chain's grant
     * covers the requested provider + scopes. Refreshes a stale token when a refresh token is present. INSECURE BY NATURE: the caller receives a
     * bearer credential, so this is disabled unless the vault was built with {@code insecureBearerRelease}; prefer {@link #proxyCall}.
     */
    public ConnectionToken getConnectionToken(Map<String, Object> pcActn, GetConnectionTokenArgs args) {
        if (!insecureBearerRelease) throw new BearerReleaseDisabledError();
        Authz a = authorize(pcActn, args.provider, args.connectionId, args.scopes, false, null);
        Fresh f = freshToken(a);
        StoredConnection done = recordUse(a, f.token);
        issueReceipt(pcActn, a, "bearer", null, null, "released", done.scopes);
        ConnectionToken out = new ConnectionToken();
        out.provider = a.provider;
        out.connectionId = a.connectionId;
        out.accessToken = done.accessToken;
        out.scopes = new ArrayList<>(done.scopes);
        Double exp = JsVal.num(pcActn.get("exp"));
        out.expiresAt = a.action != null && exp != null && !exp.isNaN() && !exp.isInfinite() ? Math.min(done.expiresAt, exp) : done.expiresAt;
        out.refreshed = f.refreshed;
        return out;
    }

    /**
     * Proxy mode. The vault makes the outbound call itself: verify the PCActn and the pinned, CONFIRMED action; derive the scopes from the action;
     * map {@code request} back to the action's parameters and require paramsDigest to equal the PCActn's signed params_digest; spend the action
     * (replay guard); attach the token; make the call without following redirects; sign a receipt linking the release to the effect.
     */
    public ProxyResult proxyCall(Map<String, Object> pcActn, ProxyRequest request, ProxyCallArgs args) {
        if (actions == null) throw new IllegalArgumentException("proxyCall requires the vault to be constructed with `actions`");
        if (proxyFetch == null) throw new IllegalArgumentException("proxyCall requires the vault to be constructed with `proxyFetch`");
        Map<String, String> sendHeaders = Proxy.checkProxyHeaders(request.headers, proxyHeaders); // before anything is spent
        Authz a = authorize(pcActn, args.provider, args.connectionId, args.scopes, true, request);
        Fresh f = freshToken(a);
        StoredConnection done = recordUse(a, f.token);
        Map<String, String> headers = new LinkedHashMap<>(sendHeaders);
        headers.put("authorization", "Bearer " + done.accessToken);
        String reqDigest = Proxy.outboundRequestDigest(request.method, request.url, sendHeaders, request.body);
        ProxyResponse response;
        try {
            response = proxyFetch.call(request.method, request.url, headers, request.body);
        } catch (Exception e) {
            issueReceipt(pcActn, a, "proxy", reqDigest, null, "failed", done.scopes);
            throw new ProxyFailedError("the outbound call failed before a response");
        }
        long size = response.body == null ? Long.MAX_VALUE : Json.utf8(response.body).length;
        Map<String, Object> receipt = issueReceipt(pcActn, a, "proxy", reqDigest, response.status, "executed", done.scopes);
        if (size > maxProxyResponseBytes) throw new ProxyFailedError("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)");
        // the credential must never travel back: a response header or body that echoes it is redacted
        String body = response.body.replace(done.accessToken, "[redacted]");
        Map<String, String> rh = new LinkedHashMap<>();
        if (response.headers != null) {
            for (Map.Entry<String, String> e : response.headers.entrySet()) {
                if (!e.getKey().toLowerCase(Locale.ROOT).equals("set-cookie")) rh.put(e.getKey(), String.valueOf(e.getValue()).replace(done.accessToken, "[redacted]"));
            }
        }
        ProxyResult r = new ProxyResult();
        r.response = new ProxyResponse(response.status, rh, body);
        r.receipt = receipt;
        return r;
    }

    private static final class Authz {
        String agentId, provider, connectionId;
        StoredConnection connection;
        List<String> requested;
        long now;
        VaultAction action;
    }

    @SuppressWarnings("unchecked")
    private static String jsStr(Object v, boolean present) {
        if (!present) return "undefined";
        if (v == null) return "null";
        Double n = net.atlasauth.pca.oauth.JsVal.num(v);
        if (n != null) return net.atlasauth.pca.AttestCommon.jsNumString(n);
        if (v instanceof Map) return "[object Object]";
        if (v instanceof List) {
            List<String> parts = new ArrayList<>();
            for (Object x : (List<?>) v) parts.add(x == null ? "" : jsStr(x, true));
            return String.join(",", parts);
        }
        return String.valueOf(v);
    }

    private Authz authorize(Map<String, Object> pcActn, String provider, String connIdArg, List<String> scopesArg, boolean needAction, ProxyRequest request) {
        String connectionId = connIdArg != null ? connIdArg : defaultConnectionId;

        Object chainO = pcActn.get("cap_chain");
        if (!(chainO instanceof List) || ((List<?>) chainO).isEmpty()) throw new NotAuthorizedError("PCActn has no capability chain");
        List<Object> chain = (List<Object>) chainO;
        Object leafO = chain.get(chain.size() - 1), rootO = chain.get(0);
        if (leafO == null || rootO == null) throw new NotAuthorizedError("PCActn capability chain is malformed");
        // a primitive hop has no members: its holder reads as undefined and the agent is then simply unknown
        Map<String, Object> leaf = leafO instanceof Map ? (Map<String, Object>) leafO : Collections.<String, Object>emptyMap();
        Map<String, Object> root = rootO instanceof Map ? (Map<String, Object>) rootO : Collections.<String, Object>emptyMap();
        String agentId = jsStr(leaf.get("holder"), leaf.containsKey("holder")); // String(holder) in the reference's template literals

        // 1. Resolve the connection: it carries the trust anchor (bound principal), so it is looked up before verification is anchored.
        StoredConnection connection = storeGet(new ConnectionStore.Key(agentId, provider, connectionId));
        if (connection == null) throw new UnknownConnectionError(agentId, provider, connectionId);

        // 2. Anchor + verify. The chain must be rooted at the connection's bound principal, else a self-minted chain would verify against itself.
        if (!connection.authority.principal.equals(root.get("issuer"))) throw new NotAuthorizedError("capability chain is not rooted at the connection's bound principal");
        long nowMs = now.getAsLong();
        String aud = connection.authority.audience != null ? connection.authority.audience : audience;
        // The root comes from the presented artifact, so a non-ed25519 root verifies ONLY under a pin for its issuer (grantFromArtifact).
        // A null audience is the deliberate opt-out ("accept any"), reported as not enforced.
        net.atlasauth.pca.PcaCore.Options co = new net.atlasauth.pca.PcaCore.Options(root);
        co.grantFromArtifact = true;
        co.pqPins = pqPins;
        if (aud == null) co.audienceAny(); else co.audience(aud);
        co.nowEpoch = nowMs;
        co.planRoots = Pca.PlanRoots.of(authorizedPlanRoots, insecureSkipPlanRootCheck);
        net.atlasauth.pca.PcaCore.Result verdict = net.atlasauth.pca.PcaCore.verify(pcActn, co);
        if (!verdict.allow) {
            Map<String, Boolean> checks = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : verdict.checks.entrySet()) checks.put(e.getKey(), !net.atlasauth.pca.PcaCore.FAIL.equals(e.getValue()));
            throw new NotAuthorizedError("PCActn verification failed: " + (verdict.reason == null || verdict.reason.isEmpty() ? "rejected" : verdict.reason), checks);
        }

        // 2b. Revocation. No source configured means no check (opt in; strict makes it mandatory).
        if (isRevoked != null) {
            boolean revoked;
            try {
                revoked = isRevoked.test(pcActn);
            } catch (Exception e) {
                throw new NotAuthorizedError("revocation source unavailable");
            }
            if (revoked) throw new NotAuthorizedError("the capability chain is revoked");
        }

        Object actionO = pcActn.get("action");
        Map<String, Object> pAction = actionO instanceof Map ? (Map<String, Object>) actionO : Collections.<String, Object>emptyMap();

        // 3. Bind the action.
        VaultAction action = null;
        if (actions != null) {
            Object verbO = pAction.get("verb");
            String verb = verbO instanceof String ? (String) verbO : String.valueOf(verbO);
            try {
                action = actions.resolve(verb);
            } catch (VaultError e) {
                throw e;
            } catch (Exception e) {
                throw new StoreError();
            }
            if (action == null || !verb.equals(action.verb)) throw new UnknownActionError(verb);
            if (!action.confirmed) throw new UnconfirmedActionError(verb);
            if (!provider.equals(action.provider)) throw new NotAuthorizedError("the action '" + verb + "' is not for provider '" + provider + "'");
            if (action.scopesMin == null || action.scopesMin.isEmpty()) throw new NotAuthorizedError("the action '" + verb + "' declares no upstream scopes (nothing to release)");
        } else if (needAction) {
            throw new UnknownActionError(String.valueOf(pAction.get("verb")));
        } else if (requireActionBinding) {
            String expectedResource = resourceFor.apply(provider, connectionId);
            if (!expectedResource.equals(pAction.get("resource"))) {
                throw new NotAuthorizedError("PCActn action resource '" + pAction.get("resource") + "' is not for this connection (expected '" + expectedResource + "')");
            }
            if (useVerb != null && !useVerb.equals(pAction.get("verb"))) {
                throw new NotAuthorizedError("PCActn action verb '" + pAction.get("verb") + "' is not a connection-use verb (expected '" + useVerb + "')");
            }
        }

        // 4. Authority coverage. null => the capability grants nothing for this provider.
        Set<String> granted = Authority.grantedOAuthScopes(chain, provider);
        if (granted == null) throw new NotAuthorizedError("capability grants no authority for provider '" + provider + "'");

        // 5. Least-privilege.
        List<String> requested;
        if (action != null) {
            List<String> min = new ArrayList<>(action.scopesMin);
            requested = scopesArg != null ? scopesArg : min;
            List<String> beyond = new ArrayList<>();
            for (String s : requested) if (!min.contains(s)) beyond.add(s);
            if (!beyond.isEmpty()) throw new ScopeExceededError(provider, requested, min, beyond);
            List<String> unheld = new ArrayList<>();
            for (String s : min) if (!connection.scopes.contains(s) || !connection.authority.scopes.contains(s)) unheld.add(s);
            if (!unheld.isEmpty()) throw new ScopeExceededError(provider, min, connection.scopes, unheld);
            // a bare bearer token cannot be narrowed after issue: it may carry nothing beyond the action's scopes (use a connection per action)
            if (!needAction) {
                List<String> extra = new ArrayList<>();
                for (String s : connection.scopes) if (!min.contains(s)) extra.add(s);
                if (!extra.isEmpty()) throw new ScopeExceededError(provider, min, connection.scopes, extra);
            }
            List<String> ungranted = new ArrayList<>();
            for (String s : min) if (!granted.contains(s)) ungranted.add(s);
            if (!ungranted.isEmpty()) throw new ScopeExceededError(provider, min, new ArrayList<>(granted), ungranted);
        } else {
            requested = scopesArg != null ? scopesArg : connection.authority.scopes;
        }
        List<String> missing = new ArrayList<>();
        for (String s : requested) if (!granted.contains(s)) missing.add(s);
        if (!missing.isEmpty()) throw new ScopeExceededError(provider, requested, new ArrayList<>(granted), missing);

        // 5a. Proxy mode: the outbound request must re-derive EXACTLY the params the PCActn signed.
        if (needAction && action != null) {
            if (request == null || action.extract == null) throw new RequestMismatchError("the action has no request extractor: proxy mode cannot bind the outbound request");
            Map<String, Object> params;
            try {
                params = action.extract.apply(request);
            } catch (RequestMismatchError e) {
                throw e;
            } catch (RuntimeException e) {
                throw new RequestMismatchError("the outbound request could not be mapped to the action parameters");
            }
            String d;
            try {
                d = Pca.paramsDigest(params);
            } catch (RuntimeException e) {
                throw new RequestMismatchError("the outbound request parameters are not canonical");
            }
            if (!d.equals(pAction.get("params_digest"))) throw new RequestMismatchError("the outbound request does not carry the parameters the PCActn signed");
        }

        // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
        if (replay != null) {
            Object pa = pcActn.get("aud");
            ReplayGuard.Verdict rv = ReplayGuard.guard(replay, pcActn, pa instanceof String ? (String) pa : null, nowMs);
            if (!rv.ok) throw new NotAuthorizedError("replay guard refused the action: " + rv.reason);
        }
        Authz z = new Authz();
        z.agentId = agentId;
        z.provider = provider;
        z.connectionId = connectionId;
        z.connection = connection;
        z.requested = requested;
        z.now = nowMs;
        z.action = action;
        return z;
    }

    private static final class Fresh {
        StoredConnection token;
        boolean refreshed;
    }

    /** Step 6: refresh a stale token, else use it as is. A token whose expiry is not a finite number can never be shown fresh. */
    private Fresh freshToken(Authz a) {
        StoredConnection connection = a.connection;
        Fresh f = new Fresh();
        f.token = connection;
        if (Double.isNaN(connection.expiresAt) || Double.isInfinite(connection.expiresAt) || !Double.isFinite(a.now) || !Double.isFinite(expiryLeewayMs) || connection.expiresAt - a.now <= expiryLeewayMs) {
            if (connection.refreshToken == null) throw new ExpiredNoRefreshError(a.provider, a.connectionId);
            String flightKey = a.agentId + "\u0000" + a.provider + "\u0000" + a.connectionId;
            CompletableFuture<Refresh.Refreshed> mine = new CompletableFuture<>();
            CompletableFuture<Refresh.Refreshed> flight = inflight.putIfAbsent(flightKey, mine);
            Refresh.Refreshed updated;
            if (flight == null) {
                try {
                    Refresh.Args ra = new Refresh.Args();
                    ra.connection = connection;
                    ra.config = providers.get(a.provider);
                    ra.refreshToken = connection.refreshToken;
                    ra.requested = a.requested;
                    ra.fetch = fetchImpl;
                    ra.now = a.now;
                    ra.defaultTokenLifetimeMs = defaultTokenLifetimeMs;
                    updated = Refresh.refreshConnection(ra);
                    mine.complete(updated);
                } catch (RuntimeException e) {
                    mine.completeExceptionally(e);
                    throw e;
                } finally {
                    inflight.remove(flightKey, mine);
                }
            } else {
                try {
                    updated = flight.join();
                } catch (CompletionException e) {
                    if (e.getCause() instanceof RuntimeException) throw (RuntimeException) e.getCause();
                    throw e;
                }
            }
            StoredConnection t = connection.copy();
            t.accessToken = updated.accessToken;
            t.refreshToken = updated.refreshToken;
            t.expiresAt = updated.expiresAt;
            t.scopes = new ArrayList<>(updated.scopes);
            f.token = t;
            f.refreshed = true;
        }
        return f;
    }

    /** Step 7: record usage and persist. */
    private StoredConnection recordUse(Authz a, StoredConnection token) {
        StoredConnection t = token.copy();
        t.lastUsedAt = (double) a.now;
        t.useCount = token.useCount + 1;
        storeSet(t);
        return t;
    }

    private Map<String, Object> issueReceipt(Map<String, Object> pcActn, Authz a, String mode, String requestDigest, Integer httpStatus, String outcome, List<String> scopes) {
        if (receipts == null) return null;
        List<String> sorted = new ArrayList<>(scopes);
        Collections.sort(sorted);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", JsVal.n(1));
        body.put("kind", "pca-release-receipt");
        body.put("action_digest", Proxy.receiptActionDigest(pcActn));
        body.put("provider", a.provider);
        body.put("connection_id", a.connectionId);
        body.put("mode", mode);
        body.put("scopes_released", new ArrayList<Object>(sorted));
        body.put("request_digest", requestDigest);
        body.put("http_status", httpStatus == null ? null : JsVal.n(httpStatus));
        body.put("outcome", outcome);
        body.put("ts", JsVal.n(a.now));
        Map<String, Object> receipt = Proxy.signReleaseReceipt(body, receipts.secretKey);
        try {
            if (receipts.sink != null) receipts.sink.accept(receipt);
        } catch (RuntimeException e) {
            // a failing sink must not turn a made call into an error the caller retries; the receipt is still returned
        }
        return receipt;
    }

    /** Remove a stored connection. */
    public void deleteConnection(String agentId, String provider, String connectionId) {
        try {
            store.delete(new ConnectionStore.Key(agentId, provider, connectionId != null ? connectionId : defaultConnectionId));
        } catch (VaultError e) {
            throw e;
        } catch (Exception e) {
            throw new StoreError();
        }
    }

    // The store's own error text is never passed on: it can quote a connection string or a record.
    private StoredConnection storeGet(ConnectionStore.Key key) {
        try {
            return store.get(key);
        } catch (VaultError e) {
            throw e;
        } catch (Exception e) {
            throw new StoreError();
        }
    }

    private void storeSet(StoredConnection c) {
        try {
            store.set(c);
        } catch (VaultError e) {
            throw e;
        } catch (Exception e) {
            throw new StoreError();
        }
    }
}
