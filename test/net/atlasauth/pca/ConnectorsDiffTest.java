package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.connect.InMemoryConnectionStore;
import net.atlasauth.pca.connect.Refresh;
import net.atlasauth.pca.connect.StoredConnection;
import net.atlasauth.pca.connect.TokenVault;
import net.atlasauth.pca.connect.ConnectionStore;
import net.atlasauth.pca.connectors.Authorize;
import net.atlasauth.pca.connectors.ConnectorError;
import net.atlasauth.pca.connectors.Exchange;
import net.atlasauth.pca.connectors.Manifest;
import net.atlasauth.pca.connectors.ProviderManifest;
import net.atlasauth.pca.connectors.ProviderRegistry;
import net.atlasauth.pca.connectors.Providers;
import net.atlasauth.pca.oauth.JsVal;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the connector catalog through the native port. */
public class ConnectorsDiffTest {
    private static final String M = "ref-connectors";

    private static Map<String, Object> m(Object o) { return ConnectDiffTest.m(o); }
    private static List<Object> l(Object o) { return ConnectDiffTest.l(o); }

    @FunctionalInterface interface Thunk { Object get() throws Exception; }

    /** The reference's {@code guard}: {ok:true, value} or the error as data (a non-ConnectorError failure is just {name:"Error"}). */
    static Map<String, Object> guard(Thunk t) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Object v = t.get();
            out.put("ok", true);
            out.put("value", v);
        } catch (Exception e) {
            out.clear();
            out.putAll(errOut(e));
        }
        return out;
    }

    static Map<String, Object> errOut(Exception e) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("ok", false);
        if (e instanceof ConnectorError) {
            ConnectorError c = (ConnectorError) e;
            o.put("name", c.errorName());
            o.put("message", c.getMessage());
            if (c instanceof ConnectorError.ManifestValidationError) o.put("issues", new ArrayList<Object>(((ConnectorError.ManifestValidationError) c).issues));
        } else {
            o.put("name", "Error");
        }
        return o;
    }

    // ---- manifests ----

    @Test void validateManifest() throws Exception {
        OracleCases.each(M, "validateManifest", a -> {
            Manifest.ManifestValidation r = Manifest.validateManifest(a.get(0));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", r.ok);
            if (r.ok) out.put("manifest", r.manifest.toMap()); else out.put("issues", new ArrayList<Object>(r.issues));
            return out;
        });
    }

    @Test void assertManifest() throws Exception { OracleCases.each(M, "assertManifest", a -> guard(() -> Manifest.assertManifest(a.get(0)).toMap())); }

    @Test void manifestDigest() throws Exception { OracleCases.each(M, "manifestDigest", a -> Manifest.manifestDigest(Manifest.assertManifest(a.get(0)))); }

    // ---- catalog and registry ----

    @Test void catalog() throws Exception {
        OracleCases.each(M, "catalog", a -> {
            Map<String, Object> out = new LinkedHashMap<>();
            List<Object> ids = new ArrayList<>(), all = new ArrayList<>();
            for (ProviderManifest p : ProviderRegistry.listProviders()) { ids.add(p.id); all.add(p.toMap()); }
            out.put("ids", ids);
            out.put("manifests", all);
            out.put("digest", ProviderRegistry.catalogDigest());
            out.put("google", ProviderRegistry.getProvider("google").toMap());
            out.put("nope", ProviderRegistry.getProvider("nope") == null ? null : "present");
            return out;
        });
    }

    @Test void registry() throws Exception {
        OracleCases.each(M, "registry", a -> {
            Map<String, Object> s = m(a.get(0));
            ProviderRegistry r = Boolean.TRUE.equals(s.get("empty")) ? new ProviderRegistry() : ProviderRegistry.createDefaultRegistry();
            List<Object> out = new ArrayList<>();
            for (Object oo : l(s.get("ops"))) {
                Map<String, Object> op = m(oo);
                String kind = (String) op.get("op");
                out.add(guard(() -> {
                    switch (kind) {
                        case "register": {
                            ProviderRegistry.RegisterOptions ro = null;
                            if (op.get("opts") != null) {
                                Map<String, Object> po = m(op.get("opts"));
                                ro = new ProviderRegistry.RegisterOptions(Boolean.TRUE.equals(po.get("replace")), (String) po.get("expectedDigest"));
                            }
                            return r.register(op.get("manifest"), ro).toMap();
                        }
                        case "get": { ProviderManifest p = r.get((String) op.get("id")); return p == null ? null : p.toMap(); }
                        case "require": return r.require((String) op.get("id")).toMap();
                        case "has": return r.has((String) op.get("id"));
                        case "list": { List<Object> o2 = new ArrayList<>(); for (ProviderManifest p : r.list()) o2.add(p.toMap()); return o2; }
                        case "ids": return new ArrayList<Object>(r.ids());
                        default: return ProviderRegistry.catalogDigest(r);
                    }
                }));
            }
            return out;
        });
    }

    // ---- authorize ----

    @Test void substituteVars() throws Exception {
        OracleCases.each(M, "substituteVars", a -> guard(() -> {
            // an explicit JSON null (unlike undefined) is read for a member by the reference: a TypeError as soon as the URL has a variable
            if (a.size() > 1 && a.get(1) == null && java.util.regex.Pattern.compile("\\{\\w+\\}").matcher((String) a.get(0)).find()) throw new IllegalStateException("TypeError: Cannot convert undefined or null to object");
            return Authorize.substituteVars((String) a.get(0), a.get(1) == null ? null : m(a.get(1)));
        }));
    }

    @Test void pkceChallenge() throws Exception {
        OracleCases.each(M, "pkceChallenge", a -> guard(() -> a.size() > 1 ? Authorize.pkceChallenge((String) a.get(0), (String) a.get(1)) : Authorize.pkceChallenge((String) a.get(0))));
    }

    static ProviderRegistry registryWith(Object customs) {
        ProviderRegistry r = ProviderRegistry.createDefaultRegistry();
        if (customs != null) for (Object c : l(customs)) r.register(c);
        return r;
    }

    @Test void buildAuthorizeUrl() throws Exception {
        OracleCases.each(M, "buildAuthorizeUrl", a -> guard(() -> Authorize.buildAuthorizeUrl((String) a.get(0), m(a.get(1)), registryWith(a.get(2))).toMap()));
    }

    /** A manifest object used as is (not validated), with only the members applyAccessToken reads. */
    static ProviderManifest raw(Object o) {
        Map<String, Object> mm = m(o);
        ProviderManifest p = new ProviderManifest();
        p.id = (String) mm.get("id");
        p.tokenPlacement = (String) mm.get("tokenPlacement");
        p.headerName = (String) mm.get("headerName");
        p.queryParam = (String) mm.get("queryParam");
        return p;
    }

    @Test void applyAccessToken() throws Exception { OracleCases.each(M, "applyAccessToken", a -> guard(() -> Authorize.applyAccessToken(raw(a.get(0)), a.get(1)))); }

    // ---- exchange ----

    static Exchange.ProviderCredentials creds(Object o) {
        Map<String, Object> c = m(o);
        return new Exchange.ProviderCredentials((String) c.get("clientId"), (String) c.get("clientSecret"), c.get("vars") == null ? null : m(c.get("vars")));
    }

    @Test void manifestToProviderConfig() throws Exception {
        OracleCases.each(M, "manifestToProviderConfig", a -> guard(() -> Exchange.manifestToProviderConfig(ProviderRegistry.getProvider((String) a.get(0)), creds(a.get(1))).toMap()));
    }

    @Test void buildVaultProviders() throws Exception {
        OracleCases.each(M, "buildVaultProviders", a -> guard(() -> {
            Map<String, Exchange.ProviderCredentials> in = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(a.get(0)).entrySet()) in.put(e.getKey(), creds(e.getValue()));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Refresh.ProviderConfig> e : Exchange.buildVaultProviders(in, null).entrySet()) out.put(e.getKey(), e.getValue().toMap());
            return out;
        }));
    }

    static Map<String, Object> tokenRun(boolean exchange, Map<String, Object> c) {
        List<Object> log = new ArrayList<>();
        InMemoryConnectionStore store = new InMemoryConnectionStore();
        TokenVault.Options vo = new TokenVault.Options();
        vo.strict = false;
        vo.insecureSkipPlanRootCheck = true;
        vo.store = store;
        final long now = (long) ConnectDiffTest.num(c.get("now"));
        vo.now = () -> now;
        TokenVault vault = new TokenVault(vo);
        Map<String, Object> bind = m(c.get("bind"));
        Exchange.ConnectionBinding b = new Exchange.ConnectionBinding();
        b.vault = vault;
        b.agentId = (String) bind.get("agentId");
        b.connectionId = (String) bind.get("connectionId");
        b.principal = (String) bind.get("principal");
        b.authorityScopes = ConnectDiffTest.strs(bind.get("scopes"));
        b.audience = (String) bind.get("audience");
        ProviderRegistry reg = registryWith(c.get("customs"));
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            StoredConnection sc;
            if (exchange) {
                Exchange.ExchangeCodeArgs x = new Exchange.ExchangeCodeArgs();
                x.providerId = (String) c.get("providerId");
                x.clientId = (String) c.get("clientId");
                x.clientSecret = (String) c.get("clientSecret");
                x.code = (String) c.get("code");
                x.redirectUri = (String) c.get("redirectUri");
                x.codeVerifier = (String) c.get("codeVerifier");
                x.scopes = ConnectDiffTest.strs(c.get("scopes"));
                x.fetch = ConnectDiffTest.transport(c.get("script"), log);
                x.bind = b;
                x.now = ConnectDiffTest.num(c.get("now"));
                x.registry = reg;
                x.vars = c.get("vars") == null ? null : m(c.get("vars"));
                x.extraParams = ConnectDiffTest.strMap(c.get("extraParams"));
                sc = Exchange.exchangeCode(x);
            } else {
                Exchange.RefreshArgs x = new Exchange.RefreshArgs();
                x.providerId = (String) c.get("providerId");
                x.clientId = (String) c.get("clientId");
                x.clientSecret = (String) c.get("clientSecret");
                x.refreshToken = (String) c.get("refreshToken");
                x.scopes = ConnectDiffTest.strs(c.get("scopes"));
                x.fetch = ConnectDiffTest.transport(c.get("script"), log);
                x.bind = b;
                x.now = ConnectDiffTest.num(c.get("now"));
                x.registry = reg;
                x.vars = c.get("vars") == null ? null : m(c.get("vars"));
                x.extraParams = ConnectDiffTest.strMap(c.get("extraParams"));
                sc = Exchange.refresh(x);
            }
            result.put("ok", true);
            result.put("value", sc.toMap());
        } catch (RuntimeException e) {
            result.putAll(errOut(e));
        }
        Object stored = null;
        try {
            StoredConnection g = store.get(new ConnectionStore.Key(b.agentId, (String) c.get("providerId"), b.connectionId != null ? b.connectionId : "default"));
            stored = g == null ? null : g.toMap();
        } catch (Exception e) { throw new IllegalStateException(e); }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("result", result);
        out.put("fetchCalls", log);
        out.put("stored", stored);
        return out;
    }

    @Test void exchange() throws Exception { OracleCases.each(M, "exchange", a -> tokenRun(true, m(a.get(0)))); }

    @Test void refresh() throws Exception { OracleCases.each(M, "refresh", a -> tokenRun(false, m(a.get(0)))); }

    // ---- what the oracle cannot pin (random state / verifier) and the I/O seams ----

    @Test void randomStateAndVerifierAreGenerated() {
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("clientId", "cid");
        opts.put("redirectUri", "https://app.example.com/cb");
        Authorize.AuthorizeUrl a = Authorize.buildAuthorizeUrl("google", opts);
        Authorize.AuthorizeUrl b = Authorize.buildAuthorizeUrl("google", opts);
        assertTrue(a.state.length() >= 43, "a random 32-byte state");
        assertFalse(a.state.equals(b.state));
        assertNotNull(a.pkce, "google declares PKCE: a verifier is generated");
        assertTrue(a.pkce.verifier.matches("[A-Za-z0-9._~-]{43,128}"));
        assertFalse(a.pkce.verifier.equals(b.pkce.verifier));
        assertEquals(Authorize.pkceChallenge(a.pkce.verifier), a.pkce.challenge);
        assertTrue(a.url.contains("code_challenge=" + a.pkce.challenge));
        assertTrue(a.url.contains("state=" + a.state));
        Authorize.AuthorizeUrl gh = Authorize.buildAuthorizeUrl("github", opts);
        assertNull(gh.pkce, "github does not use PKCE");
        Map<String, Object> forced = new LinkedHashMap<>(opts);
        forced.put("pkce", Boolean.TRUE);
        assertNotNull(Authorize.buildAuthorizeUrl("github", forced).pkce, "pkce: true forces a generated verifier");
    }

    @Test void missingTransportFailsClosed() {
        InMemoryConnectionStore store = new InMemoryConnectionStore();
        TokenVault.Options vo = new TokenVault.Options();
        vo.strict = false;
        vo.store = store;
        Exchange.ConnectionBinding b = new Exchange.ConnectionBinding();
        b.vault = new TokenVault(vo);
        b.agentId = "a";
        b.principal = "p";
        Exchange.ExchangeCodeArgs x = new Exchange.ExchangeCodeArgs();
        x.providerId = "github";
        x.clientId = "cid";
        x.code = "c";
        x.redirectUri = "https://app.example.com/cb";
        x.bind = b;
        assertThrows(ConnectorError.class, () -> Exchange.exchangeCode(x));
    }

    @Test void catalogIsTheFifteenReviewedProviders() {
        assertEquals(15, Providers.BUILTIN_MANIFESTS.size());
        for (ProviderManifest p : Providers.BUILTIN_MANIFESTS) assertEquals(p.toMap().toString(), Manifest.assertManifest(p.toMap()).toMap().toString());
        assertEquals(ProviderRegistry.createDefaultRegistry().ids(), ProviderRegistry.defaultRegistry().ids());
    }
}
