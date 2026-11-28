package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.connect.Authority;
import net.atlasauth.pca.connect.ConnectionStore;
import net.atlasauth.pca.connect.EncryptedConnectionStore;
import net.atlasauth.pca.connect.InMemoryConnectionStore;
import net.atlasauth.pca.connect.LocalKeyWrapper;
import net.atlasauth.pca.connect.Proxy;
import net.atlasauth.pca.connect.Refresh;
import net.atlasauth.pca.connect.StoredConnection;
import net.atlasauth.pca.connect.TokenVault;
import net.atlasauth.pca.connect.VaultError;
import net.atlasauth.pca.oauth.JsVal;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the outbound connection/token vault through the native port. */
public class ConnectDiffTest {
    private static final String M = "ref-connect";

    /** A native refusal carrying the reference's stable error code. */
    static final class CodedEx extends RuntimeException implements OracleCases.Coded {
        private final String code;
        CodedEx(VaultError e) { super(e.getMessage(), e); this.code = e.code(); }
        @Override public String code() { return code; }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }

    static List<String> strs(Object o) {
        if (o == null) return null;
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    static Map<String, String> strMap(Object o) {
        if (o == null) return null;
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : m(o).entrySet()) out.put(e.getKey(), e.getValue() instanceof String ? (String) e.getValue() : AttestNvidia.jsString(e.getValue())); // a header value of another JSON type
        return out;
    }

    static double num(Object o) { return JsVal.num(o); }

    static Object numOut(double d) { return net.atlasauth.pca.revoke.JsVal.numOf(d); }

    // ---- small functions ----

    @Test void oauthScopeCaveat() throws Exception { OracleCases.each(M, "oauthScopeCaveat", a -> Authority.oauthScopeCaveat((String) a.get(0), strs(a.get(1)))); }

    @Test void isOAuthScopeCaveat() throws Exception { OracleCases.each(M, "isOAuthScopeCaveat", a -> Authority.isOAuthScopeCaveat(a.get(0))); }

    @Test void grantedOAuthScopes() throws Exception {
        OracleCases.each(M, "grantedOAuthScopes", a -> {
            Set<String> s = Authority.grantedOAuthScopes(a.get(0), (String) a.get(1));
            if (s == null) return null;
            List<String> out = new ArrayList<>(s);
            Collections.sort(out);
            return out;
        });
    }

    static Proxy.HttpRequestSpec spec(Object o) {
        Map<String, Object> s = m(o);
        Proxy.HttpRequestSpec r = new Proxy.HttpRequestSpec();
        r.method = (String) s.get("method");
        r.url = (String) s.get("url");
        r.query = strs(s.get("query"));
        r.body = (String) s.get("body");
        r.fixed = s.get("fixed") == null ? null : m(s.get("fixed"));
        return r;
    }

    static Proxy.ProxyRequest request(Object o) {
        Map<String, Object> s = m(o);
        return new Proxy.ProxyRequest((String) s.get("method"), (String) s.get("url"), strMap(s.get("headers")), (String) s.get("body"));
    }

    @Test void httpExtractor() throws Exception {
        OracleCases.each(M, "httpExtractor", a -> {
            try {
                return Proxy.httpExtractor(spec(a.get(0))).apply(request(a.get(1)));
            } catch (VaultError e) {
                throw new CodedEx(e);
            }
        });
    }

    @Test void checkProxyHeaders() throws Exception {
        OracleCases.each(M, "checkProxyHeaders", a -> {
            try {
                return Proxy.checkProxyHeaders(strMap(a.get(0)), strs(a.get(1)));
            } catch (VaultError e) {
                throw new CodedEx(e);
            }
        });
    }

    @Test void defaultProxyHeaders() throws Exception { OracleCases.each(M, "DEFAULT_PROXY_HEADERS", a -> new ArrayList<>(Proxy.DEFAULT_PROXY_HEADERS)); }

    @Test void outboundRequestDigest() throws Exception {
        OracleCases.each(M, "outboundRequestDigest", a -> Proxy.outboundRequestDigest((String) a.get(0), (String) a.get(1), strMap(a.get(2)), (String) a.get(3)));
    }

    static Keys.EdKey key(Object seedB64) { return Keys.edFromSeed(Keys.unb64u((String) seedB64)); }

    @Test void signReleaseReceipt() throws Exception { OracleCases.each(M, "signReleaseReceipt", a -> Proxy.signReleaseReceipt(m(a.get(0)), key(a.get(1)))); }

    @Test void verifyReleaseReceipt() throws Exception { OracleCases.each(M, "verifyReleaseReceipt", a -> Proxy.verifyReleaseReceipt(m(a.get(0)), (String) a.get(1))); }

    @Test void receiptActionDigest() throws Exception { OracleCases.each(M, "receiptActionDigest", a -> Proxy.receiptActionDigest(m(a.get(0)))); }

    // ---- scripted transport ----

    /** The scripted token-endpoint transport: replays the case's responses in order (the last one repeats) and logs every request. */
    static final class Script implements Refresh.VaultFetch {
        final List<Object> script;
        final List<Object> log;
        int i = 0;
        Script(List<Object> script, List<Object> log) { this.script = script; this.log = log; }

        @Override public Refresh.VaultHttpResponse call(String url, Refresh.VaultHttpRequest init) throws Exception {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("url", url);
            entry.put("method", init.method);
            entry.put("headers", new LinkedHashMap<String, Object>(init.headers));
            entry.put("body", init.body);
            log.add(entry);
            Map<String, Object> r = m(script.get(Math.min(i++, script.size() - 1)));
            if (r.get("throws") != null) throw new RuntimeException((String) r.get("throws"));
            return new Refresh.VaultHttpResponse() {
                @Override public boolean ok() { return Boolean.TRUE.equals(r.get("ok")); }
                @Override public int status() { return (int) num(r.get("status")); }
                @Override public Object json() throws Exception {
                    if (Boolean.TRUE.equals(r.get("jsonThrows"))) throw new Exception("bad json");
                    return r.get("json");
                }
                @Override public String text() throws Exception {
                    if (Boolean.TRUE.equals(r.get("textThrows"))) throw new Exception("bad text");
                    return r.get("text") == null ? "" : (String) r.get("text");
                }
            };
        }
    }

    static Refresh.VaultFetch transport(Object script, List<Object> log) { return script == null ? null : new Script(l(script), log); }

    static Map<String, Object> errOut(RuntimeException e) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("ok", false);
        if (e instanceof VaultError) {
            VaultError v = (VaultError) e;
            o.put("name", v.errorName());
            o.put("code", v.code());
            if (!v.code().equals("not_authorized")) o.put("message", v.getMessage());
            if (e instanceof VaultError.RefreshFailedError && ((VaultError.RefreshFailedError) e).status != null) o.put("status", JsVal.n(((VaultError.RefreshFailedError) e).status));
            if (e instanceof VaultError.ScopeExceededError) o.put("missing", new ArrayList<Object>(((VaultError.ScopeExceededError) e).missing));
        } else {
            o.put("name", "Error");
        }
        return o;
    }

    static StoredConnection conn(Object o) {
        Map<String, Object> c = m(o);
        StoredConnection s = new StoredConnection();
        s.agentId = (String) c.get("agentId");
        s.provider = (String) c.get("provider");
        s.connectionId = (String) c.get("connectionId");
        s.accessToken = (String) c.get("accessToken");
        s.refreshToken = (String) c.get("refreshToken");
        s.expiresAt = num(c.get("expiresAt"));
        s.scopes = strs(c.get("scopes"));
        Map<String, Object> au = m(c.get("authority"));
        s.authority.provider = (String) au.get("provider");
        s.authority.principal = (String) au.get("principal");
        s.authority.scopes = strs(au.get("scopes"));
        s.authority.audience = (String) au.get("audience");
        s.createdAt = num(c.get("createdAt"));
        s.lastUsedAt = c.get("lastUsedAt") == null ? null : num(c.get("lastUsedAt"));
        s.useCount = (long) num(c.get("useCount"));
        return s;
    }

    static Refresh.ProviderConfig config(Object o) {
        if (o == null) return null;
        Map<String, Object> c = m(o);
        Refresh.ProviderConfig p = new Refresh.ProviderConfig((String) c.get("tokenEndpoint"), (String) c.get("clientId"));
        p.clientSecret = (String) c.get("clientSecret");
        p.supportsScopeNarrowing = (Boolean) c.get("supportsScopeNarrowing");
        p.extraParams = strMap(c.get("extraParams"));
        return p;
    }

    @Test void refreshConnection() throws Exception {
        OracleCases.each(M, "refreshConnection", a -> {
            Map<String, Object> c = m(a.get(0));
            List<Object> log = new ArrayList<>();
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                Refresh.Args ra = new Refresh.Args();
                ra.connection = conn(c.get("connection"));
                ra.config = config(c.get("config"));
                ra.refreshToken = (String) c.get("refreshToken");
                ra.requested = strs(c.get("requested"));
                ra.fetch = transport(c.get("script"), log);
                ra.now = num(c.get("now"));
                ra.defaultTokenLifetimeMs = num(c.get("defaultTokenLifetimeMs"));
                Refresh.Refreshed r = Refresh.refreshConnection(ra);
                out.put("ok", true);
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("accessToken", r.accessToken);
                v.put("expiresAt", numOut(r.expiresAt));
                v.put("scopes", new ArrayList<Object>(r.scopes));
                v.put("refreshToken", r.refreshToken);
                out.put("value", v);
            } catch (RuntimeException e) {
                out.putAll(errOut(e));
            }
            out.put("calls", log);
            return out;
        });
    }

    @Test void decryptRecord() throws Exception {
        OracleCases.each(M, "decryptRecord", a -> {
            Map<String, Object> c = m(a.get(0));
            InMemoryConnectionStore inner = new InMemoryConnectionStore();
            inner.set(conn(c.get("record")));
            Map<String, byte[]> ring = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(c.get("ring")).entrySet()) ring.put(e.getKey(), Keys.unb64u((String) e.getValue()));
            EncryptedConnectionStore store = new EncryptedConnectionStore(inner, new LocalKeyWrapper(ring, (String) c.get("active")));
            Map<String, Object> k = m(c.get("key"));
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                StoredConnection r = store.get(new ConnectionStore.Key((String) k.get("agentId"), (String) k.get("provider"), (String) k.get("connectionId")));
                out.put("ok", true);
                out.put("value", r == null ? null : r.toMap());
            } catch (RuntimeException e) {
                out.putAll(errOut(e));
            }
            return out;
        });
    }

    // ---- TokenVault scenarios ----

    /** A PCActn argument: a primitive has no members (reads as undefined), null stays null (a TypeError in the reference). */
    static Map<String, Object> pc(Object o) { return o == null || o instanceof Map ? m(o) : new LinkedHashMap<String, Object>(); }

    static Map<String, Object> table(Object t) { return t == null ? null : m(t); }

    static TokenVault.VaultAction action(Map<String, Object> t) {
        TokenVault.VaultAction v = new TokenVault.VaultAction();
        v.verb = (String) t.get("verb");
        v.defDigest = (String) t.get("def_digest");
        v.confirmed = Boolean.TRUE.equals(t.get("confirmed"));
        Map<String, Object> up = m(t.get("upstream"));
        v.provider = (String) up.get("provider");
        v.scopesMin = strs(up.get("scopes_min"));
        if (t.get("extract") != null) v.extract = Proxy.httpExtractor(spec(t.get("extract")));
        return v;
    }

    static Map<String, Object> vault(Map<String, Object> s) {
        final long[] nowRef = {(long) num(s.get("nowMs"))};
        InMemoryConnectionStore store = new InMemoryConnectionStore();
        List<Object> fetchLog = new ArrayList<>(), proxyLog = new ArrayList<>(), receipts = new ArrayList<>();
        Map<String, Object> op = s.get("opts") == null ? new LinkedHashMap<String, Object>() : m(s.get("opts"));
        Map<String, Object> actionsTable = table(s.get("actionsTable"));

        TokenVault.Options o = new TokenVault.Options();
        o.strict = false;
        o.store = store;
        o.now = () -> nowRef[0];
        o.fetch = transport(s.get("fetchScript"), fetchLog);
        o.insecureBearerRelease = Boolean.TRUE.equals(op.get("insecureBearerRelease"));
        o.insecureSkipPlanRootCheck = Boolean.TRUE.equals(op.get("insecureSkipPlanRootCheck"));
        if (op.get("authorizedPlanRoots") != null) o.authorizedPlanRoots = strs(op.get("authorizedPlanRoots"));
        if (op.get("audience") != null) o.audience = (String) op.get("audience");
        if (op.get("expiryLeewayMs") != null) o.expiryLeewayMs = num(op.get("expiryLeewayMs"));
        if (op.get("defaultTokenLifetimeMs") != null) o.defaultTokenLifetimeMs = num(op.get("defaultTokenLifetimeMs"));
        if (op.get("requireActionBinding") != null) o.requireActionBinding = (Boolean) op.get("requireActionBinding");
        if (op.containsKey("useVerb")) o.useVerb = (String) op.get("useVerb");
        if (op.get("defaultConnectionId") != null) o.defaultConnectionId = (String) op.get("defaultConnectionId");
        if (op.get("providers") != null) for (Map.Entry<String, Object> e : m(op.get("providers")).entrySet()) o.providers.put(e.getKey(), config(e.getValue()));
        if (op.get("pqPins") != null) o.pqPins = strMap(op.get("pqPins"));
        if (op.get("maxProxyResponseBytes") != null) o.maxProxyResponseBytes = (long) num(op.get("maxProxyResponseBytes"));
        if (Boolean.TRUE.equals(op.get("replay"))) o.replay = new MemoryStateStore();
        Object revoked = op.get("revoked");
        if (revoked != null) {
            o.isRevoked = p -> {
                if ("throws".equals(revoked)) throw new Exception("src down");
                return "yes".equals(revoked);
            };
        }
        if (actionsTable != null) o.actions = verb -> actionsTable.get(verb) == null ? null : action(m(actionsTable.get(verb)));
        if (Boolean.TRUE.equals(op.get("proxy"))) {
            List<Object> script = l(s.get("proxyScript"));
            AtomicInteger pi = new AtomicInteger();
            o.proxyFetch = (method, url, headers, body) -> {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("method", method);
                e.put("url", url);
                e.put("headers", new LinkedHashMap<String, Object>(headers));
                e.put("body", body);
                e.put("redirect", "manual");
                proxyLog.add(e);
                Map<String, Object> r = m(script.get(Math.min(pi.getAndIncrement(), script.size() - 1)));
                if (r.get("throws") != null) throw new Exception("net");
                return new Proxy.ProxyResponse((int) num(r.get("status")), strMap(r.get("headers")), (String) r.get("body"));
            };
        }
        if (op.get("receiptSeed") != null) {
            TokenVault.Receipts rc = new TokenVault.Receipts();
            rc.secretKey = key(op.get("receiptSeed"));
            rc.sink = r -> {
                receipts.add(r);
                if (Boolean.TRUE.equals(op.get("failingSink"))) throw new RuntimeException("sink");
            };
            o.receipts = rc;
        }
        TokenVault vault = new TokenVault(o);

        List<Object> results = new ArrayList<>();
        for (Object co : l(s.get("calls"))) {
            Map<String, Object> c = m(co);
            String kind = (String) c.get("op");
            if (kind.equals("now")) { nowRef[0] = (long) num(c.get("now")); continue; }
            Map<String, Object> res = new LinkedHashMap<>();
            try {
                Object value;
                if (kind.equals("put")) {
                    Map<String, Object> g = m(c.get("args"));
                    TokenVault.PutConnectionArgs p = new TokenVault.PutConnectionArgs();
                    p.agentId = (String) g.get("agentId");
                    p.provider = (String) g.get("provider");
                    p.connectionId = (String) g.get("connectionId");
                    p.accessToken = (String) g.get("accessToken");
                    p.refreshToken = (String) g.get("refreshToken");
                    p.expiresAt = num(g.get("expiresAt"));
                    p.scopes = strs(g.get("scopes"));
                    Map<String, Object> au = m(g.get("authority"));
                    p.principal = (String) au.get("principal");
                    p.authorityScopes = strs(au.get("scopes"));
                    p.audience = (String) au.get("audience");
                    value = vault.putConnection(p).toMap();
                } else if (kind.equals("get")) {
                    Map<String, Object> g = m(c.get("args"));
                    value = vault.getConnectionToken(pc(c.get("pcActn")), new TokenVault.GetConnectionTokenArgs((String) g.get("provider"), (String) g.get("connectionId"), strs(g.get("scopes")))).toMap();
                } else if (kind.equals("proxy")) {
                    Map<String, Object> g = m(c.get("args"));
                    TokenVault.ProxyResult r = vault.proxyCall(pc(c.get("pcActn")), request(c.get("request")), new TokenVault.ProxyCallArgs((String) g.get("provider"), (String) g.get("connectionId"), strs(g.get("scopes"))));
                    Map<String, Object> v = new LinkedHashMap<>();
                    Map<String, Object> rs = new LinkedHashMap<>();
                    rs.put("status", JsVal.n(r.response.status));
                    rs.put("headers", new LinkedHashMap<String, Object>(r.response.headers));
                    rs.put("body", r.response.body);
                    v.put("response", rs);
                    if (r.receipt != null) v.put("receipt", r.receipt);
                    value = v;
                } else if (kind.equals("delete")) {
                    vault.deleteConnection((String) c.get("agentId"), (String) c.get("provider"), (String) c.get("connectionId"));
                    value = null;
                } else throw new IllegalStateException("unknown op " + kind);
                res.put("ok", true);
                res.put("value", value);
            } catch (RuntimeException e) {
                res = errOut(e);
            }
            results.add(res);
        }
        List<Object> out = new ArrayList<>();
        if (s.get("watch") != null) {
            for (Object k : l(s.get("watch"))) {
                Map<String, Object> kk = m(k);
                try {
                    StoredConnection g = store.get(new ConnectionStore.Key((String) kk.get("agentId"), (String) kk.get("provider"), (String) kk.get("connectionId")));
                    out.add(g == null ? null : g.toMap());
                } catch (Exception e) { throw new IllegalStateException(e); }
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("results", results);
        r.put("store", out);
        r.put("receipts", receipts);
        r.put("fetchCalls", fetchLog);
        r.put("proxyCalls", proxyLog);
        return r;
    }

    @Test void vault() throws Exception { OracleCases.each(M, "vault", a -> vault(m(a.get(0)))); }

    // ---- what the oracle cannot pin (random IVs): round trips and tamper detection ----

    @Test void encryptedStoreRoundTripAndTamper() throws Exception {
        Map<String, byte[]> ring = new HashMap<>();
        ring.put("k1", new byte[32]);
        byte[] k2 = new byte[32];
        java.util.Arrays.fill(k2, (byte) 7);
        ring.put("k2", k2);
        LocalKeyWrapper w = new LocalKeyWrapper(ring, "k1");
        InMemoryConnectionStore inner = new InMemoryConnectionStore();
        EncryptedConnectionStore store = new EncryptedConnectionStore(inner, w);
        StoredConnection c = new StoredConnection();
        c.agentId = "agent";
        c.provider = "google";
        c.connectionId = "default";
        c.accessToken = "AT-secret";
        c.refreshToken = "RT-secret";
        c.expiresAt = 1000;
        c.scopes = new ArrayList<>(List.of("read"));
        c.authority.provider = "google";
        c.authority.principal = "p";
        c.authority.scopes = new ArrayList<>(List.of("read"));
        store.set(c);
        ConnectionStore.Key key = new ConnectionStore.Key("agent", "google", "default");
        StoredConnection raw = inner.get(key);
        org.junit.jupiter.api.Assertions.assertTrue(raw.accessToken.startsWith("pca1."), "the token must be an envelope at rest");
        org.junit.jupiter.api.Assertions.assertFalse(raw.accessToken.contains("AT-secret"));
        org.junit.jupiter.api.Assertions.assertTrue(store.encrypted());
        StoredConnection back = store.get(key);
        org.junit.jupiter.api.Assertions.assertEquals("AT-secret", back.accessToken);
        org.junit.jupiter.api.Assertions.assertEquals("RT-secret", back.refreshToken);
        // rotation: a record sealed under k1 still opens after k2 becomes active, and re-encrypts under k2
        w.setActive("k2");
        org.junit.jupiter.api.Assertions.assertEquals("AT-secret", store.get(key).accessToken);
        org.junit.jupiter.api.Assertions.assertTrue(store.reencrypt(key));
        w.removeKey("k1");
        org.junit.jupiter.api.Assertions.assertEquals("RT-secret", store.get(key).refreshToken);
        // a ciphertext moved to another connection fails to open
        StoredConnection moved = inner.get(key);
        moved.connectionId = "other";
        inner.set(moved);
        try {
            store.get(new ConnectionStore.Key("agent", "google", "other"));
            org.junit.jupiter.api.Assertions.fail("a moved ciphertext must not open");
        } catch (VaultError.StoreError expected) {
            org.junit.jupiter.api.Assertions.assertEquals("store_error", expected.code());
        }
    }

    @Test void strictModeRequiresTheProductionPieces() {
        TokenVault.Options o = new TokenVault.Options();
        try {
            new TokenVault(o);
            org.junit.jupiter.api.Assertions.fail("strict mode must refuse a bare configuration");
        } catch (IllegalArgumentException e) {
            org.junit.jupiter.api.Assertions.assertEquals("TokenVault strict mode requires an encrypting store, replay, isRevoked, audience", e.getMessage());
        }
        o.strict = false;
        try {
            new TokenVault(o);
            org.junit.jupiter.api.Assertions.fail("a store is required");
        } catch (IllegalArgumentException e) {
            org.junit.jupiter.api.Assertions.assertEquals("TokenVault requires a store", e.getMessage());
        }
    }
}
