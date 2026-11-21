package net.atlasauth.pca.connect;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.oauth.JsVal;

/** A stored outbound connection, keyed by agent + provider + connectionId. Mutable fields: stores clone in and out. */
public final class StoredConnection {
    /** The PCA authority a connection is bound to: which capability may unlock this token. */
    public static final class ConnectionAuthority {
        public String provider;
        /** The trust anchor: the b64u public key the capability chain must be rooted at. */
        public String principal;
        public List<String> scopes = new ArrayList<>();
        /** When set, the PCActn's signed aud must equal it (null = none). */
        public String audience;

        public ConnectionAuthority copy() {
            ConnectionAuthority a = new ConnectionAuthority();
            a.provider = provider;
            a.principal = principal;
            a.scopes = new ArrayList<>(scopes);
            a.audience = audience;
            return a;
        }
    }

    public String agentId;
    public String provider;
    public String connectionId;
    public String accessToken;
    /** Null when there is none. */
    public String refreshToken;
    /** Access-token expiry, epoch milliseconds. */
    public double expiresAt;
    /** The scopes the stored access token actually carries. */
    public List<String> scopes = new ArrayList<>();
    public ConnectionAuthority authority = new ConnectionAuthority();
    public double createdAt;
    /** Null when never used. */
    public Double lastUsedAt;
    public long useCount;

    public StoredConnection copy() {
        StoredConnection c = new StoredConnection();
        c.agentId = agentId;
        c.provider = provider;
        c.connectionId = connectionId;
        c.accessToken = accessToken;
        c.expiresAt = expiresAt;
        c.scopes = new ArrayList<>(scopes);
        c.authority = authority.copy();
        c.createdAt = createdAt;
        c.useCount = useCount;
        c.refreshToken = refreshToken;
        c.lastUsedAt = lastUsedAt;
        return c;
    }

    /** The reference's {@code cloneConnection}. */
    public static StoredConnection cloneConnection(StoredConnection c) { return c.copy(); }

    /** The connection as the reference's plain object (members absent when unset). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("agentId", agentId);
        m.put("provider", provider);
        m.put("connectionId", connectionId);
        m.put("accessToken", accessToken);
        m.put("expiresAt", net.atlasauth.pca.revoke.JsVal.numOf(expiresAt));
        m.put("scopes", new ArrayList<Object>(scopes));
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("provider", authority.provider);
        a.put("principal", authority.principal);
        a.put("scopes", new ArrayList<Object>(authority.scopes));
        if (authority.audience != null) a.put("audience", authority.audience);
        m.put("authority", a);
        m.put("createdAt", net.atlasauth.pca.revoke.JsVal.numOf(createdAt));
        m.put("useCount", JsVal.n(useCount));
        if (refreshToken != null) m.put("refreshToken", refreshToken);
        if (lastUsedAt != null) m.put("lastUsedAt", net.atlasauth.pca.revoke.JsVal.numOf(lastUsedAt));
        return m;
    }
}
