package net.atlasauth.pca.connectors;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The declarative unit of the connector catalog: pure data (no secrets) naming a SaaS provider's OAuth 2.0 endpoints, the scopes it offers,
 * how its access token is presented, and how it refreshes. Build one only through {@link Manifest#assertManifest} (it validates).
 */
public final class ProviderManifest {
    /** The refresh contract: how a stale access token is renewed. */
    public static final class RefreshSpec {
        /** "refresh_token" (standard refresh grant) or "none" (static / long-lived tokens). */
        public String mode;
        /** Token endpoint for refresh (null = the manifest's tokenUrl). */
        public String tokenEndpoint;
        /** Null = unset; true sends a narrowed scope on refresh. */
        public Boolean supportsScopeNarrowing;
        /** Extra static form parameters (null = none). */
        public Map<String, String> extraParams;
    }

    /** Stable, lowercase, globally-unique registry id. */
    public String id;
    public String displayName;
    /** May carry {var} placeholders (see {@link #requiredVars}). */
    public String authorizeUrl;
    public String tokenUrl;
    public List<String> scopesAvailable = new ArrayList<>();
    public List<String> defaultScopes = new ArrayList<>();
    public RefreshSpec refresh = new RefreshSpec();
    /** "bearer", "header" or "query". */
    public String tokenPlacement;
    /** Null = unset. */
    public Boolean pkce;
    /** Scope delimiter in the authorize request (null = a space). */
    public String scopeSeparator;
    public Map<String, String> authParams;
    /** "post" (default when null) or "basic". */
    public String clientAuth;
    public String headerName;
    public String queryParam;
    public List<String> requiredVars;
    public String docsUrl;

    /** The manifest as the reference's plain object: members that are unset are absent. */
    public Map<String, Object> toMap() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("mode", refresh.mode);
        if (refresh.tokenEndpoint != null) r.put("tokenEndpoint", refresh.tokenEndpoint);
        if (refresh.supportsScopeNarrowing != null) r.put("supportsScopeNarrowing", refresh.supportsScopeNarrowing);
        if (refresh.extraParams != null) r.put("extraParams", new LinkedHashMap<String, Object>(refresh.extraParams));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("displayName", displayName);
        m.put("authorizeUrl", authorizeUrl);
        m.put("tokenUrl", tokenUrl);
        m.put("scopesAvailable", new ArrayList<Object>(scopesAvailable));
        m.put("defaultScopes", new ArrayList<Object>(defaultScopes));
        m.put("refresh", r);
        m.put("tokenPlacement", tokenPlacement);
        if (pkce != null) m.put("pkce", pkce);
        if (scopeSeparator != null) m.put("scopeSeparator", scopeSeparator);
        if (authParams != null) m.put("authParams", new LinkedHashMap<String, Object>(authParams));
        if (clientAuth != null) m.put("clientAuth", clientAuth);
        if (headerName != null) m.put("headerName", headerName);
        if (queryParam != null) m.put("queryParam", queryParam);
        if (requiredVars != null) m.put("requiredVars", new ArrayList<Object>(requiredVars));
        if (docsUrl != null) m.put("docsUrl", docsUrl);
        return m;
    }
}
