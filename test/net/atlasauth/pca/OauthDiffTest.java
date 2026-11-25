package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.oauth.Oauth;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the OAuth / MCP-authorization bridge through the native port. */
public class OauthDiffTest {
    private static final String M = "ref-oauth";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> opt(List<?> a, int i) { return a.size() > i ? m(a.get(i)) : null; }

    @Test void resourceIdentifierProblem() throws Exception { OracleCases.each(M, "resourceIdentifierProblem", a -> Oauth.resourceIdentifierProblem(a.get(0))); }
    @Test void prmPathForResource() throws Exception { OracleCases.each(M, "prmPathForResource", a -> Oauth.prmPathForResource((String) a.get(0))); }
    @Test void prmUrlForResource() throws Exception { OracleCases.each(M, "prmUrlForResource", a -> Oauth.prmUrlForResource((String) a.get(0))); }
    @Test void protectedResourceMetadata() throws Exception { OracleCases.each(M, "protectedResourceMetadata", a -> Oauth.protectedResourceMetadata(m(a.get(0)))); }
    @Test void oauthDiscoveryHandler() throws Exception { OracleCases.each(M, "oauthDiscoveryHandler", a -> Oauth.oauthDiscoveryHandler(m(a.get(0)))); }
    @Test void parseProtectedResourceMetadata() throws Exception { OracleCases.each(M, "parseProtectedResourceMetadata", a -> Oauth.parseProtectedResourceMetadata(a.get(0), opt(a, 1))); }
    @Test void wwwAuthenticate() throws Exception { OracleCases.each(M, "wwwAuthenticate", a -> Oauth.wwwAuthenticate((String) a.get(0), opt(a, 1))); }
    @Test void mcpUnauthorized() throws Exception { OracleCases.each(M, "mcpUnauthorized", a -> Oauth.mcpUnauthorized((String) a.get(0), opt(a, 1))); }
    @Test void upgradeUnauthorizedChallenge() throws Exception { OracleCases.each(M, "upgradeUnauthorizedChallenge", a -> Oauth.upgradeUnauthorizedChallenge(m(a.get(0)), (String) a.get(1), opt(a, 2))); }
    @Test void checkResourceIndicator() throws Exception { OracleCases.each(M, "checkResourceIndicator", a -> Oauth.checkResourceIndicator(a.get(0), (String) a.get(1))); }
    @Test void checkTokenAudience() throws Exception { OracleCases.each(M, "checkTokenAudience", a -> Oauth.checkTokenAudience(a.get(0), (String) a.get(1))); }
    @Test void buildPcaGrantDetail() throws Exception { OracleCases.each(M, "buildPcaGrantDetail", a -> Oauth.buildPcaGrantDetail(m(a.get(0)))); }
    @SuppressWarnings("unchecked")
    @Test void pcaGrantRequestParam() throws Exception { OracleCases.each(M, "pcaGrantRequestParam", a -> Oauth.pcaGrantRequestParam((List<Object>) a.get(0))); }
    @Test void authorizePcaGrantToken() throws Exception { OracleCases.each(M, "authorizePcaGrantToken", a -> Oauth.authorizePcaGrantToken(m(a.get(0)))); }
    @Test void oauthScopeForAction() throws Exception { OracleCases.each(M, "oauthScopeForAction", a -> Oauth.oauthScopeForAction(a.get(0), m(a.get(1)))); }
}
