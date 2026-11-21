package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.connectors.Manifest;
import net.atlasauth.pca.connectors.ProviderManifest;
import net.atlasauth.pca.connectors.ProviderRegistry;
import net.atlasauth.pca.connectors.Providers;
import org.junit.jupiter.api.Test;

/** The seeded provider catalog against the reference corpus (ref-connectors-providers, 40 cases): each constant, its invariants, the catalog order and digest, and ids outside it. */
class ConnectorsProvidersRefDiffTest {
    static final String MODULE = "ref-connectors-providers";
    static final int TOTAL = 40;

    private static Object arg(List<?> a, int i) { return a.get(i); }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) { return (List<String>) o; }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("provider", x -> {
            ProviderManifest m = Providers.byId((String) arg(x, 0));
            return Issue.obj("manifest", m.toMap(), "digest", Manifest.manifestDigest(m), "valid", Manifest.validateManifest(m.toMap()).ok);
        });
        f.put("invariants", x -> {
            ProviderManifest p = Providers.byId((String) arg(x, 0));
            Map<String, Object> m = p.toMap();
            Set<String> avail = new HashSet<>(strings(m.get("scopesAvailable")));
            return Issue.obj("defaultScopesSubset", avail.containsAll(strings(m.get("defaultScopes"))),
                "scopesUnique", avail.size() == strings(m.get("scopesAvailable")).size(),
                "idMatchesKey", p.id.equals(arg(x, 0)),
                "httpsEndpoints", p.authorizeUrl.startsWith("https://") && p.tokenUrl.startsWith("https://"));
        });
        f.put("builtinManifests", x -> {
            List<Object> ids = new ArrayList<>(), digests = new ArrayList<>();
            for (ProviderManifest m : Providers.BUILTIN_MANIFESTS) { ids.add(m.id); digests.add(Manifest.manifestDigest(m)); }
            return Issue.obj("ids", ids, "digests", digests, "catalogDigest", ProviderRegistry.catalogDigest());
        });
        f.put("unknownProvider", x -> Issue.obj("found", ProviderRegistry.getProvider((String) arg(x, 0)) != null));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
