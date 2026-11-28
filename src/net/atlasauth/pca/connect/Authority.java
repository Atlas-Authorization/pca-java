package net.atlasauth.pca.connect;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The capability caveat that grants outbound OAuth authority. It is pure data inside the signed capability body, so it is
 * attenuable: a delegation hop may add a narrower {@code oauth_scope} for the same provider, which can only shrink the
 * effective grant (intersection), never widen it.
 */
public final class Authority {
    private Authority() {}

    public static final String OAUTH_SCOPE_CAVEAT = "oauth_scope";

    /** An {@code oauth_scope} caveat granting {@code scopes} on {@code provider}; duplicate scopes are collapsed (first occurrence kept). */
    public static Map<String, Object> oauthScopeCaveat(String provider, List<String> scopes) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", OAUTH_SCOPE_CAVEAT);
        m.put("provider", provider);
        m.put("scopes", new java.util.ArrayList<Object>(new LinkedHashSet<>(scopes)));
        return m;
    }

    private static boolean isStringArray(Object v) {
        if (!(v instanceof List)) return false;
        for (Object x : (List<?>) v) if (!(x instanceof String)) return false;
        return true;
    }

    public static boolean isOAuthScopeCaveat(Object cv) {
        if (!(cv instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) cv;
        if (!m.containsKey("type") || !m.containsKey("provider") || !m.containsKey("scopes")) return false;
        return OAUTH_SCOPE_CAVEAT.equals(m.get("type")) && m.get("provider") instanceof String && isStringArray(m.get("scopes"));
    }

    /**
     * The effective OAuth scopes a verified capability chain grants for {@code provider}: the intersection of every
     * {@code oauth_scope} caveat naming it in the chain's leaf. Null when the chain grants nothing for the provider (so the vault can
     * tell "not covered" from "covered but too narrow"). Run the chain verification first; this only reads the signed caveat lineage.
     */
    public static Set<String> grantedOAuthScopes(Object chain, String provider) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return null;
        List<?> c = (List<?>) chain;
        Object leaf = c.get(c.size() - 1);
        if (leaf == null) throw new NullPointerException("capability chain leaf is null"); // the reference reads leaf.caveats and throws a TypeError
        if (!(leaf instanceof Map) || !(((Map<?, ?>) leaf).get("caveats") instanceof List)) return null;
        Set<String> effective = null;
        for (Object cv : (List<?>) ((Map<?, ?>) leaf).get("caveats")) {
            if (!isOAuthScopeCaveat(cv) || !provider.equals(((Map<?, ?>) cv).get("provider"))) continue;
            Set<String> here = new LinkedHashSet<>();
            for (Object s : (List<?>) ((Map<?, ?>) cv).get("scopes")) here.add((String) s);
            if (effective == null) effective = here;
            else {
                Set<String> inter = new LinkedHashSet<>();
                for (String s : effective) if (here.contains(s)) inter.add(s);
                effective = inter;
            }
        }
        return effective;
    }
}
