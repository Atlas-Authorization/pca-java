package net.atlasauth.pca;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.erc7715.Erc7715;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the ERC-7715 permission mapping and verification through the native port. */
public class Erc7715DiffTest {
    private static final String M = "ref-erc7715";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** The reference takes the chain as a bigint: it crosses as a decimal string and becomes a BigInteger. */
    private static Map<String, Object> withChain(Object o) {
        Map<String, Object> x = new LinkedHashMap<>(m(o));
        if (x.get("chainId") instanceof String) x.put("chainId", new BigInteger((String) x.get("chainId")));
        return x;
    }

    @Test void grantToPermissionRequest() throws Exception { OracleCases.each(M, "grantToPermissionRequest", a -> Erc7715.grantToPermissionRequest(m(a.get(0)), withChain(a.get(1)))); }
    @Test void supportsRequest() throws Exception { OracleCases.each(M, "supportsRequest", a -> Erc7715.supportsRequest(a.get(0), a.get(1))); }
    @Test void revokeParams() throws Exception { OracleCases.each(M, "revokeParams", a -> a.isEmpty() ? new LinkedHashMap<String, Object>() : Erc7715.revokeParams(a.get(0))); }

    @Test void verifyGrantedPermission() throws Exception {
        OracleCases.each(M, "verifyGrantedPermission", a -> {
            Map<String, Object> x = m(a.get(3));
            Erc7715.Options o = new Erc7715.Options();
            o.allowedManagers = x.get("allowedManagers");
            if (x.get("owners") instanceof Map) { final Map<String, Object> owners = m(x.get("owners")); o.contextOwner = ctx -> owners.get(ctx); }
            return Erc7715.verifyGrantedPermission(a.get(0), a.get(1), a.get(2), o);
        });
    }

    @Test void grantDigestOf() throws Exception { OracleCases.each(M, "grantDigestOf", a -> Erc7715.grantDigestOf(a.get(0))); }
}
