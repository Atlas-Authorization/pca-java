package net.atlasauth.pca.grants;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/** Domain-separated Ed25519 signature over strict-canonical JSON, shared by every signed artifact of the grants package. */
public final class Sig {
    private Sig() {}

    public static String signerOf(Keys.EdKey secret) { return GrantSigning.signerOf(secret); }

    public static String signBody(String domain, Object body, Keys.EdKey secret) { return GrantSigning.signBody(domain, body, secret); }

    /** True iff {@code sig} is a canonical 64-byte b64u signature by {@code signer} over exactly {@code body}. Never throws. */
    public static boolean verifyBody(String domain, Object body, String signer, Object sig) { return GrantSigning.verifyBody(domain, body, signer, sig); }

    /** A safe non-negative integer (not -0). */
    public static boolean isSafeInt(Object n) { return Json.isSafeInt(n) && Json.asLong(n) >= 0; }

    public static boolean isObj(Object x) { return x instanceof Map; }

    /** A non-empty string of at most {@code max} UTF-16 units. */
    public static boolean isStr(Object x, int max) { return x instanceof String && !((String) x).isEmpty() && ((String) x).length() <= max; }

    public static boolean isStr(Object x) { return isStr(x, 512); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) { return o instanceof List ? (List<Object>) o : null; }
}
