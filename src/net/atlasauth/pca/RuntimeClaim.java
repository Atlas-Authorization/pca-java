package net.atlasauth.pca;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class. Valid
 * only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
 * {@code verifiedEvidence}), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
 * {@code "none"}. Total.
 */
public final class RuntimeClaim {
    private RuntimeClaim() {}

    public static final String DOMAIN = "atlas-pca/runtime-class-claim/v1\u0000";
    private static final List<String> CLASSES = Arrays.asList("none", "os_confined", "egress_default_deny", "wasi_no_ambient");
    private static final Set<String> KEYS = new HashSet<>(Arrays.asList("v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"));

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    @SuppressWarnings("unchecked")
    public static String verifiedClass(Object v, List<String> pinnedAttestors, String passportDigest, List<String> verifiedEvidence, Object now) {
        try {
            if (!(v instanceof Map)) return "none";
            Map<String, Object> c = (Map<String, Object>) v;
            if (!c.keySet().equals(KEYS) || !Json.isSafeInt(c.get("v")) || Json.asLong(c.get("v")) != 1) return "none";
            if (!(c.get("class") instanceof String) || !CLASSES.contains(c.get("class"))) return "none";
            if (!str(c.get("attestor"), 128) || !str(c.get("passport_digest"), 128) || !str(c.get("evidence_digest"), 128)) return "none";
            if (!nat(c.get("iat")) || !nat(c.get("exp")) || !nat(now)) return "none";
            long t = Json.asLong(now);
            if (!pinnedAttestors.contains(c.get("attestor")) || !passportDigest.equals(c.get("passport_digest")) || !verifiedEvidence.contains(c.get("evidence_digest"))) return "none";
            if (!(Json.asLong(c.get("iat")) <= t && t < Json.asLong(c.get("exp")))) return "none";
            Map<String, Object> body = new LinkedHashMap<>(c);
            body.remove("sig");
            return K3.verifyBody(DOMAIN, body, (String) c.get("attestor"), c.get("sig")) ? (String) c.get("class") : "none";
        } catch (RuntimeException e) {
            return "none";
        }
    }
}
