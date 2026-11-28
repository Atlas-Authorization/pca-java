package net.atlasauth.pca.revoke;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A stored revocation. kind is one of cap / holder / issuer / prefix; value is the canonical key (for prefix the comma-joined
 * path); notBefore (epoch ms, nullable) is the time before which the revocation does not yet bite.
 */
public final class RevocationEntry {
    public final String kind;
    public final String value;
    /** For kind prefix only: the ordered cap-id path (else null). */
    public final List<String> prefix;
    public final String reason;
    /** Epoch ms the revocation was recorded (metadata; does not gate when it bites). */
    public final double revokedAt;
    public final Double notBefore;

    public RevocationEntry(String kind, String value, List<String> prefix, String reason, double revokedAt, Double notBefore) {
        this.kind = kind;
        this.value = value;
        this.prefix = prefix == null ? null : Collections.unmodifiableList(new ArrayList<>(prefix));
        this.reason = reason;
        this.revokedAt = revokedAt;
        this.notBefore = notBefore;
    }

    /** The JSON form (the reference's entry object). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (kind != null) m.put("kind", kind);
        m.put("value", value);
        if (prefix != null) m.put("prefix", new ArrayList<Object>(prefix));
        m.put("reason", reason);
        m.put("revokedAt", JsVal.numOf(revokedAt));
        if (notBefore != null) m.put("notBefore", JsVal.numOf(notBefore));
        return m;
    }
}
