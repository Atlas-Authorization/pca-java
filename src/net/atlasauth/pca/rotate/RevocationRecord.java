package net.atlasauth.pca.rotate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/**
 * A record naming a key / capability / subtree as revoked, for a revocation registry. Only reason and revokedAt are always
 * present; the identifying fields are set to whatever the rotation knows (null when unknown).
 */
public final class RevocationRecord {
    /** The capability id being revoked (the subtree root for a subtree revocation). */
    public final String capId;
    /** The b64u holder key whose authority is revoked. */
    public final String holder;
    /** The b64u issuer key that signed the revoked capability. */
    public final String issuer;
    /** The capability id at the top of a revoked subtree. */
    public final String subtreeRoot;
    /** Every capability id this record covers. */
    public final List<String> capIds;
    public final String reason;
    /** Epoch ms the revocation was recorded. */
    public final double revokedAt;

    public RevocationRecord(String capId, String holder, String issuer, String subtreeRoot, List<String> capIds, String reason, double revokedAt) {
        this.capId = capId;
        this.holder = holder;
        this.issuer = issuer;
        this.subtreeRoot = subtreeRoot;
        this.capIds = capIds == null ? null : new ArrayList<>(capIds);
        this.reason = reason;
        this.revokedAt = revokedAt;
    }

    /** The JSON form (the reference's record object). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (capId != null) m.put("capId", capId);
        if (holder != null) m.put("holder", holder);
        if (issuer != null) m.put("issuer", issuer);
        if (subtreeRoot != null) m.put("subtreeRoot", subtreeRoot);
        if (capIds != null) m.put("capIds", new ArrayList<Object>(capIds));
        m.put("reason", reason);
        m.put("revokedAt", JsVal.numOf(revokedAt));
        return m;
    }
}
