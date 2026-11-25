package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Lease;

/** Authority-side lease operations. Verification, the registry and the live check are {@link Lease}; signing is {@link GrantSigning#signLease}. */
public final class Leases {
    private Leases() {}

    /** Renewal options. {@code veto} can only REFUSE a renewal, never lengthen the lease. Null members are absent. */
    public static final class RenewOptions {
        public Object now;
        /** Advisory increment from now; the new expiry is capped at issued_at + max_ttl. */
        public Object increment;
        public String justificationDigest;
        public List<Object> approvers;
        public Predicate<Map<String, Object>> veto;
        public List<String> chain;
    }

    private static Map<String, Object> res(boolean ok, String code, Map<String, Object> record) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (ok) m.put("record", record); else m.put("code", code);
        return m;
    }

    /** Sign and register the next record of a lease. Returns {ok:true, record} or {ok:false, code}. */
    public static Map<String, Object> renewLease(Keys.EdKey secret, Lease.Registry registry, String id, RenewOptions o) {
        if (!Sig.isSafeInt(o.now) || !Sig.isSafeInt(o.increment) || Json.asLong(o.increment) < 1) return res(false, "bad_input", null);
        Map<String, Object> cur = registry.get(id);
        if (cur == null) return res(false, "unknown_lease", null);
        if (o.veto != null && o.veto.test(cur)) return res(false, "vetoed", null);
        long now = Json.asLong(o.now);
        long cap = Json.asLong(cur.get("issued_at")) + Json.asLong(cur.get("max_ttl"));
        long expires = Math.min(now + Json.asLong(o.increment), cap);
        Map<String, Object> rest = new LinkedHashMap<>(cur);
        rest.remove("v");
        rest.remove("sig");
        rest.remove("authority");
        rest.put("seq", Json.asLong(cur.get("seq")) + 1);
        rest.put("renewed_at", now);
        rest.put("expires_at", expires);
        rest.put("justification_digest", o.justificationDigest);
        rest.put("approvers", o.approvers != null ? o.approvers : cur.get("approvers"));
        Map<String, Object> record;
        try {
            record = GrantSigning.signLease(secret, rest);
        } catch (RuntimeException e) {
            return res(false, expires <= now ? "expired_lease" : "bad_input", null);
        }
        Lease.Accept r = registry.accept(record, o.chain != null ? o.chain : new ArrayList<String>());
        return r.code == null ? res(true, null, record) : res(false, r.code, null);
    }
}
