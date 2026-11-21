package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Lease;
import net.atlasauth.pca.grants.GrantHttp.Request;
import net.atlasauth.pca.grants.GrantHttp.Response;

/**
 * Hosted lease routes (framework-neutral, same shape as the grant resource). The server only stores records the lease authority already
 * signed; it never mints one, so a compromised host cannot extend a lease.
 * <pre>
 *   POST /pca/leases             body {lease, chain?}   issue (seq 1) or renew (seq n+1)
 *   GET  /pca/leases/:id                                the newest record and its renewal ledger
 *   POST /pca/leases/:id/check   body {lease}           is this record a live lease
 *   POST /pca/leases/revoke      body {revocation}      a signed revoke by lease, prefix or grant
 * </pre>
 */
public final class LeaseHttp {
    private LeaseHttp() {}

    public static final String LEASES_PATH = "/pca/leases";

    /** Who is calling; a non-admin sees and checks only leases it holds. */
    public static final class Caller {
        public final boolean admin;
        public final String principal;

        public Caller(boolean admin, String principal) { this.admin = admin; this.principal = principal; }
    }

    @FunctionalInterface
    public interface Authenticate { Caller authenticate(Request req) throws Exception; }

    private static final Map<String, Integer> STATUS = new HashMap<>();

    static {
        STATUS.put("bad_record", 400); STATUS.put("bad_seq", 409); STATUS.put("stale_seq", 409); STATUS.put("lease_fork", 409); STATUS.put("renewal_mismatch", 422);
        STATUS.put("over_max_ttl", 422); STATUS.put("ttl_ceiling", 422); STATUS.put("not_extending", 422); STATUS.put("stale_justification", 422);
        STATUS.put("expired_lease", 409); STATUS.put("revoked", 409); STATUS.put("sod", 403); STATUS.put("unknown_authority", 403); STATUS.put("store_unreachable", 503);
    }

    public static Map<String, Object> leaseManagementMetadata(String base) {
        return GrantHttp.obj("leases", GrantHttp.obj("leases_endpoint", base + LEASES_PATH, "revoke_targets", new ArrayList<Object>(Arrays.asList("lease", "prefix", "grant"))));
    }

    /**
     * The lease routes over {@code reg}. A refused accept carries the reference's {@code message}: for {@code sod} the separation-of-duties
     * rule that failed, derived with the default policy (any approver, one needed); pass the registry's own policy to the four-argument
     * form when it sets {@code minApprovals} / {@code eligibleApprovers}, so the reason names the right rule.
     */
    public static GrantHttp.Handler leaseResourceHandler(Lease.Registry reg, Authenticate authenticate, LongSupplier now) {
        return leaseResourceHandler(reg, authenticate, now, null);
    }

    @SuppressWarnings("unchecked")
    private static String acceptMessage(Lease.Registry reg, Lease.Policy policy, String code, Object lease, List<String> chain) {
        try {
            Map<String, Object> l = Sig.map(lease);
            if (l == null) return null;
            if (code.equals("sod")) return Lease.sodError(l, policy != null ? policy : new Lease.Policy(new ArrayList<>()), chain);
            if (code.equals("bad_seq")) return reg.get((String) l.get("lease_id")) == null ? "a new lease starts at seq 1" : "renewals advance seq by exactly 1";
            if (code.equals("expired_lease")) return "an expired lease cannot be renewed";
        } catch (RuntimeException e) {
            return null; // the message is display-only
        }
        return null;
    }

    public static GrantHttp.Handler leaseResourceHandler(Lease.Registry reg, Authenticate authenticate, LongSupplier now, Lease.Policy policy) {
        LongSupplier clock = now != null ? now : System::currentTimeMillis;
        return req -> {
            try {
                Caller who = authenticate.authenticate(req);
                if (who == null || (!who.admin && (who.principal == null || who.principal.isEmpty()))) return new Response(401, GrantHttp.obj("error", "unauthenticated"));
                List<String> seg = new ArrayList<>();
                for (String p : req.path.split("/")) if (!p.isEmpty()) seg.add(p);
                Map<String, Object> b = Sig.map(req.body) != null ? Sig.map(req.body) : new java.util.LinkedHashMap<String, Object>();
                if (seg.size() < 2 || !seg.get(0).equals("pca") || !seg.get(1).equals("leases")) return new Response(404, GrantHttp.obj("error", "not_found"));
                if (seg.size() == 2 && req.method.equals("POST")) {
                    if (!who.admin) return new Response(403, GrantHttp.obj("error", "forbidden"));
                    List<String> chain = new ArrayList<>();
                    if (b.get("chain") instanceof List) {
                        boolean allStr = true;
                        for (Object x : (List<?>) b.get("chain")) allStr = allStr && x instanceof String;
                        if (allStr) for (Object x : (List<?>) b.get("chain")) chain.add((String) x);
                    }
                    Lease.Accept r = reg.accept(b.get("lease"), chain);
                    if (r.code == null) return new Response(r.replaced ? 201 : 200, GrantHttp.obj("ok", true, "replaced", r.replaced, "seq", r.seq));
                    Integer st = STATUS.get(r.code);
                    Map<String, Object> err = GrantHttp.obj("error", r.code);
                    String msg = acceptMessage(reg, policy, r.code, b.get("lease"), chain);
                    if (msg != null && !msg.isEmpty()) err.put("message", msg);
                    return new Response(st != null ? st : 400, err);
                }
                if (seg.size() == 3 && seg.get(2).equals("revoke") && req.method.equals("POST")) {
                    if (!who.admin) return new Response(403, GrantHttp.obj("error", "forbidden"));
                    Lease.Revoke r = reg.revoke(b.get("revocation"));
                    if (r.code == null) return new Response(200, GrantHttp.obj("ok", true, "revoked", (long) r.revoked));
                    return new Response(r.code.equals("store_unreachable") ? 503 : r.code.equals("unknown_authority") ? 403 : 400, GrantHttp.obj("error", r.code));
                }
                String id = seg.size() > 2 ? seg.get(2) : null;
                if (id == null) return new Response(404, GrantHttp.obj("error", "not_found"));
                if (seg.size() == 3 && req.method.equals("GET")) {
                    Map<String, Object> cur = reg.get(id);
                    if (cur == null || !visible(who, cur)) return new Response(404, GrantHttp.obj("error", "not_found"));
                    return new Response(200, GrantHttp.obj("lease", cur, "history", reg.history(id)));
                }
                if (seg.size() == 4 && seg.get(3).equals("check") && req.method.equals("POST")) {
                    Map<String, Object> cur = reg.get(id);
                    if (cur == null || !visible(who, cur)) return new Response(404, GrantHttp.obj("error", "not_found"));
                    Lease.Decision d = reg.check(b.get("lease"), clock.getAsLong());
                    Map<String, Object> body = GrantHttp.obj("decision", d.decision);
                    if (d.code != null) body.put("code", d.code);
                    if (d.leaseId != null) body.put("lease_id", d.leaseId);
                    if (d.expiresAt != null) body.put("expires_at", d.expiresAt);
                    return new Response(d.decision.equals("allow") ? 200 : 403, body);
                }
                return new Response(404, GrantHttp.obj("error", "not_found"));
            } catch (Exception e) {
                return new Response(500, GrantHttp.obj("error", "server_error"));
            }
        };
    }

    // a lease belongs to its holder: a non-admin sees and checks only leases it holds
    private static boolean visible(Caller who, Map<String, Object> lease) { return who.admin || java.util.Objects.equals(who.principal, lease.get("holder")); }
}
