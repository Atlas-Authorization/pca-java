package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;

/**
 * Grant management resource: list / inspect / amend / revoke and incremental authorization for principals. Nothing widens in place:
 * a widening merge or replace needs a fresh principal signature and a satisfied step-up and creates a NEW grant id with
 * {@code supersedes}. The pure decisions (verifyAmendment, verifyRevokeSignature, verifyNeedApproval, compareAuthority,
 * authorityDigest) are {@link K3}; this class holds the message builders, the store and the service. Records are parsed-JSON maps:
 * a grant is {id, principal, agent, parent?, status, authority, rev, chain_digest, supersedes?, superseded_by?, adjustable?,
 * created_at, history[]}; a need request is {id, grant_id, needs[], status, created_at, result_grant_id?}.
 */
public final class GrantResource {
    private GrantResource() {}

    public static final String GRANT_AMEND_DOMAIN = K3.GRANT_AMEND_DOMAIN;
    public static final String GRANT_REVOKE_DOMAIN = K3.GRANT_REVOKE_DOMAIN;
    public static final String NEED_APPROVE_DOMAIN = K3.NEED_APPROVE_DOMAIN;
    public static final String NEED_REQUEST_DOMAIN = "atlas-pca/need-request/v1\0";
    public static final String GRANT_STEPUP_DOMAIN = "atlas-pca/grant-stepup/v1\0";

    public static String compareAuthority(Object oldA, Object newA) { return K3.compareAuthority(oldA, newA); }

    public static String authorityDigest(Object a) { return K3.authorityDigest(a); }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    public static Map<String, Object> amendMessage(Map<String, Object> g, String action, Object authority) {
        return obj("grant", g.get("id"), "rev", g.get("rev"), "action", action, "authority", authorityDigest(authority));
    }

    public static Map<String, Object> needRequestMessage(String grantId, Object rev, Object needs) { return obj("grant", grantId, "rev", rev, "needs", needs); }

    public static Map<String, Object> stepUpMessage(String grantId, String challengeId, String nonce) { return obj("grant", grantId, "challenge", challengeId, "nonce", nonce); }

    public static Map<String, Object> grantRevokeMessage(String id, String scope) { return obj("grant", id, "scope", scope); }

    public static Map<String, Object> needApproveMessage(Map<String, Object> nr, Object rev, Object approved) {
        return obj("need", nr.get("id"), "grant", nr.get("grant_id"), "rev", rev, "approved", approved);
    }

    public static String signGrantBody(String domain, Object body, net.atlasauth.pca.Keys.EdKey secret) { return Sig.signBody(domain, body, secret); }

    public static final class GrantError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** not_found conflict bad_request not_narrower signature_required bad_signature step_up_required not_active need_not_lowered_only need_not_adjustable forbidden */
        public final String code;

        public GrantError(String code, String message) { super(message); this.code = code; }
    }

    /** Persistence of grants and need requests. Implementations must return copies (a caller mutates what it gets, then puts it back). */
    public interface GrantStore {
        Map<String, Object> get(String id);

        void put(Map<String, Object> g);

        List<Map<String, Object>> list();

        Map<String, Object> getNeed(String id);

        void putNeed(Map<String, Object> n);

        List<Map<String, Object>> listNeeds(String grantId);
    }

    public static final class MemoryGrantStore implements GrantStore {
        private final Map<String, Map<String, Object>> g = new LinkedHashMap<>();
        private final Map<String, Map<String, Object>> n = new LinkedHashMap<>();

        private static Map<String, Object> copy(Map<String, Object> m) { return m == null ? null : Issue.norm(m); }

        @Override public synchronized Map<String, Object> get(String id) { return copy(g.get(id)); }

        @Override public synchronized void put(Map<String, Object> rec) { g.put((String) rec.get("id"), copy(rec)); }

        @Override public synchronized List<Map<String, Object>> list() {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Map<String, Object> x : g.values()) out.add(copy(x));
            return out;
        }

        @Override public synchronized Map<String, Object> getNeed(String id) { return copy(n.get(id)); }

        @Override public synchronized void putNeed(Map<String, Object> rec) { n.put((String) rec.get("id"), copy(rec)); }

        @Override public synchronized List<Map<String, Object>> listNeeds(String grantId) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Map<String, Object> x : n.values()) if (grantId.equals(x.get("grant_id"))) out.add(copy(x));
            return out;
        }
    }

    /** Hooks and providers. Every field except {@code store}, {@code now} and {@code newId} may be null. */
    public static final class Options {
        public GrantStore store;
        public java.util.function.LongSupplier now;
        /** kind is {@code grant} or {@code need}. */
        public Function<String, String> newId;
        public Function<Map<String, Object>, Object> usage, remainingBudget, policyCard, residual;
        /** Confirms a satisfied step-up for a widening change. Absent: widening is refused (fail closed). */
        public StepUp verifyStepUp;
        public OnRevoke onRevoke;
        public OnChange onChange;
        /** Typed validation of a need: an error string refuses. */
        public Function<Map<String, Object>, String> validateNeed;
    }

    @FunctionalInterface public interface StepUp { boolean verify(String ref, Map<String, Object> grant); }

    @FunctionalInterface public interface OnRevoke { void revoked(List<String> ids, String scope, Map<String, Object> root); }

    /** kind: amend | revoke | supersede | need. */
    @FunctionalInterface public interface OnChange { void changed(String kind, Map<String, Object> grant); }

    private static final Map<String, String> FAIL_MESSAGE = new HashMap<>();

    static {
        FAIL_MESSAGE.put("not_found", "no such grant");
        FAIL_MESSAGE.put("conflict", "conflict");
        FAIL_MESSAGE.put("bad_request", "malformed request");
        FAIL_MESSAGE.put("not_narrower", "a narrow amendment must be strictly narrower");
        FAIL_MESSAGE.put("signature_required", "the amendment is signed (by the principal when it widens)");
        FAIL_MESSAGE.put("bad_signature", "the signature does not verify for this grant revision");
        FAIL_MESSAGE.put("step_up_required", "widening needs a satisfied step-up");
        FAIL_MESSAGE.put("not_active", "grant is not active");
        FAIL_MESSAGE.put("need_not_lowered_only", "an approval may only lower amounts of the requested needs");
        FAIL_MESSAGE.put("need_not_adjustable", "the need is not adjustable");
        FAIL_MESSAGE.put("forbidden", "not authorised");
    }

    private static boolean finiteNonNeg(Object v) {
        if (!(v instanceof Number) && !(v instanceof Json.Num)) return false;
        try {
            double d = v instanceof Json.Num ? Double.parseDouble(((Json.Num) v).raw) : ((Number) v).doubleValue();
            return !Double.isNaN(d) && !Double.isInfinite(d) && d >= 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean limitsOk(Object l) {
        Map<String, Object> m = Sig.map(l);
        if (m == null) return false;
        for (Object v : m.values()) if (!finiteNonNeg(v)) return false;
        return true;
    }

    private static void checkAuthority(Object a) {
        Map<String, Object> m = Sig.map(a);
        boolean ok = m != null && m.get("verbs") instanceof List && ((List<?>) m.get("verbs")).size() <= 256 && m.get("resources") instanceof List && ((List<?>) m.get("resources")).size() <= 1024;
        if (ok) for (Object v : (List<?>) m.get("verbs")) ok = ok && Sig.isStr(v, 128);
        if (ok) for (Object v : (List<?>) m.get("resources")) ok = ok && Sig.isStr(v, 512);
        ok = ok && (!m.containsKey("limits") || limitsOk(m.get("limits"))) && (!m.containsKey("expires_at") || Sig.isSafeInt(m.get("expires_at")));
        if (!ok) throw new GrantError("bad_request", "malformed authority");
    }

    private static long n(Object o) { return Json.asLong(o); }

    private static Map<String, Object> hist(long rev, Object authority, long at, String action) {
        return obj("rev", rev, "authority_digest", authorityDigest(authority), "at", at, "action", action);
    }

    /** List filter: any member may be null. */
    public static final class ListFilter {
        public String principal, agent, status;
        public Long limit;
        public String cursor;
    }

    public static final class GrantService {
        private final Options o;

        public GrantService(Options o) { this.o = o; }

        /** Create a grant record: {id, principal, agent, parent?, authority, chain_digest, ...} (status optional, default active). */
        public Map<String, Object> register(Map<String, Object> g) {
            checkAuthority(g.get("authority"));
            if (o.store.get((String) g.get("id")) != null) throw new GrantError("conflict", "grant id exists");
            long now = o.now.getAsLong();
            Map<String, Object> rec = new LinkedHashMap<>(g);
            rec.put("status", g.get("status") != null ? g.get("status") : "active");
            rec.put("rev", 1L);
            rec.put("created_at", now);
            rec.put("history", new ArrayList<Object>(Collections.singletonList(hist(1, g.get("authority"), now, "create"))));
            o.store.put(rec);
            return rec;
        }

        public Map<String, Object> list(ListFilter f) {
            long limit = Math.min(Math.max(f.limit == null ? 50 : f.limit, 1), 200);
            List<Map<String, Object>> all = new ArrayList<>();
            for (Map<String, Object> g : o.store.list()) {
                if ((f.principal == null || f.principal.equals(g.get("principal"))) && (f.agent == null || f.agent.equals(g.get("agent"))) && (f.status == null || f.status.equals(g.get("status")))) all.add(g);
            }
            all.sort((a, b) -> ((String) a.get("id")).compareTo((String) b.get("id")) < 0 ? -1 : 1);
            List<Map<String, Object>> filtered = new ArrayList<>();
            for (Map<String, Object> g : all) if (f.cursor == null || ((String) g.get("id")).compareTo(f.cursor) > 0) filtered.add(g);
            List<Map<String, Object>> page = filtered.subList(0, (int) Math.min(limit, filtered.size()));
            List<Object> views = new ArrayList<>();
            for (Map<String, Object> g : page) views.add(view(g, false));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("grants", views);
            if (filtered.size() > limit) out.put("next_cursor", page.get(page.size() - 1).get("id"));
            return out;
        }

        public Map<String, Object> inspect(String id) { return view(must(id), true); }

        private Map<String, Object> view(Map<String, Object> g, boolean rich) {
            Map<String, Object> v = new LinkedHashMap<>(g);
            v.remove("history");
            v.put("authority_digest", authorityDigest(g.get("authority")));
            List<Object> needs = new ArrayList<>();
            for (Map<String, Object> nr : o.store.listNeeds((String) g.get("id"))) if ("pending".equals(nr.get("status"))) needs.add(nr.get("id"));
            v.put("pending_needs", needs);
            if (rich) {
                put(v, "usage", o.usage, g);
                put(v, "remaining_budget", o.remainingBudget, g);
                put(v, "policy_card", o.policyCard, g);
                put(v, "residual", o.residual, g);
            }
            return v;
        }

        private static void put(Map<String, Object> v, String k, Function<Map<String, Object>, Object> p, Map<String, Object> g) {
            if (p == null) return;
            Object r = p.apply(g);
            if (r != null) v.put(k, r); // a provider with nothing to report returns null (the reference's undefined, dropped from JSON)
        }

        private Map<String, Object> must(String id) {
            Map<String, Object> g = o.store.get(id);
            if (g == null) throw new GrantError("not_found", "no such grant");
            return g;
        }

        private static boolean truthy(Object v) { return v instanceof String ? !((String) v).isEmpty() : v != null && !Boolean.FALSE.equals(v); }

        /** Amend; returns {grant, created}. {@code req} = {action, authority, sig?, signed_by?, step_up_ref?}. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> amend(String id, Map<String, Object> req) {
            Map<String, Object> cur = must(id);
            K3.AmendVerdict v = K3.verifyAmendment(cur, req, false);
            // Evaluate the (possibly consuming) step-up only when everything else already passed.
            if (!v.ok && "step_up_required".equals(v.code) && truthy(req.get("step_up_ref")) && o.verifyStepUp != null && o.verifyStepUp.verify(String.valueOf(req.get("step_up_ref")), cur)) v = K3.verifyAmendment(cur, req, true);
            if (!v.ok) throw new GrantError(v.code, FAIL_MESSAGE.get(v.code));
            long now = o.now.getAsLong();
            if (!v.widens) {
                cur.put("authority", v.next);
                long rev = n(cur.get("rev")) + 1;
                cur.put("rev", rev);
                ((List<Object>) cur.get("history")).add(hist(rev, v.next, now, (String) req.get("action")));
                o.store.put(cur);
                if (o.onChange != null) o.onChange.changed("amend", cur);
                return obj("grant", view(cur, true), "created", false);
            }
            String nid = o.newId.apply("grant");
            Map<String, Object> fresh = new LinkedHashMap<>(cur);
            fresh.put("id", nid);
            fresh.put("authority", v.next);
            fresh.put("rev", 1L);
            fresh.put("status", "active");
            fresh.put("supersedes", cur.get("id"));
            fresh.put("created_at", now);
            fresh.put("history", new ArrayList<Object>(Collections.singletonList(hist(1, v.next, now, "supersedes:" + cur.get("id")))));
            fresh.remove("superseded_by");
            cur.put("status", "superseded");
            cur.put("superseded_by", nid);
            o.store.put(fresh);
            o.store.put(cur);
            if (o.onChange != null) o.onChange.changed("supersede", fresh);
            return obj("grant", view(fresh, true), "created", true);
        }

        /**
         * Revoke, authorised by the principal's signature over {grant id, scope} ({@code sig} non-null) or by a host-authenticated admin
         * ({@code sig} null and {@code admin} true). Returns {revoked: [ids]}.
         */
        @SuppressWarnings("unchecked")
        public Map<String, Object> revoke(String id, String scope, String sig, boolean admin) {
            if (!"grant".equals(scope) && !"agent".equals(scope) && !"subtree".equals(scope)) throw new GrantError("bad_request", "unknown scope");
            Map<String, Object> root = must(id);
            if (sig != null) {
                K3.RevokeVerdict rv = K3.verifyRevokeSignature(root, scope, sig);
                if (!rv.ok) throw new GrantError(rv.code, FAIL_MESSAGE.get(rv.code));
            } else if (!admin) throw new GrantError("forbidden", "not authorised");
            List<Map<String, Object>> all = o.store.list();
            List<Map<String, Object>> hit = new ArrayList<>();
            if ("grant".equals(scope)) hit.add(root);
            else if ("agent".equals(scope)) {
                for (Map<String, Object> g : all) if (java.util.Objects.equals(g.get("agent"), root.get("agent")) && java.util.Objects.equals(g.get("principal"), root.get("principal"))) hit.add(g);
            } else {
                Set<Object> ids = new HashSet<>(Collections.singletonList(id));
                for (boolean grew = true; grew; ) {
                    grew = false;
                    for (Map<String, Object> g : all) if (g.get("parent") != null && ids.contains(g.get("parent")) && !ids.contains(g.get("id"))) { ids.add(g.get("id")); grew = true; }
                }
                for (Map<String, Object> g : all) if (ids.contains(g.get("id"))) hit.add(g);
            }
            List<String> revoked = new ArrayList<>();
            for (Map<String, Object> g : hit) {
                if ("revoked".equals(g.get("status"))) continue;
                g.put("status", "revoked");
                ((List<Object>) g.get("history")).add(hist(n(g.get("rev")), g.get("authority"), o.now.getAsLong(), "revoke:" + scope));
                o.store.put(g);
                revoked.add((String) g.get("id"));
            }
            if (o.onRevoke != null) o.onRevoke.revoked(revoked, scope, root);
            if (o.onChange != null) o.onChange.changed("revoke", root);
            return obj("revoked", new ArrayList<Object>(revoked));
        }

        /** Agent side: ask for more. Typed needs only; no authority changes until the principal approves. */
        public Map<String, Object> requestNeeds(String grantId, Object needs) {
            Map<String, Object> g = must(grantId);
            if (!"active".equals(g.get("status"))) throw new GrantError("not_active", "grant is " + g.get("status"));
            if (!(needs instanceof List) || ((List<?>) needs).size() < 1 || ((List<?>) needs).size() > 32) throw new GrantError("bad_request", "1..32 needs");
            for (Object no : (List<?>) needs) {
                Map<String, Object> nd = Sig.map(no);
                if (nd == null || !Sig.isStr(nd.get("verb"), 128) || !Sig.isStr(nd.get("resource"), 512) || (nd.get("limits") != null && !limitsOk(nd.get("limits")))) throw new GrantError("bad_request", "malformed need");
                if (o.validateNeed != null) {
                    String e = o.validateNeed.apply(nd);
                    if (e != null && !e.isEmpty()) throw new GrantError("bad_request", e);
                }
            }
            Map<String, Object> nr = obj("id", o.newId.apply("need"), "grant_id", grantId, "needs", Issue.norm(needs), "status", "pending", "created_at", o.now.getAsLong());
            o.store.putNeed(nr);
            if (o.onChange != null) o.onChange.changed("need", g);
            return nr;
        }

        /** Principal side: approve the delta (a widening merge). Returns {grant, created}. */
        public Map<String, Object> approveNeeds(String needId, Object approved, String sig, String stepUpRef) {
            Map<String, Object> nr = o.store.getNeed(needId);
            if (nr == null) throw new GrantError("not_found", "no such need request");
            if (!"pending".equals(nr.get("status"))) throw new GrantError("conflict", "need request is " + nr.get("status"));
            Map<String, Object> g = must((String) nr.get("grant_id"));
            K3.NeedVerdict v = K3.verifyNeedApproval(nr, g, approved, sig, false);
            if (!v.ok && "step_up_required".equals(v.code) && stepUpRef != null && !stepUpRef.isEmpty() && o.verifyStepUp != null && o.verifyStepUp.verify(stepUpRef, g)) v = K3.verifyNeedApproval(nr, g, approved, sig, true);
            if (!v.ok) throw new GrantError(v.code, FAIL_MESSAGE.get(v.code));
            String nid = o.newId.apply("grant");
            long now = o.now.getAsLong();
            Map<String, Object> fresh = new LinkedHashMap<>(g);
            fresh.put("id", nid);
            fresh.put("authority", v.authority);
            fresh.put("rev", 1L);
            fresh.put("status", "active");
            fresh.put("supersedes", g.get("id"));
            fresh.put("created_at", now);
            fresh.put("history", new ArrayList<Object>(Collections.singletonList(hist(1, v.authority, now, "needs:" + needId))));
            fresh.remove("superseded_by");
            g.put("status", "superseded");
            g.put("superseded_by", nid);
            nr.put("status", "approved");
            nr.put("result_grant_id", nid);
            o.store.put(fresh);
            o.store.put(g);
            o.store.putNeed(nr);
            if (o.onChange != null) o.onChange.changed("supersede", fresh);
            return obj("grant", view(fresh, true), "created", true);
        }

        /** The grant a need request belongs to. */
        public String needGrantId(String needId) {
            Map<String, Object> nr = o.store.getNeed(needId);
            if (nr == null) throw new GrantError("not_found", "no such need request");
            return (String) nr.get("grant_id");
        }

        public void denyNeeds(String needId) {
            Map<String, Object> nr = o.store.getNeed(needId);
            if (nr == null) throw new GrantError("not_found", "no such need request");
            if (!"pending".equals(nr.get("status"))) throw new GrantError("conflict", "need request is " + nr.get("status"));
            nr.put("status", "denied");
            o.store.putNeed(nr);
        }
    }
}
