package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import net.atlasauth.pca.grants.GrantResource.GrantError;
import net.atlasauth.pca.grants.GrantResource.GrantService;

/** Framework-neutral HTTP binding of the grant management resource: plain request and response objects, no servlet dependency. */
public final class GrantHttp {
    private GrantHttp() {}

    public static final String GRANTS_PATH = "/pca/grants";
    public static final String NEEDS_PATH = "/pca/needs";

    /** {@code path} is the path below the mount point (for example {@code /pca/grants/g_1/amend}); {@code body} is a parsed JSON value or null. */
    public static final class Request {
        public final String method;
        public final String path;
        public final Map<String, String> query;
        public final Object body;

        public Request(String method, String path, Map<String, String> query, Object body) {
            this.method = method;
            this.path = path;
            this.query = query == null ? new HashMap<String, String>() : query;
            this.body = body;
        }
    }

    public static final class Response {
        public final int status;
        public final Object body;

        public Response(int status, Object body) { this.status = status; this.body = body; }
    }

    /** Who is calling, as the host authenticated them. {@code principal} limits every read and write to that principal's grants. */
    public static final class Caller {
        public final String principal;
        public final boolean admin;

        public Caller(String principal, boolean admin) { this.principal = principal; this.admin = admin; }
    }

    @FunctionalInterface
    public interface Authenticate { Caller authenticate(Request req) throws Exception; }

    @FunctionalInterface
    public interface Handler { Response handle(Request req); }

    private static final Map<String, Integer> STATUS = new HashMap<>();

    static {
        STATUS.put("not_found", 404); STATUS.put("conflict", 409); STATUS.put("bad_request", 400); STATUS.put("not_narrower", 422);
        STATUS.put("signature_required", 401); STATUS.put("bad_signature", 401); STATUS.put("step_up_required", 403); STATUS.put("not_active", 409);
        STATUS.put("need_not_lowered_only", 422); STATUS.put("need_not_adjustable", 422); STATUS.put("forbidden", 403);
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static Response err(Exception e) {
        if (e instanceof GrantError) return new Response(STATUS.get(((GrantError) e).code), obj("error", ((GrantError) e).code, "message", e.getMessage()));
        return new Response(500, obj("error", "server_error"));
    }

    /** Discovery fragment for {@code /.well-known/pca-configuration}. */
    public static Map<String, Object> grantManagementMetadata(String base) {
        return obj("grant_management", obj(
            "grants_endpoint", base + GRANTS_PATH, "needs_endpoint", base + NEEDS_PATH,
            "amend_actions", new ArrayList<Object>(Arrays.asList("narrow", "merge", "replace")),
            "revoke_scopes", new ArrayList<Object>(Arrays.asList("grant", "agent", "subtree")),
            "widening", "new_grant_id_with_supersedes"));
    }

    private static final Pattern JS_NUMBER = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    /** JavaScript {@code Number(s)} for a decimal string; NaN when it is not one (hex, binary and other forms are not recognised). */
    static double jsNumber(String s) {
        String t = s.trim();
        if (t.isEmpty()) return 0;
        if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        return JS_NUMBER.matcher(t).matches() ? Double.parseDouble(t) : Double.NaN;
    }

    private static List<String> segments(String path) {
        List<String> out = new ArrayList<>();
        for (String p : path.split("/")) if (!p.isEmpty()) out.add(p);
        return out;
    }

    private static boolean has(String s) { return s != null && !s.isEmpty(); }

    public static Handler grantResourceHandler(GrantService svc, Authenticate authenticate) {
        return req -> {
            try {
                Caller who = authenticate.authenticate(req);
                if (who == null || (!who.admin && !has(who.principal))) return new Response(401, obj("error", "unauthenticated"));
                List<String> seg = segments(req.path);
                Map<String, String> q = req.query;
                Map<String, Object> b = Sig.map(req.body) != null ? Sig.map(req.body) : new LinkedHashMap<String, Object>();
                if (seg.isEmpty() || !seg.get(0).equals("pca")) return new Response(404, obj("error", "not_found"));
                String s1 = seg.size() > 1 ? seg.get(1) : null;
                String s2 = seg.size() > 2 ? seg.get(2) : null;
                String s3 = seg.size() > 3 ? seg.get(3) : null;
                if ("grants".equals(s1)) {
                    if (seg.size() == 2 && req.method.equals("GET")) {
                        String status = q.get("status");
                        if (status != null && !status.equals("active") && !status.equals("revoked") && !status.equals("superseded")) throw new GrantError("bad_request", "bad status");
                        GrantResource.ListFilter f = new GrantResource.ListFilter();
                        String principal = who.admin ? q.get("principal") : who.principal;
                        if (has(principal)) f.principal = principal;
                        if (has(q.get("agent"))) f.agent = q.get("agent");
                        if (has(status)) f.status = status;
                        if (q.get("limit") != null) {
                            double d = jsNumber(q.get("limit"));
                            if (!Double.isNaN(d) && !Double.isInfinite(d)) f.limit = (long) d;
                        }
                        if (has(q.get("cursor"))) f.cursor = q.get("cursor");
                        return new Response(200, svc.list(f));
                    }
                    if (s2 == null) return new Response(404, obj("error", "not_found"));
                    Map<String, Object> g = svc.inspect(s2);
                    if (!who.admin && !java.util.Objects.equals(g.get("principal"), who.principal)) throw new GrantError("not_found", "no such grant");
                    if (seg.size() == 3 && req.method.equals("GET")) return new Response(200, g);
                    if (seg.size() == 3 && req.method.equals("DELETE")) {
                        String scope = q.get("scope") != null ? q.get("scope") : "grant";
                        String sig = b.get("sig") instanceof String ? (String) b.get("sig") : null;
                        // A principal-scoped caller must still sign; only an admin may revoke without a principal signature.
                        return new Response(200, svc.revoke(s2, scope, who.admin && !has(sig) ? null : (sig == null ? "" : sig), who.admin && !has(sig)));
                    }
                    if (seg.size() == 4 && "amend".equals(s3) && req.method.equals("POST")) {
                        Map<String, Object> r = svc.amend(s2, b);
                        return new Response(Boolean.TRUE.equals(r.get("created")) ? 201 : 200, r.get("grant"));
                    }
                    if (seg.size() == 4 && "needs".equals(s3) && req.method.equals("POST")) return new Response(201, svc.requestNeeds(s2, b.get("needs")));
                }
                if ("needs".equals(s1) && s2 != null && "approve".equals(s3) && req.method.equals("POST")) {
                    ownNeed(svc, who, s2);
                    if (!(b.get("sig") instanceof String) || !(b.get("approved") instanceof List)) throw new GrantError("bad_request", "sig and approved are required");
                    Map<String, Object> r = svc.approveNeeds(s2, b.get("approved"), (String) b.get("sig"), b.get("step_up_ref") instanceof String ? (String) b.get("step_up_ref") : null);
                    return new Response(201, r.get("grant"));
                }
                if ("needs".equals(s1) && s2 != null && "deny".equals(s3) && req.method.equals("POST")) {
                    ownNeed(svc, who, s2);
                    svc.denyNeeds(s2);
                    return new Response(200, obj("status", "denied"));
                }
                return new Response(404, obj("error", "not_found"));
            } catch (Exception e) {
                return err(e);
            }
        };
    }

    private static void ownNeed(GrantService svc, Caller who, String needId) {
        Map<String, Object> g = svc.inspect(svc.needGrantId(needId));
        if (!who.admin && !java.util.Objects.equals(g.get("principal"), who.principal)) throw new GrantError("not_found", "no such grant");
    }
}
