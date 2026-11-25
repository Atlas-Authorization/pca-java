package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import net.atlasauth.pca.gateway.Gateway;
import net.atlasauth.pca.revoke.JsVal;
import org.junit.jupiter.api.Test;

/**
 * Replays the reference oracle over the gateway: the request binding, canonical query, path hardening, replay guard, provenance log,
 * the decision pipeline over real signed proofs (signature-only mode) and the Envoy / Lambda shapes. Verdict objects and the strict-JSON
 * parser's own message are masked (see the oracle header).
 */
class GatewayDiffTest {
    private static final String MOD = "ref-gateway";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) { return (List<Object>) o; }

    private static String str(Object o) { return o instanceof String ? (String) o : null; }

    private static Gateway.GatewayRequest request(Map<String, Object> m) {
        Gateway.GatewayRequest r = new Gateway.GatewayRequest();
        r.method = str(m.get("method"));
        r.path = str(m.get("path"));
        r.query = str(m.get("query"));
        r.authority = str(m.get("authority"));
        r.bodySha256 = str(m.get("bodySha256"));
        r.body = str(m.get("body"));
        if (m.get("headers") instanceof Map) r.headers = map(m.get("headers"));
        return r;
    }

    private static final Pattern UNDECODABLE = Pattern.compile("undecodable PCA-Action header: (?!PCA-Action header)[\\s\\S]*");

    @SuppressWarnings("unchecked")
    static Object mask(Object s) {
        if (s instanceof String) return UNDECODABLE.matcher((String) s).replaceAll("undecodable PCA-Action header: <json>");
        if (s instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) s) out.add(mask(x)); return out; }
        if (s instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) s).entrySet()) {
                Object v = e.getValue();
                if ((e.getKey().equals("x-pca-verdict") || e.getKey().equals("pcaVerdict")) && v instanceof String && !((String) v).isEmpty()) out.put(e.getKey(), "<verdict>");
                else out.put(e.getKey(), mask(v));
            }
            Object h = out.get("header");
            if (h instanceof Map && "x-pca-verdict".equals(((Map<String, Object>) h).get("key")) && !"".equals(((Map<String, Object>) h).get("value"))) {
                Map<String, Object> nh = new LinkedHashMap<>((Map<String, Object>) h);
                nh.put("value", "<verdict>");
                out.put("header", nh);
            }
            return out;
        }
        return s;
    }

    private static Gateway.BindRequestOptions bindOpts(Object o) {
        if (o == null) return null;
        Map<String, Object> m = map(o);
        Gateway.BindRequestOptions b = new Gateway.BindRequestOptions();
        b.authority = Boolean.TRUE.equals(m.get("authority"));
        b.body = m.containsKey("body") ? (Boolean) m.get("body") : null;
        return b;
    }

    @Test void canonicalQuery() throws Exception { OracleCases.each(MOD, "canonicalQuery", a -> { if (a.get(0) == null) throw new IllegalStateException("TypeError: Cannot read properties of null (reading 'startsWith')"); return Gateway.canonicalQuery((String) a.get(0)); }); }

    @Test void requestBinding() throws Exception {
        OracleCases.each(MOD, "requestBinding", a -> Gateway.requestBinding(request(map(a.get(0))), bindOpts(a.size() > 1 ? a.get(1) : null)));
    }

    @Test void bindParams() throws Exception {
        OracleCases.each(MOD, "bindParams", a -> Gateway.bindParams(map(a.get(0)), a.size() > 1 && a.get(1) != null ? map(a.get(1)) : null));
    }

    @Test void ambiguousPathReason() throws Exception { OracleCases.each(MOD, "ambiguousPathReason", a -> Gateway.ambiguousPathReason((String) a.get(0))); }

    @Test void replayScenario() throws Exception {
        OracleCases.each(MOD, "replayScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            long[] clock = {JsVal.num(spec.get("clock")).longValue()};
            Gateway.ReplayGuard g = Gateway.memoryReplayGuard(JsVal.num(spec.get("max")).intValue(), () -> clock[0]);
            List<Object> out = new ArrayList<>();
            for (Object o : list(spec.get("ops"))) {
                Map<String, Object> op = map(o);
                if (op.containsKey("setClock")) { clock[0] = JsVal.num(op.get("setClock")).longValue(); continue; }
                try {
                    Double now = op.get("now") == null ? null : JsVal.num(op.get("now"));
                    out.add(g.claim((String) op.get("key"), JsVal.num(op.get("exp")), now));
                } catch (Exception e) {
                    Map<String, Object> t = new LinkedHashMap<>();
                    t.put("threw", e.getMessage());
                    out.add(t);
                }
            }
            return out;
        });
    }

    @Test void provenanceLogScenario() throws Exception {
        OracleCases.each(MOD, "provenanceLogScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            Gateway.ProvenanceLog l = Gateway.memoryProvenanceLog(JsVal.num(spec.get("max")).intValue());
            List<Object> out = new ArrayList<>();
            for (Object o : list(spec.get("ops"))) {
                Map<String, Object> op = map(o);
                if (op.containsKey("add")) { l.add((String) op.get("session"), map(op.get("o"))); out.add("added"); }
                else out.add(new ArrayList<Object>(l.seen((String) op.get("session"))));
            }
            return out;
        });
    }

    private static Gateway.FullPolicy kind(Object k) {
        Gateway.FullPolicy p = new Gateway.FullPolicy();
        p.paramsFromBody = "body".equals(k);
        if (!p.paramsFromBody) p.paramsFn = r -> new LinkedHashMap<>();
        return p;
    }

    @Test void presentedProvenance() throws Exception {
        OracleCases.each(MOD, "presentedProvenance", a -> {
            Map<String, Object> m = new LinkedHashMap<>(map(a.get(0)));
            m.put("method", "POST");
            m.put("path", "/");
            Object v = Gateway.presentedProvenance(request(m), kind(a.get(1)));
            if (v == Gateway.ABSENT) { Map<String, Object> u = new LinkedHashMap<>(); u.put("undef", true); return u; }
            return v;
        });
    }

    @Test void presentedArtifacts() throws Exception {
        OracleCases.each(MOD, "presentedArtifacts", a -> {
            Map<String, Object> m = new LinkedHashMap<>(map(a.get(0)));
            m.put("method", "POST");
            m.put("path", "/");
            return Gateway.presentedArtifacts(request(m), kind(a.get(1)));
        });
    }

    // ---- scenarios -----------------------------------------------------------------------------------------------------------------

    static Gateway.GatewayOptions options(Map<String, Object> spec) {
        final long now = JsVal.num(spec.get("now")).longValue();
        Gateway.GatewayOptions o = new Gateway.GatewayOptions();
        o.audience = (String) spec.get("audience");
        for (Object r : list(spec.get("routes"))) {
            Map<String, Object> m = map(r);
            Map<String, Object> c = map(m.get("capability"));
            o.routes.add(new Gateway.RouteRule(str(m.get("method")), (String) m.get("path"), new Gateway.RequiredCapability((String) c.get("verb"), str(c.get("resource")))));
        }
        Map<String, Object> grants = map(spec.get("grants"));
        o.resolveGrant = (ref, pcactn) -> ref instanceof String && grants.get(ref) != null ? map(grants.get(ref)) : null;
        o.now = () -> now;
        Object br = spec.get("bindRequest");
        if ("off".equals(br)) o.bindRequestOff = true; else if (br != null) o.bindRequest = bindOpts(br);
        o.unmatchedRoute = str(spec.get("unmatched"));
        o.pathPolicy = str(spec.get("pathPolicy"));
        if (spec.get("requireChecks") != null) { o.requireChecks = new ArrayList<>(); for (Object c : list(spec.get("requireChecks"))) o.requireChecks.add((String) c); }
        o.realm = str(spec.get("realm"));
        o.insecureSkipPlanRootCheck = Boolean.TRUE.equals(spec.get("skipPlan"));
        if (spec.get("planRoots") != null) { o.authorizedPlanRoots = new ArrayList<>(); for (Object c : list(spec.get("planRoots"))) o.authorizedPlanRoots.add((String) c); }
        String replay = (String) spec.get("replay");
        switch (replay) {
            case "always": o.replayGuard = (k, e, n) -> true; break;
            case "false": o.replayGuard = (k, e, n) -> false; break;
            case "throws": o.replayGuard = (k, e, n) -> { throw new RuntimeException("store down"); }; break;
            case "memory": o.replayGuard = Gateway.memoryReplayGuard(100_000, () -> now); break;
            case "memory-full": o.replayGuard = Gateway.memoryReplayGuard(1, () -> now); break;
            default: break;
        }
        switch ((String) spec.get("revocation")) {
            case "ok": o.revocation = (p, g, n) -> new Gateway.HookResult(true, true, null); break;
            case "revoked": o.revocation = (p, g, n) -> new Gateway.HookResult(true, false, "grant revoked"); break;
            case "revoked-noreason": o.revocation = (p, g, n) -> new Gateway.HookResult(true, false, null); break;
            case "notEnforced": o.revocation = (p, g, n) -> new Gateway.HookResult(false, false, null); break;
            case "throws": o.revocation = (p, g, n) -> { throw new RuntimeException("rev down"); }; break;
            default: break;
        }
        String cp = str(spec.get("checkProof"));
        if (cp != null) {
            switch (cp) {
                case "true": o.checkProof = c -> Boolean.TRUE; break;
                case "false": o.checkProof = c -> Boolean.FALSE; break;
                case "obj-true": o.checkProof = c -> obj("allow", true, null); break;
                case "obj-false": o.checkProof = c -> obj("allow", false, null); break;
                case "obj-false-reason": o.checkProof = c -> obj("allow", false, "over limit"); break;
                default: o.checkProof = c -> { throw new RuntimeException("policy down"); };
            }
        }
        String pol = (String) spec.get("policy");
        if (pol.equals("sig")) o.policyMode = "signature-only";
        else if (pol.equals("bogus")) o.policyMode = "bogus";
        else if (pol.equals("full-missing")) { o.policyMode = "full"; o.full = new Gateway.FullPolicy(); }
        return o;
    }

    private static Map<String, Object> obj(String k, Object v, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    private static Object project(Gateway.Decision d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allow", d.allow);
        m.put("status", d.status);
        m.put("code", d.code);
        m.put("reason", d.reason);
        m.put("headers", new LinkedHashMap<String, Object>(d.headers));
        if (d.matched != null) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("verb", d.matched.verb);
            if (d.matched.resource != null) r.put("resource", d.matched.resource);
            m.put("matched", r);
        }
        if (d.pcactn != null && d.pcactn.get("grant_ref") != null) m.put("grant", d.pcactn.get("grant_ref"));
        if (d.verdict != null) m.put("verdictAllow", d.verdict.get("allow"));
        return mask(m);
    }

    private static Object created(RuntimeException e) { return obj("create", e.getMessage(), null); }

    @Test void authorizeScenario() throws Exception {
        OracleCases.each(MOD, "authorizeScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            Function<Gateway.GatewayRequest, Gateway.Decision> gw;
            try { gw = Gateway.createGateway(options(spec)); } catch (RuntimeException e) { return created(e); }
            List<Object> out = new ArrayList<>();
            for (Object r : list(spec.get("requests"))) {
                try { out.add(project(gw.apply(request(map(r))))); } catch (RuntimeException e) { out.add(obj("threw", e.getMessage(), null)); }
            }
            return out;
        });
    }

    private void adapter(String fn, Function<Gateway.GatewayOptions, Function<Map<String, Object>, Map<String, Object>>> make) throws Exception {
        OracleCases.each(MOD, fn, a -> {
            Map<String, Object> spec = map(a.get(0));
            Function<Map<String, Object>, Map<String, Object>> adapt;
            try {
                adapt = make.apply(options(spec));
            } catch (RuntimeException e) {
                return created(e);
            }
            try {
                return mask(adapt.apply(map(list(spec.get("events")).get(0))));
            } catch (RuntimeException e) {
                return obj("threw", e.getMessage(), null); // a throw from the handler itself, not from building the adapter
            }
        });
    }

    @Test void envoyScenario() throws Exception { adapter("envoyScenario", Gateway::envoyExtAuthz); }

    @Test void grpcScenario() throws Exception { adapter("grpcScenario", Gateway::envoyGrpcExtAuthz); }

    @Test void lambdaScenario() throws Exception { adapter("lambdaScenario", Gateway::lambdaAuthorizer); }

    @Test void lambdaSimpleScenario() throws Exception { adapter("lambdaSimpleScenario", Gateway::lambdaSimpleAuthorizer); }
}
