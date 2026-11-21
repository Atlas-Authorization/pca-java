package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.scim.Scim;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the SCIM provisioning package (see the oracle header for the case shapes). */
class ScimDiffTest {
    private static final String MODULE = "ref-scim";
    private static final String SEED_T = "2027-01-15T08:00:00.000Z";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static long n(Object o) { return Long.parseLong(o.toString()); }
    private static Map<String, Object> obj(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }

    @Test void issuePassport() throws Exception { OracleCases.each(MODULE, "issuePassport", a -> Scim.issuePassport(m(a.get(0)))); }
    @Test void passportFingerprint() throws Exception { OracleCases.each(MODULE, "passportFingerprint", a -> Scim.passportFingerprint(m(a.get(0)))); }

    @Test void registry() throws Exception {
        OracleCases.each(MODULE, "registry", a -> {
            List<Map<String, Object>> ps = new ArrayList<>();
            for (Object p : l(a.get(0))) ps.add(m(p));
            Scim.PassportRegistry r = Scim.buildRegistry(ps);
            String id = (String) a.get(1);
            Map<String, Object> got = r.get(id);
            return obj("all", new ArrayList<Object>(r.all()), "has", r.has(id), "get", got); // an absent passport is null in the reference (?? null)
        });
    }

    private static Scim.MetaInput meta(Map<String, Object> mm) {
        Map<String, Object> rest = new LinkedHashMap<>(mm);
        Object nowMs = rest.remove("nowMs");
        return Scim.MetaInput.of(rest, nowMs == null ? null : () -> n(nowMs));
    }

    @Test void passportToScim() throws Exception { OracleCases.each(MODULE, "passportToScim", a -> Scim.passportToScim(m(a.get(0)), m(a.get(1)), a.get(2) instanceof Map ? meta(m(a.get(2))) : Scim.MetaInput.of(null, () -> (long) Double.parseDouble(a.get(2).toString())))); }

    @Test void scimToProvisioningRequest() throws Exception {
        OracleCases.each(MODULE, "scimToProvisioningRequest", a -> {
            Scim.ProvisioningRequest r = Scim.scimToProvisioningRequest(a.get(0));
            return obj("identity", r.identity, "projection", r.projection);
        });
    }

    @Test void scimError() throws Exception {
        OracleCases.each(MODULE, "scimError", a -> {
            Map<String, Object> e = Scim.scimError((int) n(a.get(0)), (String) a.get(1), a.size() > 2 ? (String) a.get(2) : null);
            if (a.size() > 2 && a.get(2) == null) e.put("scimType", null); // an explicit null is not undefined: the reference keeps the member
            return e;
        });
    }

    @Test void scimListResponse() throws Exception {
        OracleCases.each(MODULE, "scimListResponse", a -> {
            List<Map<String, Object>> rs = new ArrayList<>();
            for (Object r : l(a.get(0))) rs.add(m(r));
            return Scim.scimListResponse(rs, n(a.get(1)), n(a.get(2)));
        });
    }

    @Test void parseFilter() throws Exception {
        OracleCases.each(MODULE, "parseFilter", a -> { Scim.EqFilter f = Scim.parseFilter(a.get(0)); return obj("attr", f.attr, "value", f.value); });
    }

    @Test void toEntraAgentPayload() throws Exception { OracleCases.each(MODULE, "toEntraAgentPayload", a -> Scim.toEntraAgentPayload(m(a.get(0)))); }
    @Test void toOktaScimPayload() throws Exception { OracleCases.each(MODULE, "toOktaScimPayload", a -> Scim.toOktaScimPayload(m(a.get(0)))); }

    private static Scim.FetchLike fetchNamed(String mode, List<Object> calls) {
        return (url, headers, body) -> {
            calls.add(obj("url", url, "init", obj("method", "POST", "headers", new LinkedHashMap<String, Object>(headers), "body", body)));
            switch (mode) {
                case "ok201": return fetchResponse(true, 201, obj("id", "obj-1"), false);
                case "err500": return fetchResponse(false, 500, obj("detail", "x"), false);
                case "badjson": return fetchResponse(true, 204, null, true);
                default: return fetchResponse(true, 200, null, false);
            }
        };
    }

    private static Scim.FetchResponse fetchResponse(boolean ok, int status, Object json, boolean throwing) {
        return new Scim.FetchResponse() {
            @Override public boolean ok() { return ok; }
            @Override public int status() { return status; }
            @Override public Object json() { if (throwing) throw new IllegalStateException("no body"); return json; }
        };
    }

    private static Object pushOut(Scim.PushResult r, List<Object> calls) {
        return obj("result", obj("ok", r.ok, "status", new Json.Num(Integer.toString(r.status)), "body", r.body), "calls", calls);
    }

    private static void push(String fn) throws Exception {
        OracleCases.each(MODULE, fn, a -> {
            List<Object> calls = new ArrayList<>();
            Scim.PushTarget target = new Scim.PushTarget("https://dir.example/scim/Agents", "TOK", fetchNamed((String) a.get(2), calls));
            return pushOut("pushToEntra".equals(fn) ? Scim.pushToEntra(m(a.get(1)), target) : Scim.pushToOkta(m(a.get(1)), target), calls);
        });
    }

    @Test void pushToEntra() throws Exception { push("pushToEntra"); }
    @Test void pushToOkta() throws Exception { push("pushToOkta"); }

    @Test void pushProvision() throws Exception {
        OracleCases.each(MODULE, "pushProvision", a -> {
            List<Object> calls = new ArrayList<>();
            return pushOut(Scim.pushProvision(Scim.toEntraAgentPayload(m(a.get(0))), new Scim.PushTarget("e", "t", fetchNamed((String) a.get(1), calls))), calls);
        });
    }

    /** JavaScript {@code String(x)} of a request member (an id or a method). */
    private static String jsText(Object x) {
        if (x == null) return "null";
        if (x instanceof List) { StringBuilder b = new StringBuilder(); boolean f = true; for (Object e : l(x)) { if (!f) b.append(','); f = false; if (e != null) b.append(jsText(e)); } return b.toString(); }
        if (x instanceof Map) return "[object Object]";
        return x instanceof Json.Num ? AttestNvidia.jsString(x) : String.valueOf(x);
    }

    private static Scim.ScimHandlerOptions sessionOptions(String name) {
        long t0 = 1_700_000_000_000L;
        Scim.ScimHandlerOptions o = new Scim.ScimHandlerOptions();
        o.now = () -> t0;
        switch (name) {
            case "open": o.baseUrl = "https://scim.acme.com/scim/v2"; o.authenticate = r -> Boolean.TRUE; break;
            case "slash": o.baseUrl = "https://scim.acme.com/scim/v2///"; o.authenticate = r -> Boolean.TRUE; break;
            case "nobase": o.allowUnauthenticated = true; break;
            case "tick": { long[] tick = {0}; o.baseUrl = "https://x.example"; o.now = () -> t0 + 1000 * tick[0]++; o.authenticate = r -> Boolean.TRUE; break; }
            case "deny": o.authenticate = r -> Boolean.FALSE; break;
            case "throwauth": o.authenticate = r -> { throw new IllegalStateException("x"); }; break;
            case "truthy": o.authenticate = r -> "yes"; break;
            default: break; // noauth, notfn: no usable authenticate and no opt-out, the constructor refuses
        }
        return o;
    }

    private static Scim.ScimResponse handle(Scim.ScimHandler h, Map<String, Object> r) {
        Scim.ScimRequest req = new Scim.ScimRequest();
        req.method = r.containsKey("method") ? jsText(r.get("method")) : "undefined";
        req.idGiven = r.containsKey("id");
        req.id = req.idGiven ? jsText(r.get("id")) : null;
        req.query = r.get("query") instanceof Map ? m(r.get("query")) : null; // a non-object query has no members
        req.body = r.get("body");
        return h.handle(req);
    }

    @Test void scimSession() throws Exception {
        OracleCases.each(MODULE, "scimSession", a -> {
            Scim.ScimHandler h = Scim.scimHandler(Scim.createMemoryStore(), sessionOptions((String) a.get(0)));
            for (Object r : l(a.get(1))) handle(h, m(r));
            List<Object> out = new ArrayList<>();
            for (Object r : l(a.get(2))) out.add(handle(h, m(r)).toJson());
            return out;
        });
    }
}
