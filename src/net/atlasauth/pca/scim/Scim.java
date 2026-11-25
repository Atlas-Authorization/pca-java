package net.atlasauth.pca.scim;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;

/**
 * SCIM 2.0 provisioning for Proof-Carrying Authority agents: the passport registry exposed as a SCIM {@code /Agents} resource
 * server ({@link #scimHandler}) and outbound push-provisioning bodies for Microsoft Entra Agent ID and Okta.
 *
 * <p>Resources, projections, requests and bodies are plain JSON values (Map / List / String / Boolean / {@link Json.Num} / null),
 * mirroring the reference package; a malformed write body is answered with a SCIM error response, never a partial write.
 * shortcut: PATCH object keys keep JSON order (a JavaScript object lists integer-like keys first), and list paging beyond 2^53 is not exact.
 */
public final class Scim {
    private Scim() {}

    public static final String AGENT_SCHEMA_URN = "urn:ietf:params:scim:schemas:atlas:2.0:Agent";
    public static final String LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public static final String PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    public static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    public static final String AGENT_RESOURCE_TYPE = "Agent";
    public static final String ENTRA_AGENT_EXTENSION_URN = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent";
    public static final String OKTA_AGENT_EXTENSION_URN = "urn:okta:scim:schemas:custom:1.0:Agent";
    private static final String SCIM_CONTENT_TYPE = "application/scim+json";

    // ---- JavaScript-flavoured value readers ----------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asRecord(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }
    private static String asString(Object v) { return v instanceof String ? (String) v : null; }
    private static boolean isNumber(Object v) { return v instanceof Json.Num || v instanceof Number; }
    private static Boolean asBoolean(Object v) {
        if (v instanceof Boolean) return (Boolean) v;
        if ("true".equals(v)) return Boolean.TRUE;
        if ("false".equals(v)) return Boolean.FALSE;
        return null;
    }
    @SuppressWarnings("unchecked")
    private static List<String> asStringArray(Object v) {
        if (!(v instanceof List)) return null;
        for (Object x : (List<Object>) v) if (!(x instanceof String)) return null;
        return (List<String>) v;
    }
    private static Object member(Map<String, Object> m, String k) { return m == null ? null : m.get(k); }

    /** JavaScript {@code String(v)} / template-literal conversion for the JSON value shapes. */
    static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num || v instanceof Number) {
            String raw = v.toString();
            try {
                return net.atlasauth.pca.AttestCommon.jsNumString(Double.parseDouble(raw)); // String(number), exponent forms included
            } catch (NumberFormatException e) { return raw; }
        }
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(jsString(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** A thrown value error carrying the SCIM {@code scimType}. */
    public static final class ScimValueException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String scimType;
        public ScimValueException(String scimType, String detail) { super(detail); this.scimType = scimType; }
        public String scimType() { return scimType; }
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    // ---- Passport <-> SCIM mapping -------------------------------------------------------------------------------

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private static String isoAt(LongSupplier now) {
        long ms = now.getAsLong();
        if (ms < -62167219200000L || ms > 253402300799999L) throw new IllegalArgumentException("invalid time value"); // shortcut: years 0000-9999 only (outside it JS prints a signed six-digit year)
        return ISO.format(Instant.ofEpochMilli(ms));
    }

    private static String trimTrailingSlash(String s) {
        int e = s.length();
        while (e > 0 && s.charAt(e - 1) == '/') e--;
        return s.substring(0, e);
    }

    /** {@code encodeURIComponent}: throws on a lone surrogate like the JavaScript URIError. */
    static String encodeUriComponent(String s) {
        StringBuilder sb = new StringBuilder();
        byte[] b;
        if (Json.hasLoneSurrogate(s)) throw new IllegalArgumentException("URI malformed");
        b = Json.utf8(s);
        for (byte x : b) {
            int c = x & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".indexOf(c) >= 0) sb.append((char) c);
            else sb.append('%').append("0123456789ABCDEF".charAt(c >> 4)).append("0123456789ABCDEF".charAt(c & 15));
        }
        return sb.toString();
    }

    /** Inputs for the SCIM {@code meta} block: any member may be null (defaults to the clock). */
    public static final class MetaInput {
        public String baseUrl;
        public String created;
        public String lastModified;
        public LongSupplier now;
        public MetaInput() {}
        /** From a JSON object {baseUrl?, created?, lastModified?}; {@code now} is given separately. */
        public static MetaInput of(Map<String, Object> m, LongSupplier now) {
            MetaInput i = new MetaInput();
            if (m != null) { i.baseUrl = asString(m.get("baseUrl")); i.created = asString(m.get("created")); i.lastModified = asString(m.get("lastModified")); }
            i.now = now;
            return i;
        }
    }

    private static Map<String, Object> buildMeta(String id, Map<String, Object> resourceSansMeta, MetaInput input) {
        LongSupplier now = input.now != null ? input.now : System::currentTimeMillis;
        String base = input.baseUrl != null ? trimTrailingSlash(input.baseUrl) : "";
        String location = base + "/Agents/" + encodeUriComponent(id);
        String created = input.created != null ? input.created : isoAt(now);
        String lastModified = input.lastModified != null ? input.lastModified : isoAt(now);
        return obj("resourceType", AGENT_RESOURCE_TYPE, "created", created, "lastModified", lastModified, "location", location,
            "version", "W/\"" + Pca.hashCanonical(resourceSansMeta) + "\"");
    }

    private static String present(Map<String, Object> m, String k) { return m.containsKey(k) ? jsString(m.get(k)) : "undefined"; }

    /** Project a passport and its governance attributes into a SCIM {@code Agent} resource (its content id is the immutable id). */
    public static Map<String, Object> passportToScim(Map<String, Object> passport, Map<String, Object> proj, MetaInput meta) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("schemas", new ArrayList<Object>(List.of(AGENT_SCHEMA_URN)));
        base.put("id", passport.get("id"));
        Object dn = proj.get("displayName");
        base.put("displayName", dn != null ? dn : present(passport, "model_id") + " (" + present(passport, "operator") + ")");
        Object act = proj.get("active");
        base.put("active", act != null ? act : Boolean.TRUE);
        if (!proj.containsKey("owner")) throw new IllegalArgumentException("canonicalize: unsupported type undefined"); // owner: undefined reaches the etag's canonical form
        base.put("owner", proj.get("owner"));
        Object caps = proj.get("capabilities");
        base.put("capabilities", caps instanceof List ? new ArrayList<Object>((List<?>) caps) : new ArrayList<Object>());
        base.put("passportRef", passport.get("id"));
        base.put("passport", passport);
        if (proj.containsKey("externalId")) base.put("externalId", proj.get("externalId"));
        if (proj.containsKey("holder")) base.put("holder", proj.get("holder"));
        Map<String, Object> out = new LinkedHashMap<>(base);
        out.put("meta", buildMeta(String.valueOf(passport.get("id")), base, meta == null ? new MetaInput() : meta));
        return out;
    }

    /** The passport identity to register plus the governance projection, distilled from a SCIM write body. */
    public static final class ProvisioningRequest {
        public final Map<String, Object> identity;
        public final Map<String, Object> projection;
        ProvisioningRequest(Map<String, Object> identity, Map<String, Object> projection) { this.identity = identity; this.projection = projection; }
    }

    private static Map<String, Object> readIdentity(Map<String, Object> body) {
        Map<String, Object> nested = asRecord(body.get("passport"));
        if (nested != null) {
            String modelId = asString(nested.get("model_id"));
            String operator = asString(nested.get("operator"));
            if (modelId == null || operator == null) throw new ScimValueException("invalidValue", "passport.model_id and passport.operator are required");
            Map<String, Object> id = new LinkedHashMap<>();
            id.put("model_id", modelId);
            id.put("operator", operator);
            Boolean hw = asBoolean(nested.get("hardware_rooted"));
            id.put("hardware_rooted", hw != null ? hw : Boolean.FALSE);
            Object iat = nested.get("issued_at");
            id.put("issued_at", isNumber(iat) ? iat : new Json.Num("0"));
            for (String k : new String[] {"weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"}) {
                String v = asString(nested.get(k));
                if (v != null) id.put(k, v);
            }
            Boolean measured = asBoolean(nested.get("weights_measured"));
            if (measured != null) id.put("weights_measured", measured);
            return id;
        }
        String modelId = asString(body.get("model"));
        if (modelId == null) modelId = asString(body.get("model_id"));
        String operator = asString(body.get("operator"));
        if (modelId == null || operator == null) throw new ScimValueException("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`");
        Boolean hw = asBoolean(body.get("hardwareRooted"));
        return obj("model_id", modelId, "operator", operator, "hardware_rooted", hw != null ? hw : Boolean.FALSE, "issued_at", new Json.Num("0"));
    }

    private static Map<String, Object> readProjection(Map<String, Object> body) {
        String owner = asString(body.get("owner"));
        if (owner == null) owner = asString(body.get("operator"));
        if (owner == null) owner = asString(member(asRecord(body.get("passport")), "operator"));
        if (owner == null) owner = "";
        Map<String, Object> proj = new LinkedHashMap<>();
        proj.put("owner", owner);
        String displayName = asString(body.get("displayName"));
        String externalId = asString(body.get("externalId"));
        Boolean active = asBoolean(body.get("active"));
        List<String> capabilities = asStringArray(body.get("capabilities"));
        String holder = asString(body.get("holder"));
        if (displayName != null) proj.put("displayName", displayName);
        if (externalId != null) proj.put("externalId", externalId);
        if (active != null) proj.put("active", active);
        if (capabilities != null) proj.put("capabilities", capabilities);
        if (holder != null) proj.put("holder", holder);
        return proj;
    }

    /**
     * Distil a SCIM Agent write body (an untrusted value) into a {@link ProvisioningRequest}. Accepts the lossless nested-passport
     * form and a flat IdP form. Throws {@link ScimValueException} on a malformed body.
     */
    public static ProvisioningRequest scimToProvisioningRequest(Object value) {
        Map<String, Object> body = asRecord(value);
        if (body == null) throw new ScimValueException("invalidSyntax", "request body must be a JSON object");
        if (body.containsKey("schemas")) {
            Object s = body.get("schemas");
            if (!(s instanceof List && ((List<?>) s).contains(AGENT_SCHEMA_URN))) throw new ScimValueException("invalidValue", "schemas must include " + AGENT_SCHEMA_URN);
        }
        return new ProvisioningRequest(readIdentity(body), readProjection(body));
    }

    // ---- store ---------------------------------------------------------------------------------------------------

    /** A stored agent: its materialized SCIM resource plus the backing passport. */
    public static final class StoredAgent {
        public final Map<String, Object> resource;
        public final Map<String, Object> passport;
        public StoredAgent(Map<String, Object> resource, Map<String, Object> passport) { this.resource = resource; this.passport = passport; }
    }

    /** A read-only passport-registry view. */
    public interface PassportRegistry {
        Map<String, Object> get(String id);
        boolean has(String id);
        List<Map<String, Object>> all();
    }

    /** The passport registry over {@code passports}, later entries replacing earlier ones by id (insertion order kept). */
    public static PassportRegistry buildRegistry(List<Map<String, Object>> passports) {
        Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        for (Map<String, Object> p : passports) byId.put(String.valueOf(p.get("id")), p);
        return new PassportRegistry() {
            @Override public Map<String, Object> get(String id) { return byId.get(id); }
            @Override public boolean has(String id) { return byId.containsKey(id); }
            @Override public List<Map<String, Object>> all() { return new ArrayList<>(byId.values()); }
        };
    }

    /** Fill {@code id} from the fingerprint of the identity fields. */
    public static Map<String, Object> issuePassport(Map<String, Object> identity) { return Issue.issuePassport(identity); }

    /** The content fingerprint of a passport identity. */
    public static String passportFingerprint(Map<String, Object> identity) { return Issue.passportFingerprint(identity); }

    /** The persistence seam the SCIM server writes through. */
    public interface AgentStore {
        List<StoredAgent> all();
        StoredAgent get(String id);
        void put(StoredAgent stored);
        boolean delete(String id);
        PassportRegistry registry();
    }

    /** The default in-memory store; insertion order is preserved for stable list output. */
    public static AgentStore createMemoryStore(List<StoredAgent> seed) {
        Map<String, StoredAgent> byId = new LinkedHashMap<>();
        for (StoredAgent s : seed) byId.put(String.valueOf(s.resource.get("id")), s);
        return new AgentStore() {
            @Override public List<StoredAgent> all() { return new ArrayList<>(byId.values()); }
            @Override public StoredAgent get(String id) { return byId.get(id); }
            @Override public void put(StoredAgent s) { byId.put(String.valueOf(s.resource.get("id")), s); }
            @Override public boolean delete(String id) { return byId.remove(id) != null; }
            @Override public PassportRegistry registry() {
                List<Map<String, Object>> ps = new ArrayList<>();
                for (StoredAgent s : byId.values()) ps.add(s.passport);
                return buildRegistry(ps);
            }
        };
    }

    public static AgentStore createMemoryStore() { return createMemoryStore(List.of()); }

    // ---- envelopes -----------------------------------------------------------------------------------------------

    /** A SCIM error body ({@code status} is a string; {@code scimType} is omitted when null). */
    public static Map<String, Object> scimError(int status, String detail, String scimType) {
        Map<String, Object> b = obj("schemas", new ArrayList<Object>(List.of(ERROR_SCHEMA)), "status", String.valueOf(status));
        if (scimType != null) b.put("scimType", scimType);
        b.put("detail", detail);
        return b;
    }

    /** A SCIM ListResponse over an already-paginated page of resources. */
    public static Map<String, Object> scimListResponse(List<Map<String, Object>> resources, long totalResults, long startIndex) { return scimListResponse(resources, totalResults, (double) startIndex); }

    /** As above with the start index as a JavaScript number (a huge one prints in exponent form). */
    static Map<String, Object> scimListResponse(List<Map<String, Object>> resources, long totalResults, double startIndex) {
        return obj("schemas", new ArrayList<Object>(List.of(LIST_RESPONSE_SCHEMA)), "totalResults", new Json.Num(Long.toString(totalResults)),
            "startIndex", new Json.Num(net.atlasauth.pca.AttestCommon.jsNumString(startIndex)), "itemsPerPage", new Json.Num(Integer.toString(resources.size())), "Resources", new ArrayList<Object>(resources));
    }

    // ---- filter --------------------------------------------------------------------------------------------------

    private static final String WS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
    private static final String DOT = "[^\\n\\r\\u2028\\u2029]";
    private static final Pattern FILTER = Pattern.compile("^" + WS + "*([A-Za-z0-9_]+)" + WS + "+eq" + WS + "+(?:\"((?:[^\"\\\\]++|\\\\" + DOT + ")*+)\"|(true|false))" + WS + "*$",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern UNESCAPE = Pattern.compile("\\\\(" + DOT + ")");
    private static final java.util.Set<String> FILTERABLE = java.util.Set.of("userName", "displayName", "externalId", "id", "active", "owner");

    /** A parsed {@code attr eq value} filter; {@code value} is a String or Boolean. */
    public static final class EqFilter {
        public final String attr;
        public final Object value;
        EqFilter(String attr, Object value) { this.attr = attr; this.value = value; }
    }

    /** Parse the SCIM {@code attr eq "value"} / {@code attr eq true|false} subset. Throws {@link ScimValueException}. */
    public static EqFilter parseFilter(Object filter) {
        if (!(filter instanceof String)) throw new ScimValueException("invalidFilter", "filter must be a string");
        String f = (String) filter;
        Matcher m = FILTER.matcher(f);
        if (!m.matches()) throw new ScimValueException("invalidFilter", "unsupported filter (only `attr eq \"value\"` is supported): " + f);
        String attr = m.group(1);
        if (!FILTERABLE.contains(attr)) throw new ScimValueException("invalidFilter", "filter attribute not supported: " + attr);
        if (m.group(3) != null) return new EqFilter(attr, "true".equals(m.group(3).toLowerCase(Locale.ROOT)));
        String raw = m.group(2) == null ? "" : m.group(2);
        return new EqFilter(attr, UNESCAPE.matcher(raw).replaceAll("$1"));
    }

    private static boolean matchesFilter(Map<String, Object> agent, EqFilter f) {
        switch (f.attr) {
            case "userName": case "displayName": return f.value.equals(agent.get("displayName"));
            case "externalId": return f.value.equals(agent.get("externalId"));
            case "id": return f.value.equals(agent.get("id"));
            case "owner": return f.value.equals(agent.get("owner"));
            case "active": return f.value.equals(agent.get("active"));
            default: return false;
        }
    }

    // ---- PATCH ---------------------------------------------------------------------------------------------------

    private static final java.util.Set<String> MUTABLE_PATHS = java.util.Set.of("active", "displayName", "externalId", "owner", "capabilities", "holder");

    private static final class PatchOp {
        String op;
        String path;
        boolean hasValue;
        Object value;
    }

    private static List<PatchOp> readPatchOps(Object value) {
        Map<String, Object> body = asRecord(value);
        if (body == null) throw new ScimValueException("invalidSyntax", "PATCH body must be a JSON object");
        Object ops = body.get("Operations");
        if (!(ops instanceof List) || ((List<?>) ops).isEmpty()) throw new ScimValueException("invalidValue", "PATCH requires a non-empty Operations array");
        List<PatchOp> out = new ArrayList<>();
        for (Object raw : (List<?>) ops) {
            Map<String, Object> o = asRecord(raw);
            String opRaw = asString(member(o, "op"));
            String op = opRaw == null ? null : opRaw.toLowerCase(Locale.ROOT);
            if (!"add".equals(op) && !"replace".equals(op) && !"remove".equals(op)) {
                throw new ScimValueException("invalidValue", "unsupported PATCH op: " + (o == null || !o.containsKey("op") ? "undefined" : jsString(o.get("op"))));
            }
            PatchOp p = new PatchOp();
            p.op = op;
            p.path = asString(member(o, "path"));
            if (o != null && o.containsKey("value")) { p.hasValue = true; p.value = o.get("value"); }
            out.add(p);
        }
        return out;
    }

    private static Map<String, Object> projectionOf(Map<String, Object> resource) {
        Map<String, Object> proj = new LinkedHashMap<>();
        proj.put("owner", resource.get("owner"));
        proj.put("active", resource.get("active"));
        proj.put("capabilities", new ArrayList<Object>((List<?>) resource.get("capabilities")));
        if (resource.get("displayName") != null) proj.put("displayName", resource.get("displayName"));
        if (resource.get("externalId") != null) proj.put("externalId", resource.get("externalId"));
        if (resource.get("holder") != null) proj.put("holder", resource.get("holder"));
        return proj;
    }

    @SuppressWarnings("unchecked")
    private static void applyScalar(Map<String, Object> proj, String path, String op, Object value) {
        if (path.equals("active")) {
            if (op.equals("remove")) { proj.put("active", Boolean.TRUE); return; }
            Boolean b = asBoolean(value);
            if (b == null) throw new ScimValueException("invalidValue", "`active` must be a boolean");
            proj.put("active", b);
            return;
        }
        if (path.equals("capabilities")) {
            if (op.equals("remove")) { proj.put("capabilities", new ArrayList<Object>()); return; }
            List<String> arr = asStringArray(value);
            if (arr == null) throw new ScimValueException("invalidValue", "`capabilities` must be a string array");
            List<Object> next = new ArrayList<>();
            if (op.equals("add") && proj.get("capabilities") instanceof List) next.addAll((List<Object>) proj.get("capabilities"));
            next.addAll(arr);
            proj.put("capabilities", next);
            return;
        }
        if (op.equals("remove")) {
            if (path.equals("displayName") || path.equals("owner")) throw new ScimValueException("mutability", "`" + path + "` cannot be removed");
            if (path.equals("externalId") || path.equals("holder")) proj.remove(path);
            return;
        }
        String s = asString(value);
        if (s == null) throw new ScimValueException("invalidValue", "`" + path + "` must be a string");
        proj.put(path, s);
    }

    private static void applyPatchOp(Map<String, Object> proj, PatchOp op) {
        if (op.path == null) {
            if (op.op.equals("remove")) throw new ScimValueException("noTarget", "a `remove` op requires a `path`");
            Map<String, Object> obj = asRecord(op.hasValue ? op.value : null);
            if (obj == null) throw new ScimValueException("invalidValue", "a pathless PATCH value must be an object");
            for (String key : new ArrayList<>(obj.keySet())) {
                if (!MUTABLE_PATHS.contains(key)) throw new ScimValueException("mutability", "attribute is immutable or unknown: " + key);
                applyScalar(proj, key, "replace", obj.get(key));
            }
            return;
        }
        if (!MUTABLE_PATHS.contains(op.path)) throw new ScimValueException("mutability", "attribute is immutable or unknown: " + op.path);
        applyScalar(proj, op.path, op.op, op.hasValue ? op.value : null);
    }

    // ---- server --------------------------------------------------------------------------------------------------

    /** The subset of an inbound HTTP request the handler needs, already routed under {@code /Agents}. */
    public static final class ScimRequest {
        public String method;
        public String id;
        public Map<String, Object> query;
        public Object body;
        /** True when the request carries an id member even if it is null (JavaScript tells an absent id from a null one). */
        public boolean idGiven;
        public ScimRequest() {}
        public ScimRequest(String method, String id, Map<String, Object> query, Object body) { this.method = method; this.id = id; this.query = query; this.body = body; }
    }

    /** The handler's response: status, a JSON body (null when there is none) and headers. */
    public static final class ScimResponse {
        public final int status;
        public final Object body;
        public final Map<String, String> headers;
        public ScimResponse(int status, Object body, Map<String, String> headers) { this.status = status; this.body = body; this.headers = headers; }
        /** {@code {status, body, headers}} as a JSON object. */
        public Map<String, Object> toJson() {
            Map<String, Object> o = obj("status", new Json.Num(Integer.toString(status)), "headers", new LinkedHashMap<String, Object>(headers));
            if (body != null) o.put("body", body); // no body is undefined in the reference: JSON leaves the member out
            return o;
        }
    }

    /** Authenticate and authorize a request; the handler admits it only on exactly {@link Boolean#TRUE} (a throw or any other value is a 401). */
    public interface Authenticator { Object authenticate(ScimRequest req) throws Exception; }

    /** A SCIM handler: one request in, one response out. */
    public interface ScimHandler { ScimResponse handle(ScimRequest req); }

    public static final class ScimHandlerOptions {
        public String baseUrl;
        public LongSupplier now;
        public Authenticator authenticate;
        public boolean allowUnauthenticated;
    }

    private static ScimResponse jsonResponse(int status, Object body, Map<String, String> extra) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("content-type", SCIM_CONTENT_TYPE);
        if (extra != null) h.putAll(extra);
        return new ScimResponse(status, body, h);
    }

    private static ScimResponse errorResponse(int status, String detail, String scimType) { return jsonResponse(status, scimError(status, detail, scimType), null); }

    @SuppressWarnings("unchecked")
    private static ScimResponse resourceResponse(int status, Map<String, Object> resource) {
        Map<String, Object> meta = (Map<String, Object>) resource.get("meta");
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("location", (String) meta.get("location"));
        extra.put("etag", (String) meta.get("version"));
        return jsonResponse(status, resource, extra);
    }

    /** JavaScript {@code Number(v)} of a query value (string / number / null), as a double. */
    static double toNumber(Object v) {
        if (v == null) return 0;
        if (isNumber(v)) return Double.parseDouble(v.toString());
        if (v instanceof Boolean) return ((Boolean) v) ? 1 : 0;
        if (v instanceof List) { // Number([x]) is Number(String([x]))
            StringBuilder j = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) j.append(',');
                first = false;
                if (x instanceof List || x instanceof Map) return Double.NaN;
                if (x != null) j.append(x instanceof Boolean || isNumber(x) || x instanceof String ? x.toString() : "");
            }
            return toNumber(j.toString());
        }
        if (!(v instanceof String)) return Double.NaN;
        String s = ((String) v).replaceAll("^" + WS + "+|" + WS + "+$", "");
        if (s.isEmpty()) return 0;
        try {
            if (s.matches("0[xX][0-9a-fA-F]+")) return new java.math.BigInteger(s.substring(2), 16).doubleValue();
            if (s.matches("0[oO][0-7]+")) return new java.math.BigInteger(s.substring(2), 8).doubleValue();
            if (s.matches("0[bB][01]+")) return new java.math.BigInteger(s.substring(2), 2).doubleValue();
            if (s.matches("[+-]?(Infinity)")) return s.startsWith("-") ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
            if (s.matches("[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?")) return Double.parseDouble(s);
        } catch (NumberFormatException e) { return Double.NaN; }
        return Double.NaN;
    }

    private static double parseIntParam(boolean present, Object v, double fallback) {
        if (!present) return fallback;
        double n = toNumber(v);
        return !Double.isNaN(n) && !Double.isInfinite(n) && n == Math.floor(n) ? n : fallback;
    }

    private static boolean has(Map<String, Object> q, String k) { return q != null && q.containsKey(k); }

    /**
     * A framework-agnostic SCIM 2.0 {@code /Agents} handler over {@code store}: GET (list, eq filter, paging), GET by id,
     * POST (register a passport), PUT, PATCH (RFC 7644 operations) and DELETE. Requires {@code authenticate} unless
     * {@code allowUnauthenticated} is set (throws IllegalArgumentException otherwise).
     */
    public static ScimHandler scimHandler(AgentStore store, ScimHandlerOptions options) {
        final ScimHandlerOptions opt = options == null ? new ScimHandlerOptions() : options;
        final Authenticator authenticate = opt.authenticate;
        if (authenticate == null && !opt.allowUnauthenticated) throw new IllegalArgumentException("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)");
        return req -> {
            if (authenticate != null) {
                boolean ok;
                try { ok = Boolean.TRUE.equals(authenticate.authenticate(req)); } catch (Exception e) { ok = false; }
                if (!ok) {
                    ScimResponse r = errorResponse(401, "authentication required", null);
                    Map<String, String> h = new LinkedHashMap<>();
                    h.put("content-type", SCIM_CONTENT_TYPE);
                    h.put("www-authenticate", "Bearer");
                    return new ScimResponse(r.status, r.body, h);
                }
            }
            String m = req.method;
            boolean withId = req.idGiven || req.id != null;
            String id = String.valueOf(req.id); // JavaScript's template text of a null id
            if ("GET".equals(m)) return !withId ? handleList(store, req.query) : handleGetOne(store, id);
            if ("POST".equals(m)) return withId ? errorResponse(405, "POST is not allowed on an individual Agent", null) : handleCreate(store, opt, req.body);
            if ("PUT".equals(m)) return !withId ? errorResponse(405, "PUT requires an Agent id", null) : handleReplace(store, opt, id, req.body);
            if ("PATCH".equals(m)) return !withId ? errorResponse(405, "PATCH requires an Agent id", null) : handlePatch(store, opt, id, req.body);
            if ("DELETE".equals(m)) return !withId ? errorResponse(405, "DELETE requires an Agent id", null) : handleDelete(store, id);
            return errorResponse(405, "method not allowed: " + m, null);
        };
    }

    private static MetaInput metaInput(ScimHandlerOptions o) {
        MetaInput i = new MetaInput();
        i.baseUrl = o.baseUrl;
        i.now = o.now;
        return i;
    }

    private static ScimResponse handleList(AgentStore store, Map<String, Object> query) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (StoredAgent s : store.all()) items.add(s.resource);
        Object filter = query == null ? null : query.get("filter");
        if (has(query, "filter") && !"".equals(filter)) {
            EqFilter parsed;
            try { parsed = parseFilter(filter); } catch (ScimValueException e) { return errorResponse(400, e.getMessage(), e.scimType()); }
            List<Map<String, Object>> kept = new ArrayList<>();
            for (Map<String, Object> a : items) if (matchesFilter(a, parsed)) kept.add(a);
            items = kept;
        }
        int total = items.size();
        double startIndex = Math.max(1, parseIntParam(has(query, "startIndex"), query == null ? null : query.get("startIndex"), 1));
        double from = Math.min(startIndex - 1, total);
        double to = total;
        if (has(query, "count")) to = Math.min(from + Math.max(0, parseIntParam(true, query.get("count"), total)), total);
        List<Map<String, Object>> page = new ArrayList<>(items.subList((int) from, (int) Math.max(from, to)));
        return jsonResponse(200, scimListResponse(page, total, startIndex), null);
    }

    private static ScimResponse handleCreate(AgentStore store, ScimHandlerOptions o, Object body) {
        ProvisioningRequest req;
        try { req = scimToProvisioningRequest(body); } catch (ScimValueException e) { return errorResponse(400, e.getMessage(), e.scimType()); }
        Map<String, Object> passport = Issue.issuePassport(req.identity);
        String pid = String.valueOf(passport.get("id"));
        if (store.get(pid) != null) return errorResponse(409, "an agent with this attested identity already exists (id " + pid + ")", "uniqueness");
        Map<String, Object> resource = passportToScim(passport, req.projection, metaInput(o));
        store.put(new StoredAgent(resource, passport));
        return resourceResponse(201, resource);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> rematerialize(ScimHandlerOptions o, StoredAgent existing, Map<String, Object> proj) {
        MetaInput meta = metaInput(o);
        meta.created = (String) ((Map<String, Object>) existing.resource.get("meta")).get("created");
        return passportToScim(existing.passport, proj, meta);
    }

    private static ScimResponse handleReplace(AgentStore store, ScimHandlerOptions o, String id, Object body) {
        StoredAgent existing = store.get(id);
        if (existing == null) return errorResponse(404, "Agent " + id + " not found", null);
        Map<String, Object> body0 = asRecord(body);
        if (body0 == null) return errorResponse(400, "request body must be a JSON object", "invalidSyntax");
        Map<String, Object> proj = readProjection(body0);
        if ("".equals(proj.get("owner"))) proj.put("owner", existing.resource.get("owner"));
        Map<String, Object> resource = rematerialize(o, existing, proj);
        store.put(new StoredAgent(resource, existing.passport));
        return resourceResponse(200, resource);
    }

    private static ScimResponse handlePatch(AgentStore store, ScimHandlerOptions o, String id, Object body) {
        StoredAgent existing = store.get(id);
        if (existing == null) return errorResponse(404, "Agent " + id + " not found", null);
        Map<String, Object> proj = projectionOf(existing.resource);
        try {
            for (PatchOp op : readPatchOps(body)) applyPatchOp(proj, op);
        } catch (ScimValueException e) { return errorResponse(400, e.getMessage(), e.scimType()); }
        Map<String, Object> resource = rematerialize(o, existing, proj);
        store.put(new StoredAgent(resource, existing.passport));
        return resourceResponse(200, resource);
    }

    private static ScimResponse handleDelete(AgentStore store, String id) {
        if (!store.delete(id)) return errorResponse(404, "Agent " + id + " not found", null);
        return new ScimResponse(204, null, new LinkedHashMap<>());
    }

    private static ScimResponse handleGetOne(AgentStore store, String id) {
        StoredAgent existing = store.get(id);
        if (existing == null) return errorResponse(404, "Agent " + id + " not found", null);
        return resourceResponse(200, existing.resource);
    }

    // ---- push-provision adapters ---------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> extensionAttributes(Map<String, Object> agent) {
        Map<String, Object> passport = (Map<String, Object>) agent.get("passport");
        Map<String, Object> a = obj("owner", agent.get("owner"), "model", passport.get("model_id"), "operator", passport.get("operator"),
            "hardwareRooted", passport.get("hardware_rooted"), "capabilities", new ArrayList<Object>((List<?>) agent.get("capabilities")), "passportRef", agent.get("passportRef"));
        if (agent.get("holder") != null) a.put("holder", agent.get("holder"));
        return a;
    }

    private static Object orRef(Map<String, Object> agent) { return agent.get("externalId") != null ? agent.get("externalId") : agent.get("passportRef"); }

    /** The SCIM body pushed to Microsoft Entra Agent ID's provisioning endpoint. */
    public static Map<String, Object> toEntraAgentPayload(Map<String, Object> agent) {
        return obj("schemas", new ArrayList<Object>(List.of(AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN)), "externalId", orRef(agent), "displayName", agent.get("displayName"),
            "active", agent.get("active"), ENTRA_AGENT_EXTENSION_URN, extensionAttributes(agent));
    }

    /** The SCIM body pushed to Okta: {@code userName} is the stable passport id; agent attributes sit under an Okta custom-app extension. */
    public static Map<String, Object> toOktaScimPayload(Map<String, Object> agent) {
        return obj("schemas", new ArrayList<Object>(List.of(AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN)), "userName", agent.get("passportRef"), "externalId", orRef(agent),
            "displayName", agent.get("displayName"), "active", agent.get("active"), OKTA_AGENT_EXTENSION_URN, extensionAttributes(agent));
    }

    /** A fetch response: status plus a body reader that may throw (a non-JSON body becomes null). */
    public interface FetchResponse {
        boolean ok();
        int status();
        Object json() throws Exception;
    }

    /** Minimal injectable HTTP POST. */
    public interface FetchLike { FetchResponse post(String url, Map<String, String> headers, String body) throws Exception; }

    /** Where and how to push an outbound provisioning body; {@code fetch} null uses the JDK HTTP client. */
    public static final class PushTarget {
        public final String endpoint;
        public final String token;
        public final FetchLike fetch;
        public PushTarget(String endpoint, String token, FetchLike fetch) { this.endpoint = endpoint; this.token = token; this.fetch = fetch; }
    }

    /** The outcome of a push-provision call. */
    public static final class PushResult {
        public final boolean ok;
        public final int status;
        public final Object body;
        PushResult(boolean ok, int status, Object body) { this.ok = ok; this.status = status; this.body = body; }
    }

    private static FetchLike defaultFetch() {
        HttpClient c = HttpClient.newHttpClient();
        return (url, headers, body) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            headers.forEach(b::header);
            HttpResponse<String> r = c.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new FetchResponse() {
                @Override public boolean ok() { return r.statusCode() >= 200 && r.statusCode() < 300; }
                @Override public int status() { return r.statusCode(); }
                @Override public Object json() { return Json.parseLenient(r.body()); }
            };
        };
    }

    /** POST an already-shaped provisioning payload to a directory endpoint (the body keeps the payload's key order). */
    public static PushResult pushProvision(Map<String, Object> payload, PushTarget target) throws Exception {
        FetchLike f = target.fetch != null ? target.fetch : defaultFetch();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("authorization", "Bearer " + target.token);
        headers.put("content-type", SCIM_CONTENT_TYPE);
        FetchResponse res = f.post(target.endpoint, headers, Json.stringify(payload)); // JSON.stringify: the payload's own key order
        Object body;
        try { body = res.json(); } catch (Exception e) { body = null; }
        return new PushResult(res.ok(), res.status(), body);
    }

    public static PushResult pushToEntra(Map<String, Object> agent, PushTarget target) throws Exception { return pushProvision(toEntraAgentPayload(agent), target); }

    public static PushResult pushToOkta(Map<String, Object> agent, PushTarget target) throws Exception { return pushProvision(toOktaScimPayload(agent), target); }
}
