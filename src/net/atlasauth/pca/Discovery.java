package net.atlasauth.pca;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Resource-server discovery ({@code .well-known/pca-configuration}): the OIDC-discovery analog for Proof-Carrying Authority. A resource
 * server publishes a small JSON document describing how to talk PCA to it (its audience id, the signature suites it accepts, the header it
 * reads the PCActn from, the freshness and step-up endpoints); a client fetches it once and auto-configures. The document is public,
 * non-secret configuration. Documents are plain maps with the member names of the wire; a malformed document throws
 * {@link IllegalArgumentException} (fail closed).
 */
public final class Discovery {
    private Discovery() {}

    public static final String WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration";

    private static final List<String> INTENT_MEMBERS = Arrays.asList("versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri");

    private static IllegalArgumentException bad(String m) { return new IllegalArgumentException("parseDiscoveryDocument: " + m); }

    private static boolean str(Object o) { return o instanceof String; }

    private static boolean strings(Object o) {
        if (!(o instanceof List)) return false;
        for (Object x : (List<?>) o) if (!str(x)) return false;
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return (Map<String, Object>) o; }

    /** Validate an {@code intent} discovery block (versions, actions_uri, schema_keys, question_relay, tiers, evidence_uri); anything malformed throws. */
    public static Map<String, Object> parseDiscoveryIntent(Object v) {
        if (!(v instanceof Map)) throw bad("intent must be an object");
        Map<String, Object> o = asMap(v);
        for (String k : o.keySet()) if (!INTENT_MEMBERS.contains(k)) throw bad("intent has unknown member '" + k + "'");
        Object vs = o.get("versions");
        boolean versionsOk = vs instanceof List && !((List<?>) vs).isEmpty();
        if (versionsOk) for (Object n : (List<?>) vs) { Double d = JsVal.num(n); if (d == null || (d != 1.0 && d != 2.0)) { versionsOk = false; break; } }
        if (!versionsOk) throw bad("intent.versions must list 1 and/or 2");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("versions", new ArrayList<>((List<?>) vs));
        for (String k : new String[] {"actions_uri", "evidence_uri"}) {
            if (o.containsKey(k)) {
                if (!str(o.get(k)) || ((String) o.get(k)).isEmpty()) throw bad("intent." + k + " must be a non-empty string");
                out.put(k, o.get(k));
            }
        }
        if (o.containsKey("schema_keys")) {
            if (!(o.get("schema_keys") instanceof List)) throw bad("intent.schema_keys must be an array");
            List<Object> keys = new ArrayList<>();
            for (Object x : (List<?>) o.get("schema_keys")) {
                if (!(x instanceof Map) || !str(asMap(x).get("kid")) || !str(asMap(x).get("alg")) || !str(asMap(x).get("pk")) || (asMap(x).containsKey("pq_pk") && !str(asMap(x).get("pq_pk"))))
                    throw bad("intent.schema_keys entries are {kid, alg, pk, pq_pk?}");
                Map<String, Object> e = asMap(x), k = new LinkedHashMap<>();
                k.put("kid", e.get("kid"));
                k.put("alg", e.get("alg"));
                k.put("pk", e.get("pk"));
                if (e.containsKey("pq_pk")) k.put("pq_pk", e.get("pq_pk"));
                keys.add(k);
            }
            out.put("schema_keys", keys);
        }
        if (o.containsKey("question_relay")) {
            if (!(o.get("question_relay") instanceof Boolean)) throw bad("intent.question_relay must be a boolean");
            out.put("question_relay", o.get("question_relay"));
        }
        if (o.containsKey("tiers")) {
            if (!(o.get("tiers") instanceof Map)) throw bad("intent.tiers must be an object");
            for (Object n : asMap(o.get("tiers")).values()) {
                Double d = JsVal.num(n);
                if (d == null || d != Math.rint(d) || d < 0 || (d == 0 && 1 / d < 0) || d > 4) throw bad("intent.tiers values must be integers 0..4");
            }
            out.put("tiers", new LinkedHashMap<>(asMap(o.get("tiers"))));
        }
        return out;
    }

    /**
     * Build a well-formed discovery document from options ({@code audience}, {@code signatureSuites}, {@code pcaVersions}, {@code actionHeader},
     * {@code requiredChecks}, {@code endpoints}, {@code trustedRoots}, {@code metadata}, {@code intent}, {@code obligationsSupported}). Throws on an empty audience.
     */
    public static Map<String, Object> buildDiscoveryDocument(Map<String, Object> opts) {
        Object aud = opts.get("audience");
        if (!str(aud) || ((String) aud).isEmpty()) throw new IllegalArgumentException("buildDiscoveryDocument: audience is required");
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("audience", aud);
        d.put("pca_versions", opts.get("pcaVersions") != null ? opts.get("pcaVersions") : new ArrayList<Object>(List.of(2L)));
        d.put("signature_suites", opts.get("signatureSuites") != null ? opts.get("signatureSuites") : new ArrayList<Object>(List.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")));
        d.put("action_header", opts.get("actionHeader") != null ? opts.get("actionHeader") : "PCA-Action");
        d.put("required_checks", opts.get("requiredChecks") != null ? opts.get("requiredChecks")
            : new ArrayList<Object>(List.of("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")));
        if (opts.get("endpoints") != null) d.put("endpoints", opts.get("endpoints"));
        if (opts.get("trustedRoots") != null) d.put("trusted_roots", opts.get("trustedRoots"));
        if (opts.get("metadata") != null) d.put("metadata", opts.get("metadata"));
        if (opts.get("intent") != null) d.put("intent", parseDiscoveryIntent(opts.get("intent")));
        if (opts.get("obligationsSupported") != null) d.put("obligations_supported", new ArrayList<>((List<?>) opts.get("obligationsSupported")));
        return d;
    }

    /** Validate and narrow an untrusted value into a discovery document. Throws on anything malformed. */
    public static Map<String, Object> parseDiscoveryDocument(Object value) {
        if (!(value instanceof Map) && !(value instanceof List)) throw bad("not an object"); // an array is an object to the reference: it fails on the first member
        Map<String, Object> v = value instanceof Map ? asMap(value) : new LinkedHashMap<>();
        if (!str(v.get("audience")) || ((String) v.get("audience")).isEmpty()) throw bad("missing audience");
        boolean versionsOk = v.get("pca_versions") instanceof List;
        if (versionsOk) for (Object n : (List<?>) v.get("pca_versions")) if (JsVal.num(n) == null) { versionsOk = false; break; }
        if (!versionsOk) throw bad("pca_versions must be a number[]");
        if (!strings(v.get("signature_suites"))) throw bad("signature_suites must be a string[]");
        if (!str(v.get("action_header")) || ((String) v.get("action_header")).isEmpty()) throw bad("missing action_header");
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("audience", v.get("audience"));
        doc.put("pca_versions", v.get("pca_versions"));
        doc.put("signature_suites", v.get("signature_suites"));
        doc.put("action_header", v.get("action_header"));
        if (strings(v.get("required_checks"))) doc.put("required_checks", v.get("required_checks"));
        if (v.get("endpoints") instanceof Map || v.get("endpoints") instanceof List) doc.put("endpoints", v.get("endpoints"));
        if (strings(v.get("trusted_roots"))) doc.put("trusted_roots", v.get("trusted_roots"));
        if (v.get("metadata") instanceof Map || v.get("metadata") instanceof List) doc.put("metadata", v.get("metadata"));
        if (v.containsKey("intent")) doc.put("intent", parseDiscoveryIntent(v.get("intent")));
        if (v.containsKey("obligations_supported")) {
            if (!strings(v.get("obligations_supported"))) throw bad("obligations_supported must be a string[]");
            doc.put("obligations_supported", new ArrayList<>((List<?>) v.get("obligations_supported")));
        }
        return doc;
    }

    /** True iff this server (per its discovery document) accepts the signature suite. */
    public static boolean acceptsSuite(Map<String, Object> doc, String suite) {
        Object s = doc == null ? null : doc.get("signature_suites");
        return s instanceof List && ((List<?>) s).contains(suite);
    }

    /** The transport of {@link #fetchDiscovery}: a GET of {@code url}. */
    public interface Fetch {
        Reply get(String url, Map<String, String> headers) throws Exception;
    }

    /** A fetch answer: {@code ok} (2xx), the status and the parsed JSON body. */
    public static final class Reply {
        public final boolean ok;
        public final int status;
        public final Object json;
        public Reply(boolean ok, int status, Object json) { this.ok = ok; this.status = status; this.json = json; }
    }

    /** The default transport: a GET over the JDK HTTP client, the body parsed with the strict JSON profile. */
    public static Fetch defaultFetch() {
        HttpClient client = HttpClient.newHttpClient();
        return (url, headers) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).GET();
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            boolean ok = r.statusCode() >= 200 && r.statusCode() < 300;
            return new Reply(ok, r.statusCode(), ok ? Json.parse(r.body()) : null);
        };
    }

    /**
     * Fetch and parse a resource server's discovery document. {@code baseUrl} is the server origin (trailing slashes are dropped); the
     * well-known path is appended. Throws on a non-2xx answer or a malformed document. {@code fetch} null = the JDK HTTP client.
     */
    public static Map<String, Object> fetchDiscovery(String baseUrl, Fetch fetch) throws Exception {
        Fetch f = fetch != null ? fetch : defaultFetch();
        int end = baseUrl.length();
        while (end > 0 && baseUrl.charAt(end - 1) == '/') end--;
        String url = baseUrl.substring(0, end) + WELL_KNOWN_PCA_PATH;
        Map<String, String> h = new LinkedHashMap<>();
        h.put("accept", "application/json");
        Reply res = f.get(url, h);
        if (!res.ok) throw new IllegalStateException("fetchDiscovery: " + url + " returned " + res.status);
        return parseDiscoveryDocument(res.json);
    }
}
