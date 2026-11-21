package net.atlasauth.pca.schema;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;

/**
 * JSON Schema (draft 2020-12) documents for the PCA wire types (the signed action, one capability hop, the discovery
 * document) plus a small dependency-free STRUCTURAL validator. The schemas describe structure only: a document that
 * passes is well-formed, never authorized. Schemas are plain JSON trees (maps and lists), the same shape the reference
 * publishes, so any generator or validator can consume them.
 */
public final class Schema {
    private Schema() {}

    /** The outcome of {@link #validate}: {@code valid} plus a readable error list (empty when valid). */
    public record ValidationResult(boolean valid, List<String> errors) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("valid", valid);
            m.put("errors", new ArrayList<Object>(errors));
            return m;
        }
    }

    private static final String DRAFT = "https://json-schema.org/draft/2020-12/schema";
    private static final List<Object> ALGS = List.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65");

    private static Map<String, Object> o(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
    private static Map<String, Object> str() { return o("type", "string"); }
    private static Map<String, Object> ref(String name) { return o("$ref", "#/$defs/" + name); }
    private static Map<String, Object> integer() { return o("type", "integer"); }
    private static Map<String, Object> arrOf(Object items) { return o("type", "array", "items", items); }
    private static Map<String, Object> alg() { return o("type", "string", "enum", new ArrayList<>(ALGS)); }
    private static List<Object> l(Object... xs) { return new ArrayList<>(List.of(xs)); }

    private static Map<String, Object> caveatDef() {
        return o("type", "object", "required", l("type"), "properties", o("type", str()), "additionalProperties", true);
    }

    private static Map<String, Object> capabilityDef() {
        return o("type", "object", "required", l("id", "issuer", "holder", "caveats", "body_digest", "sig"),
            "properties", o("id", str(), "issuer", str(), "holder", str(), "caveats", arrOf(ref("caveat")), "parent", str(),
                "body_digest", str(), "sig", str(), "alg", alg(), "pq_pk", str(), "pq_sig", str()),
            "additionalProperties", true);
    }

    private static Map<String, Object> actionDef() {
        return o("type", "object", "required", l("verb", "resource", "params_digest", "reversibility_class"),
            "properties", o("verb", str(), "resource", str(), "params_digest", str(), "reversibility_class", str()), "additionalProperties", true);
    }

    private static Map<String, Object> inclusionProofDef() {
        return o("type", "object", "required", l("index", "size", "path"),
            "properties", o("index", integer(), "size", integer(), "path", arrOf(o("type", "object", "additionalProperties", true))), "additionalProperties", true);
    }

    private static Map<String, Object> planDef() {
        return o("type", "object", "required", l("root", "inclusion_proof", "node_id"),
            "properties", o("root", str(), "inclusion_proof", ref("inclusionProof"), "node_id", str(), "conditions_digest", str()), "additionalProperties", true);
    }

    private static Map<String, Object> riskClaimDef() {
        return o("type", "object", "required", l("r", "inputs"),
            "properties", o("r", o("type", "number"), "inputs", o("type", "object", "additionalProperties", true)), "additionalProperties", true);
    }

    private static Map<String, Object> attestationDef() {
        return o("type", "object", "required", l("quote_digest", "epoch", "model_id", "measurement", "operator"),
            "properties", o("quote_digest", str(), "epoch", integer(), "model_id", str(), "measurement", str(), "operator", str()), "additionalProperties", true);
    }

    private static Map<String, Object> provenanceDef() {
        return o("type", "object", "required", l("causal_hash", "taint_level", "trusted_refs"),
            "properties", o("causal_hash", str(), "taint_level", o("type", "number"), "trusted_refs", arrOf(str())), "additionalProperties", true);
    }

    private static Map<String, Object> freshnessDef() {
        return o("type", "object", "required", l("beacon_ref", "epoch", "accumulator_witness"),
            "properties", o("beacon_ref", str(), "epoch", integer(), "accumulator_witness", str()), "additionalProperties", true);
    }

    /** The signed action object (wire format v2). A fresh deep copy each call. */
    public static Map<String, Object> pcactnSchema() {
        Map<String, Object> props = o("ver", integer(), "action", ref("action"),
            "grant_ref", str(), "cap_chain", o("type", "array", "minItems", new Json.Num("1"), "items", ref("capability")),
            "plan", ref("plan"), "attestation", ref("attestation"), "provenance", ref("provenance"), "freshness", ref("freshness"),
            "counter", integer(), "risk_claim", ref("riskClaim"), "aud", str(), "iat", integer(), "exp", integer(), "nonce", str(),
            "caution", o("type", "number"), "rationale_commitment", str(), "progress_step", o("type", "object", "additionalProperties", true),
            "prohibition_evidence", o("type", l("object", "array")), "tool_binding", str(), "alg", alg(), "pq_pk", str(), "sig", str(), "pq_sig", str(),
            "threshold", o("type", "object", "additionalProperties", true),
            "zk_compliance", o("description", "Opaque zk-compliance proof; shape is verifier-defined."), "bond_ref", str());
        return o("$schema", DRAFT, "$id", "https://atlasauth.net/schemas/pca/pcactn.schema.json", "title", "PCActn",
            "description", "Proof-Carrying Authority action object (spec §7, wire format v2).", "type", "object",
            "required", l("ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig"),
            "properties", props, "additionalProperties", true,
            "$defs", o("caveat", caveatDef(), "capability", capabilityDef(), "action", actionDef(), "inclusionProof", inclusionProofDef(), "plan", planDef(),
                "riskClaim", riskClaimDef(), "attestation", attestationDef(), "provenance", provenanceDef(), "freshness", freshnessDef()));
    }

    /** One hop of a capability chain. */
    public static Map<String, Object> capabilitySchema() {
        Map<String, Object> m = o("$schema", DRAFT, "$id", "https://atlasauth.net/schemas/pca/capability.schema.json", "title", "Capability",
            "description", "An attenuable capability chain hop (spec §5.2).");
        m.putAll(capabilityDef());
        m.put("$defs", o("caveat", caveatDef()));
        return m;
    }

    /** The resource-server discovery document. */
    public static Map<String, Object> discoverySchema() {
        return o("$schema", DRAFT, "$id", "https://atlasauth.net/schemas/pca/discovery.schema.json", "title", "PcaDiscoveryDocument",
            "description", "The .well-known/pca-configuration discovery document (internet-wide integration).", "type", "object",
            "required", l("audience", "pca_versions", "signature_suites", "action_header"),
            "properties", o("audience", str(), "pca_versions", arrOf(integer()), "signature_suites", arrOf(str()), "action_header", str(),
                "required_checks", arrOf(str()), "endpoints", ref("endpoints"), "trusted_roots", arrOf(str()), "metadata", o("type", "object", "additionalProperties", true)),
            "additionalProperties", true,
            "$defs", o("endpoints", o("type", "object",
                "properties", o("attestation_challenge", str(), "revocation_epoch", str(), "liveness_beacon", str(), "stepup", str(), "grant", str()),
                "additionalProperties", true)));
    }

    /** Every published schema keyed by wire-type name. */
    public static Map<String, Object> allSchemas() {
        return o("PCActn", pcactnSchema(), "Capability", capabilitySchema(), "PcaDiscoveryDocument", discoverySchema());
    }

    // ---- validator ----

    @SuppressWarnings("unchecked")
    private static boolean isRecord(Object v) { return v instanceof Map; }

    private static Double num(Object v) {
        if (v instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) v).raw); } catch (NumberFormatException e) { return null; }
        }
        if (v instanceof Integer || v instanceof Long || v instanceof Double) return ((Number) v).doubleValue();
        return null;
    }

    private static boolean isIntegral(double d) { return !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d); }
    private static boolean isNegZero(double d) { return d == 0.0 && Double.doubleToRawLongBits(d) != 0L; }

    private static String jsonTypeOf(Object v) {
        if (v == null) return "null";
        if (v instanceof List) return "array";
        Double d = num(v);
        if (d != null) return isIntegral(d) ? "integer" : "number";
        if (v instanceof Boolean) return "boolean";
        if (v instanceof String) return "string";
        return "object";
    }

    private static boolean matchesType(Object expected, Object v) {
        if (!(expected instanceof String)) return false;
        Double d = num(v);
        switch ((String) expected) {
            case "object": return isRecord(v);
            case "array": return v instanceof List;
            case "string": return v instanceof String;
            case "number": return d != null && !Double.isNaN(d) && !Double.isInfinite(d);
            case "integer": return d != null && isIntegral(d) && !isNegZero(d);
            case "boolean": return v instanceof Boolean;
            case "null": return v == null;
            default: return false;
        }
    }

    /** Resolve a local {@code #/...} pointer (own keys of objects only, no unescaping). */
    private static Map<?, ?> resolveRef(Object root, String ref) {
        if (!ref.startsWith("#/")) return null;
        Object cur = root;
        for (String token : ref.substring(2).split("/", -1)) {
            if (!(cur instanceof Map) || !((Map<?, ?>) cur).containsKey(token)) return null;
            cur = ((Map<?, ?>) cur).get(token);
        }
        return cur instanceof Map ? (Map<?, ?>) cur : null;
    }

    private static String label(String path) { return path.isEmpty() ? "(root)" : path; }
    private static String join(String path, String key) { return path.isEmpty() ? key : path + "." + key; }

    /** JavaScript {@code JSON.stringify} of a scalar enum member. */
    private static String stringify(Object e) {
        if (e == null) return "null";
        if (e instanceof Boolean) return e.toString();
        if (e instanceof String) return quote((String) e);
        Double d = num(e);
        if (d != null) return stringifyNum(e, d);
        return "null";
    }

    private static String stringifyNum(Object e, double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return "null";
        String s = IntentJs.normalize(e instanceof Json.Num ? e : new Json.Num(e.toString())).toString();
        return s.equals("-0") ? "0" : s;
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    boolean lone = Character.isHighSurrogate(c) ? !(i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) : Character.isLowSurrogate(c) && !(i > 0 && Character.isHighSurrogate(s.charAt(i - 1)));
                    if (c < 0x20 || lone) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /** JavaScript {@code ===} between a JSON scalar enum member and a value (containers never match). */
    private static boolean strictEq(Object e, Object v) {
        if (e == null || v == null) return e == null && v == null;
        if (e instanceof String || v instanceof String) return e.equals(v);
        if (e instanceof Boolean || v instanceof Boolean) return e.equals(v);
        Double x = num(e), y = num(v);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    private static void checkNode(Map<?, ?> schema, Object value, String path, Object root, List<String> errors) {
        Object r = schema.get("$ref");
        if (r instanceof String) {
            Map<?, ?> resolved = resolveRef(root, (String) r);
            if (resolved == null) { errors.add(label(path) + ": unresolved $ref '" + r + "'"); return; }
            checkNode(resolved, value, path, root, errors);
            return;
        }

        Object type = schema.get("type");
        if (schema.containsKey("type")) { // a null type is present in the reference too: it matches no value
            List<?> types = type instanceof List ? (List<?>) type : Collections.singletonList(type);
            boolean ok = false;
            for (Object t : types) if (matchesType(t, value)) { ok = true; break; }
            if (!ok) {
                List<String> names = new ArrayList<>();
                for (Object t : types) names.add(t == null ? "" : t.toString());
                errors.add(label(path) + ": expected type " + String.join("|", names) + ", got " + jsonTypeOf(value));
                return;
            }
        }

        Object en = schema.get("enum");
        if (en instanceof List) {
            boolean found = false;
            for (Object e : (List<?>) en) if (strictEq(e, value)) { found = true; break; }
            if (!found) {
                List<String> parts = new ArrayList<>();
                for (Object e : (List<?>) en) parts.add(stringify(e));
                errors.add(label(path) + ": value is not one of [" + String.join(", ", parts) + "]");
            }
        }

        if (isRecord(value)) {
            Map<?, ?> rec = (Map<?, ?>) value;
            Object req = schema.get("required");
            if (req instanceof List) {
                for (Object key : (List<?>) req) {
                    String k = String.valueOf(key);
                    if (!rec.containsKey(k)) errors.add(join(path, k) + ": missing required property '" + k + "'");
                }
            }
            Object props = schema.get("properties");
            if (props instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) props).entrySet()) {
                    if (rec.containsKey(e.getKey()) && e.getValue() instanceof Map) {
                        checkNode((Map<?, ?>) e.getValue(), rec.get(e.getKey()), join(path, (String) e.getKey()), root, errors);
                    }
                }
                if (Boolean.FALSE.equals(schema.get("additionalProperties"))) {
                    for (Object key : rec.keySet()) if (!((Map<?, ?>) props).containsKey(key)) errors.add(join(path, (String) key) + ": additional property not allowed");
                }
            }
        }

        Object items = schema.get("items");
        if (value instanceof List && items instanceof Map) {
            List<?> arr = (List<?>) value;
            for (int i = 0; i < arr.size(); i++) checkNode((Map<?, ?>) items, arr.get(i), path + "[" + i + "]", root, errors);
        }
    }

    /**
     * Structural check of {@code value} against {@code schema}: JSON type, required members, enum, and the same recursively
     * through properties, items and local {@code #/...} references. Not a full draft 2020-12 validator (no pattern, format,
     * oneOf/anyOf, bounds, remote refs): feed the schemas to a real validator for that.
     */
    public static ValidationResult validate(Map<String, Object> schema, Object value) {
        List<String> errors = new ArrayList<>();
        checkNode(schema, value, "", schema, errors);
        return new ValidationResult(errors.isEmpty(), errors);
    }
}
