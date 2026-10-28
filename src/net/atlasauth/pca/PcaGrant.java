package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The {@code pca_grant} OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The
 * type is a pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Total: never throws. Results:
 * validate returns null (accepted) or a code; parse and check return a {@link Result}.
 */
public final class PcaGrant {
    private PcaGrant() {}

    public static final String TYPE = "pca_grant";
    public static final String DOMAIN = "atlas-pca/pca-grant-chain/v1";
    private static final Set<String> MEMBERS = Set.of("type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations");
    private static final Set<String> REFUSED = Set.of("actions", "datatypes", "identifier", "privileges");

    /** Outcome of parse / check: {@code code} is null on success; {@code details} (parse) or {@code index} (check) carry the success value. */
    public static final class Result {
        public final String code;
        public final List<Map<String, Object>> details;
        public final int index;
        Result(String code, List<Map<String, Object>> details, int index) { this.code = code; this.details = details; this.index = index; }
    }

    /** https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'. */
    public static boolean isHttpsUrl(Object o) {
        if (!(o instanceof String)) return false;
        String u = (String) o;
        if (u.length() > 2048 || !u.startsWith("https://")) return false;
        for (int i = 0; i < u.length(); i++) {
            char c = u.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '#' || c == '\\') return false;
        }
        String rest = u.substring(8);
        int end = rest.length();
        for (int i = 0; i < rest.length(); i++) if (rest.charAt(i) == '/' || rest.charAt(i) == '?') { end = i; break; }
        String authority = rest.substring(0, end);
        return !authority.isEmpty() && authority.indexOf('@') < 0;
    }

    public static String chainDigest(List<String> ids) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", DOMAIN);
        m.put("ids", new ArrayList<Object>(ids));
        return Pca.hashCanonical(m);
    }

    @SuppressWarnings("unchecked")
    public static String validate(Object x) {
        if (!(x instanceof Map)) return "bad_entry";
        Map<String, Object> m = (Map<String, Object>) x;
        if (!TYPE.equals(m.get("type"))) return "bad_type";
        for (String k : m.keySet()) {
            if (REFUSED.contains(k)) return "refused_member";
            if (!MEMBERS.contains(k)) return "unknown_member";
        }
        Object d = m.get("chain_digest");
        if (!(d instanceof String) || Pca.decodeB64uStrict(d, 32) == null) return "bad_chain_digest";
        Object n = m.get("chain_len");
        if (!Json.isSafeInt(n) || Json.asLong(n) < 1 || Json.asLong(n) > 16) return "bad_chain_len";
        if (m.containsKey("chain_ref") && !isHttpsUrl(m.get("chain_ref"))) return "bad_chain_ref";
        if (m.containsKey("bundle_revision") && !(Json.isSafeInt(m.get("bundle_revision")) && Json.asLong(m.get("bundle_revision")) >= 0)) return "bad_bundle_revision";
        if (m.containsKey("locations")) {
            Object l = m.get("locations");
            if (!(l instanceof List) || ((List<Object>) l).isEmpty() || ((List<Object>) l).size() > 8) return "bad_locations";
            for (Object u : (List<Object>) l) if (!isHttpsUrl(u)) return "bad_locations";
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static Result parse(Object arr) {
        if (!(arr instanceof List)) return new Result("not_an_array", null, -1);
        List<Object> l = (List<Object>) arr;
        if (l.size() > 16) return new Result("too_many_details", null, -1);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object e : l) {
            if (!(e instanceof Map) || !(((Map<String, Object>) e).get("type") instanceof String)) return new Result("bad_entry", null, -1);
            Map<String, Object> m = (Map<String, Object>) e;
            if (!TYPE.equals(m.get("type"))) continue;
            String code = validate(m);
            if (code != null) return new Result(code, null, -1);
            out.add(m);
        }
        return new Result(null, out, -1);
    }

    /** Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource). */
    @SuppressWarnings("unchecked")
    public static Result check(List<Map<String, Object>> details, String resource, List<String> chainIds, boolean proofVerified) {
        if (details.isEmpty()) return new Result("no_detail", null, -1);
        if (!proofVerified) return new Result("proof_required", null, -1);
        String reason = "chain_mismatch";
        for (int i = 0; i < details.size(); i++) {
            Map<String, Object> d = details.get(i);
            int n = (int) Json.asLong(d.get("chain_len"));
            if (chainIds.size() < n || !chainDigest(chainIds.subList(0, n)).equals(d.get("chain_digest"))) continue;
            Object loc = d.get("locations");
            if (loc != null && !((List<Object>) loc).contains(resource)) { reason = "wrong_location"; continue; }
            return new Result(null, null, i);
        }
        return new Result(reason, null, -1);
    }
}
