package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Build provenance as a K1 discharge (track K9; port of the TypeScript {@code provenance-gate.ts}; refusal codes, check
 * order and reason strings are normative, shared through {@code conformance/provenance-vectors.json}).
 *
 * <p>The RFC 9162 inclusion check, the policy gates over the facts the cryptographic Sigstore check established, and the
 * {@code needs_discharge} caveat a grant uses to ask an {@code artifact} verifier for the resulting claims. Provenance can
 * only remove authority. Inputs are JSON trees ({@link Json#parse}). Total: malformed input is {@code false} or a refusal
 * code, never an exception.
 */
public final class ProvenanceGate {
    private ProvenanceGate() {}

    public static final String SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
    public static final String INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";

    private static final long MAX_SAFE = 9_007_199_254_740_991L;

    // ---- RFC 9162 inclusion ------------------------------------------------------------------------------------------

    /** RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data). */
    public static byte[] rfc9162LeafHash(byte[] data) { return Pca.sha(new byte[] {0}, data); }

    private static byte[] nodeHash(byte[] l, byte[] r) { return Pca.sha(new byte[] {1}, l, r); }

    /**
     * RFC 9162 section 2.1.3.2: verify an inclusion proof of {@code leafHash} at {@code index} in a tree of {@code size}
     * leaves with root {@code root}. {@code proof} runs from the leaf level up, without the leaf and the root. Index and size
     * are non-negative safe integers (64-bit arithmetic). False on any malformed input.
     */
    public static boolean verifyRfc9162Inclusion(byte[] leafHash, long index, long size, List<byte[]> proof, byte[] root) {
        try {
            if (!(index >= 0 && size >= 1 && size <= MAX_SAFE && index < size)) return false;
            if (leafHash == null || leafHash.length != 32 || root == null || root.length != 32) return false;
            if (proof == null || proof.size() > 64) return false;
            for (byte[] p : proof) if (p == null || p.length != 32) return false;
            long fn = index, sn = size - 1;
            byte[] r = leafHash;
            for (byte[] p : proof) {
                if (sn == 0) return false;
                if ((fn & 1) == 1 || fn == sn) {
                    r = nodeHash(p, r);
                    if ((fn & 1) == 0) {
                        while ((fn & 1) == 0 && fn != 0) {
                            fn >>= 1;
                            sn >>= 1;
                        }
                    }
                } else r = nodeHash(r, p);
                fn >>= 1;
                sn >>= 1;
            }
            return sn == 0 && Arrays.equals(r, root);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- facts and policy --------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    /** A non-empty string of at most 2048 UTF-8 bytes. */
    private static boolean str(Object v) { return IntentArtifacts.isBoundedString(v, 2048); }

    private static boolean lowerHex(Object v, int n) {
        if (!(v instanceof String) || ((String) v).length() != n) return false;
        for (char c : ((String) v).toCharArray()) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }

    private static boolean subjectError(Object s) {
        if (!(s instanceof Map) || IntentArtifacts.closedMembers(mp(s), List.of("alg", "digest"), List.of(), "object") != null) return true;
        Object alg = mp(s).get("alg");
        int n = "sha256".equals(alg) ? 64 : "sha512".equals(alg) ? 128 : -1;
        return n < 0 || !lowerHex(mp(s).get("digest"), n);
    }

    private static boolean isLevel(Object v) { return IntentJs.isInt(v) && IntentJs.lng(v) >= 1 && IntentJs.lng(v) <= 3; }

    /** Null when well-formed (closed members, bounded strings), else the reference's reason. */
    public static String provenanceFactsError(Object fo) {
        if (!(fo instanceof Map)) return "facts must be an object";
        Map<String, Object> f = mp(fo);
        String e = IntentArtifacts.closedMembers(f,
            List.of("v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"),
            List.of("source_repo", "source_ref", "source_digest", "provenance_source"), "facts");
        if (e != null) return e;
        if (!(IntentJs.isInt(f.get("v")) && IntentJs.lng(f.get("v")) == 1)) return "facts.v must be 1";
        for (String k : List.of("predicate_type", "build_type", "builder_id", "identity", "oidc_issuer")) if (!str(f.get(k))) return "facts." + k + " must be a non-empty string";
        for (String k : List.of("source_repo", "source_ref", "source_digest")) if (f.containsKey(k) && !str(f.get(k))) return "facts." + k + " must be a non-empty string";
        Object subs = f.get("subjects");
        boolean subsOk = subs instanceof List && !((List<?>) subs).isEmpty() && ((List<?>) subs).size() <= 64;
        if (subsOk) for (Object s : (List<?>) subs) if (subjectError(s)) subsOk = false;
        if (!subsOk) return "facts.subjects must be 1..64 {alg, digest}";
        if (!IntentJs.isNonNeg(f.get("integrated_time"))) return "facts.integrated_time must be a non-negative integer";
        if (!IntentJs.isNonNeg(f.get("rekor_log_index"))) return "facts.rekor_log_index must be a non-negative integer";
        if (f.containsKey("provenance_source")) {
            Object p = f.get("provenance_source");
            if (!(p instanceof Map) || IntentArtifacts.closedMembers(mp(p), List.of("uri"), List.of("git_commit"), "object") != null || !str(mp(p).get("uri"))
                || (mp(p).containsKey("git_commit") && !str(mp(p).get("git_commit")))) return "facts.provenance_source is malformed";
        }
        return null;
    }

    /** Null when well-formed, else the reference's reason. */
    public static String provenancePolicyError(Object po) {
        if (!(po instanceof Map)) return "policy must be an object";
        Map<String, Object> p = mp(po);
        String e = IntentArtifacts.closedMembers(p, List.of("roots", "min_level"),
            List.of("source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"), "policy");
        if (e != null) return e;
        Object roots = p.get("roots");
        if (!(roots instanceof List) || ((List<?>) roots).isEmpty() || ((List<?>) roots).size() > 32) return "policy.roots must hold 1..32 pairs";
        for (Object ro : (List<?>) roots) {
            if (!(ro instanceof Map) || IntentArtifacts.closedMembers(mp(ro), List.of("oidc_issuer", "builder_id", "level"), List.of("identity", "identity_prefix"), "object") != null) return "policy root is malformed";
            Map<String, Object> r = mp(ro);
            if (!str(r.get("oidc_issuer")) || !str(r.get("builder_id"))) return "policy root needs oidc_issuer and builder_id";
            if (r.containsKey("identity") == r.containsKey("identity_prefix")) return "policy root needs exactly one of identity and identity_prefix";
            if (r.containsKey("identity") && !str(r.get("identity"))) return "policy root identity is malformed";
            // a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing (length in UTF-16 units, as the reference)
            if (r.containsKey("identity_prefix") && !(str(r.get("identity_prefix")) && ((String) r.get("identity_prefix")).length() >= 10)) return "policy root identity_prefix must be at least 10 characters";
            if (!isLevel(r.get("level"))) return "policy root level must be 1, 2 or 3";
        }
        if (!isLevel(p.get("min_level"))) return "policy.min_level must be 1, 2 or 3";
        if (p.containsKey("source_repo") && !str(p.get("source_repo"))) return "policy.source_repo is malformed";
        if (p.containsKey("source_ref") && p.containsKey("source_ref_prefix")) return "policy takes source_ref or source_ref_prefix, not both";
        if (p.containsKey("source_ref") && !str(p.get("source_ref"))) return "policy.source_ref is malformed";
        if (p.containsKey("source_ref_prefix") && !str(p.get("source_ref_prefix"))) return "policy.source_ref_prefix is malformed";
        if (p.containsKey("build_types")) {
            Object b = p.get("build_types");
            boolean ok = b instanceof List && !((List<?>) b).isEmpty() && ((List<?>) b).size() <= 16;
            if (ok) for (Object x : (List<?>) b) if (!str(x)) ok = false;
            if (!ok) return "policy.build_types must hold 1..16 strings";
        }
        if (p.containsKey("max_age_s") && !(IntentJs.isInt(p.get("max_age_s")) && IntentJs.lng(p.get("max_age_s")) >= 1)) return "policy.max_age_s must be a positive integer";
        if (p.containsKey("require_runtime") && !(p.get("require_runtime") instanceof Boolean)) return "policy.require_runtime must be a boolean";
        return null;
    }

    // ---- the gate ----------------------------------------------------------------------------------------------------

    /** {@code {ok: true, level, claims}} or {@code {ok: false, code}}. */
    public static final class GateResult {
        public final boolean ok;
        public final long level;
        /** The claims of an {@code artifact} discharge (insertion order as the reference); null on refusal. */
        public final Map<String, Object> claims;
        /** The refusal code; null on success. */
        public final String code;
        GateResult(boolean ok, long level, Map<String, Object> claims, String code) { this.ok = ok; this.level = level; this.claims = claims; this.code = code; }
    }

    private static GateResult no(String code) { return new GateResult(false, 0, null, code); }

    /**
     * The provenance gates in the reference order over {@code {facts, policy, runtime?, now}}: policy, facts, clock, runtime
     * digest, predicate type, time, a pinned signer-builder pair (the highest matching level), the level floor, the
     * provenance's own source against the certificate's, the source repository and ref pins, the build type, then the
     * subject. An absent member is absent; a JSON {@code null} is present (and malformed). Total.
     */
    public static GateResult provenanceGate(Object input) {
        try {
            if (!(input instanceof Map)) return no("malformed_facts");
            Map<String, Object> in = mp(input);
            if (provenancePolicyError(in.get("policy")) != null) return no("malformed_policy");
            if (provenanceFactsError(in.get("facts")) != null) return no("malformed_facts");
            Object nowO = in.get("now");
            if (!IntentJs.isNonNeg(nowO)) return no("malformed_facts");
            long now = IntentJs.lng(nowO);
            Map<String, Object> f = mp(in.get("facts"));
            Map<String, Object> p = mp(in.get("policy"));
            boolean hasRuntime = in.containsKey("runtime");
            Object rt = in.get("runtime");
            if (hasRuntime && subjectError(rt)) return no("malformed_runtime");
            if (!SLSA_PROVENANCE_V1.equals(f.get("predicate_type"))) return no("predicate_type");
            long it = IntentJs.lng(f.get("integrated_time"));
            if (it > now) return no("future");
            if (p.containsKey("max_age_s") && now - it > IntentJs.lng(p.get("max_age_s"))) return no("stale");
            String identity = (String) f.get("identity");
            long level = 0;
            for (Object ro : (List<?>) p.get("roots")) {
                Map<String, Object> r = mp(ro);
                if (!r.get("oidc_issuer").equals(f.get("oidc_issuer")) || !r.get("builder_id").equals(f.get("builder_id"))) continue;
                if (r.containsKey("identity") ? !r.get("identity").equals(identity) : !identity.startsWith((String) r.get("identity_prefix"))) continue;
                long l = IntentJs.lng(r.get("level"));
                if (l > level) level = l;
            }
            if (level == 0) return no("no_root");
            if (level < IntentJs.lng(p.get("min_level"))) return no("level");
            if (f.containsKey("provenance_source")) {
                Map<String, Object> ps = mp(f.get("provenance_source"));
                if (ps.containsKey("git_commit") && f.containsKey("source_digest") && !ps.get("git_commit").equals(f.get("source_digest"))) return no("source_mismatch");
                if (f.containsKey("source_repo")) {
                    String uri = (String) ps.get("uri"), base = "git+" + f.get("source_repo");
                    if (!(uri.equals(base) || uri.startsWith(base + "@"))) return no("source_mismatch");
                }
            }
            if (p.containsKey("source_repo") && !p.get("source_repo").equals(f.get("source_repo"))) return no("source_repo");
            if (p.containsKey("source_ref") && !p.get("source_ref").equals(f.get("source_ref"))) return no("source_ref");
            if (p.containsKey("source_ref_prefix") && !(f.get("source_ref") instanceof String && ((String) f.get("source_ref")).startsWith((String) p.get("source_ref_prefix")))) return no("source_ref");
            if (p.containsKey("build_types") && !((List<?>) p.get("build_types")).contains(f.get("build_type"))) return no("build_type");
            List<?> subjects = (List<?>) f.get("subjects");
            Map<String, Object> subject = null;
            boolean bound = false;
            if (hasRuntime) {
                for (Object s : subjects) {
                    if (mp(s).get("alg").equals(mp(rt).get("alg")) && mp(s).get("digest").equals(mp(rt).get("digest"))) { subject = mp(s); break; }
                }
                if (subject == null) return no("runtime_mismatch");
                bound = true;
            } else {
                if (Boolean.TRUE.equals(p.get("require_runtime"))) return no("runtime_required");
                if (subjects.size() != 1) return no("subject_ambiguous");
                subject = mp(subjects.get(0));
            }
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("subject_alg", subject.get("alg"));
            claims.put("subject_digest", subject.get("digest"));
            claims.put("slsa_level", level);
            for (String k : List.of("builder_id", "build_type", "oidc_issuer", "identity", "source_repo", "source_ref", "source_digest")) if (f.containsKey(k)) claims.put(k, f.get(k));
            claims.put("rekor_log_index", IntentJs.lng(f.get("rekor_log_index")));
            claims.put("runtime_bound", bound);
            for (Object v : claims.values()) if (v instanceof String && IntentJs.u8len((String) v) > 256) return no("claim_too_long");
            return new GateResult(true, level, claims, null);
        } catch (RuntimeException e) {
            return no("malformed_facts");
        }
    }

    // ---- caveat ------------------------------------------------------------------------------------------------------

    /** Configuration of {@link #provenanceCaveat}; null members take the reference default. */
    public static final class CaveatOptions {
        /** Caveat id (K1 id syntax). null = {@code provenance}. */
        public String id;
        /** Label of the verifier's {@code artifact} pin. */
        public String issuer;
        /** 1, 2 or 3. */
        public long minLevel;
        public String sourceRepo;
        /** Allowed builder ids (1..16), when non-null. */
        public List<String> builderIds;
        public String oidcIssuer;
        /** Require {@code runtime_bound: true}. null = true. */
        public Boolean requireRuntime;
        /** {@code chain_hop} or {@code action}; null = {@code action}. */
        public String bind;
        /** null = 300 000 (5 minutes). */
        public Long ttlMs;
    }

    private static Map<String, Object> req(String claim, String op, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("claim", claim);
        m.put("op", op);
        m.put("value", value);
        return m;
    }

    /** A {@code needs_discharge} caveat that asks the pinned {@code artifact} verifier for provenance claims. */
    public static Map<String, Object> provenanceCaveat(CaveatOptions o) {
        List<Object> require = new ArrayList<>();
        require.add(req("slsa_level", "gte", o.minLevel));
        if (o.sourceRepo != null) require.add(req("source_repo", "eq", o.sourceRepo));
        if (o.builderIds != null) require.add(req("builder_id", "in", new ArrayList<Object>(o.builderIds)));
        if (o.oidcIssuer != null) require.add(req("oidc_issuer", "eq", o.oidcIssuer));
        if (!Boolean.FALSE.equals(o.requireRuntime)) require.add(req("runtime_bound", "eq", true));
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("type", CaveatLang.CAVEAT_NEEDS_DISCHARGE);
        c.put("id", o.id != null ? o.id : "provenance");
        c.put("issuer", o.issuer);
        c.put("issuer_class", "artifact");
        c.put("bind", o.bind != null ? o.bind : "action");
        c.put("ttl_ms", o.ttlMs != null ? o.ttlMs : 300_000L);
        c.put("require", require);
        return c;
    }
}
