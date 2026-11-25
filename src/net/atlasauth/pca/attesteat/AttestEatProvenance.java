package net.atlasauth.pca.attesteat;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.ProvenanceGate;
import net.atlasauth.pca.Sigstore;
import net.atlasauth.pca.jose.Jose;

/**
 * THE ARTIFACT ATTESTATION VERIFIER (port of {@code provenance.ts}): Sigstore provenance joined to runtime attestation, issued as a discharge.
 * The verifier that holds the {@code artifact}-class key runs, for one request: the Sigstore bundle against the pinned roots (offline); the digest
 * of the image that is actually running, from an EAT it already accepted (never a digest the caller states); the provenance gate (its own pins and
 * the join); and signs the discharge the request asks for, with the gate's claims. Any failure returns no discharge: provenance can only remove
 * authority.
 */
public final class AttestEatProvenance {
    private AttestEatProvenance() {}

    /**
     * The running image's digest from an ACCEPTED EAT verdict: exactly one {@code measurements} entry labelled {@code slot} (default {@code image}),
     * lowercase hex of the algorithm's length (64 for sha256, else 128). Null when the verdict is not ok, the slot is missing or repeated, or the
     * value is malformed. {@code o}: slot?, alg?. Result {alg, digest} or null.
     */
    public static Map<String, Object> runtimeDigestFromEat(Object verdict, Map<String, Object> o) {
        Map<String, Object> v = AttestEat.rec(verdict);
        if (v == null || !Boolean.TRUE.equals(v.get("ok")) || !(v.get("claims") instanceof Map)) return null;
        Map<String, Object> opts = o == null ? new LinkedHashMap<String, Object>() : o;
        Object slot = opts.get("slot") != null ? opts.get("slot") : "image";
        Object alg = opts.get("alg") != null ? opts.get("alg") : "sha256";
        Object ms = AttestEat.rec(v.get("claims")).get("measurements");
        Object hit = null;
        int hits = 0;
        if (ms != null) {
            List<Object> l = AttestEat.arr(ms);
            if (l == null) throw new IllegalArgumentException("(claims.measurements ?? []).filter is not a function");
            for (Object e : l) {
                Map<String, Object> m = AttestEat.rec(e);
                if (m != null && slot.equals(m.get("type"))) { hits++; hit = m.get("value"); }
            }
        }
        if (hits != 1) return null;
        if (!(hit instanceof String) || !((String) hit).matches("sha256".equals(alg) ? "[0-9a-f]{64}" : "[0-9a-f]{128}")) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alg", alg);
        out.put("digest", hit);
        return out;
    }

    public static Map<String, Object> runtimeDigestFromEat(Object verdict) { return runtimeDigestFromEat(verdict, null); }

    /**
     * The discharge body for a passed provenance gate and a discharge request ({@code provenanceDischargeBody}): v 1, kind pca-discharge, the request's
     * caveat id / issuer / cap_hash / bind (and action_digest), the gate's claims, iat, not_after = iat + ttl_ms and the nonce. Throws when the gate
     * refused or {@code ttl_ms} exceeds what the caveat accepts.
     */
    public static Map<String, Object> provenanceDischargeBody(Map<String, Object> request, ProvenanceGate.GateResult gate, Object iat, Object ttlMs, String nonce) {
        if (!gate.ok) throw new IllegalArgumentException("provenanceDischargeBody: the provenance gate refused (" + gate.code + ")");
        Double ttl = Jose.num(ttlMs), reqTtl = Jose.num(request.get("ttl_ms")), at = Jose.num(iat);
        if (ttl != null && reqTtl != null && ttl > reqTtl) throw new IllegalArgumentException("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", 1L);
        b.put("kind", "pca-discharge");
        b.put("caveat_id", request.get("caveat_id"));
        b.put("issuer", request.get("issuer"));
        b.put("cap_hash", request.get("cap_hash"));
        b.put("bind", request.get("bind"));
        if (request.containsKey("action_digest")) b.put("action_digest", request.get("action_digest"));
        b.put("claims", gate.claims);
        b.put("iat", iat);
        double notAfter = (at == null ? Double.NaN : at) + (ttl == null ? Double.NaN : ttl);
        b.put("not_after", notAfter == Math.rint(notAfter) && Math.abs(notAfter) < 9007199254740992.0 ? (Object) (long) notAfter : (Object) notAfter);
        b.put("nonce", nonce);
        return b;
    }

    /**
     * Issue an artifact discharge. {@code i}: bundle (a parsed Sigstore bundle), roots ({@link Sigstore.PinnedRoots}), policy ({@code provenanceGate}
     * policy), runtime? ({alg, digest} from {@link #runtimeDigestFromEat}; omit only when the policy does not require the join; an explicit null is a
     * failed join), request (the discharge request), now (verifier clock, epoch ms), issuerKey ({@link Keys.SuiteKey}, the {@code artifact}-class
     * issuer), ttl_ms? (default the request's). Result {ok: true, discharge, facts, level} or {ok: false, stage: "sigstore", code, detail} or
     * {ok: false, stage: "gate", code}. The 16-byte nonce comes from {@code nonce} (default SecureRandom).
     */
    public static Map<String, Object> issueArtifactDischarge(Map<String, Object> i, Supplier<byte[]> nonce) {
        Sigstore.Result v = Sigstore.verifySigstoreBundle(i.get("bundle"), (Sigstore.PinnedRoots) i.get("roots"));
        Map<String, Object> out = new LinkedHashMap<>();
        if (!v.ok) {
            out.put("ok", false);
            out.put("stage", "sigstore");
            out.put("code", v.code);
            out.put("detail", v.detail);
            return out;
        }
        if (i.containsKey("runtime") && i.get("runtime") == null) return gateFail("no_runtime");
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("facts", v.facts);
        in.put("policy", i.get("policy"));
        if (i.containsKey("runtime")) in.put("runtime", i.get("runtime"));
        Double now = Jose.num(i.get("now"));
        in.put("now", now == null ? null : (Object) (long) Math.floor(now / 1000));
        ProvenanceGate.GateResult gate = ProvenanceGate.provenanceGate(in);
        if (!gate.ok) return gateFail(gate.code);
        Map<String, Object> request = AttestEat.rec(i.get("request"));
        Object ttl = i.get("ttl_ms") != null ? i.get("ttl_ms") : request.get("ttl_ms");
        byte[] n = nonce != null ? nonce.get() : randomNonce();
        Map<String, Object> body = provenanceDischargeBody(request, gate, i.get("now"), ttl, java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(n));
        out.put("ok", true);
        out.put("discharge", Issue.signDischarge(body, (Keys.SuiteKey) i.get("issuerKey")));
        out.put("facts", v.facts);
        out.put("level", gate.level);
        return out;
    }

    public static Map<String, Object> issueArtifactDischarge(Map<String, Object> i) { return issueArtifactDischarge(i, null); }

    private static byte[] randomNonce() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static Map<String, Object> gateFail(String code) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("stage", "gate");
        m.put("code", code);
        return m;
    }
}
