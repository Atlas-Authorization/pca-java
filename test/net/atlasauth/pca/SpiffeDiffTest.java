package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import net.atlasauth.pca.spiffe.Spiffe;
import net.atlasauth.pca.spiffe.SpiffeDer;
import net.atlasauth.pca.spiffe.SpiffeError;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the SPIFFE package (see the oracle header for the case shapes). */
class SpiffeDiffTest {
    private static final String MODULE = "ref-spiffe";
    private static final String SUB = "spiffe://example.org/workload/db";
    private static final long NOWMS = 1_800_000_060_000L;

    /** A failure with the reference's code: the SpiffeError code, or "jose" for any other failure. */
    static final class Fail extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;
        Fail(String code, Throwable cause) { super(cause); this.code = code; }
        @Override public String code() { return code; }
    }

    static <T> T w(Callable<T> c) {
        try { return c.call(); } catch (SpiffeError e) { throw new Fail(e.code(), e); } catch (Throwable e) { throw new Fail("jose", e); }
    }

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static long n(Object o) { return Long.parseLong(o.toString()); }
    private static Map<String, Object> obj(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }
    private static Json.Num num(long v) { return new Json.Num(Long.toString(v)); }

    /** {"$bytes": b64url} to bytes; anything else unchanged. */
    private static Object bytes(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).size() == 1 && ((Map<?, ?>) o).get("$bytes") instanceof String) return Base64.getUrlDecoder().decode((String) ((Map<?, ?>) o).get("$bytes"));
        return o;
    }

    private static Object chainOf(Object c) {
        if (c instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) c) out.add(bytes(x)); return out; }
        return c;
    }

    @Test void constants() throws Exception { OracleCases.each(MODULE, "constants", a -> obj("JWT_SVID_ALGORITHMS", new ArrayList<Object>(Spiffe.JWT_SVID_ALGORITHMS))); }
    @Test void parseSpiffeId() throws Exception { OracleCases.each(MODULE, "parseSpiffeId", a -> w(() -> Spiffe.parseSpiffeId(a.get(0)).toJson())); }
    @Test void holderBindingMessage() throws Exception { OracleCases.each(MODULE, "holderBindingMessage", a -> Spiffe.holderBindingMessage((String) a.get(0), (String) a.get(1))); }

    @Test void holderToSpiffeId() throws Exception {
        OracleCases.each(MODULE, "holderToSpiffeId", a -> {
            Map<String, Object> h = m(a.get(0));
            return w(() -> Spiffe.holderToSpiffeId(new Spiffe.SpiffeHolder((String) h.get("holder"), (String) h.get("spiffeId"), (String) h.get("trustDomain"), (String) h.get("path"))));
        });
    }

    @Test void readCertFacts() throws Exception {
        OracleCases.each(MODULE, "readCertFacts", a -> SpiffeDer.readCertFacts(Base64.getUrlDecoder().decode((String) a.get(0))).toJson());
    }

    @Test void parseX509Svid() throws Exception {
        OracleCases.each(MODULE, "parseX509Svid", a -> w(() -> {
            Spiffe.X509Svid s = Spiffe.parseX509Svid(bytes(a.get(0)));
            return obj("spiffeId", s.spiffeId.toJson(), "publicKeyDer", s.publicKeyDer);
        }));
    }

    // ---- verifyX509Svid

    private static Object x509Rev(String mode, List<Object> calls) {
        if (mode == null) return null;
        if (mode.equals("notfn")) return Spiffe.NOT_A_FUNCTION;
        return (Spiffe.X509RevocationCheck) s -> {
            calls.add(s.toJson());
            switch (mode) {
                case "false": return Boolean.FALSE;
                case "true": return Boolean.TRUE;
                case "throw": throw new IllegalStateException("boom");
                case "one": return 1L;
                default:
                    if (mode.startsWith("true@")) return s.position == Integer.parseInt(mode.substring(5));
                    return new Object(); // undef / promise: not a boolean
            }
        };
    }

    private static Spiffe.VerifyX509SvidOptions x509Opts(Map<String, Object> o, List<Object> calls) {
        Spiffe.VerifyX509SvidOptions v = new Spiffe.VerifyX509SvidOptions();
        v.trustDomain = (String) o.get("trustDomain");
        v.roots = new ArrayList<>();
        for (Object r : l(o.get("roots"))) v.roots.add(bytes(r));
        if (o.get("nowMs") != null) v.nowMs = n(o.get("nowMs"));
        if (o.get("maxChainLength") != null) v.maxChainLength = (int) n(o.get("maxChainLength"));
        v.revocation = x509Rev((String) o.get("revocation"), calls);
        return v;
    }

    @Test void verifyX509Svid() throws Exception {
        OracleCases.each(MODULE, "verifyX509Svid", a -> w(() -> {
            List<Object> calls = new ArrayList<>();
            Spiffe.X509Svid r = Spiffe.verifyX509Svid(chainOf(a.get(0)), x509Opts(m(a.get(1)), calls));
            return obj("spiffeId", r.spiffeId.toJson(), "publicKeyDer", r.publicKeyDer, "calls", calls);
        }));
    }

    // ---- JWT-SVID

    private static Object jwtRev(String mode, List<Object> calls) {
        if (mode == null) return null;
        if (mode.equals("notfn")) return Spiffe.NOT_A_FUNCTION;
        return (Spiffe.JwtRevocationCheck) s -> {
            calls.add(s.toJson());
            switch (mode) {
                case "false": case "async-false": return Boolean.FALSE;
                case "true": case "async-true": return Boolean.TRUE;
                case "throw": case "async-throw": throw new IllegalStateException("boom");
                case "one": return 1L;
                default: return new Object();
            }
        };
    }

    private static Spiffe.VerifyJwtSvidOptions jwtOpts(Map<String, Object> s, Object key, List<Object> calls) {
        Spiffe.VerifyJwtSvidOptions o = new Spiffe.VerifyJwtSvidOptions();
        o.audience = new ArrayList<>();
        Object aud = s.get("audience");
        if (aud instanceof String) o.audience.add((String) aud);
        else for (Object x : l(aud)) o.audience.add((String) x);
        o.trustDomain = (String) s.get("trustDomain");
        if (s.get("currentDateMs") != null) o.currentDateMs = n(s.get("currentDateMs"));
        if (s.get("algorithms") != null) { o.algorithms = new ArrayList<>(); for (Object x : l(s.get("algorithms"))) o.algorithms.add((String) x); }
        if (s.get("clockTolerance") != null) o.clockTolerance = s.get("clockTolerance");
        o.revocation = jwtRev((String) s.get("revocation"), calls);
        o.key = key;
        return o;
    }

    private static Object jwtKeyOf(Map<String, Object> keySpec) {
        if (keySpec.get("jwk") != null) return m(keySpec.get("jwk"));
        Map<String, Object> jwks = m(m(keySpec.get("bundle")).get("jwks"));
        return Spiffe.createTrustBundleSource(() -> obj("jwks", jwks), 1000, 5000, () -> NOWMS).jwtKey;
    }

    @Test void jwtSession() throws Exception {
        OracleCases.each(MODULE, "jwtSession", a -> w(() -> {
            Map<String, Object> s = m(a.get(0));
            List<Object> calls = new ArrayList<>();
            Spiffe.JwtSvid r = Spiffe.verifyJwtSvid((String) s.get("token"), jwtOpts(s, jwtKeyOf(m(s.get("key"))), calls));
            return obj("spiffeId", r.spiffeId.toJson(), "claims", r.claims, "audience", r.audience, "expiresAt", r.expiresAt, "calls", calls);
        }));
    }

    // ---- holder binding

    private static Spiffe.SvidToHolderOptions bind(Map<String, Object> s) {
        Spiffe.SvidToHolderOptions o = new Spiffe.SvidToHolderOptions();
        if (s.get("proof") != null) o.proof = (String) s.get("proof");
        o.acceptUnboundJwtHolder = Boolean.TRUE.equals(s.get("acceptUnbound")) || Boolean.TRUE.equals(s.get("acceptUnboundJwtHolder"));
        return o;
    }

    @Test void holderSession() throws Exception {
        OracleCases.each(MODULE, "holderSession", a -> w(() -> {
            Map<String, Object> s = m(a.get(0));
            String kind = (String) s.get("svid");
            Object svid;
            if ("x509".equals(kind)) {
                Spiffe.VerifyX509SvidOptions v = new Spiffe.VerifyX509SvidOptions();
                v.trustDomain = "example.org";
                v.roots = l(s.get("roots"));
                v.nowMs = n(s.get("nowMs"));
                svid = Spiffe.verifyX509Svid(s.get("chain"), v);
            } else if ("x509-parsed".equals(kind)) svid = Spiffe.parseX509Svid(s.get("chain"));
            else if ("jwt".equals(kind)) {
                Map<String, Object> j = m(s.get("jwt"));
                svid = Spiffe.verifyJwtSvid((String) j.get("token"), jwtOpts(j, m(j.get("jwk")), new ArrayList<>()));
            } else if ("string".equals(kind)) svid = SUB;
            else if ("parsed-id".equals(kind)) svid = Spiffe.parseSpiffeId(SUB);
            else if ("hand-built".equals(kind)) svid = obj("claims", obj());
            else svid = null;
            Spiffe.SvidToHolderOptions o = bind(s);
            String op = (String) s.get("op");
            Object hk = s.get("holderKey");
            // an explicit JSON null is a key the reference refuses; only an absent key means "derive it from the SVID"
            if (op.equals("holder")) return obj("holder", Spiffe.svidToHolder(svid, hk == null && s.containsKey("holderKey") ? new Object() : bytes(hk), o).toJson());
            if (op.equals("forHolder")) {
                if (hk == null || hk instanceof String) return obj("spiffeId", Spiffe.spiffeIdForHolder(svid, (String) hk, o));
                Spiffe.svidToHolder(svid, hk, o); // a non-string key is refused (a raw object is not a key)
                throw new IllegalStateException("unreachable: a non-string holder key was accepted");
            }
            return obj("pin", Spiffe.workloadDischargePin((String) s.get("label"), svid));
        }));
    }

    // ---- caches (manual clock)

    private static Map<String, Object> cacheSession(boolean revocation, Map<String, Object> s) {
        long[] t = {n(s.get("start"))};
        int[] fetchCalls = {0};
        List<Object> fetches = l(s.get("fetches"));
        Spiffe.Fetch<Object> fetch = () -> {
            Map<String, Object> f = m(fetches.get(Math.min(fetchCalls[0], fetches.size() - 1)));
            fetchCalls[0]++;
            if (Boolean.TRUE.equals(f.get("throw"))) throw new IllegalStateException("fetch failed");
            return f.get("list");
        };
        double refreshMs = Double.parseDouble(s.get("refreshMs").toString()), maxStaleMs = Double.parseDouble(s.get("maxStaleMs").toString());
        Spiffe.RevocationSource rs = revocation ? Spiffe.createRevocationSource(fetch, refreshMs, maxStaleMs, () -> t[0]) : null;
        Spiffe.TrustBundleSource bs = revocation ? null : Spiffe.createTrustBundleSource(fetch, refreshMs, maxStaleMs, () -> t[0]);
        List<Object> out = new ArrayList<>();
        for (Object so : l(s.get("steps"))) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            try {
                Object v = null;
                if (op.equals("adv")) { t[0] += n(st.get("ms")); out.add(obj("v", num(t[0]))); continue; }
                if (op.equals("x509")) {
                    Map<String, Object> x = m(st.get("subject"));
                    v = rs.x509.check(new Spiffe.X509RevocationSubject((String) x.get("spiffeId"), (String) x.get("serialNumber"), (String) x.get("fingerprint256"), (int) n(x.get("position")), Boolean.TRUE.equals(x.get("isLeaf"))));
                } else if (op.equals("jwt")) {
                    Map<String, Object> x = m(st.get("subject"));
                    v = rs.jwt.check(new Spiffe.JwtRevocationSubject((String) x.get("spiffeId"), (String) x.get("jti"), x.get("expiresAt"), (String) x.get("tokenHash")));
                } else if (op.equals("refresh")) rs.refresh();
                else if (op.equals("ensureFresh")) rs.ensureFresh();
                else if (op.equals("x509Roots")) v = bs.x509Roots();
                else {
                    Map<String, Object> k = bs.jwtKey.resolve(m(st.get("header")), null);
                    Map<String, Object> proj = new LinkedHashMap<>();
                    proj.put("kty", k.get("kty"));
                    for (String f : new String[] {"crv", "x", "n"}) if (k.get(f) != null) proj.put(f, k.get(f));
                    v = proj;
                }
                out.add(obj("v", v));
            } catch (SpiffeError e) {
                out.add(obj("code", e.code()));
            } catch (Exception e) {
                out.add(obj("code", "jose"));
            }
        }
        return obj("steps", out, "fetchCalls", num(fetchCalls[0]));
    }

    @Test void revocationSession() throws Exception { OracleCases.each(MODULE, "revocationSession", a -> w(() -> cacheSession(true, m(a.get(0))))); }
    @Test void bundleSession() throws Exception { OracleCases.each(MODULE, "bundleSession", a -> w(() -> cacheSession(false, m(a.get(0))))); }

    // ---- admission

    private static final Set<String> KNOWN = Set.of("malformed_spiffe_id", "empty_trust_domain", "trust_domain_too_long", "invalid_trust_domain", "invalid_path", "id_too_long", "missing_audience", "missing_exp",
        "malformed_token", "invalid_subject", "trust_domain_mismatch", "no_uri_san", "multiple_uri_san", "invalid_holder_key", "unverified_svid", "missing_trust_domain", "holder_binding_failed", "malformed_certificate",
        "leaf_is_ca", "leaf_no_digital_signature", "leaf_cert_sign", "leaf_crl_sign", "leaf_root_path", "unsupported_critical_extension", "forbidden_algorithm", "invalid_typ", "chain_empty", "chain_trust_domain_mismatch",
        "chain_signature", "chain_not_ca", "chain_no_key_cert_sign", "chain_path_len", "chain_expired", "chain_untrusted_root", "chain_too_long", "trust_bundle_unavailable", "trust_bundle_invalid", "svid_revoked", "chain_revoked",
        "revocation_unavailable", "SVID is bound to a different key");

    @Test void admission() throws Exception {
        OracleCases.each(MODULE, "admission", a -> {
            Map<String, Object> s = m(a.get(0));
            Spiffe.SpiffeEvidence e = new Spiffe.SpiffeEvidence();
            e.kind = (String) s.get("kind");
            if (s.get("bind") != null) e.bind = bind(m(s.get("bind")));
            if ("x509".equals(e.kind)) {
                e.chain = s.get("chain");
                e.verifyX509 = new Spiffe.VerifyX509SvidOptions();
                e.verifyX509.trustDomain = "example.org";
                e.verifyX509.roots = l(s.get("roots"));
                e.verifyX509.nowMs = n(s.get("nowMs"));
            } else {
                e.token = (String) s.get("token");
                e.verifyJwt = new Spiffe.VerifyJwtSvidOptions();
                e.verifyJwt.audience = new ArrayList<>(List.of("api"));
                e.verifyJwt.trustDomain = "example.org";
                e.verifyJwt.currentDateMs = NOWMS;
                e.verifyJwt.key = m(s.get("jwk"));
            }
            Map<String, Object> r = Spiffe.spiffeAdmissionEvidence(e, (String) s.get("instanceKey")).toJson();
            if (r.get("reason") != null && !KNOWN.contains(r.get("reason"))) r.put("reason", "other");
            return r;
        });
    }
}
