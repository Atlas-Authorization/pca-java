package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import net.atlasauth.pca.dpop.Dpop;
import org.junit.jupiter.api.Test;

/**
 * Differential test of {@link Dpop} against the TypeScript reference (test-data/ref-dpop.json.gz): thumbprints, algorithm mapping,
 * URL reduction, replay stores, server nonces, proof creation and verification (every refusal code), mTLS confirmation and the
 * PCActn binding. A reference throw requires a throw (and the same code for a DpopVerificationError).
 */
public class DpopDiffTest {
    static final String M = "ref-dpop";

    /** A native refusal carrying the reference's stable error code. */
    static final class CodedEx extends RuntimeException implements OracleCases.Coded {
        private final String code;
        CodedEx(String code, String message) { super(message); this.code = code; }
        @Override public String code() { return code; }
    }

    static Object wrap(Callable<Object> f) throws Exception {
        try {
            return f.call();
        } catch (Dpop.DpopVerificationError e) {
            throw new CodedEx(e.code(), e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static String s(Object o) { return o instanceof String ? (String) o : null; }

    static Double d(Object o) { return OracleCases.num(o); }

    /** {"$bytes": b64u} -> byte[]; a string stays a string. */
    static Object cert(Object o) {
        Map<String, Object> mm = m(o);
        if (mm != null && mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
        return o;
    }

    // ---- stores ----

    static Dpop.DpopReplayStore store(Map<String, Object> s) {
        String kind = (String) s.get("kind");
        switch (kind) {
            case "memory": {
                Dpop.DpopReplayStore st = Dpop.createInMemoryDpopReplayStore(d(s.get("maxEntries")));
                if (s.get("preload") instanceof List) {
                    for (Object p : (List<?>) s.get("preload")) {
                        List<?> t = (List<?>) p;
                        st.addIfAbsent((String) t.get(0), d(t.get(1)), d(t.get(2)));
                    }
                }
                return st;
            }
            case "true": return (k, e, n) -> true;
            case "false": return (k, e, n) -> false;
            default: return (k, e, n) -> { throw new IllegalStateException("boom"); };
        }
    }

    static Dpop.JtiSeenSet seenSet(Set<String> set) {
        return new Dpop.JtiSeenSet() {
            @Override public boolean has(String jti) { return set.contains(jti); }
            @Override public void add(String jti) { set.add(jti); }
        };
    }

    /** The verify options an oracle case describes; {@code seen} receives the jti set when the case has one. */
    static Dpop.VerifyDpopProofOptions opts(Map<String, Object> o, Set<String>[] seen) {
        Dpop.VerifyDpopProofOptions v = new Dpop.VerifyDpopProofOptions();
        v.method = s(o.get("method"));
        v.url = s(o.get("url"));
        v.maxAgeSec = d(o.get("maxAgeSec")) == null ? 0 : d(o.get("maxAgeSec"));
        v.expectedJkt = s(o.get("expectedJkt"));
        v.requireReplayStore = o.get("requireReplayStore") instanceof Boolean ? (Boolean) o.get("requireReplayStore") : null;
        v.nowSec = d(o.get("nowSec"));
        v.expectedNonce = s(o.get("expectedNonce"));
        v.accessToken = s(o.get("accessToken"));
        if (o.get("seenJti") instanceof List) {
            Set<String> set = new LinkedHashSet<>();
            for (Object x : (List<?>) o.get("seenJti")) set.add((String) x);
            seen[0] = set;
            v.seenJti = seenSet(set);
        }
        if (m(o.get("replayStore")) != null) v.replayStore = store(m(o.get("replayStore")));
        if (m(o.get("nonceIssuer")) != null) {
            Map<String, Object> ni = m(o.get("nonceIssuer"));
            v.nonceIssuer = Dpop.createDpopNonceIssuer(Keys.unb64u((String) ni.get("secret")), d(ni.get("ttl")));
        }
        return v;
    }

    static Dpop.AssertPcaDpopOptions assertOpts(Dpop.VerifyDpopProofOptions v, boolean hasMaxAge, Map<String, Object> o) {
        Dpop.AssertPcaDpopOptions a = new Dpop.AssertPcaDpopOptions();
        a.method = v.method;
        a.url = v.url;
        a.maxAgeSec = hasMaxAge ? v.maxAgeSec : null;
        a.seenJti = v.seenJti;
        a.replayStore = v.replayStore;
        a.requireReplayStore = v.requireReplayStore;
        a.nonceIssuer = v.nonceIssuer;
        a.nowSec = v.nowSec;
        a.expectedNonce = v.expectedNonce;
        a.accessToken = v.accessToken;
        return a;
    }

    static Map<String, Object> result(Dpop.DpopVerifyResult r, Set<String> seen) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("claims", r.claims);
        out.put("jwk", r.jwk);
        out.put("jkt", r.jkt);
        if (seen != null) out.put("seen", new ArrayList<>(seen));
        return out;
    }

    static Dpop.CreateDpopProofInput createInput(Map<String, Object> in) {
        Dpop.CreateDpopProofInput c = new Dpop.CreateDpopProofInput();
        c.method = s(in.get("method"));
        c.url = s(in.get("url"));
        c.privateKey = m(in.get("privateKey"));
        c.publicJwk = m(in.get("publicJwk"));
        c.nonce = s(in.get("nonce"));
        c.ath = s(in.get("ath"));
        c.iat = d(in.get("iat"));
        c.jti = s(in.get("jti"));
        return c;
    }

    // ---- tests ----

    /** ref-dpop-rsa.json.gz is generated by CI (.github/scripts/dpop-rsa-corpus.sh), never committed: required when CI is set, skipped locally. */
    @Test void rsaCorpusIsPresent() {
        java.nio.file.Path p = BaseOracle.corpusPath(BaseOracle.RSA);
        String ci = System.getenv("CI");
        boolean inCi = "true".equals(ci) || "1".equals(ci);
        String msg = "RSA DPoP corpus missing: " + p + " (generate with .github/scripts/dpop-rsa-corpus.sh or set PCA_DPOP_RSA_CORPUS)";
        if (inCi) assertTrue(java.nio.file.Files.exists(p), msg);
        else org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.exists(p), msg);
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("allowedAlgs", Dpop.DPOP_ALLOWED_ALGS);
            r.put("typ", Dpop.DPOP_JWT_TYP);
            r.put("defaultMaxAgeSec", Dpop.DPOP_DEFAULT_MAX_AGE_SEC);
            r.put("clockSkewSec", Dpop.DPOP_CLOCK_SKEW_SEC);
            r.put("maxProofBytes", Dpop.DPOP_MAX_PROOF_BYTES);
            r.put("inMemoryMaxEntries", Dpop.DPOP_INMEMORY_MAX_ENTRIES);
            return r;
        });
    }

    @Test void jwkThumbprint() throws Exception {
        OracleCases.each(M, "jwkThumbprint", a -> wrap(() -> {
            if (!(a.get(0) instanceof Map)) throw new IllegalArgumentException("JWK must be an object");
            return Dpop.jwkThumbprint(m(a.get(0)), a.size() > 1 ? s(a.get(1)) : null);
        }));
    }

    @Test void dpopAlgForJwk() throws Exception {
        OracleCases.each(M, "dpopAlgForJwk", a -> wrap(() -> Dpop.dpopAlgForJwk(a.get(0) == null ? null : a.get(0) instanceof Map ? m(a.get(0)) : new LinkedHashMap<>())));
    }

    @Test void dpopAlgMatchesJwk() throws Exception {
        OracleCases.each(M, "dpopAlgMatchesJwk", a -> wrap(() -> Dpop.dpopAlgMatchesJwk((String) a.get(0), a.get(1))));
    }

    @Test void normalizeHtu() throws Exception {
        OracleCases.each(M, "normalizeHtu", a -> {
            if (!(a.get(0) instanceof String)) throw new IllegalArgumentException("Invalid URL");
            return Dpop.normalizeHtu((String) a.get(0));
        });
    }

    @Test void athFor() throws Exception {
        OracleCases.each(M, "athFor", a -> Dpop.athFor((String) a.get(0)));
    }

    @Test void nonceIssuer() throws Exception {
        OracleCases.each(M, "nonceIssuer", a -> wrap(() -> {
            Dpop.DpopNonceIssuer iss = Dpop.createDpopNonceIssuer(a.get(0) == null ? null : Keys.unb64u((String) a.get(0)), d(a.get(1)));
            List<String> issued = new ArrayList<>();
            List<Object> out = new ArrayList<>();
            for (Object o : (List<?>) a.get(2)) {
                Map<String, Object> op = m(o);
                Double now = d(op.get("now"));
                if ("issue".equals(op.get("op"))) {
                    if (now != null && now != Math.rint(now)) throw new IllegalArgumentException("not an integer");
                    String n = iss.issue(now == null ? null : (long) (double) now);
                    issued.add(n);
                    out.add(n);
                } else {
                    Object nonce = op.get("nonce");
                    Map<String, Object> ref = m(nonce);
                    if (ref != null && ref.containsKey("$issued")) nonce = issued.get((int) (double) d(ref.get("$issued")));
                    out.add(iss.check(nonce, now));
                }
            }
            return out;
        }));
    }

    @Test void replayStore() throws Exception {
        OracleCases.each(M, "replayStore", a -> wrap(() -> {
            if (a.get(0) != null && d(a.get(0)) == null) throw new IllegalArgumentException("maxEntries must be a positive integer");
            Dpop.DpopReplayStore st = Dpop.createInMemoryDpopReplayStore(d(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (Object o : (List<?>) a.get(1)) {
                Map<String, Object> op = m(o);
                try {
                    out.add(st.addIfAbsent((String) op.get("key"), d(op.get("exp")), d(op.get("now"))));
                } catch (RuntimeException e) {
                    out.add("throws");
                }
            }
            return out;
        }));
    }

    @Test void replayConformance() throws Exception {
        OracleCases.each(M, "replayConformance", a -> {
            String kind = (String) a.get(0);
            Supplier<Dpop.DpopReplayStore> make = () -> {
                switch (kind) {
                    case "memory": return Dpop.createInMemoryDpopReplayStore(null);
                    case "alwaysTrue": return (k, e, n) -> true;
                    case "alwaysFalse": return (k, e, n) -> false;
                    default: {
                        Set<String> seen = Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());
                        return (k, e, n) -> seen.add(k);
                    }
                }
            };
            return Dpop.runDpopReplayStoreConformance(make);
        });
    }

    /** A non-finite maxAgeSec would disable the stale check and a non-finite nowSec would void the window: both are refused. */
    @Test void nonFiniteMaxAgeAndNowRefused() throws Exception {
        byte[] seed = java.security.MessageDigest.getInstance("SHA-256").digest("dpop-non-finite".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String x = Keys.b64u(Keys.edFromSeed(seed).pub);
        Dpop.CreateDpopProofInput in = new Dpop.CreateDpopProofInput();
        in.method = "GET";
        in.url = "https://rs.example/r";
        in.iat = 1800000000.0;
        in.privateKey = new LinkedHashMap<>(Map.of("kty", "OKP", "crv", "Ed25519", "x", x, "d", Keys.b64u(seed)));
        in.publicJwk = new LinkedHashMap<>(Map.of("kty", "OKP", "crv", "Ed25519", "x", x));
        String proof = Dpop.createDpopProof(in);
        java.util.function.BiFunction<Double, Double, String> code = (maxAge, now) -> {
            Dpop.VerifyDpopProofOptions o = new Dpop.VerifyDpopProofOptions();
            o.method = "GET";
            o.url = in.url;
            o.maxAgeSec = maxAge;
            o.nowSec = now;
            o.requireReplayStore = false;
            try {
                Dpop.verifyDpopProof(proof, o);
                return "ok";
            } catch (Dpop.DpopVerificationError e) {
                return e.code();
            }
        };
        assertEquals("ok", code.apply(300.0, 1800000001.0));
        for (double v : new double[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY}) {
            assertEquals("max_age", code.apply(v, 1800000001.0), "maxAgeSec " + v);
            assertEquals("now", code.apply(300.0, v), "nowSec " + v);
        }
    }

    @Test void createDpopProof() throws Exception {
        OracleCases.each(M, "createDpopProof", a -> wrap(() -> Dpop.createDpopProof(createInput(m(a.get(0))))));
    }

    @Test void createThenVerify() throws Exception {
        OracleCases.each(M, "createThenVerify", a -> wrap(() -> {
            Map<String, Object> in = m(a.get(0));
            String proof = Dpop.createDpopProof(createInput(in));
            Map<String, Object> vo = new LinkedHashMap<>();
            vo.put("method", in.get("method"));
            vo.put("url", in.get("url"));
            vo.put("maxAgeSec", new Json.Num("300"));
            vo.put("nowSec", new Json.Num(String.valueOf((long) (d(in.get("iat")) == null ? 1_800_000_000d : d(in.get("iat"))) + 1)));
            vo.put("seenJti", new ArrayList<>());
            vo.putAll(m(a.get(1)));
            @SuppressWarnings("unchecked") Set<String>[] seen = new Set[1];
            return result(Dpop.verifyDpopProof(proof, opts(vo, seen)), seen[0]);
        }));
    }

    @Test void verifyDpopProof() throws Exception {
        OracleCases.each(M, "verifyDpopProof", a -> wrap(() -> {
            @SuppressWarnings("unchecked") Set<String>[] seen = new Set[1];
            return result(Dpop.verifyDpopProof(a.get(0), opts(m(a.get(1)), seen)), seen[0]);
        }));
    }

    @Test void mtlsCnf() throws Exception {
        OracleCases.each(M, "mtlsCnf", a -> {
            Object c = cert(a.get(0));
            return c instanceof byte[] ? Dpop.mtlsCnf((byte[]) c) : Dpop.mtlsCnf((String) c);
        });
    }

    @Test void mtlsThumbprint() throws Exception {
        OracleCases.each(M, "mtlsThumbprint", a -> wrap(() -> {
            Object c = cert(a.get(0));
            return c instanceof byte[] ? Dpop.mtlsThumbprint((byte[]) c) : Dpop.mtlsThumbprint((String) c);
        }));
    }

    @Test void assertMtlsBound() throws Exception {
        OracleCases.each(M, "assertMtlsBound", a -> wrap(() -> {
            Object c = cert(a.get(0));
            return c instanceof byte[] ? Dpop.assertMtlsBound((byte[]) c, a.get(1)) : Dpop.assertMtlsBound((String) c, a.get(1));
        }));
    }

    @Test void leafHolderJwk() throws Exception {
        OracleCases.each(M, "leafHolderJwk", a -> wrap(() -> Dpop.leafHolderJwk(m(a.get(0)))));
    }

    @Test void bindPcaToDpop() throws Exception {
        OracleCases.each(M, "bindPcaToDpop", a -> wrap(() -> Dpop.bindPcaToDpop(m(a.get(0)))));
    }

    @Test void assertPcaDpop() throws Exception {
        OracleCases.each(M, "assertPcaDpop", a -> wrap(() -> {
            @SuppressWarnings("unchecked") Set<String>[] seen = new Set[1];
            Map<String, Object> o = m(a.get(2));
            Dpop.VerifyDpopProofOptions v = opts(o, seen);
            return result(Dpop.assertPcaDpop(m(a.get(0)), a.get(1), assertOpts(v, o.containsKey("maxAgeSec"), o)), seen[0]);
        }));
    }

    // ---- what the oracle cannot see ----

    @Test void createdEdDsaProofVerifiesAndTamperingIsRefused() {
        Map<String, Object> pub = new LinkedHashMap<>();
        Keys.EdKey k = Keys.edFromSeed(new byte[32]);
        pub.put("kty", "OKP");
        pub.put("crv", "Ed25519");
        pub.put("x", k.id());
        Map<String, Object> priv = new LinkedHashMap<>(pub);
        priv.put("d", Keys.b64u(k.seed));
        Dpop.CreateDpopProofInput in = new Dpop.CreateDpopProofInput();
        in.method = "get";
        in.url = "https://api.example.com/a?b=1";
        in.privateKey = priv;
        in.publicJwk = pub;
        in.iat = 1_800_000_000d;
        String proof = Dpop.createDpopProof(in);
        Dpop.VerifyDpopProofOptions v = new Dpop.VerifyDpopProofOptions();
        v.method = "GET";
        v.url = "https://api.example.com/a";
        v.maxAgeSec = 300;
        v.nowSec = 1_800_000_001d;
        v.seenJti = seenSet(new LinkedHashSet<>());
        Dpop.DpopVerifyResult r = Dpop.verifyDpopProof(proof, v);
        assertEquals(Dpop.jwkThumbprint(pub, null), r.jkt);
        String bad = proof.substring(0, proof.length() - 2) + (proof.endsWith("AA") ? "BB" : "AA");
        v.seenJti = seenSet(new LinkedHashSet<>());
        try {
            Dpop.verifyDpopProof(bad, v);
            assertTrue(false, "a tampered signature must be refused");
        } catch (Dpop.DpopVerificationError e) {
            assertTrue(e.code().equals("signature") || e.code().equals("malformed"));
        }
    }
}
