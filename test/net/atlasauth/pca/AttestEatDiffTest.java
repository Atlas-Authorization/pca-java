package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.attesteat.AttestEat;
import net.atlasauth.pca.attesteat.AttestEatAdmission;
import net.atlasauth.pca.attesteat.AttestEatPq;
import net.atlasauth.pca.attesteat.AttestEatProvenance;
import net.atlasauth.pca.scitt.Scitt;
import org.junit.jupiter.api.Test;

class AttestEatDiffTest {
    private static final String M = "ref-attest-eat";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static boolean isBytes(Object o) { return o instanceof Map && ((Map<?, ?>) o).size() == 1 && ((Map<?, ?>) o).get("$bytes") instanceof String; }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) map(o).get("$bytes")); }

    /** {"$bytes"} members become byte[] (the oracle's rev). */
    private static Object rev(Object v) {
        if (isBytes(v)) return bytes(v);
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(rev(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : map(v).entrySet()) out.put(e.getKey(), rev(e.getValue()));
            return out;
        }
        return v;
    }

    private static PrivateKey priv(Object spec) {
        Map<String, Object> s = map(spec);
        if ("EdDSA".equals(s.get("alg"))) return Scitt.ed25519PrivateKey(Keys.unb64u((String) s.get("seed")));
        return Scitt.es256PrivateKey(Keys.unb64u((String) s.get("d")));
    }

    private static PublicKey pub(Object spec) {
        Map<String, Object> s = map(spec);
        if ("EdDSA".equals(s.get("alg"))) return Scitt.ed25519PublicKey(Keys.unb64u((String) s.get("pub")));
        return Scitt.es256PublicKey(Keys.unb64u((String) s.get("x")), Keys.unb64u((String) s.get("y")));
    }

    /** Opts with {"$bytes"} turned into bytes and a verifyKey spec turned into a key. */
    private static Map<String, Object> verifyOpts(Object o) {
        Map<String, Object> m = (Map<String, Object>) rev(o);
        if (m != null && m.get("verifyKey") instanceof Map) m.put("verifyKey", pub(m.get("verifyKey")));
        return m;
    }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    // ---- constants + pure helpers ----

    @Test void genCorpusIsPresent() { BaseOracle.requireGen(M); }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("EAT_TYP", AttestEat.EAT_TYP);
            m.put("DEFAULT_EAT_ALG", AttestEat.DEFAULT_EAT_ALG);
            m.put("DEFAULT_MAX_AGE_MS", AttestEat.DEFAULT_MAX_AGE_MS);
            m.put("CHANNEL_BINDING_DOMAIN", AttestEat.CHANNEL_BINDING_DOMAIN);
            m.put("AMD_SEV_SNP_SIGNED_REGION_END", AttestEat.AMD_SEV_SNP_SIGNED_REGION_END);
            m.put("AMD_SEV_SNP_HARDWARE_ROOT_LABEL", AttestEat.AMD_SEV_SNP_HARDWARE_ROOT_LABEL);
            m.put("KNOWN_REPORT_VERSIONS", AttestEat.KNOWN_REPORT_VERSIONS);
            m.put("KNOWN_AMD_ARK_SPKI_SHA384", AttestEat.KNOWN_AMD_ARK_SPKI_SHA384);
            m.put("AMD_MILAN_ARK_SPKI_SHA384", AttestEat.AMD_MILAN_ARK_SPKI_SHA384);
            m.put("PQCOSIGN_DOMAIN", AttestEatPq.PQCOSIGN_DOMAIN);
            m.put("DEFAULT_PQ_COSIGN_SUITE", AttestEatPq.DEFAULT_PQ_COSIGN_SUITE);
            m.put("PQ_COSIGN_SUITES", AttestEatPq.PQ_COSIGN_SUITES);
            return m;
        });
    }

    @Test void deriveChannelCnf() throws Exception { OracleCases.each(M, "deriveChannelCnf", a -> AttestEat.deriveChannelCnf(a.get(0), arg(a, 1))); }

    @Test void bindChannel() throws Exception { OracleCases.each(M, "bindChannel", a -> AttestEat.bindChannel(a.get(0), a.get(1), a.get(2))); }

    // ---- EAT ----

    @Test void buildEAT() throws Exception {
        OracleCases.each(M, "buildEAT", a -> {
            Map<String, Object> args = new LinkedHashMap<>(map(a.get(0)));
            if (args.get("key") instanceof Map) args.put("key", priv(args.get("key")));
            return AttestEat.buildEAT(args);
        });
    }

    @Test void verifyEAT() throws Exception {
        OracleCases.each(M, "verifyEAT", a -> AttestEat.verifyEAT(a.get(0), pub(a.get(1)), a.size() > 2 ? map(a.get(2)) : new LinkedHashMap<String, Object>()));
    }

    /**
     * Cases where the port is stricter than these vectors (a present clock skew that is not a finite number; a minimum tier other than
     * affirming / affirming-hw-rooted): the current reference refuses them too, the vectors predate that fix. Each must refuse.
     */
    static final java.util.Set<String> STRICTER = java.util.Set.of("verifyFreshness/skew junk string", "verifyFreshness/skew junk stale",
        "verifyFreshness/skew string number", "verifyFreshness/skew null", "verifyFreshness/skew true", "verifyFreshAttestedEAT/amd skew junk",
        "eatAdmissionEvidence/min tier unknown", "eatAdmissionEvidence/min tier null");

    private static void eachStrict(String fn, OracleCases.Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, fn)) {
            if (STRICTER.contains(c.get("name"))) {
                Object got = f.apply((List<?>) c.get("args"));
                if (!(got instanceof Map) || !Boolean.FALSE.equals(((Map<?, ?>) got).get("ok"))) bad.add(c.get("name") + " was not refused: " + got);
            } else {
                String d = OracleCases.diff(c, c.get("out"), f);
                if (d != null) bad.add(d);
            }
        }
        org.junit.jupiter.api.Assertions.assertTrue(bad.isEmpty(), String.join("\n", bad));
    }

    @Test void verifyFreshness() throws Exception { eachStrict("verifyFreshness", a -> AttestEat.verifyFreshness(map(a.get(0)), map(a.get(1)))); }

    @Test void nonFiniteSkewAndUnknownMinTierRefused() {
        Map<String, Object> eat = new LinkedHashMap<>();
        eat.put("eat_nonce", "n1");
        eat.put("iat", 1_000_000_000L); // decades stale: only an unbounded skew would admit it
        for (Object skew : new Object[] {Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.NaN, "5", null, Boolean.TRUE}) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("expectedNonce", "n1");
            o.put("now", 1_800_000_000_000L);
            o.put("maxAgeMs", 60_000L);
            o.put("clockSkewMs", skew);
            Map<String, Object> r = AttestEat.verifyFreshness(eat, o);
            org.junit.jupiter.api.Assertions.assertEquals(Boolean.FALSE, r.get("ok"), String.valueOf(skew));
            org.junit.jupiter.api.Assertions.assertEquals("invalid clockSkewMs (must be a finite number)", r.get("reason"), String.valueOf(skew));
        }
        for (Object tier : new Object[] {"warning", "rejected", "bogus", null, 2L}) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("instanceKey", "k");
            o.put("minTier", tier);
            Map<String, Object> r = AttestEatAdmission.eatAdmissionEvidence("x", o);
            org.junit.jupiter.api.Assertions.assertEquals(Boolean.FALSE, r.get("ok"), String.valueOf(tier));
            org.junit.jupiter.api.Assertions.assertEquals(Boolean.FALSE, r.get("bound"), String.valueOf(tier));
            org.junit.jupiter.api.Assertions.assertEquals("invalid minTier", r.get("reason"), String.valueOf(tier));
        }
    }

    @Test void verifyChannelBinding() throws Exception { OracleCases.each(M, "verifyChannelBinding", a -> AttestEat.verifyChannelBinding(map(a.get(0)), map(a.get(1)))); }

    @Test void appraise() throws Exception {
        OracleCases.each(M, "appraise", a -> {
            Map<String, Object> ev = map(a.get(0));
            switch (a.size()) {
                case 1: return AttestEat.appraise(ev);
                case 2: return AttestEat.appraise(ev, map(a.get(1)));
                case 3: return AttestEat.appraise(ev, map(a.get(1)), map(a.get(2)));
                default: return AttestEat.appraise(ev, map(a.get(1)), map(a.get(2)), map(a.get(3)));
            }
        });
    }

    @Test void parseReportTolerant() throws Exception {
        OracleCases.each(M, "parseReportTolerant", a -> {
            Map<String, Object> r = AttestEat.parseReportTolerant(bytes(a.get(0)));
            Map<String, Object> out = new LinkedHashMap<>();
            for (String k : new String[] {"ok", "version", "known", "degraded", "notes"}) out.put(k, r.get(k));
            out.put("hasReport", r.containsKey("report"));
            if (r.containsKey("evidence")) out.put("evidence", r.get("evidence"));
            if (r.containsKey("report")) out.put("measured", AttestEat.measuredFromReport(map(r.get("report"))));
            return out;
        });
    }

    // ---- AMD hardware root + composition ----

    @Test void verifyAmdAttestation() throws Exception {
        OracleCases.each(M, "verifyAmdAttestation", a -> {
            Map<String, Object> r = AttestEat.verifyAmdAttestation(bytes(a.get(0)), map(rev(a.get(1))));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", r.get("ok"));
            out.put("hardwareRoot", r.get("hardwareRoot"));
            if (r.containsKey("reason")) out.put("reason", r.get("reason"));
            if (r.containsKey("evidence")) out.put("evidence", r.get("evidence"));
            if (r.containsKey("measured")) out.put("measured", r.get("measured"));
            return out;
        });
    }

    @Test void verifyFreshAttestedEAT() throws Exception { eachStrict("verifyFreshAttestedEAT", a -> AttestEat.verifyFreshAttestedEAT(a.get(0), verifyOpts(a.get(1)))); }

    // ---- post-quantum co-signature ----

    private static Keys.SuiteKey suiteKey(String suite, Object spec) {
        Map<String, Object> s = map(spec);
        Keys.EdKey ed = s.get("ed") != null ? Keys.edFromSeed(Keys.unb64u((String) s.get("ed"))) : null;
        Keys.PqKey pq = null;
        if (s.get("pq") != null) {
            Map<String, Object> p = map(s.get("pq"));
            Pq.Prim prim;
            switch ((String) p.get("prim")) {
                case "ml-dsa-65": prim = Pq.Prim.ML_DSA_65; break;
                case "ml-dsa-87": prim = Pq.Prim.ML_DSA_87; break;
                case "slh-dsa-sha2-128f": prim = Pq.Prim.SLH_DSA_SHA2_128F; break;
                default: prim = Pq.Prim.SLH_DSA_SHA2_256S;
            }
            pq = Keys.pqFromSeed(prim, Keys.unb64u((String) p.get("seed")));
        }
        return Keys.suite(suite, ed, pq);
    }

    @Test void canonicalVerdictBytes() throws Exception { OracleCases.each(M, "canonicalVerdictBytes", a -> AttestEatPq.canonicalVerdictBytes(map(a.get(0)), a.get(1))); }

    @Test void verdictFromAppraisal() throws Exception { OracleCases.each(M, "verdictFromAppraisal", a -> AttestEatPq.verdictFromAppraisal(map(a.get(0)), map(a.get(1)))); }

    @Test void isPqCoSignSuite() throws Exception { OracleCases.each(M, "isPqCoSignSuite", a -> AttestEatPq.isPqCoSignSuite(arg(a, 0))); }

    @Test void coSignAttestation() throws Exception {
        OracleCases.each(M, "coSignAttestation", a -> {
            Map<String, Object> op = map(a.get(1));
            String suite = op.get("suite") instanceof String ? (String) op.get("suite") : AttestEatPq.DEFAULT_PQ_COSIGN_SUITE;
            AttestEatPq.CoSignOptions o = new AttestEatPq.CoSignOptions(suiteKey(suite, op.get("key")));
            if (op.get("suite") != null) o.suite = suite;
            o.now = op.get("now");
            return AttestEatPq.coSignAttestation(map(a.get(0)), o);
        });
    }

    @Test void verifyCoSignedAttestation() throws Exception {
        // ageMs is the distance to the clock of the run: the recorded value is the generator's wall clock, so it is only comparable under an explicit numeric `now`
        for (Map<String, Object> c : OracleCases.of(M, "verifyCoSignedAttestation")) {
            List<?> a = (List<?>) c.get("args");
            if (!(a.size() > 1 && a.get(1) instanceof Map && ((Map<?, ?>) a.get(1)).get("now") instanceof Json.Num) && c.get("out") instanceof Map) ((Map<?, ?>) c.get("out")).remove("ageMs");
        }
        OracleCases.each(M, "verifyCoSignedAttestation", a -> {
            Object r = AttestEatPq.verifyCoSignedAttestation(a.get(0), a.size() > 1 ? map(a.get(1)) : null);
            if (!(a.size() > 1 && a.get(1) instanceof Map && ((Map<?, ?>) a.get(1)).get("now") instanceof Json.Num) && r instanceof Map) { r = new java.util.LinkedHashMap<>((Map<?, ?>) r); ((Map<?, ?>) r).remove("ageMs"); }
            return r;
        });
    }

    // ---- admission + provenance ----

    @Test void ed25519Jkt() throws Exception { OracleCases.each(M, "ed25519Jkt", a -> AttestEatAdmission.ed25519Jkt((String) a.get(0))); }

    @Test void eatAdmissionEvidence() throws Exception { eachStrict("eatAdmissionEvidence", a -> AttestEatAdmission.eatAdmissionEvidence(a.get(0), verifyOpts(a.get(1)))); }

    @Test void runtimeDigestFromEat() throws Exception {
        OracleCases.each(M, "runtimeDigestFromEat", a -> AttestEatProvenance.runtimeDigestFromEat(a.get(0), a.size() > 1 ? map(a.get(1)) : null));
    }

    @Test void issueArtifactDischarge() throws Exception {
        OracleCases.each(M, "issueArtifactDischarge", a -> {
            Map<String, Object> i = new LinkedHashMap<>(map(a.get(0)));
            i.put("roots", Sigstore.parseTrustedRoot(i.get("roots")));
            i.put("issuerKey", Keys.ed25519(Keys.edFromSeed(Keys.unb64u((String) map(i.get("issuerKey")).get("seed")))));
            int[] n = {0};
            Supplier<byte[]> nonce = () -> {
                try {
                    return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(("eat-oracle-nonce/" + n[0]++).getBytes(StandardCharsets.UTF_8)), 16);
                } catch (java.security.NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            };
            return AttestEatProvenance.issueArtifactDischarge(i, nonce);
        });
    }
}
