package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The PUF attestation root against the reference corpus (ref-attest-puf, 278 cases): the repetition-code fuzzy extractor, the simulated
 * PUF, the TPM endorsement-key provider over an injected runner, enrollment, the device attestor, the registry and the verifier. A
 * reference result may be wrapped as {ok, value}; a TPM error text is compared by presence only.
 */
class AttestPufRefDiffTest {
    static final String MODULE = "ref-attest-puf";
    static final int TOTAL = 278;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    private static byte[] b64(String s) { return Base64.getUrlDecoder().decode(s); }

    private static byte[] bytes(Object o) { return o instanceof Map && m(o).get("$bytes") instanceof String ? b64((String) m(o).get("$bytes")) : null; }

    /** {"$bytes"} as bytes, {"$num"} as that double, throughout a value. */
    @SuppressWarnings("unchecked")
    private static Object dec(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(dec(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$bytes") instanceof String) return b64((String) map.get("$bytes"));
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    /** A bare reference result, or the value of {ok: true, value}. */
    private static Object unwrap(Object want) {
        Map<String, Object> w = m(want);
        return w != null && w.size() == 2 && w.containsKey("ok") && w.containsKey("value") && Boolean.TRUE.equals(w.get("ok")) ? w.get("value") : want;
    }

    private static AttestPuf.PufProvider puf(Object specO) {
        Map<String, Object> s = m(specO);
        List<Integer> flips = new ArrayList<>();
        if (s.get("flip") instanceof List) for (Object f : (List<?>) s.get("flip")) flips.add((int) dbl(f));
        return AttestPuf.createSimulatedPuf((String) s.get("id"), b64((String) s.get("seed")), (int) dbl(s.get("length")), flips);
    }

    private static AttestPuf.RandomBytes rand(Object o) {
        List<?> r = (List<?>) o;
        int[] i = {0};
        return n -> Arrays.copyOf(bytes(r.get(i[0]++ == 0 ? 0 : 1)), n);
    }

    private static String hex(byte[] b) { return AttestCommon.toHexLower(b); }

    private static Object fuzzyEnroll(List<?> x) {
        Map<String, Object> p = m(arg(x, 1));
        AttestPuf.FuzzyEnrollment e = AttestPuf.fuzzyEnroll(bytes(arg(x, 0)), dbl(p.get("rep")), dbl(p.get("messageBits")), rand(arg(x, 2)));
        return Issue.obj("keySha256", hex(AttestCommon.sha256Sum(e.key)), "helper", e.helper);
    }

    private static Object fuzzyReproduce(List<?> x) {
        return Issue.obj("keySha256", hex(AttestCommon.sha256Sum(AttestPuf.fuzzyReproduce(bytes(arg(x, 0)), m(arg(x, 1))))));
    }

    private static Object tpmEk(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0)), o = m(sc.get("opts"));
        Object runSpec = sc.get("run");
        List<Object> calls = new ArrayList<>();
        AttestPuf.TpmCommandRunner runner = (cmd, args) -> {
            calls.add(new ArrayList<Object>(Arrays.asList(cmd, new ArrayList<Object>(args))));
            if ("undefined".equals(runSpec)) return null;
            Map<String, Object> r = m(runSpec);
            if (r.containsKey("$throws")) throw new RuntimeException((String) r.get("$throws"));
            AttestPuf.TpmCommandResult res = new AttestPuf.TpmCommandResult();
            res.status = r.get("status") == null ? null : (int) dbl(r.get("status"));
            res.stdout = bytes(r.get("stdout"));
            res.stderr = (String) r.get("stderr");
            res.error = (String) r.get("error");
            return res;
        };
        AttestPuf.TpmEkPufOptions opts = new AttestPuf.TpmEkPufOptions();
        if (o != null) {
            opts.id = o.get("id") instanceof String ? (String) o.get("id") : null;
            opts.length = IntentJs.num(o.get("length"));
            opts.tool = (String) o.get("tool");
            opts.ekHandle = (String) o.get("ekHandle");
            if (o.get("args") instanceof List) { opts.args = new ArrayList<>(); for (Object a : (List<?>) o.get("args")) opts.args.add((String) a); }
            opts.minEkBytes = IntentJs.num(o.get("minEkBytes"));
        }
        opts.run = runner;
        Map<String, Object> out;
        try {
            AttestPuf.TpmEkPufProvider p = new AttestPuf.TpmEkPufProvider(opts);
            Object v = "readEkPublic".equals(sc.get("op")) ? p.readEkPublic() : p.response(sc.get("challenge") == null ? ChallengeHolder.DEFAULT : bytes(sc.get("challenge")));
            out = Issue.obj("ok", true, "value", v);
        } catch (RuntimeException e) {
            out = Issue.obj("ok", false, "error", e.getMessage() == null ? "error" : e.getMessage());
        }
        out.put("calls", calls);
        return out;
    }

    /** The default challenge of the generator: its first 32 bytes are sha256("attest-puf-oracle-randomness/challenge"). */
    private static final class ChallengeHolder {
        static final byte[] DEFAULT = Pca.sha("attest-puf-oracle-randomness/challenge".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static Object enrollPuf(List<?> x) {
        Map<String, Object> o = m(arg(x, 2));
        AttestPuf.EnrollOptions opts = new AttestPuf.EnrollOptions();
        opts.rep = dbl(o.get("rep"));
        opts.messageBits = dbl(o.get("messageBits"));
        opts.alg = (String) o.get("alg");
        opts.randomBytes = rand(arg(x, 3));
        return AttestPuf.enrollPuf(puf(arg(x, 0)), bytes(arg(x, 1)), opts);
    }

    private static Object registry(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        AttestPuf.EnrollmentRegistry r = AttestPuf.createPufEnrollmentRegistry(sc.get("enrollments") instanceof List ? (List<?>) sc.get("enrollments") : null);
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) sc.get("ops")) {
            Map<String, Object> op = m(o);
            String k = op.keySet().iterator().next();
            switch (k) {
                case "register": r.register(op.get(k)); out.add(null); break;
                case "lookup": out.add(r.lookup((String) op.get(k))); break;
                case "revoke": r.revoke((String) op.get(k)); out.add(null); break;
                default: out.add(r.isRevoked((String) op.get(k))); break;
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static AttestPuf.VerifierOptions options(Map<String, Object> cfg, List<?> enrollments, List<?> revoked, Object evidence, boolean seam, boolean resolver) {
        AttestPuf.VerifierOptions o = new AttestPuf.VerifierOptions();
        Map<String, Object> pol = m(cfg.get("policy"));
        if (pol != null) {
            o.policy = new AttestPuf.Policy();
            o.policy.measurements = pol.get("measurements") instanceof List ? (List<String>) pol.get("measurements") : null;
            o.policy.weightsMeasurements = pol.get("weightsMeasurements") instanceof List ? (List<String>) pol.get("weightsMeasurements") : null;
            if ("custom".equals(pol.get("identity"))) {
                o.policy.deriveIdentity = (st, enr) -> Issue.obj("model_id", "m-custom", "weights_digest", st.get("weights_digest") == null ? "" : st.get("weights_digest"),
                    "weights_measured", true, "runtime_measurement", st.get("measurement"), "operator", enr.get("providerId"));
            }
        }
        o.requirePq = Boolean.TRUE.equals(cfg.get("requirePq"));
        if (resolver) {
            Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
            if (enrollments != null) for (Object e : enrollments) byId.put((String) m(e).get("providerId"), m(e));
            o.resolveEnrollment = (id, doc, ctx) -> byId.get(id);
        }
        if (seam) o.resolveEvidence = (doc, ctx) -> evidence;
        if (revoked != null) o.isRevoked = revoked::contains;
        return o;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("PUF_EXTRACT_INFO", AttestPuf.PUF_EXTRACT_INFO, "PUF_ATTEST_DOMAIN", AttestPuf.PUF_ATTEST_DOMAIN,
            "PUF_KEY_BYTES", AttestPuf.PUF_KEY_BYTES, "TPM_EK_PUF_DOMAIN", AttestPuf.TPM_EK_PUF_DOMAIN));
        f.put("repetitionCorrectionBound", x -> AttestPuf.repetitionCorrectionBound(dbl(arg(x, 0))));
        f.put("simulatedPufResponse", x -> puf(arg(x, 0)).response(bytes(arg(x, 1))));
        f.put("fuzzyEnroll", AttestPufRefDiffTest::fuzzyEnroll);
        f.put("fuzzyReproduce", AttestPufRefDiffTest::fuzzyReproduce);
        f.put("tpmEk", AttestPufRefDiffTest::tpmEk);
        f.put("enrollPuf", AttestPufRefDiffTest::enrollPuf);
        f.put("pufAttest", x -> AttestPuf.createPufAttestor(puf(arg(x, 0)), m(arg(x, 1))).attest(m(dec(arg(x, 2)))));
        f.put("registry", AttestPufRefDiffTest::registry);
        f.put("verifyPuf", x -> {
            Map<String, Object> sc = m(arg(x, 0)), cfg = m(sc.get("config")), in = m(sc.get("input"));
            AttestPuf.Verifier v = AttestPuf.createPufVerifier(options(cfg, (List<?>) sc.get("enrollments"), (List<?>) sc.get("revoked"), sc.get("evidence"),
                !Boolean.TRUE.equals(cfg.get("noEvidenceSeam")), !Boolean.TRUE.equals(cfg.get("noResolveEnrollment"))));
            Map<String, Object> input = Issue.obj("document", new LinkedHashMap<String, Object>(), "ctx", new LinkedHashMap<String, Object>(), "nowMs", in.get("nowMs"));
            if (in.containsKey("expected")) input.put("expected", in.get("expected"));
            return v.verify(input);
        });
        f.put("buildVerifier", x -> {
            Map<String, Object> cfg = m(arg(x, 0));
            AttestPuf.createPufVerifier(options(cfg, null, null, null, false, !Boolean.TRUE.equals(cfg.get("noResolveEnrollment"))));
            return Issue.obj("built", true);
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                Object want = unwrap(c.get("out"));
                OracleCases.Fn fn = e.getValue();
                if (e.getKey().equals("tpmEk")) { // the error text is compared by presence only
                    Map<String, Object> w = new LinkedHashMap<>(m(want));
                    if (w.containsKey("error")) w.put("error", "");
                    want = w;
                    fn = a -> { Map<String, Object> r = (Map<String, Object>) e.getValue().apply(a); if (r.containsKey("error")) r.put("error", ""); return r; };
                }
                String d = OracleCases.diff(c, want, fn);
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
