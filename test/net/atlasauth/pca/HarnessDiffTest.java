package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.harness.Harness;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the attested orchestration harness through the native port. */
public class HarnessDiffTest {
    private static final String M = "ref-harness";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static byte[] seedOf(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

    @Test void consts() throws Exception {
        OracleCases.each(M, "consts", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("HARNESS_VERSION", Harness.HARNESS_VERSION);
            o.put("HARNESS_MODEL_ID", Harness.HARNESS_MODEL_ID);
            o.put("ENFORCED_CHECKS", Harness.ENFORCED_CHECKS);
            return o;
        });
    }

    @Test void measurement() throws Exception { OracleCases.each(M, "computeHarnessMeasurement", a -> Harness.computeHarnessMeasurement(a.get(0), a.get(1), a.get(2))); }

    @Test void attestationVerifier() throws Exception { OracleCases.each(M, "harnessAttest", a -> Harness.createHarnessAttestationVerifier(a.get(0)).apply(a.get(1))); }

    @Test void harness() throws Exception {
        OracleCases.each(M, "harness", a -> {
            Map<String, Object> spec = m(a.get(0));
            Map<String, Object> op = m(spec.get("opts"));
            long[] t = {1_800_000_000_000L};
            int[] k = {0};
            Harness h;
            try {
                Harness.Options o = new Harness.Options();
                o.grant = m(op.get("grant"));
                o.chain = op.get("chain") == null ? null : l(op.get("chain"));
                o.agentSeed = seedOf((String) op.get("label"));
                o.plan = op.get("plan");
                o.audience = op.get("audience");
                o.budget = op.get("budget");
                o.policy = op.get("policy") == null ? null : m(op.get("policy"));
                o.baseRisk = op.get("baseRisk") == null ? null : m(op.get("baseRisk"));
                o.now = () -> t[0];
                o.ttlMs = op.get("ttlMs") == null ? null : Long.valueOf(IntentJs.num(op.get("ttlMs")).longValue());
                o.measurementManifest = op.get("manifest") == null ? null : new ArrayList<String>(l(op.get("manifest")).stream().map(x -> (String) x).toList());
                o.nonce = () -> "n" + (k[0]++);
                o.attestation = op.get("attestation") == null ? null : m(op.get("attestation"));
                h = new Harness(o);
            } catch (RuntimeException e) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("$err", Boolean.TRUE);
                return err;
            }
            List<Object> outs = new ArrayList<>();
            for (Object s : l(spec.get("steps"))) {
                Map<String, Object> st = m(s);
                if ("now".equals(st.get("op"))) { t[0] = IntentJs.num(st.get("t")).longValue(); outs.add(null); continue; }
                Map<String, Object> orc = m(st.get("oracle"));
                outs.add(h.step(() -> {
                    if ("throw".equals(orc.get("kind"))) throw new IllegalStateException((String) orc.get("msg"));
                    return "bad".equals(orc.get("kind")) ? orc.get("v") : orc.get("c");
                }));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("steps", outs);
            out.put("budget", h.budget());
            out.put("counter", h.counter());
            out.put("planRoot", h.planRoot());
            out.put("measurement", h.harnessMeasurement());
            return out;
        });
    }

    @Test void randomNonceIsHex() {
        Harness.Options o = new Harness.Options();
        Map<String, Object> grant = new LinkedHashMap<>();
        grant.put("id", "g");
        o.grant = grant;
        o.agentSeed = new byte[32];
        Map<String, Object> node = new LinkedHashMap<>();
        node.put("id", "n1");
        node.put("verb", "read");
        node.put("resource", "doc:1");
        o.plan = new ArrayList<Object>(List.of(node));
        o.audience = "aud";
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("B", new Json.Num("1"));
        b.put("tau", new Json.Num("0"));
        b.put("asOf", new Json.Num("0"));
        o.budget = b;
        o.now = () -> 0L;
        Map<String, Object> cand = new LinkedHashMap<>();
        cand.put("verb", "read");
        cand.put("resource", "doc:1");
        cand.put("nodeId", "n1");
        Map<String, Object> r = new Harness(o).step(() -> cand);
        assertTrue(Boolean.TRUE.equals(r.get("ok")));
        assertTrue(((String) m(r.get("pcactn")).get("nonce")).matches("[0-9a-f]{32}"));
    }
}
