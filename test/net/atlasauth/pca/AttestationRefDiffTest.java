package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The software attestation layer against the reference corpus (ref-attestation-soft, 512 cases): the binding, the dev attestor and its
 * documents, the registry, the nonce store and entropy gate, the agent-binding match, verifyAttestation and its hook, the multi-root
 * verifier and evidence anchoring. A reason that starts with the fail-closed error prefix carries the reference's own exception text
 * after it, so only the prefix is compared. The 2 verify cases the reference accepts only through its legacy unbound-PQ option are
 * asserted REFUSED: this SDK verifies a PQ attestor only under a key the verifier pins.
 */
class AttestationRefDiffTest {
    static final String MODULE = "ref-attestation-soft";
    static final int TOTAL = 512;
    static final String ERR_PREFIX = "attestation verification error (fail closed):";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** The corpus spelling of a non-finite number, {"$num": text}, as that double (throughout a value). */
    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    private static Attestation.HardwareVerifier hw(Object h) {
        Map<String, Object> spec = m(h);
        if (spec == null) return null;
        if (spec.containsKey("throws")) return in -> { throw new RuntimeException((String) spec.get("throws")); };
        return in -> spec.get("result");
    }

    /** A reason that starts with the error prefix keeps only the prefix (the text after it is the reference's own exception). */
    @SuppressWarnings("unchecked")
    private static Object cut(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(cut(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        Map<String, Object> out = new LinkedHashMap<>(map);
        if (out.get("reason") instanceof String && ((String) out.get("reason")).startsWith(ERR_PREFIX)) out.put("reason", ERR_PREFIX);
        return out;
    }

    private static Object quote(Object ctx) { return pathOf(ctx, "pcactn", "attestation", "quote_digest"); }

    private static Object pathOf(Object o, String... keys) {
        Object cur = o;
        for (String k : keys) cur = m(cur) == null ? null : m(cur).get(k);
        return cur;
    }

    private static Map<String, Object> verifyInput(Object a) {
        Map<String, Object> in = new LinkedHashMap<>(m(nums(a)));
        in.remove("hardware");
        return in;
    }

    private static Object verify(List<?> x) {
        Map<String, Object> raw = m(arg(x, 0));
        return Attestation.verifyAttestation(verifyInput(raw), hw(raw.get("hardware")));
    }

    private static Object hook(List<?> x) {
        Map<String, Object> op = m(nums(arg(x, 0)));
        double now = dbl(op.get("now"));
        Attestation.VerifierOptions o = new Attestation.VerifierOptions();
        o.trustedAttestorKeys = op.get("trustedAttestorKeys");
        o.now = () -> now;
        o.hardwareVerifier = hw(m(arg(x, 0)).get("hardware"));
        o.resolveDocument = Attestation.attestationRegistry(op.get("docs") == null ? new ArrayList<Object>() : op.get("docs"));
        if (op.get("store") != null) {
            Map<String, Object> st = m(op.get("store"));
            o.nonceStore = Attestation.memoryNonceStoreJs(st.get("max"), st.get("retentionMs"), () -> now);
        }
        if (op.containsKey("storeConsume")) {
            boolean answer = Boolean.TRUE.equals(op.get("storeConsume"));
            o.nonceStore = nonce -> answer;
        }
        Object binding = op.get("binding");
        if ("throws".equals(binding)) {
            o.expectedBinding = ctx -> { throw new RuntimeException("boom"); };
        } else if (binding != null) {
            Map<String, Object> byNonce = m(m(binding).get("byNonce"));
            o.expectedBinding = ctx -> quote(ctx) instanceof String ? byNonce.get(quote(ctx)) : null;
        }
        o.minNonceBytes = op.get("minNonceBytes");
        o.insecureSelfDeclaredNonce = Boolean.TRUE.equals(op.get("insecure_selfDeclaredNonce"));
        o.maxNonceAgeMs = op.get("maxNonceAgeMs");
        o.clockSkewMs = op.get("clockSkewMs");
        o.pqPins = m(op.get("pqPins"));
        Attestation.Hook h = Attestation.createAttestationVerifier(o);
        List<Object> out = new ArrayList<>();
        for (Object ctx : (List<?>) arg(x, 1)) out.add(h.apply(nums(ctx)));
        return out;
    }

    private static Object multiRoot(List<?> x) {
        Map<String, Object> pol = m(nums(arg(x, 0)));
        List<Attestation.Root> roots = new ArrayList<>();
        for (Object ro : (List<?>) pol.get("roots")) {
            Map<String, Object> r = m(ro);
            Object id = r.get("id");
            roots.add(new Attestation.Root(id instanceof String ? (String) id : null, hw(r.get("hw")), Boolean.TRUE.equals(r.get("required")), (String) r.get("suite")));
        }
        Attestation.MultiRoot v = Attestation.createMultiRootVerifier(roots, dbl(pol.get("threshold")));
        if (arg(x, 1) == null) return Issue.obj("built", true);
        return v.verify(new LinkedHashMap<>(m(nums(arg(x, 1)))));
    }

    private static Object nonceStore(List<?> x) {
        Map<String, Object> opts = m(arg(x, 1));
        double[] clock = {0};
        Attestation.NonceStore st = Attestation.memoryNonceStoreJs(nums(arg(x, 0)), opts == null ? null : nums(opts.get("retentionMs")), () -> clock[0]);
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) arg(x, 2)) {
            List<?> op = (List<?>) o;
            if ("clock".equals(op.get(0))) { clock[0] = dbl(nums(op.get(1))); out.add(null); }
            else out.add(st.consume(nums(op.get(1))));
        }
        return out;
    }

    private static Object anchor(List<?> x) {
        Map<String, Object> op = m(nums(arg(x, 1)));
        Attestation.AnchorOptions o = new Attestation.AnchorOptions();
        if ("ok".equals(op.get("ledger"))) {
            o.ledger = new MerkleLog();
            o.principal = op.get("principal") == null ? "" : (String) op.get("principal");
            for (int i = 0; i < (op.get("preload") == null ? 0 : (int) dbl(op.get("preload"))); i++) o.ledger.appendCommitment("c" + i);
        }
        if (op.get("guardianSeed") != null) o.guardianSecret = bytes(op.get("guardianSeed"));
        o.instanceId = (String) op.get("instanceId");
        if (op.containsKey("now")) { double now = dbl(op.get("now")); o.now = () -> now; }
        o.required = Boolean.TRUE.equals(op.get("required"));
        return Attestation.anchorAttestationEvidence(nums(arg(x, 0)), o);
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("ATTEST_ANCHOR_DOMAIN", Attestation.ATTEST_ANCHOR_DOMAIN, "ATTEST_BIND_DOMAIN", Attestation.ATTEST_BIND_DOMAIN,
            "DEFAULT_NONCE_RETENTION_MS", Attestation.DEFAULT_NONCE_RETENTION_MS, "MAX_ATTESTATION_AGE_MS", Attestation.MAX_ATTESTATION_AGE_MS,
            "MIN_ATTESTATION_NONCE_BYTES", Attestation.MIN_ATTESTATION_NONCE_BYTES));
        f.put("attestationBinding", x -> Attestation.attestationBinding(nums(arg(x, 0))));
        f.put("attestationBindingB64u", x -> Attestation.attestationBindingB64u(nums(arg(x, 0))));
        f.put("attest", x -> Attestation.createDevAttestor(bytes(arg(x, 0)), suite(arg(x, 1))).attest(m(nums(arg(x, 2)))));
        f.put("attestorPublicKey", x -> Attestation.createDevAttestor(bytes(arg(x, 0)), suite(arg(x, 1))).publicKey);
        f.put("attestationDigest", x -> Attestation.attestationDigest(nums(arg(x, 0))));
        f.put("registry", x -> {
            java.util.function.Function<Object, Map<String, Object>> r = Attestation.attestationRegistry(nums(arg(x, 0)));
            List<Object> out = new ArrayList<>();
            for (Object q : (List<?>) arg(x, 1)) out.add(r.apply(Issue.obj("pcactn", Issue.obj("attestation", Issue.obj("quote_digest", nums(q))))));
            return out;
        });
        f.put("nonceStore", AttestationRefDiffTest::nonceStore);
        f.put("nonceEntropyOk", x -> Attestation.nonceEntropyOk(nums(arg(x, 0)), nums(arg(x, 1))));
        f.put("requiresAttestation", x -> Attestation.requiresAttestation(nums(arg(x, 0))));
        f.put("nonceBinds", x -> Attestation.nonceBinds(nums(arg(x, 0)), nums(arg(x, 1))));
        f.put("matchAgentBinding", x -> Attestation.matchAgentBinding(nums(arg(x, 0)), nums(arg(x, 1))));
        f.put("multiRoot", AttestationRefDiffTest::multiRoot);
        f.put("attestationEvidenceDigest", x -> Attestation.attestationEvidenceDigest(nums(arg(x, 0))));
        f.put("anchorEvidence", AttestationRefDiffTest::anchor);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>(), handled = new TreeSet<>(f.keySet());
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        handled.add("verifyAttestation"); // replayed below
        handled.add("attestationHook");
        assertEquals(handled, fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            if (e.getKey().equals("multiRoot")) { replayCut(e.getKey(), e.getValue()); continue; }
            OracleCases.each(MODULE, e.getKey(), e.getValue());
        }
    }

    /** A function replayed with the fail-closed error prefix compared as a prefix. */
    private static void replayCut(String fn, OracleCases.Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MODULE, fn)) {
            String d = OracleCases.diff(c, cut(c.get("out")), x -> cut(f.apply(x)));
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad));
    }

    @Test void verifyEveryCase() throws Exception {
        List<String> bad = new ArrayList<>();
        int unbound = 0;
        for (Map<String, Object> c : OracleCases.of(MODULE, "verifyAttestation")) {
            Map<String, Object> input = m(arg((List<?>) c.get("args"), 0));
            Object want = c.get("out");
            if (Boolean.TRUE.equals(input.get("allowUnboundPq")) && Boolean.TRUE.equals(m(want).get("ok"))) {
                unbound++; // accepted by the reference only because the document vouches for its own PQ key
                want = Issue.obj("ok", false, "present", true, "bound", false, "reason", "attestation signature does not verify");
            }
            String d = OracleCases.diff(c, cut(want), x -> cut(verify(x)));
            if (d != null) bad.add(d);
        }
        assertEquals(2, unbound);
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }

    @Test void hookEveryCase() throws Exception { replayCut("attestationHook", AttestationRefDiffTest::hook); }
}
