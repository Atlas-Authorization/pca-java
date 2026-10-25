import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.IntentClassifier;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.IntentMap;
import net.atlasauth.pca.IntentRevocation;
import net.atlasauth.pca.IntentV2;
import net.atlasauth.pca.IntentWB;
import net.atlasauth.pca.OracleFacts;
import net.atlasauth.pca.ParamProvenance;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.Threshold;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * JUnit-free conformance runner for PCA wire format v2 (ed25519 + the post-quantum suites + the v2.1
 * agent-leaf threshold-share binding). Run from sdks/java-pca with BouncyCastle on the classpath. ML-DSA-65
 * (FIPS-204) needs a final-FIPS-204 BouncyCastle (bcprov-jdk18on >= 1.80):
 *
 *   BC=~/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar
 *   javac -cp "$BC" -d out src/net/atlasauth/pca/*.java ConformanceTest.java
 *   java  -cp "out:$BC" ConformanceTest
 *
 * <p>This verifier implements the three CROSS-IMPL suites every verifier at parity must cover (GAP 1):
 * {@code ed25519}, {@code ml-dsa-65} and {@code hybrid-ed25519-ml-dsa-65}, for BOTH the leaf signature
 * ({@code requires:"pq"}) AND non-leaf capability-chain hops ({@code requires:"pq-nonleaf"}). Vectors whose
 * suite is a REGISTERED post-quantum suite this verifier does not implement (ml-dsa-87, slh-dsa-*, the nested
 * hybrid, and their hybrids) are SKIPPED with an explicit count — never silently, never faked. Deliberately
 * unknown-alg / stray-field wire negatives still RUN (they are suite-agnostic fail-closed checks). It also
 * enforces the v2.1 agent-leaf share binding (GAP 2): a BARE agent share and a cross-signer-set replay are
 * REJECTED.
 */
public class ConformanceTest {
    static final String DIR = "conformance/";
    static int fails = 0, checks = 0;

    /** The suites this verifier implements: its capability manifest (packages/pca/conformance/SUITES.md). */
    static final Set<String> IMPLEMENTED_SUITES = Set.copyOf(Pq.supportedSuites());
    /** Every registered suite (the TS registry). A vector needing one outside the manifest must fail with unsupported_suite. */
    static final Set<String> ALL_REGISTERED_SUITES = Set.copyOf(Pq.REGISTERED_SUITES);

    static String canonOf(Object o) { return Json.canonicalize(o); }

    /** A primitive's input: {@code input_json} (raw JSON text, parsed with this SDK's parser) takes precedence over {@code input}. */
    static Object inputOf(Map<String, Object> e) {
        return e.get("input_json") instanceof String ? Json.parseLenient((String) e.get("input_json")) : e.get("input");
    }

    /** The first suite a v2 vector's {@code requires_suite} (a string or a list) names that this verifier does not implement, else null. */
    static String missingRequiredSuite(Object rs) {
        if (rs instanceof String) return IMPLEMENTED_SUITES.contains(rs) ? null : (String) rs;
        if (rs instanceof List) for (Object s : (List<?>) rs) if (s instanceof String && !IMPLEMENTED_SUITES.contains(s)) return (String) s;
        return null;
    }

    /** The refusal reason of an Intent Layer v2 primitive (null when it passes). */
    @SuppressWarnings("unchecked")
    static String intentPrimitiveReason(String kind, Object input) {
        switch (kind) {
            case "intent_schema": {
                Map<String, Object> in = (Map<String, Object>) IntentJs.normalize(input);
                String v = ActionSchema.verify(in.get("schema"), in.get("keys"));
                return v != null ? v : ActionSchema.conform(in.get("schema"), (String) in.get("verb"), in.get("params")).reason;
            }
            case "intent_revocation": return IntentRevocation.primitiveReason(input);
            case "intent_world": return OracleFacts.decideIntentWorld(input).reason;
            case "intent_provenance": return ParamProvenance.decide(input).reason;
            case "intent_classifier": return IntentClassifier.decide(input).reason;
            case "intent_map": return IntentMap.decidePrimitive(input).reason;
            case "intent_read_purpose": return null;
            default: return null;
        }
    }

    /**
     * The Intent Layer v2 primitive verdicts compared exactly as the README says: intent_schema {sig, digest when sig,
     * conform {ok, code?, path?}}; intent_revocation {ok}; intent_world ok (+ world, single_source when ok); intent_provenance
     * outcome (+ labels, classes unless deny, friction for a question); intent_classifier ok (+ classes when ok); intent_wb_active
     * {facts, provenance, classes}. Null = match.
     */
    @SuppressWarnings("unchecked")
    static String intentPrimitiveMismatch(String kind, Object input, Map<String, Object> exp) {
        switch (kind) {
            case "intent_schema": {
                Map<String, Object> in = (Map<String, Object>) IntentJs.normalize(input);
                boolean sig = ActionSchema.verify(in.get("schema"), in.get("keys")) == null;
                if (sig != (Boolean) exp.get("sig")) return "sig=" + sig;
                if (sig && !ActionSchema.digest(in.get("schema")).equals(exp.get("digest"))) return "digest";
                ActionSchema.Conform c = ActionSchema.conform(in.get("schema"), (String) in.get("verb"), in.get("params"));
                Map<String, Object> wc = (Map<String, Object>) exp.get("conform");
                if (c.ok != (Boolean) wc.get("ok")) return "conform.ok=" + c.ok + " (" + c.code + ")";
                if (!c.ok && !c.code.equals(wc.get("code"))) return "conform.code=" + c.code;
                if (!c.ok && !java.util.Objects.equals(c.path, wc.get("path"))) return "conform.path=" + c.path;
                return null;
            }
            case "intent_revocation": {
                boolean ok = IntentRevocation.checkPrimitive(input);
                return ok == (Boolean) exp.get("ok") ? null : "ok=" + ok;
            }
            case "intent_world": {
                OracleFacts.WorldResult r = OracleFacts.decideIntentWorld(input);
                if (r.ok != (Boolean) exp.get("ok")) return "ok=" + r.ok + " (" + r.reason + ")";
                if (r.ok && !canonOf(r.world).equals(canonOf(exp.get("world")))) return "world=" + canonOf(r.world);
                if (r.ok && !canonOf(r.singleSource).equals(canonOf(exp.get("single_source")))) return "single_source=" + r.singleSource;
                return null;
            }
            case "intent_provenance": {
                ParamProvenance.ProvResult r = ParamProvenance.decide(input);
                if (!r.outcome.equals(exp.get("outcome"))) return "outcome=" + r.outcome + " (" + r.reason + ")";
                if (r.outcome.equals("deny")) return null;
                if (!canonOf(r.labels).equals(canonOf(exp.get("labels")))) return "labels=" + canonOf(r.labels);
                if (!canonOf(r.classes).equals(canonOf(exp.get("classes")))) return "classes=" + canonOf(r.classes);
                if (r.outcome.equals("question") && !r.friction.equals(exp.get("friction"))) return "friction=" + r.friction;
                return null;
            }
            case "intent_wb_active": {
                boolean[] a = IntentWB.active(input);
                return a[0] == (Boolean) exp.get("facts") && a[1] == (Boolean) exp.get("provenance") && a[2] == (Boolean) exp.get("classes")
                    ? null : "active=" + java.util.Arrays.toString(a);
            }
            case "intent_read_purpose": {
                ParamProvenance.ReadPurposeResult r = ParamProvenance.decideReadPurpose(input);
                Map<String, Object> got = new java.util.LinkedHashMap<>();
                got.put("outcome", r.outcome);
                got.put("minimise", r.minimise);
                got.put("uncovered", r.uncovered);
                return canonOf(got).equals(canonOf(exp)) ? null : "got " + canonOf(got);
            }
            case "intent_map_commit": {
                String c = IntentMap.commitLeaves(((Map<String, Object>) input).get("leaves"));
                return c.equals(exp.get("map_commit")) ? null : "map_commit=" + c;
            }
            case "intent_map": {
                IntentMap.Decision d = IntentMap.decidePrimitive(input);
                if (d.ok != (Boolean) exp.get("ok")) return "ok=" + d.ok + " (" + d.reason + ")";
                if (d.ok && !canonOf(d.cell).equals(canonOf(exp.get("cell")))) return "cell=" + d.cell;
                if (d.ok && d.pPpm != Json.asLong(exp.get("p_ppm"))) return "p_ppm=" + d.pPpm;
                return null;
            }
            default: {
                IntentClassifier.ClassResult r = IntentClassifier.decide(input);
                if (r.ok != (Boolean) exp.get("ok")) return "ok=" + r.ok + " (" + r.reason + ")";
                if (r.ok && !canonOf(r.classes).equals(canonOf(exp.get("classes")))) return "classes=" + canonOf(r.classes);
                return null;
            }
        }
    }

    static void check(boolean ok, String msg) {
        checks++;
        if (!ok) { fails++; System.out.println("  FAIL: " + msg); }
    }

    /** Fixtures are trusted but contain deliberately non-canonical values, so they use the LENIENT profile. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DIR + name)));
    }

    static String str(Object o) { return o instanceof String ? (String) o : ""; }

    /** primitives.depth `expand`: the marker string (value) / substring (text) becomes `levels` nested arrays around `leaf`, built iteratively. */
    @SuppressWarnings("unchecked")
    static Object expandDepthInput(String api, Object input, Map<String, Object> ex) {
        if (ex == null) return input;
        String marker = (String) ex.get("marker");
        int levels = (int) Json.asLong(ex.get("levels"));
        Object leaf = ex.get("leaf");
        if (api.equals("pcactn_json") || api.equals("json_parse")) {
            Map<String, Object> i = new java.util.LinkedHashMap<>((Map<String, Object>) input);
            String text = (String) i.get("text");
            int at = text.indexOf(marker);
            i.put("text", text.substring(0, at) + "[".repeat(levels) + Json.canonicalize(leaf) + "]".repeat(levels) + text.substring(at + marker.length()));
            return i;
        }
        Object nest = leaf;
        for (int k = 0; k < levels; k++) { List<Object> l = new java.util.ArrayList<>(); l.add(nest); nest = l; }
        java.util.ArrayDeque<Object> st = new java.util.ArrayDeque<>();
        st.push(input);
        while (!st.isEmpty()) { // the input itself is shallow; replace the single marker value in place
            Object o = st.pop();
            if (o instanceof Map) for (Map.Entry<String, Object> e : ((Map<String, Object>) o).entrySet()) {
                if (marker.equals(e.getValue())) e.setValue(nest); else st.push(e.getValue());
            } else if (o instanceof List) { List<Object> l = (List<Object>) o; for (int k = 0; k < l.size(); k++) { if (marker.equals(l.get(k))) l.set(k, nest); else st.push(l.get(k)); } }
        }
        return input;
    }

    /** primitives.depth verdict per api (true == accepted / verifies / counts / parses). */
    @SuppressWarnings("unchecked")
    static boolean depthVerdict(String api, Object in) {
        switch (api) {
            case "chain": {
                Map<String, Object> i = (Map<String, Object>) in;
                return Pca.verifyChain((List<Object>) i.get("chain"), (String) i.get("expected_root_issuer"), true, null).isEmpty();
            }
            case "threshold_share": return Threshold.verifyShareEntry(in);
            case "pcactn_json": {
                Map<String, Object> i = (Map<String, Object>) in;
                return Pca.verifyPcactnJson((String) i.get("text"), (Map<String, Object>) i.get("grant"), Json.asLong(i.get("now")), (String) i.get("aud")).allow;
            }
            case "json_parse":
                try { Json.parse((String) ((Map<String, Object>) in).get("text")); return true; } catch (IllegalArgumentException e) { return false; }
            default: throw new IllegalStateException("unknown depth api " + api);
        }
    }

    /** Raw bytes of a base64url string of arbitrary length; throws (fail-closed) on a malformed input. */
    static byte[] b64uBytes(Object o) {
        byte[] b = Pca.decodeB64uStrict(o, -1);
        if (b == null) throw new IllegalArgumentException("not canonical base64url: " + o);
        return b;
    }

    /**
     * The set of signature suites a vector exercises: the leaf {@code alg} plus every cap-chain hop {@code alg}.
     * An absent {@code alg} is the default ed25519 and contributes nothing to skip (so downgrade vectors, which
     * strip the suite fields, always RUN as the structural negatives they are). Only inspects the parsed
     * {@code pcactn}; raw {@code pcactn_json} vectors are all ed25519 core, so none is ever suite-skipped.
     */
    @SuppressWarnings("unchecked")
    static Set<String> suitesExercised(Map<String, Object> v) {
        Set<String> out = new LinkedHashSet<>();
        Object pco = v.get("pcactn");
        if (!(pco instanceof Map)) return out;
        Map<String, Object> p = (Map<String, Object>) pco;
        if (p.get("alg") instanceof String) out.add((String) p.get("alg"));
        if (p.get("cap_chain") instanceof List) {
            for (Object ho : (List<Object>) p.get("cap_chain")) {
                if (ho instanceof Map && ((Map<String, Object>) ho).get("alg") instanceof String)
                    out.add((String) ((Map<String, Object>) ho).get("alg"));
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        fails = 0; checks = 0;
        Map<String, Object> doc = load("vectors.json");
        check(Json.asLong(doc.get("format")) == 2 && Json.asLong(doc.get("ver")) == 2, "format-2 vectors");
        check("2.1".equals(doc.get("agent_leaf_binding")), "agent_leaf_binding == 2.1");
        List<Object> vs = (List<Object>) doc.get("vectors");
        if (vs.isEmpty()) throw new IllegalStateException("no vectors");

        int ran = 0, vecFails = 0, skipped = 0;
        // Per-skipped-suite tally and a record of which cross-impl suites got a PASSING positive LEAF vector.
        Map<String, Integer> skipBySuite = new TreeMap<>();
        Set<String> crossImplPositiveLeafPassed = new LinkedHashSet<>();
        for (Object x : vs) {
            Map<String, Object> v = (Map<String, Object>) x;
            Set<String> suites = suitesExercised(v);
            // Skip iff the vector exercises a REGISTERED suite we do not implement. A bogus/unknown alg
            // (e.g. "ml-dsa-999") is NOT registered, so it still runs and is correctly rejected fail-closed.
            String unsupported = null;
            for (String s : suites)
                if (ALL_REGISTERED_SUITES.contains(s) && !IMPLEMENTED_SUITES.contains(s)) { unsupported = s; break; }
            // 0.4.1: a vector may name the suite it needs in `requires` (e.g. a threshold share under ml-dsa-87).
            if (unsupported == null && v.get("requires") instanceof String && ALL_REGISTERED_SUITES.contains((String) v.get("requires"))
                && !IMPLEMENTED_SUITES.contains((String) v.get("requires"))) unsupported = (String) v.get("requires");
            if (unsupported != null) {
                skipped++;
                skipBySuite.merge(unsupported, 1, Integer::sum);
                System.out.println("SKIP " + v.get("name") + " (unimplemented suite: " + unsupported + ")");
                if (v.get("pcactn") instanceof Map) {
                    Map<String, Object> uctx = (Map<String, Object>) v.get("context");
                    Pca.Verdict ug = Pca.verifyPcactn(v.get("pcactn"), (Map<String, Object>) v.get("grant"), Json.asLong(uctx.get("now")),
                        (String) uctx.get("aud"), null, null, null);
                    check(!ug.allow && ug.reason.contains(Pq.UNSUPPORTED_SUITE), v.get("name") + ": suite " + unsupported
                        + " is not implemented, so it must fail with unsupported_suite (" + ug.reason + ")");
                }
                continue;
            }

            int before = fails;
            Map<String, Object> ctx = (Map<String, Object>) v.get("context");
            java.util.List<String> allowedSuites = null;
            if (ctx.get("allowed_suites") instanceof java.util.List) {
                allowedSuites = new java.util.ArrayList<>();
                for (Object o : (java.util.List<Object>) ctx.get("allowed_suites")) allowedSuites.add(String.valueOf(o));
            }
            long now = Json.asLong(ctx.get("now"));
            String aud = (String) ctx.get("aud");
            Map<String, Object> grant = (Map<String, Object>) v.get("grant");
            // Intent Layer M2: `intent-*` vectors may carry context.intent_policy (an object) or context.intent_policy_json
            // (raw JSON text, parsed with this SDK's parser; it wins when both are present). Absent = no policy.
            Pca.IntentPolicy intentPolicy = (ctx.get("intent_policy_json") instanceof String ? Pca.IntentPolicy.fromJsonText((String) ctx.get("intent_policy_json")) : Pca.IntentPolicy.fromJson(ctx.get("intent_policy")));
            // Intent Layer v2: `schema-*` / `session-*` / `acc-*` / `layers-*` vectors carry the verifier state in context.intent_v2.
            IntentV2.Context intentV2 = (ctx.containsKey("intent_v2") ? IntentV2.Context.fromJson(ctx.get("intent_v2")) : null);
            Pca.Verdict got = v.containsKey("pcactn_json")
                ? Pca.verifyPcactnJson((String) v.get("pcactn_json"), grant, now, aud, allowedSuites, intentPolicy, intentV2)
                : Pca.verifyPcactn(v.get("pcactn"), grant, now, aud, allowedSuites, intentPolicy, intentV2);
            Map<String, Object> exp = (Map<String, Object>) v.get("expect");
            // Intent Layer v2: a vector whose v2 artifacts need a suite this verifier lacks must FAIL closed with unsupported_suite
            String missingSuite = missingRequiredSuite(v.get("requires_suite"));
            if (missingSuite != null) {
                check(!got.allow && got.reason.contains("unsupported_suite"), v.get("name") + ": requires_suite " + missingSuite + " not implemented, so it must fail with unsupported_suite (" + got.reason + ")");
                ran++;
                continue;
            }
            if (exp.get("reason_contains") instanceof String)
                check(got.reason.contains((String) exp.get("reason_contains")), v.get("name") + ": reason '" + got.reason + "' does not contain " + exp.get("reason_contains"));
            boolean wantAllow = (Boolean) exp.get("allow");
            check(got.allow == wantAllow, v.get("name") + ": allow=" + got.allow + " want " + wantAllow + " (" + got.reason + ")");
            Map<String, Object> want = (Map<String, Object>) exp.get("checks");
            check(want.keySet().equals(got.checks.keySet()), v.get("name") + ": check set " + got.checks.keySet() + " want " + want.keySet());
            for (Map.Entry<String, Object> e : want.entrySet())
                check(e.getValue().equals(got.checks.get(e.getKey())), v.get("name") + ": check " + e.getKey() + "=" + got.checks.get(e.getKey()) + " want " + e.getValue() + " (" + got.reason + ")");
            boolean ok = fails == before;
            ran++;
            if (!ok) vecFails++;
            System.out.println((ok ? "PASS " : "FAIL ") + v.get("name"));

            // GAP 1 evidence: record each cross-impl LEAF suite proven by a passing positive (allow==true) vector.
            if (ok && wantAllow && "pq".equals(v.get("requires"))) {
                Object pco = v.get("pcactn");
                String leaf = pco instanceof Map && ((Map<String, Object>) pco).get("alg") instanceof String
                    ? (String) ((Map<String, Object>) pco).get("alg") : "ed25519";
                if (IMPLEMENTED_SUITES.contains(leaf)) crossImplPositiveLeafPassed.add(leaf);
            }
            if (ok && wantAllow && (v.get("requires") == null || "".equals(v.get("requires")))) {
                crossImplPositiveLeafPassed.add("ed25519"); // core positives exercise the ed25519 leaf
            }
        }

        // ---- GAP 1: the three cross-impl suites must each be exercised by a passing positive -----------------
        System.out.println();
        for (String s : List.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"))
            check(crossImplPositiveLeafPassed.contains(s), "GAP1: cross-impl suite exercised by a passing positive: " + s);

        // ---- primitives --------------------------------------------------------------------------------------
        Map<String, Object> prim = (Map<String, Object>) doc.get("primitives");
        for (Object x : (List<Object>) prim.get("canonical")) {
            Map<String, Object> c = (Map<String, Object>) x;
            String s = Json.canonicalizeStrict(c.get("value"));
            check(s.equals(c.get("expect")), "canonical " + s + " vs " + c.get("expect"));
            check(Pca.hashStrict(c.get("value")).equals(c.get("hash")), "hash for " + s);
        }
        for (Object x : (List<Object>) prim.get("json_parse")) {
            Map<String, Object> j = (Map<String, Object>) x;
            String in = (String) j.get("input");
            boolean accepted;
            String canon = null;
            try { canon = Json.canonicalizeStrict(Json.parse(in)); accepted = true; } catch (RuntimeException e) { accepted = false; }
            check(accepted == (Boolean) j.get("accept"), "json_parse accept=" + accepted + " for " + in);
            if (accepted && j.containsKey("canonical")) check(canon.equals(j.get("canonical")), "json_parse canonical " + canon + " for " + in);
        }
        for (Object x : (List<Object>) prim.get("b64u")) {
            Map<String, Object> b = (Map<String, Object>) x;
            int len = b.containsKey("len") ? (int) Json.asLong(b.get("len")) : -1;
            boolean valid = Pca.decodeB64uStrict(b.get("input"), len) != null;
            check(valid == (Boolean) b.get("valid"), "b64u valid=" + valid + " for '" + b.get("input") + "' len " + len);
        }
        for (Object x : (List<Object>) prim.get("merkle")) {
            Map<String, Object> m = (Map<String, Object>) x;
            List<Object> leaves = (List<Object>) m.get("leaves");
            String root = Pca.merkleRoot(leaves);
            check(root.equals(m.get("root")), "merkle root " + root + " vs " + m.get("root"));
            List<Object> proofs = (List<Object>) m.get("proofs");
            for (int i = 0; i < proofs.size(); i++)
                check(Pca.verifyInclusion(root, (Map<String, Object>) proofs.get(i), leaves.get(i)), "proof " + i);
        }
        check(Pca.paramsDigest(null).equals(prim.get("params_digest_empty")), "empty params digest");

        // ---- GAP 2: v2.1 agent-leaf threshold-share binding --------------------------------------------------
        // Recompute the role/signer-set/t-bound share message for EVERY entry and verify share.sig over it.
        int shareChecks = 0;
        boolean bareAgentRejectVerified = false, wrongSetRejectVerified = false, boundAgentAccepted = false;
        for (Object x : (List<Object>) prim.get("threshold_share")) {
            Map<String, Object> e = (Map<String, Object>) x;
            String role = str(e.get("role"));
            int t = (int) Json.asLong(e.get("t"));
            List<Object> signerSet = (List<Object>) e.get("signer_set");
            byte[] tmsg = b64uBytes(e.get("threshold_message"));
            Map<String, Object> share = (Map<String, Object>) e.get("share");
            boolean wantValid = !e.containsKey("valid") || (Boolean) e.get("valid");
            boolean gotValid = Threshold.verifyShare(role, tmsg, signerSet, t, share);
            String nm = e.containsKey("name") ? (String) e.get("name") : role + "-t" + t;
            // Suite capability: an entry whose `requires` suite this verifier lacks is not compared; it must be refused.
            if (e.get("requires") instanceof String && !IMPLEMENTED_SUITES.contains((String) e.get("requires"))) {
                check(!gotValid, "threshold_share " + nm + ": share under unsupported suite " + e.get("requires") + " verified (want fail closed)");
                continue;
            }
            check(gotValid == wantValid, "threshold_share " + nm + ": verify=" + gotValid + " want " + wantValid);
            shareChecks++;
            if ("agent-bare-rejected".equals(nm)) bareAgentRejectVerified = !gotValid;
            if ("agent-bound-wrong-set".equals(nm)) wrongSetRejectVerified = !gotValid;
            if ("agent-bound-t1".equals(nm) || "agent-bound-t2".equals(nm)) boundAgentAccepted = gotValid;
        }
        // The v2.1 binding is only meaningful if BOTH the bare-agent and the wrong-signer-set shares are REJECTED
        // AND a properly bound agent share is ACCEPTED.
        check(bareAgentRejectVerified, "GAP2: bare pre-v2.1 agent share (agent-bare-rejected) is REJECTED");
        check(wrongSetRejectVerified, "GAP2: cross-signer-set agent share (agent-bound-wrong-set) is REJECTED");
        check(boundAgentAccepted, "GAP2: a v2.1 signerSetHash‖t-bound agent share is ACCEPTED");

        // ---- post-quantum artifact signatures (same agility seam as the leaf) --------------------------------
        int artRan = 0, artSkipped = 0;
        for (Object x : (List<Object>) prim.get("pq_artifact")) {
            Map<String, Object> a = (Map<String, Object>) x;
            String alg = str(a.get("alg"));
            if (ALL_REGISTERED_SUITES.contains(alg) && !IMPLEMENTED_SUITES.contains(alg)) { artSkipped++; continue; }
            boolean wantValid = !a.containsKey("valid") || (Boolean) a.get("valid");
            boolean gotValid;
            try {
                byte[] msg = b64uBytes(a.get("message"));
                gotValid = Pq.verifyArtifactSignature(alg, str(a.get("ed_pub")), a.get("pq_pk"), msg, a.get("sig"), a.get("pq_sig"));
            } catch (RuntimeException ex) {
                gotValid = false; // fail-closed
            }
            check(gotValid == wantValid, "pq_artifact " + a.get("artifact") + "/" + alg + ": verify=" + gotValid + " want " + wantValid);
            artRan++;
        }

        // ---- R4-01: standalone chain verification with verifier-side PQ authority (primitives.chain_pin) ---------
        int pinRan = 0, pinSkipped = 0;
        for (Object x : (List<Object>) prim.get("chain_pin")) {
            Map<String, Object> cv = (Map<String, Object>) x;
            Map<String, Object> ex = (Map<String, Object>) cv.get("expect");
            boolean wantOk = Boolean.TRUE.equals(ex.get("ok"));
            String wantReason = ex.get("reason") instanceof String ? (String) ex.get("reason") : null;
            boolean pinReason = wantReason != null && wantReason.startsWith("hop 0: root suite");
            Set<String> need = new LinkedHashSet<>();
            for (Object ho : (List<Object>) cv.get("chain")) if (ho instanceof Map && ((Map<String, Object>) ho).get("alg") instanceof String) need.add((String) ((Map<String, Object>) ho).get("alg"));
            if (!pinReason && !IMPLEMENTED_SUITES.containsAll(need)) { pinSkipped++; continue; }
            List<String> allowed = null;
            if (cv.get("allowed_suites") instanceof List) { allowed = new java.util.ArrayList<>(); for (Object o : (List<Object>) cv.get("allowed_suites")) allowed.add(String.valueOf(o)); }
            String why;
            try {
                why = Pca.verifyChain((List<Object>) cv.get("chain"), (String) cv.get("expected_root_issuer"), cv.get("expected_root_issuer") instanceof String,
                    allowed, (Map<String, Object>) cv.get("pq_pins"), (Map<String, Object>) cv.get("trusted_root"));
            } catch (RuntimeException ex2) { why = "exception: " + ex2; }
            check(why.isEmpty() == wantOk, "chain_pin " + cv.get("name") + ": ok=" + why.isEmpty() + " want " + wantOk + (why.isEmpty() ? "" : " (" + why + ")"));
            if (pinReason) check(wantReason.equals(why), "chain_pin " + cv.get("name") + ": exact hop 0 pin reason");
            pinRan++;
        }
        check(pinRan + pinSkipped >= 25, "chain_pin: at least 25 vectors present (" + (pinRan + pinSkipped) + ")");

        // ---- round 6: whole signer-set validation, signer-set hash, malformed input (gen-conformance-r6.mjs) -------
        int tsRan = 0, tsSkipped = 0, malformedRan = 0;
        for (Object x : (List<Object>) prim.get("threshold_set")) {
            Map<String, Object> e = (Map<String, Object>) x;
            if (e.get("requires") instanceof String && !IMPLEMENTED_SUITES.contains((String) e.get("requires"))) { tsSkipped++; continue; }
            boolean want = Boolean.TRUE.equals(e.get("valid"));
            boolean got;
            try { got = Threshold.verifyShareEntry(e); } catch (Throwable th) { check(false, "threshold_set " + e.get("name") + ": THREW " + th); continue; }
            check(got == want, "threshold_set " + e.get("name") + ": verify=" + got + " want " + want);
            tsRan++;
        }
        for (Object x : (List<Object>) prim.get("signer_set_hash")) {
            Map<String, Object> e = (Map<String, Object>) x;
            String h = Threshold.signerSetHashB64u(e.get("signer_set"));
            check(String.valueOf(e.get("hash")).equals(h), "signer_set_hash " + e.get("name") + ": got " + h);
        }
        for (Object x : (List<Object>) prim.get("malformed")) {
            Map<String, Object> m = (Map<String, Object>) x;
            String nm = String.valueOf(m.get("name"));
            Object in = m.get("input");
            malformedRan++;
            try {
                boolean accepted;
                switch (String.valueOf(m.get("api"))) {
                    case "chain": {
                        Map<String, Object> i = (Map<String, Object>) in;
                        accepted = Pca.verifyChain((List<Object>) i.get("chain"), (String) i.get("expected_root_issuer"), true, null).isEmpty();
                        break;
                    }
                    case "threshold_share": accepted = Threshold.verifyShareEntry(in); break;
                    case "pcactn_json": {
                        Map<String, Object> i = (Map<String, Object>) in;
                        accepted = Pca.verifyPcactnJson((String) i.get("text"), (Map<String, Object>) i.get("grant"), Json.asLong(i.get("now")), (String) i.get("aud")).allow;
                        break;
                    }
                    default: accepted = true;
                }
                check(!accepted, "malformed " + nm + ": accepted");
            } catch (Throwable th) { check(false, "malformed " + nm + ": THREW " + th); }
        }
        check(tsRan + tsSkipped >= 55 && malformedRan >= 80, "round-6 primitives present (threshold_set " + (tsRan + tsSkipped) + ", malformed " + malformedRan + ")");
        System.out.println("ROUND6: threshold_set " + tsRan + " run, " + tsSkipped + " skipped; malformed " + malformedRan);

        // ---- nesting depth (gen-conformance-depth.mjs): limit-1 / limit / limit+1 and a huge (expanded) depth per entry point.
        // Each case runs on a 512 KiB-stack thread (a typical servlet worker): the verdict must equal `valid` and nothing may escape.
        int depthRan = 0;
        for (Object x : (List<Object>) prim.get("depth")) {
            Map<String, Object> d = (Map<String, Object>) x;
            String nm = String.valueOf(d.get("name"));
            Object in = expandDepthInput(String.valueOf(d.get("api")), d.get("input"), (Map<String, Object>) d.get("expand"));
            boolean want = Boolean.TRUE.equals(d.get("valid"));
            Object[] out = new Object[1];
            Thread t = new Thread(null, () -> {
                try { out[0] = depthVerdict(String.valueOf(d.get("api")), in); } catch (Throwable th) { out[0] = th; }
            }, "depth", 512 * 1024);
            t.start();
            try { t.join(); } catch (InterruptedException ie) { throw new IllegalStateException(ie); }
            if (out[0] instanceof Throwable) check(false, "depth " + nm + ": THREW " + out[0]);
            else check(Boolean.valueOf(want).equals(out[0]), "depth " + nm + ": verdict=" + out[0] + " want " + want);
            depthRan++;
        }
        check(depthRan >= 20, "depth primitives present (" + depthRan + ")");
        System.out.println("DEPTH: " + depthRan + " run");

        // ---- 0.4.1: policy-layer caveats (root caveats included) and the strict PCA-Action header ----------------
        int caveatRan = 0;
        for (Object x : (List<Object>) prim.get("caveat_eval")) {
            Map<String, Object> e = (Map<String, Object>) x;
            Map<String, Object> exp = (Map<String, Object>) e.get("expect");
            Caveats.Result r;
            try { r = Caveats.evaluateCaveats(Caveats.policyCaveats(e.get("grant"), e.get("chain")), e.get("context")); }
            catch (Throwable th) { check(false, "caveat_eval " + e.get("name") + ": THREW " + th); continue; }
            check(Boolean.valueOf(r.ok).equals(exp.get("allow")), "caveat_eval " + e.get("name") + ": allow=" + r.ok + " want " + exp.get("allow") + " " + r.failed);
            check(r.failed.equals(exp.get("failed")), "caveat_eval " + e.get("name") + ": failed=" + r.failed + " want " + exp.get("failed"));
            caveatRan++;
        }
        check(caveatRan >= 40, "caveat_eval primitives present (" + caveatRan + ")");
        System.out.println("CAVEAT_EVAL: " + caveatRan + " run");
        int headerRan = 0;
        for (Object x : (List<Object>) prim.get("pca_header")) {
            Map<String, Object> e = (Map<String, Object>) x;
            boolean want = Boolean.TRUE.equals(e.get("valid"));
            String got;
            try { got = Pca.decodePcaHeader((String) e.get("input")); }
            catch (Throwable th) { check(false, "pca_header " + e.get("name") + ": THREW " + th); continue; }
            check((got != null) == want, "pca_header " + e.get("name") + ": valid=" + (got != null) + " want " + want);
            if (got != null && want) check(got.equals(e.get("text")), "pca_header " + e.get("name") + ": text mismatch");
            headerRan++;
        }
        check(headerRan >= 27, "pca_header primitives present (" + headerRan + ")");
        System.out.println("PCA_HEADER: " + headerRan + " run");

        // ---- Intent Layer v2 primitives (rules 13 step 7, 14, 16, 17, 18); reason strings are never compared ----
        for (String kind : List.of("intent_schema", "intent_revocation", "intent_world", "intent_provenance", "intent_classifier", "intent_wb_active", "intent_map_commit", "intent_map", "intent_read_purpose")) {
            if (!(prim.get(kind) instanceof List)) { System.out.println(kind.toUpperCase() + ": absent"); continue; }
            int n = 0;
            for (Object x : (List<Object>) prim.get(kind)) {
                Map<String, Object> e = (Map<String, Object>) x;
                String why;
                try {
                    Map<String, Object> exp = (Map<String, Object>) e.get("expect");
                    String missingSuite = missingRequiredSuite(e.get("requires_suite"));
                    Object input = inputOf(e);
                    String reason = intentPrimitiveReason(kind, input);
                    if (missingSuite != null) why = reason != null && reason.contains("unsupported_suite") ? null : "requires_suite " + missingSuite + ": must fail with unsupported_suite (" + reason + ")";
                    else {
                        why = intentPrimitiveMismatch(kind, input, exp);
                        if (why == null && exp.get("reason_contains") instanceof String && (reason == null || !reason.contains((String) exp.get("reason_contains"))))
                            why = "reason '" + reason + "' does not contain " + exp.get("reason_contains");
                    }
                }
                catch (Throwable th) { why = "THREW " + th; }
                check(why == null, kind + " " + e.get("name") + ": " + why);
                n++;
            }
            check(n >= 1, kind + " primitives present (" + n + ")");
            System.out.println(kind.toUpperCase() + ": " + n + " run");
        }

        // ---- report ------------------------------------------------------------------------------------------
        System.out.println();
        System.out.println("VECTORS: " + (ran + skipped) + " total = " + ran + " run (" + (ran - vecFails) + " passed, " + vecFails + " failed), " + skipped + " skipped");
        if (!skipBySuite.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Integer> en : skipBySuite.entrySet()) sb.append("\n    ").append(en.getKey()).append(": ").append(en.getValue());
            System.out.println("  skipped by unimplemented suite:" + sb);
        }
        System.out.println("THRESHOLD_SHARE (v2.1 agent-leaf binding): " + shareChecks + " shares checked; "
            + "bare-agent rejected=" + bareAgentRejectVerified + ", wrong-set rejected=" + wrongSetRejectVerified
            + ", bound-agent accepted=" + boundAgentAccepted);
        System.out.println("PQ_ARTIFACT: " + artRan + " run, " + artSkipped + " skipped (unimplemented suites)");
        System.out.println("CHAIN_PIN (R4-01): " + pinRan + " run, " + pinSkipped + " skipped");
        System.out.println("ASSERTIONS: " + checks + " checked, " + fails + " failures");
        if (System.getProperty("pca.noexit") == null) System.exit(fails == 0 ? 0 : 1);
    }
}
