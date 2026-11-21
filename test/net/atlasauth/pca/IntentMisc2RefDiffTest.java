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
 * The leftovers of five intent modules against the reference corpus (ref-intent-misc2, 770 cases): the signed "ask the principal" question and its
 * problem, the strict-artifact helpers, classifier verdicts, policy, quorum decision (with the votes) and attestation gate, the signing and digest
 * half of accumulator receipts and sequencer key sets, and admission and settlement through a session store (one fresh in-memory store per case). A
 * reference throw requires a refusal. Every fn has a handler, the total is asserted, and the one case that the reference accepts only through
 * allowUnboundPq is not offered here (this SDK has no such option).
 */
class IntentMisc2RefDiffTest {
    static final String MODULE = "ref-intent-misc2";
    static final int TOTAL = 770;

    private static Map<String, Object> m(Object o) { return AttestRootsKit.m(o); }

    private static Object arg(List<?> a, int i) { return AttestRootsKit.arg(a, i); }

    private static Object dec(Object o) { return AttestRootsKit.dec(o); }

    private static byte[] bytes(Object o) { return (byte[]) o; }

    @SuppressWarnings("unchecked")
    private static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<Object>) o) out.add((String) x);
        return out;
    }

    private static Pq.SignerSuiteOpts suite(List<?> a, int i) {
        Map<String, Object> d = m(arg(a, i));
        if (d == null) return null;
        Pq.SignerSuiteOpts s = new Pq.SignerSuiteOpts();
        s.alg = (String) d.get("alg");
        Object ps = d.get("pqSeed");
        if (ps instanceof byte[]) s.mlDsa = Pq.mlDsa65Keygen((byte[]) ps); // the corpus resolves {"$bytes": ...} to the byte string
        else if (ps instanceof String) s.mlDsa = Pq.mlDsa65Keygen(AttestRootsKit.unb((String) ps));
        return s;
    }

    private static Object resolved(Object params, Object path) {
        Predicates.Resolved r = IntentArtifacts.resolveParamPath(params, path);
        return r.found ? Issue.obj("found", true, "value", r.value) : Issue.obj("found", false);
    }

    private static Object classOut(IntentClassifier.ClassResult r) {
        return r.ok ? Issue.obj("ok", true, "classes", r.classes, "votes", r.votes) : Issue.obj("ok", false, "reason", r.reason);
    }

    private static Object admit(List<?> a) {
        IntentMisc2.SessionStore[] store = {new IntentMisc2.MemorySessionStore(true)};
        List<Object> res = new ArrayList<>();
        for (Object opo : (List<?>) arg(a, 0)) {
            List<?> op = (List<?>) opo;
            switch ((String) op.get(0)) {
                case "store": {
                    Object spec = m(op.get(1)).get("durable");
                    store[0] = new IntentMisc2.MemorySessionStore("absent".equals(spec) ? null : spec);
                    res.add(null);
                    break;
                }
                case "admit": {
                    Map<String, Object> args = m(op.get(1));
                    try {
                        Map<String, Object> verdict = IntentMisc2.admitIntentAction(store[0], args, acc -> {
                            if ("throws".equals(args.get("verifyAs"))) throw new IllegalStateException("verify down"); // the oracle throws before it records acc
                            res.add(Issue.obj("acc", acc));
                            return Issue.obj("allow", m(args.get("verifyAs")).get("allow"));
                        }, !Boolean.FALSE.equals(args.get("requireDurable")));
                        res.add(verdict);
                    } catch (RuntimeException e) {
                        res.add(Issue.obj("$err", true));
                    }
                    break;
                }
                case "settle": res.add(IntentMisc2.settleIntentEvent(store[0], (String) op.get(1), (String) op.get(2), (String) op.get(3))); break;
                case "events": res.add(store[0].withSession((String) op.get(1), tx -> tx.events())); break;
                default: res.add(Issue.obj("$err", true)); break;
            }
        }
        return res;
    }

    private static Map<String, OracleCases.Fn> fns() {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> IntentMisc2.constants());
        // intent-artifacts
        f.put("isPathSegment", x -> IntentArtifacts.isPathSegment(arg(x, 0) instanceof String ? (String) arg(x, 0) : AttestNvidia.jsString(arg(x, 0))));
        f.put("isPlainObject", x -> arg(x, 0) instanceof Map);
        f.put("isSafeInt", x -> IntentJs.isInt(arg(x, 0)));
        f.put("utf8Len", x -> IntentJs.u8len((String) arg(x, 0)));
        f.put("isBoundedString", x -> {
            Double max = IntentJs.num(arg(x, 1));
            return arg(x, 0) instanceof String && !((String) arg(x, 0)).isEmpty() && max != null && IntentJs.u8len((String) arg(x, 0)) <= max;
        });
        f.put("isDigest", x -> IntentArtifacts.isDigest(arg(x, 0)));
        f.put("isScalar", x -> IntentArtifacts.isScalar(arg(x, 0)));
        f.put("scalarEq", x -> IntentArtifacts.scalarEq(arg(x, 0), arg(x, 1)));
        f.put("closedMembers", x -> IntentArtifacts.closedMembers(m(arg(x, 0)), strs(arg(x, 1)), strs(arg(x, 2)), arg(x, 3) instanceof String ? (String) arg(x, 3) : "object"));
        f.put("pinPqOk", x -> x.isEmpty() || (arg(x, 0) instanceof String && !((String) arg(x, 0)).isEmpty()));
        f.put("artifactSuiteError", x -> m(arg(x, 0)) != null ? IntentArtifacts.artifactSuiteError(m(arg(x, 0))) : "artifact must be an object");
        f.put("artifactMessage", x -> IntentArtifacts.artifactMessage((String) arg(x, 0), m(arg(x, 1))));
        f.put("signArtifact", x -> IntentMisc2.signArtifact((String) arg(x, 0), m(arg(x, 1)), bytes(arg(x, 2)), suite(x, 3)));
        f.put("verifyArtifactSig", x -> IntentMisc2.verifyArtifactSig((String) arg(x, 0), arg(x, 1), arg(x, 2)));
        f.put("artifactRef", x -> IntentArtifacts.artifactRef((String) arg(x, 0), (String) arg(x, 1), arg(x, 2)));
        f.put("publicKeyB64u", x -> IntentMisc2.publicKeyB64u(bytes(arg(x, 0))));
        f.put("resolveParamPath", x -> resolved(arg(x, 0), arg(x, 1)));
        f.put("isParamPath", x -> IntentArtifacts.isParamPath(arg(x, 0)));
        f.put("setNested", x -> {
            Map<String, Object> o = m(arg(x, 0));
            Map<String, Object> root = m(o.get("root"));
            boolean ok = IntentArtifacts.setNested(root, (String) o.get("path"), o.get("value"));
            return Issue.obj("ok", ok, "root", root);
        });
        f.put("isClock", x -> IntentJs.isInt(arg(x, 0)));
        f.put("ownGet", x -> m(arg(x, 0)) != null ? m(arg(x, 0)).get((String) arg(x, 1)) : null);
        f.put("nullRecord", x -> new LinkedHashMap<String, Object>());
        // intent-required
        f.put("intentActionDigest", x -> IntentRequired.intentActionDigest(arg(x, 0)));
        f.put("cellCoordsError", x -> IntentRequired.cellCoordsError(arg(x, 0)));
        f.put("intentRequiredShapeError", x -> IntentRequired.intentRequiredShapeError(arg(x, 0), !(m(arg(x, 1)) != null && Boolean.FALSE.equals(m(arg(x, 1)).get("signed")))));
        f.put("signIntentRequired", x -> IntentRequired.signIntentRequired(m(arg(x, 0)), (String) arg(x, 1), bytes(arg(x, 2)), suite(x, 3)));
        f.put("verifyIntentRequired", x -> IntentRequired.verifyIntentRequired(arg(x, 0), arg(x, 1), arg(x, 2)));
        f.put("verifyIntentRequiredAt", x -> IntentRequired.verifyIntentRequiredAt(arg(x, 0), arg(x, 1), arg(x, 2)));
        f.put("intentProblem", x -> IntentRequired.intentProblem(arg(x, 0), m(arg(x, 1))));
        // intent-classifier
        f.put("validateClassifierVerdictWire", x -> IntentClassifier.validateVerdictWire(arg(x, 0)));
        f.put("classifierContentDigest", x -> IntentJs.hashCanonical(arg(x, 0)));
        f.put("signClassifierVerdict", x -> IntentMisc2.signClassifierVerdict(m(arg(x, 0)), bytes(arg(x, 1)), suite(x, 2)));
        f.put("classifierVerdictRef", x -> IntentClassifier.verdictRef(m(arg(x, 0))));
        f.put("validateClassifierPolicy", x -> IntentClassifier.validatePolicy(arg(x, 0)));
        f.put("classifierCheckActive", x -> m(arg(x, 0)) != null && IntentClassifier.classifierCheckActive(m(arg(x, 0)).get("committed"), m(arg(x, 0)).get("policy")));
        f.put("decideClassifierDimensions", x -> classOut(IntentClassifier.decide(arg(x, 0))));
        f.put("verifyClassifierAttestation", x -> IntentMisc2.verifyClassifierAttestation(arg(x, 0), arg(x, 1), arg(x, 2)));
        // intent-acc
        f.put("monitorStates", x -> {
            List<String> q = IntentAcc.monitorStates(m(arg(x, 0)));
            return q.isEmpty() ? null : new ArrayList<Object>(q); // an unknown kind is the reference's undefined (the native has the empty set)
        });
        f.put("monitorInitialState", x -> IntentHistory.monitorInitialState(m(arg(x, 0))));
        f.put("distinctKey", x -> IntentAcc.distinctKey(arg(x, 0)));
        f.put("sortedDistinct", x -> IntentMisc2.sortedDistinct(strs(arg(x, 0))));
        f.put("signAccReceipt", x -> IntentMisc2.signAccReceipt(m(arg(x, 0)), bytes(arg(x, 1)), suite(x, 2)));
        f.put("accReceiptDigest", x -> IntentAcc.receiptDigest(arg(x, 0)));
        f.put("accReceiptCoreDigest", x -> IntentMisc2.accReceiptCoreDigest(m(arg(x, 0))));
        f.put("verifyReceiptSignature", x -> m(arg(x, 0)) != null && IntentAcc.verifyReceiptSignature(m(arg(x, 0)), (String) arg(x, 1), m(arg(x, 2)) == null ? null : m(m(arg(x, 2)).get("pqPins"))));
        f.put("signSequencerKeySet", x -> IntentMisc2.signSequencerKeySet(m(arg(x, 0)), bytes(arg(x, 1)), suite(x, 2)));
        f.put("sequencerKeySetDigest", x -> IntentAcc.keySetDigest(arg(x, 0)));
        f.put("verifyKeySet", x -> IntentAcc.verifyKeySet(arg(x, 0), (String) arg(x, 1), arg(x, 2), x.size() > 2));
        // intent-history
        f.put("accContextFor", x -> {
            Map<String, Object> cand = m(arg(x, 2));
            return IntentHistory.accContextFor(m(arg(x, 0)), (List<?>) arg(x, 1), m(cand.get("params")), cand.get("t"), arg(x, 3));
        });
        f.put("admit", IntentMisc2RefDiffTest::admit);
        return f;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = fns();
        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size(), "case total");
        Set<String> fnNames = new TreeSet<>();
        for (Map<String, Object> c : all) fnNames.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fnNames, "every fn of the corpus has a handler");
        List<String> bad = new ArrayList<>();
        int replayed = 0, refused = 0;
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                Map<String, Object> hc = new LinkedHashMap<>(c);
                hc.put("args", dec(c.get("args")));
                replayed++;
                if (Json.canonicalize(c.get("args")).contains("allowUnboundPq")) {
                    // the reference accepts a PQ receipt with no pinned PQ key only through allowUnboundPq; this SDK never offers it: the case must be refused
                    refused++;
                    Object got = e.getValue().apply((List<?>) hc.get("args"));
                    if (!Boolean.FALSE.equals(got)) bad.add(c.get("name") + ": an unbound PQ receipt was accepted: " + got);
                    continue;
                }
                String d = AttestRootsKit.diff(hc, e.getValue());
                if (d != null) bad.add(d);
            }
        }
        assertEquals(TOTAL, replayed, "every case was replayed");
        assertEquals(1, refused, "the allowUnboundPq cases are refused, counted");
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
