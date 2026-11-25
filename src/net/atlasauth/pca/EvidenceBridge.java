package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Public entry points to the package-private intent artifact verifiers the dispute-evidence replay reads. */
public final class EvidenceBridge {
    private EvidenceBridge() {}

    /** The first {@code intent_session} caveat of a grant, or null. */
    public static Map<String, Object> grantSessionCaveat(Object grant) { return IntentSession.grantSessionCaveat(grant); }

    /** A sequencer key set verifies under its pinned root (and the root's pinned PQ key when {@code rootPqPresent}). */
    public static boolean verifySequencerKeySet(Object k, String root, Object rootPqPk, boolean rootPqPresent) {
        return IntentAcc.verifyKeySet(k, root, rootPqPk, rootPqPresent);
    }

    /**
     * Rule 15 receipt check against a sequenced holder. {@code minKeySetVersion} (null = none) is a bare version floor; {@code tracked}
     * (null = none) the tracked {version, digest}. Null ages take the core defaults.
     */
    public static boolean verifyReceiptAgainstHolder(Map<String, Object> r, Map<String, Object> holder, List<?> keySets, double now, Double maxReceiptAgeMs,
                                                     Double maxKeySetAgeMs, Map<String, Object> tracked, Double minKeySetVersion) {
        List<Object> sets = new ArrayList<>(keySets);
        if (minKeySetVersion != null) {
            double f = minKeySetVersion;
            if (!(Double.isFinite(f) && f == Math.rint(f) && f >= 0 && f <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(f))) return false;
            sets.removeIf(k -> { Double v = IntentJs.num(IntentJs.get(k, "version")); return v != null && v < f; });
        }
        return IntentAcc.verifyReceiptAgainstHolder(r, holder, sets, now,
            maxReceiptAgeMs == null ? IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS : maxReceiptAgeMs,
            maxKeySetAgeMs == null ? IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS : maxKeySetAgeMs, tracked);
    }

    public static boolean receiptArithmeticOk(Object agg, Map<String, Object> r, long val) { return IntentAcc.receiptArithmeticOk(agg, r, val); }

    /** The value an event contributes to accumulator {@code a} ({@code accValueOf}); null when it has none (the reference's {@code ok: false}). */
    public static Long accValue(Map<String, Object> a, String verb, Map<String, Object> params, Object schema) {
        IntentAcc.AccValue v = IntentAcc.accValueOf(a, verb, params, schema);
        return v.reason == null ? Long.valueOf(v.val) : null;
    }

    /** {@code verifyArtifactSig} under one pinned Ed25519 key. */
    public static boolean verifyArtifactSig(String domain, Map<String, Object> artifact, String pinnedPk) { return IntentArtifacts.verifyArtifactSig(domain, artifact, pinnedPk, null); }

    /** {@code verifyArtifactSig} under a pinned signer: the Ed25519 key and, for a PQ or hybrid suite, the pin's PQ key. */
    public static boolean verifyArtifactSig(String domain, Map<String, Object> artifact, Object pinnedPk, Object pinnedPqPk) { return IntentArtifacts.verifyArtifactSig(domain, artifact, pinnedPk, pinnedPqPk); }

    /** The artifact's suite capability problem ({@code alg} / {@code pq_pk} / {@code pq_sig} shape), or null. */
    public static String artifactSuiteError(Map<String, Object> artifact) { return IntentArtifacts.artifactSuiteError(artifact); }

    public static String validateFactWire(Object f) { return OracleFacts.validateFactWire(f); }
    public static String validateOfferSetWire(Object o) { return OracleFacts.validateOfferSetWire(o); }
    public static String validateClassifierVerdictWire(Object v) { return IntentClassifier.validateVerdictWire(v); }
    public static String verifyLabels(Object labels, List<?> keys) { return ParamProvenance.verifyLabels(labels, keys); }

    /** The verifier context {@code acc} for a candidate action: {state: pre-states of the site-local accumulators, monitors: monitor states}. */
    public static Map<String, Object> accContextFor(Map<String, Object> root, List<?> history, Map<String, Object> candParams, Object candT, Object schema) {
        Map<String, Object> state = new LinkedHashMap<>();
        Object accs = root.get("accumulators");
        if (!(accs instanceof List)) throw new IllegalArgumentException("session root accumulators is not iterable");
        for (Object ao : (List<?>) accs) {
            Map<String, Object> a = IntentJs.obj(ao);
            if (!"site_local".equals(IntentJs.get(a.get("holder"), "kind"))) continue;
            if (IntentHistory.accKeyOf(a, candParams) == null) continue; // the verifier fails the claim (missing key)
            Map<String, Object> pre = IntentHistory.accPreState(a, history, candParams, candT, schema);
            if (pre == null) throw new IllegalArgumentException("accPreState failed for " + a.get("id"));
            state.put((String) a.get("id"), pre);
        }
        Map<String, Object> monitors = new LinkedHashMap<>();
        Object ms = root.get("monitors");
        if (!(ms instanceof List)) throw new IllegalArgumentException("session root monitors is not iterable");
        for (Object mo : (List<?>) ms) {
            Map<String, Object> m = IntentJs.obj(mo);
            monitors.put((String) m.get("id"), IntentHistory.monitorState(m, history));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", state);
        out.put("monitors", monitors);
        return out;
    }
}
