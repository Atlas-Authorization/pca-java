package net.atlasauth.pca.pqthreshold;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Frost;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.PcaCore;
import net.atlasauth.pca.W3Bridge;

/**
 * The signing and PCActn-verifier side of the hybrid post-quantum threshold step-up: sign with a FROST quorum plus ML-DSA-65 co-signers, fold the
 * classical aggregate into a PCActn's threshold container, and enforce both halves through the core verifier's threshold hook. The artifact formats
 * and the standalone verifier live in {@link PqThreshold}.
 */
public final class HybridThreshold {
    private HybridThreshold() {}

    /** The classical FROST quorum supplied to {@link #hybridThresholdSign}; {@code groupPublicKey} is 32 bytes or canonical b64u(32). */
    public static final class FrostQuorumInput {
        public Object groupPublicKey;
        public List<Frost.FrostParticipantShare> quorum;
        public int t;
        public FrostQuorumInput(Object groupPublicKey, List<Frost.FrostParticipantShare> quorum, int t) { this.groupPublicKey = groupPublicKey; this.quorum = quorum; this.t = t; }
    }

    private static byte[] groupKeyBytes(Object k) {
        if (k instanceof byte[]) {
            if (((byte[]) k).length != 32) throw new IllegalArgumentException("hybridThresholdSign: FROST group public key must be 32 bytes");
            return (byte[]) k;
        }
        byte[] d = k instanceof String ? Pca.decodeB64uStrict(k, 32) : null;
        if (d == null) throw new IllegalArgumentException("hybridThresholdSign: FROST group public key is not canonical b64u(32)");
        return d;
    }

    /**
     * A hybrid artifact for {@code action}: the FROST t-of-n aggregate over {@code thresholdMessage(action)} (produced here by {@link Frost#cosign}, which
     * throws on a short quorum or an invalid share) plus one ML-DSA-65 co-signature per signer over the same message.
     */
    public static Map<String, Object> hybridThresholdSign(Map<String, Object> action, FrostQuorumInput frost, List<PqThreshold.MlDsaKeyPair> pqSigners, Integer pqT) {
        if (frost.t < 1) throw new IllegalArgumentException("hybridThresholdSign: frost.t must be a positive integer (got " + frost.t + ")");
        if (frost.quorum.size() < frost.t) throw new IllegalArgumentException("hybridThresholdSign: FROST quorum of " + frost.quorum.size() + " is below the threshold t=" + frost.t);
        if (pqSigners.isEmpty()) throw new IllegalArgumentException("hybridThresholdSign: at least one ML-DSA co-signer is required");
        byte[] message = Pca.thresholdMessage(action);
        byte[] groupKey = groupKeyBytes(frost.groupPublicKey);
        byte[] aggregate = Frost.cosign(groupKey, frost.quorum, message, frost.t);
        return PqThreshold.hybridThresholdAssemble(action, groupKey, aggregate, frost.t, frost.quorum.size(), pqSigners, pqT);
    }

    /** The PCActn with the classical aggregate folded into its threshold container, and the PQ block that travels alongside it. */
    public static final class StepUp {
        public final Map<String, Object> pcactn, pq;
        public StepUp(Map<String, Object> pcactn, Map<String, Object> pq) { this.pcactn = pcactn; this.pq = pq; }
    }

    /**
     * Fold a hybrid artifact into a PCActn step-up: the FROST aggregate becomes a 'guardian' share (publicKey = the group key, sig = the aggregate) in
     * {@code threshold.shares}; {@code thresholdMessage} excludes {@code threshold}, so neither quorum's signed bytes change. The PQ block cannot live
     * in the signed body and rides alongside.
     */
    @SuppressWarnings("unchecked")
    public static StepUp foldHybridStepUp(Map<String, Object> action, Map<String, Object> artifact) {
        Object frost = artifact.get("frost");
        if (!(frost instanceof Map)) throw new IllegalArgumentException("foldHybridStepUp: artifact has no FROST part");
        Map<String, Object> f = (Map<String, Object>) frost;
        Map<String, Object> share = new LinkedHashMap<>();
        share.put("role", "guardian");
        if (f.containsKey("group_pk")) share.put("publicKey", f.get("group_pk")); // an absent member stays absent (JSON drops undefined)
        if (f.containsKey("sig")) share.put("sig", f.get("sig"));
        List<Object> shares = new ArrayList<>();
        Object th = action.get("threshold");
        if (th instanceof Map && ((Map<String, Object>) th).get("shares") instanceof List) shares.addAll((List<Object>) ((Map<String, Object>) th).get("shares"));
        shares.add(share);
        Map<String, Object> threshold = new LinkedHashMap<>();
        threshold.put("shares", shares);
        Map<String, Object> pcactn = new LinkedHashMap<>(action);
        pcactn.put("threshold", threshold);
        return new StepUp(pcactn, (Map<String, Object>) artifact.get("pq"));
    }

    /** Configuration of {@link #createHybridThresholdVerifier}; values are wire/config values (keys may be String or byte[]). */
    public static final class VerifierOpts {
        public Object groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities;
        public Object pqBlock;
        public String signerSetCommitment;
    }

    private static Object deepCopy(Object v) {
        if (v instanceof Map) { Map<String, Object> o = new LinkedHashMap<>(); for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) o.put((String) e.getKey(), deepCopy(e.getValue())); return o; }
        if (v instanceof List) { List<Object> o = new ArrayList<>(); for (Object x : (List<?>) v) o.add(deepCopy(x)); return o; }
        if (v instanceof byte[]) return ((byte[]) v).clone();
        return v;
    }

    private static String normalizeGroupKeyB64u(Object k) {
        String s = GroupDescriptor.asB64u(k);
        return s != null && Pca.decodeB64uStrict(s, 32) != null ? s : null;
    }

    private static String checkDescriptor(VerifierOpts o) {
        Map<String, Object> r = GroupDescriptor.verifyGroupDescriptor(o.groupDescriptor, o.trustedAuthorities, o.groupKey, o.t, o.signerSetCommitment);
        return Boolean.TRUE.equals(r.get("ok")) ? null : (String) r.get("reason");
    }

    /**
     * The core verifier's threshold hook enforcing the hybrid step-up: the FROST aggregate folded into {@code pcactn.threshold} (a plain Ed25519
     * signature under the TRUSTED group key) AND the ML-DSA quorum block. The configuration is copied, so later edits by the caller change nothing.
     * Enforced and ok only when both hold; every other outcome is an enforced refusal.
     */
    public static PcaCore.Hook createHybridThresholdVerifier(VerifierOpts in) {
        VerifierOpts o = new VerifierOpts();
        o.groupKey = deepCopy(in.groupKey); o.pqPublicKeys = deepCopy(in.pqPublicKeys); o.t = in.t; o.pqT = in.pqT; o.pqBlock = deepCopy(in.pqBlock);
        o.groupDescriptor = deepCopy(in.groupDescriptor); o.trustedAuthorities = deepCopy(in.trustedAuthorities); o.signerSetCommitment = in.signerSetCommitment;
        String trustedGroupKey = normalizeGroupKeyB64u(o.groupKey);
        if (!(o.pqPublicKeys instanceof List)) throw new IllegalArgumentException("pqPublicKeys is not iterable");
        Set<String> pool = PqThreshold.normalizePqQuorumPool((List<?>) o.pqPublicKeys);
        return ctx -> {
            String descriptorReason = checkDescriptor(o);
            if (descriptorReason != null) return PcaCore.HookResult.enforced(false, descriptorReason, null);
            byte[] message = Pca.thresholdMessage(ctx.pcactn);
            if (trustedGroupKey == null) return PcaCore.HookResult.enforced(false, "trusted FROST group key is not a canonical b64u(32) point", null);
            Object sig = null;
            boolean found = false;
            Object th = ctx.pcactn.get("threshold");
            if (th instanceof Map && ((Map<?, ?>) th).get("shares") instanceof List) {
                for (Object s : (List<?>) ((Map<?, ?>) th).get("shares")) {
                    if (s instanceof Map && ((Map<?, ?>) s).get("sig") instanceof String && trustedGroupKey.equals(((Map<?, ?>) s).get("publicKey"))) { sig = ((Map<?, ?>) s).get("sig"); found = true; break; }
                }
            }
            if (!found) return PcaCore.HookResult.enforced(false, "no FROST aggregate for the trusted group key in the step-up", null);
            if (!W3Bridge.verifyB64u(trustedGroupKey, message, (String) sig)) {
                return PcaCore.HookResult.enforced(false, "FROST aggregate does not verify under the trusted group key (quorum short or forged)", null);
            }
            Map<String, Object> pq = PqThreshold.verifyPqQuorum(o.pqBlock, message, pool, o.pqT);
            if (o.pqT == null) pq.remove("need");
            if (!Boolean.TRUE.equals(pq.get("ok"))) return PcaCore.HookResult.enforced(false, pq.get("reason") != null ? (String) pq.get("reason") : "post-quantum quorum short", null);
            return PcaCore.HookResult.enforced(true);
        };
    }

    /** Options of {@link #verifyHybridStepUp}; {@code t} is the step-up tier (the classical threshold). */
    public static final class StepUpVerifyOpts {
        public Map<String, Object> grant;
        public Object groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities;
        public String signerSetCommitment;
        /** Audience: {@link #audience(String)} (must equal), {@link #audienceAny()} (explicit opt-out), or unset (fails when the PCActn carries an aud). */
        public String audience;
        public boolean audienceGiven;
        public Long nowEpoch;
        public StepUpVerifyOpts audience(String a) { this.audience = a; this.audienceGiven = true; return this; }
        public StepUpVerifyOpts audienceAny() { this.audience = null; this.audienceGiven = true; return this; }
    }

    public static final class StepUpResult {
        public final boolean allow;
        /** The full PCActn verification (wire, audience, validity, chain, leaf signature, counter, threshold hook). */
        public final PcaCore.Result core;
        /** The post-quantum quorum verdict, also computed standalone for the audit surface. */
        public final Map<String, Object> pq;
        public final String reason;
        StepUpResult(boolean allow, PcaCore.Result core, Map<String, Object> pq, String reason) { this.allow = allow; this.core = core; this.pq = pq; this.reason = reason; }
    }

    /** Verify a folded hybrid step-up end to end: the whole PCActn must verify AND both the FROST threshold and the ML-DSA quorum must hold. */
    public static StepUpResult verifyHybridStepUp(StepUp stepUp, StepUpVerifyOpts opts) {
        if (!(opts.pqPublicKeys instanceof List)) throw new IllegalArgumentException("pqPublicKeys is not iterable");
        Set<String> pool = PqThreshold.normalizePqQuorumPool((List<?>) opts.pqPublicKeys);
        Map<String, Object> pq = PqThreshold.verifyPqQuorum(stepUp.pq, Pca.thresholdMessage(stepUp.pcactn), pool, opts.pqT);
        if (opts.pqT == null) pq.remove("need");
        VerifierOpts v = new VerifierOpts();
        v.groupKey = opts.groupKey; v.pqPublicKeys = opts.pqPublicKeys; v.t = opts.t; v.pqT = opts.pqT; v.pqBlock = stepUp.pq;
        v.groupDescriptor = opts.groupDescriptor; v.trustedAuthorities = opts.trustedAuthorities; v.signerSetCommitment = opts.signerSetCommitment;
        PcaCore.Options o = new PcaCore.Options(opts.grant);
        o.planRoots = Pca.PlanRoots.SKIP;
        if (opts.audienceGiven) { if (opts.audience == null) o.audienceAny(); else o.audience(opts.audience); }
        o.nowEpoch = opts.nowEpoch;
        PcaCore.Hooks h = new PcaCore.Hooks();
        h.threshold = createHybridThresholdVerifier(v);
        o.hooks = h;
        PcaCore.Result core = PcaCore.verify(stepUp.pcactn, o);
        return new StepUpResult(core.allow, core, pq, core.allow ? null : core.reason);
    }
}
