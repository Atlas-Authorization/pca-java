package net.atlasauth.pca;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Verifier-side revocation staleness (T9): the TypeScript {@code RevocationStalenessPolicy}, {@code checkRevocationAge},
 * {@code checkRevocationEpoch} and the staleness branch of {@code createRevocationChecker}. The signer chooses an epoch's
 * {@code not_after}; this lets the VERIFIER cap how old ({@code now - issued_at}) the revocation state may be, with a stricter
 * window for actions that cannot be undone. The class of an action is the stricter of the server's authoritative class and the
 * PCActn's signed {@code reversibility_class}; a missing or unknown class counts as irreversible (fail closed).
 *
 * <p>Off unless a policy is given ({@link Authorize.Input#revocationStaleness}). Nothing here throws at request time.
 */
public final class RevocationStaleness {
    public static final long REVOCATION_EPOCH_REFRESH_MS = 60_000L;
    public static final long REVOCATION_EPOCH_VALIDITY_MS = 5 * 60_000L;
    /** Default window of an irreversible action: two refresh periods. */
    public static final long REVOCATION_IRREVERSIBLE_MAX_AGE_MS = 2 * REVOCATION_EPOCH_REFRESH_MS;
    /** How far ahead of the verifier's clock an issue time may be. */
    public static final long SKEW_MS = 60_000L;

    private static final String NOT_PINNED = "revocation epoch not signed by the pinned guardian";

    /** Maximum age for any action (null: {@link #REVOCATION_EPOCH_VALIDITY_MS}). */
    public final Double maxRevocationAgeMs;
    /** Window of an irreversible action (null: {@link #REVOCATION_IRREVERSIBLE_MAX_AGE_MS}), capped by the maximum. */
    public final Double irreversibleMs;
    /** Window of a costly action (null: the maximum), capped by the maximum. */
    public final Double costlyMs;
    private final boolean stalenessSet;
    /** Accept state that is not guardian-signed (a bare root) for an irreversible action. */
    public final boolean allowUnsignedRootForIrreversible;
    /** The pinned guardian key (base64url) a signed epoch must verify under. */
    public final String guardianPublic;
    /** PQ-key pins {@code identity -> pq_pk} for a PQ / hybrid epoch (null: none, so only ed25519 epochs verify). */
    public final Map<String, Object> pqPins;
    /** {@code (epoch, pcactn)}: called after an admitted action whose epoch passed every check (persist it as the new last accepted epoch). */
    public final BiConsumer<Map<String, Object>, Map<String, Object>> onEpochAccepted;

    /** An empty policy: the 5 minute maximum, 2 minutes for an irreversible action. */
    /**
     * {@code pcactn -> capability ids} that need a non-membership proof (null: every {@code id} in the PCActn's cap_chain, so a
     * revoked ancestor kills its descendants). Return an empty list to check freshness only.
     */
    public final Function<Map<String, Object>, List<String>> ids;
    /**
     * {@code (capabilityId, pcactn) -> non-membership proof} ({@code {size, lo?, hi?}}). Null, or a null answer, DENIES (fail
     * closed).
     */
    public final BiFunction<String, Map<String, Object>, Map<String, Object>> proofs;

    public RevocationStaleness() { this(null, null, null, false, false, null, null, null, null, null); }

    private RevocationStaleness(Double max, Double irreversible, Double costly, boolean stalenessSet, boolean allowUnsigned,
                                String guardianPublic, Map<String, Object> pqPins, BiConsumer<Map<String, Object>, Map<String, Object>> onAccepted,
                                Function<Map<String, Object>, List<String>> ids, BiFunction<String, Map<String, Object>, Map<String, Object>> proofs) {
        positive("maxRevocationAgeMs", max);
        positive("staleness.irreversible", irreversible);
        positive("staleness.costly", costly);
        this.maxRevocationAgeMs = max;
        this.irreversibleMs = irreversible;
        this.costlyMs = costly;
        this.stalenessSet = stalenessSet || irreversible != null || costly != null;
        this.allowUnsignedRootForIrreversible = allowUnsigned;
        this.guardianPublic = guardianPublic;
        this.pqPins = pqPins;
        this.onEpochAccepted = onAccepted;
        this.ids = ids;
        this.proofs = proofs;
    }

    /** A malformed window is a configuration error, raised at construction and never at request time. */
    private static void positive(String name, Double v) {
        if (v != null && !(v > 0 && !Double.isInfinite(v)))
            throw new IllegalArgumentException(name + " must be a positive number of milliseconds");
    }

    public RevocationStaleness maxRevocationAgeMs(double ms) {
        return new RevocationStaleness(ms, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardianPublic, pqPins, onEpochAccepted, ids, proofs);
    }
    /** Per-class windows (null: the default), each capped by the maximum. Setting either turns the policy on. */
    public RevocationStaleness staleness(Double irreversible, Double costly) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversible, costly, true, allowUnsignedRootForIrreversible, guardianPublic, pqPins, onEpochAccepted, ids, proofs);
    }
    public RevocationStaleness allowUnsignedRootForIrreversible(boolean allow) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allow, guardianPublic, pqPins, onEpochAccepted, ids, proofs);
    }
    public RevocationStaleness guardianPublic(String guardian) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardian, pqPins, onEpochAccepted, ids, proofs);
    }
    public RevocationStaleness pqPins(Map<String, Object> pins) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardianPublic,
            pins == null ? null : new LinkedHashMap<>(pins), onEpochAccepted, ids, proofs);
    }
    public RevocationStaleness onEpochAccepted(BiConsumer<Map<String, Object>, Map<String, Object>> callback) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardianPublic, pqPins, callback, ids, proofs);
    }

    /** A copy that proves these capability ids ({@code pcactn -> ids}) instead of the cap_chain's; an empty list checks freshness only. */
    public RevocationStaleness ids(Function<Map<String, Object>, List<String>> ids) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardianPublic, pqPins, onEpochAccepted, ids, proofs);
    }
    /** A copy with the non-membership proof source {@code (capabilityId, pcactn) -> proof}. */
    public RevocationStaleness proofs(BiFunction<String, Map<String, Object>, Map<String, Object>> proofs) {
        return new RevocationStaleness(maxRevocationAgeMs, irreversibleMs, costlyMs, stalenessSet, allowUnsignedRootForIrreversible, guardianPublic, pqPins, onEpochAccepted, ids, proofs);
    }

    /**
     * verifyNonMembership: true iff {@code proof} ({@code {size, lo?, hi?}} of leaf proofs) shows {@code id} is NOT in the sorted
     * revocation set the size-bound {@code root} commits to. A revoked id has no valid proof. Total.
     */
    public static boolean verifyNonMembership(String root, Map<String, Object> proof, String id) {
        try {
            return root != null && proof != null && id != null && Mesh.nonMembership(root, proof, id);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** True when the policy turns the age check on (the TypeScript {@code stalenessPolicyOn}: any age option set). */
    public boolean isOn() { return maxRevocationAgeMs != null || stalenessSet; }

    /**
     * From the reference's policy object {@code {maxRevocationAgeMs?, staleness?: {irreversible?, costly?},
     * allowUnsignedRootForIrreversible?}} (a {@link Json} tree). A window that is present but not a positive number throws.
     */
    public static RevocationStaleness fromJson(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("revocation staleness policy must be an object");
        Map<?, ?> m = (Map<?, ?>) o;
        Object st = m.get("staleness");
        Map<?, ?> sm = st instanceof Map ? (Map<?, ?>) st : Map.of();
        return new RevocationStaleness(window(m, "maxRevocationAgeMs"), window(sm, "irreversible"), window(sm, sm.containsKey("rate_limited") ? "rate_limited" : "costly"), m.containsKey("staleness"),
            Boolean.TRUE.equals(m.get("allowUnsignedRootForIrreversible")), null, null, null, null, null);
    }

    private static Double window(Map<?, ?> m, String k) {
        if (!m.containsKey(k)) return null;
        Double d = IntentJs.num(m.get(k));
        return d == null ? Double.NaN : d; // NaN fails the positive() test
    }

    // ---- classes ----------------------------------------------------------------------------------------------------

    /** Severity over both vocabularies the verifier sees; an unknown or non-string class is the most restrictive. */
    public static int classRank(Object c) {
        if (!(c instanceof String)) return 2;
        switch ((String) c) {
            case "reversible": return 0;
            case "rate_limited": case "costly": return 1;
            default: return 2;
        }
    }

    /** The stricter of the server's class and the signed one: {@code reversible}, {@code rate_limited} or {@code irreversible}. */
    public static String effectiveReversibility(Object serverClass, Object signedClass) {
        int rank = Math.max(serverClass == null ? 0 : classRank(serverClass), classRank(signedClass));
        return rank >= 2 ? "irreversible" : rank == 1 ? "rate_limited" : "reversible";
    }

    /** The maximum age of revocation state this policy allows for an action of {@code cls}. */
    public double revocationMaxAgeMs(String cls) {
        double max = maxRevocationAgeMs != null ? maxRevocationAgeMs : (double) REVOCATION_EPOCH_VALIDITY_MS;
        if ("irreversible".equals(cls)) return Math.min(max, irreversibleMs != null ? irreversibleMs : (double) REVOCATION_IRREVERSIBLE_MAX_AGE_MS);
        if ("costly".equals(cls) || "rate_limited".equals(cls)) return Math.min(max, costlyMs != null ? costlyMs : max);
        return max;
    }

    // ---- results ----------------------------------------------------------------------------------------------------

    /** {@code ok}, or {@code reason}. {@code epoch} is the signed epoch that passed every check (the gate only). */
    public static final class Check {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> epoch;
        Check(boolean ok, String reason, Map<String, Object> epoch) { this.ok = ok; this.reason = reason; this.epoch = epoch; }
        static Check pass() { return new Check(true, null, null); }
        static Check bad(String reason) { return new Check(false, reason, null); }
        @Override public String toString() { return ok ? "Check{ok}" : "Check{" + reason + "}"; }
    }

    /** JavaScript {@code String(n)} for the integer case; other values print as their shortest round-trip decimal. */
    static String jsNum(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0.0) return "0";
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new BigDecimal(d).toPlainString();
        return IntentJs.shortest(d);
    }

    /**
     * Age check of revocation state issued (or fetched from a trusted source) at {@code issuedAt} (a number; anything else is
     * an unknown time). An unknown issue time is unverifiable and denies; a time more than 60 s in the future denies (the same
     * skew as the signed epoch check). Never throws.
     */
    public static Check checkRevocationAge(Object issuedAt, double now, double maxAgeMs, String what) {
        Double t = IntentJs.num(issuedAt);
        if (t == null || Double.isNaN(t) || Double.isInfinite(t)) return Check.bad(what + " age is unknown (unverifiable revocation state)");
        if (!(t <= now + SKEW_MS)) return Check.bad(what + " issued in the future");
        if (!(now - t <= maxAgeMs))
            return Check.bad(what + " is " + jsNum(now - t) + " ms old, over the verifier's maximum of " + jsNum(maxAgeMs) + " ms (stale revocation state)");
        return Check.pass();
    }

    /** The inputs of {@link #checkRevocationEpoch}. */
    public static final class EpochOptions {
        /** The pinned guardian key (base64url Ed25519). */
        public String guardianPublic;
        /** Epoch milliseconds (no implicit clock: the caller owns freshness). */
        public double now;
        /** The grant the epoch must be for (null: any). */
        public String grantRef;
        /** The newest epoch already accepted for the grant: an older one is a rollback (null: none). */
        public Double lastAcceptedEpoch;
        /** The epoch the PCActn signed in {@code freshness.epoch}; must be at least the signed epoch (null: not checked). */
        public Double pcactnEpoch;
        /** Verifier-side maximum age ({@code now - issued_at}); null: only the signed {@code not_after} bounds staleness. */
        public Double maxAgeMs;
        /** PQ-key pins for a PQ / hybrid epoch. */
        public Map<String, Object> pqPins;

        public EpochOptions(String guardianPublic, double now) { this.guardianPublic = guardianPublic; this.now = now; }
    }

    /**
     * Verify a signed revocation epoch: the pinned guardian and a suite this build verifies, the shape, the signature over
     * {@code "atlas-pca/revepoch/v1\0" || canonical({instance_id, grant_ref, epoch, set_size, root, issued_at, not_after} +
     * suite fields)} (a PQ / hybrid epoch only under {@code pqPins}), grant binding, {@code now <= not_after}, issue time, the
     * optional age cap, rollback and PCActn freshness. Never throws.
     */
    public static Check checkRevocationEpoch(Object epO, EpochOptions o) {
        try {
            if (!(epO instanceof Map) || o.guardianPublic == null) return Check.bad(NOT_PINNED);
            Map<String, Object> ep = IntentJs.obj(epO);
            Object alg = ep.get("alg");
            boolean algPresent = ep.containsKey("alg");
            if (!o.guardianPublic.equals(ep.get("guardian"))) return Check.bad(NOT_PINNED);
            if (Pq.resolveSigAlg(alg, algPresent) == null) {
                // a registered suite this build cannot verify is refused with its own reason, never accepted
                if (alg instanceof String && Pq.REGISTERED_SUITES.contains(alg)) return Check.bad(Pq.UNSUPPORTED_SUITE + ": " + alg);
                return Check.bad(NOT_PINNED);
            }
            for (String k : new String[] {"epoch", "set_size"}) {
                if (!IntentJs.isSafeInteger(ep.get(k)) || IntentJs.num(ep.get(k)) < 0) return Check.bad("malformed revocation epoch");
            }
            for (String k : new String[] {"issued_at", "not_after"}) {
                if (!IntentJs.isSafeInteger(ep.get(k))) return Check.bad("malformed revocation epoch");
            }
            Map<String, Object> base = Ledger.pick(ep, "instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after");
            if (base == null) return Check.bad("revocation epoch check error");
            // a body the strict canonicalizer refuses (a lone surrogate) throws here: the outer catch answers "check error"
            byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                IntentJs.canonBytes(IntentJs.bindSuiteFields(base, alg, algPresent, ep.get("pq_pk"), ep.containsKey("pq_pk"))));
            if (!IntentJs.verifyPinnedSuite(alg, algPresent, o.guardianPublic, ep.get("pq_pk"), msg, ep.get("sig"), ep.get("pq_sig"), o.pqPins))
                return Check.bad("revocation epoch signature invalid");
            if (o.grantRef != null && !o.grantRef.equals(ep.get("grant_ref"))) return Check.bad("revocation epoch is for a different grant");
            double issued = IntentJs.num(ep.get("issued_at"));
            double epoch = IntentJs.num(ep.get("epoch"));
            if (!(o.now <= IntentJs.num(ep.get("not_after")))) return Check.bad("revocation epoch expired (stale revocation root)");
            if (!(issued <= o.now + SKEW_MS)) return Check.bad("revocation epoch issued in the future");
            if (o.maxAgeMs != null) {
                Check age = checkRevocationAge(ep.get("issued_at"), o.now, o.maxAgeMs, "revocation epoch");
                if (!age.ok) return age;
            }
            if (o.lastAcceptedEpoch != null && epoch < o.lastAcceptedEpoch)
                return Check.bad("revocation epoch " + jsNum(epoch) + " is older than the last accepted " + jsNum(o.lastAcceptedEpoch) + " (rollback)");
            if (o.pcactnEpoch != null && !(o.pcactnEpoch >= epoch))
                return Check.bad("PCActn freshness.epoch " + jsNum(o.pcactnEpoch) + " predates the revocation epoch " + jsNum(epoch));
            return Check.pass();
        } catch (RuntimeException e) {
            return Check.bad("revocation epoch check error");
        }
    }

    // ---- the gate ---------------------------------------------------------------------------------------------------

    /**
     * The revocation state a verification relies on: a guardian-signed epoch ({@link #epoch}), or a bare root that is not
     * signed ({@link #root}), the latter held to the age cap via the time YOUR trusted source issued it.
     */
    public static final class State {
        final boolean signed;
        final Map<String, Object> epoch;
        final String root;
        final Double lastAcceptedEpoch;
        final Object issuedAt;

        private State(boolean signed, Map<String, Object> epoch, String root, Double last, Object issuedAt) {
            this.signed = signed; this.epoch = epoch; this.root = root; this.lastAcceptedEpoch = last; this.issuedAt = issuedAt;
        }

        /** A guardian-signed epoch; {@code root} (may be null) must equal the epoch's; {@code lastAcceptedEpoch} is the rollback pin (may be null). */
        public static State epoch(Map<String, Object> epoch, String root, Long lastAcceptedEpoch) {
            return new State(true, epoch, root, lastAcceptedEpoch == null ? null : (double) lastAcceptedEpoch, null);
        }

        /** A bare root issued at {@code issuedAtMs} by your trusted source (null: unknown, which is denied under a policy). */
        public static State root(String root, Long issuedAtMs) { return new State(false, null, root, null, issuedAtMs); }

        /**
         * From the context member {@code revocation_state}: a {@code State}, or {@code {kind: "epoch", epoch, root?,
         * last_accepted_epoch?}} / {@code {kind: "root", root, issued_at}}. Anything else is no state (null).
         */
        static State of(Object o) {
            if (o instanceof State) return (State) o;
            if (!(o instanceof Map)) return null;
            Map<?, ?> m = (Map<?, ?>) o;
            Object root = m.get("root");
            if ("epoch".equals(m.get("kind")) && m.get("epoch") instanceof Map)
                return new State(true, IntentJs.obj(m.get("epoch")), root instanceof String ? (String) root : null, IntentJs.num(m.get("last_accepted_epoch")), null);
            if ("root".equals(m.get("kind")))
                return new State(false, null, root instanceof String ? (String) root : null, null, m.get("issued_at"));
            return null;
        }
    }

    /**
     * The revocation-state gate (the TypeScript {@code createRevocationChecker} with no capability ids to prove). A signed
     * epoch is verified against {@code guardianPublic} (signature, grant binding, expiry, rollback, the PCActn's
     * {@code freshness.epoch}) and, with a policy, the per-class age cap; a given root must equal the epoch's. A bare root
     * under a policy is refused for an irreversible action (unless allowed) and held to the same cap via its issue time.
     * No state is denied. {@code policy} null (or not {@link #isOn() on}) applies no verifier-side cap. Total.
     *
     * @param signedClass the PCActn's signed {@code reversibility_class}; @param serverClass the authoritative one (may be null)
     * @param pcactnEpoch the PCActn's {@code freshness.epoch} (null: not checked)
     * @param guardianPublic overrides {@code policy.guardianPublic} when non-null
     */
    public static Check checkState(RevocationStaleness policy, State state, double now, String grantRef, Object signedClass,
                                   Object serverClass, Double pcactnEpoch, String guardianPublic) {
        return checkState(policy, state, now, grantRef, signedClass, serverClass, pcactnEpoch, guardianPublic, null, null);
    }

    /**
     * {@link #checkState(RevocationStaleness, State, double, String, Object, Object, Double, String)} then, for each of
     * {@code ids}, a valid non-membership proof from {@code proofs} against the state's root: a missing proof is
     * {@code no non-membership proof for <id>}, a revoked id or invalid proof {@code capability <id> is revoked or proof invalid}.
     * A null {@code proofs} supplies none.
     */
    public static Check checkState(RevocationStaleness policy, State state, double now, String grantRef, Object signedClass,
                                   Object serverClass, Double pcactnEpoch, String guardianPublic, List<String> ids,
                                   Function<String, Map<String, Object>> proofs) {
        try {
            boolean on = policy != null && policy.isOn();
            String cls = on ? effectiveReversibility(serverClass, signedClass) : null;
            Double maxAge = on ? policy.revocationMaxAgeMs(cls) : null;
            String gp = guardianPublic != null ? guardianPublic : policy != null ? policy.guardianPublic : null;
            if (state == null) return Check.bad("no signed revocation epoch");
            String root = state.root;
            Map<String, Object> accepted = null;
            if (state.signed) {
                if (state.epoch == null || gp == null || gp.isEmpty()) return Check.bad("no signed revocation epoch");
                EpochOptions eo = new EpochOptions(gp, now);
                eo.grantRef = grantRef;
                eo.lastAcceptedEpoch = state.lastAcceptedEpoch;
                eo.pcactnEpoch = pcactnEpoch;
                eo.maxAgeMs = maxAge;
                eo.pqPins = policy != null ? policy.pqPins : null;
                Check chk = checkRevocationEpoch(state.epoch, eo);
                if (!chk.ok) return chk;
                Object eroot = state.epoch.get("root");
                if (root != null && !root.equals(eroot)) return Check.bad("revocation root does not match the signed epoch");
                root = eroot instanceof String ? (String) eroot : null;
                accepted = state.epoch;
            } else if (on) {
                if ("irreversible".equals(cls) && !policy.allowUnsignedRootForIrreversible)
                    return Check.bad("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)");
                Check age = checkRevocationAge(state.issuedAt, now, maxAge, "revocation root");
                if (!age.ok) return age;
            }
            if (root == null || root.isEmpty()) return Check.bad("no revocation root");
            if (ids != null) for (String id : ids) {
                Map<String, Object> proof = proofs == null ? null : proofs.apply(id);
                if (proof == null) return Check.bad("no non-membership proof for " + id);
                if (!verifyNonMembership(root, proof, id)) return Check.bad("capability " + id + " is revoked or proof invalid");
            }
            return new Check(true, null, accepted);
        } catch (RuntimeException e) {
            return Check.bad("revocation state check error (fail closed)");
        }
    }
}
