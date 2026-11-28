package net.atlasauth.pca.connect;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.events.Events;

/**
 * One-time-use guard for a signature-verified PCActn (the vault's replay check): the nonce is consumed once under a key that binds the
 * audience, the grant and the leaf holder. Run it only AFTER the PCActn verified, last of the authorization checks. Never throws: a store
 * failure is a denial. Check order follows the formally verified replay decision (no store call before every pre-check passed).
 */
public final class ReplayGuard {
    private ReplayGuard() {}

    static final long MAX_LIFETIME_MS = 3_600_000L;
    static final long MAX_SKEW_MS = 60_000L;
    static final int MAX_REPLAY_COMPONENT_LEN = 512;
    static final int MAX_AUD_LEN = 256;
    static final int MAX_NONCE_LEN = 128;
    static final long MAX_SAFE = 9007199254740991L;
    /**
     * The shortest time a consumed nonce must be retained after it was consumed: the longest action lifetime plus the clock-skew
     * allowance in both directions. A pruning horizon below this can free a still-valid nonce.
     */
    public static final long REPLAY_MIN_RETENTION_MS = MAX_LIFETIME_MS + 2 * MAX_SKEW_MS;

    /** The guard's options. Defaults: skew {@link #MAX_SKEW_MS} (also the ceiling), a nonce required, no counter stream. */
    public static final class Options {
        /** Clock skew tolerated in both directions (ms); a negative or non-finite value means the default, a larger one the ceiling. */
        public Double clockSkewMs;
        /** When true (default) a PCActn without a {@code nonce} is refused; when false the counter alone guards it. */
        public boolean requireNonce = true;
        /** When true the (aud, grant, leaf holder) counter stream is advanced through {@code store.claim} after the nonce. */
        public boolean counters;
    }

    /** The guard's verdict: {@code ok}, else a denial {@code code} (malformed, audience, not_yet_valid, expired, replay, store_unavailable) and a reason. */
    public static final class Verdict {
        public final boolean ok;
        public final String code, reason;
        Verdict(boolean ok, String code, String reason) { this.ok = ok; this.code = code; this.reason = reason; }
        static Verdict deny(String code, String reason) { return new Verdict(false, code, reason); }
    }

    private static int u8len(String s) { return Json.utf8(s).length; }

    private static boolean safeNonNegInt(Object o) {
        if (!Json.isSafeInt(o)) return false;
        if (o instanceof Json.Num && ((Json.Num) o).raw.startsWith("-")) return false; // -0 is not a counter / time
        return Json.asLong(o) >= 0;
    }

    private static boolean wellFormed(String s) { return !s.isEmpty() && !Json.hasLoneSurrogate(s) && u8len(s) <= MAX_REPLAY_COMPONENT_LEN; }

    /** Decide whether {@code p} (a parsed PCActn) may be accepted once, for the verifier audience {@code aud} at {@code now} (epoch ms). */
    public static Verdict guard(StateStore store, Object p, String aud, long now) { return guard(store, p, aud, now, new Options()); }

    /** {@link #guard(StateStore, Object, String, long)} with the guard's options (clock skew, nonce requirement, counter stream). */
    public static Verdict guard(StateStore store, Object p, String aud, long now, Options opts) {
        Options o = opts == null ? new Options() : opts;
        double skew = Math.min(o.clockSkewMs != null && !o.clockSkewMs.isNaN() && !o.clockSkewMs.isInfinite() && o.clockSkewMs >= 0 ? o.clockSkewMs : MAX_SKEW_MS, MAX_SKEW_MS);
        long skewFloor = (long) Math.floor(skew), skewCeil = (long) Math.ceil(skew);
        boolean objectOk = p instanceof Map;
        Map<?, ?> pm = objectOk ? (Map<?, ?>) p : null;
        Object chain = objectOk ? pm.get("cap_chain") : null;
        Object leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? ((List<?>) chain).get(((List<?>) chain).size() - 1) : null;
        boolean leafOk = leaf instanceof Map && ((Map<?, ?>) leaf).get("holder") instanceof String && objectOk && pm.get("grant_ref") instanceof String;
        boolean componentsOk = leafOk && wellFormed((String) pm.get("grant_ref")) && wellFormed((String) ((Map<?, ?>) leaf).get("holder"));
        boolean hasNonce = objectOk && pm.containsKey("nonce");
        Object nonce = hasNonce ? pm.get("nonce") : null;
        boolean nonceOk = hasNonce && nonce instanceof String && !((String) nonce).isEmpty() && u8len((String) nonce) <= MAX_NONCE_LEN && !Json.hasLoneSurrogate((String) nonce);

        boolean nowOk = now >= -MAX_SAFE && now <= MAX_SAFE;
        boolean verifierAudOk = aud != null && !aud.isEmpty() && u8len(aud) <= MAX_AUD_LEN && !Json.hasLoneSurrogate(aud);
        boolean audMatches = objectOk && pm.get("aud") instanceof String && pm.get("aud").equals(aud);
        boolean iatOk = objectOk && safeNonNegInt(pm.get("iat"));
        boolean expOk = objectOk && safeNonNegInt(pm.get("exp"));
        long iat = iatOk ? Json.asLong(pm.get("iat")) : 0, exp = expOk ? Json.asLong(pm.get("exp")) : 0;
        boolean counterOk = objectOk && safeNonNegInt(pm.get("counter"));
        boolean windowOk = iatOk && expOk && exp > iat && exp - iat <= MAX_LIFETIME_MS;

        // formally verified Pre
        if (!nowOk || !verifierAudOk || !objectOk) return Verdict.deny("malformed", !nowOk ? "verifier clock is not an integer epoch-ms" : !verifierAudOk ? "verifier audience is invalid" : "not a PCActn");
        if (!audMatches) return Verdict.deny("audience", "the PCActn is for another audience");
        if (!windowOk) return Verdict.deny("malformed", "iat / exp are not a valid bounded window");
        if (iat > now + skewFloor) return Verdict.deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance");
        if (now > exp) return Verdict.deny("expired", "the PCActn has expired");
        if (!leafOk) return Verdict.deny("malformed", "no leaf holder / grant");
        if (!componentsOk) return Verdict.deny("malformed", "grant / holder is not a bounded string");
        if (!counterOk) return Verdict.deny("malformed", "counter is not a non-negative safe integer");
        // the retention horizon must be representable
        if (exp + skewCeil > MAX_SAFE) return Verdict.deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)");
        long retainUntil = exp + skewCeil; // the whole-millisecond horizon at or above exp + skew: a record is never freed early
        // nonce stage: a present nonce is consumed (malformed = deny); an absent one is refused unless requireNonce is off
        if (hasNonce ? !nonceOk : o.requireNonce) return Verdict.deny("malformed", hasNonce ? "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" : "a nonce is required");
        try {
            String grantRef = (String) pm.get("grant_ref"), holder = (String) ((Map<?, ?>) leaf).get("holder");
            if (hasNonce && !store.consumeOnce(Events.replayKey("pca-nonce/v1", aud, grantRef, holder, (String) nonce), retainUntil, now)) return Verdict.deny("replay", "nonce already consumed");
            if (o.counters) {
                StateStore.ClaimResult c = store.claim(Events.replayKey("pca-counter/v1", aud, grantRef, holder), Json.asLong(pm.get("counter")));
                if (c == null) throw new IllegalStateException("the counter store answered null");
                if (!c.ok) return Verdict.deny("replay", "counter is not greater than the last accepted");
            }
        } catch (RuntimeException e) {
            return Verdict.deny("store_unavailable", "replay store failed closed: " + (e.getMessage() == null ? "error" : e.getMessage()));
        }
        return new Verdict(true, null, null);
    }
}
