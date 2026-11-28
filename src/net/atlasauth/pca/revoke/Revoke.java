package net.atlasauth.pca.revoke;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Realtime revocation and a mid-run kill-switch for Proof-Carrying Authority, layered on the core verifier.
 * {@link #checkRevocation} walks every hop of a PCActn's cap_chain against a {@link RevocationRegistry};
 * {@link #verifyWithRevocation} ANDs the core outcome with that gate and fails closed; {@link #ingestCaepEvent} bridges a
 * Shared-Signals / CAEP revocation event into registry entries. PCActns and results are JSON objects (Map).
 */
public final class Revoke {
    private Revoke() {}

    /** CAEP 1.0 section 3.4: a session for the subject was revoked. */
    public static final String SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    /** PCA: a single grant (by grant_ref, the root grant's cap id) is revoked. */
    public static final String GRANT_REVOKED = "https://atlasauth.net/caep/grant-revoked";
    /** PCA: a mid-run kill-switch that revokes every grant the named agent holds. */
    public static final String KILL_SWITCH = "https://atlasauth.net/caep/kill-switch";

    /** The outcome of a revocation check; matched and reason are set only when revoked. */
    public static final class IsRevokedResult {
        public final boolean revoked;
        public final RevocationEntry matched;
        public final String reason;

        public IsRevokedResult(boolean revoked, RevocationEntry matched, String reason) {
            this.revoked = revoked;
            this.matched = matched;
            this.reason = reason;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("revoked", revoked);
            if (matched != null) m.put("matched", matched.toMap());
            if (reason != null) m.put("reason", reason);
            return m;
        }
    }

    /** The combined core-verify and revocation-gate outcome. */
    public static final class VerifyWithRevocationResult {
        /** True only when the core verified and nothing in the chain is revoked. */
        public final boolean allow;
        public final boolean coreAllow;
        public final IsRevokedResult revocation;
        /** Why the action was denied (the core's reason, or the revocation reason); null when allowed. */
        public final Object reason;

        public VerifyWithRevocationResult(boolean allow, boolean coreAllow, IsRevokedResult revocation, Object reason) {
            this.allow = allow;
            this.coreAllow = coreAllow;
            this.revocation = revocation;
            this.reason = reason;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", allow);
            m.put("coreAllow", coreAllow);
            m.put("revocation", revocation.toMap());
            if (!allow) m.put("reason", reason);
            return m;
        }
    }

    /** True when a revocation is in effect at now (a future notBefore has not yet been reached). Non-finite clocks bite. */
    public static boolean isActiveAt(RevocationEntry entry, double now) {
        if (entry.notBefore == null) return true;
        if (Double.isNaN(now) || Double.isInfinite(now) || Double.isNaN(entry.notBefore) || Double.isInfinite(entry.notBefore)) return true;
        return now >= entry.notBefore;
    }

    private static String matchReason(RevocationEntry e) {
        String base = e.kind + " " + e.value + " is revoked";
        return e.reason.length() > 0 ? base + ": " + e.reason : base;
    }

    private static boolean startsWith(List<String> ids, List<String> prefix) {
        if (prefix.isEmpty() || ids.size() < prefix.size()) return false;
        for (int i = 0; i < prefix.size(); i++) if (!ids.get(i).equals(prefix.get(i))) return false;
        return true;
    }

    private static IsRevokedResult closed(String why) { return new IsRevokedResult(true, null, "revocation check failed closed: " + why); }

    private static IsRevokedResult scan(List<?> chain, RevocationRegistry registry, double now) {
        List<String> ids = new ArrayList<>();
        String[] kinds = {"cap", "issuer", "holder"};
        for (Object hop : chain) {
            Map<?, ?> h = (Map<?, ?>) hop;
            Object[] keys = {h.get("id"), h.get("issuer"), h.get("holder")};
            for (int i = 0; i < 3; i++) {
                if (!JsVal.nonEmpty(keys[i])) continue;
                RevocationEntry e = registry.lookup(kinds[i], (String) keys[i]);
                if (e != null && isActiveAt(e, now)) return new IsRevokedResult(true, e, matchReason(e));
            }
            if (h.get("id") instanceof String) ids.add((String) h.get("id"));
        }
        for (RevocationEntry e : registry.prefixes()) {
            if (e.prefix != null && startsWith(ids, e.prefix) && isActiveAt(e, now)) return new IsRevokedResult(true, e, matchReason(e));
        }
        return new IsRevokedResult(false, null, null);
    }

    /**
     * Is any authority in this PCActn's cap_chain revoked at opts.now (default: the clock)? Never throws and never reports
     * "not revoked" because it could not look: a missing or malformed PCActn / cap_chain, a hop whose id, issuer or holder is
     * not a non-empty string, a non-finite now, or a store that throws all yield revoked with a reason that starts
     * "revocation check failed closed". Use this wherever the answer gates an action.
     */
    public static IsRevokedResult checkRevocation(Object p, RevocationRegistry registry, Map<String, Object> opts) {
        Object nowO = opts == null ? null : opts.get("now");
        double now;
        if (nowO == null) now = (double) System.currentTimeMillis();
        else if (!JsVal.isFinite(nowO)) return closed("clock is not a finite number");
        else now = JsVal.num(nowO);
        Object chain = JsVal.opt(p, "cap_chain");
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return closed("the action carries no capability chain");
        for (Object hop : (List<?>) chain) {
            for (String k : new String[] {"id", "issuer", "holder"}) {
                if (!JsVal.nonEmpty(JsVal.opt(hop, k))) return closed("a chain hop has no " + k);
            }
        }
        try {
            return scan((List<?>) chain, registry, now);
        } catch (RuntimeException e) {
            return closed("the revocation store failed (" + (e instanceof JsVal.TypeError ? "TypeError" : "Error") + ")");
        }
    }

    /**
     * Combine the core verify outcome with the revocation gate. Allow only if the core verified and nothing in the chain is
     * revoked; a core result that did not allow denies regardless of the registry, and any match denies regardless of the core.
     */
    public static VerifyWithRevocationResult verifyWithRevocation(Object p, Object coreVerifyResult, RevocationRegistry registry, Map<String, Object> opts) {
        boolean coreAllow = coreVerifyResult instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) coreVerifyResult).get("allow"));
        IsRevokedResult revocation = checkRevocation(p, registry, opts);
        boolean allow = coreAllow && !revocation.revoked;
        if (allow) return new VerifyWithRevocationResult(true, coreAllow, revocation, null);
        Object reason = !coreAllow ? JsVal.or(JsVal.opt(coreVerifyResult, "reason"), "core verification failed") : JsVal.or(revocation.reason, "revoked");
        return new VerifyWithRevocationResult(false, coreAllow, revocation, reason);
    }

    private static double revokedAtFrom(Object ts, RevocationRegistry registry) {
        return JsVal.isFinite(ts) ? JsVal.round(JsVal.num(ts) * 1000) : registry.nowMs();
    }

    private static String stringField(Object ev, Object subject, String key) {
        if (!JsVal.has(ev, "subject")) return null;
        Object v = JsVal.member(subject, key);
        return JsVal.nonEmpty(v) ? (String) v : null;
    }

    private static Map<String, Object> cap(Object value, Object reason, double revokedAt) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", "cap");
        m.put("value", value);
        m.put("reason", reason);
        m.put("revokedAt", JsVal.numOf(revokedAt));
        return m;
    }

    private static Map<String, Object> at(Object reason, double revokedAt) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("reason", reason);
        m.put("revokedAt", JsVal.numOf(revokedAt));
        return m;
    }

    /**
     * Bridge a CAEP / PCA revocation event ({type, payload}) into registry entries; returns the entries added.
     * grant-revoked revokes the grant's cap id (the whole subtree under it); kill-switch kills the agent's holder key (and
     * the named grant_ref too); any other type is read as session-revoked: when the subject carries a holder / agent / id
     * key, that agent is killed.
     */
    public static List<RevocationEntry> ingestCaepEvent(Object event, RevocationRegistry registry) {
        List<RevocationEntry> added = new ArrayList<>();
        Object type = JsVal.member(event, "type");
        Object ev = JsVal.member(event, "payload");
        if (GRANT_REVOKED.equals(type)) {
            Object ref = JsVal.member(ev, "grant_ref");
            if (JsVal.nonEmpty(ref)) {
                added.add(registry.revoke(cap(ref, JsVal.or(JsVal.opt(ev, "reason"), "CAEP grant-revoked"), revokedAtFrom(JsVal.opt(ev, "event_timestamp"), registry))));
            }
        } else if (KILL_SWITCH.equals(type)) {
            double revokedAt = revokedAtFrom(JsVal.member(ev, "event_timestamp"), registry);
            Object agent = JsVal.opt(ev, "agent");
            Object reason = JsVal.or(JsVal.opt(ev, "reason"), "CAEP kill-switch");
            if (JsVal.nonEmpty(agent)) added.add(registry.killAgent(agent, at(reason, revokedAt)));
            Object ref = JsVal.opt(ev, "grant_ref");
            if (JsVal.nonEmpty(ref)) added.add(registry.revoke(cap(ref, reason, revokedAt)));
        } else {
            Object subject = JsVal.member(ev, "subject");
            String holder = stringField(ev, subject, "holder");
            if (holder == null) holder = stringField(ev, subject, "agent");
            if (holder == null) holder = stringField(ev, subject, "id");
            if (holder != null) {
                added.add(registry.killAgent(holder, at(JsVal.or(JsVal.or(JsVal.opt(ev, "reason_admin"), JsVal.opt(ev, "reason_user")), "CAEP session-revoked"), revokedAtFrom(JsVal.opt(ev, "event_timestamp"), registry))));
            }
        }
        return added;
    }
}
