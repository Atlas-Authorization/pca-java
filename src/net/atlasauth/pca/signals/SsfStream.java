package net.atlasauth.pca.signals;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.revoke.JsVal;

/**
 * SSF stream health: configuration, status, verification events and poll / push delivery bookkeeping, plus the CAEP events PCA
 * emits from its decision log. A pushed revocation is only a guarantee if you know the stream is alive: a receiver that has not
 * seen a verified round trip recently cannot claim "no revocation was missed", and {@link StreamHealth#revocationFreshWithin}
 * turns that into one boolean the verifier combines with the signed revocation epoch (pull bound). Unhealthy means escalate,
 * never allow. Sources: OpenID SSF 1.0 sections 6.1, 7.1, 8.1.1, 8.1.2, 8.1.4, RFC 8935 (push), RFC 8936 (poll), OpenID CAEP 1.0.
 */
public final class SsfStream {
    private SsfStream() {}

    public static final String DELIVERY_PUSH = "urn:ietf:rfc:8935";
    public static final String DELIVERY_POLL = "urn:ietf:rfc:8936";
    public static final List<String> STREAM_STATUSES = java.util.Collections.unmodifiableList(java.util.Arrays.asList("enabled", "paused", "disabled")); // contains(null) is false, not an exception

    static boolean httpsUrl(Object u) {
        if (!(u instanceof String)) return false;
        String s = (String) u;
        if (!s.startsWith("https://") || s.length() == 8) return false;
        for (int i = 8; i < s.length(); i++) if (JsVal.isSpace(s.charAt(i))) return false;
        return true;
    }

    private static boolean strs(Object x) {
        if (!(x instanceof List)) return false;
        for (Object e : (List<?>) x) if (!JsVal.nonEmpty(e)) return false;
        return true;
    }

    private static boolean nonNegSafeInt(Object v) {
        Double d = JsVal.num(v);
        return JsVal.isSafeInteger(v) && d >= 0 && !(d == 0.0 && Double.doubleToRawLongBits(d) != 0L);
    }

    /** SSF 8.1.1 shape checks. Returns the problems found (empty = valid). */
    public static List<String> validateStreamConfig(Object c) {
        List<String> e = new ArrayList<>();
        if (!(c instanceof Map)) { e.add("not an object"); return e; }
        Map<?, ?> o = (Map<?, ?>) c;
        if (!JsVal.nonEmpty(o.get("stream_id"))) e.add("stream_id is required");
        if (!JsVal.nonEmpty(o.get("iss"))) e.add("iss is required");
        Object aud = o.get("aud");
        if (!(JsVal.nonEmpty(aud) || (aud instanceof List && !((List<?>) aud).isEmpty() && strs(aud)))) e.add("aud must be a non-empty string or array");
        Object delivered = o.get("events_delivered"), supported = o.get("events_supported");
        if (!strs(delivered) || ((List<?>) delivered).isEmpty()) e.add("events_delivered must be a non-empty array of event type URIs");
        if (o.containsKey("events_supported") && !strs(supported)) e.add("events_supported must be an array of URIs");
        if (o.containsKey("events_requested") && (!strs(o.get("events_requested")) || ((List<?>) o.get("events_requested")).isEmpty())) e.add("events_requested must be a non-empty array of URIs");
        if (strs(delivered) && strs(supported)) {
            boolean subset = true;
            for (Object x : (List<?>) delivered) if (!((List<?>) supported).contains(x)) subset = false;
            if (!subset) e.add("events_delivered must be a subset of events_supported");
        }
        Object d = o.get("delivery");
        Object method = JsVal.opt(d, "method");
        if (!JsVal.truthy(d) || (!DELIVERY_PUSH.equals(method) && !DELIVERY_POLL.equals(method))) e.add("delivery.method must be the RFC 8935 or RFC 8936 URI");
        else if (!httpsUrl(JsVal.opt(d, "endpoint_url"))) e.add("delivery.endpoint_url must be an https URL");
        if (o.containsKey("min_verification_interval") && !nonNegSafeInt(o.get("min_verification_interval"))) e.add("min_verification_interval must be a non-negative integer (seconds)");
        return e;
    }

    private static String fmt(double d) { return JsVal.str(JsVal.numOf(d)); }

    /**
     * Receiver-side health of one stream. All times are epoch SECONDS passed in (no hidden clock). A verification state is
     * single-use, expiring, and only valid if THIS tracker issued it. States: healthy, degraded, failing, paused, disabled, unverified.
     */
    public static final class StreamHealth {
        public final Map<String, Object> config;
        private final Map<String, Object> o;
        private String status = "enabled";
        private Double lastEvent, lastVerified, lastRequested;
        private double fails = 0, rejected = 0;
        private final Map<String, Double> pending = new LinkedHashMap<>();
        private static final SecureRandom RNG = new SecureRandom();

        /** config is the stream configuration; opts (may be null): verifyTimeoutSec (60), verifiedWithinSec (300), failAfter (3), maxPending (16). */
        public StreamHealth(Map<String, Object> config, Map<String, Object> opts) {
            this.config = config;
            this.o = opts == null ? new LinkedHashMap<>() : opts;
        }

        private double opt(String k, double dflt) {
            Object v = o.get(k);
            return v == null ? dflt : JsVal.num(v);
        }

        public synchronized void setStatus(Object s) {
            if (!STREAM_STATUSES.contains(s)) throw new IllegalArgumentException("unknown stream status");
            status = (String) s;
        }

        /** Any valid SET arrived on this stream. */
        public synchronized void recordEvent(double nowSec) { lastEvent = Math.max(lastEvent == null ? 0 : lastEvent, nowSec); }

        /**
         * Start a verification: returns the state to send to the transmitter's verification endpoint, or null when the transmitter's
         * min_verification_interval has not elapsed (SSF: it would answer 429), the stream is not enabled, or too many are outstanding.
         */
        public synchronized String requestVerification(double nowSec) {
            if (!status.equals("enabled")) return null;
            if (!Double.isFinite(nowSec)) return null;
            Object minO = config.get("min_verification_interval");
            double min = minO == null ? 0 : JsVal.num(minO);
            if (lastRequested != null && !(nowSec - lastRequested >= min)) return null;
            expire(nowSec);
            if (!(pending.size() < opt("maxPending", 16))) return null;
            double timeoutAt = nowSec + opt("verifyTimeoutSec", 60);
            if (!Double.isFinite(timeoutAt)) return null; // a NaN or infinite timeout would leave the request pending forever
            byte[] b = new byte[16];
            RNG.nextBytes(b);
            String state = Keys.b64u(b);
            pending.put(state, timeoutAt);
            lastRequested = nowSec;
            return state;
        }

        /** A verification SET came back carrying state. True iff it matches an outstanding, unexpired request (single use). */
        public synchronized boolean ackVerification(Object state, double nowSec) {
            if (!Double.isFinite(nowSec)) { rejected++; return false; }
            expire(nowSec);
            Double exp = state instanceof String ? pending.get(state) : null;
            if (exp == null) {
                rejected++;
                return false;
            }
            pending.remove(state);
            lastVerified = nowSec;
            lastEvent = Math.max(lastEvent == null ? 0 : lastEvent, nowSec);
            fails = 0;
            return true;
        }

        private void expire(double nowSec) {
            for (java.util.Iterator<Map.Entry<String, Double>> it = pending.entrySet().iterator(); it.hasNext();) {
                if (nowSec > it.next().getValue()) { it.remove(); fails++; }
            }
        }

        public synchronized Map<String, Object> report(double nowSec) {
            expire(nowSec);
            List<Object> reasons = new ArrayList<>();
            double within = opt("verifiedWithinSec", 300);
            String state;
            if (status.equals("disabled")) { state = "disabled"; reasons.add("stream is disabled: no events are transmitted or held"); }
            else if (status.equals("paused")) { state = "paused"; reasons.add("stream is paused: events may be delayed"); }
            else if (!(fails < opt("failAfter", 3))) { state = "failing"; reasons.add(fmt(fails) + " consecutive verification requests timed out"); }
            else if (lastVerified == null) { state = "unverified"; reasons.add("no verification round trip has completed"); }
            else if (!(Double.isFinite(nowSec) && nowSec - lastVerified <= within)) { state = "degraded"; reasons.add("last verified " + fmt(nowSec - lastVerified) + "s ago, over " + fmt(within) + "s"); }
            else state = "healthy";
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("state", state);
            r.put("status", status);
            r.put("reasons", reasons);
            r.put("pending_verifications", JsVal.numOf(pending.size()));
            r.put("consecutive_verification_failures", JsVal.numOf(fails));
            r.put("rejected_verifications", JsVal.numOf(rejected));
            if (lastEvent != null) r.put("last_event_at", JsVal.numOf(lastEvent));
            if (lastVerified != null) r.put("last_verified_at", JsVal.numOf(lastVerified));
            return r;
        }

        /**
         * May the verifier assume no pushed revocation was missed in the last maxAgeSec? Only if the stream is enabled and a verified
         * round trip completed inside that window. Otherwise fall back to the signed epoch pull bound.
         */
        public synchronized boolean revocationFreshWithin(double maxAgeSec, double nowSec) {
            return status.equals("enabled") && lastVerified != null && Double.isFinite(nowSec) && nowSec - lastVerified <= maxAgeSec;
        }
    }

    // ---- transmitter side ----

    /** The outcome of {@link #handleVerificationRequest}: status 204 with the signed verification SET, or an error status and text. */
    public static final class VerificationOutcome {
        public final int status;
        public final String set;
        public final String error;
        VerificationOutcome(int status, String set, String error) { this.status = status; this.set = set; this.error = error; }
    }

    /**
     * SSF 8.1.4.2: handle a verification request for a stream. 404 unknown stream, 400 malformed, 429 inside the stream's
     * min_verification_interval; otherwise 204 plus the signed verification SET to deliver on the stream. streams maps stream id to a
     * record {config, lastVerification?} that is updated in place; key is a private Ed25519 JWK.
     */
    public static VerificationOutcome handleVerificationRequest(Map<String, Map<String, Object>> streams, Object req, double nowSec, Map<String, Object> key) {
        if (!(req instanceof Map) || !(((Map<?, ?>) req).get("stream_id") instanceof String)
            || (((Map<?, ?>) req).containsKey("state") && !(((Map<?, ?>) req).get("state") instanceof String))) {
            return new VerificationOutcome(400, null, "stream_id (string) is required; state must be a string");
        }
        Map<?, ?> r = (Map<?, ?>) req;
        Map<String, Object> s = streams.get(r.get("stream_id"));
        if (s == null) return new VerificationOutcome(404, null, "no such stream");
        Object cfg = s.get("config");
        Object minO = JsVal.member(cfg, "min_verification_interval");
        double min = minO == null ? 0 : JsVal.num(minO);
        Object last = s.get("lastVerification");
        if (!Double.isFinite(nowSec) || (last != null && !(nowSec - JsVal.num(last) >= min))) return new VerificationOutcome(429, null, "verification requested too soon");
        s.put("lastVerification", JsVal.numOf(nowSec));
        Map<String, Object> ev = new LinkedHashMap<>();
        if (r.containsKey("state")) ev.put("state", r.get("state"));
        Map<String, Object> events = new LinkedHashMap<>();
        events.put(Signals.VERIFICATION, ev);
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("events", events);
        JsVal.member(cfg, "iss");
        if (JsVal.has(cfg, "iss")) args.put("issuer", ((Map<?, ?>) cfg).get("iss"));
        if (JsVal.has(cfg, "aud")) args.put("audience", ((Map<?, ?>) cfg).get("aud"));
        if (JsVal.has(cfg, "stream_id")) args.put("subject", ((Map<?, ?>) cfg).get("stream_id"));
        args.put("key", key);
        return new VerificationOutcome(204, Signals.buildSET(args), null);
    }

    /** RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors. */
    public static final class PollQueue {
        private final Map<String, String> q = new LinkedHashMap<>();
        /** Receiver errors recorded by {@link #poll}: {jti, err, description}. */
        public final List<Map<String, Object>> errors = new ArrayList<>();

        public synchronized void enqueue(String jti, String set) { q.put(jti, set); }

        public synchronized int depth() { return q.size(); }

        /**
         * One RFC 8936 poll. req: {maxEvents?, returnImmediately?, ack?: [jti], setErrs?: {jti: {err, description}}}. Returns
         * {sets: {jti: set}, moreAvailable?: true}. Throws on a maxEvents that is not a non-negative integer.
         */
        public synchronized Map<String, Object> poll(Object req) {
            Object maxO = JsVal.member(req, "maxEvents"); // a null req throws, as reading its members does
            if (JsVal.has(req, "maxEvents") && !nonNegSafeInt(maxO)) throw new IllegalArgumentException("maxEvents must be a non-negative integer");
            Object ack = JsVal.opt(req, "ack");
            if (ack != null) {
                if (!(ack instanceof List)) throw new JsVal.TypeError("ack must be a list of jti strings");
                for (Object j : (List<?>) ack) q.remove(j);
            }
            // An errored SET is released too: retransmitting a SET the receiver found invalid cannot help.
            Object errs = JsVal.opt(req, "setErrs");
            if (errs instanceof Map) {
                for (Map.Entry<?, ?> en : ((Map<?, ?>) errs).entrySet()) {
                    if (q.remove(en.getKey()) != null) {
                        Object why = en.getValue();
                        Map<String, Object> rec = new LinkedHashMap<>();
                        rec.put("jti", en.getKey());
                        Object e1 = JsVal.member(why, "err"), e2 = JsVal.member(why, "description");
                        if (JsVal.has(why, "err")) rec.put("err", e1);
                        if (JsVal.has(why, "description")) rec.put("description", e2);
                        errors.add(rec);
                    }
                }
            }
            double max = maxO != null ? JsVal.num(maxO) : Double.POSITIVE_INFINITY;
            Map<String, Object> sets = new LinkedHashMap<>();
            int n = 0;
            for (Map.Entry<String, String> e : q.entrySet()) {
                if (n >= max) break;
                sets.put(e.getKey(), e.getValue());
                n++;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("sets", sets);
            if (q.size() > n) out.put("moreAvailable", true);
            return out;
        }
    }

    /** RFC 8935 receiver status for a receiveSET outcome ({ok} or {ok: false, code, reason}): {status: 202}, or {status: 400, body: {err, description}}. */
    public static Map<String, Object> pushResponse(Object r) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (JsVal.truthy(JsVal.member(r, "ok"))) {
            out.put("status", new Json.Num("202"));
            return out;
        }
        Object code = JsVal.opt(r, "code");
        String err = "verify_failed".equals(code) ? "invalid_key"
            : "malformed".equals(code) || "oversize".equals(code) ? "invalid_request"
            : "misconfigured".equals(code) || "replay_store_error".equals(code) ? "access_denied" : "invalid_request";
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("err", err);
        if (JsVal.has(r, "reason")) body.put("description", ((Map<?, ?>) r).get("reason"));
        out.put("status", new Json.Num("400"));
        out.put("body", body);
        return out;
    }

    // ---- CAEP events from the decision log ----

    private static String eventSet(Map<String, Object> a, String type, Object event) {
        Map<String, Object> events = new LinkedHashMap<>();
        events.put(type, event);
        Map<String, Object> args = new LinkedHashMap<>();
        if (JsVal.has(a, "issuer")) args.put("issuer", a.get("issuer"));
        if (JsVal.has(a, "audience")) args.put("audience", a.get("audience"));
        args.put("key", a.get("key"));
        args.put("events", events);
        return Signals.buildSET(args);
    }

    /** Emit risk-level-change (from the behavioural immune system). a: {issuer, audience, key, event}. */
    public static String riskLevelChangeSET(Map<String, Object> a) { return eventSet(a, Signals.RISK_LEVEL_CHANGE, JsVal.member(a, "event")); }

    /** Emit assurance-level-change (from a discharge change); change_direction is derived when both levels are in a.order. a: {issuer, audience, key, event, order?}. */
    @SuppressWarnings("unchecked")
    public static String assuranceLevelChangeSET(Map<String, Object> a) {
        Object ev = JsVal.member(a, "event");
        Map<String, Object> e = ev instanceof Map ? new LinkedHashMap<>((Map<String, Object>) ev) : new LinkedHashMap<>();
        Object order = a.get("order");
        if (e.containsKey("previous_level") && !e.containsKey("change_direction") && JsVal.truthy(order)) {
            if (!(order instanceof List)) throw new JsVal.TypeError("order must be a list");
            int i = ((List<?>) order).indexOf(e.get("previous_level")), j = ((List<?>) order).indexOf(e.get("current_level"));
            if (i >= 0 && j >= 0 && i != j) e.put("change_direction", j > i ? "increase" : "decrease");
        }
        return eventSet(a, Signals.ASSURANCE_LEVEL_CHANGE, e);
    }
}
