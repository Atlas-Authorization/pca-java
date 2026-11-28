package net.atlasauth.pca.events;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Typed step-up lifecycle events and signed webhooks for Proof-Carrying Authority. A step-up ceremony creates a grant, then
 * approves, denies, or lets it expire; this turns those four moments into small content-addressed events you can serialize,
 * HMAC-sign and ship to your own inbox, then verify on the way in. It decides nothing: it is a transport contract (a stable
 * event shape plus a Stripe-style signature so the receiver can tell a real delivery from a forged or replayed one).
 *
 * <p>Events are JSON objects (Map): {id, type, at, grant_ref, action: {verb, resource}, tier, actor?}.
 */
public final class Events {
    private Events() {}

    /** Smallest secret accepted. A short or empty HMAC key makes every signature guessable. */
    public static final int MIN_SECRET_BYTES = 16;
    private static final int MAX_HEADER_CHARS = 2048;
    public static final List<String> EVENT_TYPES = List.of("step_up.created", "step_up.approved", "step_up.denied", "step_up.expired");

    private static final String ID_DOMAIN = "atlas-pca/stepup-event/v1";

    // ---- events ----

    private static Map<String, Object> actionOf(Object action) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("verb", JsVal.has(action, "verb") ? ((Map<?, ?>) action).get("verb") : absent("action.verb"));
        a.put("resource", JsVal.has(action, "resource") ? ((Map<?, ?>) action).get("resource") : absent("action.resource"));
        return a;
    }

    /** A string with no lone UTF-16 surrogate. */
    private static boolean wf(Object x) {
        if (!(x instanceof String)) return false;
        String s = (String) x;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
            else if (Character.isSurrogate(c)) return false;
        }
        return true;
    }

    /** The checks every event passes at build and at serialize time (the reference's checkEventFields): fail closed on anything else. */
    private static void checkEventFields(String who, Object e, boolean withId) {
        if (!(e instanceof Map)) throw new IllegalArgumentException(who + ": not an object");
        Object type = JsVal.opt(e, "type"), tier = JsVal.opt(e, "tier");
        Double t = JsVal.num(tier);
        if (!(type instanceof String) || !EVENT_TYPES.contains(type) || t == null || (t != 2 && t != 3)) throw new IllegalArgumentException(who + ": unknown event type or tier");
        if (JsVal.has(e, "at")) {
            Double at = JsVal.num(JsVal.opt(e, "at"));
            if (at == null || at.isNaN() || at.isInfinite()) throw new IllegalArgumentException(who + ": at must be a finite number");
        }
        if (!wf(JsVal.opt(e, "grant_ref"))) throw new IllegalArgumentException(who + ": grant_ref must be a well-formed string");
        Object a = JsVal.opt(e, "action");
        if (!(a instanceof Map) || !wf(JsVal.opt(a, "verb")) || !wf(JsVal.opt(a, "resource"))) throw new IllegalArgumentException(who + ": action must carry well-formed verb and resource strings");
        if (JsVal.has(e, "actor") && !wf(JsVal.opt(e, "actor"))) throw new IllegalArgumentException(who + ": actor must be a well-formed string");
        if (withId && !wf(JsVal.opt(e, "id"))) throw new IllegalArgumentException(who + ": id must be a well-formed string");
    }

    private static Object absent(String what) { throw new IllegalArgumentException("canonicalize: unsupported type undefined (" + what + ")"); }

    /** base64url(sha256(strictCanonical(fields))), domain-separated so ids never collide across event kinds. */
    private static String eventId(Object type, Object at, Object grantRef, Map<String, Object> action, Object tier, boolean hasActor, Object actor) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", ID_DOMAIN);
        m.put("type", type);
        m.put("at", at);
        m.put("grant_ref", grantRef);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("verb", action.get("verb"));
        a.put("resource", action.get("resource"));
        m.put("action", a);
        m.put("tier", tier);
        if (hasActor) m.put("actor", actor);
        return Pca.hashCanonical(m);
    }

    /**
     * Build a step-up event, filling at (default: the clock, in ms) and deriving a content-addressed id from every other field.
     * Two builds with the same inputs produce the same id. data: {at?, grant_ref, action: {verb, resource}, tier, actor?}; a
     * member that is absent where the reference's canonical form would meet undefined throws.
     */
    public static Map<String, Object> buildStepUpEvent(Object type, Object dataIn) {
        Object data = IntentJs.normalize(dataIn);
        Map<String, Object> checked = new LinkedHashMap<>();
        if (data instanceof Map) for (Map.Entry<?, ?> en : ((Map<?, ?>) data).entrySet()) checked.put((String) en.getKey(), en.getValue());
        checked.put("type", type);
        checkEventFields("buildStepUpEvent", checked, false);
        Object atO = JsVal.or(JsVal.member(data, "at"), new Json.Num(Long.toString(System.currentTimeMillis())));
        Object action = JsVal.member(data, "action");
        JsVal.member(action, "verb"); // a null action throws, as reading its members does
        Map<String, Object> act = actionOf(action);
        Object grantRef = JsVal.has(data, "grant_ref") ? ((Map<?, ?>) data).get("grant_ref") : absent("grant_ref");
        Object tier = JsVal.has(data, "tier") ? ((Map<?, ?>) data).get("tier") : absent("tier");
        boolean hasActor = JsVal.has(data, "actor");
        Object actor = hasActor ? ((Map<?, ?>) data).get("actor") : null;
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("type", type);
        e.put("at", atO);
        e.put("grant_ref", grantRef);
        e.put("action", act);
        e.put("tier", tier);
        if (hasActor) e.put("actor", actor);
        e.put("id", eventId(type, atO, grantRef, act, tier, hasActor, actor));
        return e;
    }

    private static boolean isIndex(String k) {
        if (k.isEmpty() || k.length() > 10 || (k.length() > 1 && k.charAt(0) == '0')) return false;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    @SuppressWarnings("unchecked")
    private static void stringify(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(v);
        else if (v instanceof String) sb.append(Json.canonicalize(v));
        else if (JsVal.num(v) != null) {
            Double d = JsVal.num(v);
            if (d.isNaN() || d.isInfinite()) sb.append("null");
            else sb.append(Json.canonicalize(v instanceof Json.Num ? v : JsVal.numOf(d)));
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) { if (!first) sb.append(','); first = false; stringify(sb, x); }
            sb.append(']');
        } else if (v instanceof Map) {
            // JavaScript orders integer-like keys first (ascending), then the rest in insertion order
            Map<String, Object> m = (Map<String, Object>) v;
            List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
            for (String k : m.keySet()) (isIndex(k) ? idx : rest).add(k);
            idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
            idx.addAll(rest);
            sb.append('{');
            boolean first = true;
            for (String k : idx) {
                if (!first) sb.append(',');
                first = false;
                sb.append(Json.canonicalize(k)).append(':');
                stringify(sb, m.get(k));
            }
            sb.append('}');
        } else throw new IllegalArgumentException("serializeEvent: unsupported value");
    }

    /** The JSON wire form (JSON.stringify of the event: members in insertion order). */
    public static String serializeEvent(Object e) {
        checkEventFields("serializeEvent", e, true);
        if (JsVal.num(JsVal.opt(e, "at")) == null || JsVal.num(JsVal.opt(e, "at")).isNaN() || JsVal.num(JsVal.opt(e, "at")).isInfinite()) throw new IllegalArgumentException("serializeEvent: at must be a finite number");
        StringBuilder sb = new StringBuilder();
        stringify(sb, e);
        return sb.toString();
    }

    /** Message prefix of a refusal that is a JSON syntax error (the reference's text there is engine-specific). */
    public static final String SYNTAX_PREFIX = "JSON.parse: ";

    /** Parse and validate a JSON step-up event. Throws on anything that is not a well-formed event. */
    public static Map<String, Object> parseEvent(String s) {
        Object raw;
        try {
            raw = Json.parse(s); // the strict canonical profile: no duplicate member, exponent or trailing-zero number, lone surrogate or non-canonical form
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(SYNTAX_PREFIX + e.getMessage());
        }
        if (!(raw instanceof Map || raw instanceof List)) throw new IllegalArgumentException("parseEvent: not an object");
        Object id = JsVal.opt(raw, "id");
        if (!JsVal.nonEmpty(id)) throw new IllegalArgumentException("parseEvent: bad id");
        Object type = JsVal.opt(raw, "type");
        if (!(type instanceof String) || !EVENT_TYPES.contains(type)) throw new IllegalArgumentException("parseEvent: bad type");
        Object at = JsVal.opt(raw, "at");
        if (!JsVal.isFinite(at)) throw new IllegalArgumentException("parseEvent: bad at");
        if (!(JsVal.opt(raw, "grant_ref") instanceof String)) throw new IllegalArgumentException("parseEvent: bad grant_ref");
        Object action = JsVal.opt(raw, "action");
        if (!(action instanceof Map || action instanceof List)) throw new IllegalArgumentException("parseEvent: bad action");
        Object verb = JsVal.opt(action, "verb"), resource = JsVal.opt(action, "resource");
        if (!(verb instanceof String) || !(resource instanceof String)) throw new IllegalArgumentException("parseEvent: bad action fields");
        Double t = JsVal.num(JsVal.opt(raw, "tier"));
        if (t == null || (t != 2.0 && t != 3.0)) throw new IllegalArgumentException("parseEvent: bad tier");
        Object tier = new Json.Num(t == 2.0 ? "2" : "3");
        boolean hasActor = JsVal.has(raw, "actor");
        Object actor = JsVal.opt(raw, "actor");
        if (hasActor && !(actor instanceof String)) throw new IllegalArgumentException("parseEvent: bad actor");
        Object atN = IntentJs.normalize(at);
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("verb", verb);
        act.put("resource", resource);
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("id", id);
        e.put("type", type);
        e.put("at", atN);
        e.put("grant_ref", JsVal.opt(raw, "grant_ref"));
        e.put("action", act);
        e.put("tier", tier);
        if (hasActor) e.put("actor", actor);
        // The id is a content address. An event whose id is not the digest of its fields was edited or forged.
        if (!eventId(type, atN, e.get("grant_ref"), act, tier, hasActor, actor).equals(id)) throw new IllegalArgumentException("parseEvent: id does not match the event content");
        return e;
    }

    // ---- signed webhooks ----

    private static byte[] utf8(String s) {
        // TextEncoder writes U+FFFD for a lone surrogate (Java's encoder writes '?')
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
            else if (Character.isSurrogate(c)) sb.append('�');
            else sb.append(c);
        }
        return Json.utf8(sb.toString());
    }

    private static byte[] secretBytes(Object secret) {
        byte[] b = secret instanceof String ? utf8((String) secret) : secret instanceof byte[] ? (byte[]) secret : null;
        return b != null && b.length >= MIN_SECRET_BYTES ? b : null;
    }

    private static byte[] hmac(byte[] key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(utf8(message));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    /** noble hexToBytes: an even-length string of ASCII hex digits (either case), else null. */
    private static byte[] hexToBytes(String s) {
        if (s.length() % 2 != 0) return null;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = hexDigit(s.charAt(2 * i)), lo = hexDigit(s.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte) (hi * 16 + lo);
        }
        return out;
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static boolean timingSafeEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static boolean jsSpace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }

    /** String.prototype.trim (the JavaScript whitespace set, not Java's). */
    static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && jsSpace(s.charAt(a))) a++;
        while (b > a && jsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** A parsed `t=...,v1=...` signature header. */
    static final class Sig {
        final double t;
        final List<String> v1;
        Sig(double t, List<String> v1) { this.t = t; this.v1 = v1; }
    }

    /** Parse t=&lt;digits&gt;,v1=&lt;hex&gt;[,v1=...]. Several v1 are allowed (secret rotation); two different t are not. */
    static Sig parseSignatureHeader(Object h) {
        if (!(h instanceof String) || ((String) h).length() > MAX_HEADER_CHARS) return null;
        Double t = null;
        List<String> v1 = new ArrayList<>();
        for (String part : ((String) h).split(",", -1)) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String key = trim(part.substring(0, eq)), val = trim(part.substring(eq + 1));
            if (key.equals("t")) {
                if (val.length() < 1 || val.length() > 15) return null;
                for (int i = 0; i < val.length(); i++) if (val.charAt(i) < '0' || val.charAt(i) > '9') return null;
                double n = Double.parseDouble(val);
                if (t != null && t != n) return null;
                t = n;
            } else if (key.equals("v1")) v1.add(val);
        }
        if (t == null || v1.isEmpty()) return null;
        return new Sig(t, v1);
    }

    private static double nowSeconds() { return Math.floor((double) System.currentTimeMillis() / 1000); }

    /**
     * Stripe-style signature for a webhook payload: t=&lt;unixSeconds&gt;,v1=&lt;hex HMAC-SHA256 of "&lt;t&gt;.&lt;payload&gt;"&gt;. opts.timestamp (or
     * null opts) pins the second count (default: the clock). Throws on a secret shorter than {@link #MIN_SECRET_BYTES} bytes and on
     * a timestamp that is not a non-negative safe integer; the error never contains the secret. secret is a String or byte[].
     */
    public static String signWebhook(Object secret, String payload, Map<String, Object> opts) {
        byte[] key = secretBytes(secret);
        if (key == null) throw new IllegalArgumentException("signWebhook: the secret must be at least " + MIN_SECRET_BYTES + " bytes");
        Object ts = opts == null ? null : opts.get("timestamp");
        Object tO = ts != null ? ts : JsVal.numOf(nowSeconds());
        if (!JsVal.isSafeInteger(tO) || JsVal.num(tO) < 0) throw new IllegalArgumentException("signWebhook: timestamp must be a non-negative integer (unix seconds)");
        long t = (long) (double) JsVal.num(tO);
        return "t=" + t + ",v1=" + hex(hmac(key, t + "." + payload));
    }

    /**
     * Verify a signature header against the payload: recompute the HMAC, compare constant-time, and enforce the timestamp tolerance
     * (default 300 s). Returns false, never throws, on a malformed header, a bad signature, a stale timestamp, a secret that is too
     * short, or a tolerance / clock that is not a finite non-negative number. With several v1 entries (secret rotation) any one may
     * match. opts: toleranceSec?, now? (unix seconds). A valid signature is not proof of freshness beyond the tolerance window: use
     * {@link #verifyDelivery} to also refuse a replay.
     */
    public static boolean verifyWebhook(Object secret, String payload, Object signatureHeader, Map<String, Object> opts) {
        try {
            byte[] key = secretBytes(secret);
            if (key == null) return false;
            Sig parsed = parseSignatureHeader(signatureHeader);
            if (parsed == null) return false;
            Object tolO = JsVal.or(opts == null ? null : opts.get("toleranceSec"), new Json.Num("300"));
            Object nowO = JsVal.or(opts == null ? null : opts.get("now"), JsVal.numOf(nowSeconds()));
            if (!JsVal.isFinite(tolO) || JsVal.num(tolO) < 0 || !JsVal.isFinite(nowO)) return false;
            if (Math.abs(JsVal.num(nowO) - parsed.t) > JsVal.num(tolO)) return false;
            byte[] expected = hmac(key, ((long) parsed.t) + "." + payload);
            boolean match = false;
            for (String v : parsed.v1) {
                byte[] provided = hexToBytes(v);
                if (provided == null) continue;
                if (timingSafeEqual(expected, provided)) match = true; // no early exit: every candidate costs the same
            }
            return match;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The verdict of {@link #verifyDelivery}: ok with the event, or not ok with a reason. */
    public static final class DeliveryVerdict {
        public final boolean ok;
        public final Map<String, Object> event;
        public final String reason;
        DeliveryVerdict(boolean ok, Map<String, Object> event, String reason) { this.ok = ok; this.event = event; this.reason = reason; }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (ok) m.put("event", event); else m.put("reason", reason);
            return m;
        }
    }

    private static DeliveryVerdict no(String why) { return new DeliveryVerdict(false, null, why); }

    /** base64url(sha256(length-prefixed parts)) under the namespace, as the reference's replayKey (a lone surrogate is refused). */
    public static String replayKey(String namespace, String... parts) {
        List<byte[]> chunks = new ArrayList<>();
        List<String> all = new ArrayList<>();
        all.add(namespace);
        for (String p : parts) all.add(p);
        int total = 0;
        for (String p : all) {
            if (p == null || Json.hasLoneSurrogate(p)) throw new IllegalArgumentException("replayKey: every part must be a well-formed string (no lone surrogates)");
            byte[] b = Json.utf8(p);
            chunks.add(ByteBuffer.allocate(4).putInt(b.length).array());
            chunks.add(b);
            total += 4 + b.length;
        }
        ByteBuffer buf = ByteBuffer.allocate(total);
        for (byte[] c : chunks) buf.put(c);
        try {
            return namespace + ":" + Keys.b64u(MessageDigest.getInstance("SHA-256").digest(buf.array()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long ms(double v, boolean up) { return (long) (up ? Math.ceil(v) : Math.floor(v)); }

    /**
     * Accept one webhook delivery: signature and freshness ({@link #verifyWebhook}), a well-formed event whose id matches its
     * content ({@link #parseEvent}), and a first sight of that event id (replay.consumeOnce). A store that throws refuses. Never
     * throws, and no reason contains the secret or the payload. opts: toleranceSec?, now?. A fractional retention horizon is
     * rounded toward a longer retention (ceil for the horizon, floor for the clock): the fail-closed direction.
     */
    public static DeliveryVerdict verifyDelivery(Object secret, String payload, Object signatureHeader, StateStore replay, Map<String, Object> opts) {
        try {
            if (opts == null || replay == null) return no("a replay store is required");
            if (!verifyWebhook(secret, payload, signatureHeader, opts)) return no("bad signature");
            Map<String, Object> event;
            try {
                event = parseEvent(payload);
            } catch (RuntimeException e) {
                return no(e.getMessage());
            }
            Sig sig = parseSignatureHeader(signatureHeader);
            double nowSec = JsVal.num(JsVal.or(opts.get("now"), JsVal.numOf(nowSeconds())));
            double tolerance = JsVal.num(JsVal.or(opts.get("toleranceSec"), new Json.Num("300")));
            try {
                boolean first = replay.consumeOnce(replayKey("pca-stepup-event/v1", (String) event.get("id")), ms((sig.t + tolerance) * 1000 + 1, true), ms(nowSec * 1000, false));
                if (!first) return no("replayed delivery");
            } catch (RuntimeException e) {
                return no("replay store unavailable");
            }
            return new DeliveryVerdict(true, event, null);
        } catch (RuntimeException e) {
            return no("bad signature");
        }
    }

    /** The headers to attach to an outbound webhook POST. */
    public static Map<String, String> webhookHeaders(Object secret, String payload, Map<String, Object> opts) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("PCA-Signature", signWebhook(secret, payload, opts));
        h.put("content-type", "application/json");
        return h;
    }
}
