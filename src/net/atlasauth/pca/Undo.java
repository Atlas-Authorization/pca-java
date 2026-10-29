package net.atlasauth.pca;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * UNDO WINDOWS (0.5), the pure, language-neutral layer: reversible actions execute at once and the principal gets a veto window in
 * which they can undo them. This class verifies what an undo coordinator produces, so any service can check one-click undo
 * tokens, the signed and hash-chained audit receipts of a record, and the record state machine. The coordinator itself (admission,
 * the durable ledger, compensation, notification) is a separate service; {@link Authorize} only calls its admission hook
 * ({@link Admit}).
 *
 * <pre>
 *     open --veto (now &lt;= window_end)--&gt; vetoed --compensated--&gt; compensated
 *       |                                  |  \--compensation_failed--&gt; compensation_failed --retry--&gt; vetoed
 *       +--finalize (now &gt; window_end)--&gt; finalized
 *       +--abort (the effect never ran)--&gt; finalized
 * </pre>
 *
 * Signatures are plain Ed25519 over {@code utf8(domain) || strictCanonical(body)} (no post-quantum suite). Every function is total.
 */
public final class Undo {
    private Undo() {}

    public static final String TOKEN_DOMAIN = "atlas-pca/undo-token/v1\0";
    public static final String RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\0";
    public static final String COMPENSATION_DOMAIN = "atlas-pca/undo-compensation/v1";
    public static final String RECEIPT_REF_DOMAIN = "atlas-pca/undo-receipt-ref/v1";
    public static final String TOKEN_REF_DOMAIN = "atlas-pca/undo-token-ref/v1";
    public static final String TOKEN_KIND = "pca-undo-token";
    public static final String RECEIPT_KIND = "pca-undo-receipt";

    /** The floor of a veto window: a human must be able to react. */
    public static final long MIN_WINDOW_MS = 30_000L;
    public static final long DEFAULT_WINDOW_MS = 900_000L;
    public static final long MAX_WINDOW_MS = 86_400_000L;

    public static final List<String> STATES = List.of("open", "vetoed", "compensated", "compensation_failed", "finalized");
    public static final List<String> EVENTS = List.of("opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect");
    public static final List<String> VETO_VIAS = List.of("token", "operator", "fraud_proof", "revocation");
    static final List<String> TOKEN_MEMBERS = List.of("v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig");
    static final List<String> RECEIPT_MEMBERS = List.of("v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer", "sig");

    /** The token check codes, in check order. */
    public static final String OK = "ok", MALFORMED = "malformed", SIGNER = "signer", SIGNATURE = "signature", RECORD = "record",
        BINDING = "binding", EXPIRED = "expired";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }
    private static boolean isOne(Object v) { return IntentJs.isInt(v) && IntentJs.lng(v) == 1L; }

    /** A record id: a string of 1..256 characters without control characters (U+0000..U+001F). */
    public static boolean idOk(Object s) {
        if (!(s instanceof String) || ((String) s).isEmpty() || ((String) s).length() > 256) return false;
        for (char c : ((String) s).toCharArray()) if (c < 0x20) return false;
        return true;
    }

    private static byte[] domainBytes(String domain, Object body) { return IntentJs.message(domain, body); }

    private static Map<String, Object> without(Map<String, Object> m, String k) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        out.remove(k);
        return out;
    }

    // ---- digests --------------------------------------------------------------------------------------------------------

    /** {@code hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?})} of a compensating action. */
    public static String compensationDigest(Map<String, ?> c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", COMPENSATION_DOMAIN);
        for (String k : new String[] {"verb", "resource", "params", "undo_of", "def_digest"}) m.put(k, c.get(k));
        if (c.containsKey("target_param")) m.put("target_param", c.get("target_param"));
        return Pca.hashCanonical(IntentJs.normalize(m));
    }

    // ---- the one-click undo token ---------------------------------------------------------------------------------------

    /**
     * Sign the undo token of a record {@code {id, aud, principal, compensation_digest, render_digest?, window_end}} under the undo
     * service key: bound to the record, the compensation it starts, the render the human was shown and the window end.
     */
    public static Map<String, Object> signToken(Map<String, ?> record, Keys.EdKey key) {
        if (key == null) throw new IllegalArgumentException("signToken: the undo service key is required");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", IntentJs.ofLong(1));
        body.put("kind", TOKEN_KIND);
        body.put("record", record.get("id"));
        body.put("aud", record.get("aud"));
        body.put("principal", record.get("principal"));
        body.put("compensation_digest", record.get("compensation_digest"));
        body.put("render_digest", record.get("render_digest") == null ? "" : record.get("render_digest"));
        body.put("exp", record.get("window_end"));
        body.put("signer", key.id());
        body = obj(IntentJs.normalize(body));
        body.put("sig", Pca.b64(key.sign(domainBytes(TOKEN_DOMAIN, body))));
        return body;
    }

    /**
     * The FIRST check a token fails against the pinned undo service key and the stored record at {@code now}, in order:
     * {@code malformed} (shape: exactly the 10 members), {@code signer} (not the pinned key), {@code signature}, {@code record}
     * (another record id), {@code binding} (aud, principal, compensation, render digest or exp differ), {@code expired}
     * ({@code now} not a safe integer, or {@code now > exp}: valid THROUGH {@code exp}), else {@code ok}. Never throws.
     */
    public static String tokenCheck(Object token, String expectedSigner, Map<String, ?> record, Object now) {
        try {
            if (!(token instanceof Map)) return MALFORMED;
            Map<String, Object> t = obj(IntentJs.normalize(token));
            if (t.size() != TOKEN_MEMBERS.size() || !t.keySet().containsAll(TOKEN_MEMBERS)) return MALFORMED;
            if (!isOne(t.get("v")) || !TOKEN_KIND.equals(t.get("kind")) || !idOk(t.get("record")) || !(t.get("aud") instanceof String)
                || !(t.get("principal") instanceof String) || !(t.get("compensation_digest") instanceof String) || !(t.get("render_digest") instanceof String)
                || !IntentJs.isInt(t.get("exp")) || !(t.get("signer") instanceof String) || Pca.decodeB64uStrict(t.get("sig"), 64) == null) return MALFORMED;
            if (!t.get("signer").equals(expectedSigner)) return SIGNER;
            if (!Pca.verifyB64u(expectedSigner, domainBytes(TOKEN_DOMAIN, without(t, "sig")), (String) t.get("sig"))) return SIGNATURE;
            if (!t.get("record").equals(record.get("id"))) return RECORD;
            Object render = record.get("render_digest") == null ? "" : record.get("render_digest");
            Double end = IntentJs.num(record.get("window_end"));
            if (!t.get("aud").equals(record.get("aud")) || !t.get("principal").equals(record.get("principal"))
                || !t.get("compensation_digest").equals(record.get("compensation_digest")) || !t.get("render_digest").equals(render)
                || end == null || IntentJs.num(t.get("exp")).doubleValue() != end.doubleValue()) return BINDING;
            if (!IntentJs.isInt(now) || IntentJs.num(now) > IntentJs.num(t.get("exp"))) return EXPIRED;
            return OK;
        } catch (RuntimeException e) {
            return MALFORMED;
        }
    }

    /** {@link #tokenCheck(Object, String, Map, Object)} at a clock in epoch milliseconds. */
    public static String tokenCheck(Object token, String expectedSigner, Map<String, ?> record, long now) {
        return tokenCheck(token, expectedSigner, record, (Object) now);
    }

    /** The token as a URL-safe string (base64url of its strict-canonical JSON) for a one-click link. Throws on a non-canonical token. */
    public static String encodeToken(Map<String, ?> token) { return Pca.b64(Json.canonicalizeStrict(IntentJs.normalize(token)).getBytes(StandardCharsets.UTF_8)); }

    /** Inverse of {@link #encodeToken}: a JSON object, or null for anything else (at most 4096 characters, strict base64url, UTF-8 and JSON). */
    public static Map<String, Object> decodeToken(Object s) {
        try {
            if (!(s instanceof String) || ((String) s).isEmpty() || ((String) s).length() > 4096) return null;
            byte[] b = Pca.decodeB64uStrict(s, -1);
            if (b == null) return null;
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
            Object x = Json.parse(text);
            return x instanceof Map ? obj(x) : null;
        } catch (CharacterCodingException | RuntimeException e) {
            return null;
        }
    }

    /** {@code hashCanonical({d: "atlas-pca/undo-token-ref/v1", t})}. */
    public static String tokenDigest(Map<String, ?> token) { return IntentJs.ref(TOKEN_REF_DOMAIN, "t", IntentJs.normalize(token)); }

    // ---- receipts -------------------------------------------------------------------------------------------------------

    /** Sign a receipt body {@code {record, event, state, at, compensation_digest, prev, note}} under the undo service key. */
    public static Map<String, Object> signReceipt(Map<String, ?> body, Keys.EdKey key) {
        if (key == null) throw new IllegalArgumentException("signReceipt: the undo service key is required");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", IntentJs.ofLong(1));
        b.put("kind", RECEIPT_KIND);
        for (String k : new String[] {"record", "event", "state", "at", "compensation_digest", "prev", "note"}) b.put(k, body.get(k));
        b.put("signer", key.id());
        b = obj(IntentJs.normalize(b));
        b.put("sig", Pca.b64(key.sign(domainBytes(RECEIPT_DOMAIN, b))));
        return b;
    }

    /** True iff {@code r} is well formed (exactly 11 members, known event and state) and signed by {@code expectedSigner}. Never throws. */
    public static boolean verifyReceipt(Object r, String expectedSigner) {
        try {
            if (!(r instanceof Map)) return false;
            Map<String, Object> x = obj(IntentJs.normalize(r));
            if (!isOne(x.get("v")) || !RECEIPT_KIND.equals(x.get("kind")) || !idOk(x.get("record")) || !EVENTS.contains(x.get("event"))
                || !STATES.contains(x.get("state")) || !IntentJs.isInt(x.get("at")) || !(x.get("compensation_digest") instanceof String)
                || !(x.get("prev") instanceof String) || !(x.get("note") instanceof String) || expectedSigner == null
                || !expectedSigner.equals(x.get("signer")) || Pca.decodeB64uStrict(x.get("sig"), 64) == null) return false;
            if (x.size() != RECEIPT_MEMBERS.size()) return false;
            return Pca.verifyB64u(expectedSigner, domainBytes(RECEIPT_DOMAIN, without(x, "sig")), (String) x.get("sig"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** {@code hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r})} (the receipt WITH its signature). */
    public static String receiptDigest(Map<String, ?> receipt) { return IntentJs.ref(RECEIPT_REF_DOMAIN, "r", IntentJs.normalize(receipt)); }

    /**
     * Verify a record's receipt chain ({@code record.receipts}): every receipt verifies, names this record id and compensation
     * digest, links {@code prev} to the previous receipt's digest ({@code ""} for the first), the first is {@code opened}, {@code at}
     * never decreases, and the last receipt's state is the record's state. Null when sound, else the reason. Never throws.
     */
    public static String receiptChainError(Map<String, ?> record, String expectedSigner) {
        try {
            Object rs = record == null ? null : record.get("receipts");
            if (!(rs instanceof List) || ((List<?>) rs).isEmpty()) return "no receipts";
            List<?> list = (List<?>) rs;
            String prev = "";
            Double at = null;
            for (int i = 0; i < list.size(); i++) {
                if (!verifyReceipt(list.get(i), expectedSigner)) return "receipt " + i + " does not verify";
                Map<String, Object> r = obj(IntentJs.normalize(list.get(i)));
                if (!r.get("record").equals(record.get("id")) || !r.get("compensation_digest").equals(record.get("compensation_digest")))
                    return "receipt " + i + " is for another record";
                if (!r.get("prev").equals(prev)) return "receipt " + i + " does not link to the previous one";
                if (i == 0 && !"opened".equals(r.get("event"))) return "the first receipt is not opened";
                double a = IntentJs.num(r.get("at"));
                if (at != null && a < at) return "receipt " + i + " goes back in time";
                prev = receiptDigest(r);
                at = a;
            }
            return obj(list.get(list.size() - 1)).get("state").equals(record.get("state")) ? null : "the last receipt does not state the record state";
        } catch (RuntimeException e) {
            return "evaluation error (fail closed)";
        }
    }

    // ---- the pure transitions -------------------------------------------------------------------------------------------

    /** The result of {@link #transition}: {@code applied} (with the next {@code record} and the receipt {@code event}/{@code note}), {@code replayed} or {@code refused} ({@code code}). */
    public static final class Transition {
        public final String outcome, code, reason;
        /** The next record (applied) or the unchanged one (replayed); null when refused. */
        public final Map<String, Object> record;
        /** The receipt event and note of an applied transition (the store signs and links the receipt); null otherwise. */
        public final String event, note;
        Transition(String outcome, String code, String reason, Map<String, Object> record, String event, String note) {
            this.outcome = outcome; this.code = code; this.reason = reason; this.record = record; this.event = event; this.note = note;
        }
    }

    private static Transition refused(String code, String reason) { return new Transition("refused", code, reason, null, null, null); }
    private static Transition replayed(Map<String, Object> rec) { return new Transition("replayed", null, null, rec, null, null); }

    private static String jsString(Map<String, Object> ev, String k, int max) {
        String s = IntentRevocation.jsText(ev.get(k), ev.containsKey(k));
        return s.length() > max ? s.substring(0, max) : s;
    }

    private static Map<String, Object> outcomeOf(long now, String status) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("at", IntentJs.ofLong(now));
        o.put("status", status);
        return o;
    }

    /**
     * The state machine, pure: {@code record} is not modified; an applied transition returns the next record (version bumped; the
     * receipt is NOT appended: the store layer signs and links it). The record fields read are {@code state}, {@code window_end},
     * {@code ver}, {@code attempt}, {@code effect} (present or absent) and {@code outcome.status}. {@code event} is
     * {@code {kind: veto, veto: {at, via, by}}}, {@code {kind: finalize}}, {@code {kind: abort, reason}},
     * {@code {kind: effect, result?}}, {@code {kind: compensated, result?}}, {@code {kind: compensation_failed, reason}} or
     * {@code {kind: retry}}. {@code now} is the trusted server clock. Never throws.
     */
    public static Transition transition(Object record, Object event, Object now) {
        try {
            if (!(record instanceof Map)) return refused("invalid", "malformed record");
            Map<String, Object> rec = obj(IntentJs.normalize(record));
            String state = rec.get("state") instanceof String ? (String) rec.get("state") : null;
            if (!STATES.contains(state) || !IntentJs.isInt(rec.get("window_end")) || !IntentJs.isInt(rec.get("ver"))) return refused("invalid", "malformed record");
            if (!IntentJs.isInt(now)) return refused("invalid", "now must be a safe integer");
            long t = IntentJs.lng(now), windowEnd = IntentJs.lng(rec.get("window_end"));
            Map<String, Object> ev = event instanceof Map ? obj(IntentJs.normalize(event)) : new LinkedHashMap<>();
            Object kind = ev.get("kind");
            boolean hasEffect = rec.containsKey("effect");
            Map<String, Object> next = new LinkedHashMap<>(rec);
            next.put("ver", IntentJs.ofLong(IntentJs.lng(rec.get("ver")) + 1));
            if ("veto".equals(kind)) {
                Object v = ev.get("veto");
                if (!(v instanceof Map) || !IntentJs.isInt(obj(v).get("at")) || !VETO_VIAS.contains(obj(v).get("via"))
                    || !(obj(v).get("by") instanceof String) || ((String) obj(v).get("by")).isEmpty()) return refused("invalid", "malformed veto");
                if (state.equals("vetoed") || state.equals("compensated") || state.equals("compensation_failed")) return replayed(rec);
                if (state.equals("finalized")) return refused("finalized", "the window is closed and the action is final");
                if (t > windowEnd) return refused("window_closed", "the veto window closed at " + windowEnd);
                next.put("state", "vetoed");
                next.put("veto", new LinkedHashMap<>(obj(v)));
                return new Transition("applied", null, null, next, "vetoed", (String) obj(v).get("via"));
            }
            if ("finalize".equals(kind)) {
                if (state.equals("finalized")) return replayed(rec);
                if (!state.equals("open")) return refused("vetoed", "a " + state + " record is not finalized");
                if (t <= windowEnd) return refused("window_open", "the veto window is open until " + windowEnd);
                next.put("state", "finalized");
                next.put("outcome", outcomeOf(t, "finalized"));
                return new Transition("applied", null, null, next, "finalized", "");
            }
            if ("abort".equals(kind)) {
                Object out = rec.get("outcome");
                if (state.equals("finalized") && out instanceof Map && "aborted".equals(obj(out).get("status"))) return replayed(rec);
                if (!state.equals("open") && !state.equals("vetoed")) return refused("finalized", "a " + state + " record cannot be aborted");
                if (hasEffect) return refused("effect_recorded", "the effect ran: it can only be compensated or finalized");
                Map<String, Object> o = outcomeOf(t, "aborted");
                o.put("reason", jsString(ev, "reason", 512));
                next.put("state", "finalized");
                next.put("outcome", o);
                return new Transition("applied", null, null, next, "aborted", jsString(ev, "reason", 128));
            }
            if ("effect".equals(kind)) {
                if (hasEffect) return replayed(rec);
                if (!state.equals("open") && !state.equals("vetoed")) return refused("finalized", "a " + state + " record takes no effect report");
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("at", IntentJs.ofLong(t));
                if (ev.containsKey("result")) e.put("result", ev.get("result"));
                next.put("effect", e);
                return new Transition("applied", null, null, next, "effect", "");
            }
            if ("compensated".equals(kind)) {
                if (state.equals("compensated")) return replayed(rec);
                if (!state.equals("vetoed") && !state.equals("compensation_failed")) return refused("not_vetoed", "a " + state + " record is not being compensated");
                Map<String, Object> o = outcomeOf(t, "compensated");
                if (ev.containsKey("result")) o.put("result", ev.get("result"));
                next.put("state", "compensated");
                next.put("outcome", o);
                return new Transition("applied", null, null, next, "compensated", "");
            }
            if ("compensation_failed".equals(kind)) {
                if (state.equals("compensation_failed")) return replayed(rec);
                if (!state.equals("vetoed")) return refused("not_vetoed", "a " + state + " record is not being compensated");
                Map<String, Object> o = outcomeOf(t, "compensation_failed");
                o.put("reason", jsString(ev, "reason", 512));
                next.put("state", "compensation_failed");
                next.put("outcome", o);
                return new Transition("applied", null, null, next, "compensation_failed", jsString(ev, "reason", 128));
            }
            if ("retry".equals(kind)) {
                if (!state.equals("compensation_failed")) return refused("not_failed", "a " + state + " record is not retried");
                if (!IntentJs.isInt(rec.get("attempt"))) return refused("invalid", "malformed record");
                next.put("state", "vetoed");
                next.put("attempt", IntentJs.ofLong(IntentJs.lng(rec.get("attempt")) + 1));
                return new Transition("applied", null, null, next, "retried", "");
            }
            return refused("invalid", "unknown event");
        } catch (RuntimeException e) {
            return refused("invalid", "evaluation error (fail closed)");
        }
    }

    // ---- the window -----------------------------------------------------------------------------------------------------

    /**
     * Clamp a requested window (ms) into {@code [max(30 s, minMs), min(maxMs, 24 h)]} (a host max below the min is the min); an
     * absent (null) or non-finite request is {@code defaultMs} (null: 15 min). Null policy members take their defaults.
     */
    public static long resolveWindow(Double requestedMs, Double minMs, Double maxMs, Double defaultMs) {
        double min = Math.max(MIN_WINDOW_MS, minMs != null ? minMs : MIN_WINDOW_MS);
        double max = Math.max(min, Math.min(maxMs != null ? maxMs : MAX_WINDOW_MS, MAX_WINDOW_MS));
        double want = requestedMs != null && Double.isFinite(requestedMs) ? requestedMs : defaultMs != null ? defaultMs : DEFAULT_WINDOW_MS;
        return (long) Math.floor(Math.min(max, Math.max(min, want)));
    }

    // ---- the admission hook of authorize --------------------------------------------------------------------------------

    /**
     * The undo admission hook of {@link Authorize} ({@link Authorize.Input#undo}, {@link Authorize.Options#withUndo}). It is called
     * ONLY for a refused verdict whose decision is {@code escalate}, with no escalation answer presented and no provenance
     * escalation ({@code provenance_flow} and Intent rule 17 {@code provenance} both not failing).
     *
     * <p>CONTRACT: return an admission {@code {id, window_end, compensation: {verb, resource}}} ONLY after the window's record is
     * durably opened by your undo coordinator (the reference coordinator or the hosted ledger): the action is confirmed reversible,
     * its compensating action is authorized under the same grant, and the veto window runs until {@code window_end}. Return null
     * to leave the escalation standing. An exception, or a malformed admission ({@code id} not a non-empty string of at most 128
     * characters, {@code window_end} not a non-negative safe integer, {@code compensation.verb} not a non-empty string), is no
     * admission: the escalation stands.
     */
    @FunctionalInterface
    public interface Admit {
        Map<String, Object> admit(Map<String, Object> pcactn, Map<String, Object> grant, Authorize.Operation operation);
    }

    /** Null when {@code a} is a usable admission {@code {id, window_end, compensation: {verb, resource?}}}, else the reason. */
    static String admissionError(Object a) {
        if (!(a instanceof Map)) return "an admission must be an object";
        Map<String, Object> m = obj(a);
        if (!(m.get("id") instanceof String) || ((String) m.get("id")).isEmpty() || ((String) m.get("id")).length() > 128) return "admission id must be a non-empty string of at most 128 characters";
        if (!IntentJs.isNonNeg(m.get("window_end"))) return "admission window_end must be a non-negative safe integer";
        Object c = m.get("compensation");
        if (!(c instanceof Map) || !(obj(c).get("verb") instanceof String) || ((String) obj(c).get("verb")).isEmpty()) return "admission compensation.verb must be a non-empty string";
        return null;
    }

    /** The {@code undo_window} obligation of an admission: {@code {kind: "undo_window", params: {id, window_end}, due: window_end}}. */
    public static Map<String, Object> obligation(Map<String, ?> admission) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("id", admission.get("id"));
        params.put("window_end", IntentJs.ofLong(IntentJs.lng(admission.get("window_end"))));
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("kind", "undo_window");
        o.put("params", params);
        o.put("due", IntentJs.ofLong(IntentJs.lng(admission.get("window_end"))));
        return o;
    }
}
