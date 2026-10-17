package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Rule 15: accumulators, monitors, sequencer reservation receipts and the sequencer's root-signed key sets
 * (packages/pca/src/intent-acc.ts). The verifier never takes an accumulator value from the agent: it recomputes the
 * post-action value from its own pre-state (site-local) or from a sequencer-signed receipt, and the agent's signed claim
 * must equal it.
 */
public final class IntentAcc {
    private IntentAcc() {}

    public static final int MAX_SESSION_ACCUMULATORS = 16;
    public static final int MAX_SESSION_MONITORS = 16;
    public static final int MAX_MONITOR_WITHIN = 64;
    public static final String ACC_RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\0";
    public static final String ACC_RECEIPT_REF_DOMAIN = "atlas-pca/acc-receipt-ref/v1";
    public static final String ACC_RESERVE_DOMAIN = "atlas-pca/acc-reserve/v1";
    public static final String SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\0";
    public static final String SEQUENCER_KEYS_REF_DOMAIN = "atlas-pca/sequencer-keys-ref/v1";
    public static final long RECEIPT_SKEW_MS = 60_000L;
    /** A receipt lives at most this long: {@code issued_at <= expires_at <= issued_at + 900000} (15 min). */
    public static final long MAX_RECEIPT_LIFETIME_MS = 900_000L;
    /** Default bound on a receipt's age at verification, policy {@code acc.max_receipt_age_s} (15 min). */
    public static final long DEFAULT_MAX_RECEIPT_AGE_MS = 900_000L;
    /** Default bound on a key set's age, policy {@code acc.max_keyset_age_s} (1 h). */
    public static final long DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000L;
    static final List<String> ACC_AGGS = List.of("sum", "count", "distinct", "max");
    static final List<String> MONITOR_KINDS = List.of("requires_prior", "precedes", "never", "always", "responds_within");
    static final Pattern ACC_ID_RE = Pattern.compile("[A-Za-z0-9_]{1,64}");
    static final Pattern KID_RE = Pattern.compile("[A-Za-z0-9_.:-]{1,64}");
    private static final Pattern PARAM_PATH_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}");
    private static final Pattern UNIT_RE = Pattern.compile("[a-z0-9_]+(?:\\.[a-z0-9_]+)*");
    private static final List<String> RECEIPT_KEYS = List.of("v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at",
        "expires_at", "kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig");

    private static boolean idOk(Object v) { return v instanceof String && ACC_ID_RE.matcher((String) v).matches(); }
    private static boolean declIdOk(Object v) { return idOk(v) && !ActionSchema.RESERVED_NAMES.contains(v); }
    private static boolean onlyKeys(Map<?, ?> m, String... allowed) {
        List<String> a = List.of(allowed);
        for (Object k : m.keySet()) if (!a.contains(k)) return false;
        return true;
    }
    private static boolean exactKeys(Object o, String... keys) {
        if (!(o instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) o;
        if (m.size() != keys.length) return false;
        for (String k : keys) if (!m.containsKey(k)) return false;
        return true;
    }

    /** The state set Q of a monitor. */
    static List<String> monitorStates(Map<String, Object> m) {
        switch (String.valueOf(m.get("kind"))) {
            case "requires_prior": case "precedes": return List.of("unmet", "met");
            case "never": return List.of("clean", "seen");
            case "always": return List.of("ok", "broken");
            case "responds_within": {
                long w = IntentJs.isInt(m.get("within")) ? IntentJs.lng(m.get("within")) : 0;
                List<String> out = new ArrayList<>();
                out.add("idle");
                for (long i = 1; i <= w; i++) out.add("pending:" + i);
                out.add("missed");
                return out;
            }
            default: return List.of();
        }
    }

    private static boolean predicateShapeOk(Object p) {
        if (!(p instanceof Map)) return false;
        Object verb = ((Map<?, ?>) p).get("verb");
        if (verb instanceof String) return true;
        if (!(verb instanceof List) || ((List<?>) verb).isEmpty()) return false;
        for (Object x : (List<?>) verb) if (!(x instanceof String)) return false;
        return true;
    }

    /** Shape of an accumulator declaration in S. Null = well-formed. */
    static String accumulatorDeclError(Object aO) {
        if (!(aO instanceof Map)) return "accumulator must be an object";
        Map<String, Object> a = IntentJs.obj(aO);
        for (String k : a.keySet()) if (!List.of("id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder").contains(k)) return "accumulator: unknown member '" + k + "'";
        if (!declIdOk(a.get("id"))) return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype";
        String at = "accumulator '" + a.get("id") + "'";
        if (!(a.get("agg") instanceof String) || !ACC_AGGS.contains(a.get("agg"))) return at + ": unknown agg";
        if (a.containsKey("val") && (!(a.get("val") instanceof String) || !PARAM_PATH_RE.matcher((String) a.get("val")).matches())) return at + ": val must be action.params.<name>";
        if (a.containsKey("unit") && (!(a.get("unit") instanceof String) || ((String) a.get("unit")).length() > 64 || !UNIT_RE.matcher((String) a.get("unit")).matches())) return at + ": unit must be a unit id";
        if (!(a.get("sel") instanceof Map)) return at + ": sel must be an object";
        Map<String, Object> sel = IntentJs.obj(a.get("sel"));
        for (String k : sel.keySet()) if (!List.of("verbs", "accumulates_into", "event").contains(k)) return at + ": sel has unknown member '" + k + "'";
        if (sel.containsKey("verbs")) {
            Object vs = sel.get("verbs");
            boolean ok = vs instanceof List && !((List<?>) vs).isEmpty() && ((List<?>) vs).size() <= 64;
            if (ok) for (Object v : (List<?>) vs) if (!(v instanceof String) || ((String) v).isEmpty()) ok = false;
            if (!ok) return at + ": sel.verbs must be 1..64 verb names";
        }
        if (sel.containsKey("accumulates_into") && (!(sel.get("accumulates_into") instanceof String) || !UNIT_RE.matcher((String) sel.get("accumulates_into")).matches()))
            return at + ": sel.accumulates_into must be a unit id";
        if (sel.containsKey("event") && (!(sel.get("event") instanceof String) || !List.of("intent_required", "question", "clarification").contains(sel.get("event")))) return at + ": unknown sel.event";
        boolean actionSel = sel.containsKey("verbs") || sel.containsKey("accumulates_into");
        if (actionSel == sel.containsKey("event")) return at + ": sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind";
        if (!(a.get("win") instanceof Map)) return at + ": win must be an object";
        Map<String, Object> w = IntentJs.obj(a.get("win"));
        Object wk = w.get("kind");
        if ("task".equals(wk)) {
            if (w.size() != 1) return at + ": win {kind: task} has no other member";
        } else if ("sliding".equals(wk)) {
            if (!exactKeys(w, "kind", "ms") || !(IntentJs.isInt(w.get("ms")) && IntentJs.num(w.get("ms")) > 0)) return at + ": win sliding needs a positive ms";
        } else if ("period".equals(wk)) {
            if (!exactKeys(w, "kind", "ms", "t0") || !(IntentJs.isInt(w.get("ms")) && IntentJs.num(w.get("ms")) > 0) || !IntentJs.isNonNeg(w.get("t0"))) return at + ": win period needs a positive ms and t0 >= 0";
        } else return at + ": unknown win kind";
        boolean keyNull = a.containsKey("key") && a.get("key") == null;
        if (!keyNull && (!(a.get("key") instanceof String) || !PARAM_PATH_RE.matcher((String) a.get("key")).matches())) return at + ": key must be null or action.params.<name>";
        if (a.containsKey("domain_max") && !IntentJs.isNonNeg(a.get("domain_max"))) return at + ": domain_max must be a non-negative safe integer";
        if (a.containsKey("cap") && !IntentJs.isNonNeg(a.get("cap"))) return at + ": cap must be a non-negative safe integer";
        if (!(a.get("holder") instanceof Map)) return at + ": holder must be an object";
        Map<String, Object> h = IntentJs.obj(a.get("holder"));
        Object hk = h.get("kind");
        if ("site_local".equals(hk) || "wallet".equals(hk)) {
            if (h.size() != 1) return at + ": holder " + hk + " has no other member";
        } else if ("sequenced".equals(hk)) {
            for (String k : h.keySet()) if (!List.of("kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri").contains(k)) return at + ": holder sequenced has unknown member '" + k + "'";
            if (!(h.get("uri") instanceof String) || ((String) h.get("uri")).isEmpty()) return at + ": holder sequenced needs a uri";
            if (!IntentJs.b32(h.get("root"))) return at + ": holder.root is not canonical base64url (32 bytes)";
            String rse = IntentJs.suiteError(h.get("root_alg"), h.containsKey("root_alg"));
            if (rse != null) return at + ": holder.root_alg: " + rse;
            if (h.containsKey("root_pq_pk") && !IntentJs.b64any(h.get("root_pq_pk"))) return at + ": holder.root_pq_pk is not canonical base64url";
            if (h.containsKey("keys_uri") && (!(h.get("keys_uri") instanceof String) || ((String) h.get("keys_uri")).isEmpty())) return at + ": holder.keys_uri must be a non-empty string";
        } else return at + ": unknown holder kind";
        boolean wallet = "wallet".equals(hk);
        if (wallet != sel.containsKey("event")) return at + ": wallet events are wallet-held and only wallet events are";
        if (!wallet) {
            Object agg = a.get("agg");
            if (!"count".equals(agg) && !a.containsKey("val") && !sel.containsKey("accumulates_into")) return at + ": " + agg + " needs val (or sel.accumulates_into for a sum)";
            if (!"sum".equals(agg) && !"count".equals(agg) && !a.containsKey("val")) return at + ": " + agg + " needs val";
            if ("count".equals(agg) && a.containsKey("val")) return at + ": count takes no val";
        }
        return null;
    }

    /** Shape of a monitor declaration in S. Null = well-formed. */
    static String monitorDeclError(Object mO) {
        if (!(mO instanceof Map)) return "monitor must be an object";
        Map<String, Object> m = IntentJs.obj(mO);
        for (String k : m.keySet()) if (!List.of("id", "kind", "p", "q", "status", "within").contains(k)) return "monitor: unknown member '" + k + "'";
        if (!declIdOk(m.get("id"))) return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype";
        String at = "monitor '" + m.get("id") + "'";
        Object kind = m.get("kind");
        if (!(kind instanceof String) || !MONITOR_KINDS.contains(kind)) return at + ": unknown kind";
        if (!predicateShapeOk(m.get("p"))) return at + ": p must be a predicate";
        boolean needsQ = "requires_prior".equals(kind) || "precedes".equals(kind) || "responds_within".equals(kind);
        if (needsQ != m.containsKey("q")) return at + ": q is required exactly for requires_prior / precedes / responds_within";
        if (m.containsKey("q") && !predicateShapeOk(m.get("q"))) return at + ": q must be a predicate";
        if (m.containsKey("status") && !"admitted".equals(m.get("status")) && !"committed".equals(m.get("status"))) return at + ": status must be admitted or committed";
        if ("responds_within".equals(kind) != m.containsKey("within")) return at + ": within is required exactly for responds_within";
        if (m.containsKey("within") && !(IntentJs.isInt(m.get("within")) && IntentJs.num(m.get("within")) >= 1 && IntentJs.num(m.get("within")) <= MAX_MONITOR_WITHIN))
            return at + ": within must be an integer in 1.." + MAX_MONITOR_WITHIN;
        return null;
    }

    // ---- selection, values, combination ----
    /** The action is selected: its verb is listed, or its schema verb has a parameter feeding {@code sel.accumulates_into}. */
    static boolean accSelects(Map<String, Object> a, String verb, Object schema) {
        Map<String, Object> sel = IntentJs.obj(a.get("sel"));
        if (sel.containsKey("event")) return false;
        if (sel.get("verbs") instanceof List && ((List<?>) sel.get("verbs")).contains(verb)) return true;
        if (sel.containsKey("accumulates_into") && schema != null) {
            Map<String, Object> v = ActionSchema.schemaVerb(schema, verb);
            return v != null && !ActionSchema.accumulationParams(v, (String) sel.get("accumulates_into")).isEmpty();
        }
        return false;
    }

    /** val(omega): {ok, val, key} or {reason}. */
    static final class AccValue {
        final String reason; final long val; final String key;
        AccValue(String reason, long val, String key) { this.reason = reason; this.val = val; this.key = key; }
    }

    static String distinctKey(Object x) {
        if (x instanceof String || IntentJs.isInt(x)) {
            try { return IntentJs.canon(x); } catch (RuntimeException e) { return null; }
        }
        return null;
    }

    static AccValue accValueOf(Map<String, Object> a, String verb, Map<String, Object> params, Object schema) {
        Object agg = a.get("agg");
        if ("count".equals(agg)) return new AccValue(null, 1, null);
        if ("distinct".equals(agg)) {
            String name = ((String) a.get("val")).substring("action.params.".length());
            String k = params.containsKey(name) ? distinctKey(params.get(name)) : null;
            return k == null ? new AccValue(a.get("val") + " must be a string or a safe integer", 0, null) : new AccValue(null, 1, k);
        }
        if (a.containsKey("val")) {
            String name = ((String) a.get("val")).substring("action.params.".length());
            Object x = params.containsKey(name) ? params.get(name) : null;
            return params.containsKey(name) && IntentJs.isNonNeg(x) ? new AccValue(null, IntentJs.lng(x), null) : new AccValue(a.get("val") + " must be a non-negative safe integer", 0, null);
        }
        Map<String, Object> v = schema != null ? ActionSchema.schemaVerb(schema, verb) : null;
        if (v == null) return new AccValue("no schema entry for '" + verb + "' to read accumulates_into", 0, null);
        long s = 0;
        for (String p : ActionSchema.accumulationParams(v, (String) IntentJs.get(a.get("sel"), "accumulates_into"))) {
            String name = p.substring("action.params.".length());
            if (!params.containsKey(name)) continue;
            Object x = params.get(name);
            if (!IntentJs.isNonNeg(x)) return new AccValue(p + " must be a non-negative safe integer", 0, null);
            s += IntentJs.lng(x);
            if (s > 9007199254740991L) return new AccValue("accumulated value exceeds 2^53-1", 0, null);
        }
        return new AccValue(null, s, null);
    }

    private static String want(Object agg) { return "sum".equals(agg) ? "sum" : "count".equals(agg) ? "count" : "max".equals(agg) ? "max" : "values"; }

    static String preStateError(Object agg, Object sO) {
        if (!(sO instanceof Map)) return "pre-state must be an object";
        Map<?, ?> s = (Map<?, ?>) sO;
        String want = want(agg);
        if (s.size() != 1 || !s.containsKey(want)) return "pre-state of a " + agg + " accumulator is {" + want + "}";
        if (want.equals("values")) {
            Object vs = s.get("values");
            if (!(vs instanceof List)) return "pre-state values must be strings";
            for (Object x : (List<?>) vs) if (!(x instanceof String)) return "pre-state values must be strings";
            if (new HashSet<Object>((List<?>) vs).size() != ((List<?>) vs).size()) return "pre-state values must be distinct";
            return null;
        }
        return IntentJs.isNonNeg(s.get(want)) ? null : "pre-state " + want + " must be a non-negative safe integer";
    }

    /** The post-action value (null when it leaves the safe-integer range). */
    static Long combineAcc(Object agg, Map<?, ?> pre, AccValue v) {
        long post;
        switch (String.valueOf(agg)) {
            case "sum": post = IntentJs.lng(pre.get("sum")) + v.val; break;
            case "count": post = IntentJs.lng(pre.get("count")) + 1; break;
            case "max": post = Math.max(IntentJs.lng(pre.get("max")), v.val); break;
            default: {
                List<?> vs = (List<?>) pre.get("values");
                post = vs.size() + (vs.contains(v.key) ? 0 : 1);
            }
        }
        return post <= 9007199254740991L ? post : null;
    }

    static long preValue(Object agg, Map<?, ?> pre) {
        switch (String.valueOf(agg)) {
            case "sum": return IntentJs.lng(pre.get("sum"));
            case "count": return IntentJs.lng(pre.get("count"));
            case "max": return IntentJs.lng(pre.get("max"));
            default: return ((List<?>) pre.get("values")).size();
        }
    }

    // ---- receipts ----
    /** The digest a reservation binds: the PCActn without sig, pq_sig, threshold and intent_session. */
    public static String pcactnReservationDigest(Map<String, Object> p) {
        Map<String, Object> body = new LinkedHashMap<>(p);
        for (String k : new String[] {"sig", "pq_sig", "threshold", "intent_session"}) body.remove(k);
        return IntentJs.ref(ACC_RESERVE_DOMAIN, "b", body);
    }

    static String receiptShapeError(Object rO) {
        if (!(rO instanceof Map)) return "receipt is not an object";
        Map<String, Object> r = IntentJs.obj(rO);
        for (String k : r.keySet()) if (!RECEIPT_KEYS.contains(k)) return "receipt: unknown member '" + k + "'";
        if (!OracleFacts.isOne(r.get("v")) || !"pca-acc-receipt".equals(r.get("kind"))) return "not a pca-acc-receipt v1";
        if (!IntentJs.b32(r.get("session"))) return "receipt.session is not canonical base64url (32 bytes)";
        if (!idOk(r.get("acc"))) return "receipt.acc is not an accumulator id";
        if (!(IntentJs.isInt(r.get("seq")) && IntentJs.num(r.get("seq")) >= 1)) return "receipt.seq must be a safe integer >= 1";
        if (!IntentJs.isNonNeg(r.get("pre")) || !IntentJs.isNonNeg(r.get("delta")) || !IntentJs.isNonNeg(r.get("post"))) return "receipt pre / delta / post must be non-negative safe integers";
        if (!IntentJs.b32(r.get("pcactn_digest"))) return "receipt.pcactn_digest is not canonical base64url (32 bytes)";
        if (!(r.get("aud") instanceof String) || ((String) r.get("aud")).isEmpty()) return "receipt.aud must be a non-empty string";
        if (!IntentJs.isNonNeg(r.get("issued_at")) || !IntentJs.isNonNeg(r.get("expires_at"))) return "receipt.issued_at / expires_at must be non-negative safe integers";
        double ia = IntentJs.num(r.get("issued_at")), ea = IntentJs.num(r.get("expires_at"));
        if (!(ea >= ia && ea - ia <= MAX_RECEIPT_LIFETIME_MS)) return "receipt.expires_at must be within " + MAX_RECEIPT_LIFETIME_MS + " ms after issued_at";
        if (!(r.get("kid") instanceof String) || !KID_RE.matcher((String) r.get("kid")).matches()) return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}";
        Object l = r.get("ledger");
        if (!exactKeys(l, "head", "index") || !IntentJs.isNonNeg(IntentJs.get(l, "index")) || !IntentJs.b32(IntentJs.get(l, "head"))) return "receipt.ledger must be {index, head}";
        if (!IntentJs.b32(r.get("signer"))) return "receipt.signer is not canonical base64url (32 bytes)";
        String rse = IntentJs.suiteError(r.get("alg"), r.containsKey("alg"));
        if (rse != null) return "receipt.alg: " + rse;
        String suite = IntentJs.suiteOf(r);
        if (suite.equals("ed25519") && (r.containsKey("pq_pk") || r.containsKey("pq_sig"))) return "an ed25519 receipt must not carry pq_pk / pq_sig";
        if (!(r.get("sig") instanceof String)) return "receipt.sig must be a string";
        return null;
    }

    private static Map<String, Object> receiptBody(Map<String, Object> r) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid"}) b.put(k, r.get(k));
        Map<String, Object> ledger = new LinkedHashMap<>();
        ledger.put("index", IntentJs.get(r.get("ledger"), "index"));
        ledger.put("head", IntentJs.get(r.get("ledger"), "head"));
        b.put("ledger", ledger);
        b.put("signer", r.get("signer"));
        return b;
    }

    static boolean verifyReceiptSignature(Map<String, Object> r, String expectedSigner, Map<String, Object> pin) {
        try {
            if (receiptShapeError(r) != null || !r.get("signer").equals(expectedSigner)) return false;
            byte[] msg = IntentJs.message(ACC_RECEIPT_DOMAIN, IntentJs.bindSuiteFields(receiptBody(r), r.get("alg"), r.containsKey("alg"), r.get("pq_pk"), r.containsKey("pq_pk")));
            return IntentJs.verifyPinnedSuite(r.get("alg"), r.containsKey("alg"), (String) r.get("signer"), r.get("pq_pk"), msg, r.get("sig"), r.get("pq_sig"), pin);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The receipt's content address (what {@code intent_session.acc[].receipt} carries). */
    public static String receiptDigest(Object r) { return IntentJs.ref(ACC_RECEIPT_REF_DOMAIN, "r", r); }

    static boolean receiptArithmeticOk(Object agg, Map<String, Object> r, long val) {
        long pre = IntentJs.lng(r.get("pre")), delta = IntentJs.lng(r.get("delta")), post = IntentJs.lng(r.get("post"));
        switch (String.valueOf(agg)) {
            case "sum": return delta == val && post == pre + delta;
            case "count": return delta == 1 && post == pre + 1;
            case "max": return delta == val && post == Math.max(pre, delta);
            default: return (delta == 0 || delta == 1) && post == pre + delta;
        }
    }

    // ---- sequencer key sets ----
    static String keySetShapeError(Object kO) {
        if (!(kO instanceof Map)) return "key set is not an object";
        Map<String, Object> k = IntentJs.obj(kO);
        for (String x : k.keySet()) if (!List.of("v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig").contains(x)) return "key set: unknown member '" + x + "'";
        if (!OracleFacts.isOne(k.get("v")) || !"pca-sequencer-keys".equals(k.get("kind"))) return "not a pca-sequencer-keys v1";
        if (!IntentJs.b32(k.get("sequencer"))) return "sequencer is not canonical base64url (32 bytes)";
        if (!(IntentJs.isNonNeg(k.get("version")) && IntentJs.num(k.get("version")) >= 1)) return "version must be a safe integer >= 1";
        if (!IntentJs.isNonNeg(k.get("issued_at"))) return "issued_at must be a non-negative safe integer";
        Object keys = k.get("keys");
        if (!(keys instanceof List) || ((List<?>) keys).isEmpty() || ((List<?>) keys).size() > 256) return "keys must be 1..256 entries";
        Set<String> kids = new HashSet<>();
        for (Object eO : (List<?>) keys) {
            if (!(eO instanceof Map) || !onlyKeys((Map<?, ?>) eO, "kid", "pk", "alg", "pq_pk", "not_before", "not_after")) return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}";
            Map<String, Object> e = IntentJs.obj(eO);
            if (!(e.get("kid") instanceof String) || !KID_RE.matcher((String) e.get("kid")).matches() || !kids.add((String) e.get("kid"))) return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct";
            if (!IntentJs.b32(e.get("pk"))) return "key pk is not canonical base64url (32 bytes)";
            String kse = IntentJs.suiteError(e.get("alg"), e.containsKey("alg"));
            if (kse != null) return "key alg: " + kse;
            if (e.containsKey("pq_pk") && !IntentJs.b64any(e.get("pq_pk"))) return "key pq_pk is not canonical base64url";
            if (!IntentJs.isNonNeg(e.get("not_before"))
                || (e.containsKey("not_after") && !(IntentJs.isNonNeg(e.get("not_after")) && IntentJs.num(e.get("not_after")) >= IntentJs.num(e.get("not_before")))))
                return "key validity must be 0 <= not_before <= not_after";
        }
        String ase = IntentJs.suiteError(k.get("alg"), k.containsKey("alg"));
        if (ase != null) return "alg: " + ase;
        String suite = IntentJs.suiteOf(k);
        if (suite.equals("ed25519") && (k.containsKey("pq_pk") || k.containsKey("pq_sig"))) return "an ed25519 key set must not carry pq_pk / pq_sig";
        if (!(k.get("sig") instanceof String)) return "sig must be a string";
        return null;
    }

    static boolean verifyKeySet(Object kO, String root, Object rootPqPk, boolean rootPqPresent) {
        try {
            if (keySetShapeError(kO) != null) return false;
            Map<String, Object> k = IntentJs.obj(kO);
            if (!root.equals(k.get("sequencer"))) return false;
            Map<String, Object> pin = rootPqPresent ? IntentJs.pin(root, rootPqPk) : null;
            Map<String, Object> body = new LinkedHashMap<>();
            for (String x : new String[] {"v", "kind", "sequencer", "version", "issued_at", "keys"}) body.put(x, k.get(x));
            byte[] msg = IntentJs.message(SEQUENCER_KEYS_DOMAIN, IntentJs.bindSuiteFields(body, k.get("alg"), k.containsKey("alg"), k.get("pq_pk"), k.containsKey("pq_pk")));
            return IntentJs.verifyPinnedSuite(k.get("alg"), k.containsKey("alg"), root, k.get("pq_pk"), msg, k.get("sig"), k.get("pq_sig"), pin);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A key set's content address: {@code base64url(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set})))}. */
    public static String keySetDigest(Object ks) { return IntentJs.ref(SEQUENCER_KEYS_REF_DOMAIN, "k", ks); }

    /** {@code acc.keyset_versions[root]} is exactly {@code {version, digest}}: version a safe integer &gt;= 1, digest 32-byte base64url. Null = ok. */
    static String trackedKeySetError(Object t) {
        if (!(t instanceof Map)) return "a tracked key set must be an object {version, digest}";
        for (Object k : ((Map<?, ?>) t).keySet()) if (!"version".equals(k) && !"digest".equals(k)) return "a tracked key set has the unknown member '" + k + "'";
        Object v = IntentJs.get(t, "version");
        if (!IntentJs.isInt(v) || IntentJs.num(v) < 1) return "a tracked key set version must be a safe integer >= 1";
        if (!IntentJs.b32(IntentJs.get(t, "digest"))) return "a tracked key set digest must be canonical base64url (32 bytes)";
        return null;
    }

    private static boolean nonNegSafe(double d) { return Double.isFinite(d) && d == Math.rint(d) && d >= 0 && d <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(d); }

    /**
     * Verify a receipt against the sequenced holder of S (rule 15 step 3, sequenced). False unless ALL hold: the clock and
     * every bound are safe integers; the receipt is well-formed (lifetime at most 15 min), {@code issued_at <= now + 60 s} and
     * {@code now - issued_at <= maxReceiptAgeMs}; SOME presented key set verifies under {@code holder.root} (PQ: pinned by
     * {@code holder.root_pq_pk}), and, when the verifier tracks {@code {version, digest}} for the root, {@code version >= tracked.version}
     * (no rollback) and at {@code version == tracked.version} the same key-set digest (no equivocation), {@code issued_at <= now + 60 s} and
     * {@code now - issued_at <= maxKeySetAgeMs}, and lists {@code receipt.kid} with {@code pk == receipt.signer},
     * {@code not_before <= receipt.issued_at} and, when {@code not_after} is set, {@code receipt.issued_at <= not_after} AND
     * {@code not_after >= now - 60 s} (a retired key stops verifying), the entry's suite equal to the receipt's; and the
     * receipt verifies under that entry (its PQ key pinned by the entry).
     */
    static boolean verifyReceiptAgainstHolder(Map<String, Object> r, Map<String, Object> holder, Object keySets, double now,
                                              double maxReceiptAgeMs, double maxKeySetAgeMs, Object tracked) {
        if (!(Double.isFinite(now) && now == Math.rint(now) && Math.abs(now) <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(now))) return false;
        if (!nonNegSafe(maxReceiptAgeMs) || !nonNegSafe(maxKeySetAgeMs) || (tracked != null && trackedKeySetError(tracked) != null)) return false;
        if (!(keySets instanceof List) || receiptShapeError(r) != null) return false;
        double issued = IntentJs.num(r.get("issued_at"));
        if (!(issued <= now + RECEIPT_SKEW_MS) || !(now - issued <= maxReceiptAgeMs)) return false;
        String rs = IntentJs.suiteOf(r);
        for (Object kO : (List<?>) keySets) {
            if (!verifyKeySet(kO, (String) holder.get("root"), holder.get("root_pq_pk"), holder.containsKey("root_pq_pk"))) continue;
            if (tracked != null) {
                double v = IntentJs.num(IntentJs.get(kO, "version")), tv = IntentJs.num(IntentJs.get(tracked, "version"));
                if (v < tv || (v == tv && !keySetDigest(kO).equals(IntentJs.get(tracked, "digest")))) continue; // rollback / equivocation
            }
            double ksIssued = IntentJs.num(IntentJs.get(kO, "issued_at"));
            if (!(ksIssued <= now + RECEIPT_SKEW_MS) || !(now - ksIssued <= maxKeySetAgeMs)) continue;
            Map<String, Object> e = null;
            for (Object x : (List<?>) IntentJs.get(kO, "keys")) if (r.get("kid").equals(IntentJs.get(x, "kid"))) { e = IntentJs.obj(x); break; }
            if (e == null || !e.get("pk").equals(r.get("signer")) || issued < IntentJs.num(e.get("not_before"))) continue;
            if (e.containsKey("not_after") && (issued > IntentJs.num(e.get("not_after")) || IntentJs.num(e.get("not_after")) < now - RECEIPT_SKEW_MS)) continue;
            String es = IntentJs.suiteOf(e);
            if (!(es == null ? "ed25519" : es).equals(rs == null ? "x" : rs)) continue;
            Map<String, Object> pin = e.containsKey("pq_pk") ? IntentJs.pin((String) e.get("pk"), e.get("pq_pk")) : null;
            if (verifyReceiptSignature(r, (String) e.get("pk"), pin)) return true;
        }
        return false;
    }
}
