package net.atlasauth.pca;

import static net.atlasauth.pca.Workflow.ID_RE;
import static net.atlasauth.pca.Workflow.LABEL_RE;
import static net.atlasauth.pca.Workflow.NAME_RE;
import static net.atlasauth.pca.Workflow.isB32;
import static net.atlasauth.pca.Workflow.isObj;
import static net.atlasauth.pca.Workflow.isScalarMap;
import static net.atlasauth.pca.Workflow.isStr;
import static net.atlasauth.pca.Workflow.isUint;
import static net.atlasauth.pca.Workflow.l;
import static net.atlasauth.pca.Workflow.m;
import static net.atlasauth.pca.Workflow.onlyKeys;
import static net.atlasauth.pca.Workflow.re;
import static net.atlasauth.pca.Workflow.sortedUnique;
import static net.atlasauth.pca.Workflow.verifyBody;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Read-side authorization (K5, C-310..C-319): what an agent may SEE, proven, and where it may go next. A signed read grant gives
 * per (verb, resource prefix, purpose) a mask mode per data class; {@link #redactRead} applies it to one response, {@link #checkSink}
 * decides whether data read under a chain of read receipts may reach a sink. Tighten-only, total, integers only. Ports
 * packages/pca/src/readside.ts check for check and replays packages/pca/conformance/readside-vectors.json.
 */
public final class ReadSide {
    private ReadSide() {}

    public static final String READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\u0000";
    public static final String READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\u0000";
    private static final String RG_REF = "atlas-pca/read-grant-ref/v1";
    private static final String RR_REF = "atlas-pca/read-receipt-ref/v1";
    private static final String RH = "atlas-pca/read-hash/v1";
    private static final String RT = "atlas-pca/read-token/v1";
    private static final String RV = "atlas-pca/read-value/v1";
    private static final int SALT_MIN = 16;
    private static final Pattern MODE_RE = Pattern.compile("(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})");

    private static boolean isMode(Object x) { return re(MODE_RE, x); }
    private static int rank(String mode) {
        String k = mode.startsWith("bucket:") ? "bucket" : mode;
        switch (k) {
            case "show": return 0;
            case "last4": return 1;
            case "bucket": return 2;
            case "token": return 3;
            case "hash": return 4;
            default: return 5; // drop (modes are validated before they reach here)
        }
    }
    private static List<String> sorted(Set<String> xs) { return new ArrayList<>(new TreeSet<>(xs)); }
    private static boolean bmp(String s) { return s.codePoints().allMatch(c -> c < 0x10000); }
    private static Map<String, Object> dm(String d, Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("d", d);
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    // ---- validation ----

    private static boolean validEntry(Object o) {
        if (!isObj(o) || !onlyKeys(o, List.of("verb", "resource_prefix", "purposes", "modes", "default_mode"))) return false;
        Map<String, Object> e = m(o);
        if (!isStr(e.get("verb"), 128) || !isStr(e.get("resource_prefix"), 512) || !sortedUnique(e.get("purposes"), ID_RE, 16) || l(e.get("purposes")).isEmpty()) return false;
        if (!isObj(e.get("modes")) || m(e.get("modes")).size() > 32 || !isMode(e.get("default_mode"))) return false;
        for (Map.Entry<String, Object> k : m(e.get("modes")).entrySet()) if (!re(LABEL_RE, k.getKey()) || !isMode(k.getValue())) return false;
        return true;
    }

    /** Shape of a read grant body (no signature). */
    public static boolean validReadGrantBody(Object o) {
        if (!isObj(o) || !onlyKeys(o, List.of("v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks"))) return false;
        Map<String, Object> b = m(o);
        if (!Json.isSafeInt(b.get("v")) || Json.asLong(b.get("v")) != 1) return false;
        if (!re(ID_RE, b.get("id")) || !isB32(b.get("principal")) || !isUint(b.get("issued_at")) || !isUint(b.get("expires_at"))) return false;
        if (!(b.get("reads") instanceof List) || l(b.get("reads")).isEmpty() || l(b.get("reads")).size() > 32) return false;
        for (Object e : l(b.get("reads"))) if (!validEntry(e)) return false;
        if (!isObj(b.get("caps")) || m(b.get("caps")).size() > 32) return false;
        for (Map.Entry<String, Object> e : m(b.get("caps")).entrySet()) if (!re(LABEL_RE, e.getKey()) || !isUint(e.getValue())) return false;
        Object s = b.get("sinks");
        if (!isObj(s) || m(s).size() > 16) return false;
        for (Map.Entry<String, Object> e : m(s).entrySet()) {
            Object v = e.getValue();
            if (!re(ID_RE, e.getKey()) || !isObj(v) || !onlyKeys(v, List.of("allow", "escalate")) || !sortedUnique(m(v).get("allow"), LABEL_RE, 16) || !sortedUnique(m(v).get("escalate"), LABEL_RE, 16)) return false;
            for (Object a : l(m(v).get("allow"))) if (l(m(v).get("escalate")).contains(a)) return false;
        }
        return true;
    }

    public static String readGrantDigest(Object body) { return Pca.hashCanonical(dm(RG_REF, "g", body)); }
    public static String readReceiptRef(Object r) { return Pca.hashCanonical(dm(RR_REF, "r", r)); }

    private static Map<String, Object> recBody(Map<String, Object> r) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer"}) b.put(k, r.get(k));
        return b;
    }

    // ---- redaction ----

    /** One field of a read: what happened with it and a salted digest of its value. */
    public static final class Field {
        public final String cls, action, kind, vd;
        Field(String cls, String action, String kind, String vd) { this.cls = cls; this.action = action; this.kind = kind; this.vd = vd; }
        Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("class", cls); o.put("action", action); o.put("kind", kind); o.put("vd", vd);
            return o;
        }
    }

    public static final class Read {
        public final String decision, code;
        public final Map<String, Object> view;
        public final Map<String, Field> fields;
        public final List<String> labels;
        public final Map<String, Long> counts;
        Read(String decision, String code, Map<String, Object> view, Map<String, Field> fields, List<String> labels, Map<String, Long> counts) {
            this.decision = decision; this.code = code; this.view = view; this.fields = fields; this.labels = labels; this.counts = counts;
        }
        /** Plain-map form (integers as Long) for comparing with the shared vectors. */
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("decision", decision); o.put("code", code); o.put("view", view);
            Map<String, Object> f = new LinkedHashMap<>();
            for (Map.Entry<String, Field> e : fields.entrySet()) f.put(e.getKey(), e.getValue().toMap());
            o.put("fields", f); o.put("labels", labels); o.put("counts", new LinkedHashMap<String, Object>(counts));
            return o;
        }
    }

    private static Read out(String decision, String code, Map<String, Long> counts) {
        return new Read(decision, code, new LinkedHashMap<>(), new LinkedHashMap<>(), new ArrayList<>(), counts);
    }

    static final class Graded {
        final Map<String, Object> body;
        final String code;
        Graded(Map<String, Object> body, String code) { this.body = body; this.code = code; }
    }

    static Graded gradeGrant(Object g, Object principal, Object now) {
        if (!isB32(principal) || !isUint(now)) return new Graded(null, "bad_request");
        if (!isObj(g) || !onlyKeys(g, List.of("body", "sig")) || !validReadGrantBody(m(g).get("body"))) return new Graded(null, "bad_grant");
        Map<String, Object> b = m(m(g).get("body"));
        if (!(principal instanceof String) || !principal.equals(b.get("principal")) || !verifyBody(READ_GRANT_DOMAIN, b, principal, m(g).get("sig"))) return new Graded(null, "bad_signature");
        long n = Json.asLong(now);
        if (n < Json.asLong(b.get("issued_at"))) return new Graded(null, "not_yet");
        if (n >= Json.asLong(b.get("expires_at"))) return new Graded(null, "expired");
        return new Graded(b, null);
    }

    private static Map<String, Long> longs(Map<String, Object> src) {
        Map<String, Long> o = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : src.entrySet()) o.put(e.getKey(), Json.asLong(e.getValue()));
        return o;
    }

    /** Apply a read grant to one response. Never throws. */
    @SuppressWarnings("unchecked")
    public static Read redactRead(Object grant, Object principal, Object now, Object verbO, Object resourceO, Object purposeO, Object schema, Object recordO, Object tightenO, Object saltO, Object countsO) {
        try {
            Graded g = gradeGrant(grant, principal, now);
            if (g.code != null) return out("deny", g.code, new LinkedHashMap<>());
            if (!isB32(principal) || !isUint(now) || !isStr(verbO, 128) || !isStr(resourceO, 512) || !re(ID_RE, purposeO) || !(saltO instanceof String) || ((String) saltO).length() < SALT_MIN) return out("deny", "bad_request", new LinkedHashMap<>());
            String verb = (String) verbO, resource = (String) resourceO, purpose = (String) purposeO, salt = (String) saltO;
            if (!isObj(schema) || !isObj(m(schema).get("fields")) || !(m(schema).get("required") instanceof List)) return out("deny", "bad_request", new LinkedHashMap<>());
            Map<String, Object> scFields = m(m(schema).get("fields"));
            for (Map.Entry<String, Object> e : scFields.entrySet()) if (!re(NAME_RE, e.getKey()) || !re(LABEL_RE, e.getValue())) return out("deny", "bad_request", new LinkedHashMap<>());
            List<Object> required = l(m(schema).get("required"));
            for (Object p : required) if (!(p instanceof String) || !scFields.containsKey(p)) return out("deny", "bad_request", new LinkedHashMap<>());
            if (!isScalarMap(recordO) || !isObj(tightenO)) return out("deny", "bad_request", new LinkedHashMap<>());
            for (Map.Entry<String, Object> e : m(tightenO).entrySet()) if (!re(LABEL_RE, e.getKey()) || !isMode(e.getValue())) return out("deny", "bad_request", new LinkedHashMap<>());
            if (!isObj(countsO)) return out("deny", "bad_request", new LinkedHashMap<>());
            for (Map.Entry<String, Object> e : m(countsO).entrySet()) if (!re(LABEL_RE, e.getKey()) || !isUint(e.getValue())) return out("deny", "bad_request", new LinkedHashMap<>());
            Map<String, Object> record = m(recordO), tighten = m(tightenO);
            Map<String, Long> inCounts = longs(m(countsO));
            Map<String, Object> entry = null;
            for (Object eo : l(g.body.get("reads"))) {
                Map<String, Object> e = m(eo);
                if (e.get("verb").equals(verb) && resource.startsWith((String) e.get("resource_prefix")) && l(e.get("purposes")).contains(purpose)) { entry = e; break; }
            }
            if (entry == null) return out("deny", "no_read_scope", inCounts);
            Map<String, Field> fields = new LinkedHashMap<>();
            Map<String, Object> view = new LinkedHashMap<>();
            Map<String, Long> used = new LinkedHashMap<>();
            for (String path : new TreeSet<>(record.keySet())) {
                Object raw = record.get(path);
                Object v = raw instanceof Json.Num ? (Object) Json.asLong(raw) : raw; // scalars validated: String, Boolean or a safe integer
                String cls = (String) scFields.get(path);
                // a field the schema does not classify is never shown
                String vd = Pca.hashCanonical(dm(RV, "salt", salt, "p", path, "v", v));
                if (cls == null) { fields.put(path, new Field("unclassified", "dropped", null, vd)); continue; }
                String mode = m(entry.get("modes")).containsKey(cls) ? (String) m(entry.get("modes")).get(cls) : (String) entry.get("default_mode");
                String t = (String) tighten.get(cls);
                if (t != null && rank(t) > rank(mode)) mode = t;
                Object shown = null;
                String action = "masked";
                String kind = mode.startsWith("bucket:") ? "bucket" : mode;
                if (mode.equals("show")) {
                    shown = v; action = "shown"; kind = null;
                } else if (mode.equals("last4")) {
                    if (v instanceof String && bmp((String) v)) {
                        int[] cps = ((String) v).codePoints().toArray();
                        if (cps.length > 4) shown = "****" + new String(cps, cps.length - 4, 4);
                    }
                } else if (mode.startsWith("bucket:")) {
                    long n = Long.parseLong(mode.substring(7));
                    if (Json.isSafeInt(v) && Json.asLong(v) >= 0) shown = Json.asLong(v) - (Json.asLong(v) % n);
                } else if (mode.equals("hash")) {
                    shown = Pca.hashCanonical(dm(RH, "salt", salt, "c", cls, "v", v));
                } else if (mode.equals("token")) {
                    shown = "tok_" + Pca.hashCanonical(dm(RT, "salt", salt, "c", cls, "v", v)).substring(0, 22);
                }
                if (shown == null) { fields.put(path, new Field(cls, "dropped", null, vd)); continue; }
                fields.put(path, new Field(cls, action, kind, vd));
                view.put(path, shown);
                used.merge(cls, 1L, Long::sum);
            }
            Map<String, Long> counts = new LinkedHashMap<>(inCounts);
            Map<String, Object> caps = m(g.body.get("caps"));
            for (Map.Entry<String, Long> e : used.entrySet()) {
                long total = counts.getOrDefault(e.getKey(), 0L) + e.getValue();
                counts.put(e.getKey(), total);
                Object cap = caps.get(e.getKey());
                if (cap != null && total > Json.asLong(cap)) return out("deny", "read_cap", inCounts);
            }
            for (Object p : required) if (!view.containsKey(p)) return out("escalate", "required_dropped", inCounts);
            Set<String> cl = new TreeSet<>();
            for (Field f : fields.values()) if (!f.action.equals("dropped")) cl.add(f.cls);
            return new Read("allow", null, view, fields, sorted(cl), counts);
        } catch (Exception e) {
            return out("deny", "bad_request", new LinkedHashMap<>());
        }
    }

    // ---- read receipts and sinks ----

    private static boolean validReadReceipt(Object o) {
        if (!isObj(o) || !onlyKeys(o, List.of("v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig"))) return false;
        Map<String, Object> r = m(o);
        if (!Json.isSafeInt(r.get("v")) || Json.asLong(r.get("v")) != 1) return false;
        if (!isB32(r.get("grant")) || !isStr(r.get("verb"), 128) || !isStr(r.get("resource"), 512) || !re(ID_RE, r.get("purpose")) || !isUint(r.get("seq"))) return false;
        Object prev = r.get("prev");
        if (!(prev == null || isB32(prev)) || (Json.asLong(r.get("seq")) == 0) != (prev == null)) return false;
        if (!isUint(r.get("issued_at")) || !isB32(r.get("signer")) || !(r.get("sig") instanceof String) || !sortedUnique(r.get("labels"), LABEL_RE, 32) || !isObj(r.get("fields")) || m(r.get("fields")).size() > 64) return false;
        for (Map.Entry<String, Object> e : m(r.get("fields")).entrySet()) {
            Object f = e.getValue();
            if (!re(NAME_RE, e.getKey()) || !isObj(f) || !onlyKeys(f, List.of("class", "action", "kind", "vd"))) return false;
            Map<String, Object> fm = m(f);
            Object c = fm.get("class"), a = fm.get("action"), k = fm.get("kind");
            if (!(c instanceof String) || !(c.equals("unclassified") || re(LABEL_RE, c))) return false;
            if (!"shown".equals(a) && !"masked".equals(a) && !"dropped".equals(a)) return false;
            if (!(k == null || k instanceof String) || !isB32(fm.get("vd"))) return false;
        }
        return true;
    }

    /** The labels carried by a verified, unbroken chain of read receipts, or an error code (and the offending index). */
    public static final class Chain {
        public final List<String> labels;
        public final String code;
        public final int at;
        Chain(List<String> labels, String code, int at) { this.labels = labels; this.code = code; this.at = at; }
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            if (code == null) o.put("labels", labels);
            else { o.put("code", code); o.put("at", (long) at); }
            return o;
        }
    }

    public static Chain readChainLabels(Object receipts, Object rsSigner, String grantDigest, Object now) {
        if (!(receipts instanceof List)) return new Chain(null, "bad_receipt", 0);
        if (!isUint(now)) return new Chain(null, "bad_receipt", 0);
        long n = Json.asLong(now);
        Set<String> all = new TreeSet<>();
        Map<String, Object> prev = null;
        List<Object> rs = l(receipts);
        for (int i = 0; i < rs.size(); i++) {
            if (!validReadReceipt(rs.get(i))) return new Chain(null, "bad_receipt", i);
            Map<String, Object> r = m(rs.get(i));
            if (!(rsSigner instanceof String) || !rsSigner.equals(r.get("signer")) || !grantDigest.equals(r.get("grant")) || Json.asLong(r.get("seq")) != i || Json.asLong(r.get("issued_at")) > n) return new Chain(null, "bad_receipt", i);
            if ((prev == null ? r.get("prev") != null : !readReceiptRef(prev).equals(r.get("prev"))) || !verifyBody(READ_RECEIPT_DOMAIN, recBody(r), rsSigner, r.get("sig"))) return new Chain(null, "bad_receipt", i);
            // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
            Set<String> want = new TreeSet<>();
            for (Object f : m(r.get("fields")).values()) if (!"dropped".equals(m(f).get("action"))) want.add((String) m(f).get("class"));
            if (!new ArrayList<>(want).equals(l(r.get("labels")))) return new Chain(null, "bad_receipt", i);
            for (Object lab : l(r.get("labels"))) all.add((String) lab);
            prev = r;
        }
        return new Chain(sorted(all), null, -1);
    }

    /** Verdict of {@link #checkSink}. */
    public static final class Sink {
        public final String decision, code;
        public final List<String> labels;
        Sink(String decision, String code, List<String> labels) { this.decision = decision; this.code = code; this.labels = labels; }
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("decision", decision); o.put("code", code); o.put("labels", labels);
            return o;
        }
    }

    private static Sink no(String code) { return new Sink("deny", code, new ArrayList<>()); }

    /** May data read under these receipts reach {@code sink}? Deny on any label the grant does not allow; escalate on an "ask" label. Never throws. */
    public static Sink checkSink(Object grant, Object principal, Object rsSigner, Object now, Object sink, Object receipts) {
        try {
            Graded g = gradeGrant(grant, principal, now);
            if (g.code != null) return no(g.code);
            if (!isB32(rsSigner) || !(sink instanceof String)) return no("bad_request");
            Object rule = m(g.body.get("sinks")).get(sink);
            if (rule == null) return no("unknown_sink");
            Chain c = readChainLabels(receipts, rsSigner, readGrantDigest(g.body), now);
            if (c.code != null) return no(c.code);
            List<Object> allow = l(m(rule).get("allow")), esc = l(m(rule).get("escalate"));
            for (String lab : c.labels) if (!allow.contains(lab) && !esc.contains(lab)) return new Sink("deny", "label_flow", c.labels);
            for (String lab : c.labels) if (esc.contains(lab)) return new Sink("escalate", "label_escalate", c.labels);
            return new Sink("allow", null, c.labels);
        } catch (Exception e) {
            return no("bad_request");
        }
    }
}
