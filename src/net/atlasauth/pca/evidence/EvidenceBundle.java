package net.atlasauth.pca.evidence;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntSupplier;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * The dispute evidence bundle {@code pca-intent-evidence} v1: closed-member shape validation, the deterministic normal form,
 * the commitments-only normal form and the bundle digest. A bundle is a JSON tree (Map / List / String / Boolean /
 * Json.Num / null); every function mirrors the TypeScript export of the same name.
 */
public final class EvidenceBundle {
    private EvidenceBundle() {}

    public static final String EVIDENCE_DOMAIN = "atlas-pca/intent-evidence/v1";

    private static final List<String> TOP_KEYS = Arrays.asList(
        "v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels", "canaries",
        "deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels", "effects", "settlements", "revocation_epochs", "anchors");

    // ---- JavaScript-flavoured helpers (shared by the evidence package) ---------------------------------------------------------

    static boolean isObj(Object v) { return v instanceof Map; }

    static boolean isNegZero(Object v) {
        Double d = JsVal.num(v);
        return d != null && d == 0.0 && Double.doubleToRawLongBits(d) != 0L;
    }

    /** {@code typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0)}. */
    static boolean isInt(Object v) { return JsVal.isSafeInteger(v) && !isNegZero(v); }

    static boolean isNonNegInt(Object v) { return isInt(v) && JsVal.num(v) >= 0; }

    static boolean numIs(Object v, double want) { Double d = JsVal.num(v); return d != null && d == want; }

    /** {@code Object.keys}: array-index keys ascending first, then the others in insertion order. */
    static List<String> jsKeys(Map<?, ?> m) {
        List<String> idx = new ArrayList<>();
        List<String> rest = new ArrayList<>();
        for (Object k : m.keySet()) {
            String s = (String) k;
            if (isArrayIndex(s)) idx.add(s); else rest.add(s);
        }
        Collections.sort(idx, Comparator.comparingLong(Long::parseLong));
        idx.addAll(rest);
        return idx;
    }

    private static boolean isArrayIndex(String s) {
        if (s.isEmpty() || s.length() > 10) return false;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
        if (s.length() > 1 && s.charAt(0) == '0') return false;
        return Long.parseLong(s) < 4294967295L;
    }

    /** {@code JSON.parse(JSON.stringify(v))}: a deep copy with every number as JSON prints it (-0 becomes 0). */
    @SuppressWarnings("unchecked")
    static Object plain(Object v) {
        if (v instanceof Json.Num || v instanceof Double || v instanceof Float) {
            Object n = IntentJs.normalize(v instanceof Float ? Double.valueOf((Float) v) : v);
            return n instanceof Json.Num && "-0".equals(((Json.Num) n).raw) ? new Json.Num("0") : n;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), plain(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(plain(x));
            return out;
        }
        return v;
    }

    /** Sign of {@code a < b ? -1 : a > b ? 1 : 0} for two strings; anything else compares equal. */
    static int cmp(Object a, Object b) {
        if (!(a instanceof String) || !(b instanceof String)) return 0;
        int c = ((String) a).compareTo((String) b);
        return c < 0 ? -1 : c > 0 ? 1 : 0;
    }

    /** {@code a - b || next()}: a zero or NaN difference falls through to the next key. */
    static int by(Object a, Object b, IntSupplier next) {
        Double x = JsVal.num(a);
        Double y = JsVal.num(b);
        double d = x == null || y == null ? Double.NaN : x - y;
        if (d == 0.0 || Double.isNaN(d)) return next.getAsInt();
        return d < 0 ? -1 : 1;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o, String what) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("TypeError: " + what + " is not an object");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object o, String what) {
        if (!(o instanceof List)) throw new IllegalArgumentException("TypeError: " + what + " is not an array");
        return (List<Object>) o;
    }

    // ---- shape ------------------------------------------------------------------------------------------------------------

    private static String closed(Object o, List<String> keys, String where) {
        if (!isObj(o)) return where + " must be an object";
        for (String k : jsKeys((Map<?, ?>) o)) if (!keys.contains(k)) return where + ": unknown member \"" + k + "\"";
        return null;
    }

    private static Object g(Object o, String k) { return ((Map<?, ?>) o).get(k); }

    private static boolean isStr(Object o) { return o instanceof String; }

    private static boolean present(Object o, String k) { return ((Map<?, ?>) o).containsKey(k); }

    /** Closed-member shape validation (unknown members are refused at every level the bundle owns). Null when valid. */
    public static String bundleShapeError(Object b) {
        String top = closed(b, TOP_KEYS, "bundle");
        if (top != null) return top;
        Object x = b;
        if (!numIs(g(x, "v"), 1) || !"pca-intent-evidence".equals(g(x, "kind"))) return "not a pca-intent-evidence v1 bundle";
        String subj = closed(g(x, "subject"), Arrays.asList("pcactn_digest", "aud", "session"), "subject");
        if (subj != null) return subj;
        Object s = g(x, "subject");
        if (!isStr(g(s, "pcactn_digest")) || !isStr(g(s, "aud")) || !isStr(g(s, "session"))) return "subject members must be strings";
        String st = closed(g(x, "statement"), Arrays.asList("commit", "opening"), "statement");
        if (st != null) return st;
        if (!isStr(g(g(x, "statement"), "commit"))) return "statement.commit must be a string";
        Object sr = g(x, "session_root");
        if (!isObj(sr) || !numIs(g(sr, "v"), 1) || !"pca-intent-session".equals(g(sr, "kind"))) return "session_root is not a pca-intent-session v1";
        if (!isStr(g(sr, "session")) || !isStr(g(sr, "intent_ref")) || !isInt(g(sr, "expires_at"))) return "session_root is missing session / intent_ref / expires_at";
        Object pr = g(sr, "principals");
        boolean prOk = pr instanceof List && !((List<?>) pr).isEmpty();
        if (prOk) for (Object p : (List<?>) pr) if (!(isObj(p) && isStr(g(p, "key")))) { prOk = false; break; }
        if (!prOk) return "session_root.principals must be a non-empty key list";
        String sc = closed(g(x, "schema"), Arrays.asList("doc", "anchor"), "schema");
        if (sc != null) return sc;
        Object doc = g(g(x, "schema"), "doc");
        if (!isObj(doc) || !"pca-action-schema".equals(g(doc, "kind")) || !isObj(g(doc, "sig"))) return "schema.doc is not a signed pca-action-schema";
        if (!isObj(g(x, "root_grant"))) return "root_grant must be a capability";
        for (String k : new String[] {"maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors"}) {
            if (!(g(x, k) instanceof List)) return k + " must be an array";
        }
        for (String k : new String[] {"facts", "classifier", "offer_sets", "labels", "settlements"}) {
            if (present(x, k) && !(g(x, k) instanceof List)) return k + " must be an array";
        }
        List<?> maps = (List<?>) g(x, "maps");
        for (int i = 0; i < maps.size(); i++) {
            Object m = maps.get(i);
            String e = closed(m, Arrays.asList("seq", "commit", "map", "disclosed"), "maps[" + i + "]");
            if (e != null) return e;
            if (!isInt(g(m, "seq")) || JsVal.num(g(m, "seq")) < 0 || !isStr(g(m, "commit"))) return "maps[" + i + "] needs an integer seq and a commit";
        }
        List<?> cl = (List<?>) g(x, "canary_labels");
        for (int i = 0; i < cl.size(); i++) {
            Object c = cl.get(i);
            String e = closed(c, Arrays.asList("question_id", "label"), "canary_labels[" + i + "]");
            if (e != null) return e;
            if (!isStr(g(c, "question_id")) || !(numIs(g(c, "label"), 0) || numIs(g(c, "label"), 1))) return "canary_labels[" + i + "] is malformed";
        }
        String cs = closed(g(x, "canaries"), Arrays.asList("asked", "false_yes", "false_no"), "canaries");
        if (cs != null) return cs;
        Object cn = g(x, "canaries");
        if (!(isNonNegInt(g(cn, "asked")) && isNonNegInt(g(cn, "false_yes")) && isNonNegInt(g(cn, "false_no")))) return "canaries counts must be non-negative integers";
        String ac = closed(g(x, "accumulator"), Arrays.asList("holder", "events", "receipts", "sequencer_keys"), "accumulator");
        if (ac != null) return ac;
        Object acc = g(x, "accumulator");
        if (!"site_local".equals(g(acc, "holder")) && !"sequenced".equals(g(acc, "holder"))) return "accumulator.holder must be site_local or sequenced";
        if (!(g(acc, "events") instanceof List)) return "accumulator.events must be an array";
        List<?> evs = (List<?>) g(acc, "events");
        for (int i = 0; i < evs.size(); i++) {
            Object ev = evs.get(i);
            String e = closed(ev, Arrays.asList("acc", "post", "pcactn_digest", "delta", "status"), "accumulator.events[" + i + "]");
            if (e != null) return e;
            if (!isStr(g(ev, "acc")) || !isNonNegInt(g(ev, "post")) || !isStr(g(ev, "pcactn_digest"))) return "accumulator.events[" + i + "] is malformed";
            if (present(ev, "delta") && !isNonNegInt(g(ev, "delta"))) return "accumulator.events[" + i + "].delta must be a non-negative integer";
        }
        if (present(acc, "receipts") && !(g(acc, "receipts") instanceof List)) return "accumulator.receipts must be an array";
        if (present(acc, "sequencer_keys") && !(g(acc, "sequencer_keys") instanceof List)) return "accumulator.sequencer_keys must be an array";
        List<?> re = (List<?>) g(x, "revocation_epochs");
        for (int i = 0; i < re.size(); i++) {
            Object r = re.get(i);
            String e = closed(r, Arrays.asList("epoch", "revoked"), "revocation_epochs[" + i + "]");
            if (e != null) return e;
            if (!isObj(g(r, "epoch")) || !(g(r, "revoked") instanceof List)) return "revocation_epochs[" + i + "] needs an epoch and its revoked list";
        }
        List<?> an = (List<?>) g(x, "anchors");
        for (int i = 0; i < an.size(); i++) {
            String e = closed(an.get(i), Arrays.asList("kind", "digest", "index", "proof", "signed_tree_head"), "anchors[" + i + "]");
            if (e != null) return e;
        }
        List<?> ef = (List<?>) g(x, "effects");
        for (int i = 0; i < ef.size(); i++) {
            Object e = ef.get(i);
            if (!isObj(e) || !isStr(g(e, "pcactn_digest"))) return "effects[" + i + "] needs a pcactn_digest";
        }
        return null;
    }

    // ---- normal form --------------------------------------------------------------------------------------------------------

    private static Object seqOf(Object cap) {
        Object cvs = JsVal.member(cap, "caveats");
        if (!(cvs instanceof List)) throw new IllegalArgumentException("TypeError: caveats.find is not a function");
        for (Object k : (List<?>) cvs) {
            if ("intent_session".equals(JsVal.member(k, "type"))) {
                Object s = JsVal.member(k, "seq");
                return isInt(s) ? s : new Json.Num("9007199254740991");
            }
        }
        return new Json.Num("9007199254740991");
    }

    private static Object mem(Object o, String k) { return JsVal.member(o, k); }

    private static String key(Object v) { return Pca.hashCanonical(v); }

    private static void sortSet(Object arr) {
        if (arr == null || Boolean.FALSE.equals(arr)) return;
        asList(arr, "set").sort((a, c) -> cmp(key(a), key(c)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> withoutParams(Object e) {
        Map<String, Object> k = new LinkedHashMap<>(asMap(e, "effect"));
        k.remove("params");
        return k;
    }

    /**
     * Deterministic normal form. Members that are SETS (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
     * canary labels) are sorted by a content key; {@code accumulator.events} is a SEQUENCE and is never reordered.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> normalizeBundle(Object b) {
        Map<String, Object> x = asMap(plain(b), "bundle");
        asList(x.get("maps"), "maps").sort((a, c) -> by(mem(a, "seq"), mem(c, "seq"), () -> cmp(mem(a, "commit"), mem(c, "commit"))));
        asList(x.get("answers"), "answers").sort((a, c) -> by(mem(a, "observed_at"), mem(c, "observed_at"),
            () -> { int q = cmp(mem(a, "question_id"), mem(c, "question_id")); return q != 0 ? q : cmp(mem(a, "sig"), mem(c, "sig")); }));
        asList(x.get("canary_labels"), "canary_labels").sort((a, c) -> {
            int q = cmp(mem(a, "question_id"), mem(c, "question_id"));
            return q != 0 ? q : by(mem(a, "label"), mem(c, "label"), () -> 0);
        });
        asList(x.get("deltas"), "deltas").sort((a, c) -> by(seqOf(a), seqOf(c), () -> cmp(mem(a, "id"), mem(c, "id"))));
        asList(x.get("pcactns"), "pcactns").sort((a, c) -> by(mem(a, "iat"), mem(c, "iat"),
            () -> by(mem(a, "counter"), mem(c, "counter"), () -> cmp(key(a), key(c)))));
        asList(x.get("verdicts"), "verdicts").sort((a, c) -> {
            int q = cmp(mem(a, "pcactn_digest"), mem(c, "pcactn_digest"));
            return q != 0 ? q : cmp(key(a), key(c));
        });
        asList(x.get("effects"), "effects").sort((a, c) -> {
            int q = cmp(mem(a, "pcactn_digest"), mem(c, "pcactn_digest"));
            return q != 0 ? q : cmp(key(withoutParams(a)), key(withoutParams(c)));
        });
        asList(x.get("revocation_epochs"), "revocation_epochs").sort((a, c) -> by(mem(mem(a, "epoch"), "issued_at"), mem(mem(c, "epoch"), "issued_at"),
            () -> by(mem(mem(a, "epoch"), "epoch"), mem(mem(c, "epoch"), "epoch"), () -> cmp(key(a), key(c)))));
        asList(x.get("anchors"), "anchors").sort((a, c) -> {
            int q = cmp(mem(a, "kind"), mem(c, "kind"));
            return q != 0 ? q : by(mem(a, "index"), mem(c, "index"), () -> cmp(mem(a, "digest"), mem(c, "digest")));
        });
        sortSet(x.get("facts"));
        sortSet(x.get("classifier"));
        sortSet(x.get("offer_sets"));
        sortSet(x.get("labels"));
        sortSet(x.get("settlements"));
        Object acc = mem(x.get("accumulator"), "receipts");
        if (JsVal.truthy(acc)) asList(acc, "receipts").sort((a, c) -> cmp(key(a), key(c)));
        return x;
    }

    /** Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence). */
    public static Map<String, Object> buildEvidenceBundle(Map<String, Object> parts) {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("v", new Json.Num("1"));
        raw.put("kind", "pca-intent-evidence");
        raw.putAll(parts);
        Map<String, Object> b = normalizeBundle(raw);
        String bad = bundleShapeError(b);
        if (bad != null) throw new IllegalArgumentException("buildEvidenceBundle: " + bad);
        return b;
    }

    /** The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> commitmentForm(Object b) {
        Map<String, Object> n = normalizeBundle(b);
        Map<String, Object> out = new LinkedHashMap<>(n);
        out.remove("anchors");
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("commit", mem(n.get("statement"), "commit"));
        out.put("statement", st);
        List<Object> maps = new ArrayList<>();
        for (Object m : asList(n.get("maps"), "maps")) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("seq", mem(m, "seq"));
            e.put("commit", mem(m, "commit"));
            if (m instanceof Map && ((Map<?, ?>) m).containsKey("disclosed")) e.put("disclosed", ((Map<String, Object>) m).get("disclosed"));
            maps.add(e);
        }
        out.put("maps", maps);
        List<Object> effects = new ArrayList<>();
        for (Object e : asList(n.get("effects"), "effects")) effects.add(withoutParams(e));
        out.put("effects", effects);
        return out;
    }

    /** The bundle's content address: H over the commitments-only normal form. */
    public static String evidenceDigest(Object b) {
        // a member the form copies but the bundle lacks is undefined in the reference, and canonicalization refuses it
        Map<String, Object> nb = normalizeBundle(b);
        Object st = nb.get("statement");
        if (!(st instanceof Map) || !((Map<?, ?>) st).containsKey("commit")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        for (Object m : asList(nb.get("maps"), "maps")) {
            if (!(m instanceof Map) || !((Map<?, ?>) m).containsKey("seq") || !((Map<?, ?>) m).containsKey("commit")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        }
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("d", EVIDENCE_DOMAIN);
        w.put("b", commitmentForm(b));
        return Pca.hashCanonical(w);
    }
}
