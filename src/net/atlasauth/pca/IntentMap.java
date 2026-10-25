package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Rule 19 (Intent Layer v2 V15): the committed Intent Map and the Z0 disclosure (packages/pca/src/intent-map-commit.ts
 * {@code commitMap} / {@code decideMapDisclosure}). Every leaf is hashed with its own 32-byte salt and a per-kind tag
 * ({@code SHA-256(TAG_kind || r || strictCanonical(leaf))}), nodes with {@code TAG_NODE}, the tree has the RFC 9162 shape
 * and {@code map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || root))}. The {@code map} check opens the action's
 * header, cell and metrics leaves against the commitment and recomputes the cell of the action. Never throws.
 */
public final class IntentMap {
    private IntentMap() {}

    public static final String MAP_TAG_HEADER = "atlas-pca/intent-map/header/v1\0";
    public static final String MAP_TAG_CELL = "atlas-pca/intent-map/cell/v1\0";
    public static final String MAP_TAG_METRICS = "atlas-pca/intent-map/metrics/v1\0";
    public static final String MAP_TAG_LEARNER = "atlas-pca/intent-map/learner/v1\0";
    public static final String MAP_TAG_NODE = "atlas-pca/intent-map/node/v1\0";
    public static final String MAP_TAG_COMMIT = "atlas-pca/intent-map/commit/v1\0";
    /** The {@code intent_session.map_form} value that selects the committed form. */
    public static final String MAP_FORM_COMMIT = "commit";
    /** The OTHER value of a categorical dimension (U+22A5). */
    public static final String MAP_OTHER = "⊥";
    public static final long MAX_MAP_LEAVES = 1L << 24;
    public static final long MAX_VERB_CELLS = 1L << 20;
    public static final int MAX_MAP_DIMS = 16;
    public static final int MAX_MAP_CUTS = 256;
    public static final int MAX_MAP_VALUES = 256;
    public static final int MAX_MAP_STRING_BYTES = 256;
    static final List<String> METRIC_FIELDS = List.of("residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm",
        "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts");
    private static final Pattern PATH_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}");

    /** The Z0 verdict: when {@code ok}, the action's cell indices, its {@code p_ppm} and the committed residual risk. */
    public static final class Decision {
        public final boolean ok;
        public final String reason;
        public final List<Long> cell;
        public final long pPpm;
        public final long residualRiskPpm;
        Decision(boolean ok, String reason, List<Long> cell, long pPpm, long residualRiskPpm) {
            this.ok = ok; this.reason = reason; this.cell = cell; this.pPpm = pPpm; this.residualRiskPpm = residualRiskPpm;
        }
        static Decision bad(String reason) { return new Decision(false, reason, null, 0, 0); }
    }

    // ---- hashing ----
    static String tagOf(String kind) {
        switch (kind) {
            case "header": return MAP_TAG_HEADER;
            case "cell": return MAP_TAG_CELL;
            case "metrics": return MAP_TAG_METRICS;
            case "learner": return MAP_TAG_LEARNER;
            default: throw new IllegalArgumentException("unknown leaf kind");
        }
    }
    static byte[] u64be(long n) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) { out[i] = (byte) (n & 0xff); n >>>= 8; }
        return out;
    }
    /** SHA-256(TAG_kind || salt || strictCanonical(leaf)); throws on a leaf without a strict canonical form. */
    public static byte[] leafHash(String kind, byte[] salt, Object leaf) {
        if (salt == null || salt.length != 32) throw new IllegalArgumentException("mapLeafHash: the salt is 32 bytes");
        return Pca.sha(IntentJs.utf8(tagOf(kind)), salt, IntentJs.canonBytes(leaf));
    }
    static byte[] nodeHash(byte[] l, byte[] r) { return Pca.sha(IntentJs.utf8(MAP_TAG_NODE), l, r); }
    static String commitOf(long size, byte[] root) { return Pca.b64(Pca.sha(IntentJs.utf8(MAP_TAG_COMMIT), u64be(size), root)); }

    private static long split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }
    private static byte[] treeRoot(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = (int) split(hs.size());
        return nodeHash(treeRoot(hs.subList(0, k)), treeRoot(hs.subList(k, hs.size())));
    }

    /** The {@code primitives.intent_map_commit} entry point: the commitment of a full leaf list {@code [{kind, salt, leaf}]}. */
    public static String commitLeaves(Object leaves) {
        List<?> ls = (List<?>) IntentJs.normalize(leaves);
        if (ls.isEmpty()) throw new IllegalArgumentException("mapTree: empty");
        List<byte[]> hs = new ArrayList<>();
        for (Object l : ls) hs.add(leafHash((String) IntentJs.get(l, "kind"), Pca.decodeB64uStrict(IntentJs.get(l, "salt"), 32), IntentJs.get(l, "leaf")));
        return commitOf(hs.size(), treeRoot(hs));
    }

    /** RFC 9162 §2.1.3.2 inclusion with this file's node hash: the root, or null when the path does not fit (index, size). */
    static byte[] rootFromPath(long index, long size, byte[] leafHash, List<byte[]> path) {
        if (!(index >= 0 && index < size)) return null;
        long fn = index, sn = size - 1;
        byte[] r = leafHash;
        for (byte[] p : path) {
            if (sn == 0) return null;
            if (fn % 2 == 1 || fn == sn) {
                r = nodeHash(p, r);
                if (fn % 2 == 0) while (fn % 2 == 0 && fn != 0) { fn /= 2; sn /= 2; }
            } else {
                r = nodeHash(r, p);
            }
            fn /= 2;
            sn /= 2;
        }
        return sn == 0 ? r : null;
    }

    // ---- leaf shapes (closed and typed) ----
    private static boolean isStr(Object v, int max) { return v instanceof String && !Json.hasLoneSurrogate((String) v) && IntentJs.u8len((String) v) <= max; }
    private static boolean closed(Object o, List<String> allowed, List<String> required) {
        Map<?, ?> m = (Map<?, ?>) o;
        for (Object k : m.keySet()) if (!allowed.contains(k)) return false;
        for (String k : required) if (!m.containsKey(k)) return false;
        return true;
    }
    private static boolean isDimPath(Object p) { return "action.resource".equals(p) || (p instanceof String && PATH_RE.matcher((String) p).matches()); }
    private static long lng(Object o) { return IntentJs.lng(o); }

    /** The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped). */
    static List<long[]> numCells(Map<String, Object> d) {
        List<long[]> out = new ArrayList<>();
        long cur = lng(d.get("lo"));
        for (Object co : (List<?>) d.get("cuts")) {
            long c = lng(co);
            if (cur <= c - 1) out.add(new long[] {cur, c - 1});
            out.add(new long[] {c, c});
            cur = c + 1;
        }
        long hi = lng(d.get("hi"));
        if (cur <= hi) out.add(new long[] {cur, hi});
        return out;
    }
    private static long dimCells(Map<String, Object> d) { return "num".equals(d.get("kind")) ? numCells(d).size() : ((List<?>) d.get("values")).size(); }

    private static String dimError(Object dO, int j) {
        if (!(dO instanceof Map)) return "dims[" + j + "] must be an object";
        Map<String, Object> d = IntentJs.obj(dO);
        Object kind = d.get("kind");
        if ("num".equals(kind)) {
            List<String> ks = List.of("kind", "path", "lo", "hi", "cuts");
            if (!closed(d, ks, ks)) return "dims[" + j + "] must be exactly {kind, path, lo, hi, cuts}";
            if (!isDimPath(d.get("path")) || "action.resource".equals(d.get("path"))) return "dims[" + j + "].path must be action.params.<name>";
            if (!IntentJs.isInt(d.get("lo")) || !IntentJs.isInt(d.get("hi")) || IntentJs.num(d.get("lo")) > IntentJs.num(d.get("hi")))
                return "dims[" + j + "] lo / hi must be safe integers with lo <= hi";
            if (!(d.get("cuts") instanceof List) || ((List<?>) d.get("cuts")).size() > MAX_MAP_CUTS) return "dims[" + j + "].cuts must be an array of at most " + MAX_MAP_CUTS;
            double prev = Double.NEGATIVE_INFINITY;
            for (Object c : (List<?>) d.get("cuts")) {
                if (!IntentJs.isInt(c) || IntentJs.num(c) <= prev || IntentJs.num(c) < IntentJs.num(d.get("lo")) || IntentJs.num(c) > IntentJs.num(d.get("hi")))
                    return "dims[" + j + "].cuts must be strictly increasing safe integers in [lo, hi]";
                prev = IntentJs.num(c);
            }
            return null;
        }
        if ("cat".equals(kind)) {
            List<String> ks = List.of("kind", "path", "values");
            if (!closed(d, ks, ks)) return "dims[" + j + "] must be exactly {kind, path, values}";
            if (!isDimPath(d.get("path"))) return "dims[" + j + "].path must be action.resource or action.params.<name>";
            Object vsO = d.get("values");
            if (!(vsO instanceof List) || ((List<?>) vsO).isEmpty() || ((List<?>) vsO).size() > MAX_MAP_VALUES) return "dims[" + j + "].values must be an array of 1.." + MAX_MAP_VALUES;
            List<?> vs = (List<?>) vsO;
            Set<String> seen = new HashSet<>();
            List<String> vk = List.of("kind", "value");
            for (int i = 0; i < vs.size(); i++) {
                Object v = vs.get(i);
                if (!(v instanceof Map) || !closed(v, vk, vk)) return "dims[" + j + "].values[" + i + "] must be exactly {kind, value}";
                Object k = IntentJs.get(v, "kind"), value = IntentJs.get(v, "value");
                if (!"exact".equals(k) && !"prefix".equals(k) && !"other".equals(k)) return "dims[" + j + "].values[" + i + "].kind must be exact, prefix or other";
                if (!isStr(value, MAX_MAP_STRING_BYTES)) return "dims[" + j + "].values[" + i + "].value must be a string of at most " + MAX_MAP_STRING_BYTES + " UTF-8 bytes";
                boolean badOther = "other".equals(k) ? i != vs.size() - 1 || !MAP_OTHER.equals(value) : "prefix".equals(k) && ((String) value).isEmpty();
                if (badOther) return "dims[" + j + "].values: exactly one other ('" + MAP_OTHER + "'), last; prefixes non-empty";
                if (!seen.add(k + ":" + value)) return "dims[" + j + "].values must be distinct";
            }
            if (!"other".equals(IntentJs.get(vs.get(vs.size() - 1), "kind"))) return "dims[" + j + "].values must end with the other value";
            return null;
        }
        return "dims[" + j + "].kind must be num or cat";
    }

    /** Shape of a header leaf (closed, typed; {@code cells} equals the product of the dimensions' cell counts). Null = well-formed. */
    public static String headerError(Object h) {
        List<String> ks = List.of("verb", "first", "cells", "dims");
        if (!(h instanceof Map) || !closed(h, ks, ks)) return "the header leaf must be exactly {verb, first, cells, dims}";
        Object verb = IntentJs.get(h, "verb");
        if (!isStr(verb, 128) || ((String) verb).isEmpty()) return "header.verb must be a non-empty string of at most 128 UTF-8 bytes";
        Object first = IntentJs.get(h, "first");
        if (!IntentJs.isNonNeg(first) || IntentJs.num(first) >= MAX_MAP_LEAVES) return "header.first must be a leaf index";
        Object cells = IntentJs.get(h, "cells");
        if (!IntentJs.isInt(cells) || IntentJs.num(cells) < 1 || IntentJs.num(cells) > MAX_VERB_CELLS) return "header.cells must be a safe integer in [1, " + MAX_VERB_CELLS + "]";
        Object dims = IntentJs.get(h, "dims");
        if (!(dims instanceof List) || ((List<?>) dims).size() > MAX_MAP_DIMS) return "header.dims must be an array of at most " + MAX_MAP_DIMS;
        Set<Object> paths = new HashSet<>();
        long n = 1;
        List<?> dl = (List<?>) dims;
        for (int j = 0; j < dl.size(); j++) {
            String e = dimError(dl.get(j), j);
            if (e != null) return "header." + e;
            Map<String, Object> d = IntentJs.obj(dl.get(j));
            if (!paths.add(d.get("path"))) return "header.dims paths must be distinct";
            n *= dimCells(d);
            if (n > MAX_VERB_CELLS) return "header: too many cells";
        }
        if (n != IntentJs.num(cells)) return "header.cells is not the product of the dimensions' cell counts";
        return null;
    }

    public static String cellError(Object c) {
        List<String> ks = List.of("verb", "cell", "p_ppm", "in_grant");
        if (!(c instanceof Map) || !closed(c, ks, ks)) return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}";
        Object verb = IntentJs.get(c, "verb");
        if (!isStr(verb, 128) || ((String) verb).isEmpty()) return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes";
        Object cell = IntentJs.get(c, "cell");
        boolean ok = cell instanceof List && ((List<?>) cell).size() <= MAX_MAP_DIMS;
        if (ok) for (Object x : (List<?>) cell) if (!IntentJs.isNonNeg(x)) ok = false;
        if (!ok) return "cell.cell must be an array of non-negative safe integers";
        Object p = IntentJs.get(c, "p_ppm");
        if (!IntentJs.isNonNeg(p) || IntentJs.num(p) > 1_000_000) return "cell.p_ppm must be a safe integer in [0, 1000000]";
        if (!(IntentJs.get(c, "in_grant") instanceof Boolean)) return "cell.in_grant must be a boolean";
        return null;
    }

    public static String metricsError(Object m) {
        List<String> allowed = new ArrayList<>(METRIC_FIELDS);
        allowed.add("log2_vs_mbits");
        if (!(m instanceof Map) || !closed(m, allowed, METRIC_FIELDS)) return "the metrics leaf must be exactly {" + String.join(", ", METRIC_FIELDS) + ", log2_vs_mbits?}";
        for (String k : allowed) {
            if (k.equals("log2_vs_mbits") && !IntentJs.own(m, k)) continue;
            if (!IntentJs.isNonNeg(IntentJs.get(m, k))) return "metrics." + k + " must be a non-negative safe integer";
        }
        return null;
    }

    public static String learnerError(Object l) {
        List<String> ks = List.of("learner_digest");
        if (!(l instanceof Map) || !closed(l, ks, ks)) return "the learner leaf must be exactly {learner_digest}";
        return IntentJs.b32(IntentJs.get(l, "learner_digest")) ? null : "learner.learner_digest must be canonical base64url (32 bytes)";
    }

    /** Cell of ω under a well-formed header: {indices, flat}, or null when a value lies outside its dimension. */
    static long[][] cellOf(Map<String, Object> header, Object resource, Object params) {
        List<?> dims = (List<?>) header.get("dims");
        long[] cell = new long[dims.size()];
        long flat = 0;
        for (int j = 0; j < dims.size(); j++) {
            Map<String, Object> d = IntentJs.obj(dims.get(j));
            String path = (String) d.get("path");
            Object x = path.equals("action.resource") ? resource
                : params instanceof Map && IntentJs.own(params, path.substring("action.params.".length())) ? IntentJs.get(params, path.substring("action.params.".length())) : null;
            boolean present = path.equals("action.resource") || (params instanceof Map && IntentJs.own(params, path.substring("action.params.".length())));
            long i = -1;
            if ("num".equals(d.get("kind"))) {
                if (present && IntentJs.isInt(x)) {
                    double v = IntentJs.num(x);
                    List<long[]> cs = numCells(d);
                    for (int k = 0; k < cs.size(); k++) if (v >= cs.get(k)[0] && v <= cs.get(k)[1]) { i = k; break; }
                }
            } else if (present && x instanceof String && !Json.hasLoneSurrogate((String) x)) {
                String s = (String) x;
                List<?> vs = (List<?>) d.get("values");
                int best = -1, bestLen = -1;
                for (int k = 0; k < vs.size(); k++) {
                    Object vk = IntentJs.get(vs.get(k), "kind");
                    String vv = (String) IntentJs.get(vs.get(k), "value");
                    if ("exact".equals(vk) && vv.equals(s)) { best = k; bestLen = Integer.MAX_VALUE; break; }
                    if ("prefix".equals(vk) && s.startsWith(vv) && vv.length() > bestLen) { best = k; bestLen = vv.length(); }
                }
                i = best >= 0 ? best : vs.size() - 1;
            }
            if (i < 0) return null;
            cell[j] = i;
            flat = flat * dimCells(d) + i;
        }
        return new long[][] {cell, {flat}};
    }

    private static String entryShape(Object e, String what) {
        List<String> ks = List.of("index", "salt", "leaf", "path");
        if (!(e instanceof Map) || !closed(e, ks, ks)) return "disclosure." + what + " must be exactly {index, salt, leaf, path}";
        if (!IntentJs.isNonNeg(IntentJs.get(e, "index"))) return "disclosure." + what + ".index must be a non-negative safe integer";
        if (!IntentJs.b32(IntentJs.get(e, "salt"))) return "disclosure." + what + ".salt must be canonical base64url (32 bytes)";
        Object path = IntentJs.get(e, "path");
        boolean ok = path instanceof List && ((List<?>) path).size() <= 64;
        if (ok) for (Object h : (List<?>) path) if (!IntentJs.b32(h)) ok = false;
        if (!ok) return "disclosure." + what + ".path must be an array of 32-byte digests";
        return null;
    }

    /** Shape of a Z0 disclosure (closed, typed). Null = well-formed. */
    public static String disclosureError(Object d) {
        List<String> ks = List.of("size", "header", "cell", "metrics");
        if (!(d instanceof Map) || !closed(d, ks, ks)) return "the disclosure must be exactly {size, header, cell, metrics}";
        Object size = IntentJs.get(d, "size");
        if (!IntentJs.isInt(size) || IntentJs.num(size) < 4 || IntentJs.num(size) > MAX_MAP_LEAVES) return "disclosure.size must be a safe integer in [4, " + MAX_MAP_LEAVES + "]";
        for (String k : new String[] {"header", "cell", "metrics"}) {
            String e = entryShape(IntentJs.get(d, k), k);
            if (e != null) return e;
        }
        String e = headerError(IntentJs.get(IntentJs.get(d, "header"), "leaf"));
        if (e == null) e = cellError(IntentJs.get(IntentJs.get(d, "cell"), "leaf"));
        if (e == null) e = metricsError(IntentJs.get(IntentJs.get(d, "metrics"), "leaf"));
        return e;
    }

    /** Does the disclosed entry {@code e} (leaf kind {@code kind}) open {@code commit} in a tree of {@code size} leaves? */
    private static boolean opens(String kind, Object e, long size, String commit) {
        try {
            byte[] h = leafHash(kind, Pca.decodeB64uStrict(IntentJs.get(e, "salt"), 32), IntentJs.get(e, "leaf"));
            List<byte[]> path = new ArrayList<>();
            for (Object x : (List<?>) IntentJs.get(e, "path")) path.add(Pca.decodeB64uStrict(x, 32));
            byte[] root = rootFromPath(lng(IntentJs.get(e, "index")), size, h, path);
            return root != null && commitOf(size, root).equals(commit);
        } catch (RuntimeException x) {
            return false;
        }
    }

    /**
     * Z0, the {@code map} check (rule 19) over normalized values. {@code paramsPresent} false = params absent ({}); {@code eps}
     * null = no ε. First failure wins; never throws.
     */
    public static Decision decide(Object mapCommit, Object action, boolean paramsPresent, Object params, Object disclosure, Double eps) {
        try {
            String de = disclosureError(disclosure);
            if (de != null) return Decision.bad("map disclosure malformed: " + de);
            if (!IntentJs.b32(mapCommit)) return Decision.bad("the PCActn carries no map commitment");
            String commit = (String) mapCommit;
            if (paramsPresent && !(params instanceof Map)) return Decision.bad("params must be an object");
            Object ps = paramsPresent ? params : new java.util.LinkedHashMap<String, Object>();
            if (!Pca.paramsDigest(ps).equals(IntentJs.get(action, "params_digest"))) return Decision.bad("the params do not hash to action.params_digest");
            Object hd = IntentJs.get(disclosure, "header"), cd = IntentJs.get(disclosure, "cell"), md = IntentJs.get(disclosure, "metrics");
            Map<String, Object> h = IntentJs.obj(IntentJs.get(hd, "leaf"));
            long size = lng(IntentJs.get(disclosure, "size"));
            long first = lng(h.get("first"));
            if (!h.get("verb").equals(IntentJs.get(action, "verb")))
                return Decision.bad("the disclosed header is not the action's verb");
            if (!(lng(IntentJs.get(hd, "index")) < first) || !(first + lng(h.get("cells")) <= size - 2)) return Decision.bad("the disclosed header does not fit the committed layout");
            if (!opens("header", hd, size, commit)) return Decision.bad("the header leaf does not open the map commitment");
            if (!opens("cell", cd, size, commit)) return Decision.bad("the cell leaf does not open the map commitment");
            if (!opens("metrics", md, size, commit)) return Decision.bad("the metrics leaf does not open the map commitment");
            long[][] w = cellOf(h, IntentJs.get(action, "resource"), ps);
            if (w == null) return Decision.bad("the action's value lies outside the committed map's dimension");
            Map<String, Object> c = IntentJs.obj(IntentJs.get(cd, "leaf"));
            List<?> cc = (List<?>) c.get("cell");
            boolean same = lng(IntentJs.get(cd, "index")) == first + w[1][0] && c.get("verb").equals(h.get("verb")) && cc.size() == w[0].length;
            if (same) for (int i = 0; i < cc.size(); i++) if (lng(cc.get(i)) != w[0][i]) same = false;
            if (!same) return Decision.bad("the disclosed cell is not the action's cell");
            if (!Boolean.TRUE.equals(c.get("in_grant"))) return Decision.bad("the action's cell is outside the committed grant");
            if (lng(IntentJs.get(md, "index")) != size - 2) return Decision.bad("the disclosed metrics leaf is not at its committed position");
            long risk = lng(IntentJs.get(IntentJs.get(md, "leaf"), "residual_risk_ppm"));
            if (eps != null && !(risk <= eps)) return Decision.bad("the committed residual risk " + risk + " ppm exceeds ε = " + eps.longValue());
            List<Long> out = new ArrayList<>();
            for (long x : w[0]) out.add(x);
            return new Decision(true, null, out, lng(c.get("p_ppm")), risk);
        } catch (RuntimeException e) {
            return Decision.bad("map error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /**
     * The {@code primitives.intent_map} entry point: {@code {map_commit, action, params?, disclosure, max_residual_risk_ppm?}}
     * (params absent = {}; ε absent = none).
     */
    public static Decision decidePrimitive(Object input) {
        try {
            Map<String, Object> in = IntentJs.obj(IntentJs.normalize(input));
            Double eps = in.containsKey("max_residual_risk_ppm") ? IntentJs.num(in.get("max_residual_risk_ppm")) : null;
            if (in.containsKey("max_residual_risk_ppm") && eps == null) return Decision.bad("max_residual_risk_ppm must be a number");
            return decide(in.get("map_commit"), in.containsKey("action") ? in.get("action") : new java.util.LinkedHashMap<String, Object>(),
                in.containsKey("params"), in.get("params"), in.get("disclosure"), eps);
        } catch (RuntimeException e) {
            return Decision.bad("map error (fail closed): " + e.getClass().getSimpleName());
        }
    }
}
