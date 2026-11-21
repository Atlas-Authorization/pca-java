package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Cell coordinates and the wallet's own outcome space. A site names a question's cell by coordinates (an inclusive cell-index
 * range per numeric dimension, a value set per categorical one); the wallet resolves them against ITS OWN copy of the outcome
 * space and refuses anything it cannot resolve exactly: an unknown dimension, an index out of range, an unknown value, or a
 * dimension of the verb the coordinates leave out. A cell box is {@code int[][]}: per dimension the allowed cell indices
 * (sorted, de-duplicated).
 */
public final class WalletBox {
    private WalletBox() {}

    /** The outcome of {@link #resolveCoords}: ok with the verb space and the box, or a refusal reason. */
    public static final class BoxResult {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> vs;
        public final int[][] box;

        BoxResult(String reason) { this.ok = false; this.reason = reason; this.vs = null; this.box = null; }

        BoxResult(Map<String, Object> vs, int[][] box) { this.ok = true; this.reason = null; this.vs = vs; this.box = box; }

        /** {ok, reason} or {ok, verb, box} (the verb space itself is omitted). */
        public Map<String, Object> toMap() {
            if (!ok) return Wallet.obj("ok", false, "reason", reason);
            return Wallet.obj("ok", true, "verb", vs.get("verb"), "box", boxList(box));
        }
    }

    public static List<Object> boxList(int[][] box) {
        List<Object> out = new ArrayList<>();
        for (int[] ids : box) out.add(WalletNoise.idxList(ids));
        return out;
    }

    public static int[][] boxOf(Object o) {
        List<?> l = (List<?>) o;
        int[][] b = new int[l.size()][];
        for (int i = 0; i < b.length; i++) b[i] = WalletNoise.idxOf(l.get(i));
        return b;
    }

    private static final Pattern ACC = Pattern.compile("env\\.acc\\.([A-Za-z0-9_.-]+)\\.post");
    private static final Pattern MON = Pattern.compile("env\\.mon\\.([A-Za-z0-9_.-]+)\\.state");
    private static final Pattern PROV = Pattern.compile("env\\.prov\\.([^\\n\\r\\u2028\\u2029]+)");
    private static final Pattern WORLD = Pattern.compile("env\\.world\\.([A-Za-z0-9_.-]+)");

    /** The coordinate key of a dimension path (the spec's short aliases for lifted dimensions). */
    public static String coordKeyOf(String path) {
        Matcher m = ACC.matcher(path);
        if (m.matches()) return m.group(1);
        m = MON.matcher(path);
        if (m.matches()) return "mon:" + m.group(1);
        m = PROV.matcher(path);
        if (m.matches()) return "prov:" + m.group(1);
        m = WORLD.matcher(path);
        if (m.matches()) return m.group(1);
        return path;
    }

    /** The label of categorical value i of a dimension, as used in coordinates: its raw value. */
    public static String catLabel(Map<String, Object> d, int i) { return (String) WalletOmega.value(d, i).get("value"); }

    /** {@code JSON.stringify} of a string. */
    public static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    boolean lone = Character.isSurrogate(c) && !((Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)))
                        || (Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(s.charAt(i - 1))));
                    if (c < 0x20 || lone) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    /** Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once. */
    @SuppressWarnings("unchecked")
    public static BoxResult resolveCoords(Map<String, Object> omega, String verb, Map<String, Object> coords) {
        Map<String, Object> vs = WalletOmega.verbSpace(omega, verb);
        if (vs == null) return new BoxResult("verb " + verb + " is not in the wallet's outcome space");
        int nd = WalletOmega.dims(vs).size();
        Map<String, Integer> byKey = new HashMap<>();
        for (int k = 0; k < nd; k++) {
            String path = (String) WalletOmega.dim(vs, k).get("path");
            byKey.put(path, k);
            byKey.put(coordKeyOf(path), k);
        }
        Set<Integer> named = new HashSet<>();
        for (String key : coords.keySet()) {
            Integer k = byKey.get(key);
            if (k == null) return new BoxResult("unknown dimension " + key);
            if (named.contains(k)) return new BoxResult("dimension " + WalletOmega.dim(vs, k).get("path") + " is named twice");
            named.add(k);
        }
        int[][] box = new int[nd][];
        for (int k = 0; k < nd; k++) {
            Map<String, Object> d = WalletOmega.dim(vs, k);
            String path = (String) d.get("path");
            Object c = coords.get(path);
            if (c == null) {
                String ck = coordKeyOf(path);
                c = coords.get(ck);
                // an explicit null reaches the member access (a TypeError there); only an absent key is "left out"
                if (c == null && !coords.containsKey(ck)) return new BoxResult("coordinates leave out dimension " + path);
            }
            if (c == null) throw new IllegalArgumentException("Cannot read properties of null (reading '" + ("num".equals(d.get("kind")) ? "length" : "every") + "')");
            if ("num".equals(d.get("kind"))) {
                List<?> cl = c instanceof List ? (List<?>) c : null;
                if (!(cl != null && cl.size() == 2 && JsVal.isNumber(cl.get(0)) && JsVal.isNumber(cl.get(1)))) return new BoxResult("dimension " + path + " is numeric: expected an index range");
                double lo = JsVal.num(cl.get(0)), hi = JsVal.num(cl.get(1));
                boolean ok = lo == Math.rint(lo) && hi == Math.rint(hi) && !Double.isInfinite(lo) && !Double.isInfinite(hi) && !JsVal.isNegZero(cl.get(0)) && !JsVal.isNegZero(cl.get(1))
                    && lo >= 0 && lo <= hi && hi < WalletOmega.numCells(d).size();
                if (!ok) return new BoxResult("index range of " + path + " is out of range");
                int[] ids = new int[(int) (hi - lo) + 1];
                for (int i = 0; i < ids.length; i++) ids[i] = (int) lo + i;
                box[k] = ids;
            } else {
                if (!(c instanceof List)) throw new IllegalArgumentException("c.every is not a function");
                List<?> cl = (List<?>) c;
                for (Object x : cl) if (!(x instanceof String)) return new BoxResult("dimension " + path + " is categorical: expected a value set");
                TreeSet<Integer> ids = new TreeSet<>();
                for (Object lab : cl) {
                    int hits = 0, hit = -1;
                    List<Object> vals = WalletOmega.values(d);
                    for (int j = 0; j < vals.size(); j++) if (lab.equals(WalletOmega.value(d, j).get("value"))) { hits++; hit = j; }
                    if (hits == 0) return new BoxResult("unknown value " + jsonString((String) lab) + " for " + path);
                    if (hits > 1) return new BoxResult("value " + jsonString((String) lab) + " names two cells of " + path);
                    ids.add(hit);
                }
                int[] arr = new int[ids.size()];
                int n = 0;
                for (int i : ids) arr[n++] = i;
                box[k] = arr;
            }
        }
        return new BoxResult(vs, box);
    }

    /** The coordinates of a box (the inverse of resolveCoords; numeric sides must be contiguous). */
    public static Map<String, Object> coordsOfBox(Map<String, Object> vs, int[][] box) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
            Map<String, Object> d = WalletOmega.dim(vs, k);
            int[] ids = box[k];
            if ("num".equals(d.get("kind"))) {
                int lo = Integer.MAX_VALUE, hi = Integer.MIN_VALUE;
                for (int i : ids) { lo = Math.min(lo, i); hi = Math.max(hi, i); }
                if (hi - lo + 1 != ids.length) throw new IllegalArgumentException("coordsOfBox: numeric side of " + d.get("path") + " is not contiguous");
                out.put((String) d.get("path"), new ArrayList<Object>(Arrays.asList((long) lo, (long) hi)));
            } else {
                List<Object> labels = new ArrayList<>();
                for (int i : ids) labels.add(catLabel(d, i));
                out.put((String) d.get("path"), labels);
            }
        }
        return out;
    }

    /** Coordinates of one cell. */
    public static Map<String, Object> coordsOfCell(Map<String, Object> vs, int[] idx) {
        int[][] box = new int[idx.length][];
        for (int i = 0; i < idx.length; i++) box[i] = new int[] {idx[i]};
        return coordsOfBox(vs, box);
    }

    public static boolean cellInBox(int[][] box, int[] idx) {
        if (box.length != idx.length) return false;
        for (int k = 0; k < box.length; k++) {
            boolean in = false;
            for (int i : box[k]) if (i == idx[k]) in = true;
            if (!in) return false;
        }
        return true;
    }

    /** Every cell (per-dimension indices) of a box, in lexicographic order. */
    public static List<int[]> boxCells(int[][] box) {
        List<int[]> out = new ArrayList<>();
        out.add(new int[0]);
        for (int[] ids : box) {
            List<int[]> next = new ArrayList<>();
            for (int[] pre : out) for (int i : ids) {
                int[] c = Arrays.copyOf(pre, pre.length + 1);
                c[pre.length] = i;
                next.add(c);
            }
            out = next;
        }
        return out;
    }

    public static double boxSize(int[][] box) {
        double n = 1;
        for (int[] ids : box) n *= ids.length;
        return n;
    }

    /** The cell of a concrete action in the wallet's outcome space (null when it falls outside: fail closed). */
    public static final class CellAtVs {
        public final Map<String, Object> vs;
        public final int[] idx;

        CellAtVs(Map<String, Object> vs, int[] idx) { this.vs = vs; this.idx = idx; }

        public Map<String, Object> toMap() { return Wallet.obj("verb", vs.get("verb"), "idx", WalletNoise.idxList(idx)); }
    }

    public static CellAtVs cellOfAction(Map<String, Object> omega, Map<String, Object> a) {
        Map<String, Object> vs = WalletOmega.verbSpace(omega, a.get("verb"));
        if (vs == null) return null;
        Object values = a.get("values");
        if (!WalletOmega.dims(vs).isEmpty() && !(values instanceof Map) && !(values instanceof List)) {
            // `path in primitive` throws in the reference (absent is "undefined", an explicit null "null")
            String shown = !a.containsKey("values") ? "undefined" : values == null ? "null" : JsVal.num(values) != null ? WalletCard.jsNum(JsVal.num(values)) : String.valueOf(values);
            throw new IllegalArgumentException("Cannot use 'in' operator to search for '" + WalletOmega.dim(vs, 0).get("path") + "' in " + shown);
        }
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
            if (!(values instanceof Map) || !((Map<?, ?>) values).containsKey(WalletOmega.dim(vs, k).get("path"))) return null;
        }
        int[] idx = WalletOmega.cellOf(vs, Wallet.obj("verb", a.get("verb"), "values", values));
        return idx == null ? null : new CellAtVs(vs, idx);
    }

    /** Flat lexicographic index of a cell (the tie-breaker "cell index"). */
    public static double flatIndex(Map<String, Object> vs, int[] idx) {
        double f = 0;
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) f = f * WalletOmega.cellCount(WalletOmega.dim(vs, k)) + idx[k];
        return f;
    }
}
