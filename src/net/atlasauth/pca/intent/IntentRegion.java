package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Regions: the part of the outcome space a cell question was about, written in value terms rather than cell indices, so an
 * observation keeps its meaning when the space is refined or lifted onto another organisation's space. Mapping onto a finer
 * space is exact; onto a non-refining one a "yes" claims only the cells wholly inside (inner) and a "no" widens to every
 * cell that meets the region (outer).
 */
public final class IntentRegion {
    private IntentRegion() {}

    /** One restricted dimension: numeric {@code lo..hi} or categorical (reference value list + the listed cell indices). */
    public static final class RegionDim {
        public final String kind;
        public final double lo, hi;
        public final List<CatValue> values;
        public final List<Integer> cells;
        RegionDim(String kind, double lo, double hi, List<CatValue> values, List<Integer> cells) {
            this.kind = kind; this.lo = lo; this.hi = hi; this.values = values; this.cells = cells;
        }
        public static RegionDim num(double lo, double hi) { return new RegionDim("num", lo, hi, null, null); }
        public static RegionDim cat(List<CatValue> values, List<Integer> cells) { return new RegionDim("cat", 0, 0, values, cells); }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind);
            if (kind.equals("num")) {
                m.put("lo", lo);
                m.put("hi", hi);
            } else {
                List<Object> vs = new ArrayList<>();
                for (CatValue v : values) vs.add(IntentOmega.catValueJson(v));
                m.put("values", vs);
                m.put("cells", new ArrayList<Object>(cells));
            }
            return m;
        }

        public static RegionDim fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            if ("num".equals(m.get("kind"))) return num(IntentOmega.dbl(m.get("lo")), IntentOmega.dbl(m.get("hi")));
            List<CatValue> vs = new ArrayList<>();
            for (Object x : IntentOmega.arr(m.get("values"))) vs.add(new CatValue((String) IntentOmega.obj(x).get("kind"), (String) IntentOmega.obj(x).get("value")));
            List<Integer> cs = new ArrayList<>();
            for (Object x : IntentOmega.arr(m.get("cells"))) cs.add((int) IntentOmega.dbl(x));
            return cat(vs, cs);
        }
    }

    public static final class Region {
        public final String verb;
        public final Map<String, RegionDim> dims;
        public Region(String verb, Map<String, RegionDim> dims) { this.verb = verb; this.dims = dims; }

        public Map<String, Object> toJson() {
            Map<String, Object> ds = new LinkedHashMap<>();
            for (Map.Entry<String, RegionDim> e : dims.entrySet()) ds.put(e.getKey(), e.getValue().toJson());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verb", verb);
            m.put("dims", ds);
            return m;
        }

        public static Region fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            Map<String, RegionDim> ds = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : IntentOmega.obj(m.get("dims")).entrySet()) ds.put(e.getKey(), RegionDim.fromJson(e.getValue()));
            return new Region((String) m.get("verb"), ds);
        }
    }

    /** The value-space region of one cell. */
    public static Region regionOfCell(VerbSpace vs, int[] idx) {
        Map<String, RegionDim> dims = new LinkedHashMap<>();
        for (int k = 0; k < vs.dims.size(); k++) {
            Dim d = vs.dims.get(k);
            if (d instanceof NumDim n) {
                NumCell c = IntentOmega.numCells(n).get(idx[k]);
                dims.put(d.path, RegionDim.num(c.lo(), c.hi()));
            } else dims.put(d.path, RegionDim.cat(new ArrayList<>(((CatDim) d).values), new ArrayList<>(List.of(idx[k]))));
        }
        return new Region(vs.verb, dims);
    }

    /** Restrict one dimension: {@code part} is {lo, hi} for a numeric dimension, {cells} for a categorical one. */
    public static Region restrictRegion(Region r, Dim d, Map<String, Object> part) {
        Map<String, RegionDim> dims = new LinkedHashMap<>(r.dims);
        if (d instanceof NumDim && part.containsKey("lo")) dims.put(d.path, RegionDim.num(IntentOmega.dbl(part.get("lo")), IntentOmega.dbl(part.get("hi"))));
        else if (d instanceof CatDim c && part.containsKey("cells")) {
            List<Integer> cs = new ArrayList<>();
            for (Object x : IntentOmega.arr(part.get("cells"))) cs.add((int) IntentOmega.dbl(x));
            dims.put(d.path, RegionDim.cat(new ArrayList<>(c.values), cs));
        } else throw new IllegalArgumentException("restrictRegion: part does not match the kind of " + d.path);
        return new Region(r.verb, dims);
    }

    /** The cells of {@code d} covered by {@code rd}; {@code inner} = wholly inside, else meeting it. */
    public static List<Integer> dimCellsIn(Dim d, RegionDim rd, boolean inner) {
        int n = IntentOmega.cellCount(d);
        List<Integer> all = new ArrayList<>();
        for (int i = 0; i < n; i++) all.add(i);
        if (rd == null) return all;
        List<Integer> out = new ArrayList<>();
        if (d instanceof NumDim nd) {
            if (!rd.kind.equals("num")) throw new IllegalArgumentException("region: " + d.path + " is numeric in the space but categorical in the region");
            for (int i : all) {
                NumCell c = IntentOmega.numCells(nd).get(i);
                if (inner ? c.lo() >= rd.lo && c.hi() <= rd.hi : c.hi() >= rd.lo && c.lo() <= rd.hi) out.add(i);
            }
            return out;
        }
        if (!rd.kind.equals("cat")) throw new IllegalArgumentException("region: " + d.path + " is categorical in the space but numeric in the region");
        CatDim ref = new CatDim(d.path, rd.values);
        Set<Integer> inSet = new HashSet<>(rd.cells);
        for (int i : all) if (inSet.contains(IntentOmega.catCellOf(ref, IntentOmega.catRep((CatDim) d, i)))) out.add(i);
        return out;
    }

    /** Flat cell indices covered by the region (row-major, last dimension fastest); throws on a dimension the verb space lacks. */
    public static List<Long> regionCells(VerbSpace vs, Region r, boolean inner) {
        if (!r.verb.equals(vs.verb)) throw new IllegalArgumentException("region: verb " + r.verb + " does not match " + vs.verb);
        for (String p : r.dims.keySet()) {
            boolean found = false;
            for (Dim d : vs.dims) if (d.path.equals(p)) found = true;
            if (!found) throw new IllegalArgumentException("region: restricts " + p + ", which the space has no dimension for");
        }
        List<List<Integer>> per = new ArrayList<>();
        for (Dim d : vs.dims) per.add(dimCellsIn(d, r.dims.get(d.path), inner));
        for (List<Integer> x : per) if (x.isEmpty()) return new ArrayList<>();
        List<Long> acc = new ArrayList<>();
        acc.add(0L);
        for (int k = 0; k < per.size(); k++) {
            long size = IntentOmega.cellCount(vs.dims.get(k));
            List<Long> next = new ArrayList<>();
            for (long f : acc) for (int c : per.get(k)) next.add(f * size + c);
            acc = next;
        }
        return acc;
    }

    public static boolean valueInRegionDim(String path, RegionDim rd, Object x) {
        if (rd.kind.equals("num")) return x instanceof Double && (Double) x >= rd.lo && (Double) x <= rd.hi;
        return x instanceof String && rd.cells.contains(IntentOmega.catCellOf(new CatDim(path, rd.values), (String) x));
    }
}
