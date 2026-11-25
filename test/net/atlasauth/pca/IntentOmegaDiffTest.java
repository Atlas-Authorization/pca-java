package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.intent.IntentDerive;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentPolicy;
import net.atlasauth.pca.intent.IntentRegion;
import org.junit.jupiter.api.Test;

class IntentOmegaDiffTest {
    private static final String M = "ref-intent-omega";

    private static double d(Object o) { return IntentOmega.dbl(o); }

    private static int i(Object o) { return (int) d(o); }

    private static Dim dim(Object o) { return IntentOmega.dimFromJson(o); }

    private static VerbSpace vs(Object o) { return IntentOmega.verbSpaceFromJson(o); }

    private static Outcome out(Object o) { return IntentOmega.outcomeFromJson(o); }

    private static List<Object> ints(int[] a) { List<Object> l = new ArrayList<>(); for (int x : a) l.add(x); return l; }

    private static int[] idx(Object o) {
        List<?> l = (List<?>) o;
        int[] a = new int[l.size()];
        for (int k = 0; k < a.length; k++) a[k] = i(l.get(k));
        return a;
    }

    private static Object value(Object o) { return IntentOmega.isNumber(o) ? (Object) d(o) : o; }

    private static Map<String, Object> stats(IntentOmega.Stats s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mass", s.mass());
        m.put("harm", s.harm());
        return m;
    }

    private static boolean inner(Object o) { return "inner".equals(o); }

    private static Map<String, Object> asMap(Object o) { return IntentOmega.obj(o); }

    @Test void deriveOmega() throws Exception { OracleCases.each(M, "deriveOmega", a -> IntentOmega.omegaToJson(IntentDerive.deriveOmega(asMap(a.get(0))))); }

    @Test void harmMax() throws Exception { OracleCases.each(M, "harmMax", a -> IntentOmega.harmMax(IntentOmega.omegaFromJson(a.get(0)))); }

    @Test void verbSpace() throws Exception {
        OracleCases.each(M, "verbSpace", a -> {
            VerbSpace v = IntentOmega.verbSpace(IntentOmega.omegaFromJson(a.get(0)), (String) a.get(1));
            return v == null ? null : IntentOmega.verbSpaceToJson(v);
        });
    }

    @Test void verbCellCount() throws Exception { OracleCases.each(M, "verbCellCount", a -> IntentOmega.verbCellCount(vs(a.get(0)))); }

    @Test void decodeCell() throws Exception { OracleCases.each(M, "decodeCell", a -> ints(IntentOmega.decodeCell(vs(a.get(0)), d(a.get(1))))); }

    @Test void encodeCell() throws Exception { OracleCases.each(M, "encodeCell", a -> IntentOmega.encodeCell(vs(a.get(0)), idx(a.get(1)))); }

    @Test void cellRep() throws Exception { OracleCases.each(M, "cellRep", a -> IntentOmega.outcomeToJson(IntentOmega.cellRep(vs(a.get(0)), idx(a.get(1))))); }

    @Test void cellStats() throws Exception { OracleCases.each(M, "cellStats", a -> stats(IntentOmega.cellStats(vs(a.get(0)), idx(a.get(1))))); }

    @Test void cellOf() throws Exception {
        OracleCases.each(M, "cellOf", a -> {
            int[] r = IntentOmega.cellOf(vs(a.get(0)), out(a.get(1)));
            return r == null ? null : ints(r);
        });
    }

    @Test void harmOf() throws Exception { OracleCases.each(M, "harmOf", a -> IntentOmega.harmOf(vs(a.get(0)), out(a.get(1)))); }

    @Test void cellCount() throws Exception { OracleCases.each(M, "cellCount", a -> IntentOmega.cellCount(dim(a.get(0)))); }

    @Test void numCells() throws Exception {
        OracleCases.each(M, "numCells", a -> {
            List<Object> l = new ArrayList<>();
            for (IntentOmega.NumCell c : IntentOmega.numCells((NumDim) dim(a.get(0)))) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("lo", c.lo());
                m.put("hi", c.hi());
                l.add(m);
            }
            return l;
        });
    }

    @Test void numRep() throws Exception { OracleCases.each(M, "numRep", a -> IntentOmega.numRep((NumDim) dim(a.get(0)), i(a.get(1)))); }

    @Test void repValue() throws Exception { OracleCases.each(M, "repValue", a -> IntentOmega.repValue(dim(a.get(0)), i(a.get(1)))); }

    @Test void catRep() throws Exception { OracleCases.each(M, "catRep", a -> IntentOmega.catRep((IntentOmega.CatDim) dim(a.get(0)), i(a.get(1)))); }

    @Test void catCellOf() throws Exception { OracleCases.each(M, "catCellOf", a -> IntentOmega.catCellOf((IntentOmega.CatDim) dim(a.get(0)), (String) a.get(1))); }

    @Test void cellOfValue() throws Exception { OracleCases.each(M, "cellOfValue", a -> IntentOmega.cellOfValue(dim(a.get(0)), value(a.get(1)))); }

    @Test void dimCellStats() throws Exception { OracleCases.each(M, "dimCellStats", a -> stats(IntentOmega.dimCellStats(dim(a.get(0)), i(a.get(1))))); }

    @Test void intervalWeight() throws Exception { OracleCases.each(M, "intervalWeight", a -> IntentOmega.intervalWeight((NumDim) dim(a.get(0)), d(a.get(1)), d(a.get(2)))); }

    @Test void rngSeq() throws Exception {
        OracleCases.each(M, "rngSeq", a -> {
            DoubleSupplier r = IntentOmega.rng(d(a.get(0)));
            List<Object> l = new ArrayList<>();
            for (int k = i(a.get(1)); k > 0; k--) l.add(r.getAsDouble());
            return l;
        });
    }

    @Test void sampleOutcomes() throws Exception {
        OracleCases.each(M, "sampleOutcomes", a -> {
            IntentOmega.Omega om = IntentOmega.omegaFromJson(a.get(0));
            DoubleSupplier r = IntentOmega.rng(d(a.get(1)));
            List<Object> l = new ArrayList<>();
            for (int k = i(a.get(2)); k > 0; k--) l.add(IntentOmega.outcomeToJson(IntentOmega.sampleOutcome(om, r).o()));
            return l;
        });
    }

    @Test void normalizePolicy() throws Exception { OracleCases.each(M, "normalizePolicy", a -> IntentPolicy.normalizePolicy(a.get(0))); }

    @Test void slotsToPolicy() throws Exception { OracleCases.each(M, "slotsToPolicy", a -> IntentDerive.slotsToPolicy(a.get(0))); }

    @Test void outcomeToAction() throws Exception { OracleCases.each(M, "outcomeToAction", a -> IntentPolicy.outcomeToAction(vs(a.get(0)), out(a.get(1)))); }

    @Test void admits() throws Exception { OracleCases.each(M, "admits", a -> IntentPolicy.admitter(a.get(0)).admits(vs(a.get(1)), out(a.get(2)))); }

    @Test void regionOfCell() throws Exception { OracleCases.each(M, "regionOfCell", a -> IntentRegion.regionOfCell(vs(a.get(0)), idx(a.get(1))).toJson()); }

    @Test void regionCells() throws Exception {
        OracleCases.each(M, "regionCells", a -> IntentRegion.regionCells(vs(a.get(0)), IntentRegion.Region.fromJson(a.get(1)), inner(a.get(2))));
    }

    @Test void dimCellsIn() throws Exception {
        OracleCases.each(M, "dimCellsIn", a -> IntentRegion.dimCellsIn(dim(a.get(0)), a.get(1) == null ? null : IntentRegion.RegionDim.fromJson(a.get(1)), inner(a.get(2))));
    }

    @Test void restrictRegion() throws Exception {
        OracleCases.each(M, "restrictRegion", a -> IntentRegion.restrictRegion(new IntentRegion.Region("v", new LinkedHashMap<>()), dim(a.get(0)), asMap(a.get(1))).toJson());
    }

    @Test void valueInRegionDim() throws Exception {
        OracleCases.each(M, "valueInRegionDim", a -> IntentRegion.valueInRegionDim((String) a.get(0), IntentRegion.RegionDim.fromJson(a.get(1)), value(a.get(2))));
    }
}
