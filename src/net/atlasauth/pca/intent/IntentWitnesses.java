package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Specification by example for a fixed grant: boundary facets (admission changes when exactly one dimension moves to an
 * adjacent cell), one verb witness per verb, and one unconstrained witness per dimension the grant ignores. The question count
 * is linear in the number of facets, not in the size of the space.
 */
public final class IntentWitnesses {
    private IntentWitnesses() {}

    /** One question: an action inside or outside the grant, isolating one literal. */
    public record Witness(String kind, String side, String verb, int[] cell, Outcome outcome, boolean grantAllows, String facet, String question) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind);
            m.put("side", side);
            m.put("verb", verb);
            List<Object> c = new ArrayList<>();
            for (int x : cell) c.add(x);
            m.put("cell", c);
            m.put("outcome", IntentOmega.outcomeToJson(outcome));
            m.put("grantAllows", grantAllows);
            m.put("facet", facet);
            m.put("question", question);
            return m;
        }
    }

    public static List<Witness> boundaryWitnesses(Object grant, Omega omega) { return boundaryWitnesses(grant, omega, Catalog.DEFAULT); }

    private static final class Best {
        int[] ins, outs;
        double score;
    }

    public static List<Witness> boundaryWitnesses(Object grant, Omega omega, Catalog catalog) {
        IntentPolicy.Admitter g = IntentPolicy.admitter(grant);
        List<Witness> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (VerbSpace vs : omega.verbs) {
            int n = (int) IntentOmega.verbCellCount(vs);
            boolean[] acc = new boolean[n];
            double[] mass = new double[n];
            int typical = -1;
            int typicalOut = -1;
            for (int c = 0; c < n; c++) {
                int[] idx = IntentOmega.decodeCell(vs, c);
                acc[c] = g.admits(vs, IntentOmega.cellRep(vs, idx));
                mass[c] = IntentOmega.cellStats(vs, idx).mass();
                if (acc[c] && (typical < 0 || mass[c] > mass[typical])) typical = c;
                if (typicalOut < 0 || mass[c] > mass[typicalOut]) typicalOut = c;
            }
            if (typical < 0) {
                push(out, seen, vs, "verb", IntentOmega.decodeCell(vs, typicalOut), false, vs.verb + "|verb", catalog);
                continue;
            }
            int[] base = IntentOmega.decodeCell(vs, typical);
            push(out, seen, vs, "verb", base, true, vs.verb + "|verb", catalog);
            Map<String, Best> best = new HashMap<>();
            for (int c = 0; c < n; c++) {
                if (!acc[c]) continue;
                int[] idx = IntentOmega.decodeCell(vs, c);
                for (int k = 0; k < vs.dims.size(); k++) {
                    Dim d = vs.dims.get(k);
                    int nk = IntentOmega.cellCount(d);
                    List<Integer> neigh = new ArrayList<>();
                    if (d instanceof NumDim) {
                        for (int x : new int[] {idx[k] - 1, idx[k] + 1}) if (x >= 0 && x < nk) neigh.add(x);
                    } else for (int x = 0; x < nk; x++) if (x != idx[k]) neigh.add(x);
                    for (int x : neigh) {
                        int[] j = idx.clone();
                        j[k] = x;
                        int cj = (int) IntentOmega.encodeCell(vs, j);
                        if (acc[cj]) continue;
                        String facet = d instanceof NumDim ? vs.verb + "|" + d.path + "|" + Math.min(x, idx[k]) + "~" + Math.max(x, idx[k]) : vs.verb + "|" + d.path + "|" + x;
                        int shared = 0;
                        for (int t = 0; t < idx.length; t++) if (t != k && idx[t] == base[t]) shared++;
                        double score = shared * 10 + mass[c];
                        Best prev = best.get(facet);
                        if (prev == null || score > prev.score) {
                            Best b = new Best();
                            b.ins = idx;
                            b.outs = j;
                            b.score = score;
                            best.put(facet, b);
                        }
                    }
                }
            }
            List<String> facets = new ArrayList<>(best.keySet());
            facets.sort(String::compareTo);
            for (String facet : facets) {
                push(out, seen, vs, "boundary", best.get(facet).ins, true, facet, catalog);
                push(out, seen, vs, "boundary", best.get(facet).outs, false, facet, catalog);
            }
            for (int k = 0; k < vs.dims.size(); k++) {
                Dim d = vs.dims.get(k);
                int nk = IntentOmega.cellCount(d);
                if (nk < 2) continue;
                boolean depends = false;
                for (int c = 0; c < n && !depends; c++) {
                    int[] idx = IntentOmega.decodeCell(vs, c);
                    for (int x = 0; x < nk && !depends; x++) {
                        int[] j = idx.clone();
                        j[k] = x;
                        if (acc[(int) IntentOmega.encodeCell(vs, j)] != acc[c]) depends = true;
                    }
                }
                if (depends) continue;
                int[] j = base.clone();
                if (d instanceof NumDim) j[k] = nk - 1;
                else {
                    int o = -1;
                    List<IntentOmega.CatValue> vals = ((CatDim) d).values;
                    for (int i = 0; i < vals.size() && o < 0; i++) if (vals.get(i).kind().equals("other")) o = i;
                    j[k] = o;
                }
                push(out, seen, vs, "unconstrained", j, true, vs.verb + "|" + d.path + "|unconstrained", catalog);
            }
        }
        return out;
    }

    private static void push(List<Witness> out, Set<String> seen, VerbSpace vs, String kind, int[] idx, boolean allows, String facet, Catalog catalog) {
        StringBuilder key = new StringBuilder(vs.verb).append('|');
        for (int i = 0; i < idx.length; i++) key.append(i == 0 ? "" : ",").append(idx[i]);
        if (!seen.add(key.toString())) return;
        out.add(new Witness(kind, allows ? "inside" : "outside", vs.verb, idx.clone(), IntentOmega.cellRep(vs, idx), allows, facet, IntentRender.renderQuestion(vs, idx, catalog)));
    }

    /** The oracle's disagreements with the grant, with the number of questions asked. */
    public record WitnessCheck(int questions, List<Witness> mismatches) {}

    /** Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree. */
    public static WitnessCheck checkWitnesses(List<Witness> witnesses, Predicate<Witness> oracle) {
        List<Witness> bad = new ArrayList<>();
        for (Witness w : witnesses) if (oracle.test(w) != w.grantAllows()) bad.add(w);
        return new WitnessCheck(witnesses.size(), bad);
    }
}
