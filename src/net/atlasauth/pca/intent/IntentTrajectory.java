package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiPredicate;
import java.util.function.Function;
import net.atlasauth.pca.IntentHistory;
import net.atlasauth.pca.IntentTrajectoryBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Trajectory intent as ordinary intent: the augmented outcome space adds to every verb one numeric dimension per accumulator (the value the
 * accumulator would have after the action) and one categorical dimension per monitor (its state), the lift of a candidate action into it, the
 * per-step admission rule, and the accumulators the wallet always adds. Psi, histories and schemas are JSON trees.
 */
public final class IntentTrajectory {
    private IntentTrajectory() {}

    public static final String ACC_DIM_PREFIX = "env.acc.";
    public static final String MON_DIM_PREFIX = "env.mon.";

    public static String accDimPath(String id) { return ACC_DIM_PREFIX + id + ".post"; }

    public static String monDimPath(String id) { return MON_DIM_PREFIX + id + ".state"; }

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static Map<String, Object> m(Object o) { return IntentOmega.obj(o); }

    /** The v2 dimension kind of a path: param, acc, mon, canon, world, rel, prov, class or other. */
    public static String dimKindOf(String path) {
        if (path.startsWith("action.params.")) return "param";
        if (path.startsWith(ACC_DIM_PREFIX)) return "acc";
        if (path.startsWith(MON_DIM_PREFIX)) return "mon";
        if (path.startsWith("env.canon.")) return "canon";
        if (path.startsWith("env.world.")) return "world";
        if (path.startsWith("env.rel.")) return "rel";
        if (path.startsWith("env.prov.")) return "prov";
        if (path.startsWith("env.class.")) return "class";
        return "other";
    }

    private static Map<String, Object> schemaVerb(Object schema, String verb) {
        if (schema == null) return null;
        for (Object v : IntentOmega.arr(m(schema).get("verbs"))) if (verb.equals(m(v).get("verb"))) return m(v);
        return null;
    }

    private static List<String> predicateVerbs(Object verb) {
        List<String> out = new ArrayList<>();
        if (verb instanceof List) for (Object x : (List<?>) verb) out.add((String) x);
        else out.add((String) verb);
        return out;
    }

    private static boolean selects(Map<String, Object> a, String verb, Object schema) {
        Map<String, Object> sel = m(a.get("sel"));
        if (sel.get("verbs") instanceof List && ((List<?>) sel.get("verbs")).contains(verb)) return true;
        if (sel.get("accumulates_into") != null) {
            Map<String, Object> v = schemaVerb(schema, verb);
            return v != null && !IntentTrajectoryBridge.accumulationParams(v, (String) sel.get("accumulates_into")).isEmpty();
        }
        return false;
    }

    /**
     * The augmented space from the outcome space and Psi ({accumulators, monitors}). {@code opts}: cuts? (accumulator id to cuts), scope? ("all" | "selected"),
     * schema? ({verbs}). Wallet-held accumulators are not dimensions.
     */
    public static Omega augmentOmega(Omega omega, Map<String, Object> psi, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? lm() : opts;
        boolean selected = "selected".equals(o.get("scope"));
        Map<String, Object> cutsByAcc = o.get("cuts") == null ? lm() : m(o.get("cuts"));
        List<VerbSpace> verbs = new ArrayList<>();
        for (VerbSpace vs : omega.verbs) {
            List<Dim> extra = new ArrayList<>();
            for (Object ao : IntentOmega.arr(psi.get("accumulators"))) {
                Map<String, Object> a = m(ao);
                if ("wallet".equals(m(a.get("holder")).get("kind"))) continue;
                if (selected && !selects(a, vs.verb, o.get("schema"))) continue;
                if (a.get("domain_max") == null) throw new IllegalArgumentException("augmentOmega: accumulator '" + a.get("id") + "' needs domain_max (A_ψ) to be a dimension of Ω̃");
                double dm = IntentOmega.dbl(a.get("domain_max"));
                TreeSet<Double> cuts = new TreeSet<>();
                if (cutsByAcc.get(a.get("id")) != null) {
                    for (Object c : IntentOmega.arr(cutsByAcc.get(a.get("id")))) {
                        double x = IntentOmega.isNumber(c) ? IntentOmega.dbl(c) : Double.NaN;
                        if (x == Math.floor(x) && Math.abs(x) <= 9007199254740991.0 && x >= 0 && x <= dm) cuts.add(x + 0.0);
                    }
                }
                double[] cs = new double[cuts.size()];
                int i = 0;
                for (double c : cuts) cs[i++] = c;
                extra.add(new NumDim(accDimPath((String) a.get("id")), 0, dm, cs, "loguniform"));
            }
            for (Object mo : IntentOmega.arr(psi.get("monitors"))) {
                Map<String, Object> mon = m(mo);
                if (selected) {
                    boolean keep = mon.get("q") == null ? true : predicateVerbs(m(mon.get("q")).get("verb")).contains(vs.verb) || predicateVerbs(m(mon.get("q")).get("verb")).contains("*");
                    if (!keep) continue;
                }
                List<CatValue> values = new ArrayList<>();
                for (String s : IntentTrajectoryBridge.monitorStates(mon)) values.add(new CatValue("exact", s));
                extra.add(new CatDim(monDimPath((String) mon.get("id")), values));
            }
            List<Dim> dims = new ArrayList<>();
            for (Dim d : vs.dims) if (!dimKindOf(d.path).equals("acc") && !dimKindOf(d.path).equals("mon")) dims.add(d);
            dims.addAll(extra);
            dims.sort((a, b) -> Json.compareUtf8(a.path, b.path));
            verbs.add(new VerbSpace(vs.verb, vs.reversibility, vs.weight, dims));
        }
        return new Omega(verbs, new ArrayList<>(omega.approximate));
    }

    /**
     * lift(history, action, t) as an outcome of the augmented space, or null when the verb is not in it. {@code cand}: verb, resource, params, t.
     * Throws where the accumulator or monitor computation does.
     */
    public static Outcome liftAction(Omega omegaTilde, Map<String, Object> psi, List<Object> history, Map<String, Object> cand, Object schema) {
        VerbSpace vs = null;
        for (VerbSpace v : omegaTilde.verbs) if (v.verb.equals(cand.get("verb"))) { vs = v; break; }
        if (vs == null) return null;
        Map<String, Object> decl = schemaVerb(schema, (String) cand.get("verb"));
        Map<String, Object> params = m(cand.get("params"));
        Map<String, Object> values = lm();
        for (Dim d : vs.dims) {
            String k = dimKindOf(d.path);
            if (k.equals("param")) {
                String name = d.path.substring("action.params.".length());
                Object x = params.containsKey(name) ? params.get(name) : null;
                if (IntentOmega.isNumber(x)) values.put(d.path, IntentOmega.dbl(x));
                else if (x instanceof String) values.put(d.path, x);
            } else if (k.equals("canon")) {
                String name = d.path.substring("env.canon.".length());
                Object pd = decl == null ? null : m(decl.get("params")).get("action.params." + name);
                if (pd != null && params.containsKey(name)) values.put(d.path, IntentSchema.canonValue(m(pd), params.get(name)));
            } else if (k.equals("acc")) {
                String id = d.path.substring(ACC_DIM_PREFIX.length(), d.path.length() - ".post".length());
                for (Object ao : IntentOmega.arr(psi.get("accumulators"))) {
                    if (id.equals(m(ao).get("id"))) {
                        Long post = IntentHistory.accPost(m(ao), history, (String) cand.get("verb"), params, cand.get("t"), schema);
                        if (post == null) throw new IllegalStateException("liftAction: the accumulator '" + id + "' cannot be evaluated for this action");
                        values.put(d.path, (double) post);
                        break;
                    }
                }
            } else if (k.equals("mon")) {
                String id = d.path.substring(MON_DIM_PREFIX.length(), d.path.length() - ".state".length());
                for (Object mo : IntentOmega.arr(psi.get("monitors"))) {
                    if (id.equals(m(mo).get("id"))) {
                        String s = IntentHistory.monitorState(m(mo), history);
                        if (s != null) values.put(d.path, s);
                        break;
                    }
                }
            } else if (d.path.equals("action.resource")) values.put(d.path, cand.get("resource"));
        }
        return new Outcome((String) cand.get("verb"), values);
    }

    /** The space and per-dimension cell of a lifted outcome, or null when it lies outside the space. */
    public record LiftedCell(VerbSpace vs, int[] cell) {}

    public static LiftedCell liftedCell(Omega omegaTilde, Outcome o) {
        VerbSpace vs = null;
        for (VerbSpace v : omegaTilde.verbs) if (v.verb.equals(o.verb())) { vs = v; break; }
        if (vs == null) return null;
        int[] cell = IntentOmega.cellOf(vs, o);
        return cell == null ? null : new LiftedCell(vs, cell);
    }

    /** The result of one step: whether it was admitted, the new history, and the lifted outcome. */
    public record Step(boolean admitted, List<Object> history, Outcome lifted) {}

    /** The trajectory-grant step rule: admit the action iff its lift lies in a cell {@code inGrant} accepts; the history gains a reserved event on admission. */
    public static Step stepTrajectory(Omega omegaTilde, Map<String, Object> psi, List<Object> history, Map<String, Object> cand, BiPredicate<String, int[]> inGrant, Object schema) {
        Outcome lifted = liftAction(omegaTilde, psi, history, cand, schema);
        LiftedCell c = lifted == null ? null : liftedCell(omegaTilde, lifted);
        boolean ok = c != null && inGrant.test((String) cand.get("verb"), c.cell());
        List<Object> next = new ArrayList<>(history);
        if (ok) {
            Map<String, Object> ev = lm();
            ev.put("id", cand.get("id"));
            ev.put("verb", cand.get("verb"));
            ev.put("resource", cand.get("resource"));
            ev.put("params", cand.get("params"));
            ev.put("t", cand.get("t"));
            ev.put("status", "reserved");
            next.add(ev);
        }
        return new Step(ok, next, lifted);
    }

    private static String sanitize(String u) {
        String s = u.replaceAll("[^A-Za-z0-9_]", "_");
        return s.length() > 58 ? s.substring(0, 58) : s;
    }

    /**
     * The accumulators the wallet always adds: a per-task spend sum for every accumulation unit any verb feeds, a per-verb spend sum for every
     * untagged {@code money.amount} integer parameter, and the wallet-held question counter. {@code holder} defaults to site_local.
     */
    public static List<Map<String, Object>> defaultAccumulators(Object schema, double spendDomainMax, Double questionCap, Map<String, Object> holderIn) {
        Map<String, Object> holder = holderIn != null ? holderIn : lm();
        if (holderIn == null) holder.put("kind", "site_local");
        TreeSet<String> units = new TreeSet<>(Json::compareUtf8);
        List<String[]> untagged = new ArrayList<>();
        for (Object vo : IntentOmega.arr(m(schema).get("verbs"))) {
            Map<String, Object> v = m(vo);
            for (Map.Entry<String, Object> e : m(v.get("params")).entrySet()) {
                Map<String, Object> d = m(e.getValue());
                List<Object> into = d.get("accumulates_into") instanceof List ? IntentOmega.arr(d.get("accumulates_into")) : new ArrayList<>();
                for (Object u : into) units.add((String) u);
                if ("integer".equals(d.get("type")) && "money.amount".equals(d.get("semantic")) && into.isEmpty()) untagged.add(new String[] {(String) v.get("verb"), e.getKey()});
            }
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (String u : units) {
            Map<String, Object> a = lm();
            a.put("id", "spend_" + sanitize(u));
            a.put("agg", "sum");
            a.put("unit", u);
            Map<String, Object> sel = lm();
            sel.put("accumulates_into", u);
            a.put("sel", sel);
            Map<String, Object> win = lm();
            win.put("kind", "task");
            a.put("win", win);
            a.put("key", null);
            a.put("domain_max", spendDomainMax);
            a.put("holder", holder);
            out.add(a);
        }
        untagged.sort((x, y) -> Json.compareUtf8(x[0] + x[1], y[0] + y[1]));
        for (String[] u : untagged) {
            Map<String, Object> a = lm();
            String id = "spend_" + sanitize(u[0]) + "_" + sanitize(u[1].substring("action.params.".length()));
            a.put("id", id.length() > 64 ? id.substring(0, 64) : id);
            a.put("agg", "sum");
            a.put("val", u[1]);
            Map<String, Object> sel = lm();
            sel.put("verbs", new ArrayList<Object>(List.of(u[0])));
            a.put("sel", sel);
            Map<String, Object> win = lm();
            win.put("kind", "task");
            a.put("win", win);
            a.put("key", null);
            a.put("domain_max", spendDomainMax);
            a.put("holder", holder);
            out.add(a);
        }
        Map<String, Object> q = lm();
        q.put("id", "questions");
        q.put("agg", "count");
        Map<String, Object> sel = lm();
        sel.put("event", "intent_required");
        q.put("sel", sel);
        Map<String, Object> win = lm();
        win.put("kind", "task");
        q.put("win", win);
        q.put("key", null);
        q.put("cap", questionCap != null ? questionCap : 6.0);
        Map<String, Object> wh = lm();
        wh.put("kind", "wallet");
        q.put("holder", wh);
        out.add(q);
        return out;
    }

    /** The fact line for an accumulator dimension of a cell ({@code fmt}: amount renderer, default the integer; {@code thisAction} may be null). */
    public static String describeAccCell(NumDim d, int cellIndex, String label, Double thisAction, Function<Double, String> fmt) {
        Function<Double, String> f = fmt != null ? fmt : x -> net.atlasauth.pca.AttestCommon.jsNumString(x);
        List<NumCell> cells = IntentOmega.numCells(d);
        if (cellIndex < 0 || cellIndex >= cells.size()) throw new IllegalArgumentException("describeAccCell: no such cell");
        NumCell c = cells.get(cellIndex);
        String range = c.lo() == c.hi() ? "exactly " + f.apply(c.lo()) : "between " + f.apply(c.lo()) + " and " + f.apply(c.hi());
        return label + ": " + range + (thisAction != null ? " (this action: " + f.apply(thisAction) + ")" : "");
    }

    /** The per-session harm range of a trajectory Monte Carlo estimate: [0, L_max * H_max]. */
    public static double trajectoryHarmRange(double maxSessionLength, double harmMax) {
        if (!(maxSessionLength == Math.floor(maxSessionLength) && Math.abs(maxSessionLength) <= 9007199254740991.0 && maxSessionLength >= 0) || !(harmMax >= 0)) throw new IllegalArgumentException("trajectoryHarmRange: bad arguments");
        return maxSessionLength * harmMax;
    }
}
