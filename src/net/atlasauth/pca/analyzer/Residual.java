package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs;
import net.atlasauth.pca.analyzer.Enumerate.Probes;
import net.atlasauth.pca.analyzer.Enumerate.Rep;

/**
 * PARTIAL EVALUATION, RESIDUAL POLICIES AND "WHAT MAY I DO?" DISCOVERY. {@code residual(policy, known, {unknown})} specialises the policy
 * to what is known about a request and leaves the unknown parameters symbolic; the residual is itself a policy, evaluated by the same
 * evaluator, and is exact for every completion of the unknowns. Only constants are folded, with the evaluator's own three-valued rules; a
 * veto that reads an unknown field stays and keeps firing. Everything here is advisory and outside the verifier.
 */
public final class Residual {
    private Residual() {}

    private static final String UNKNOWN_VERB = "\u0000unknown-verb\u0000";
    private static final String UNKNOWN_RESOURCE = "\u0000unknown-resource\u0000";

    private static boolean isUnknownPath(Object path, List<String> unknown) {
        if (!(path instanceof String)) return false;
        String p = (String) path;
        for (String u : unknown) if (p.equals(u) || p.startsWith(u + ".") || u.startsWith(p + ".")) return true;
        return false;
    }

    /** A partially evaluated condition: a constant (with its source condition) or a symbolic remainder. */
    private static final class PE {
        final String v; final Object src; final Object c; // v != null: constant
        PE(String v, Object src, Object c) { this.v = v; this.src = src; this.c = c; }
        boolean isConst() { return v != null; }
        Object cond() { return isConst() ? src : c; }
    }

    private static PE cst(String v, Object src) { return new PE(v, src, null); }
    private static PE sym(Object c) { return new PE(null, null, c); }

    private static String triName(Predicates.Tri t) { return t == Predicates.Tri.TRUE ? "true" : t == Predicates.Tri.FALSE ? "false" : "unknown"; }

    private static PE pe(Object c, Map<String, Object> ctx, List<String> unk) {
        if (!(c instanceof Map || c instanceof List)) return cst("unknown", c);
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of")) {
                Object xs = Js.get(c, "all_of");
                if (!(xs instanceof List) || ((List<?>) xs).isEmpty()) return cst("unknown", c);
                List<PE> rs = new ArrayList<>();
                for (Object x : (List<?>) xs) rs.add(pe(x, ctx, unk));
                for (PE r : rs) if (r.isConst() && r.v.equals("false")) return cst("false", c);
                List<PE> kept = new ArrayList<>();
                for (PE r : rs) if (!(r.isConst() && r.v.equals("true"))) kept.add(r);
                if (kept.isEmpty()) return cst("true", c);
                if (allConst(kept)) return cst("unknown", c);
                List<Object> cs = new ArrayList<>();
                for (PE r : kept) cs.add(r.cond());
                return sym(cs.size() == 1 ? cs.get(0) : Js.obj("all_of", cs));
            }
            if (Js.has(c, "any_of")) {
                Object xs = Js.get(c, "any_of");
                if (!(xs instanceof List) || ((List<?>) xs).isEmpty()) return cst("unknown", c);
                List<PE> rs = new ArrayList<>();
                for (Object x : (List<?>) xs) rs.add(pe(x, ctx, unk));
                for (PE r : rs) if (r.isConst() && r.v.equals("true")) return cst("true", c);
                List<PE> kept = new ArrayList<>();
                for (PE r : rs) if (!(r.isConst() && r.v.equals("false"))) kept.add(r);
                if (kept.isEmpty()) return cst("false", c);
                if (allConst(kept)) return cst("unknown", c);
                List<Object> cs = new ArrayList<>();
                for (PE r : kept) cs.add(r.cond());
                return sym(cs.size() == 1 ? cs.get(0) : Js.obj("any_of", cs));
            }
            PE r = pe(Js.get(c, "not"), ctx, unk);
            if (!r.isConst()) return sym(Js.obj("not", r.c));
            return cst(r.v.equals("true") ? "false" : r.v.equals("false") ? "true" : "unknown", c);
        }
        if (Field.isLeaf(c) && (isUnknownPath(Js.get(c, "field"), unk) || isUnknownPath(Js.get(c, "ref"), unk) || isUnknownPath(Js.get(c, "collection"), unk))) return sym(c);
        return cst(triName(Predicates.evaluateConditionTri(c, ctx)), c);
    }

    private static boolean allConst(List<PE> xs) { for (PE r : xs) if (!r.isConst()) return false; return true; }

    /** The AND of a {@code where} list: a constant ("true" / "false" / "unknown") or the symbolic remainder. */
    private static final class PeAll {
        final String v; final List<Object> cs;
        PeAll(String v, List<Object> cs) { this.v = v; this.cs = cs; }
    }

    private static PeAll peAll(Object where, boolean present, Map<String, Object> ctx, List<String> unk) {
        if (!present) return new PeAll("true", null);
        if (!(where instanceof List)) return new PeAll("unknown", null);
        List<PE> rs = new ArrayList<>();
        for (Object w : (List<?>) where) rs.add(pe(w, ctx, unk));
        for (PE r : rs) if (r.isConst() && r.v.equals("false")) return new PeAll("false", null);
        List<PE> kept = new ArrayList<>();
        for (PE r : rs) if (!(r.isConst() && r.v.equals("true"))) kept.add(r);
        if (kept.isEmpty()) return new PeAll("true", null);
        if (allConst(kept)) return new PeAll("unknown", null);
        List<Object> cs = new ArrayList<>();
        for (PE r : kept) cs.add(r.cond());
        return new PeAll(null, cs);
    }

    private static Map<String, Object> contextOf(Object k) {
        Object v = Js.get(k, "verb"), r = Js.get(k, "resource");
        Map<String, Object> action = Js.obj("verb", v != null ? v : UNKNOWN_VERB, "resource", r != null ? r : UNKNOWN_RESOURCE, "params", Js.copy(Js.get(k, "params")));
        if (Js.has(k, "reversibilityClass")) action.put("reversibility_class", Js.get(k, "reversibilityClass"));
        return Js.obj("action", action, "subject", Js.copy(Js.get(k, "subject")), "env", Js.copy(Js.get(k, "env")));
    }

    /** hashCanonical of a policy: the digest a PCActn cites to say which policy it was planned against. */
    public static String policyDigestOf(PolicyModel model) {
        List<Object> meet = new ArrayList<>();
        for (PolicyModel m : model.meets) meet.add(policyDigestOf(m));
        return Pca.hashCanonical(Js.obj("predicates", model.predicates, "caveats", model.caveats, "vetoes", model.vetoes, "tighten", model.tighten, "meet", meet));
    }

    private static void flatten(PolicyModel m, List<PolicyModel> out) {
        out.add(m);
        for (PolicyModel x : m.meets) flatten(x, out);
    }

    private static Map<String, Object> verbResource(Object verb, boolean hasVerb, Object resource, boolean hasResource) {
        Map<String, Object> m = Js.obj();
        if (hasVerb) m.put("verb", verb);
        if (hasResource) m.put("resource", resource);
        return m;
    }

    private static Map<String, Object> residualPart(PolicyModel part, Map<String, Object> ctx, List<String> unk, boolean verbKnown, boolean resKnown) {
        List<Object> predicates = new ArrayList<>();
        for (Object p : part.predicates) {
            if (!(p instanceof Map || p instanceof List)) continue;
            if (verbKnown && !Predicates.predicateMatches(verbResource(Js.get(p, "verb"), Js.has(p, "verb"), "*", true), ctx)) continue;
            if (resKnown && !Predicates.predicateMatches(verbResource("*", true, Js.get(p, "resource"), Js.has(p, "resource")), ctx)) continue;
            PeAll w = peAll(Js.get(p, "where"), Js.has(p, "where"), ctx, unk);
            if (w.v != null && !w.v.equals("true")) continue; // false and unknown both fail closed for a permit
            Map<String, Object> np = Js.obj();
            if (verbKnown) np.put("verb", "*"); else Js.putIf(np, "verb", p, "verb");
            if (!resKnown && Js.has(p, "resource")) np.put("resource", Js.get(p, "resource"));
            if (w.cs != null) np.put("where", w.cs);
            predicates.add(np);
        }
        List<Object> vetoes = new ArrayList<>();
        for (Object v : part.vetoes) {
            Map<String, Object> r = peVeto(v, ctx, unk, verbKnown, resKnown);
            if (r != null) vetoes.add(r);
        }
        List<Object> tighten = new ArrayList<>();
        for (Object t : part.tighten) {
            PE r = pe(Js.get(t, "when"), ctx, unk);
            if (r.isConst() && r.v.equals("false")) continue; // a veto-polarity rule that cleanly cannot hold
            Map<String, Object> nt = Js.copy(t);
            nt.put("when", !r.isConst() ? r.c : Js.get(t, "when"));
            tighten.add(nt);
        }
        return Js.obj("predicates", predicates, "caveats", part.caveats, "vetoes", vetoes, "tighten", tighten);
    }

    private static Map<String, Object> peVeto(Object v, Map<String, Object> ctx, List<String> unk, boolean verbKnown, boolean resKnown) {
        Object when = Js.req(Js.get(v, "when"));
        if (verbKnown && !Predicates.predicateMatches(verbResource(Js.get(when, "verb"), Js.has(when, "verb"), "*", true), ctx)) return null;
        if (resKnown && Js.has(when, "resource") && !Predicates.predicateMatches(verbResource("*", true, Js.get(when, "resource"), true), ctx)) return null;
        PeAll w = peAll(Js.get(when, "where"), Js.has(when, "where"), ctx, unk);
        // veto polarity: a clean false removes the veto; true and unknown mean it applies
        if (w.v != null && w.v.equals("false")) return null;
        Map<String, Object> nw = Js.obj();
        if (verbKnown) nw.put("verb", "*"); else Js.putIf(nw, "verb", when, "verb");
        if (!resKnown && Js.has(when, "resource")) nw.put("resource", Js.get(when, "resource"));
        if (w.cs != null) nw.put("where", w.cs);
        Map<String, Object> out = Js.obj();
        Js.putIf(out, "id", v, "id");
        Js.putIf(out, "kind", v, "kind");
        out.put("when", nw);
        Object over = Js.get(v, "over");
        if (Js.truthy(over)) {
            if (isUnknownPath(Js.get(over, "path"), unk)) out.put("over", over);
            else {
                Predicates.Resolved r = Predicates.resolvePath(ctx, Js.get(over, "path"));
                boolean isOver = !r.found || !Js.isFin(r.value) || Js.num(r.value) < 0 || Js.num(r.value) > (Js.has(over, "threshold") ? Js.toNum(Js.get(over, "threshold")) : Double.NaN);
                if (!isOver) return null;
            }
        }
        Object unless = Js.get(v, "unless");
        if (Js.truthy(unless) && "approval".equals(Js.get(v, "kind"))) out.put("unless", unless); // the evidence of approval: carried, never used to drop the veto
        else if (Js.truthy(unless)) {
            PeAll u = peAll(unless, true, ctx, unk);
            if (u.cs != null) out.put("unless", u.cs);
            else if ("true".equals(u.v)) return null; // the exception certainly holds: the veto never applies
            // an exception that certainly fails (false / unknown) leaves the veto unconditional
        }
        return out;
    }

    /**
     * Specialise {@code policy} to {@code known} ({verb, resource, params, subject, env, reversibilityClass}); everything under
     * {@code opts.unknown} (default {@code ["action.params"]}) stays symbolic. Returns {decision: never | always | conditional, reason?,
     * policy, policyDigest}.
     */
    public static Map<String, Object> residual(Object policy, Map<String, Object> known, Map<String, Object> opts) {
        PolicyModel model = Enumerate.toModel(policy);
        String digest = policyDigestOf(model);
        boolean verbKnown = Js.has(known, "verb");
        boolean resKnown = Js.has(known, "resource") && !Boolean.TRUE.equals(Js.get(opts, "resourceUnknown"));
        List<String> unk = new ArrayList<>();
        Object uo = Js.get(opts, "unknown");
        if (uo == null) unk.add("action.params");
        else for (Object u : Js.list(uo)) {
            if (!(u instanceof String)) throw new IllegalArgumentException("unknown path is not a string");
            unk.add((String) u);
        }
        if (!verbKnown) unk.add("action.verb");
        if (!resKnown) unk.add("action.resource");
        Map<String, Object> ctx = contextOf(known);
        if (!model.caveatSat) return never("caveats unsatisfiable: " + (model.caveatReason != null ? model.caveatReason : "unknown"), digest);
        if (Js.has(known, "reversibilityClass") && model.revCap != null) {
            Object rc = Js.get(known, "reversibilityClass");
            int idx = rc instanceof String ? Analyzer.REVERSIBILITY_ORDER.indexOf(rc) : -1;
            if (idx < 0 || idx > model.revCap) return never("reversibility class exceeds the caveat cap", digest);
        }
        List<PolicyModel> flat = new ArrayList<>();
        flatten(model, flat);
        List<Map<String, Object>> parts = new ArrayList<>();
        for (PolicyModel m : flat) parts.add(residualPart(m, ctx, unk, verbKnown, resKnown));
        Map<String, Object> policyOut = Js.copy(parts.get(0));
        if (parts.size() > 1) policyOut.put("meet", new ArrayList<Object>(parts.subList(1, parts.size())));
        Map<String, Object> res = Js.obj("decision", "conditional", "policy", policyOut, "policyDigest", digest);
        for (Map<String, Object> p : parts) if (Js.list(p.get("predicates")).isEmpty()) return never("no permit survives the known facts", digest);
        for (Map<String, Object> p : parts) {
            for (Object v : Js.list(p.get("vetoes"))) {
                Object w = Js.get(v, "when");
                boolean noWhere = !Js.has(w, "where") || (Js.get(w, "where") instanceof List && ((List<?>) Js.get(w, "where")).isEmpty());
                boolean noRes = !Js.has(w, "resource") || "*".equals(Js.get(w, "resource"));
                if ("deny".equals(Js.get(v, "kind")) && noRes && noWhere && !Js.has(v, "unless") && !Js.has(v, "over")) {
                    return never("veto " + CaveatAnalysis.jsString(Js.get(v, "id"), Js.has(v, "id")) + " applies to every completion", digest);
                }
            }
        }
        boolean always = true;
        for (Map<String, Object> p : parts) {
            boolean anyOpen = false;
            for (Object x : Js.list(p.get("predicates"))) if (!Js.has(x, "where")) anyOpen = true;
            if (!(anyOpen && Js.list(p.get("vetoes")).isEmpty() && Js.list(p.get("tighten")).isEmpty())) { always = false; break; }
        }
        if (always) res.put("decision", "always");
        return res;
    }

    private static Map<String, Object> never(String reason, String digest) {
        Map<String, Object> empty = Js.obj("predicates", new ArrayList<Object>(), "caveats", new ArrayList<Object>(), "vetoes", new ArrayList<Object>(), "tighten", new ArrayList<Object>());
        return Js.obj("decision", "never", "reason", reason, "policy", empty, "policyDigest", digest);
    }

    /** The residual as a policy the analyzer and the real evaluator both understand. */
    public static Map<String, Object> residualPolicy(Map<String, Object> r) {
        Map<String, Object> own = Js.copy(Js.get(r, "policy"));
        Object meet = own.remove("meet");
        if (Js.truthy(meet)) {
            List<Object> ms = new ArrayList<>();
            for (Object m : Js.list(meet)) ms.add(Js.copy(m));
            own.put("meet", ms);
        }
        return own;
    }

    /** Ternary decision of a residual once the unknown fields are bound: {@code ctx} is {action: {verb, resource, params?, reversibility_class?}, subject?, env?}. */
    public static String evaluateResidual(Map<String, Object> r, Map<String, Object> ctx) {
        if ("never".equals(Js.get(r, "decision"))) return "deny";
        Object action = Js.req(Js.get(ctx, "action"));
        Map<String, Object> a = Js.obj();
        Js.putIf(a, "verb", action, "verb");
        Js.putIf(a, "resource", action, "resource");
        if (Js.truthy(Js.get(action, "params"))) a.put("params", Js.get(action, "params"));
        if (Js.truthy(Js.get(ctx, "subject"))) a.put("subject", Js.get(ctx, "subject"));
        if (Js.truthy(Js.get(ctx, "env"))) a.put("env", Js.get(ctx, "env"));
        if (Js.truthy(Js.get(action, "reversibility_class"))) a.put("reversibilityClass", Js.get(action, "reversibility_class"));
        return Enumerate.decideAction(Enumerate.toModel(residualPolicy(r)), a);
    }

    // ---- "what may I do?" ----

    /** A numeric range; null bounds are open (undefined). */
    private static final class NumRange {
        Double lo, hi; boolean loInc, hiInc;
        NumRange(Double lo, Double hi, boolean loInc, boolean hiInc) { this.lo = lo; this.hi = hi; this.loInc = loInc; this.hiInc = hiInc; }
        NumRange copy() { return new NumRange(lo, hi, loInc, hiInc); }
        Map<String, Object> toJson() {
            Map<String, Object> m = Js.obj();
            if (lo != null) m.put("lo", Js.n(lo));
            if (hi != null) m.put("hi", Js.n(hi));
            if (loInc) m.put("loInclusive", true);
            if (hiInc) m.put("hiInclusive", true);
            return m;
        }
    }

    private static double or(Double d, double dflt) { return d == null ? dflt : d; }

    private static List<NumRange> mergeRanges(List<NumRange> rs) {
        List<NumRange> sorted = new ArrayList<>(rs);
        sorted.sort((a, b) -> {
            double d = or(a.lo, Double.NEGATIVE_INFINITY) - or(b.lo, Double.NEGATIVE_INFINITY);
            if (!Double.isNaN(d) && d != 0) return d < 0 ? -1 : 1;
            return Integer.compare((b.loInc ? 1 : 0) - (a.loInc ? 1 : 0), 0);
        });
        List<NumRange> out = new ArrayList<>();
        for (NumRange r : sorted) {
            NumRange last = out.isEmpty() ? null : out.get(out.size() - 1);
            double lastHi = last == null ? 0 : or(last.hi, Double.POSITIVE_INFINITY);
            double rLo = or(r.lo, Double.NEGATIVE_INFINITY);
            if (last != null && lastHi >= rLo && !(lastHi == rLo && !last.hiInc && !r.loInc)) {
                double rHi = or(r.hi, Double.POSITIVE_INFINITY);
                if (rHi > lastHi || (rHi == lastHi && r.hiInc)) {
                    last.hi = r.hi; // null when r.hi is undefined
                    last.hiInc = r.hiInc;
                }
            } else out.add(r.copy());
        }
        return out;
    }

    private static NumRange cellRange(double value, List<Double> T) {
        if (T.contains(value == 0 ? 0.0 : value)) return new NumRange(value, value, true, true);
        Double below = null, above = null;
        for (int i = T.size() - 1; i >= 0; i--) if (T.get(i) < value) { below = T.get(i); break; }
        for (Double t : T) if (t > value) { above = t; break; }
        return new NumRange(below, above, false, false);
    }

    private static final class Seen {
        final Object value; boolean allow, escalate;
        Seen(Object value) { this.value = value; }
    }

    /**
     * Per verb shape ({verb, params: {name: {type?, values?, min?, max?, ...}}}): is it autonomous, approval-only or denied for the known
     * principal, and which parameter values are still allowed. Enumerates the grid of the residual policy (exact on the decided fragment;
     * otherwise {@code approximate}). Options: remaining, missingDischarges, maxCombinations.
     */
    public static List<Object> whatMayIDo(Object policy, List<Object> verbs, Map<String, Object> known, Map<String, Object> o) {
        List<Object> out = new ArrayList<>();
        double max = Js.isNum(Js.get(o, "maxCombinations")) ? Js.num(Js.get(o, "maxCombinations")) : Enumerate.DEFAULT_MAX_COMBINATIONS;
        for (Object shape : verbs) {
            Object verb = Js.get(Js.req(shape), "verb");
            Map<String, Object> k2 = Js.copy(known);
            k2.put("verb", verb);
            Map<String, Object> res = residual(policy, k2, null);
            Map<String, Object> env = Js.obj("verb", verb, "status", "denied", "params", new LinkedHashMap<String, Object>(),
                "resources", Js.obj("autonomous", new ArrayList<Object>(), "withApproval", new ArrayList<Object>(), "other", false),
                "policyDigest", res.get("policyDigest"), "advisory", true);
            if (Js.truthy(Js.get(o, "remaining"))) env.put("remaining", Js.copy(Js.get(o, "remaining")));
            if (Js.truthy(Js.get(o, "missingDischarges"))) env.put("missingDischarges", new ArrayList<>(Js.list(Js.get(o, "missingDischarges"))));
            if ("never".equals(res.get("decision"))) {
                env.put("reason", res.get("reason"));
                out.add(env);
                continue;
            }
            PolicyModel rp = Enumerate.toModel(residualPolicy(res));
            Map<String, Object> sparams = Js.copy(Js.get(shape, "params"));
            List<String> declared = Js.keys(sparams);
            ProbeInputs in = new ProbeInputs();
            in.predicateSets.add(Enumerate.probeSet(rp));
            for (String name : declared) {
                Object d = sparams.get(name);
                String path = "action.params." + name;
                if (Js.has(d, "values")) in.extraFieldConditions.add(new Object[] {path, Js.obj("field", path, "op", "in", "value", Js.get(d, "values"))});
            }
            for (String name : declared) {
                Object d = sparams.get(name);
                String path = "action.params." + name;
                if (Js.has(d, "min")) in.extraFieldConditions.add(new Object[] {path, Js.obj("field", path, "op", "gte", "value", Js.get(d, "min"))});
                if (Js.has(d, "max")) in.extraFieldConditions.add(new Object[] {path, Js.obj("field", path, "op", "lte", "value", Js.get(d, "max"))});
            }
            in.varyReversibility = rp.revCap != null;
            Probes pr = Enumerate.collectProbes(in);
            pr.verbs = new ArrayList<>();
            pr.verbs.add(verb);
            if (Enumerate.productSize(pr) > max) {
                env.put("status", "needs-approval");
                env.put("approximate", true);
                env.put("reason", "representative grid exceeded the bound; no domain is claimed");
                out.add(env);
                continue;
            }
            if (Js.has(known, "resource")) { pr.resources = new ArrayList<>(); pr.resources.add(Js.get(known, "resource")); }
            Map<String, Map<String, Seen>> seen = new LinkedHashMap<>();
            Map<String, Seen> resSeen = new LinkedHashMap<>();
            boolean[] flags = new boolean[3]; // anyAllow, anyEscalate, freshResAllow
            Enumerate.forEachRep(pr, rep -> {
                String d = Enumerate.decide(rp, rep);
                if (d.equals("deny")) return false;
                if (d.equals("allow")) flags[0] = true; else flags[1] = true;
                Map<String, Object> act = Enumerate.repToAction(rep);
                Map<String, Object> ap = Js.copy(act.get("params"));
                for (String name : declared) {
                    Map<String, Seen> m = seen.computeIfAbsent(name, x -> new LinkedHashMap<>());
                    boolean present = ap.containsKey(name);
                    String key = present ? Js.stringify(ap.get(name)) : "\u0000absent";
                    Seen cur = m.computeIfAbsent(key, x -> new Seen(present ? ap.get(name) : ABSENT_VALUE));
                    if (d.equals("allow")) cur.allow = true; else cur.escalate = true;
                }
                String res0 = (String) act.get("resource");
                Seen rr = resSeen.computeIfAbsent(res0, x -> new Seen(null));
                if (d.equals("allow")) rr.allow = true; else rr.escalate = true;
                if (res0.startsWith("\u0000")) flags[2] = true;
                return false;
            });
            env.put("status", flags[0] ? "autonomous" : flags[1] ? "needs-approval" : "denied");
            Map<String, Object> penv = Js.map(env.get("params"));
            for (String name : declared) {
                Object decl = sparams.get(name);
                String path = "action.params." + name;
                List<Double> T = Exposure.thresholds(rp, path);
                Map<String, Seen> m = seen.getOrDefault(name, new LinkedHashMap<>());
                List<Seen> vals = new ArrayList<>(m.values());
                Object dmin = Js.get(decl, "min"), dmax = Js.get(decl, "max");
                boolean hasMin = Js.has(decl, "min"), hasMax = Js.has(decl, "max");
                List<Seen> nums = new ArrayList<>(), strs = new ArrayList<>();
                for (Seen x : vals) {
                    if (Js.isNum(x.value) && (!hasMin || Js.num(x.value) >= Js.toNum(dmin)) && (!hasMax || Js.num(x.value) <= Js.toNum(dmax))) nums.add(x);
                    if (x.value instanceof String) strs.add(x);
                }
                if ("integer".equals(Js.get(decl, "type")) || !nums.isEmpty()) {
                    penv.put(name, Js.obj("kind", "numeric",
                        "autonomous", ranges(nums, T, hasMin, dmin, hasMax, dmax, x -> x.allow),
                        "withApproval", ranges(nums, T, hasMin, dmin, hasMax, dmax, x -> x.escalate && !x.allow)));
                } else if (Js.has(decl, "values") || !strs.isEmpty()) {
                    Seen fresh = null;
                    for (Seen x : strs) if (((String) x.value).startsWith("\u0000")) { fresh = x; break; }
                    boolean noValues = !Js.has(decl, "values");
                    penv.put(name, Js.obj("kind", "enum",
                        "autonomous", pickList(strs, x -> x.allow),
                        "withApproval", pickList(strs, x -> x.escalate && !x.allow),
                        "otherAutonomous", noValues && fresh != null && fresh.allow,
                        "otherWithApproval", noValues && fresh != null && fresh.escalate && !fresh.allow));
                } else penv.put(name, Js.obj("kind", "unconstrained"));
            }
            List<String> auto = new ArrayList<>(), appr = new ArrayList<>();
            for (Map.Entry<String, Seen> e : resSeen.entrySet()) {
                if (e.getKey().startsWith("\u0000")) continue;
                if (e.getValue().allow) auto.add(e.getKey());
                if (e.getValue().escalate && !e.getValue().allow) appr.add(e.getKey());
            }
            Collections.sort(auto);
            Collections.sort(appr);
            env.put("resources", Js.obj("autonomous", new ArrayList<Object>(auto), "withApproval", new ArrayList<Object>(appr), "other", flags[2]));
            if (!rp.undecidable.isEmpty()) {
                env.put("approximate", true);
                env.put("reason", "over-approximated (" + String.join("; ", rp.undecidable) + ")");
            }
            out.add(env);
        }
        return out;
    }

    private static final Object ABSENT_VALUE = new Object();

    private static List<Object> pickList(List<Seen> strs, java.util.function.Predicate<Seen> f) {
        List<String> l = new ArrayList<>();
        for (Seen x : strs) if (f.test(x) && !((String) x.value).startsWith("\u0000")) l.add((String) x.value);
        Collections.sort(l);
        return new ArrayList<Object>(l);
    }

    private static List<Object> ranges(List<Seen> nums, List<Double> T, boolean hasLo, Object lo, boolean hasHi, Object hi, java.util.function.Predicate<Seen> pick) {
        List<NumRange> rs = new ArrayList<>();
        for (Seen x : nums) {
            if (!pick.test(x)) continue;
            NumRange r = cellRange(Js.num(x.value), T);
            if (hasLo && (r.lo == null || r.lo < Js.toNum(lo))) { r.lo = Js.toNum(lo); r.loInc = true; }
            if (hasHi && (r.hi == null || r.hi > Js.toNum(hi))) { r.hi = Js.toNum(hi); r.hiInc = true; }
            rs.add(r);
        }
        List<Object> out = new ArrayList<>();
        for (NumRange r : mergeRanges(rs)) out.add(r.toJson());
        return out;
    }
}
