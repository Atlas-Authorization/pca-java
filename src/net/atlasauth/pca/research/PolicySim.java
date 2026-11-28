package net.atlasauth.pca.research;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.Risk;

/**
 * Policy simulation and linting: before a principal enables a grant, replay a batch of historical or hypothetical actions against the
 * compiled policy (which auto-admit, which force a human step-up, which are denied) and run static lints for the classic mistakes. Pure,
 * offline, and mutating nothing: it composes the compiled policy's predicates and caveats with the trust-budget algebra. A planning tool:
 * the resource server's verifier remains the authority at run time.
 */
public final class PolicySim {
    private PolicySim() {}

    private static final List<String> REVERSIBILITY_ORDER = List.of("reversible", "rate_limited", "irreversible");

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static double clamp01(double x) { return Math.max(0, Math.min(1, x)); }

    private static double num(Object o) { return Js.d(o); }

    private static double cost(double r, double kappa) { return nz(kappa) * clamp01(Double.isNaN(r) || Double.isInfinite(r) ? 1 : r); }

    private static double jsNumber(Map<String, Object> params, String field) {
        Object v = params == null ? null : params.get(field);
        boolean present = params != null && params.containsKey(field);
        if (!present) return Double.NaN;
        if (v == null) return 0;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        Double d = net.atlasauth.pca.StoreJs.dbl(v);
        if (d != null) return d;
        if (v instanceof String || v instanceof List) return jsToNumber(Js.str(v));
        return Double.NaN;
    }

    /** JavaScript {@code Number(string)}: trimmed, empty is 0, hex/octal/binary prefixes, decimal and Infinity; anything else NaN. */
    private static double jsToNumber(String s) {
        String t = s.strip();
        if (t.isEmpty()) return 0;
        try {
            if (t.matches("0[xX][0-9a-fA-F]+")) return Long.parseLong(t.substring(2), 16);
            if (t.matches("0[oO][0-7]+")) return Long.parseLong(t.substring(2), 8);
            if (t.matches("0[bB][01]+")) return Long.parseLong(t.substring(2), 2);
            if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
            if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
            if (!t.matches("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")) return Double.NaN;
            return Double.parseDouble(t);
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    private static double riskOf(Facade.CompiledPolicy policy, Catalog catalog, String verb, Map<String, Object> params) {
        Catalog.Spec spec = catalog.get(verb);
        double kappa = num(policy.riskPolicy.get("kappa"));
        if ("dollars".equals(policy.budgetModel) && spec != null && spec.amountField != null) {
            double amt = jsNumber(params, spec.amountField);
            if (!Double.isNaN(amt) && !Double.isInfinite(amt) && kappa > 0) return clamp01(amt / kappa);
        }
        return clamp01(spec != null ? spec.blastRadius : 0.8);
    }

    private static Map<String, Object> simResult(Map<String, Object> action, String outcome, Integer t, double r, String reason, double budgetAfter) {
        Map<String, Object> m = Js.obj();
        m.put("action", action);
        m.put("outcome", outcome);
        if (t != null) m.put("t", Js.n((long) t));
        m.put("r", Js.n(r));
        if (reason != null) m.put("reason", reason);
        m.put("budgetAfter", Js.n(budgetAfter));
        return m;
    }

    private static final class Timed {
        final Map<String, Object> a;
        final double at;
        Timed(Map<String, Object> a, double at) { this.a = a; this.at = at; }
    }

    /**
     * Replay actions in time order against the policy, threading the trust budget as the server would (leak between actions; debit kappa*r on
     * every metered admit; step-up when the budget cannot cover a machine-band action). An action with no usable time is reported as denied,
     * not skipped or guessed. {@code catalog} may be null (the built-in one); {@code start} is the clock the budget starts at and the base of
     * untimed actions' order ({@code start + index}).
     */
    public static Map<String, Object> simulate(Facade.CompiledPolicy policy, List<Map<String, Object>> actions, Catalog catalog, double start) {
        Catalog cat = catalog != null ? catalog : Catalog.DEFAULT;
        List<Timed> timed = new ArrayList<>();
        for (int i = 0; i < actions.size(); i++) {
            Map<String, Object> a = actions.get(i);
            Object at = a.get("at");
            timed.add(new Timed(a, at != null ? (Js.isFinite(at) ? Js.d(at) : Double.NaN) : start + i));
        }
        List<Timed> ordered = new ArrayList<>();
        List<Map<String, Object>> results = new ArrayList<>();
        double bMax = num(policy.riskPolicy.get("bMax")), lambda = num(policy.riskPolicy.get("lambda")), kappa = num(policy.riskPolicy.get("kappa"));
        double theta1 = num(policy.riskPolicy.get("theta1")), theta2 = num(policy.riskPolicy.get("theta2"));
        double budgetB = bMax, asOf = start;
        for (Timed x : timed) if (!Double.isNaN(x.at) && !Double.isInfinite(x.at)) ordered.add(x);
        ordered.sort((x, y) -> { double d = x.at - y.at; return d == 0 ? 0 : d < 0 ? -1 : 1; });
        for (Timed x : timed) if (Double.isNaN(x.at) || Double.isInfinite(x.at)) results.add(simResult(x.a, "deny", null, 1, "action has no finite time", budgetB));

        List<Double> recent = new ArrayList<>();
        double peakRisk = 0, autonomousRisk = 0;
        for (Timed x : ordered) {
            Map<String, Object> a = x.a;
            double at = x.at;
            Catalog.Spec spec = cat.get((String) a.get("verb"));
            Map<String, Object> params = Js.map(a.get("params"));
            Map<String, Object> act = Js.obj();
            act.put("verb", a.get("verb"));
            act.put("resource", a.get("resource"));
            act.put("params", params != null ? params : Js.obj());
            act.put("reversibility_class", spec != null ? spec.reversibility : "irreversible");
            Map<String, Object> ctx = Js.obj();
            ctx.put("action", act);
            double r = riskOf(policy, cat, (String) a.get("verb"), params);
            peakRisk = Math.max(peakRisk, r);

            String denial = Predicates.denialReason(policy.predicates, ctx);
            Caveats.Result cav = null;
            if (denial == null) {
                Map<String, Object> cctx = Js.obj();
                cctx.put("now", Js.n(at));
                cctx.put("blast_radius", Js.n(spec != null ? spec.blastRadius : 1.0));
                cctx.put("reversibility_class", spec != null ? spec.reversibility : "irreversible");
                List<Object> rec = new ArrayList<>();
                for (Double d : recent) rec.add(Js.n(d));
                cctx.put("recent_action_times", rec);
                cav = Caveats.evaluateCaveats(policy.caveats, cctx);
            }
            // leak: B falls by lambda per second since the last update (idempotent at the same instant)
            double dt = Math.max(0, at - asOf);
            budgetB = Math.max(0, budgetB - nz(lambda) * (dt / 1000));
            asOf = Math.max(at, asOf);

            if (denial != null) { results.add(simResult(a, "deny", null, r, denial, budgetB)); continue; }
            if (!cav.ok) { results.add(simResult(a, "deny", null, r, "caveat(s) failed: " + String.join(", ", cav.failed), budgetB)); continue; }
            int t = Risk.requiredThreshold(r, theta1, theta2, false).t;
            double c = cost(r, kappa);
            boolean admit = false;
            int tOut;
            if (t < 3 && !(Double.isFinite(budgetB) && budgetB >= c)) tOut = 3;
            else if (t == 1) { admit = true; tOut = 1; }
            else tOut = t == 2 ? 2 : 3;
            if (admit) {
                budgetB = budgetB - c;
                autonomousRisk += r;
                recent.add(at);
                results.add(simResult(a, "auto", 1, r, null, budgetB));
            } else {
                // t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view
                results.add(simResult(a, "step_up", tOut, r, "requires tier " + tOut, budgetB));
            }
        }
        long auto = 0, stepUp = 0, deny = 0;
        for (Map<String, Object> m : results) {
            Object o = m.get("outcome");
            if ("auto".equals(o)) auto++; else if ("step_up".equals(o)) stepUp++; else deny++;
        }
        Map<String, Object> rep = Js.obj();
        rep.put("results", new ArrayList<Object>(results));
        rep.put("auto", Js.n(auto));
        rep.put("stepUp", Js.n(stepUp));
        rep.put("deny", Js.n(deny));
        rep.put("endBudget", Js.n(budgetB));
        rep.put("peakRisk", Js.n(peakRisk));
        rep.put("autonomousRisk", Js.n(autonomousRisk));
        return rep;
    }

    // ---- linting ------------------------------------------------------------------------------------------------------------

    private static int sev(String cls) { return REVERSIBILITY_ORDER.indexOf(cls); }

    private static Map<String, Object> lint(String level, String code, String message) {
        Map<String, Object> m = Js.obj();
        m.put("level", level);
        m.put("code", code);
        m.put("message", message);
        return m;
    }

    /**
     * Static lints over a compiled policy: {@code error} = almost certainly a mistake (a limit that matches no granted action), {@code warn} =
     * a real risk worth a second look, {@code info} = a notable but intentional property. {@code catalog} may be null.
     */
    public static List<Object> lintPolicy(Facade.CompiledPolicy policy, Catalog catalog) {
        Catalog cat = catalog != null ? catalog : Catalog.DEFAULT;
        List<Object> lints = new ArrayList<>();
        Set<String> granted = new HashSet<>();
        for (Catalog.Spec s : policy.actions) { granted.add(s.verb); granted.add(s.action); granted.addAll(s.aliases); }
        for (String key : keysOf(policy.inputLimits)) if (!granted.contains(key)) lints.add(lint("error", "limit-unmatched", "limit for '" + key + "' matches no granted action"));

        for (Catalog.Spec spec : policy.actions) {
            Map<String, Object> pred = null;
            for (Object p : policy.predicates) { Map<String, Object> pm = Js.map(p); if (pm != null && spec.verb.equals(pm.get("verb"))) { pred = pm; break; } }
            boolean broad = pred == null || !Js.truthy(pred.get("resource")) || "*".equals(pred.get("resource"));
            if (spec.amountField != null && !spec.amountField.isEmpty() && !policy.limits.containsKey(spec.verb))
                lints.add(lint("warn", "money-unbounded", "money action '" + spec.verb + "' has no per-call limit — spend is bounded only by the trust budget"));
            if (broad && sev(spec.reversibility) >= sev("rate_limited"))
                lints.add(lint("warn", "broad-resource", "'" + spec.verb + "' (" + spec.reversibility + ") matches ANY resource — consider a resource prefix"));
            if (cat.get(spec.verb) == null)
                lints.add(lint("info", "uncatalogued", "'" + spec.verb + "' is not in the catalog — treated conservatively (irreversible, high blast radius)"));
        }

        double theta2 = num(policy.riskPolicy.get("theta2")), bMax = num(policy.riskPolicy.get("bMax")), kappa = num(policy.riskPolicy.get("kappa"));
        if (theta2 >= 1) {
            boolean hasIrrev = false;
            for (Catalog.Spec s : policy.actions) if (sev(s.reversibility) >= sev("irreversible")) hasIrrev = true;
            lints.add(lint(hasIrrev ? "warn" : "info", "no-step-up-band",
                "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted" + (hasIrrev ? " — including irreversible actions" : "")));
        }
        if (kappa > 0 && bMax / kappa > 100)
            lints.add(lint("warn", "large-autonomy", "autonomous bound is " + Js.jsNum(Js.round(bMax / kappa)) + "× a max-risk action between human co-signs"));
        return lints;
    }

    private static List<String> keysOf(Map<String, Object> m) {
        // Object.keys order: array-index keys ascending, then insertion order
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (k.matches("0|[1-9][0-9]{0,9}") && Long.parseLong(k) < 4294967295L ? idx : rest).add(k);
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }
}
