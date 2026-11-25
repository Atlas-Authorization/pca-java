package net.atlasauth.pca.research;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them
 * autonomously) and evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels
 * something upstream attached; this checks them against ceilings and never tracks data through a program.
 *
 * <p>A policy is {@code {classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}}; a context is
 * {@code {verb, resource, taint, trustedRefs?}}; a result is {@code {outcome: allow|step_up|deny, class?, reason?}}.
 */
public final class Dlp {
    private Dlp() {}

    private static boolean matches(Object pattern, Object resource) {
        if ("*".equals(pattern)) return true;
        if (!(pattern instanceof String)) throw new IllegalArgumentException("DLP: a class resource must be a string");
        String p = (String) pattern;
        if (p.endsWith("*")) {
            if (!(resource instanceof String)) throw new IllegalArgumentException("DLP: the resource must be a string");
            return ((String) resource).startsWith(p.substring(0, p.length() - 1));
        }
        return p.equals(resource);
    }

    private static double specificity(String pattern) {
        if (pattern.equals("*")) return 0;
        if (pattern.endsWith("*")) return pattern.length() - 1;
        return pattern.length() + 1000; // exact beats any prefix
    }

    // a malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling (unconstrained) sorts last
    private static double strictness(Map<String, Object> c) {
        Object m = c.get("maxTaintForAuto");
        if (m == null && !c.containsKey("maxTaintForAuto")) return Double.POSITIVE_INFINITY;
        return Js.isNum(m) ? Js.d(m) : Double.NEGATIVE_INFINITY;
    }

    private static boolean verbMatches(Map<String, Object> c, Object verb) {
        Object vs = c.get("verbs");
        if (!Js.truthy(vs)) return true;
        if (vs instanceof List) return ((List<?>) vs).contains(verb);
        if (vs instanceof String) return verb instanceof String ? ((String) vs).contains((String) verb) : ((String) vs).contains(Js.str(verb));
        throw new IllegalArgumentException("DLP: verbs must be a list");
    }

    private static int cmp(double x) { return Double.isNaN(x) || x == 0 ? 0 : x < 0 ? -1 : 1; }

    /** The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equals the STRICTEST wins. Null for none. */
    private static Map<String, Object> classFor(List<?> classes, Map<String, Object> ctx) {
        List<Map<String, Object>> applicable = new ArrayList<>();
        for (Object o : classes) {
            Map<String, Object> c = Js.map(o);
            if (c == null) throw new IllegalArgumentException("DLP: a class must be an object");
            if (matches(c.get("resource"), ctx.get("resource")) && verbMatches(c, ctx.get("verb"))) applicable.add(c);
        }
        if (applicable.isEmpty()) return null;
        applicable.sort((a, b) -> {
            int s = cmp(specificity((String) b.get("resource")) - specificity((String) a.get("resource")));
            return s != 0 ? s : cmp(strictness(a) - strictness(b));
        });
        return applicable.get(0);
    }

    private static boolean has(Map<String, Object> m, String k) { return m.get(k) != null || m.containsKey(k); }

    // A ceiling that is present but not a number would make every comparison false and allow everything.
    private static boolean malformed(Map<String, Object> policy, Map<String, Object> cls) {
        if (cls != null) return (has(cls, "maxTaintForAuto") && !Js.isNum(cls.get("maxTaintForAuto"))) || (has(cls, "hardDenyAbove") && !Js.isNum(cls.get("hardDenyAbove")));
        return has(policy, "defaultMaxTaintForAuto") && !Js.isNum(policy.get("defaultMaxTaintForAuto"));
    }

    private static Map<String, Object> result(String outcome, Map<String, Object> cls, String reason) {
        Map<String, Object> r = Js.obj();
        r.put("outcome", outcome);
        if (cls != null && cls.containsKey("name")) r.put("class", cls.get("name"));
        if (reason != null) r.put("reason", reason);
        return r;
    }

    /**
     * Evaluate an action's data flow against the DLP policy. Fails CLOSED: a malformed policy or ceiling is a deny, and a taint that is not a
     * finite number is treated as maximally tainted so it can never beat a ceiling.
     */
    public static Map<String, Object> evaluateDlp(Map<String, Object> policy, Map<String, Object> ctx) {
        if (policy == null || !(policy.get("classes") instanceof List)) return result("deny", null, "malformed DLP policy");
        Map<String, Object> cls = classFor((List<?>) policy.get("classes"), ctx);
        if (malformed(policy, cls)) return result("deny", cls, "malformed DLP policy: ceilings must be numbers");
        Object max = cls != null ? cls.get("maxTaintForAuto") : policy.get("defaultMaxTaintForAuto");
        boolean hasMax = cls != null ? has(cls, "maxTaintForAuto") : has(policy, "defaultMaxTaintForAuto");
        boolean bad = !Js.isFinite(ctx.get("taint"));
        double taint = !bad ? Js.d(ctx.get("taint")) : Double.POSITIVE_INFINITY;
        if (!hasMax) return result("allow", cls, null); // no ceiling at all: nothing to compare against
        double m = Js.d(max);
        String label = cls != null && cls.get("name") != null ? Js.str(cls.get("name")) : "<default>";
        if (cls != null && has(cls, "hardDenyAbove") && (bad || taint > Js.d(cls.get("hardDenyAbove"))))
            return result("deny", cls, "taint " + Js.jsNum(taint) + " exceeds hard ceiling " + Js.jsNum(Js.d(cls.get("hardDenyAbove"))) + " for '" + label + "'");
        if (bad || taint > m) return result("step_up", cls, "taint " + Js.jsNum(taint) + " > " + Js.jsNum(m) + " for '" + label + "' — needs human review");
        return result("allow", cls, null);
    }

    /** Preset with no options: no classes. */
    public static Map<String, Object> defaultDlpPolicy() { return defaultDlpPolicy(Js.obj()); }

    /** Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. {@code opts} {@code {piiResource?, secretsResource?}} must not be null. */
    public static Map<String, Object> defaultDlpPolicy(Map<String, Object> opts) {
        if (opts == null) throw new IllegalArgumentException("defaultDlpPolicy: opts must not be null");
        List<Object> classes = new ArrayList<>();
        Map<String, Object> o = opts;
        if (Js.truthy(o.get("piiResource"))) classes.add(cls("pii", o.get("piiResource"), 0, 2));
        if (Js.truthy(o.get("secretsResource"))) classes.add(cls("secrets", o.get("secretsResource"), 0, 0));
        Map<String, Object> p = Js.obj();
        p.put("classes", classes);
        return p;
    }

    private static Map<String, Object> cls(String name, Object resource, long max, long hard) {
        Map<String, Object> c = Js.obj();
        c.put("name", name);
        c.put("resource", resource);
        c.put("maxTaintForAuto", Js.n(max));
        c.put("hardDenyAbove", Js.n(hard));
        return c;
    }
}
