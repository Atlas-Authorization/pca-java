package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * PCA 0.4.1 policy-layer caveat helpers, mirroring {@code policyCaveats} (packages/pca/src/policy-vm.ts) and the caveat
 * evaluator ({@code envelopeCaveatEvaluator} in predicates.ts + {@code max_spend} in agent-native.ts).
 *
 * <p>The core verifier ({@link Pca#verifyPcactn}, the nine checks) and the servlet filter / Spring interceptor treat
 * caveats as opaque and do NOT evaluate them. A resource server that enforces a grant's caveats calls
 * {@code evaluateCaveats(policyCaveats(grant, chain), ctx)} with its own action parameters. {@link #policyCaveats}
 * includes the caveats placed directly on the ROOT grant (outside the {@code envelope} caveat): before 0.4.1 the
 * reference policy layer signed those but never evaluated them.
 *
 * <p>The context is a map with snake_case keys, exactly the {@code context} of the {@code primitives.caveat_eval}
 * vectors: {@code now} (epoch ms), {@code delegation_depth}, {@code blast_radius}, {@code reversibility_class},
 * {@code recent_action_times} (all optional) and {@code action} ({@code {verb, resource, reversibility_class, params}}).
 * An absent optional field leaves the caveat that needs it unsatisfied. Unknown caveat types (and {@code note},
 * {@code envelope}, {@code resource_prefix}, {@code predicates}, {@code tool_schema}) are unsatisfied: fail closed.
 */
public final class Caveats {
    private Caveats() {}

    /** The verdict of {@link #evaluateCaveats}: {@code ok} iff every caveat is satisfied; {@code failed} = the unsatisfied types, in order. */
    public static final class Result {
        public final boolean ok;
        public final List<String> failed;
        Result(boolean ok, List<String> failed) {
            this.ok = ok;
            this.failed = Collections.unmodifiableList(failed);
        }
        @Override public String toString() { return "Result{ok=" + ok + ", failed=" + failed + "}"; }
    }

    static final List<String> REVERSIBILITY_ORDER = List.of("reversible", "rate_limited", "irreversible");

    /**
     * The ROOT grant's caveats the policy layer evaluates: {@code grant.caveats} without its FIRST {@code envelope} caveat
     * (order kept; a second envelope stays and is unsatisfied). A non-list {@code caveats} is returned as is (and refused
     * by {@link #evaluateCaveats}); a non-object grant yields null. The input is never mutated.
     */
    public static Object rootCaveats(Object grant) {
        if (!(grant instanceof Map)) return null;
        Object cs = ((Map<?, ?>) grant).get("caveats");
        if (!(cs instanceof List)) return cs;
        List<Object> out = new ArrayList<>((List<?>) cs);
        for (int i = 0; i < out.size(); i++) {
            Object c = out.get(i);
            if (c instanceof Map && "envelope".equals(((Map<?, ?>) c).get("type"))) { out.remove(i); break; }
        }
        return out;
    }

    /**
     * Every caveat the policy layer evaluates for an action under {@code grant} delegated along {@code chain} (root first):
     * {@link #rootCaveats} of the grant, then the caveats the hops appended ({@code leaf.caveats} beyond the grant's,
     * leaf = the last chain element). Nothing is appended when the chain is absent, empty or not a list, or when either
     * caveat list is not a list. A non-list root list is returned as is.
     */
    public static Object policyCaveats(Object grant, Object chain) {
        Object root = rootCaveats(grant);
        if (!(root instanceof List)) return root;
        List<Object> out = new ArrayList<>((List<?>) root);
        if (chain instanceof List && !((List<?>) chain).isEmpty()) {
            List<?> ch = (List<?>) chain;
            Object leaf = ch.get(ch.size() - 1);
            Object gcs = ((Map<?, ?>) grant).get("caveats");
            Object lcs = leaf instanceof Map ? ((Map<?, ?>) leaf).get("caveats") : null;
            if (lcs instanceof List && gcs instanceof List) {
                List<?> l = (List<?>) lcs;
                for (int i = ((List<?>) gcs).size(); i < l.size(); i++) out.add(l.get(i));
            }
        }
        return out;
    }

    /** Evaluate every caveat against {@code ctx}. Total: never throws; a non-list => {@code ok=false, failed=["<malformed caveats>"]}. */
    public static Result evaluateCaveats(Object caveats, Object ctx) {
        List<String> failed = new ArrayList<>();
        if (!(caveats instanceof List)) {
            failed.add("<malformed caveats>");
            return new Result(false, failed);
        }
        for (Object cv : (List<?>) caveats) {
            boolean ok;
            try {
                ok = satisfied(cv, ctx);
            } catch (RuntimeException e) {
                ok = false;
            }
            if (!ok) {
                Object t = cv instanceof Map ? ((Map<?, ?>) cv).get("type") : null;
                failed.add(t instanceof String ? (String) t : "<malformed>");
            }
        }
        return new Result(failed.isEmpty(), failed);
    }

    /** One caveat against {@code ctx}; false (unsatisfied) for anything malformed or unknown. */
    public static boolean satisfied(Object caveat, Object ctx) {
        if (!(caveat instanceof Map) || !(ctx instanceof Map)) return false;
        Map<?, ?> cv = (Map<?, ?>) caveat;
        Map<?, ?> c = (Map<?, ?>) ctx;
        Object type = cv.get("type");
        if ("max_spend".equals(type)) return maxSpend(cv, c);
        Double now = fin(c.get("now"));
        if (now == null || !(type instanceof String)) return false;
        switch ((String) type) {
            case "expires": {
                Double at = fin(cv.get("at"));
                return at != null && now < at;
            }
            case "not_before": {
                Double at = fin(cv.get("at"));
                return at != null && now >= at;
            }
            case "rate": {
                Double max = fin(cv.get("max")), per = fin(cv.get("per_secs"));
                if (max == null || per == null || per <= 0) return false;
                Object times = c.get("recent_action_times");
                if (!(times instanceof List)) return false;
                double lo = now - per * 1000;
                int n = 0;
                for (Object t : (List<?>) times) {
                    Double d = fin(t);
                    if (d != null && d > lo && d <= now) n++;
                }
                return n < max;
            }
            case "max_blast_radius": {
                Double max = fin(cv.get("max")), br = fin(c.get("blast_radius"));
                return max != null && br != null && br <= max;
            }
            case "reversibility_max": {
                Object lim = cv.get("class"), cur = c.get("reversibility_class");
                if (!(lim instanceof String) || !(cur instanceof String)) return false;
                int li = REVERSIBILITY_ORDER.indexOf(lim), ci = REVERSIBILITY_ORDER.indexOf(cur);
                return li >= 0 && ci >= 0 && ci <= li;
            }
            case "delegation_depth": {
                Double max = fin(cv.get("max")), d = fin(c.get("delegation_depth"));
                return max != null && d != null && d <= max;
            }
            case "budget_alloc": {
                Double lim = fin(cv.get("limit"));
                return lim != null && lim >= 0;
            }
            default:
                return false;
        }
    }

    /**
     * {@code max_spend {usd}}: {@code usd} a finite number >= 0; {@code ctx.action.params} an object with an own finite
     * {@code amount} >= 0 and {@code amount <= usd}; an own {@code currency}, when present, exactly "usd" or "USD".
     * Does not need {@code now}.
     */
    static boolean maxSpend(Map<?, ?> cv, Map<?, ?> c) {
        Double lim = fin(cv.get("usd"));
        if (lim == null || lim < 0) return false;
        Object act = c.get("action");
        if (!(act instanceof Map)) return false;
        Object params = ((Map<?, ?>) act).get("params");
        if (!(params instanceof Map)) return false;
        Map<?, ?> p = (Map<?, ?>) params;
        if (!p.containsKey("amount")) return false;
        Double amount = fin(p.get("amount"));
        if (amount == null || amount < 0) return false;
        if (p.containsKey("currency")) {
            Object cur = p.get("currency");
            if (!"usd".equals(cur) && !"USD".equals(cur)) return false;
        }
        return amount <= lim;
    }

    /** A finite JSON number as a double (JavaScript semantics: an overflowing literal is not finite), else null. Booleans/strings are not numbers. */
    static Double fin(Object o) {
        double d;
        if (o instanceof Json.Num) {
            try { d = Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        } else if (o instanceof Double || o instanceof Float || o instanceof Integer || o instanceof Long
                || o instanceof Short || o instanceof Byte || o instanceof BigDecimal || o instanceof BigInteger) {
            d = ((Number) o).doubleValue();
        } else {
            return null;
        }
        return Double.isFinite(d) ? d : null;
    }
}
