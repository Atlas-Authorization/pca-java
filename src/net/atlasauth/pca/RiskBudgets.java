package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The multi-agent budget algebra over trust budgets {@code {B, tau, asOf?}}: allocating a sub-agent's budget out of its parent's, consolidated
 * debits (a sub-agent's spend ALSO debits every ancestor, so a swarm can never collectively spend more than a node's allocation) and the full
 * re-confirmation recharge. Every refusal changes nothing and names the reason.
 */
public final class RiskBudgets {
    private RiskBudgets() {}

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static double num(Object o) { Double d = StoreJs.dbl(o); return d == null ? Double.NaN : d; }

    private static Map<String, Object> no(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    private static Map<String, Object> debit(Map<String, Object> b, double x) {
        Map<String, Object> out = new LinkedHashMap<>(b);
        out.put("B", StoreJs.num(Math.max(0, num(b.get("B")) - x)));
        return out;
    }

    /** Allocate a sub-agent budget {@code B_sub = alloc}, guarded by {@code 0 <= alloc <= parent.B}: {@code {ok:true, sub}} or {@code {ok:false, reason}}. */
    public static Map<String, Object> subBudget(Map<String, Object> parent, double alloc) {
        if (Double.isNaN(alloc) || Double.isInfinite(alloc) || alloc < 0) return no("allocation must be finite and >= 0");
        double pb = num(parent.get("B"));
        if (!(Double.isFinite(pb) && alloc <= pb)) return no("allocation exceeds parent remaining budget");
        Map<String, Object> sub = new LinkedHashMap<>();
        sub.put("B", StoreJs.num(alloc));
        if (parent.containsKey("tau")) sub.put("tau", parent.get("tau"));
        Object asOf = parent.get("asOf") != null ? parent.get("asOf") : parent.get("tau");
        if (asOf != null) sub.put("asOf", asOf);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("sub", sub);
        return m;
    }

    /** A sub-agent's debit ALSO debits the parent. Fails (no state change) if either cannot cover {@code c}: {@code {ok:true, parent, sub}} or {@code {ok:false, reason}}. */
    public static Map<String, Object> debitConsolidated(Map<String, Object> parent, Map<String, Object> sub, double c) {
        double x = nz(c);
        if (!(Double.isFinite(num(sub.get("B"))) && num(sub.get("B")) >= x)) return no("sub-agent budget insufficient");
        if (!(Double.isFinite(num(parent.get("B"))) && num(parent.get("B")) >= x)) return no("parent budget insufficient");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("parent", debit(parent, x));
        m.put("sub", debit(sub, x));
        return m;
    }

    /**
     * {@link #debitConsolidated} along a root-to-leaf budget path of N levels: every node must cover {@code c}; if ANY cannot, nothing is debited
     * and the first offender is named. {@code {ok:true, nodes}} or {@code {ok:false, reason}}.
     */
    public static Map<String, Object> debitConsolidatedPath(List<Object> path, double c) {
        double x = nz(c);
        for (int i = 0; i < path.size(); i++) {
            Map<String, Object> node = StoreJs.map(path.get(i));
            if (!(Double.isFinite(num(node.get("B"))) && num(node.get("B")) >= x)) return no("budget node at depth " + i + " insufficient (need " + AttestCommon.jsNumString(x) + ", have " + IntentRevocation.jsText(node.get("B"), node.containsKey("B")) + ")");
        }
        List<Object> nodes = new ArrayList<>();
        for (Object n : path) nodes.add(debit(StoreJs.map(n), x));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("nodes", nodes);
        return m;
    }

    /** Human co-sign recharge: {@code B = min(bMax, B + rho), tau = asOf = now}. The only way a budget increases. */
    public static Map<String, Object> recharge(Map<String, Object> b, double rho, double bMax, double now) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", StoreJs.num(Math.min(nz(bMax), num(b.get("B")) + nz(rho))));
        m.put("tau", StoreJs.num(now));
        m.put("asOf", StoreJs.num(now));
        return m;
    }

    /** Full goal re-confirmation: {@code B = bMax, tau = asOf = now}. */
    public static Map<String, Object> rechargeFull(double bMax, double now) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", StoreJs.num(nz(bMax)));
        m.put("tau", StoreJs.num(now));
        m.put("asOf", StoreJs.num(now));
        return m;
    }
}
