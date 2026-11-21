package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Bond sizing for optimistic claims: {@code max(floor, curve(k, exposure))} on the micro grid, linear by default, optionally convex. */
public final class IntentBond {
    private IntentBond() {}

    public static final double MICROS_PER_UNIT = 1_000_000;
    private static final double MAX_SAFE_MICROS = 1e15;

    public record Tier(double upTo, double marginalK) {}

    /** The sizing and per-depositor cap policy; {@code curveKind} is null/linear, power (gamma) or piecewise (tiers). */
    public static final class BondPolicy {
        public double floor = 1, k = 1, maxOpenClaims = 100, maxOpenAmount = Double.POSITIVE_INFINITY;
        public String curveKind;
        public double gamma = Double.NaN;
        public List<Tier> tiers;
        public boolean tiersIsArray = true;

        public static BondPolicy fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            BondPolicy p = new BondPolicy();
            p.floor = num(m.get("floor")); p.k = num(m.get("k")); p.maxOpenClaims = num(m.get("maxOpenClaims"));
            p.maxOpenAmount = m.get("maxOpenAmount") == null ? Double.POSITIVE_INFINITY : num(m.get("maxOpenAmount"));
            if (m.get("curve") != null) {
                Map<String, Object> c = IntentOmega.obj(m.get("curve"));
                p.curveKind = (String) c.get("kind");
                if (c.containsKey("gamma")) p.gamma = num(c.get("gamma"));
                if (c.containsKey("tiers")) {
                    if (c.get("tiers") instanceof List) {
                        p.tiers = new ArrayList<>();
                        for (Object t : IntentOmega.arr(c.get("tiers"))) p.tiers.add(new Tier(num(IntentOmega.obj(t).get("upTo")), num(IntentOmega.obj(t).get("marginalK"))));
                    } else p.tiersIsArray = false;
                }
            }
            return p;
        }
    }

    private static double num(Object o) { return o != null && IntentOmega.isNumber(o) ? IntentOmega.dbl(o) : Double.NaN; }

    public static final BondPolicy DEFAULT_BOND_POLICY = new BondPolicy();

    /** Round an amount up onto the micro grid (a micro amount round-trips exactly; amounts too large for it are unchanged). */
    public static double quantizeUp(double x) {
        if (!Double.isFinite(x) || x <= 0) return x;
        double scaled = x * MICROS_PER_UNIT;
        if (scaled > MAX_SAFE_MICROS) return x;
        double r = IntentMapKit.jsRound(scaled);
        double m = r / MICROS_PER_UNIT == x || Math.abs(scaled - r) <= 1e-3 ? r : Math.ceil(scaled);
        return m / MICROS_PER_UNIT;
    }

    private static double curveComponent(BondPolicy p, double e) {
        String kind = p.curveKind;
        if (kind == null || kind.equals("linear")) return p.k * e;
        if (kind.equals("power")) {
            if (!(Double.isFinite(p.gamma) && p.gamma >= 1)) throw new IllegalArgumentException("bondAmount: power curve requires finite gamma >= 1");
            return p.k * StrictMath.pow(e, p.gamma);
        }
        if (!p.tiersIsArray || p.tiers == null || p.tiers.isEmpty()) throw new IllegalArgumentException("bondAmount: piecewise curve requires at least one tier");
        double acc = 0, prevUpTo = 0, prevMarginal = 0;
        for (Tier t : p.tiers) {
            if (!(Double.isFinite(t.upTo()) && t.upTo() > prevUpTo) && t.upTo() != Double.POSITIVE_INFINITY) throw new IllegalArgumentException("bondAmount: piecewise tier `upTo` must be strictly increasing");
            if (!(Double.isFinite(t.marginalK()) && t.marginalK() >= 0)) throw new IllegalArgumentException("bondAmount: piecewise `marginalK` must be a finite number >= 0");
            if (t.marginalK() < prevMarginal) throw new IllegalArgumentException("bondAmount: piecewise marginal rates must be non-decreasing (convex)");
            double width = Math.min(e, t.upTo()) - prevUpTo;
            if (width > 0) acc += width * t.marginalK();
            prevUpTo = t.upTo();
            prevMarginal = t.marginalK();
            if (e <= t.upTo()) break;
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal;
        return p.k * acc;
    }

    /** The bond for an exposure; a non-finite or non-positive exposure gives the floor. */
    public static double bondAmount(BondPolicy policy, double exposure) {
        double e = Double.isFinite(exposure) && exposure > 0 ? exposure : 0;
        return quantizeUp(Math.max(policy.floor, curveComponent(policy, e)));
    }
}
