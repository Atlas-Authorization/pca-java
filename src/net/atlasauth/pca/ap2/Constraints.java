package net.atlasauth.pca.ap2;

import java.time.LocalDate;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Evaluation of AP2 open-mandate constraints against a closed mandate / checkout.
 *
 * <p>This follows the AP2 documentation's evaluation rules and is deliberately stricter than the official SDK in four places,
 * each a fail-closed choice: a line-item requirement whose {@code acceptable_items} is empty matches nothing; the maximal flow
 * must equal both the required and the carted quantity; a closed payment without {@code execution_date} is evaluated at the
 * verification time; {@code execution_date} bounds are compared as instants, not as strings.
 *
 * <p>Mandates and contexts are parsed JSON (Map, List, String, Boolean, Json.Num, null). A usage context is
 * {@code {totalAmount, totalUses, lastUsedDate?}}: the minor-unit sum of previous closed payments, their count, and the
 * epoch seconds of the most recent one.
 */
public final class Constraints {
    private Constraints() {}

    /** A usage context map ({@code lastUsedDate} may be null). */
    public static Map<String, Object> context(double totalAmount, double totalUses, Double lastUsedDate) {
        Map<String, Object> c = Js.m("totalAmount", Js.n(totalAmount), "totalUses", Js.n(totalUses));
        if (lastUsedDate != null) c.put("lastUsedDate", Js.n((double) lastUsedDate));
        return c;
    }

    public static boolean merchantMatches(Object candidate, Object target) {
        Object cid = Js.get(candidate, "id"), tid = Js.get(target, "id");
        if (Js.truthy(cid) && Js.truthy(tid)) return Js.sEq(cid, tid);
        return Js.truthy(Js.get(candidate, "name")) && Js.truthy(Js.get(candidate, "website"))
            && Js.sEq(Js.get(candidate, "name"), Js.get(target, "name")) && Js.sEq(Js.get(candidate, "website"), Js.get(target, "website"));
    }

    private static Object sortKeys(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(sortKeys(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> src = Js.obj(v);
            List<String> keys = new ArrayList<>(src.keySet());
            keys.sort(String::compareTo); // UTF-16 code unit order, as Array.prototype.sort
            Map<String, Object> out = new LinkedHashMap<>();
            for (String k : keys) out.put(k, sortKeys(src.get(k)));
            return out;
        }
        return v;
    }

    private static boolean sameJson(Object a, Object b) { return Objects.equals(Js.stringify(sortKeys(a)), Js.stringify(sortKeys(b))); }

    private static final Pattern RFC3339 = Pattern.compile("(\\d{4})-(\\d{2})-(\\d{2})(?:T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,9}))?(Z|([+-])(\\d{2}):(\\d{2})))?");

    /**
     * Epoch ms of an RFC 3339 instant, or null. STRICT, and independent of the host: {@code YYYY-MM-DD} (UTC midnight) or
     * {@code YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)}, with every component in range (real calendar day, hour &lt;= 23, no
     * leap second; the fraction is truncated to ms). An impossible day is refused rather than rolled over.
     */
    static Double parseInstant(Object s) {
        if (!(s instanceof String)) return null;
        Matcher m = RFC3339.matcher((String) s);
        if (!m.matches()) return null;
        int y = Integer.parseInt(m.group(1)), mo = Integer.parseInt(m.group(2)), d = Integer.parseInt(m.group(3));
        if (mo < 1 || mo > 12 || d < 1 || d > YearMonth.of(y, mo).lengthOfMonth()) return null;
        double day = (double) (LocalDate.of(y, mo, d).toEpochDay() * 86_400_000L);
        if (m.group(4) == null) return day;
        int h = Integer.parseInt(m.group(4)), mi = Integer.parseInt(m.group(5)), se = Integer.parseInt(m.group(6));
        if (h > 23 || mi > 59 || se > 59) return null;
        String frac = m.group(7);
        double ms = 0;
        if (frac != null) {
            String f = frac.length() > 3 ? frac.substring(0, 3) : frac;
            while (f.length() < 3) f += "0";
            ms = Integer.parseInt(f);
        }
        double offset = 0;
        if (!m.group(8).equals("Z")) {
            int oh = Integer.parseInt(m.group(10)), om = Integer.parseInt(m.group(11));
            if (oh > 23 || om > 59) return null;
            offset = (m.group(9).equals("+") ? 1 : -1) * (oh * 60 + om) * 60_000.0;
        }
        return day + ((h * 60 + mi) * 60 + se) * 1000.0 + ms - offset;
    }

    /** Start (epoch ms, UTC) of the calendar period of {@code frequency} that contains {@code ms}; NaN for an unknown frequency. */
    static double periodStart(double ms, Object frequency) {
        if (Double.isNaN(ms) || Math.abs(ms) > 8.64e15) return Double.NaN;
        final long DAY = 86_400_000L;
        long t = (long) ms;
        long dayNum = Math.floorDiv(t, DAY);
        long day = dayNum * DAY;
        long monIdx = Math.floorMod(dayNum + 3, 7L); // Monday = 0 (1970-01-01 was a Thursday)
        LocalDate ld = LocalDate.ofEpochDay(dayNum);
        if (!(frequency instanceof String)) return Double.NaN;
        switch ((String) frequency) {
            case "ON_DEMAND": return 0;
            case "DAILY": return day;
            case "WEEKLY": return day - monIdx * DAY;
            case "BIWEEKLY": {
                long weekStart = day - monIdx * DAY;
                long week2 = 14 * DAY;
                long epochMonday = -3 * DAY;
                return epochMonday + Math.floorDiv(weekStart - epochMonday, week2) * week2;
            }
            case "MONTHLY": return LocalDate.of(ld.getYear(), ld.getMonthValue(), 1).toEpochDay() * DAY;
            case "QUARTERLY": return LocalDate.of(ld.getYear(), ((ld.getMonthValue() - 1) / 3) * 3 + 1, 1).toEpochDay() * DAY;
            case "ANNUALLY": return LocalDate.of(ld.getYear(), 1, 1).toEpochDay() * DAY;
            default: return Double.NaN;
        }
    }

    /** Inputs of {@link #checkPaymentConstraints}. */
    public static final class PaymentCheckOptions {
        /** {@code sd_hash} of the open checkout mandate this payment is chained to (for {@code payment.reference}). */
        public String openCheckoutHash;
        /** Usage state; required to evaluate {@code payment.budget} and recurrence limits / frequency. */
        public Map<String, Object> context;
        /** Verification time, epoch seconds. */
        public double now;

        public PaymentCheckOptions() {}

        public PaymentCheckOptions(String openCheckoutHash, Map<String, Object> context, double now) {
            this.openCheckoutHash = openCheckoutHash;
            this.context = context;
            this.now = now;
        }
    }

    private static double d(Object o) {
        Double v = Js.num(o);
        return v == null ? Double.NaN : v;
    }

    /** A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it. */
    private static String contextProblem(Map<String, Object> c) {
        if (!Js.isNonNegInt(c.get("totalAmount")) || !Js.isNonNegInt(c.get("totalUses")) || (c.containsKey("lastUsedDate") && !Js.isNonNegInt(c.get("lastUsedDate")))) {
            return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate";
        }
        return null;
    }

    private static List<String> one(String s) {
        List<String> l = new ArrayList<>();
        l.add(s);
        return l;
    }

    private static List<String> evaluatePayment(Object c, Map<String, Object> closed, PaymentCheckOptions o) {
        Object amt = closed.get("payment_amount");
        Object type = Js.get(c, "type");
        List<String> v = new ArrayList<>();
        String t = type instanceof String ? (String) type : "\u0000";
        switch (t) {
            case "payment.amount_range": {
                if (!Js.sEq(Js.get(amt, "currency"), Js.get(c, "currency"))) v.add("currency mismatch: expected " + Js.str(Js.getU(c, "currency")) + ", got " + Js.str(Js.getU(amt, "currency")));
                if (!Double.isFinite(d(Js.get(amt, "amount")))) v.add("amount " + Js.str(Js.getU(amt, "amount")) + " is not finite");
                if (Js.def(c, "min") && !(d(Js.get(amt, "amount")) >= d(Js.get(c, "min")))) v.add("amount " + Js.str(Js.getU(amt, "amount")) + " below minimum " + Js.str(Js.get(c, "min")));
                if (!(d(Js.get(amt, "amount")) <= d(Js.get(c, "max")))) v.add("amount " + Js.str(Js.getU(amt, "amount")) + " exceeds maximum " + Js.str(Js.getU(c, "max")));
                return v;
            }
            case "payment.allowed_payees": {
                for (Object m : Js.arr(Js.get(c, "allowed"))) if (merchantMatches(m, closed.get("payee"))) return v;
                return one("payee " + Js.str(Js.getU(closed.get("payee"), "name")) + " is not in the allowed list");
            }
            case "payment.allowed_payment_instruments": {
                for (Object i : Js.arr(Js.get(c, "allowed"))) if (Js.sEq(Js.get(i, "id"), Js.get(closed.get("payment_instrument"), "id"))) return v;
                return one("payment instrument " + Js.str(Js.getU(closed.get("payment_instrument"), "id")) + " is not in the allowed list");
            }
            case "payment.allowed_pisps": {
                Object p = closed.get("pisp");
                if (!Js.truthy(p)) return one("missing PISP in the closed mandate");
                for (Object a : Js.arr(Js.get(c, "allowed"))) {
                    if (Js.sEq(Js.get(a, "legal_name"), Js.get(p, "legal_name")) && Js.sEq(Js.get(a, "brand_name"), Js.get(p, "brand_name")) && Js.sEq(Js.get(a, "domain_name"), Js.get(p, "domain_name"))) return v;
                }
                return one("PISP is not in the allowed list");
            }
            case "payment.reference": {
                if (o.openCheckoutHash == null || o.openCheckoutHash.isEmpty()) return one("openCheckoutHash is required to evaluate a payment.reference constraint");
                return Js.sEq(o.openCheckoutHash, Js.get(c, "conditional_transaction_id")) ? v : one("payment.reference does not match the open checkout mandate hash");
            }
            case "payment.budget": {
                if (!Js.sEq(Js.get(amt, "currency"), Js.get(c, "currency"))) return one("budget currency mismatch: expected " + Js.str(Js.getU(c, "currency")) + ", got " + Js.str(Js.getU(amt, "currency")));
                // The official SDK converts the budget with int(max * 100) for every currency; this check reads it the same way,
                // and the issuing side (ap2BudgetMax) chooses max so that this reading is never above the PCA cap.
                if (o.context == null) return one("mandate context is required to evaluate a budget");
                String bad = contextProblem(o.context);
                if (bad != null) return one(bad);
                double scaled = d(Js.get(c, "max")) * 100;
                double maxMinor = Js.round(scaled);
                if (!(Math.abs(scaled - maxMinor) <= 1e-6)) return one("budget.max is not a whole number of minor units");
                double spend = d(o.context.get("totalAmount")) + d(Js.get(amt, "amount"));
                return !(Double.isFinite(spend) && spend <= maxMinor)
                    ? one("cumulative spend " + Js.str(Js.n(spend)) + " exceeds budget " + Js.str(Js.n(maxMinor)) + " (past spend " + Js.str(o.context.get("totalAmount")) + ")")
                    : v;
            }
            case "payment.agent_recurrence": {
                if (o.context != null) {
                    String bad = contextProblem(o.context);
                    if (bad != null) return one(bad);
                }
                if (Js.def(c, "max_occurrences")) {
                    if (o.context == null) return one("mandate context is required to evaluate recurrence limits");
                    if (!(d(o.context.get("totalUses")) < d(Js.get(c, "max_occurrences")))) {
                        v.add("maximum occurrences exceeded: " + Js.str(o.context.get("totalUses")) + " >= " + Js.str(Js.get(c, "max_occurrences")));
                    }
                }
                if (!"ON_DEMAND".equals(Js.get(c, "frequency"))) {
                    if (!Mandates.FREQUENCIES.contains(Js.get(c, "frequency"))) return one("unknown recurrence frequency");
                    if (o.context == null) return one("mandate context is required to evaluate recurrence frequency");
                    if (o.context.containsKey("lastUsedDate")) {
                        double last = d(o.context.get("lastUsedDate"));
                        if (!(last * 1000 < periodStart(o.now * 1000, Js.get(c, "frequency")))) v.add("already used in the current " + Js.str(Js.get(c, "frequency")) + " period");
                    }
                }
                return v;
            }
            case "payment.execution_date": {
                Double at = closed.containsKey("execution_date") ? parseInstant(closed.get("execution_date")) : Double.valueOf(o.now * 1000);
                if (at == null || !Double.isFinite(at)) return one("execution_date " + Js.str(Js.getU(closed, "execution_date")) + " is not a valid instant");
                for (String key : new String[] {"not_before", "not_after"}) {
                    if (!Js.def(c, key)) continue;
                    boolean before = key.equals("not_before");
                    Object bound = Js.get(c, key);
                    Double b = parseInstant(bound);
                    if (b == null) v.add(key + " " + Js.str(bound) + " is not a valid instant");
                    else if (before ? !(at >= b) : !(at <= b)) v.add("execution date is " + (before ? "before" : "after") + " the allowed window (" + key + " " + Js.str(bound) + ")");
                }
                return v;
            }
            default:
                return one("unknown constraint type " + Js.str(Js.getU(c, "type")));
        }
    }

    /** Violations of the open payment mandate's constraints and pre-set claims by {@code closed} (empty = satisfied). */
    public static List<String> checkPaymentConstraints(Map<String, Object> open, Map<String, Object> closed, PaymentCheckOptions o) {
        List<String> v = new ArrayList<>();
        if (open.containsKey("payee") && !merchantMatches(open.get("payee"), closed.get("payee"))) {
            v.add("pre-set payee mismatch: expected " + Js.str(Js.getU(open.get("payee"), "name")) + ", got " + Js.str(Js.getU(closed.get("payee"), "name")));
        }
        if (open.containsKey("payment_amount") && !sameJson(open.get("payment_amount"), Js.getU(closed, "payment_amount"))) v.add("pre-set payment_amount mismatch");
        if (open.containsKey("payment_instrument") && !sameJson(open.get("payment_instrument"), Js.getU(closed, "payment_instrument"))) v.add("pre-set payment_instrument mismatch");
        if (open.containsKey("pisp") && !sameJson(open.get("pisp"), Js.getU(closed, "pisp"))) v.add("pre-set pisp mismatch");
        if (open.containsKey("execution_date") && !Js.sEq(open.get("execution_date"), Js.getU(closed, "execution_date"))) v.add("pre-set execution_date mismatch");

        Set<Object> types = new HashSet<>();
        for (Object c : Js.arr(open.get("constraints"))) types.add(Js.get(c, "type"));
        if (types.contains("payment.agent_recurrence")) {
            if (!types.contains("payment.amount_range")) v.add("payment.agent_recurrence requires a payment.amount_range constraint");
            if (!types.contains("payment.budget")) v.add("payment.agent_recurrence requires a payment.budget constraint");
        }
        for (Object c : Js.arr(open.get("constraints"))) v.addAll(evaluatePayment(c, closed, o));
        return v;
    }

    // ---------------------------------------------------------------------------------------------
    // checkout side
    // ---------------------------------------------------------------------------------------------

    private static final Pattern ISO_CCY = Pattern.compile("[A-Z]{3}");

    /**
     * Validate and project the checkout payload into the slice of the UCP Checkout object the constraints read
     * ({@code id, currency, line_items[{id, item{id,title,price}, quantity}], totals[{type,amount}], merchant?}); throws a
     * descriptive {@link Ap2Error} when malformed.
     */
    public static Map<String, Object> projectCheckout(Map<String, Object> payload) {
        Object id = payload.get("id");
        if (!(id instanceof String) || ((String) id).isEmpty()) throw bad("id is required");
        Object currency = payload.get("currency");
        if (!(currency instanceof String) || !ISO_CCY.matcher((String) currency).matches()) throw bad("currency must be ISO 4217");
        if (!Js.isArr(payload.get("line_items")) || Js.arr(payload.get("line_items")).isEmpty()) throw bad("line_items must be a non-empty array");
        if (!Js.isArr(payload.get("totals"))) throw bad("totals must be an array");
        List<Object> lineItems = new ArrayList<>();
        List<Object> src = Js.arr(payload.get("line_items"));
        for (int i = 0; i < src.size(); i++) {
            Object li = src.get(i);
            if (!Js.isObj(li) || !Js.isStr(Js.get(li, "id")) || !Js.isObj(Js.get(li, "item"))) throw bad("line_items[" + i + "] is malformed");
            Object item = Js.get(li, "item");
            Object price = Js.get(item, "price");
            if (!Js.isStr(Js.get(item, "id")) || !Js.isStr(Js.get(item, "title")) || !Js.isSafeInteger(price) || Js.num(price) < 0 || Js.isNegZero(Js.num(price))) {
                throw bad("line_items[" + i + "].item needs id, title and integer minor-unit price");
            }
            Object qty = Js.get(li, "quantity");
            if (!Js.isSafeInteger(qty) || Js.num(qty) < 1) throw bad("line_items[" + i + "].quantity must be a positive integer");
            lineItems.add(Js.m("id", Js.get(li, "id"), "item", Js.m("id", Js.get(item, "id"), "title", Js.get(item, "title"), "price", price), "quantity", qty));
        }
        List<Object> totals = new ArrayList<>();
        List<Object> tsrc = Js.arr(payload.get("totals"));
        for (int i = 0; i < tsrc.size(); i++) {
            Object t = tsrc.get(i);
            if (!Js.isObj(t) || !Js.isStr(Js.get(t, "type")) || !Js.isSafeInteger(Js.get(t, "amount")) || Js.isNegZero(Js.num(Js.get(t, "amount")))) throw bad("totals[" + i + "] is malformed");
            totals.add(Js.m("type", Js.get(t, "type"), "amount", Js.get(t, "amount")));
        }
        Map<String, Object> merchant = null;
        if (payload.containsKey("merchant")) {
            Object m = payload.get("merchant");
            if (!Js.isObj(m) || !Js.isStr(Js.get(m, "id")) || !Js.isStr(Js.get(m, "name"))) throw bad("merchant needs id and name");
            merchant = Js.m("id", Js.get(m, "id"), "name", Js.get(m, "name"));
            if (Js.isStr(Js.get(m, "website"))) merchant.put("website", Js.get(m, "website"));
        }
        Map<String, Object> out = Js.m("id", id, "currency", currency, "line_items", lineItems, "totals", totals);
        if (merchant != null) out.put("merchant", merchant);
        return out;
    }

    private static Ap2Error bad(String m) { return new Ap2Error("checkout_jwt payload: " + m); }

    /** The checkout's single {@code total} entry in minor units (the number), or null if absent / ambiguous. */
    public static Object checkoutTotal(Map<String, Object> checkout) {
        Object found = null;
        int n = 0;
        for (Object t : Js.arr(checkout.get("totals"))) {
            if ("total".equals(Js.get(t, "type"))) {
                n++;
                found = Js.get(t, "amount");
            }
        }
        return n == 1 ? found : null;
    }

    /**
     * Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp on the bipartite graph of the
     * documentation): satisfied iff the flow equals both the required and the carted total.
     */
    private static List<String> lineItemViolations(List<Object> cart, List<Object> reqs) {
        Map<Object, Double> qty = new LinkedHashMap<>();
        for (Object li : cart) {
            Object itemId = Js.get(Js.get(li, "item"), "id");
            qty.put(itemId, (qty.containsKey(itemId) ? qty.get(itemId) : 0.0) + d(Js.get(li, "quantity")));
        }
        List<Object> skus = new ArrayList<>(qty.keySet());
        final int S = 0;
        final int T = 1 + skus.size() + reqs.size();
        List<Map<Integer, Double>> cap = new ArrayList<>();
        for (int i = 0; i <= T; i++) cap.add(new LinkedHashMap<>());
        final double INF = 9007199254740991.0;
        for (int i = 0; i < skus.size(); i++) add(cap, S, 1 + i, qty.get(skus.get(i)));
        for (int j = 0; j < reqs.size(); j++) {
            Object r = reqs.get(j);
            add(cap, 1 + skus.size() + j, T, d(Js.get(r, "quantity")));
            Set<Object> ok = new HashSet<>();
            for (Object a : Js.arr(Js.get(r, "acceptable_items"))) ok.add(Js.get(a, "id"));
            for (int i = 0; i < skus.size(); i++) if (ok.contains(skus.get(i))) add(cap, 1 + i, 1 + skus.size() + j, INF);
        }
        double flow = 0;
        for (;;) {
            Map<Integer, Integer> parent = new LinkedHashMap<>();
            parent.put(S, S);
            List<Integer> queue = new ArrayList<>();
            queue.add(S);
            for (int h = 0; h < queue.size() && !parent.containsKey(T); h++) {
                int u = queue.get(h);
                for (Map.Entry<Integer, Double> e : cap.get(u).entrySet()) {
                    if (e.getValue() > 0 && !parent.containsKey(e.getKey())) {
                        parent.put(e.getKey(), u);
                        queue.add(e.getKey());
                    }
                }
            }
            if (!parent.containsKey(T)) break;
            double push = INF;
            for (int v = T; v != S; v = parent.get(v)) push = Math.min(push, cap.get(parent.get(v)).get(v));
            for (int v = T; v != S; v = parent.get(v)) {
                int u = parent.get(v);
                cap.get(u).put(v, cap.get(u).get(v) - push);
                cap.get(v).put(u, cap.get(v).get(u) + push);
            }
            flow += push;
        }
        double required = 0;
        for (Object r : reqs) required += d(Js.get(r, "quantity"));
        double carted = 0;
        for (double q : qty.values()) carted += q;
        if (flow == required && flow == carted) return new ArrayList<>();
        return one("line items do not satisfy the constraint: assigned " + Js.str(Js.n(flow)) + " of " + Js.str(Js.n(required)) + " required and " + Js.str(Js.n(carted)) + " carted units");
    }

    private static void add(List<Map<Integer, Double>> cap, int u, int v, double c) {
        cap.get(u).put(v, cap.get(u).getOrDefault(v, 0.0) + c);
        cap.get(v).put(u, cap.get(v).getOrDefault(u, 0.0));
    }

    private static List<String> evaluateCheckout(Object c, Map<String, Object> checkout) {
        Object type = Js.get(c, "type");
        if ("checkout.allowed_merchants".equals(type)) {
            Object m = checkout.get("merchant");
            if (!Js.truthy(m)) return one("missing merchant in the checkout");
            for (Object a : Js.arr(Js.get(c, "allowed"))) if (merchantMatches(a, m)) return new ArrayList<>();
            return one("merchant " + Js.str(Js.getU(m, "name")) + " is not in the allowed list");
        }
        if (!"checkout.line_items".equals(type)) return one("unknown constraint type " + Js.str(Js.getU(c, "type")));
        return Js.arr(checkout.get("line_items")).isEmpty() ? one("empty cart does not satisfy a line_items constraint") : lineItemViolations(Js.arr(checkout.get("line_items")), Js.arr(Js.get(c, "items")));
    }

    /** Violations of the open checkout mandate's constraints by {@code checkout} (a {@link #projectCheckout} result; empty = satisfied). */
    public static List<String> checkCheckoutConstraints(Map<String, Object> open, Map<String, Object> checkout) {
        List<String> out = new ArrayList<>();
        for (Object c : Js.arr(open.get("constraints"))) out.addAll(evaluateCheckout(c, checkout));
        return out;
    }
}
