package net.atlasauth.pca.ap2;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * AP2 mandate claim shapes (Intent/Cart/Payment, closed and open) and their validators.
 *
 * <p>The shapes follow the official AP2 JSON Schemas. The validators are hand-written over parsed JSON (Map, List, String,
 * Boolean, Json.Num, null), check at least what those schemas check, and are stricter in places where a lax reading would be
 * unsafe (non-negative safe-integer amounts, well-formed JWKs). Each returns the list of problems (empty = valid).
 */
public final class Mandates {
    private Mandates() {}

    public static final String VCT_CHECKOUT = "mandate.checkout.1";
    public static final String VCT_CHECKOUT_OPEN = "mandate.checkout.open.1";
    public static final String VCT_PAYMENT = "mandate.payment.1";
    public static final String VCT_PAYMENT_OPEN = "mandate.payment.open.1";

    /** Namespaced claim carrying PCA's own proof inside a mandate object. */
    public static final String PCA_CLAIM = "x_pca";

    public static final List<String> FREQUENCIES = Collections.unmodifiableList(
        Arrays.asList("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"));

    // ---------------------------------------------------------------------------------------------
    // currencies and minor units
    // ---------------------------------------------------------------------------------------------

    private static final Set<String> ZERO_DECIMAL = new HashSet<>(Arrays.asList("BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF"));
    private static final Set<String> THREE_DECIMAL = new HashSet<>(Arrays.asList("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"));
    private static final Set<String> FOUR_DECIMAL = new HashSet<>(Arrays.asList("CLF", "UYW"));

    static boolean isAlpha3(Object v) {
        if (!(v instanceof String)) return false;
        String s = (String) v;
        if (s.length() != 3) return false;
        for (int i = 0; i < 3; i++) if (s.charAt(i) < 'A' || s.charAt(i) > 'Z') return false;
        return true;
    }

    /** ISO 4217 minor-unit exponent for {@code currency} (2 for any code not in the 0/3/4-digit tables). */
    public static int currencyExponent(Object currency) {
        if (!isAlpha3(currency)) throw new Ap2Error("currency must be an ISO 4217 alpha-3 code, got " + (currency == Js.UNDEF ? "undefined" : Js.stringify(currency)));
        if (ZERO_DECIMAL.contains(currency)) return 0;
        if (THREE_DECIMAL.contains(currency)) return 3;
        if (FOUR_DECIMAL.contains(currency)) return 4;
        return 2;
    }

    /**
     * Convert a major-unit amount (e.g. {@code 120.5} USD) to integer minor units ({@code 12050}). Throws unless the amount is
     * exactly representable with the currency's exponent: float drift ({@code 0.1 + 0.2}) is refused rather than rounded away.
     */
    public static double toMinorUnits(Object major, Object currency) {
        int e = currencyExponent(currency);
        if (!Js.isFinite(major) || Js.num(major) < 0) throw new Ap2Error("amount must be a finite non-negative number, got " + Js.str(major));
        double m = Js.num(major);
        if (m >= 1e21) throw new Ap2Error("amount " + Js.str(major) + " is outside the safe integer range in minor units"); // toFixed answers in exponent form there
        String fixed = new BigDecimal(m).setScale(e, RoundingMode.HALF_UP).toPlainString();
        if (Double.parseDouble(fixed) != m) throw new Ap2Error("amount " + Js.str(major) + " is not exactly representable in " + currency + " minor units");
        double minor = Double.parseDouble(fixed.replace(".", ""));
        if (!Js.isSafeInteger(minor)) throw new Ap2Error("amount " + Js.str(major) + " is outside the safe integer range in minor units");
        return minor;
    }

    /** Integer minor units to the major-unit number PCA budgets use (exact for any safe integer). */
    public static double fromMinorUnits(Object minor, Object currency) {
        int e = currencyExponent(currency);
        if (!Js.isSafeInteger(minor) || Js.num(minor) < 0 || Js.isNegZero(Js.num(minor))) throw new Ap2Error("minor-unit amount must be a non-negative safe integer, got " + Js.str(minor));
        return Js.num(minor) / Math.pow(10, e);
    }

    // ---------------------------------------------------------------------------------------------
    // validators
    // ---------------------------------------------------------------------------------------------

    private static List<String> problems(String... ps) { return new ArrayList<>(Arrays.asList(ps)); }

    private static List<String> merchantProblems(Object v, String at) {
        if (!Js.isObj(v)) return problems(at + ": not an object");
        List<String> p = new ArrayList<>();
        if (!Js.isNonEmptyStr(Js.get(v, "id"))) p.add(at + ".id: required string");
        if (!Js.isNonEmptyStr(Js.get(v, "name"))) p.add(at + ".name: required string");
        if (Js.def(v, "website") && !Js.isStr(Js.get(v, "website"))) p.add(at + ".website: must be a string");
        return p;
    }

    private static List<String> amountProblems(Object v, String at) {
        if (!Js.isObj(v)) return problems(at + ": not an object");
        List<String> p = new ArrayList<>();
        if (!Js.isNonNegInt(Js.get(v, "amount"))) p.add(at + ".amount: must be a non-negative integer (minor units)");
        if (!isAlpha3(Js.get(v, "currency"))) p.add(at + ".currency: must be an ISO 4217 alpha-3 code");
        return p;
    }

    private static List<String> instrumentProblems(Object v, String at) {
        if (!Js.isObj(v)) return problems(at + ": not an object");
        List<String> p = new ArrayList<>();
        if (!Js.isNonEmptyStr(Js.get(v, "id"))) p.add(at + ".id: required string");
        if (!Js.isNonEmptyStr(Js.get(v, "type"))) p.add(at + ".type: required string");
        if (Js.def(v, "description") && !Js.isStr(Js.get(v, "description"))) p.add(at + ".description: must be a string");
        return p;
    }

    private static List<String> pispProblems(Object v, String at) {
        if (!Js.isObj(v)) return problems(at + ": not an object");
        List<String> p = new ArrayList<>();
        for (String k : new String[] {"legal_name", "brand_name", "domain_name"}) if (!Js.isNonEmptyStr(Js.get(v, k))) p.add(at + "." + k + ": required string");
        return p;
    }

    private static List<String> timeProblems(Map<String, Object> v) {
        List<String> p = new ArrayList<>();
        for (String k : new String[] {"iat", "exp"}) if (v.containsKey(k) && !Js.isNonNegInt(v.get(k))) p.add(k + ": must be an integer epoch-seconds");
        return p;
    }

    private static List<String> cnfProblems(Object v) {
        if (!Js.isObj(v) || !Js.isObj(Js.get(v, "jwk"))) return problems("cnf: must be { jwk }");
        try {
            Sdjwt.assertP256Jwk(Js.get(v, "jwk"), "cnf.jwk");
            return new ArrayList<>();
        } catch (Ap2Error e) {
            return problems(e.getMessage());
        }
    }

    private static List<String> pcaClaimProblems(Map<String, Object> v) {
        return v.containsKey(PCA_CLAIM) && !Js.isObj(v.get(PCA_CLAIM)) ? problems(PCA_CLAIM + ": must be an object") : new ArrayList<>();
    }

    private static List<String> listProblems(Object v, String at, BiFunction<Object, String, List<String>> each) {
        if (!Js.isArr(v)) return problems(at + ": must be an array");
        List<String> out = new ArrayList<>();
        List<Object> l = Js.arr(v);
        for (int i = 0; i < l.size(); i++) out.addAll(each.apply(l.get(i), at + "[" + i + "]"));
        return out;
    }

    private static List<String> paymentConstraintProblems(Object c, String at) {
        if (!Js.isObj(c) || !Js.isStr(Js.get(c, "type"))) return problems(at + ": constraint must be an object with a string type");
        Map<String, Object> m = Js.obj(c);
        String type = (String) m.get("type");
        List<String> p = new ArrayList<>();
        switch (type) {
            case "payment.agent_recurrence": {
                Object f = m.get("frequency");
                if (!Js.isStr(f) || !FREQUENCIES.contains(f)) p.add(at + ".frequency: not a known frequency");
                if (m.containsKey("max_occurrences") && !(Js.isInt(m.get("max_occurrences")) && Js.num(m.get("max_occurrences")) > 0)) p.add(at + ".max_occurrences: must be a positive integer");
                return p;
            }
            case "payment.allowed_payees":
                return listProblems(m.get("allowed"), at + ".allowed", Mandates::merchantProblems);
            case "payment.allowed_payment_instruments":
                return listProblems(m.get("allowed"), at + ".allowed", Mandates::instrumentProblems);
            case "payment.allowed_pisps":
                return listProblems(m.get("allowed"), at + ".allowed", Mandates::pispProblems);
            case "payment.amount_range": {
                if (!isAlpha3(m.get("currency"))) p.add(at + ".currency: must be an ISO 4217 alpha-3 code");
                if (!Js.isNonNegInt(m.get("max"))) p.add(at + ".max: must be a non-negative integer (minor units)");
                if (m.containsKey("min") && !Js.isNonNegInt(m.get("min"))) p.add(at + ".min: must be a non-negative integer (minor units)");
                if (Js.isInt(m.get("max")) && Js.isInt(m.get("min")) && Js.num(m.get("min")) > Js.num(m.get("max"))) p.add(at + ": min exceeds max");
                return p;
            }
            case "payment.budget": {
                if (!isAlpha3(m.get("currency"))) p.add(at + ".currency: must be an ISO 4217 alpha-3 code");
                if (!Js.isFinite(m.get("max")) || Js.num(m.get("max")) < 0) p.add(at + ".max: must be a non-negative number (major units)");
                return p;
            }
            case "payment.execution_date":
                for (String k : new String[] {"not_before", "not_after"}) if (m.containsKey(k) && !Js.isStr(m.get(k))) p.add(at + "." + k + ": must be a string");
                return p;
            case "payment.reference":
                return Js.isNonEmptyStr(m.get("conditional_transaction_id")) ? p : problems(at + ".conditional_transaction_id: required string");
            default:
                return problems(at + ": unknown constraint type " + type);
        }
    }

    private static List<String> checkoutConstraintProblems(Object c, String at) {
        if (!Js.isObj(c) || !Js.isStr(Js.get(c, "type"))) return problems(at + ": constraint must be an object with a string type");
        Map<String, Object> m = Js.obj(c);
        String type = (String) m.get("type");
        if (type.equals("checkout.allowed_merchants")) return listProblems(m.get("allowed"), at + ".allowed", Mandates::merchantProblems);
        if (type.equals("checkout.line_items")) {
            Object items = m.get("items");
            if (!Js.isArr(items) || Js.arr(items).isEmpty()) return problems(at + ".items: must be a non-empty array");
            List<String> out = new ArrayList<>();
            List<Object> l = Js.arr(items);
            for (int i = 0; i < l.size(); i++) {
                Object it = l.get(i);
                String a = at + ".items[" + i + "]";
                if (!Js.isObj(it)) {
                    out.add(a + ": not an object");
                    continue;
                }
                if (!Js.isNonEmptyStr(Js.get(it, "id"))) out.add(a + ".id: required string");
                if (!Js.isInt(Js.get(it, "quantity")) || Js.num(Js.get(it, "quantity")) <= 0) out.add(a + ".quantity: must be a positive integer");
                out.addAll(listProblems(Js.get(it, "acceptable_items"), a + ".acceptable_items", (x, ax) -> {
                    if (!Js.isObj(x)) return problems(ax + ": not an object");
                    List<String> p = new ArrayList<>();
                    for (String k : new String[] {"id", "title"}) if (!Js.isNonEmptyStr(Js.get(x, k))) p.add(ax + "." + k + ": required string");
                    return p;
                }));
            }
            return out;
        }
        return problems(at + ": unknown constraint type " + type);
    }

    private static List<String> vctProblem(Map<String, Object> v, String want) {
        return want.equals(v.get("vct")) ? new ArrayList<>() : problems("vct: must be " + want);
    }

    private static boolean anyConstraintOfType(Object constraints, String type) {
        for (Object c : Js.arr(constraints)) if (Js.isObj(c) && type.equals(Js.get(c, "type"))) return true;
        return false;
    }

    public static List<String> openPaymentMandateProblems(Object v) {
        if (!Js.isObj(v)) return problems("mandate: not an object");
        Map<String, Object> m = Js.obj(v);
        List<String> p = vctProblem(m, VCT_PAYMENT_OPEN);
        p.addAll(timeProblems(m));
        p.addAll(cnfProblems(m.get("cnf")));
        p.addAll(pcaClaimProblems(m));
        p.addAll(listProblems(m.get("constraints"), "constraints", Mandates::paymentConstraintProblems));
        if (Js.isArr(m.get("constraints")) && !anyConstraintOfType(m.get("constraints"), "payment.reference")) p.add("constraints: must contain a payment.reference constraint");
        if (m.containsKey("payee")) p.addAll(merchantProblems(m.get("payee"), "payee"));
        if (m.containsKey("payment_amount")) p.addAll(amountProblems(m.get("payment_amount"), "payment_amount"));
        if (m.containsKey("payment_instrument")) p.addAll(instrumentProblems(m.get("payment_instrument"), "payment_instrument"));
        if (m.containsKey("pisp")) p.addAll(pispProblems(m.get("pisp"), "pisp"));
        if (m.containsKey("execution_date") && !Js.isStr(m.get("execution_date"))) p.add("execution_date: must be a string");
        if (m.containsKey("risk_data") && !Js.isObj(m.get("risk_data"))) p.add("risk_data: must be an object");
        return p;
    }

    public static List<String> paymentMandateProblems(Object v) {
        if (!Js.isObj(v)) return problems("mandate: not an object");
        Map<String, Object> m = Js.obj(v);
        List<String> p = vctProblem(m, VCT_PAYMENT);
        p.addAll(timeProblems(m));
        p.addAll(pcaClaimProblems(m));
        if (!Js.isNonEmptyStr(m.get("transaction_id"))) p.add("transaction_id: required string");
        p.addAll(merchantProblems(m.get("payee"), "payee"));
        p.addAll(amountProblems(m.get("payment_amount"), "payment_amount"));
        p.addAll(instrumentProblems(m.get("payment_instrument"), "payment_instrument"));
        if (m.containsKey("pisp")) p.addAll(pispProblems(m.get("pisp"), "pisp"));
        if (m.containsKey("execution_date") && !Js.isStr(m.get("execution_date"))) p.add("execution_date: must be a string");
        if (m.containsKey("risk_data") && !Js.isObj(m.get("risk_data"))) p.add("risk_data: must be an object");
        return p;
    }

    public static List<String> openCheckoutMandateProblems(Object v) {
        if (!Js.isObj(v)) return problems("mandate: not an object");
        Map<String, Object> m = Js.obj(v);
        List<String> p = vctProblem(m, VCT_CHECKOUT_OPEN);
        p.addAll(timeProblems(m));
        p.addAll(cnfProblems(m.get("cnf")));
        p.addAll(pcaClaimProblems(m));
        p.addAll(listProblems(m.get("constraints"), "constraints", Mandates::checkoutConstraintProblems));
        if (Js.isArr(m.get("constraints")) && !anyConstraintOfType(m.get("constraints"), "checkout.line_items")) p.add("constraints: must contain a checkout.line_items constraint");
        return p;
    }

    public static List<String> checkoutMandateProblems(Object v) {
        if (!Js.isObj(v)) return problems("mandate: not an object");
        Map<String, Object> m = Js.obj(v);
        List<String> p = vctProblem(m, VCT_CHECKOUT);
        p.addAll(timeProblems(m));
        p.addAll(pcaClaimProblems(m));
        if (!Js.isNonEmptyStr(m.get("checkout_jwt"))) p.add("checkout_jwt: required string");
        if (!Js.isNonEmptyStr(m.get("checkout_hash"))) p.add("checkout_hash: required string");
        return p;
    }

    /** Returns {@code v} when {@code problems(v)} is empty, else throws {@link Ap2Error} listing them. */
    public static Object assertValid(Object v, Function<Object, List<String>> problems, String what) {
        List<String> p = problems.apply(v);
        if (!p.isEmpty()) throw new Ap2Error(what + ": " + String.join("; ", p));
        return v;
    }
}
